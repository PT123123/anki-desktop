"""配对二维码的 AnkiQt 界面（SPEC-v2 §4.7）。

这里只放界面：出码、把票据画成二维码、从图片文件里读出票据、把结果摊开给用户核对。
协议、配对、同步一律走 `LanEngine` 的既有方法，本模块不重复实现任何一条。

电脑端没有摄像头，所以"扫码"= 选一张二维码图片（对方手机存的、或截图发过来的）。
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

QR_PX = 340
IMAGE_FILTER = "图片 (*.png *.jpg *.jpeg *.bmp *.webp *.gif)"


class PairQrDialog(QDialog):
    """亮自己的码 + 读对方的图 + 核对安全码。"""

    def __init__(self, engine, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.engine = engine
        self.setWindowTitle("局域网同步 - 配对二维码")
        self._ticket_text: str | None = None
        self._build_ui()
        self.refresh_qr()
        self.refresh_peers()

    # ----------------------------------------------------------------- 界面
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_label.setMinimumSize(QR_PX, QR_PX)
        root.addWidget(self.qr_label)

        self.code_label = QLabel()
        self.code_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.code_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        root.addWidget(self.code_label)

        self.hint_label = QLabel(
            "扫到码只是把地址和配对码交接过来；配对完成后两端各自显示的 4 位安全码"
            "必须一致，否则说明中间有人。不一致请立刻解除配对、重新扫码。"
        )
        self.hint_label.setWordWrap(True)
        root.addWidget(self.hint_label)

        buttons = QHBoxLayout()
        self.btn_new = QPushButton("换新码")
        self.btn_new.clicked.connect(self.refresh_qr)
        self.btn_scan = QPushButton("导入二维码图片…")
        self.btn_scan.clicked.connect(self.pick_image)
        buttons.addWidget(self.btn_new)
        buttons.addWidget(self.btn_scan)
        root.addLayout(buttons)

        peer_row = QHBoxLayout()
        peer_row.addWidget(QLabel("已配对设备"))
        self.peer_combo = QComboBox()
        peer_row.addWidget(self.peer_combo, 1)
        self.btn_unpair = QPushButton("解除配对")
        self.btn_unpair.clicked.connect(self.unpair_selected)
        peer_row.addWidget(self.btn_unpair)
        root.addLayout(peer_row)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        root.addWidget(self.status_label)

    # ------------------------------------------------------------- 显示二维码
    def refresh_qr(self) -> None:
        """开会话拿活码并把票据画成二维码；拿不到地址/没在监听时退回数字码。"""
        try:
            info = self.engine.show_pair_qr()
        except ValueError as exc:
            self.qr_label.clear()
            self._ticket_text = None
            self.code_label.setText("")
            self.set_status(f"无法出码：{exc}", ok=False)
            return
        self._ticket_text = info["ticket_text"]
        self.qr_label.setPixmap(self._pixmap(self._ticket_text))
        self.code_label.setText(
            f"数字码 {info['pair_code']}（{info['expires_in']} 秒内有效，只能用一次）"
        )
        self.set_status(info["note"], ok=True)

    def _pixmap(self, text: str) -> QPixmap:
        """segno 只能写文件，所以画到临时 PNG 再读回来。"""
        from . import qrimg

        handle, name = tempfile.mkstemp(suffix=".png", prefix="lansync-qr-")
        os.close(handle)
        path = Path(name)
        try:
            qrimg.render_png(text, path)
            return QPixmap(str(path))
        finally:
            path.unlink(missing_ok=True)

    # ----------------------------------------------------------------- 扫码
    def pick_image(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择对方的二维码图片", "", IMAGE_FILTER)
        if not path:
            return
        try:
            self.scan_text(self.decode_image(path))
        except Exception as exc:  # 读不到文件、图片损坏、cv2 解不出
            self.set_status(f"解析图片失败：{exc}", ok=False)

    @staticmethod
    def decode_image(path: str) -> str:
        from . import qrimg

        return qrimg.decode_image(path)

    def scan_text(self, text: str) -> dict:
        """把一段二维码文本交给引擎：解析票据 → 走既有 commit。"""
        if not text:
            self.set_status("图片里没识别到二维码", ok=False)
            return {}
        from .pairqr import PairQrError

        try:
            result = self.engine.scan_ticket_text(text)
        except PairQrError as exc:
            # 摄像头/截图里的码千奇百怪，扫到别的二维码是常态，不是配对失败。
            self.set_status(f"这不是 Anki 的配对二维码（{exc.code}）", ok=False)
            return {}
        except Exception as exc:
            self.set_status(f"配对失败：{exc}", ok=False)
            return {}
        self.set_status(
            f"已与 {result.get('peer_name') or result['name']}（{result['scanned_from']}）配对，"
            f"安全码 {result['security_code']} —— 请核对与对方屏幕上显示的一致",
            ok=True,
        )
        self.refresh_peers()
        return result

    # ------------------------------------------------------------- 安全码核对
    def refresh_peers(self) -> None:
        self.peer_combo.clear()
        for row in self.engine.store.devices(include_unpaired=False):
            code = row.get("security_code") or "无"
            label = f"{row.get('name') or row['peer_id'][:8]}（{row['peer_id'][:8]}）安全码 {code}"
            self.peer_combo.addItem(label, row["peer_id"])
        if self.peer_combo.count() == 0:
            self.peer_combo.addItem("（还没有已配对设备）")

    def selected_peer_id(self) -> str | None:
        return self.peer_combo.currentData()

    def unpair_selected(self) -> None:
        peer_id = self.selected_peer_id()
        if not peer_id:
            return
        self.engine.unpair(peer_id)
        self.set_status(f"已解除配对：{peer_id[:8]}，此后的同步请求都会被拒绝", ok=True)
        self.refresh_peers()

    def set_status(self, text: str, *, ok: bool) -> None:
        self.status_label.setText(text)
        self.status_label.setStyleSheet("color: paletteWindowText" if ok else "color: red")
