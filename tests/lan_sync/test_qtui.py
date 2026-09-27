# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 PT123123 <31439216+PT123123@users.noreply.github.com>

"""AnkiQt 配对二维码对话框（SPEC-v2 §4.7）的离屏测试。

跑在 `out/pyenv` 那个装了 PyQt6 的环境里（`QT_QPA_PLATFORM=offscreen`）：
这里证明的是"界面这一层接对了"——票据真能画成 QPixmap、真能从一张 PNG 里读回原文、
按钮真打到引擎的方法、失败真有话给用户。协议字节层由 `tools/lansync_e2e.py` 的 E7qr 臂管。
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("PyQt6")
pytest.importorskip("segno")
pytest.importorskip("cv2")

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QFileDialog  # noqa: E402

from lan_sync import pairqr, qrimg  # noqa: E402
from lan_sync.qtui import PairQrDialog  # noqa: E402

TICKET_HOST = "192.168.1.44"


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


class FakeStore:
    def __init__(self, rows=None):
        self.rows = rows or []

    def devices(self, include_unpaired=True):
        return list(self.rows)


class FakeEngine:
    """只实现对话框用到的四个方法，其余一概不碰。"""

    def __init__(self, ticket_text=None, scan_error=None, store_rows=None):
        self.ticket_text = ticket_text
        self.scan_error = scan_error
        self.scanned: list[str] = []
        self.unpaired: list[str] = []
        self.begin_calls = 0
        self.store = FakeStore(store_rows)

    def show_pair_qr(self):
        self.begin_calls += 1
        if self.ticket_text is None:
            raise ValueError("这台机器现在没有可用的局域网地址")
        return {
            "pair_code": "123456",
            "expires_in": 300,
            "security_code": None,
            "ticket_text": self.ticket_text,
            "note": "扫码只是交接地址+配对码",
        }

    def scan_ticket_text(self, text):
        self.scanned.append(text)
        if self.scan_error is not None:
            raise self.scan_error
        return {"peer_id": "peer-1", "name": "手机", "security_code": "ab12",
                "scanned_from": f"{TICKET_HOST}:5600", "peer_name": "手机"}

    def unpair(self, peer_id):
        self.unpaired.append(peer_id)


def make_ticket(device_id="a" * 36) -> str:
    return pairqr.encode_ticket(device_id, "工作机", "desktop", TICKET_HOST, 5600, "123456")


def shows_an_image(label) -> bool:
    """PyQt 的 QLabel 没图时返回的是一个 null QPixmap，不是 None。"""
    pixmap = label.pixmap()
    return pixmap is not None and not pixmap.isNull()


def test_a_ticket_really_becomes_a_pixmap(qapp):
    dialog = PairQrDialog(FakeEngine(make_ticket()))
    assert shows_an_image(dialog.qr_label)
    assert dialog.qr_label.pixmap().width() >= 100
    assert "123456" in dialog.code_label.text()
    dialog.close()


def test_the_digital_fallback_is_still_there_when_no_qr(qapp):
    engine = FakeEngine(None)
    dialog = PairQrDialog(engine)
    assert not shows_an_image(dialog.qr_label)
    assert "无法出码" in dialog.status_label.text()
    assert engine.begin_calls == 1
    dialog.close()


def test_an_imported_image_is_decoded_and_handed_to_the_engine(qapp, tmp_path, monkeypatch):
    text = make_ticket()
    image = tmp_path / "peer.png"
    qrimg.render_png(text, image)

    engine = FakeEngine(text)
    dialog = PairQrDialog(engine)
    monkeypatch.setattr(QFileDialog, "getOpenFileName",
                        staticmethod(lambda *a, **k: (str(image), "")))
    dialog.pick_image()

    # 真从 PNG 里读回来的原文，必须和出码端一字不差
    assert engine.scanned == [text]
    assert "ab12" in dialog.status_label.text()
    dialog.close()


def test_a_foreign_qr_is_not_reported_as_pairing_failure(qapp, tmp_path):
    image = tmp_path / "other.png"
    qrimg.render_png("https://example.com/download", image)

    engine = FakeEngine(make_ticket(), scan_error=pairqr.PairQrError("not_our_qr"))
    dialog = PairQrDialog(engine)
    monkeypatch_result = dialog.scan_text(dialog.decode_image(str(image)))

    assert monkeypatch_result == {}
    assert "不是 Anki 的配对二维码" in dialog.status_label.text()
    assert "配对失败" not in dialog.status_label.text()
    dialog.close()


def test_an_empty_image_is_told_apart_from_a_foreign_one(qapp):
    dialog = PairQrDialog(FakeEngine(make_ticket()))
    assert dialog.scan_text("") == {}
    assert "没识别到二维码" in dialog.status_label.text()
    dialog.close()


def test_unpairing_targets_the_selected_peer(qapp):
    rows = [{"peer_id": "peer-1", "name": "手机", "security_code": "ab12"}]
    engine = FakeEngine(make_ticket(), store_rows=rows)
    dialog = PairQrDialog(engine)
    assert dialog.selected_peer_id() == "peer-1"
    assert "ab12" in dialog.peer_combo.currentText()

    dialog.btn_unpair.click()
    assert engine.unpaired == ["peer-1"]
    # 解除后列表里没有已配对设备了，按钮也就选不到 id
    dialog.engine.store.rows = []
    dialog.refresh_peers()
    assert dialog.selected_peer_id() is None
    dialog.close()


def test_clicking_new_code_rebuilds_the_qr(qapp):
    engine = FakeEngine(make_ticket())
    dialog = PairQrDialog(engine)
    before = engine.begin_calls
    dialog.btn_new.click()
    assert engine.begin_calls == before + 1
    assert shows_an_image(dialog.qr_label)
    dialog.close()
