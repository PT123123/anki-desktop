"""配对票据 ↔ 二维码图片的渲染/解码（SPEC-v2 §4.7 的桌面落地）。

依赖是**惰性导入**的：`segno` 出图（纯 Python，PNG/SVG，不需 Pillow 也行），
`opencv` 从图片文件解回文本。这样没装这两个包时，CLI 的其余命令和 `tests/lan_sync`
都不受影响 —— 只有真正 `pair show`/`pair scan` 才需要它们。

电脑没有摄像头，所以"扫码"= 读一张用户保存/传过来的二维码图片。
"""

from __future__ import annotations

from pathlib import Path


def render_png(text: str, path: Path, *, scale: int = 8) -> Path:
    """把票据文本写成 PNG 图片文件（强制 PNG 内容，与扩展名无关）。"""
    import segno  # noqa: PLC0415  惰性：只有出码才依赖

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # error='M'：扫码距离/屏幕反光下更稳，尺寸仍很小。
    segno.make(text, error="M").save(str(path), kind="png", scale=scale, border=2)
    return path


def render_svg(text: str, path: Path) -> Path:
    import segno  # noqa: PLC0415

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    segno.make(text, error="M").save(str(path), kind="svg", border=2)
    return path


def terminal_ascii(text: str, *, compact: bool = True) -> str:
    """在终端里直接打一个可扫的二维码（半块字符），无需 GUI 也无需图片文件。"""
    import io  # noqa: PLC0415

    import segno  # noqa: PLC0415

    buf = io.StringIO()
    segno.make(text, error="M").terminal(out=buf, compact=compact)
    return buf.getvalue()


def decode_image(path: Path | str) -> str:
    """从图片文件解出二维码文本。

    用 `np.fromfile` 而不是 `cv2.imread`，因为 Windows 下 `cv2.imread` 不吃非 ASCII 路径。
    解不出码返回空串，由调用方给"没识别到二维码"的提示。
    """
    import cv2  # noqa: PLC0415
    import numpy as np  # noqa: PLC0415

    buf = np.fromfile(str(path), dtype=np.uint8)
    if buf.size == 0:
        raise FileNotFoundError(f"图片为空或不存在: {path}")
    img = cv2.imdecode(buf, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError(f"无法解码图片文件: {path}")
    data, _pts, _ = cv2.QRCodeDetector().detectAndDecode(img)
    return data or ""
