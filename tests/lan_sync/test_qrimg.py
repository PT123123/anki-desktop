"""二维码图片渲染/解码往返（桌面 Slice 2 的 qrimg）。

segno / opencv 是惰性依赖；没装就整体 skip，不影响其余纯逻辑测试。
"""

from __future__ import annotations

import pytest

from lan_sync import pairqr

pytest.importorskip("segno")
pytest.importorskip("cv2")

from lan_sync import qrimg  # noqa: E402

ID = "bbbbbbbb-2222-4222-8222-222222222222"


def _ticket_text() -> str:
    # 名字带非 ASCII + 双引号，确保图片这条链不会在编码/渲染处把内容截断。
    return pairqr.encode_ticket(ID, '笔记本"α"', "desktop", "192.168.1.20", 5600, "246810")


def test_png_roundtrip_preserves_ticket(tmp_path):
    text = _ticket_text()
    png = qrimg.render_png(text, tmp_path / "pair.png")
    assert png.exists() and png.stat().st_size > 0
    assert qrimg.decode_image(png) == text


def test_unicode_path_png_roundtrip(tmp_path):
    text = _ticket_text()
    png = qrimg.render_png(text, tmp_path / "配对 码.png")
    assert qrimg.decode_image(png) == text


def test_svg_is_written_but_not_image_decodable(tmp_path):
    # SVG 是矢量，cv2 只解位图；它只作"打印友好"输出格式，扫码路径用位图。
    svg = qrimg.render_svg(_ticket_text(), tmp_path / "pair.svg")
    assert svg.exists() and "<svg" in svg.read_text(encoding="utf-8")


def test_decode_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        qrimg.decode_image(tmp_path / "nope.png")


def test_foreign_qr_image_decodes_but_fails_pairqr_validation(tmp_path):
    import segno

    png = tmp_path / "url.png"
    segno.make("https://example.com/", error="M").save(str(png), kind="png", scale=8)
    data = qrimg.decode_image(png)
    assert data == "https://example.com/"
    with pytest.raises(pairqr.PairQrError) as exc:
        pairqr.decode_ticket(data)
    assert exc.value.code == "not_our_qr"
