"""二维码配对票据（SPEC-v2 §4.7）。

票据是**明文**承载的连接 + 一次性配对码交接：显示端本机 `begin_pairing()` 拿到活码后，把
"连我这里 + 用这个码"编成一段文本渲染成二维码；扫描端解析后走既有的 `GET /info` 验证 +
`/pair/commit`，不新增任何网络路由。

格式是 `magic + 空格 + 紧凑 JSON`，与 `protocol.encode_announce` 同族。JSON 的键序、分隔符、
非 ASCII 处理都参与两端字节对齐，固定输入 → 固定文本由 `vectors.json` 的 `pair_qr` 段钉死。

安全姿态没变：把 6 位码塞进二维码 ≈ 把码显示在屏幕上让人抄，中间人防护仍然只有配对完成后
人工核对的 4 位安全码（SPEC §4.1）。
"""

from __future__ import annotations

import json
import re

from .protocol import is_site_local_ipv4, KIND_ANDROID, KIND_DESKTOP

# 票据文本前缀；也是 JSON 里 `t` 字段的值。与 `v`（协议版本）分开是刻意的：
# 将来换票据字段布局时改 `t`，换线上协议版本时改 `v`。
PAIR_QR_MAGIC = "anki-lan-pair/1"
PAIR_QR_PROTOCOL = 2

# 键序即协议：两端都按这个顺序出紧凑 JSON，向量才逐字节可比。
_KEYS = ("t", "v", "id", "nk", "nm", "h", "p", "c")

_KINDS = (KIND_DESKTOP, KIND_ANDROID)
_PAIR_CODE_RE = re.compile(r"\d{6}")
_DEFAULT_PORT = 5600


class PairQrError(Exception):
    """本地解析/校验失败（不是 HTTP 错误，没有对端参与）。`code` 供界面选文案。"""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


class Ticket:
    """解析后的配对票据。`pair_code` 是敏感项，只在 commit 时出网一次。"""

    def __init__(self, device_id: str, name: str, kind: str, host: str,
                 port: int, pair_code: str) -> None:
        self.device_id = device_id
        self.name = name
        self.kind = kind
        self.host = host
        self.port = port
        self.pair_code = pair_code

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    def __repr__(self) -> str:  # 绝不把 pair_code 打进日志
        return f"Ticket(id={self.device_id[:8]}, {self.kind} {self.endpoint})"


def encode_ticket(device_id: str, name: str, kind: str, host: str,
                  port: int, pair_code: str) -> str:
    """生成规范票据文本。校验本机侧输入；不合规直接抛（是编程错误，不是对端错误）。"""
    if not device_id:
        raise PairQrError("bad_id", "device_id 不能为空")
    if not _PAIR_CODE_RE.fullmatch(pair_code or ""):
        raise PairQrError("bad_code", "配对码必须是 6 位十进制")
    if not is_site_local_ipv4(host):
        raise PairQrError("bad_address", "只能宣告 site-local IPv4")
    if kind not in _KINDS:
        raise PairQrError("bad_kind", f"未知设备类型: {kind}")
    port = int(port) or _DEFAULT_PORT
    if not 1 <= port <= 65535:
        raise PairQrError("bad_port", f"端口超出范围: {port}")
    obj = {
        "t": PAIR_QR_MAGIC,
        "v": PAIR_QR_PROTOCOL,
        "id": device_id,
        "nk": kind,
        "nm": name,
        "h": host,
        "p": port,
        "c": pair_code,
    }
    # json.dumps 按插入序输出（未 sort_keys），插入序即 _KEYS，所以键序由协议固定。
    # ensure_ascii：票据文本恒为 ASCII。二维码解码端猜字符集是常态（实测 OpenCV 的 QR 解码器
    # 会把 UTF-8 的中文设备名弄成乱码，zxing 的 writer 不显式指定时还会退回 ISO-8859-1），
    # 而 `\uXXXX` 是 JSON 标准转义，任何一端解出来都一样。
    ordered = json.dumps({k: obj[k] for k in _KEYS},
                         ensure_ascii=True, separators=(",", ":"))
    return f"{PAIR_QR_MAGIC} {ordered}"


def decode_ticket(text: str) -> Ticket:
    """解析并校验票据。陌生二维码 → `not_our_qr`（绝不抛解析异常，摄像头会扫到任意码）。

    未知字段忽略（前向兼容，§9）；`t` 与 `v` 必须匹配，否则拒绝而不是猜着往下走。
    """
    prefix = f"{PAIR_QR_MAGIC} "
    if not isinstance(text, str) or not text.startswith(prefix):
        raise PairQrError("not_our_qr", "不是 Anki 局域网配对二维码")
    try:
        data = json.loads(text[len(prefix):])
    except ValueError as exc:
        raise PairQrError("bad_format", f"票据 JSON 不成形: {exc}") from exc
    if not isinstance(data, dict):
        raise PairQrError("bad_format", "票据载荷不是对象")
    if data.get("t") != PAIR_QR_MAGIC:
        raise PairQrError("bad_format", "票据类型标记不匹配")
    if int(data.get("v", 0)) < PAIR_QR_PROTOCOL:
        raise PairQrError("old_protocol", "对端协议版本过旧")

    device_id = str(data.get("id", ""))
    if not device_id:
        raise PairQrError("bad_id", "票据缺少 device_id")

    pair_code = str(data.get("c", ""))
    if not _PAIR_CODE_RE.fullmatch(pair_code):
        raise PairQrError("bad_code", "配对码必须是 6 位十进制")

    host = str(data.get("h", ""))
    if not is_site_local_ipv4(host):
        raise PairQrError("bad_address", "对端地址不是可用的内网 IPv4")

    try:
        port = int(data.get("p") or _DEFAULT_PORT)
    except (TypeError, ValueError) as exc:
        raise PairQrError("bad_port", "端口非法") from exc
    if not 1 <= port <= 65535:
        raise PairQrError("bad_port", f"端口超出范围: {port}")

    kind = str(data.get("nk", KIND_DESKTOP))
    name = str(data.get("nm", ""))
    return Ticket(device_id, name, kind, host, port, pair_code)
