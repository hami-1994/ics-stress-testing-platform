"""
測項：DNP3 Link Layer Status Request 高頻率洪水
分類：DNP3
說明：DNP3 資料連結層有一個標準的「Link Status Request」功能（用於偵測連線是否存活，
     類似心跳機制），這裡以受控速率重複送出該請求，測試 Outstation（現場裝置/RTU）
     對連結層訊框的處理能力與是否有速率限制/防護機制。

重要限制：
  - DNP3 CRC-16 演算法在下方以標準位元運算方式實作（多項式 0xA6BC），但**未在真實
    DNP3 裝置或封包截取上驗證過**。正式使用前，建議先用 Wireshark（內建 DNP3 解析器）
    確認產生的訊框 CRC 是否被目標正確接受，如有落差請以 Wireshark 的結果為準調整。
  - 這裡只組出資料連結層（Data Link Layer）等級的訊框，不含應用層（Application Layer）
    內容，足以測試「大量訊框湧入」情境，但不是完整的 DNP3 交易模擬。
需求：無額外套件，純標準函式庫。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "DNP3 Link Status Request 洪水"
CATEGORY = "DNP3"
PROTOCOL = "TCP"
DEFAULT_PORT = 20000
TEST_TYPE = "traffic"  # 流量型：連結層 Link Status Request 心跳訊框洪水，靠封包速率本身造成負擔

_START = b"\x05\x64"  # DNP3 Data Link Layer 固定起始位元組


def _crc16_dnp3(data: bytes) -> bytes:
    """DNP3 CRC-16，多項式 0xA6BC（bit-reversed 表示法），逐位元運算版本。"""
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    crc = (~crc) & 0xFFFF
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def _build_link_status_request(dest_addr: int, src_addr: int) -> bytes:
    """組一個 DNP3 Link Status Request 訊框（Primary frame, function code 0x09）。
    Header: START(2) LEN(1) CTRL(1) DEST(2,LE) SRC(2,LE) CRC(2)  -- 共 10 bytes header
    CTRL = 0xC9 = 1100 1001b: DIR=1, PRM=1, FCB=0, FCV=0, FUNC=01001(=9, REQUEST_LINK_STATUS)
    """
    length = 5  # CTRL + DEST(2) + SRC(2) 共 5 bytes 被計入 LEN 欄位
    ctrl = 0xC9
    body = bytes([length, ctrl]) + dest_addr.to_bytes(2, "little") + src_addr.to_bytes(2, "little")
    header = _START + body
    crc = _crc16_dnp3(body)
    return header + crc


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 300000, "min": 1, "max": 300000, "desc": "每秒送出訊框數"},
        "dest_addr": {"type": "int", "default": 1, "min": 0, "max": 65535, "desc": "DNP3 目的位址（Outstation）"},
        "src_addr": {"type": "int", "default": 1, "min": 0, "max": 65535, "desc": "DNP3 來源位址（Master）"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 350))
    dest_addr = int(params.get("dest_addr", 1))
    src_addr = int(params.get("src_addr", 1))

    frame = _build_link_status_request(dest_addr, src_addr)
    limiter = RateLimiter(rate)
    sent, errors = 0, 0
    start = time.time()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((target, port))
    except OSError as e:
        log_fn(f"[!] 無法連線 {target}:{port}: {e}")
        return {"sent": 0, "error": str(e)}

    log_fn(f"[+] 開始送出 DNP3 Link Status Request @ {rate}/s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            sock.sendall(frame)
            sent += 1
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")
            break

    sock.close()
    return {"frames_sent": sent, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
