"""
測項：FTP 控制連線洪水（connect / banner / QUIT 循環）
分類：FTP（預設埠 21/TCP，控制連線）
說明：模擬真實情境中「大量用戶端快速建立又斷開 FTP 控制連線」對 FTPd 的負載，
     測試目標對 accept()/child-process-per-connection（或 thread-per-connection）
     的處理能力與資源回收速度。

安全設計（重要）：
  - 全程「不」送出任何 USER / PASS 指令，絕不嘗試任何帳號密碼組合（不論真實或假造），
    避免落入「帳密猜測/暴力破解」的範疇。
  - 每個連線只做：TCP 三方交握 -> 讀取 banner（220 訊息）-> 送出 QUIT -> 讀回應 -> 關閉，
    純粹是「連線churn」負載測試，不涉及任何驗證流程。
  - 不偽造來源位址，全部連線皆由執行本測試的機器真實發起。
  - 速率透過 RateLimiter 控制，並非無上限全速；duration 經 clamp_duration() 限制。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "FTP 控制連線洪水（connect/QUIT 循環）"
CATEGORY = "FTP"
PROTOCOL = "TCP"
DEFAULT_PORT = 21
TEST_TYPE = "resource"  # 控制連線建立-關閉循環（churn）


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {
            "type": "int", "default": 80000, "min": 1, "max": 80000,
            "desc": "每秒建立的控制連線次數",
        },
        "connect_timeout": {
            "type": "float", "default": 2.0, "min": 0.5, "max": 5.0,
            "desc": "單次連線/收送逾時秒數",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 150))
    timeout = float(params.get("connect_timeout", 2.0))

    limiter = RateLimiter(rate)
    stats = {"connected": 0, "banner_ok": 0, "quit_ok": 0, "errors": 0}
    start = time.time()

    log_fn(f"[+] FTP 控制連線洪水 -> {target}:{port} @ {rate}/s, {duration}s（不送出任何帳密）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            stats["connected"] += 1
            banner = s.recv(256)
            if banner.startswith(b"220"):
                stats["banner_ok"] += 1
            s.sendall(b"QUIT\r\n")
            resp = s.recv(256)
            if resp:
                stats["quit_ok"] += 1
        except OSError as e:
            stats["errors"] += 1
            if stats["errors"] <= 5:
                log_fn(f"[!] 連線錯誤：{e}")
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    return {
        "connected": stats["connected"],
        "banner_ok": stats["banner_ok"],
        "quit_ok": stats["quit_ok"],
        "errors": stats["errors"],
        "elapsed_sec": round(time.time() - start, 1),
    }
