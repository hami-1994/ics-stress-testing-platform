"""
測項：WebSocket 連線洪水（Upgrade 握手循環）
分類：一般（不限特定通訊協定家族，許多現代裝置管理介面/儀表板都用 WebSocket）
說明：越來越多裝置管理後台（含部分 IoT/工控人機介面 Web UI）用 WebSocket 做
     即時資料推播。WebSocket 的連線建立本質是一個 HTTP Upgrade 請求，Server
     端接受後會把該 TCP 連線長期保持在已升級狀態，因此連線數上限/資源分配
     往往比一般短連線 HTTP 請求更吃緊。本測項快速建立又關閉大量 WebSocket
     Upgrade 握手，測試對象對高頻連線建立的處理能力。

實作：純標準函式庫 socket + base64，依 RFC 6455 §4.1 標準格式組出 Upgrade
請求：
    GET <path> HTTP/1.1\\r\\n
    Host: <target>:<port>\\r\\n
    Upgrade: websocket\\r\\n
    Connection: Upgrade\\r\\n
    Sec-WebSocket-Key: <16 bytes 隨機值的 base64 編碼>\\r\\n
    Sec-WebSocket-Version: 13\\r\\n
    \\r\\n
  每次連線只做「連線 -> 送出 Upgrade 請求 -> 讀取回應（預期 101 Switching
  Protocols）-> 關閉」，不維持連線、不送任何 WebSocket frame 資料。

安全設計：不涉及任何驗證/帳密；不偽造來源位址；速率透過 RateLimiter 控制；
duration 經 clamp_duration() 限制。
"""
import base64
import os
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "WebSocket 連線洪水（Upgrade 握手循環）"
CATEGORY = "一般"
PROTOCOL = "TCP"
DEFAULT_PORT = 80
TEST_TYPE = "resource"  # 連線型：連線建立-Upgrade-關閉快速循環（churn）


def _build_upgrade_request(target: str, port: int, path: str) -> bytes:
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    msg = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {target}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    return msg.encode("ascii")


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 100000, "min": 1, "max": 100000, "desc": "每秒建立連線 + Upgrade 握手次數"},
        "path": {"type": "string", "default": "/", "desc": "WebSocket 端點路徑"},
        "connect_timeout": {"type": "float", "default": 2.0, "min": 0.5, "max": 5.0, "desc": "單次連線/收送逾時秒數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 100))
    path = params.get("path", "/")
    timeout = float(params.get("connect_timeout", 2.0))

    limiter = RateLimiter(rate)
    stats = {"connected": 0, "upgrade_ok": 0, "no_upgrade": 0, "errors": 0}
    start = time.time()

    log_fn(f"[+] WebSocket 連線洪水 -> {target}:{port}{path} @ {rate}/s, {duration}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            stats["connected"] += 1
            s.sendall(_build_upgrade_request(target, port, path))
            resp = s.recv(2048)
            if b"101" in resp.split(b"\r\n", 1)[0]:
                stats["upgrade_ok"] += 1
            else:
                stats["no_upgrade"] += 1
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
        "upgrade_ok": stats["upgrade_ok"],
        "no_upgrade": stats["no_upgrade"],
        "errors": stats["errors"],
        "elapsed_sec": round(time.time() - start, 1),
    }
