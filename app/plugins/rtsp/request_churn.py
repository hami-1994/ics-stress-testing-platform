"""
測項：RTSP OPTIONS/DESCRIBE 請求連線洪水
分類：RTSP/ONVIF (IP攝影機)（標準埠 554/TCP，部分裝置用 8000/8554）
說明：RTSP（Real Time Streaming Protocol）是 IP Camera/NVR/視訊監控裝置最常見
     的串流控制協定，ONVIF 標準的視訊串流也是建立在 RTSP 之上。許多嵌入式
     攝影機的 RTSP daemon 資源相當有限，快速建立連線並送出 OPTIONS/DESCRIBE
     請求（RTSP 協定交握的第一步，文字格式與 HTTP 極為相似）能有效測試其連線
     與請求解析的處理能力。

實作：純標準函式庫 socket，文字格式請求依 RFC 2326 標準格式組出：
    OPTIONS rtsp://<target>:<port>/ RTSP/1.0\\r\\n
    CSeq: 1\\r\\n
    User-Agent: kali-stress-tool\\r\\n
    \\r\\n
  （或 DESCRIBE，依 request_method 參數）每次連線只送一個請求、讀一次回應
  （預期 "RTSP/1.0 ..." 狀態列）即斷線，屬於連線層級 churn 測試。

安全設計：不涉及任何帳號密碼（RTSP DESCRIBE 若需要驗證會回 401，本測項不會
嘗試任何憑證組合，只記錄是否收到回應）；不偽造來源位址；速率透過 RateLimiter
控制；duration 經 clamp_duration() 限制。

重要限制：不同攝影機廠牌的 RTSP URL path（例如 /Streaming/Channels/101、
/live/ch0 等）差異很大，本測項預設用根路徑 "/" 送 OPTIONS（多數裝置對此都會回應，
不需要知道正確串流路徑），若要測 DESCRIBE 對特定串流路徑的負載，請透過 rtsp_path
參數自行填入受測裝置實際的串流路徑。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "RTSP OPTIONS/DESCRIBE 請求連線洪水"
CATEGORY = "RTSP/ONVIF (IP攝影機)"
PROTOCOL = "TCP"
DEFAULT_PORT = 554
TEST_TYPE = "resource"  # 連線建立 + OPTIONS/DESCRIBE 請求 + 關閉循環（churn）


def _build_request(method: str, target: str, port: int, path: str, cseq: int) -> bytes:
    url = f"rtsp://{target}:{port}{path}"
    msg = (
        f"{method} {url} RTSP/1.0\r\n"
        f"CSeq: {cseq}\r\n"
        "User-Agent: kali-stress-tool\r\n"
        "\r\n"
    )
    return msg.encode("ascii")


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 50000, "min": 1, "max": 50000, "desc": "每秒建立連線 + 送出請求次數"},
        "request_method": {"type": "string", "default": "OPTIONS", "desc": "OPTIONS 或 DESCRIBE"},
        "rtsp_path": {"type": "string", "default": "/", "desc": "RTSP URL 路徑（DESCRIBE 需填受測裝置實際串流路徑）"},
        "connect_timeout": {"type": "float", "default": 2.0, "min": 0.5, "max": 5.0, "desc": "單次連線/收送逾時秒數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 80))
    method = params.get("request_method", "OPTIONS").upper()
    if method not in ("OPTIONS", "DESCRIBE"):
        method = "OPTIONS"
    path = params.get("rtsp_path", "/")
    timeout = float(params.get("connect_timeout", 2.0))

    limiter = RateLimiter(rate)
    stats = {"connected": 0, "response_ok": 0, "no_response": 0, "errors": 0}
    cseq = 0
    start = time.time()

    log_fn(f"[+] RTSP {method} 連線洪水 -> {target}:{port} @ {rate}/s, {duration}s（不涉及任何驗證）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        cseq += 1
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            stats["connected"] += 1
            s.sendall(_build_request(method, target, port, path, cseq))
            resp = s.recv(2048)
            if resp.startswith(b"RTSP/"):
                stats["response_ok"] += 1
            else:
                stats["no_response"] += 1
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
        "response_ok": stats["response_ok"],
        "no_response": stats["no_response"],
        "errors": stats["errors"],
        "elapsed_sec": round(time.time() - start, 1),
    }
