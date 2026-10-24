"""
測項：FTP PASV 模式資料連線洪水
分類：FTP（預設埠 21/TCP，控制連線；資料連線埠由伺服器 PASV 回應動態指定）
說明：模擬用戶端快速要求被動模式（PASV）並立即開啟/關閉對應資料連線的負載，
     測試 FTPd 對「PASV 埠配置 -> 資料連線 accept -> 回收」這條路徑在高頻率下的
     處理能力（許多 FTPd 的 PASV 埠池大小/資料連線 timeout 設計是常見瓶頸）。

安全設計（重要）：
  - 全程「不」送出 USER / PASS，不嘗試任何登入。直接在未驗證狀態下送出 PASV 指令；
    若伺服器要求先登入才允許 PASV（常見回應如 530 Please login with USER and PASS），
    該拒絕回應本身就是測試訊號（控制連線配置與拒絕處理路徑），我們不會因此嘗試任何
    帳密組合去繞過它。
  - 不偽造來源位址，資料連線與控制連線皆由執行本測試的機器真實發起。
  - 速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。
"""
import re
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "FTP PASV 資料連線洪水"
CATEGORY = "FTP"
PROTOCOL = "TCP"
DEFAULT_PORT = 21
TEST_TYPE = "resource"  # 針對性消耗伺服器 PASV 資料連線埠資源，非單純比流量大小

_PASV_RE = re.compile(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)")


def _parse_pasv(resp: bytes):
    m = _PASV_RE.search(resp.decode(errors="ignore"))
    if not m:
        return None
    a, b, c, d, p1, p2 = (int(x) for x in m.groups())
    ip = f"{a}.{b}.{c}.{d}"
    data_port = p1 * 256 + p2
    return ip, data_port


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 100))
    timeout = float(params.get("connect_timeout", 2.0))

    limiter = RateLimiter(rate)
    stats = {"pasv_ok": 0, "pasv_rejected": 0, "data_conn_ok": 0, "errors": 0}
    start = time.time()

    log_fn(f"[+] FTP PASV 資料連線洪水 -> {target}:{port} @ {rate}/s, {duration}s（不送出任何帳密）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        ctrl = None
        data = None
        try:
            ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ctrl.settimeout(timeout)
            ctrl.connect((target, port))
            ctrl.recv(256)  # banner，不做任何判斷即可
            ctrl.sendall(b"PASV\r\n")
            resp = ctrl.recv(256)
            if resp.startswith(b"227"):
                stats["pasv_ok"] += 1
                parsed = _parse_pasv(resp)
                if parsed:
                    data_ip, data_port = parsed
                    try:
                        data = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        data.settimeout(timeout)
                        data.connect((data_ip, data_port))
                        stats["data_conn_ok"] += 1
                    except OSError as e:
                        stats["errors"] += 1
                        if stats["errors"] <= 5:
                            log_fn(f"[!] 資料連線失敗：{e}")
            else:
                stats["pasv_rejected"] += 1
            ctrl.sendall(b"QUIT\r\n")
        except OSError as e:
            stats["errors"] += 1
            if stats["errors"] <= 5:
                log_fn(f"[!] 控制連線錯誤：{e}")
        finally:
            for s in (data, ctrl):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    return {
        "pasv_accepted": stats["pasv_ok"],
        "pasv_rejected": stats["pasv_rejected"],
        "data_conn_ok": stats["data_conn_ok"],
        "errors": stats["errors"],
        "elapsed_sec": round(time.time() - start, 1),
    }


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {
            "type": "int", "default": 50000, "min": 1, "max": 50000,
            "desc": "每秒 PASV 請求 + 資料連線循環次數",
        },
        "connect_timeout": {
            "type": "float", "default": 2.0, "min": 0.5, "max": 5.0,
            "desc": "單次連線/收送逾時秒數",
        },
    }
