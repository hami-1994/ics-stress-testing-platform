"""
測項：Telnet 連線洪水（connect / banner 讀取循環）
分類：Telnet（標準埠 23/TCP）
說明：Telnet 是許多 IoT/嵌入式裝置（路由器、老舊工業設備、序列轉乙太網路
     閘道器）預設仍開啟的管理介面，且往往沒有連線數限制或速率保護。快速建立
     又關閉大量 TCP 連線並讀取初始 IAC 協商/banner 位元組，測試裝置對高頻連線
     建立的處理能力，這是實務上常見的 IoT 預設服務攻擊面之一。

安全設計（重要，比照同專案 ftp/conn_churn_flood.py、ssh/banner_flood.py 的做法）：
  - 全程「不」送出任何帳號、密碼或任何 Telnet IAC 協商回覆，僅做「連線 -> 讀取
    對方主動送出的初始資料（IAC 協商序列或文字 banner）-> 關閉」，絕不嘗試任何
    帳密組合（no login/credential attempts of any kind）。
  - 不偽造來源位址，所有連線皆由執行本測試的機器真實發起。
  - 速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。
需求：無額外套件，純標準函式庫。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "Telnet 連線洪水（connect/banner 讀取循環）"
CATEGORY = "Telnet"
PROTOCOL = "TCP"
DEFAULT_PORT = 23
TEST_TYPE = "resource"  # 連線建立 + banner 讀取 + 關閉循環（churn）


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 50000, "min": 1, "max": 50000, "desc": "每秒建立的連線次數"},
        "connect_timeout": {"type": "float", "default": 2.0, "min": 0.5, "max": 5.0, "desc": "單次連線/讀取逾時秒數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 80))
    timeout = float(params.get("connect_timeout", 2.0))

    limiter = RateLimiter(rate)
    stats = {"connected": 0, "data_received": 0, "no_data": 0, "errors": 0}
    start = time.time()

    log_fn(f"[+] Telnet 連線洪水 -> {target}:{port} @ {rate}/s, {duration}s（不送出任何帳密）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            stats["connected"] += 1
            data = s.recv(256)
            if data:
                stats["data_received"] += 1
            else:
                stats["no_data"] += 1
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
        "data_received": stats["data_received"],
        "no_data": stats["no_data"],
        "errors": stats["errors"],
        "elapsed_sec": round(time.time() - start, 1),
    }
