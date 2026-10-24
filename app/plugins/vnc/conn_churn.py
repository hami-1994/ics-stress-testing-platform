"""
測項：VNC 連線洪水（RFB 版本交握循環）
分類：VNC（標準埠 5900/TCP）
說明：VNC（RFB 協定）是 ICS/SCADA 環境 HMI 主機常見的遠端桌面暴露面（比
     RDP 更常出現在工控環境，因為許多老舊 HMI/工程師站只支援 VNC），且
     RFB 版本交握是連線建立的第一步，發生在任何驗證機制之前。快速建立又
     斷開連線並完成版本號交換，測試對象在「驗證前」階段的連線處理能力。

實作：依 RFC 6143（The Remote Framebuffer Protocol）標準格式，連線後 Server
會主動送出 12 bytes 版本字串（形如 "RFB 003.008\\n"），Client 依規範應回覆
相同格式的版本字串完成版本協商，之後才會進入 Security Type 協商/驗證階段。
本測項只做到「讀取版本字串 -> 回覆版本字串 -> 關閉」，不繼續進行 Security
Type 選擇或任何形式的驗證流程。

安全設計（重要）：
  - 全程「不」進行 Security Type 協商、不嘗試 VNC Authentication（DES 挑戰-
    回應）或任何密碼/金鑰，純粹是版本交握層級的連線 churn 測試（no auth
    attempts of any kind）。
  - 不偽造來源位址；速率透過 RateLimiter 控制；duration 經 clamp_duration()
    限制。
需求：無額外套件，純標準函式庫。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "VNC 連線洪水（RFB 版本交握循環）"
CATEGORY = "VNC"
PROTOCOL = "TCP"
DEFAULT_PORT = 5900
TEST_TYPE = "resource"  # 連線建立 + RFB 版本交握 + 關閉循環（churn）


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 50000, "min": 1, "max": 50000, "desc": "每秒建立的連線次數"},
        "connect_timeout": {"type": "float", "default": 2.0, "min": 0.5, "max": 5.0, "desc": "單次連線/收送逾時秒數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 60))
    timeout = float(params.get("connect_timeout", 2.0))

    limiter = RateLimiter(rate)
    stats = {"connected": 0, "rfb_banner_ok": 0, "no_banner": 0, "errors": 0}
    start = time.time()

    log_fn(f"[+] VNC 連線洪水 -> {target}:{port} @ {rate}/s, {duration}s（僅版本交握，不進行任何驗證）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            stats["connected"] += 1
            banner = s.recv(12)
            if banner.startswith(b"RFB "):
                stats["rfb_banner_ok"] += 1
                s.sendall(banner)  # 依協定回覆相同版本字串完成版本協商，之後即斷線
            else:
                stats["no_banner"] += 1
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
        "rfb_banner_ok": stats["rfb_banner_ok"],
        "no_banner": stats["no_banner"],
        "errors": stats["errors"],
        "elapsed_sec": round(time.time() - start, 1),
    }
