"""
測項：SSH Banner 交換連線洪水
分類：SSH（預設埠 22/TCP）
說明：模擬大量用戶端快速連線 sshd、完成 TCP 交握並讀取 SSH 版本 banner
     （形如 "SSH-2.0-OpenSSH_9.x"）後立即斷線的負載，測試 sshd 的
     MaxStartups / pre-auth 連線併發上限與資源回收速度——這是實務上常見的
     sshd DoS 面向之一（大量 pre-auth 連線耗盡 MaxStartups 額度）。

安全設計（重要）：
  - 全程僅止於「TCP 連線 + 讀取對方送出的第一行 banner」，不進行 SSH 版本協商
    以外的任何動作，「絕對不」嘗試 KEXINIT、不建立金鑰交換、更不會嘗試任何
    使用者名稱/密碼或金鑰驗證（no auth attempts of any kind）。純粹是連線層級的
    負載測試。
  - 不偽造來源位址，所有連線皆由執行本測試的機器真實發起。
  - 速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "SSH Banner 交換連線洪水"
CATEGORY = "SSH"
PROTOCOL = "TCP"
DEFAULT_PORT = 22
TEST_TYPE = "traffic"  # 靠連線+banner讀取的高頻率速率造成負擔的洪水攻擊


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {
            "type": "int", "default": 80000, "min": 1, "max": 80000,
            "desc": "每秒建立的連線次數",
        },
        "connect_timeout": {
            "type": "float", "default": 2.0, "min": 0.5, "max": 5.0,
            "desc": "單次連線/讀取 banner 逾時秒數",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 150))
    timeout = float(params.get("connect_timeout", 2.0))

    limiter = RateLimiter(rate)
    stats = {"connected": 0, "banner_ok": 0, "no_banner": 0, "errors": 0}
    start = time.time()

    log_fn(f"[+] SSH Banner 連線洪水 -> {target}:{port} @ {rate}/s, {duration}s（不進行任何驗證）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            stats["connected"] += 1
            banner = s.recv(256)
            if banner.startswith(b"SSH-"):
                stats["banner_ok"] += 1
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
        "banner_ok": stats["banner_ok"],
        "no_banner": stats["no_banner"],
        "errors": stats["errors"],
        "elapsed_sec": round(time.time() - start, 1),
    }
