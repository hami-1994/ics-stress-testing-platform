"""
測項：RDP X.224 Connection Request PDU 洪水
分類：RDP（預設埠 3389/TCP）
說明：模擬大量用戶端快速建立 TCP 連線並送出 RDP 交握第一步——TPKT 封裝的
     X.224 Connection Request PDU（含標準 RDP Negotiation Request，宣告支援
     PROTOCOL_SSL/PROTOCOL_HYBRID）——然後立即斷線，測試終端伺服器/RDP 閘道器
     在交握初期階段的連線處理能力。這是 nmap rdp-enum-encryption、masscan 等
     工具在做 RDP 服務探測時使用的相同最小交握封包。

安全設計（重要）：
  - 僅送出 X.224 Connection Request（交握第一步），完全不進行 TLS/CredSSP/NLA
    交握，更「不」涉及任何使用者名稱、密碼或憑證，純粹是連線層級/交握初期的
    負載測試。
  - 封包位元組是依公開文件（[MS-RDPBCP]、ITU-T T.123）組出的最小交握封包，
    採業界工具常用的固定 byte layout，屬「best-effort 最小探測封包」，
    未針對所有 RDP 伺服器實作版本逐一驗證相容性，測試結果僅供參考。
  - 不偽造來源位址，所有連線皆由執行本測試的機器真實發起。
  - 速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "RDP X.224 Connection Request 洪水"
CATEGORY = "RDP"
PROTOCOL = "TCP"
DEFAULT_PORT = 3389
TEST_TYPE = "resource"  # 連線建立 + X.224 交握 + 關閉循環（churn）

# 標準最小 RDP 交握封包：TPKT header + X.224 CR TPDU + RDP Negotiation Request
# (requestedProtocols = PROTOCOL_SSL | PROTOCOL_HYBRID = 0x00000003)
# TPKT length=0x0013(19)、X.224 length indicator=0x0e(14)，
# 業界工具（nmap rdp-enum-encryption 等）常用的公開已知 byte layout。
_X224_CR_PDU = bytes.fromhex(
    "03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 03 00 00 00".replace(" ", "")
)


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {
            "type": "int", "default": 50000, "min": 1, "max": 50000,
            "desc": "每秒建立的連線 + X.224 交握次數",
        },
        "connect_timeout": {
            "type": "float", "default": 2.0, "min": 0.5, "max": 5.0,
            "desc": "單次連線/收送逾時秒數",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 120))
    timeout = float(params.get("connect_timeout", 2.0))

    limiter = RateLimiter(rate)
    stats = {"connected": 0, "cc_received": 0, "no_response": 0, "errors": 0}
    start = time.time()

    log_fn(f"[+] RDP X.224 Connection Request 洪水 -> {target}:{port} @ {rate}/s, {duration}s（無憑證交握）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            stats["connected"] += 1
            s.sendall(_X224_CR_PDU)
            resp = s.recv(4096)
            if resp and len(resp) >= 4 and resp[0] == 0x03:
                stats["cc_received"] += 1
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
        "cc_received": stats["cc_received"],
        "no_response": stats["no_response"],
        "errors": stats["errors"],
        "elapsed_sec": round(time.time() - start, 1),
    }
