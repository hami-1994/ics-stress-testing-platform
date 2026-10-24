"""
測項：ICMP Echo (Ping) 洪水測試
分類：網路層 (ARP/ICMP/IGMP/LLDP)（Layer 3，無 TCP/UDP Port 概念）
說明：以可控速率持續送出 ICMP Echo Request 到 target，屬於典型的
     ping flood 可用性測試，用來評估目標裝置/防火牆對 ICMP 流量的處理
     能力（許多嵌入式裝置的網路 stack 在高頻 ICMP 下會影響其他服務的
     回應時間）。

這與平台既有的「Ping 監控」功能不同：監控功能是低頻率健康檢查，
本測項是「真正的壓力測試」，會以設定速率持續發送直到 duration 結束。

安全設計（重要）：
  - 使用 scapy 的 L3 send()（依路由表自動選擇本機出口介面與來源 IP），
    「不」偽造來源位址。
  - 只送往 Orchestrator 傳入的單一 target，不會對其他位址發送。
  - 速率透過 RateLimiter 控制，並非無上限全速（不使用 `ping -f`／
    `hping3 --flood` 的無限全速模式）；duration 經 clamp_duration() 限制。
需求：scapy，且需要 root 或 CAP_NET_RAW 權限才能送出 raw ICMP 封包。
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "ICMP Echo (Ping) 洪水測試"
CATEGORY = "網路層 (ARP/ICMP/IGMP/LLDP)"
PROTOCOL = "L2"
TEST_TYPE = "traffic"  # 流量型：ICMP Echo Request 洪水，靠封包速率本身造成負擔

def get_param_schema() -> dict:
    return {
        "rate_pps": {"type": "int", "default": 800000, "min": 1, "max": 800000, "desc": "每秒送出封包數"},
        "payload_size": {"type": "int", "default": 56, "min": 0, "max": 1400, "desc": "ICMP 資料欄位大小(bytes)"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from scapy.all import ICMP, IP, Raw, send
    except ImportError:
        log_fn("[!] 未安裝 scapy，請先執行 pip install scapy")
        return {"packets_sent": 0, "error": "scapy not installed"}

    duration = clamp_duration(duration)
    rate = int(params.get("rate_pps", 4000))
    size = int(params.get("payload_size", 56))
    payload = b"\x00" * size

    limiter = RateLimiter(rate)
    sent, errors = 0, 0
    seq = 0
    start = time.time()

    log_fn(f"[+] ICMP Echo 洪水 -> {target} @ {rate}pps, {duration}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        seq = (seq + 1) & 0xFFFF
        pkt = IP(dst=target) / ICMP(id=0x1234, seq=seq) / Raw(load=payload)
        try:
            send(pkt, verbose=False)
            sent += 1
        except (PermissionError, OSError) as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] 發送失敗（權限或路由問題）：{e}")
            if errors > 20:
                log_fn("[!] 連續發送失敗過多，提前中止")
                break

    return {"packets_sent": sent, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
