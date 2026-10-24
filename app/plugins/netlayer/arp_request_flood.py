"""
測項：ARP Request 洪水（Who-has）
分類：網路層 (ARP/ICMP/IGMP/LLDP)（Layer 2/3，無 TCP/UDP Port 概念）
說明：以可控速率持續送出 ARP who-has 請求，詢問 target IP 的 MAC 位址，
     測試同網段內交換器/路由器/裝置對 ARP 廣播流量的處理能力與 ARP 表
     更新負載——這是工控/辦公網路常見的基礎可用性測試面向，許多低階
     交換器或嵌入式裝置在高頻 ARP 廣播下會出現 CPU 飆高或 ARP 表溢位。

安全設計（重要）：
  - 「不」偽造來源 MAC/IP：來源欄位交由 scapy 依 iface 自動帶入本機真實
     MAC/IP，不採用類似 --rand-source 之類的偽造來源作法。
  - pdst（詢問對象）固定為 Orchestrator 傳入的 target，不會對其他位址發送。
  - 速率透過 RateLimiter 控制，並非無上限全速；duration 經 clamp_duration()
    限制。
需求：scapy，且需要 root 或 CAP_NET_RAW 權限才能送出 raw L2 frame。
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "ARP Request 洪水（Who-has）"
CATEGORY = "網路層 (ARP/ICMP/IGMP/LLDP)"
PROTOCOL = "L2"
TEST_TYPE = "traffic"  # 流量型：ARP 廣播封包洪水，靠封包速率本身造成負擔

def get_param_schema() -> dict:
    return {
        "iface": {"type": "string", "default": "eth0", "desc": "發送用網路介面"},
        "rate_pps": {"type": "int", "default": 800000, "min": 1, "max": 800000, "desc": "每秒送出封包數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from scapy.all import ARP, Ether, sendp
    except ImportError:
        log_fn("[!] 未安裝 scapy，請先執行 pip install scapy")
        return {"packets_sent": 0, "error": "scapy not installed"}

    duration = clamp_duration(duration)
    iface = params.get("iface", "eth0")
    rate = int(params.get("rate_pps", 4000))

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target)
    limiter = RateLimiter(rate)
    sent, errors = 0, 0
    start = time.time()

    log_fn(f"[+] ARP who-has 洪水 -> {target}（iface={iface}, {rate}pps, {duration}s）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
        except (PermissionError, OSError, ValueError) as e:
            # ValueError：scapy 在 iface 參數指向不存在的網路介面時丟出的例外類型，
            # 與 PermissionError/OSError 一併接住以涵蓋常見的發送失敗情境。
            errors += 1
            if errors <= 5:
                log_fn(f"[!] 發送失敗（權限、介面問題或介面名稱不存在）：{e}")
            if errors > 20:
                log_fn("[!] 連續發送失敗過多，提前中止")
                break

    return {"packets_sent": sent, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
