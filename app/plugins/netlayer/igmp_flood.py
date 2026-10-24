"""
測項：IGMP Membership Report/Query 洪水
分類：網路層 (ARP/ICMP/IGMP/LLDP)（Layer 2/3 多點群播群組管理，無 TCP/UDP Port 概念）
說明：以可控速率持續送出 IGMPv2 Membership Report（或 Query）封包，
     target 視為受測的多點群播群組位址（例如受測工控環境常用的群播位址），
     測試支援 IGMP Snooping 的交換器/路由器在高頻群組異動下的處理能力
     與群組成員表（snooping table）負載——這是工業乙太網路交換器常見的
     可用性測試面向。

安全設計（重要）：
  - 來源 MAC/IP 由 scapy 依 iface 自動帶入本機真實位址，「不」偽造來源。
  - 目的群播 IP 固定為 Orchestrator 傳入的 target（視為受測群播位址），
    目的 MAC 依 IPv4 群播對應規則由群播 IP 自動換算，不指向任何第三方。
  - 速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。
需求：scapy（含 IGMP 層，多數發行版隨附於 scapy.contrib.igmp），
     且需要 root 或 CAP_NET_RAW 權限。
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "IGMP Membership Report/Query 洪水"
CATEGORY = "網路層 (ARP/ICMP/IGMP/LLDP)"
PROTOCOL = "L2"
TEST_TYPE = "traffic"  # 流量型：IGMP Report/Query 群播封包洪水，靠封包速率本身造成負擔

def get_param_schema() -> dict:
    return {
        "iface": {"type": "string", "default": "eth0", "desc": "發送用網路介面"},
        "igmp_type": {
            "type": "string", "default": "report",
            "desc": "report=IGMPv2 Membership Report(0x16)；query=Membership Query(0x11)",
        },
        "rate_pps": {"type": "int", "default": 500000, "min": 1, "max": 500000, "desc": "每秒送出封包數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from scapy.all import Ether, IP, sendp
    except ImportError:
        log_fn("[!] 未安裝 scapy，請先執行 pip install scapy")
        return {"packets_sent": 0, "error": "scapy not installed"}
    try:
        from scapy.contrib.igmp import IGMP
    except ImportError:
        log_fn("[!] 目前安裝的 scapy 缺少 IGMP 模組（scapy.contrib.igmp），請確認 scapy 版本或安裝完整版")
        return {"packets_sent": 0, "error": "scapy.contrib.igmp not available"}

    duration = clamp_duration(duration)
    iface = params.get("iface", "eth0")
    igmp_type = 0x16 if str(params.get("igmp_type", "report")).lower() != "query" else 0x11
    rate = int(params.get("rate_pps", 2500))

    # 群播 IP -> 群播 MAC 的標準對應規則：01:00:5e + IP 低 23 bits
    try:
        octets = [int(x) for x in target.split(".")]
        mac = "01:00:5e:%02x:%02x:%02x" % (octets[1] & 0x7F, octets[2], octets[3])
    except (ValueError, IndexError):
        mac = "01:00:5e:00:00:01"

    pkt = Ether(dst=mac) / IP(dst=target, ttl=1) / IGMP(type=igmp_type, gaddr=target)
    limiter = RateLimiter(rate)
    sent, errors = 0, 0
    start = time.time()

    log_fn(f"[+] IGMP {('Report' if igmp_type == 0x16 else 'Query')} 洪水 -> group {target}（iface={iface}, {rate}pps, {duration}s）")
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
