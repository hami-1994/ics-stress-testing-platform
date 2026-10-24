"""
測項：LLDP Frame 洪水
分類：網路層 (ARP/ICMP/IGMP/LLDP)（純 Layer 2，EtherType 0x88CC，無 IP/Port）
說明：以可控速率持續送出最小合法的 LLDP（Link Layer Discovery Protocol）
     frame（Chassis ID + Port ID + TTL + End of LLDPDU），送往標準的
     Nearest Bridge 群播位址 01:80:c2:00:00:0e，測試交換器/工控裝置對
     LLDP 鄰居探索訊框的處理能力——很多交換器/工業裝置的 LLDP 代理需要
     解析並更新鄰居表，高頻 LLDP 流量是常見的可用性測試面向。

重要限制（與 EtherCAT L2 測項一致的既有慣例）：
  - LLDP 是純 Layer 2 協定，本身沒有 IP 定址概念，目的位址固定為協定規範
    的標準群播 MAC（並非可任意指定的第三方位址）；因此這裡的 target 欄位
    僅供記錄用途（例如記錄受測產線/網段名稱），實際發送對象由協定規範
    決定，操作者需確保是在受測、已授權的實體/隔離網段上執行。
  - Chassis ID 使用本機真實網卡 MAC（透過 scapy get_if_hwaddr 取得），
    「不」偽造來源位址。
  - 速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。
需求：scapy（含 LLDP 層，位於 scapy.contrib.lldp），
     且需要 root 或 CAP_NET_RAW 權限。
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "LLDP Frame 洪水"
CATEGORY = "網路層 (ARP/ICMP/IGMP/LLDP)"
PROTOCOL = "L2"
TEST_TYPE = "traffic"  # 流量型：LLDP frame 廣播洪水，靠封包速率本身造成負擔

_LLDP_MULTICAST_MAC = "01:80:c2:00:00:0e"  # Nearest Bridge，LLDP 標準目的位址


def get_param_schema() -> dict:
    return {
        "iface": {"type": "string", "default": "eth0", "desc": "發送用網路介面"},
        "rate_pps": {"type": "int", "default": 350000, "min": 1, "max": 350000, "desc": "每秒送出封包數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from scapy.all import Ether, get_if_hwaddr, sendp
    except ImportError:
        log_fn("[!] 未安裝 scapy，請先執行 pip install scapy")
        return {"frames_sent": 0, "error": "scapy not installed"}
    try:
        from scapy.contrib.lldp import (
            LLDPDU,
            LLDPDUChassisID,
            LLDPDUEndOfLLDPDU,
            LLDPDUPortID,
            LLDPDUTimeToLive,
        )
    except ImportError:
        log_fn("[!] 目前安裝的 scapy 缺少 LLDP 模組（scapy.contrib.lldp），請確認 scapy 版本或安裝完整版")
        return {"frames_sent": 0, "error": "scapy.contrib.lldp not available"}

    duration = clamp_duration(duration)
    iface = params.get("iface", "eth0")
    rate = int(params.get("rate_pps", 1200))

    try:
        own_mac = get_if_hwaddr(iface)
    except OSError as e:
        log_fn(f"[!] 無法取得介面 {iface} 的 MAC 位址：{e}")
        return {"frames_sent": 0, "error": str(e)}

    lldpdu = (
        LLDPDUChassisID(subtype=4, id=own_mac)  # subtype 4 = MAC address（IEEE 802.1AB Table 8-2 正確）
        / LLDPDUPortID(subtype=7, id="stress-test")  # subtype 7 = Locally assigned；IEEE 802.1AB Table 8-3 中
                                                       # subtype 1 為 Interface Alias、subtype 2 為 Port Component，
                                                       # 兩者皆非任意字串語意，因此使用 subtype 7（本地自訂），
                                                       # 與 "stress-test" 這類無特定格式字串相符。
        / LLDPDUTimeToLive(ttl=120)
        / LLDPDUEndOfLLDPDU()
    )
    pkt = Ether(src=own_mac, dst=_LLDP_MULTICAST_MAC, type=0x88CC) / lldpdu

    limiter = RateLimiter(rate)
    sent, errors = 0, 0
    start = time.time()

    log_fn(f"[+] LLDP frame 洪水 -> iface={iface}（記錄用 target={target}）, {rate}pps, {duration}s")
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

    return {"frames_sent": sent, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
