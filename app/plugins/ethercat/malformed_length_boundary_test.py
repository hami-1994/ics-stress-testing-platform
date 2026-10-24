"""
測項：EtherCAT 訊框長度邊界異常測試
分類：EtherCAT（Layer 2，EtherType 0x88A4）
說明：EtherCAT 訊框（EtherCAT Header 的 11-bit Length 欄位／Datagram Header 的 Len
欄位）理論上必須與實際附加的資料長度一致；真實 ESC（EtherCAT Slave Controller）
或韌體堆疊若未正確驗證這些長度欄位，可能發生緩衝區溢位/欠讀等問題。本測項送出
一組固定的「長度欄位與實際資料不一致」邊界框（宣告長度大於/小於實際內容、宣告
11-bit 最大長度但內容截斷、缺少必要的 WKC 尾端欄位等），用來測試受測 Slave 對
長度欄位的輸入驗證健全性——這不是任意亂數 fuzzing，而是幾種明確定義的邊界情境，
重複發送以觀察是否觸發異常/當機/停止回應。

重要限制：同 l2_frame_flood.py，這是 Layer 2 廣播/單播注入，僅能在受測、已授權的
隔離實體網段上執行；target 欄位僅供記錄，實際發送對象由 dst_mac 決定。訊框位元
欄位配置依 ETG.1000 公開規範手動組出，未經真實硬體逐位元驗證。
需求：scapy、且需要 root 或 CAP_NET_RAW 權限。
"""
import itertools
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "EtherCAT 訊框長度邊界異常測試"
CATEGORY = "EtherCAT"
PROTOCOL = "L2"
TEST_TYPE = "resource"  # 畸形/邊界異常：EtherCAT Header/Datagram 長度欄位與實際內容不一致


def get_param_schema() -> dict:
    return {
        "iface": {"type": "string", "default": "eth0", "desc": "發送用網路介面"},
        "dst_mac": {"type": "string", "default": "ff:ff:ff:ff:ff:ff", "desc": "目的 MAC（廣播或指定 Slave MAC）"},
        "rate_pps": {"type": "int", "default": 300000, "min": 1, "max": 300000, "desc": "每秒送出邊界異常框數（僅調整流量大小，不改變邊界異常的內容/嚴重程度）"},
    }


def _boundary_payloads():
    """組出幾種長度欄位與實際資料不一致的邊界框，回傳 bytes 清單（不含 Ethernet Header）。"""
    payloads = []

    # 1) EtherCAT Header 宣告長度為 0，但實際仍附上完整 datagram（宣告值小於實際內容）
    dgram1 = struct.pack("<BBHHH", 4, 1, 0x0000, 0x0000, 2) + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    hdr1 = struct.pack("<H", (0 & 0x07FF) | (1 << 12))
    payloads.append(hdr1 + dgram1)

    # 2) EtherCAT Header 宣告 11-bit 最大長度 2047，但實際只附上最小 datagram（宣告值遠大於實際內容）
    dgram2 = struct.pack("<BBHHH", 4, 2, 0x0000, 0x0000, 0) + b"\x00\x00" + b"\x00\x00"
    hdr2 = struct.pack("<H", (2047 & 0x07FF) | (1 << 12))
    payloads.append(hdr2 + dgram2)

    # 3) Datagram 內部 Len 欄位宣告 60 bytes 資料，但實際只附上 4 bytes（datagram 內部長度不一致）
    dgram3 = struct.pack("<BBHHH", 4, 3, 0x0000, 0x0000, 60) + b"\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00"
    hdr3 = struct.pack("<H", (len(dgram3) & 0x07FF) | (1 << 12))
    payloads.append(hdr3 + dgram3)

    # 4) 缺少必要的 WKC(2 bytes) 尾端欄位（訊框短於最小合法 EtherCAT 訊框結構）
    dgram4 = struct.pack("<BBHHH", 4, 4, 0x0000, 0x0000, 0) + b"\x00\x00"  # 無 data、無 WKC
    hdr4 = struct.pack("<H", (len(dgram4) & 0x07FF) | (1 << 12))
    payloads.append(hdr4 + dgram4)

    return payloads


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from scapy.all import Ether, Raw, sendp
    except ImportError:
        log_fn("[!] 未安裝 scapy，請先執行 pip install scapy")
        return {"frames_sent": 0, "error": "scapy not installed"}

    duration = clamp_duration(duration)
    iface = params.get("iface", "eth0")
    dst_mac = params.get("dst_mac", "ff:ff:ff:ff:ff:ff")
    rate = int(params.get("rate_pps", 800))

    payload_cycle = itertools.cycle(_boundary_payloads())
    limiter = RateLimiter(rate)
    sent = 0
    start = time.time()

    log_fn(f"[+] EtherCAT 長度邊界異常框測試 -> iface={iface}, dst={dst_mac}, {rate}pps, {duration}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        pkt = Ether(dst=dst_mac, type=0x88A4) / Raw(load=next(payload_cycle))
        try:
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
        except (PermissionError, OSError, ValueError) as e:
            # 一併攔截 ValueError：scapy 在 iface 參數指向不存在的網路介面時會丟出
            # 這個例外類型，統一在此攔截並輸出清楚的錯誤訊息，避免原始 traceback 外洩。
            log_fn(f"[!] 發送失敗（權限、介面問題或介面名稱不存在）：{e}")
            break

    return {"frames_sent": sent, "elapsed_sec": round(time.time() - start, 1)}
