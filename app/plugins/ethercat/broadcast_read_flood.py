"""
測項：EtherCAT Broadcast Read (BRD) 命令注入風暴
分類：EtherCAT（Layer 2，EtherType 0x88A4）
說明：BRD（Broadcast Read，Cmd=7）是 EtherCAT 主站常用於掃描匯流排上所有 Slave
數量/狀態的標準命令（datagram 經過每個 Slave 時都要遞增 Working Counter 並視需要
附加讀取資料再往下傳遞）。與既有的 ethercat/l2_frame_flood.py（單純注入固定原始
位元組、命令類型未特別區分）不同，本測項明確使用 BRD 命令類型並依規格動態組出
Datagram Header，以高頻率灌入，模擬對匯流排廣播掃描路徑的持續壓力，測試 Slave
控制器（ESC）在「每一顆 Slave 都要處理、轉發並累加」這類廣播型命令下的即時處理裕度。

重要限制：同 l2_frame_flood.py，這是 Layer 2 廣播，僅能在受測、已授權的隔離實體
網段上執行；target 欄位僅供記錄，實際發送對象為乙太網路廣播位址。訊框欄位配置
依 EtherCAT 標準（ETG.1000）公開規範的 Frame Header / Datagram Header 位元配置
手動組出，未經真實 EtherCAT 主站/從站硬體逐位元驗證，如與特定廠牌韌體行為不符，
請以實際抓包比對調整。
需求：scapy、且需要 root 或 CAP_NET_RAW 權限。
"""
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "EtherCAT Broadcast Read (BRD) 命令注入風暴"
CATEGORY = "EtherCAT"
PROTOCOL = "L2"
TEST_TYPE = "traffic"  # 流量型：BRD 廣播 datagram 注入洪水，靠封包速率本身造成負擔


def get_param_schema() -> dict:
    return {
        "iface": {"type": "string", "default": "eth0", "desc": "發送用網路介面"},
        "rate_pps": {"type": "int", "default": 800000, "min": 1, "max": 800000, "desc": "每秒送出 datagram 數"},
        "data_len": {"type": "int", "default": 2, "min": 0, "max": 64, "desc": "BRD 資料區長度(bytes)"},
    }


def _build_ecat_brd_payload(idx: int, data_len: int) -> bytes:
    """組出一個 EtherCAT Header + 單一 BRD Datagram 的原始 payload（不含 Ethernet Header）。"""
    cmd = 7  # BRD = Broadcast Read
    adp = 0x0000  # Auto-increment 位址，廣播讀取時通常為 0
    ado = 0x0000  # 暫存器位址（示範用，指向 0x0000）
    data = b"\x00" * data_len
    wkc = b"\x00\x00"  # Working Counter，請求端送出時填 0，由沿途 Slave 遞增

    round_trip_c = 0  # C bit：是否還有後續 datagram（此處僅單一 datagram）
    more_m = 0  # M bit：保留
    len_m = (data_len & 0x07FF) | (round_trip_c << 14) | (more_m << 15)

    # Datagram Header：Cmd(1) + Idx(1) + ADP(2) + ADO(2) + LenM(2) + IRQ(2) = 10 bytes
    dgram_header = struct.pack("<BBHHH", cmd, idx & 0xFF, adp, ado, len_m) + b"\x00\x00"
    dgram = dgram_header + data + wkc

    total_len = len(dgram)
    ecat_header_val = (total_len & 0x07FF) | (1 << 12)  # type=1 表示 EtherCAT command
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
    rate = int(params.get("rate_pps", 4000))
    data_len = int(params.get("data_len", 2))
    dst_mac = "ff:ff:ff:ff:ff:ff"  # BRD 語意上就是對匯流排上所有 Slave 廣播

    limiter = RateLimiter(rate)
    sent = 0
    idx = 0
    start = time.time()

    log_fn(f"[+] EtherCAT BRD 廣播讀取風暴 -> iface={iface}, {rate}pps, {duration}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        payload = _build_ecat_brd_payload(idx, data_len)
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
