"""
測項：Modbus TCP 訊框長度邊界異常測試（Malformed/Oversized PDU Boundary Test）
分類：Modbus TCP
說明：Modbus TCP ADU（MBAP Header + PDU）的 MBAP「Length」欄位理論上必須與其後
實際攜帶的 Unit ID + PDU 位元組數一致；許多低成本 ICS Modbus Slave/Gateway 韌體
對這個欄位的輸入驗證並不嚴謹（業界曾有實際案例是因為 Length 與實際資料不符而
導致緩衝區溢位/服務中斷）。本測項固定送出幾種「Length 欄位與實際資料不一致」的
邊界框（宣告長度大於實際內容、宣告長度小於實際內容、宣告 Modbus 協定上限附近的
極端值、零長度 PDU 等），重複發送以觀察 Slave 對邊界情境輸入驗證的健全性——這不是
任意亂數 fuzzing，而是幾種明確定義的邊界條件框，並且全程走正常 TCP 連線（不偽造
來源）。

實作：原生 socket 直接組 MBAP + PDU bytes（pymodbus 的高階 API 不允許送出長度欄位
不合法的訊框，因此這裡改用底層 socket），迴圈受 duration + stop_event + RateLimiter
控制；若連線因異常框被裝置關閉，會嘗試重新連線並繼續測試至時間結束。
"""
import itertools
import socket
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "Modbus TCP 訊框長度邊界異常測試"
CATEGORY = "Modbus TCP"
PROTOCOL = "TCP"
DEFAULT_PORT = 502
TEST_TYPE = "resource"  # 畸形/邊界異常 MBAP 長度欄位測試


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 7500, "min": 1, "max": 7500, "desc": "每秒送出邊界異常框數（僅調整流量大小，不改變邊界異常的內容/嚴重程度）"},
        "unit_id": {"type": "int", "default": 1, "min": 0, "max": 247, "desc": "Slave ID"},
    }


def _boundary_frames(unit_id: int, txn_start: int):
    """回傳一組 (說明, bytes) 的邊界異常 Modbus TCP ADU 清單。"""
    frames = []

    # 1) 宣告 Length 大於實際附加資料（FC03 請求，宣告長度比實際多 20 bytes）
    pdu1 = struct.pack(">BHH", 0x03, 0x0000, 0x007D)  # FC03, addr=0, count=125
    mbap1 = struct.pack(">HHHB", txn_start, 0x0000, len(pdu1) + 1 + 20, unit_id)
    frames.append(("length_larger_than_actual", mbap1 + pdu1))

    # 2) 宣告 Length 小於實際附加資料（宣告只有 2 bytes，實際附上完整 FC16 請求）
    values = b"\x00\x00" * 10
    pdu2 = struct.pack(">BHHB", 0x10, 0x0000, 0x000A, 20) + values  # FC16 寫入10個暫存器
    mbap2 = struct.pack(">HHHB", txn_start + 1, 0x0000, 2, unit_id)
    frames.append(("length_smaller_than_actual", mbap2 + pdu2))

    # 3) Length 欄位使用協定上限附近的極端值（0xFFFF），但實際只附上極小 PDU
    pdu3 = struct.pack(">B", 0x03)  # 只有 function code，缺 address/count
    mbap3 = struct.pack(">HHHB", txn_start + 2, 0x0000, 0xFFFF, unit_id)
    frames.append(("extreme_max_length_truncated_pdu", mbap3 + pdu3))

    # 4) 只有 MBAP header，PDU 完全省略（零長度 PDU）
    mbap4 = struct.pack(">HHHB", txn_start + 3, 0x0000, 1, unit_id)
    frames.append(("zero_length_pdu", mbap4))

    # 5) Length 欄位與實際附加資料一致，但 PDU 內容本身不完整
    #    （用來測試「長度沒有異常但內容不完整」的另一種邊界，與情境1~3的長度不一致不同）
    pdu5 = struct.pack(">B", 0x03)
    mbap5 = struct.pack(">HHHB", txn_start + 4, 0x0000, len(pdu5) + 1, unit_id)
    frames.append(("length_matches_but_pdu_incomplete", mbap5 + pdu5))

    return frames


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 10))
    unit_id = int(params.get("unit_id", 1))

    limiter = RateLimiter(rate)
    sent, responses, timeouts, reconnects = 0, 0, 0, 0
    start = time.time()
    txn = 1

    def _connect():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        s.connect((target, port))
        return s

    try:
        sock = _connect()
    except OSError as e:
        log_fn(f"[!] 無法連線 {target}:{port}：{e}")
        return {"frames_sent": 0, "connected": False, "error": str(e)}

    log_fn(f"[+] 開始 Modbus 長度邊界異常框測試 @ {rate}/s -> {target}:{port}")
    frame_cycle = itertools.cycle(range(5))

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        frames = _boundary_frames(unit_id, txn)
        txn = (txn + 5) % 0xFFFF
        _, data = frames[next(frame_cycle)]
        try:
            sock.sendall(data)
            sent += 1
            try:
                resp = sock.recv(256)
                if resp:
                    responses += 1
            except socket.timeout:
                timeouts += 1
        except OSError as e:
            log_fn(f"[!] 連線異常（可能是裝置因異常框關閉連線）：{e}，嘗試重新連線")
            try:
                sock.close()
            except OSError:
                pass
            try:
                sock = _connect()
                reconnects += 1
            except OSError as e2:
                log_fn(f"[!] 重新連線失敗：{e2}")
                break

    try:
        sock.close()
    except OSError:
        pass

    elapsed = time.time() - start
    log_fn(
        f"[+] 完成，送出 {sent} 個邊界框，收到回應 {responses} 次，逾時 {timeouts} 次，重連 {reconnects} 次"
    )
    return {
        "frames_sent": sent,
        "responses": responses,
        "timeouts": timeouts,
        "reconnects": reconnects,
        "elapsed_sec": round(elapsed, 1),
    }
