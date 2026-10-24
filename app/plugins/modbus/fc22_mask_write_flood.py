"""
測項：Modbus FC22（Mask Write Register）高頻率讀-改-寫風暴
分類：Modbus TCP（資源消耗型，非單純流量型）
說明：FC22 語意是「讀出目前暫存器值 → 用 AND mask 清位元 → 用 OR mask 設位元 → 寫回」，
規範定義的運算式是 Result = (Current Contents AND And_Mask) OR (Or_Mask AND (NOT And_Mask))。
跟 FC03/FC16 這種「單純讀」或「單純寫」不同，FC22 在 Slave 端通常牽涉：
  1) 讀取當前值（可能需要鎖定該暫存器，避免跟其他來源的讀寫競爭）
  2) 位元運算
  3) 寫回（часто連動 flash 落盤/影像暫存器更新/事件通知）
這一整套「讀-改-寫」在許多資源受限的嵌入式韌體上是用互斥鎖（mutex）保護的臨界區段，
高頻率送出 FC22 請求，除了測試流量處理能力，更是測試這個臨界區段/鎖競爭在高頻率下
是否會造成回應延遲劣化、逾時甚至死鎖——這是 fc16_write_flood.py（單純覆寫，不需要
先讀當前值）測不出來的資源消耗面向。

安全設計：
  - AND mask / OR mask 預設值為 0xFFFF / 0x0000，也就是「維持原值不變」的操作
    （Result = Current AND 0xFFFF = Current），只造成讀-改-寫路徑的 CPU/鎖競爭負載，
    不會實際改變目標暫存器內容，大幅降低誤動作風險；使用者仍可自行調整 mask 值，
    但正式測試前務必確認目標暫存器範圍是測試用途。
  - 沿用 pymodbus 原生 client（`mask_write_register`），迴圈受 duration + stop_event +
    RateLimiter 控制。若目標裝置的 pymodbus 版本沒有這個方法，會自動退回用原生 socket
    手刻 FC22 PDU（function code 0x16：address(2) + and_mask(2) + or_mask(2)）。
需求套件：pip install pymodbus
"""
import socket
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "Modbus FC22 讀改寫（Mask Write）風暴"
CATEGORY = "Modbus TCP"
PROTOCOL = "TCP"
DEFAULT_PORT = 502
TEST_TYPE = "resource"  # 讀-改-寫臨界區段鎖競爭，非單純比流量大小


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 40000, "min": 1, "max": 40000, "desc": "每秒讀改寫次數"},
        "register_addr": {"type": "int", "default": 100, "min": 0, "max": 65535, "desc": "目標暫存器位址（請避開實際控制用途暫存器）"},
        "and_mask": {"type": "int", "default": 65535, "min": 0, "max": 65535, "desc": "AND mask（預設 0xFFFF＝維持原值不變，僅造成讀改寫負載）"},
        "or_mask": {"type": "int", "default": 0, "min": 0, "max": 65535, "desc": "OR mask（預設 0＝維持原值不變）"},
        "unit_id": {"type": "int", "default": 1, "min": 0, "max": 247, "desc": "Slave ID"},
    }


def _raw_mask_write(sock, txn, unit_id, addr, and_mask, or_mask) -> bool:
    pdu = struct.pack(">BHHH", 0x16, addr, and_mask, or_mask)
    mbap = struct.pack(">HHHB", txn, 0x0000, len(pdu) + 1, unit_id)
    sock.sendall(mbap + pdu)
    try:
        resp = sock.recv(256)
        return bool(resp) and len(resp) >= 8 and resp[7] & 0x80 == 0
    except socket.timeout:
        return False


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 80))
    addr = int(params.get("register_addr", 100))
    and_mask = int(params.get("and_mask", 65535))
    or_mask = int(params.get("or_mask", 0))
    unit = int(params.get("unit_id", 1))

    ok, fail = 0, 0
    start = time.time()
    limiter = RateLimiter(rate)

    use_pymodbus = True
    client = None
    try:
        from pymodbus.client import ModbusTcpClient

        client = ModbusTcpClient(target, port=port)
        if not client.connect():
            log_fn(f"[!] 無法連線 {target}:{port}")
            return {"ok": 0, "fail": 0, "connected": False}
        if not hasattr(client, "mask_write_register"):
            use_pymodbus = False
    except ImportError:
        use_pymodbus = False

    raw_sock = None
    if not use_pymodbus:
        log_fn("[i] pymodbus 不可用或版本不支援 mask_write_register，改用原生 socket 手刻 FC22")
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(2.0)
            raw_sock.connect((target, port))
        except OSError as e:
            log_fn(f"[!] 無法連線 {target}:{port}：{e}")
            return {"ok": 0, "fail": 0, "connected": False, "error": str(e)}

    log_fn(f"[+] 開始 FC22 讀改寫風暴 @ {rate}/s，addr={addr}，and_mask=0x{and_mask:04X}，or_mask=0x{or_mask:04X}"
           f"（預設 mask 組合等效於「維持原值」，只造成讀改寫鎖競爭負載，不改變實際內容）")

    txn = 1
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            if use_pymodbus:
                rr = client.mask_write_register(address=addr, and_mask=and_mask, or_mask=or_mask, slave=unit)
                success = not rr.isError()
            else:
                success = _raw_mask_write(raw_sock, txn, unit, addr, and_mask, or_mask)
                txn = (txn + 1) % 0xFFFF
            if success:
                ok += 1
            else:
                fail += 1
        except Exception:  # noqa: BLE001  現場各種 Modbus/連線例外都要能繼續下一輪
            fail += 1

    if client:
        client.close()
    if raw_sock:
        try:
            raw_sock.close()
        except OSError:
            pass

    log_fn(f"[+] 完成，成功 {ok} 次，失敗 {fail} 次")
    return {"ok": ok, "fail": fail, "elapsed_sec": round(time.time() - start, 1)}
