"""
測項：Modbus FC16（Write Multiple Registers）高頻率寫入風暴
分類：Modbus TCP
說明：相對於唯讀的 FC03 高頻率讀取（fc03_high_freq_read.py），FC16 屬於「寫入路徑」，
會實際改變 Slave 上暫存器的內容，也往往牽涉 Slave 韌體額外的驗證/落盤/生效流程
（例如觸發 watchdog 重置計時器、寫回 flash、通知上層應用等），因此高頻率 FC16
寫入請求對 Slave 造成的負載模式與純讀取不同，也更貼近「寫入路徑資源耗盡」這類
真實情境下的壓力測試。

安全設計：
  - 預設寫入位址/暫存器數量皆可調整，且刻意提供固定的 write_value（而非隨機值），
    降低誤寫入造成不可預期行為的風險；正式測試前務必確認目標暫存器範圍是測試用、
    非實際控制用途的暫存器。
  - 沿用 pymodbus 原生 client（同 fc03_high_freq_read.py），迴圈受 duration + stop_event
    + RateLimiter 控制，不提供無限全速模式。
需求套件：pip install pymodbus
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "Modbus FC16 暫存器高頻率寫入"
CATEGORY = "Modbus TCP"
PROTOCOL = "TCP"
DEFAULT_PORT = 502
TEST_TYPE = "traffic"  # 高頻率寫入洪水，靠請求速率造成負擔


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 40000, "min": 1, "max": 40000, "desc": "每秒寫入次數"},
        "register_addr": {"type": "int", "default": 100, "min": 0, "max": 65535, "desc": "起始暫存器位址（請避開實際控制用途暫存器）"},
        "register_count": {"type": "int", "default": 10, "min": 1, "max": 123, "desc": "一次寫入暫存器數量（FC16 上限123）"},
        "write_value": {"type": "int", "default": 0, "min": 0, "max": 65535, "desc": "寫入值（固定值，降低誤寫入風險）"},
        "unit_id": {"type": "int", "default": 1, "min": 0, "max": 247, "desc": "Slave ID"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from pymodbus.client import ModbusTcpClient
    except ImportError:
        log_fn("[!] 未安裝 pymodbus，請先執行 pip install pymodbus")
        return {"ok": 0, "fail": 0, "error": "pymodbus not installed"}

    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 90))
    addr = int(params.get("register_addr", 100))
    count = int(params.get("register_count", 10))
    value = int(params.get("write_value", 0))
    unit = int(params.get("unit_id", 1))

    client = ModbusTcpClient(target, port=port)
    if not client.connect():
        log_fn(f"[!] 無法連線 {target}:{port}")
        return {"ok": 0, "fail": 0, "connected": False}

    values = [value] * count
    limiter = RateLimiter(rate)
    ok, fail = 0, 0
    start = time.time()
    log_fn(f"[+] 開始高頻率 FC16 寫入 @ {rate}/s，addr={addr}, count={count}, value={value}")

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            rr = client.write_registers(addr, values, slave=unit)
            if rr.isError():
                fail += 1
            else:
                ok += 1
        except Exception:  # noqa: BLE001  現場各種 Modbus/連線例外都要能繼續下一輪
            fail += 1

    client.close()
    log_fn(f"[+] 完成，成功 {ok} 次，失敗 {fail} 次")
    return {"ok": ok, "fail": fail, "elapsed_sec": round(time.time() - start, 1)}
