"""
測項：Modbus FC03（Read Holding Registers）高頻率高載讀取
分類：Modbus TCP
用途：測試 Modbus Slave 對高頻率讀取請求的處理能力/回應延遲劣化情況。

實作：使用 pymodbus 原生 client，迴圈受 duration + stop_event 控制以確保測試
     時長與停止機制可控，並可直接統計成功/失敗次數與耗時，便於彙整進測試報告。
需求套件：pip install pymodbus
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "Modbus FC03 暫存器高頻率讀取"
CATEGORY = "Modbus TCP"
PROTOCOL = "TCP"
DEFAULT_PORT = 502
TEST_TYPE = "traffic"  # 高頻率讀取洪水，靠請求速率造成負擔


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 100000, "min": 1, "max": 100000, "desc": "每秒讀取次數"},
        "register_addr": {"type": "int", "default": 1, "min": 0, "max": 65535, "desc": "起始暫存器位址"},
        "register_count": {"type": "int", "default": 125, "min": 1, "max": 125, "desc": "一次讀取數量（Modbus 上限125）"},
        "unit_id": {"type": "int", "default": 1, "min": 0, "max": 247, "desc": "Slave ID"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from pymodbus.client import ModbusTcpClient
    except ImportError:
        log_fn("[!] 未安裝 pymodbus，請先執行 pip install pymodbus")
        return {"ok": 0, "fail": 0, "error": "pymodbus not installed"}

    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 150))
    addr = int(params.get("register_addr", 1))
    count = int(params.get("register_count", 125))
    unit = int(params.get("unit_id", 1))

    client = ModbusTcpClient(target, port=port)
    if not client.connect():
        log_fn(f"[!] 無法連線 {target}:{port}")
        return {"ok": 0, "fail": 0, "connected": False}

    limiter = RateLimiter(rate)
    ok, fail = 0, 0
    start = time.time()
    log_fn(f"[+] 開始高頻率 FC03 讀取 @ {rate}/s，addr={addr}, count={count}")

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            rr = client.read_holding_registers(addr, count=count, slave=unit)
            if rr.isError():
                fail += 1
            else:
                ok += 1
        except Exception as e:  # noqa: BLE001  現場各種 Modbus/連線例外都要能繼續下一輪
            fail += 1

    client.close()
    log_fn(f"[+] 完成，成功 {ok} 次，失敗 {fail} 次")
    return {"ok": ok, "fail": fail, "elapsed_sec": round(time.time() - start, 1)}
