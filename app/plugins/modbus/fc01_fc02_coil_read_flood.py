"""
測項：Modbus FC01/FC02（Read Coils / Read Discrete Inputs）高頻率讀取洪水
分類：Modbus TCP（流量型）
說明：跟 fc03_high_freq_read.py（Read Holding Registers）是同一類「唯讀高頻率讀取」壓力，
但 FC01（Read Coils）/FC02（Read Discrete Inputs）是位元層級的讀取，許多 Slave 韌體的
bit-level 讀取路徑（要把暫存器/記憶體位元組拆成個別 bit 陣列回傳）跟 word-level 的
FC03 走的不是同一段程式碼，負載特性可能不同（例如某些低成本韌體用逐 bit 迴圈組回應，
在 count 接近協定上限 2000 bits 時單次回應組裝成本會明顯上升）。兩種功能碼在同一個測項
內交替送出，一次涵蓋兩種常見的位元讀取路徑。

實作：沿用 fc03_high_freq_read.py 的 pymodbus 原生 client 模式。
需求套件：pip install pymodbus
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "Modbus FC01/FC02 位元狀態高頻率讀取"
CATEGORY = "Modbus TCP"
PROTOCOL = "TCP"
DEFAULT_PORT = 502
TEST_TYPE = "traffic"  # 高頻率位元讀取洪水，靠請求速率造成負擔


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 100000, "min": 1, "max": 100000, "desc": "每秒讀取次數（FC01/FC02 交替）"},
        "start_addr": {"type": "int", "default": 0, "min": 0, "max": 65535, "desc": "起始位元位址"},
        "bit_count": {"type": "int", "default": 2000, "min": 1, "max": 2000, "desc": "一次讀取位元數量（協定上限 2000）"},
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
    addr = int(params.get("start_addr", 0))
    count = int(params.get("bit_count", 2000))
    unit = int(params.get("unit_id", 1))

    client = ModbusTcpClient(target, port=port)
    if not client.connect():
        log_fn(f"[!] 無法連線 {target}:{port}")
        return {"ok": 0, "fail": 0, "connected": False}

    limiter = RateLimiter(rate)
    ok, fail = 0, 0
    fc01_count, fc02_count = 0, 0
    start = time.time()
    toggle = 0
    log_fn(f"[+] 開始 FC01/FC02 高頻率讀取 @ {rate}/s，addr={addr}, count={count}")

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            if toggle == 0:
                rr = client.read_coils(addr, count=count, slave=unit)
                fc01_count += 1
            else:
                rr = client.read_discrete_inputs(addr, count=count, slave=unit)
                fc02_count += 1
            toggle ^= 1
            if rr.isError():
                fail += 1
            else:
                ok += 1
        except Exception:  # noqa: BLE001  現場各種 Modbus/連線例外都要能繼續下一輪
            fail += 1

    client.close()
    log_fn(f"[+] 完成，成功 {ok} 次，失敗 {fail} 次（FC01 x{fc01_count}／FC02 x{fc02_count}）")
    return {
        "ok": ok, "fail": fail, "fc01_requests": fc01_count, "fc02_requests": fc02_count,
        "elapsed_sec": round(time.time() - start, 1),
    }
