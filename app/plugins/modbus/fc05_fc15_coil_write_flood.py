"""
測項：Modbus FC05/FC15（Write Single/Multiple Coils）高頻率寫入洪水
分類：Modbus TCP（流量型）
說明：跟 fc16_write_flood.py（Write Multiple Registers）是同一類「寫入路徑」壓力，但
FC05（Write Single Coil）/FC15（Write Multiple Coils）走的是位元層級寫入路徑，許多
Slave 韌體會對每一次線圈寫入觸發實體輸出（繼電器/DO 通道）切換或至少更新影像暫存器，
高頻率交替寫入 ON/OFF 可能造成實體輸出通道抖動或韌體事件佇列堆積，是跟純暫存器寫入
不同的壓力情境。

安全設計：
  - 固定在 coil_addr 這一個位址上交替寫 ON/OFF（不隨機挑位址），降低誤動作風險；
    正式測試前務必確認目標位址是測試用、非實際控制輸出的線圈。
  - 沿用 pymodbus 原生 client，迴圈受 duration + stop_event + RateLimiter 控制。
需求套件：pip install pymodbus
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "Modbus FC05/FC15 線圈高頻率寫入"
CATEGORY = "Modbus TCP"
PROTOCOL = "TCP"
DEFAULT_PORT = 502
TEST_TYPE = "traffic"  # 高頻率位元寫入洪水，靠請求速率造成負擔


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 50000, "min": 1, "max": 50000, "desc": "每秒寫入次數（FC05/FC15 交替）"},
        "coil_addr": {"type": "int", "default": 100, "min": 0, "max": 65535, "desc": "線圈位址（請避開實際輸出用途的線圈）"},
        "multi_coil_count": {"type": "int", "default": 16, "min": 1, "max": 1968, "desc": "FC15 一次寫入的線圈數量（協定上限 1968）"},
        "unit_id": {"type": "int", "default": 1, "min": 0, "max": 247, "desc": "Slave ID"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from pymodbus.client import ModbusTcpClient
    except ImportError:
        log_fn("[!] 未安裝 pymodbus，請先執行 pip install pymodbus")
        return {"ok": 0, "fail": 0, "error": "pymodbus not installed"}

    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 100))
    addr = int(params.get("coil_addr", 100))
    multi_count = int(params.get("multi_coil_count", 16))
    unit = int(params.get("unit_id", 1))

    client = ModbusTcpClient(target, port=port)
    if not client.connect():
        log_fn(f"[!] 無法連線 {target}:{port}")
        return {"ok": 0, "fail": 0, "connected": False}

    limiter = RateLimiter(rate)
    ok, fail = 0, 0
    fc05_count, fc15_count = 0, 0
    start = time.time()
    toggle = 0
    coil_state = False
    log_fn(f"[+] 開始 FC05/FC15 高頻率寫入 @ {rate}/s，addr={addr}")

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            if toggle == 0:
                rr = client.write_coil(addr, coil_state, slave=unit)
                fc05_count += 1
                coil_state = not coil_state
            else:
                rr = client.write_coils(addr, [coil_state] * multi_count, slave=unit)
                fc15_count += 1
            toggle ^= 1
            if rr.isError():
                fail += 1
            else:
                ok += 1
        except Exception:  # noqa: BLE001  現場各種 Modbus/連線例外都要能繼續下一輪
            fail += 1

    client.close()
    log_fn(f"[+] 完成，成功 {ok} 次，失敗 {fail} 次（FC05 x{fc05_count}／FC15 x{fc15_count}）")
    return {
        "ok": ok, "fail": fail, "fc05_requests": fc05_count, "fc15_requests": fc15_count,
        "elapsed_sec": round(time.time() - start, 1),
    }
