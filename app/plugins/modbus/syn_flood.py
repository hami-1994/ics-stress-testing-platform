"""
測項：Modbus TCP Port SYN Flood（爆發性 TCP 流量干擾）
分類：Modbus TCP（預設埠 502）
底層工具：nping（nmap 套件）
對應原始命令：sudo nping --tcp --flags SYN --rate 5000 -p 502 <IP>
（保留 --rate 可調速率參數，這一支原始指令本身就是可控速率，不需額外調整）
"""
from ..common import run_subprocess, clamp_duration

NAME = "Modbus TCP Port SYN Flood"
CATEGORY = "Modbus TCP"
PROTOCOL = "TCP"
DEFAULT_PORT = 502
TEST_TYPE = "traffic"  # SYN flood，靠封包速率造成負擔


def get_param_schema() -> dict:
    return {
        "rate_pps": {"type": "int", "default": 1000000, "min": 1, "max": 1000000, "desc": "--rate"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_pps", 5000))
    count = rate * duration

    cmd = [
        "nping", "--tcp", "--flags", "SYN", "-p", str(port),
        "--rate", str(rate), "--count", str(count), "-v", "0", target,
    ]
    return run_subprocess(cmd, duration + 10, stop_event, log_fn)
