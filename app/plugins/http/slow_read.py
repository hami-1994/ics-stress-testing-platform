"""
測項：Slow Read HTTP 慢速回應接收
分類：HTTP/Web
底層工具：slowhttptest
對應原始命令：slowhttptest -X -c 1000 -r 200 -w 512 -l 300 -u http://<IP>/
"""
from ..common import run_subprocess, clamp_duration

NAME = "Slow Read HTTP 慢速回應接收"
CATEGORY = "HTTP/Web"
PROTOCOL = "HTTP"
DEFAULT_PORT = 80
TEST_TYPE = "resource"  # 連線型：以極小接收視窗拖住大量連線，佔滿伺服器連線/工作執行緒池


def get_param_schema() -> dict:
    return {
        "connections": {"type": "int", "default": 750000, "min": 1, "max": 750000, "desc": "-c 總連線數"},
        "connect_rate": {"type": "int", "default": 150000, "min": 1, "max": 150000, "desc": "-r 每秒建立連線數"},
        "recv_window": {"type": "int", "default": 512, "min": 1, "max": 4096, "desc": "-w TCP 接收視窗大小"},
        "path": {"type": "string", "default": "/"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    conns = int(params.get("connections", 1500))
    rate = int(params.get("connect_rate", 300))
    window = int(params.get("recv_window", 512))
    path = params.get("path", "/")
    url = f"http://{target}:{port}{path}"

    cmd = [
        "slowhttptest", "-X", "-c", str(conns),
        "-r", str(rate), "-w", str(window),
        "-l", str(duration), "-u", url,
    ]
    return run_subprocess(cmd, duration + 15, stop_event, log_fn)
