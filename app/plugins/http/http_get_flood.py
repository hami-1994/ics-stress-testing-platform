"""
測項：HTTP GET 高併發負載衝擊
分類：HTTP/Web
底層工具：wrk
對應原始命令：wrk -t12 -c400 -d30s http://<IP>/
"""
from ..common import run_subprocess, clamp_duration

NAME = "HTTP GET 高併發負載衝擊"
CATEGORY = "HTTP/Web"
PROTOCOL = "HTTP"
DEFAULT_PORT = 80
TEST_TYPE = "traffic"  # 流量型：高併發 GET 請求洪水，靠請求速率/併發量本身造成負擔


def get_param_schema() -> dict:
    return {
        "threads": {"type": "int", "default": 9600, "min": 1, "max": 9600, "desc": "wrk -t"},
        "connections": {"type": "int", "default": 900000, "min": 1, "max": 1500000, "desc": "wrk -c"},
        "path": {"type": "string", "default": "/", "desc": "請求路徑"},
        "use_https": {"type": "bool", "default": False},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    threads = int(params.get("threads", 18))
    conns = int(params.get("connections", 900))
    path = params.get("path", "/")
    scheme = "https" if params.get("use_https") else "http"
    url = f"{scheme}://{target}:{port}{path}"

    cmd = ["wrk", "-t", str(threads), "-c", str(conns), "-d", f"{duration}s", url]
    # wrk 到 -d 時間就會自然結束，多給 15 秒緩衝讓它把統計資料印完
    return run_subprocess(cmd, duration + 15, stop_event, log_fn)
