"""
測項：MS-RPC Endpoint Mapper TCP 連線洪水（純連線層級 churn）
分類：RPC（預設埠 135/TCP）
說明：快速對 RPC Endpoint Mapper 埠（135/TCP）建立又關閉 TCP 連線，
     不送出任何 DCE/RPC 封包內容，純測試該埠 TCP accept queue / 每連線
     資源配置與回收的處理能力。與同分類的 epm_bind_flood 互補——
     後者測 bind 交握階段負載，這個測項測純 TCP 連線層級負載。

安全設計：不送出任何應用層資料，不涉及任何驗證或帳密；不偽造來源位址，
     所有連線皆由執行本測試的機器真實發起。速率透過 RateLimiter 控制，
     duration 經 clamp_duration() 限制。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "MS-RPC 連線洪水（純 TCP churn）"
CATEGORY = "RPC"
PROTOCOL = "TCP"
DEFAULT_PORT = 135
TEST_TYPE = "resource"  # 純 TCP 連線建立-關閉循環（churn）


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {
            "type": "int", "default": 150000, "min": 1, "max": 150000,
            "desc": "每秒連線 + 關閉次數",
        },
        "connect_timeout": {
            "type": "float", "default": 2.0, "min": 0.5, "max": 5.0,
            "desc": "單次連線逾時秒數",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 350))
    timeout = float(params.get("connect_timeout", 2.0))

    limiter = RateLimiter(rate)
    stats = {"connected": 0, "errors": 0}
    start = time.time()

    log_fn(f"[+] MS-RPC 連線洪水 -> {target}:{port} @ {rate}/s, {duration}s（純 TCP，無應用層內容）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            with socket.create_connection((target, port), timeout=timeout):
                stats["connected"] += 1
        except OSError as e:
            stats["errors"] += 1
            if stats["errors"] <= 5:
                log_fn(f"[!] 連線錯誤：{e}")

    return {
        "connected": stats["connected"],
        "errors": stats["errors"],
        "elapsed_sec": round(time.time() - start, 1),
    }
