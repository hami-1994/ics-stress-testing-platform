"""
測項：CIP Session/Forward Open 建立-關閉快速循環
分類：EtherNet/IP (CIP)（預設埠 44818，Explicit Messaging）
說明：與既有的 cip/session_exhaustion.py（同時「保持」大量 session 不放）不同，
本測項測的是「循序、高頻率地建立又立刻關閉」CIP session 的行為模式——每次
CIPDriver 開啟連線都會走 RegisterSession，這也是後續 Forward Open（Class 1/3
連線）在建立 I/O 連線前必經的前置交握。快速反覆的建立/釋放循環，用來測試裝置端
session table 的配置/釋放路徑是否存在資源緩慢增長（memory leak）、session ID
計數器競態等問題，這是與「同時佔用大量連線」不同的另一種失效面向。

實作：使用 pycomm3 CIPDriver 作為 context manager，於單一背景迴圈中反覆
open→close，透過 RateLimiter 控制循環速率，受 duration + stop_event 統一收尾。
需求套件：pip install pycomm3
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "CIP Session/Forward Open 建立-關閉快速循環"
CATEGORY = "EtherNet/IP (CIP)"
PROTOCOL = "TCP"
DEFAULT_PORT = 44818
TEST_TYPE = "resource"  # 連線建立-關閉快速循環（churn）


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 10000, "min": 1, "max": 10000, "desc": "每秒建立+關閉循環次數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from pycomm3 import CIPDriver
    except ImportError:
        log_fn("[!] 未安裝 pycomm3，請先執行 pip install pycomm3")
        return {"cycles_ok": 0, "cycles_fail": 0, "error": "pycomm3 not installed"}

    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 25))

    limiter = RateLimiter(rate)
    ok, fail = 0, 0
    start = time.time()
    log_fn(f"[+] 開始 CIP session/Forward Open 建立-關閉快速循環 @ {rate}/s -> {target}:{port}")

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            with CIPDriver(target) as cip:  # noqa: F841  只需完成建立/釋放循環，不做讀寫
                ok += 1
        except Exception:  # noqa: BLE001  裝置拒絕/斷線都算失敗，繼續下一次循環
            fail += 1

    elapsed = time.time() - start
    log_fn(f"[+] 完成，成功循環 {ok} 次，失敗 {fail} 次")
    return {"cycles_ok": ok, "cycles_fail": fail, "elapsed_sec": round(elapsed, 1)}
