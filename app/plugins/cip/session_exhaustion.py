"""
測項：CIP Session 飽和耗盡測試
分類：EtherNet/IP (CIP)（預設埠 44818，Explicit Messaging）
說明：測試 CIP 裝置（如 PLC/閘道器）對同時 Session 數量的上限與異常處理行為。

設計：整體迴圈受 duration + stop_event 控制，確保測試不會無限期執行；用內部
stop_local Event 通知所有背景執行緒收工、確保測試結束時 CIP session 會被關閉，
不會在目標裝置上留下大量「殭屍」session。
需求套件：pip install pycomm3
"""
import threading
import time

from ..common import clamp_duration

NAME = "CIP Session 飽和耗盡測試"
CATEGORY = "EtherNet/IP (CIP)"
PROTOCOL = "TCP"
DEFAULT_PORT = 44818
TEST_TYPE = "resource"  # 佔滿 CIP session 池上限


def get_param_schema() -> dict:
    return {
        "concurrent_sessions": {"type": "int", "default": 50000, "min": 1, "max": 50000, "desc": "同時維持的 CIP session 數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from pycomm3 import CIPDriver
    except ImportError:
        log_fn("[!] 未安裝 pycomm3，請先執行 pip install pycomm3")
        return {"opened": 0, "failed": 0, "error": "pycomm3 not installed"}

    duration = clamp_duration(duration)
    n = int(params.get("concurrent_sessions", 350))
    stats = {"opened": 0, "failed": 0}
    stop_local = threading.Event()

    def hold_session():
        try:
            with CIPDriver(target) as cip:  # noqa: F841  只需維持連線，不做讀寫
                stats["opened"] += 1
                while not stop_local.is_set():
                    time.sleep(0.5)
        except Exception:  # noqa: BLE001  裝置拒絕/斷線都算失敗，繼續統計即可
            stats["failed"] += 1

    log_fn(f"[+] 嘗試建立 {n} 個 CIP session -> {target}:{port}")
    threads = [threading.Thread(target=hold_session, daemon=True) for _ in range(n)]
    for t in threads:
        t.start()

    start = time.time()
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        time.sleep(1)

    stop_local.set()
    for t in threads:
        t.join(timeout=2)

    log_fn(f"[+] 開啟 {stats['opened']} 個 session，失敗 {stats['failed']}")
    return {
        "opened": stats["opened"],
        "failed": stats["failed"],
        "elapsed_sec": round(time.time() - start, 1),
    }
