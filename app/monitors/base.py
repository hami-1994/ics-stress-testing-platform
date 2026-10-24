"""
app/monitors/base.py — 監控器共用的執行/取樣/寫檔迴圈

MonitorRunner 在獨立 thread 跑，每 interval 秒呼叫一次 sample_fn(config)，
把結果寫進 CSV，並呼叫 on_sample callback（Orchestrator 會用它把資料丟去 WebSocket）。
"""
import csv
import threading
import time
from pathlib import Path
from typing import Callable


class MonitorRunner:
    def __init__(self, monitor_type: str, sample_fn: Callable[[dict], dict], config: dict,
                 csv_path: Path, on_sample: Callable[[str, dict], None], interval: float = 1.0):
        self.monitor_type = monitor_type
        self.sample_fn = sample_fn
        self.config = config
        self.csv_path = csv_path
        self.on_sample = on_sample
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval + 2)

    def _run(self):
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        writer = None
        f = None
        try:
            f = open(self.csv_path, "w", newline="")
            while not self._stop.is_set():
                t0 = time.time()
                try:
                    metrics = self.sample_fn(self.config)
                except Exception as e:  # noqa: BLE001  監控器本身出錯不該讓測試整個中斷
                    metrics = {"error": str(e)}
                metrics = {"ts": round(time.time(), 3), **metrics}

                if writer is None:
                    writer = csv.DictWriter(f, fieldnames=list(metrics.keys()))
                    writer.writeheader()
                writer.writerow(metrics)
                f.flush()

                try:
                    self.on_sample(self.monitor_type, metrics)
                except Exception:  # noqa: BLE001  推播失敗不該讓監控迴圈掛掉
                    pass

                elapsed = time.time() - t0
                self._stop.wait(max(0.0, self.interval - elapsed))
        finally:
            if f:
                f.close()
