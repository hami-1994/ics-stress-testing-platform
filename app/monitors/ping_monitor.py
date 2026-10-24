"""測項執行期間對目標做 Ping 監控：RTT 與是否逾時（丟包）。"""
import subprocess
import re

TYPE = "ping"
NAME = "Ping 監控（延遲/丟包）"

_RTT_RE = re.compile(r"time[=<]([\d.]+)")


def sample(config: dict) -> dict:
    target = config.get("target", "")
    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-W", "1", target],
            capture_output=True, text=True, timeout=3,
        )
        m = _RTT_RE.search(out.stdout)
        if m:
            return {"rtt_ms": float(m.group(1)), "loss": False}
        return {"rtt_ms": None, "loss": True}
    except (subprocess.TimeoutExpired, OSError):
        return {"rtt_ms": None, "loss": True}
