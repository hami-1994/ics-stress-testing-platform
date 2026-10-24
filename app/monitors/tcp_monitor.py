"""TCP 監控：連線狀態分布（ESTABLISHED/SYN_SENT/TIME_WAIT...），可選過濾目標埠。"""
import subprocess
from collections import Counter

TYPE = "tcp"
NAME = "TCP 連線狀態監控"


def sample(config: dict) -> dict:
    port = config.get("port")
    try:
        out = subprocess.run(["ss", "-tan"], capture_output=True, text=True, timeout=3)
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"error": str(e)}

    counts = Counter()
    total = 0
    for line in out.stdout.splitlines()[1:]:
        parts = line.split()
        if not parts:
            continue
        state = parts[0]
        if port:
            # 粗略過濾：本地或遠端位址包含 :port
            if f":{port}" not in line:
                continue
        counts[state] += 1
        total += 1

    return {
        "total": total,
        "established": counts.get("ESTAB", 0),
        "syn_sent": counts.get("SYN-SENT", 0),
        "syn_recv": counts.get("SYN-RECV", 0),
        "time_wait": counts.get("TIME-WAIT", 0),
        "close_wait": counts.get("CLOSE-WAIT", 0),
        "closing": counts.get("CLOSING", 0) + counts.get("LAST-ACK", 0),
    }
