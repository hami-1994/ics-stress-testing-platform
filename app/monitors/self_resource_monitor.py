"""
攻擊端自我資源監控（設計文件 5.4 節強烈建議項）：
CPU / 記憶體使用率，避免高強度測試把發起測試的 Kali 主機自己打掛。
"""
import psutil

TYPE = "self_resource"
NAME = "攻擊端自我資源監控"


def sample(config: dict) -> dict:
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "mem_percent": psutil.virtual_memory().percent,
        "load1": psutil.getloadavg()[0] if hasattr(psutil, "getloadavg") else None,
    }
