"""網路介面監控：發送/接收 bps、pps、錯誤/丟棄數（對發起測試的主機自己的網卡取樣），
以及「實體鏈路載波狀態」（carrier）。

這個監控器量的是**發起測試的 Kali 主機自己的網卡**，不是標的的網卡——這點很重要：
  - bps/pps/errin/errout/dropin/dropout 這些流量計數器，在測試期間本來就會因為攻擊端
    自己送出大量封包而劇烈波動/出現誤差，不能直接當成「標的斷線」的判定依據，只適合
    當診斷參考（見 app/health.py 的判斷邏輯：這幾個欄位只會導致 warn，不會導致 critical）。
  - 但「carrier」（實體鏈路載波偵測）是另一回事：這是網卡晶片本身偵測到的「有沒有偵測到
    對方的實體訊號」，不受封包流量大小影響，是乾淨的訊號。如果測試主機的這張網卡是直接
    跟受測標的對接（直連網路線，或接在同一台交換器上彼此相鄰的兩個 port），對方的網路介面
    /實體鏈路斷線時，這裡通常也會反映出 carrier 掉為 0——這是使用者實際反映的情境：
    「我測試的 kali 和受測產品對接，他 Link Down 我 Kali 應該會知道」，確實可以這樣用，
    所以這個訊號被納入「判定用」（見 app/health.py）。如果測試主機這張網卡是接在共用交換器
    上、中間還有其他裝置或路由器，carrier 只能代表「這個網段本身還有訊號」，不能精準對應到
    某一台特定裝置，這時候還是要搭配 service/ping 等監控器交叉確認。
"""
import time

import psutil

TYPE = "iface"
NAME = "網路介面監控"

_last = {}


def _pick_iface(config: dict) -> str:
    iface = config.get("iface")
    if iface:
        return iface
    stats = psutil.net_io_counters(pernic=True)
    for name in stats:
        if name != "lo":
            return name
    return "lo"


def _read_carrier(iface: str) -> int | None:
    """讀取 /sys/class/net/{iface}/carrier：1=偵測到鏈路訊號，0=沒有訊號（實體斷線／
    對方網路介面關閉），讀取失敗（虛擬介面不支援、介面不存在、權限問題等）回傳 None，
    代表「無法判斷」，不當成異常，避免對不支援這個檔案的介面類型誤報。"""
    try:
        with open(f"/sys/class/net/{iface}/carrier") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def sample(config: dict) -> dict:
    iface = _pick_iface(config)
    counters = psutil.net_io_counters(pernic=True).get(iface)
    now = time.time()
    carrier = _read_carrier(iface)
    if counters is None:
        return {"iface": iface, "error": "介面不存在", "carrier": carrier}

    prev = _last.get(iface)
    _last[iface] = (now, counters)

    if not prev:
        return {"iface": iface, "bps_sent": 0, "bps_recv": 0, "pps_sent": 0, "pps_recv": 0,
                "errin": counters.errin, "errout": counters.errout,
                "dropin": counters.dropin, "dropout": counters.dropout, "carrier": carrier}

    prev_ts, prev_c = prev
    dt = max(now - prev_ts, 0.001)
    return {
        "iface": iface,
        "bps_sent": round((counters.bytes_sent - prev_c.bytes_sent) * 8 / dt, 1),
        "bps_recv": round((counters.bytes_recv - prev_c.bytes_recv) * 8 / dt, 1),
        "pps_sent": round((counters.packets_sent - prev_c.packets_sent) / dt, 1),
        "pps_recv": round((counters.packets_recv - prev_c.packets_recv) / dt, 1),
        "errin": counters.errin, "errout": counters.errout,
        "dropin": counters.dropin, "dropout": counters.dropout,
        "carrier": carrier,
    }
