"""
測項：Siemens S7 Setup Communication 建立-關閉快速循環（真實 S7 協定層）
分類：Siemens S7（預設埠 102）
說明：與既有的 s7/setup_communication_exhaustion.py（同時「保持」大量真實 S7
連線不放，測連線池上限）不同，本測項測的是「循序、高頻率地建立又立刻關閉」
真實 S7 連線（COTP CR + Setup Communication 完整交握）的行為模式——這與
cip/forward_open_close_churn.py 之於 cip/session_exhaustion.py 的關係相同：
「同時佔用大量連線」與「快速反覆建立/釋放」是兩種不同的失效面向，後者測的是
PLC 端連線資源的配置/釋放路徑是否存在資源緩慢增長（memory leak）、連線
identifier 計數器競態、或釋放不完全導致連線池被「殭屍」連線緩慢耗盡等問題。

**範圍限制（重要，與 s7/setup_communication_exhaustion.py 採用完全相同的安全
邊界，這是本專案既有的既定政策，本測項不改變這個立場）**：這裡「只」做連線
建立與立即關閉（COTP CR + Setup Communication），不呼叫任何 db_read/db_write/
read_area/write_area 等資料存取函式，不讀取、不寫入、不觸碰 PLC 的任何記憶體/
程式狀態，純粹測 S7 連線層資源本身。

實作方式：延續 s7/setup_communication_exhaustion.py 已驗證可用的 python-snap7
API（Client.connect(address, rack, slot, tcp_port)），差別在於單一背景執行緒
迴圈內反覆 connect → disconnect → destroy，透過 RateLimiter 控制循環速率，
受 duration + stop_event 統一收尾，與 cip/forward_open_close_churn.py 的迴圈
結構一致。
需求套件：pip install python-snap7（另需系統可用的 libsnap7 動態函式庫）
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "Siemens S7 Setup Communication 建立-關閉快速循環（真實 S7 協定層）"
CATEGORY = "Siemens S7"
PROTOCOL = "TCP"
DEFAULT_PORT = 102
TEST_TYPE = "resource"  # 循序快速建立/關閉真實 S7 連線，屬連線資源配置/釋放路徑測試


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {
            "type": "int", "default": 5000, "min": 1, "max": 5000,
            "desc": "每秒完成的 connect→disconnect 循環次數（含完整 COTP+Setup Communication 交握，"
                    "真實速率會受目標回應時間限制，此為送出端節流上限）",
        },
        "rack": {
            "type": "int", "default": 0, "min": 0, "max": 7,
            "desc": "S7 Rack 編號，需與實際 PLC 硬體組態相符（S7-1200/1500 常見為 0）",
        },
        "slot": {
            "type": "int", "default": 1, "min": 0, "max": 31,
            "desc": "S7 Slot 編號，需與實際 PLC 硬體組態相符（S7-1200/1500 常見為 1，S7-300 常見為 2）",
        },
        "connect_timeout_sec": {
            "type": "float", "default": 3.0, "min": 0.5, "max": 10.0,
            "desc": "單一連線建立的逾時秒數",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        import snap7
        from snap7.type import Parameter
    except ImportError:
        log_fn("[!] 未安裝 python-snap7，請先執行 pip install python-snap7"
               "（另需系統可用的 libsnap7 動態函式庫）")
        return {"ok": 0, "fail": 0, "error": "python-snap7 not installed"}

    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 20))
    rack = int(params.get("rack", 0))
    slot = int(params.get("slot", 1))
    timeout_sec = float(params.get("connect_timeout_sec", 3.0))
    timeout_ms = max(1, int(timeout_sec * 1000))
    tcp_port = int(port) if port else DEFAULT_PORT

    limiter = RateLimiter(rate)
    ok, fail = 0, 0
    error_logged = 0
    start = time.time()

    log_fn(f"[+] 開始 S7 建立-關閉快速循環 @ {rate}/s -> {target}:{tcp_port}，rack={rack}, slot={slot}")

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        client = snap7.client.Client()
        try:
            for param in (Parameter.PingTimeout, Parameter.SendTimeout, Parameter.RecvTimeout):
                try:
                    client.set_param(param, timeout_ms)
                except Exception:  # noqa: BLE001
                    pass
            client.connect(target, rack, slot, tcp_port)
            ok += 1
            client.disconnect()
        except Exception as e:  # noqa: BLE001  連線拒絕/逾時/rack-slot 錯誤等都算失敗，繼續下一輪
            fail += 1
            if error_logged < 5:
                error_logged += 1
                log_fn(f"[!] S7 連線循環失敗：{e}")
        finally:
            try:
                client.destroy()
            except Exception:  # noqa: BLE001
                pass

    elapsed = time.time() - start
    log_fn(f"[+] 完成，成功循環 {ok} 次，失敗 {fail} 次")
    return {"ok": ok, "fail": fail, "elapsed_sec": round(elapsed, 1)}
