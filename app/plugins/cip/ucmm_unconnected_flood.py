"""
測項：CIP UCMM（Unconnected Message）顯式訊息請求風暴
分類：EtherNet/IP (CIP)
說明：CIP Unconnected Messaging（UCMM）是裝置在還沒有建立 Class 1/3 連線前，
用來查詢裝置資訊、進行一次性讀寫的機制（例如 Get_Attribute_Single）；裝置端通常會
為每個 unconnected request 配置暫存的訊息路由/緩衝資源。持續高頻率送出 UCMM 請求，
測試裝置對這類「不需要先建立連線」的請求路徑之資源配置與釋放是否健全，這與
cip/session_exhaustion.py（同時保持大量 session）及
cip/forward_open_close_churn.py（循序快速建立/關閉 session）是不同的失效面向。

實作：使用 pycomm3 的 CIPDriver.generic_message() 公開介面，在單一已註冊的 session
內反覆送出 Get_Attribute_Single（Identity Object, Class 0x01 / Instance 1 / Attribute 1，
即 Vendor ID，任何合規 CIP 裝置都必須實作這個物件），受 rate + duration + stop_event
控制。需注意：generic_message() 的確切參數名稱/簽章可能隨 pycomm3 版本略有差異，
若因版本差異丟出例外，會被計入 fail 並繼續下一次循環，不會中斷整個測試。
需求套件：pip install pycomm3
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "CIP UCMM 顯式訊息請求風暴"
CATEGORY = "EtherNet/IP (CIP)"
PROTOCOL = "TCP"
DEFAULT_PORT = 44818
TEST_TYPE = "traffic"  # 高頻率 UCMM 查詢請求洪水，靠請求速率造成負擔


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 60000, "min": 1, "max": 60000, "desc": "每秒送出 UCMM 請求數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from pycomm3 import CIPDriver, Services
    except ImportError:
        log_fn("[!] 未安裝 pycomm3，請先執行 pip install pycomm3")
        return {"ok": 0, "fail": 0, "error": "pycomm3 not installed"}

    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 150))

    try:
        cip = CIPDriver(target)
        cip.open()
    except Exception as e:  # noqa: BLE001
        log_fn(f"[!] 無法建立 CIP session -> {target}:{port}：{e}")
        return {"ok": 0, "fail": 0, "connected": False, "error": str(e)}

    limiter = RateLimiter(rate)
    ok, fail = 0, 0
    start = time.time()
    log_fn(f"[+] 開始 CIP UCMM 請求風暴 @ {rate}/s -> {target}:{port}（Get_Attribute_Single, Identity Object）")

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            cip.generic_message(
                service=Services.get_attribute_single,
                class_code=0x01,
                instance=1,
                attribute=1,
                request_data=b"",
                name="ucmm_flood_probe",
            )
            ok += 1
        except Exception:  # noqa: BLE001  版本差異/裝置拒絕都算失敗，繼續下一次循環
            fail += 1

    try:
        cip.close()
    except Exception:  # noqa: BLE001
        pass

    elapsed = time.time() - start
    log_fn(f"[+] 完成，成功 {ok} 次，失敗 {fail} 次")
    return {"ok": ok, "fail": fail, "elapsed_sec": round(elapsed, 1)}
