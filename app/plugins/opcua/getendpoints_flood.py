"""
測項：OPC UA GetEndpoints 查詢風暴（Session 建立前負載）
分類：OPC UA（預設埠 4840）
說明：GetEndpoints 是 OPC UA client 在建立 Session 之前，用來查詢 Server 支援哪些
Endpoint/安全模式的標準服務，任何 client 連線流程一定會先呼叫。由於這個階段還沒有
Session/驗證機制把關，高頻率的 GetEndpoints 請求可以測試 Server 在「尚未建立正式
Session」這個較輕量但完全開放的路徑上的資源消耗與回應延遲劣化情況，與
opcua/hello_flood.py（測試同時保持大量 SecureChannel）及本檔案另一個手足測項
create_session_churn.py（測試完整 Session 生命週期循環）互補，涵蓋不同的連線階段。

實作：使用 asyncua 的低階 API（connect_socket/send_hello/open_secure_channel/
get_endpoints），每一輪完成後關閉 SecureChannel 與 Socket，避免留下大量閒置連線；
自行以 asyncio 版本的節流機制控速（RateLimiter 是同步版本，這裡改用等效的
「下一次允許發送時間」邏輯搭配 asyncio.sleep，避免阻塞事件迴圈），並受
duration + stop_event 控制。
需求套件：pip install asyncua
"""
import asyncio
import time

from ..common import clamp_duration

NAME = "OPC UA GetEndpoints 查詢風暴"
CATEGORY = "OPC UA"
PROTOCOL = "TCP"
DEFAULT_PORT = 4840
TEST_TYPE = "resource"  # 連線型：每一輪皆為完整的連線建立-關閉循環（open_secure_channel/close_secure_channel），非單純無狀態查詢

def get_param_schema() -> dict:
    return {
        "rate_per_sec": {
            "type": "int", "default": 40000, "min": 1, "max": 40000,
            "desc": "每秒 GetEndpoints 循環數（含建立/關閉 SecureChannel）",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from asyncua import Client
    except ImportError:
        log_fn("[!] 未安裝 asyncua，請先執行 pip install asyncua")
        return {"ok": 0, "fail": 0, "error": "asyncua not installed"}

    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 80))
    interval = 1.0 / rate if rate > 0 else 0.0
    url = f"opc.tcp://{target}:{port}"

    async def _main():
        ok, fail = 0, 0
        start = time.time()
        next_t = start
        log_fn(f"[+] 開始 GetEndpoints 查詢風暴 @ {rate}/s -> {url}")

        while time.time() - start < duration and not (stop_event and stop_event.is_set()):
            now = time.time()
            if next_t > now:
                await asyncio.sleep(min(next_t - now, 0.5))
                continue
            next_t = now + interval

            c = Client(url=url)
            try:
                await c.connect_socket()
                await c.send_hello()
                await c.open_secure_channel()
                await c.get_endpoints()
                ok += 1
            except Exception:  # noqa: BLE001
                fail += 1
            finally:
                try:
                    await c.close_secure_channel()
                except Exception:  # noqa: BLE001
                    pass
                try:
                    await c.disconnect_socket()
                except Exception:  # noqa: BLE001
                    pass

        return ok, fail, time.time() - start

    ok, fail, elapsed = asyncio.run(_main())
    log_fn(f"[+] 完成，成功 {ok} 次，失敗 {fail} 次")
    return {"ok": ok, "fail": fail, "elapsed_sec": round(elapsed, 1)}
