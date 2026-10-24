"""
測項：OPC UA CreateSession/CloseSession 快速循環
分類：OPC UA（預設埠 4840）
說明：與 opcua/hello_flood.py（同時保持大量 SecureChannel 不放）不同，本測項測的是
「循序、高頻率地完成一次完整 Session 生命週期」——每輪都走完整的 connect（Hello→
OpenSecureChannel→CreateSession→ActivateSession）再立刻 disconnect，用來測試 Server
在 Session table 配置/釋放路徑上是否存在資源緩慢增長、Session ID/驗證權杖處理的
競態問題等，這是與「同時佔用大量連線」不同的另一種失效面向（概念上對應
cip/forward_open_close_churn.py 在 CIP 協定上的做法）。

實作：使用 asyncua 高階 Client 的 connect()/disconnect()，序列化、逐輪執行，
以「下一次允許發送時間」的方式節流（asyncio.sleep，不阻塞事件迴圈），
受 duration + stop_event 控制。
需求套件：pip install asyncua
"""
import asyncio
import time

from ..common import clamp_duration

NAME = "OPC UA CreateSession/CloseSession 快速循環"
CATEGORY = "OPC UA"
PROTOCOL = "TCP"
DEFAULT_PORT = 4840
TEST_TYPE = "resource"  # 連線型：CreateSession/CloseSession 連線建立-關閉循環（churn）

def get_param_schema() -> dict:
    return {
        "rate_per_sec": {
            "type": "int", "default": 10000, "min": 1, "max": 10000,
            "desc": "每秒完整 Session 建立+關閉循環次數",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from asyncua import Client
    except ImportError:
        log_fn("[!] 未安裝 asyncua，請先執行 pip install asyncua")
        return {"ok": 0, "fail": 0, "error": "asyncua not installed"}

    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 25))
    interval = 1.0 / rate if rate > 0 else 0.0
    url = f"opc.tcp://{target}:{port}"

    async def _main():
        ok, fail = 0, 0
        start = time.time()
        next_t = start
        log_fn(f"[+] 開始 CreateSession/CloseSession 快速循環 @ {rate}/s -> {url}")

        while time.time() - start < duration and not (stop_event and stop_event.is_set()):
            now = time.time()
            if next_t > now:
                await asyncio.sleep(min(next_t - now, 0.5))
                continue
            next_t = now + interval

            c = Client(url=url)
            try:
                await c.connect()
                ok += 1
            except Exception:  # noqa: BLE001
                fail += 1
            finally:
                try:
                    await c.disconnect()
                except Exception:  # noqa: BLE001
                    pass

        return ok, fail, time.time() - start

    ok, fail, elapsed = asyncio.run(_main())
    log_fn(f"[+] 完成，成功 {ok} 次，失敗 {fail} 次")
    return {"ok": ok, "fail": fail, "elapsed_sec": round(elapsed, 1)}
