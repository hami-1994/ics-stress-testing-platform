"""
測項：OPC UA 訂閱（Subscription/MonitoredItem）建立-刪除快速循環
分類：OPC UA（預設埠 4840）
說明：OPC UA 的 Publish/Subscribe 機制（Subscription + MonitoredItem）是 Server 端
負擔較重的功能之一，Server 需要維護取樣佇列、Publish timer、通知佇列等狀態。本測項
在單一已建立的 Session 內，反覆建立 Subscription、訂閱一個標準節點的資料變化、再
立即刪除該 Subscription，測試 Server 對這類「狀態建立/銷毀」路徑的資源回收健全性，
與純粹的連線/Session 層級測項（hello_flood.py、create_session_churn.py）互補，
針對的是應用層的訂閱管理路徑。

監控節點預設為 ns=0;i=2258（Server_ServerStatus_CurrentTime），這是 OPC UA Part 5
規範定義、所有合規 Server 都必須實作的標準節點，如目標 Server 對此節點行為不同，
可自行透過 node_id 參數調整。

實作：使用 asyncua 高階 Client 建立一次連線後於迴圈中重複
create_subscription()/subscribe_data_change()/delete()，以「下一次允許發送時間」的
方式節流（asyncio.sleep，不阻塞事件迴圈），受 duration + stop_event 控制，
結束時關閉連線。
需求套件：pip install asyncua
"""
import asyncio
import time

from ..common import clamp_duration

NAME = "OPC UA 訂閱建立-刪除快速循環"
CATEGORY = "OPC UA"
PROTOCOL = "TCP"
DEFAULT_PORT = 4840
TEST_TYPE = "resource"  # 資源占用型：針對 Server 端 Subscription/MonitoredItem 狀態（取樣佇列、Publish timer）做針對性消耗，非單純流量/連線數

def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 20000, "min": 1, "max": 20000, "desc": "每秒訂閱建立+刪除循環次數"},
        "node_id": {"type": "string", "default": "i=2258", "desc": "要監控的節點 NodeId（預設為標準 ServerStatus.CurrentTime）"},
        "publishing_interval_ms": {"type": "int", "default": 100, "min": 50, "max": 5000, "desc": "Subscription Publishing Interval (ms)"},
    }


class _NullHandler:
    """僅用來滿足 asyncua create_subscription() 需要 handler 物件的介面，資料變化通知不做任何處理。"""

    def datachange_notification(self, node, val, data):
        pass


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from asyncua import Client
    except ImportError:
        log_fn("[!] 未安裝 asyncua，請先執行 pip install asyncua")
        return {"ok": 0, "fail": 0, "error": "asyncua not installed"}

    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 50))
    interval = 1.0 / rate if rate > 0 else 0.0
    node_id = params.get("node_id", "i=2258")
    pub_interval = int(params.get("publishing_interval_ms", 100))
    url = f"opc.tcp://{target}:{port}"

    async def _main():
        ok, fail = 0, 0
        start = time.time()

        c = Client(url=url)
        try:
            await c.connect()
        except Exception as e:  # noqa: BLE001
            log_fn(f"[!] 無法連線/建立 Session -> {url}：{e}")
            return ok, fail, 0.0, False

        node = c.get_node(node_id)
        handler = _NullHandler()
        next_t = start
        log_fn(f"[+] 開始訂閱建立-刪除快速循環 @ {rate}/s -> {url}，node={node_id}")

        while time.time() - start < duration and not (stop_event and stop_event.is_set()):
            now = time.time()
            if next_t > now:
                await asyncio.sleep(min(next_t - now, 0.5))
                continue
            next_t = now + interval

            try:
                sub = await c.create_subscription(pub_interval, handler)
                await sub.subscribe_data_change(node)
                await sub.delete()
                ok += 1
            except Exception:  # noqa: BLE001
                fail += 1

        elapsed = time.time() - start
        try:
            await c.disconnect()
        except Exception:  # noqa: BLE001
            pass

        return ok, fail, elapsed, True

    ok, fail, elapsed, connected = asyncio.run(_main())
    log_fn(f"[+] 完成，成功 {ok} 次，失敗 {fail} 次")
    return {"ok": ok, "fail": fail, "connected": connected, "elapsed_sec": round(elapsed, 1)}
