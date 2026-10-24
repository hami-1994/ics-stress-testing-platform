"""
app/events.py — WebSocket 連線管理與跨執行緒事件廣播

Orchestrator/Monitor 是在背景 thread 跑的（不是 async），但 WebSocket 送資料要在
asyncio event loop 裡做，所以用 asyncio.run_coroutine_threadsafe 把事件排進主
event loop，這是 thread -> asyncio 溝通的標準做法。

事件格式對應設計文件第 6 節：
    scan_progress / scan_completed / test_started / test_progress /
    monitor_sample / log_line / test_completed / alert / project_closed
"""
import asyncio
import json
from collections import defaultdict

from fastapi import WebSocket

_connections: dict[int, list[WebSocket]] = defaultdict(list)
_main_loop: asyncio.AbstractEventLoop | None = None


def set_main_loop(loop: asyncio.AbstractEventLoop):
    global _main_loop
    _main_loop = loop


async def connect(project_id: int, ws: WebSocket):
    await ws.accept()
    _connections[project_id].append(ws)


def disconnect(project_id: int, ws: WebSocket):
    if ws in _connections[project_id]:
        _connections[project_id].remove(ws)


async def _broadcast_async(project_id: int, event: dict):
    dead = []
    for ws in list(_connections.get(project_id, [])):
        try:
            await ws.send_text(json.dumps(event, ensure_ascii=False, default=str))
        except Exception:  # noqa: BLE001
            dead.append(ws)
    for ws in dead:
        disconnect(project_id, ws)


def broadcast(project_id: int, event_type: str, payload: dict):
    """執行緒安全版本：從背景 thread（Orchestrator/Monitor）呼叫。"""
    event = {"type": event_type, **payload}
    if _main_loop is None:
        return
    try:
        asyncio.run_coroutine_threadsafe(_broadcast_async(project_id, event), _main_loop)
    except RuntimeError:
        pass
