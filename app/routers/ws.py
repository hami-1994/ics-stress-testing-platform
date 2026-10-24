"""ws.py — 即時事件推播（設計文件第 6 節）"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import events

router = APIRouter()


@router.websocket("/ws/project/{project_id}")
async def project_ws(websocket: WebSocket, project_id: int):
    await events.connect(project_id, websocket)
    try:
        while True:
            # 前端目前不會主動送控制指令進來（控制走 REST，見設計文件第 6 節），
            # 這裡只是保持連線、順便偵測斷線。
            await websocket.receive_text()
    except WebSocketDisconnect:
        events.disconnect(project_id, websocket)
