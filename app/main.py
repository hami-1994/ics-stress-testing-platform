"""
app/main.py — FastAPI 進入點

啟動方式見專案根目錄的 run.sh（uvicorn app.main:app），預設只 bind 127.0.0.1（設計文件第 3 節）。
"""
import asyncio

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from . import events
from .config import BASE_DIR
from .db import init_db
from .routers import monitors, ports, projects, runs, scans, storage, targets, test_items, ws

app = FastAPI(title="ICS Security Stress Testing Platform", version="1.0.0")

app.include_router(targets.router)
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(ports.router)
app.include_router(monitors.router)
app.include_router(test_items.router)
app.include_router(runs.router)
app.include_router(storage.router)
app.include_router(ws.router)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")


@app.on_event("startup")
async def on_startup():
    init_db()
    events.set_main_loop(asyncio.get_event_loop())


@app.get("/", response_class=HTMLResponse)
def index():
    return (BASE_DIR / "app" / "templates" / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {"ok": True}
