"""monitors.py — 監控器選擇（設計文件 5.4 節）"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..monitors import REGISTRY

router = APIRouter(prefix="/api/projects/{project_id}/monitors", tags=["monitors"])


@router.get("/available")
def list_available_monitor_types():
    return [{"type": t, "name": mod.NAME} for t, mod in REGISTRY.items()]


@router.get("", response_model=list[schemas.MonitorConfigOut])
def list_monitors(project_id: int, db: Session = Depends(get_db)):
    return db.query(models.MonitorConfig).filter_by(project_id=project_id).all()


@router.post("", response_model=schemas.MonitorConfigOut)
def add_monitor(project_id: int, body: schemas.MonitorConfigIn, db: Session = Depends(get_db)):
    if body.type not in REGISTRY:
        raise HTTPException(status_code=400, detail=f"不支援的監控器類型：{body.type}")
    mc = models.MonitorConfig(
        project_id=project_id, type=body.type, enabled=body.enabled, config_json=body.config_json,
    )
    db.add(mc)
    db.commit()
    db.refresh(mc)
    return mc


@router.delete("/{monitor_id}")
def delete_monitor(project_id: int, monitor_id: int, db: Session = Depends(get_db)):
    mc = db.get(models.MonitorConfig, monitor_id)
    if not mc or mc.project_id != project_id:
        raise HTTPException(status_code=404, detail="找不到此監控器設定")
    db.delete(mc)
    db.commit()
    return {"ok": True}
