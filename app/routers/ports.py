"""ports.py — Port 選擇（設計文件 5.3 節）：勾選/取消、手動新增、備註"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db

router = APIRouter(prefix="/api/projects/{project_id}/ports", tags=["ports"])


@router.get("", response_model=list[schemas.PortEntryOut])
def list_ports(project_id: int, db: Session = Depends(get_db)):
    return (
        db.query(models.PortEntry)
        .filter_by(project_id=project_id)
        .order_by(models.PortEntry.port)
        .all()
    )


@router.post("", response_model=schemas.PortEntryOut)
def add_port(project_id: int, body: schemas.PortEntryCreate, db: Session = Depends(get_db)):
    entry = models.PortEntry(
        project_id=project_id, port=body.port, protocol=body.protocol,
        service_name=body.service_name, note=body.note, source="manual",
        state="open", selected=True,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@router.patch("/{port_id}", response_model=schemas.PortEntryOut)
def update_port(project_id: int, port_id: int, body: schemas.PortEntryUpdate, db: Session = Depends(get_db)):
    entry = db.get(models.PortEntry, port_id)
    if not entry or entry.project_id != project_id:
        raise HTTPException(status_code=404, detail="找不到此 Port")
    if body.selected is not None:
        entry.selected = body.selected
    if body.note is not None:
        entry.note = body.note
    db.commit()
    db.refresh(entry)
    return entry


@router.delete("/{port_id}")
def delete_port(project_id: int, port_id: int, db: Session = Depends(get_db)):
    entry = db.get(models.PortEntry, port_id)
    if not entry or entry.project_id != project_id:
        raise HTTPException(status_code=404, detail="找不到此 Port")
    db.delete(entry)
    db.commit()
    return {"ok": True}
