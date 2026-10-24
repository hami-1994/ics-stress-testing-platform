"""scans.py — Port Scan（設計文件 5.2 節）"""
import threading

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, scan, schemas
from ..config import PROJECTS_DIR
from ..db import get_db

router = APIRouter(prefix="/api/projects/{project_id}/scans", tags=["scans"])


@router.post("", response_model=schemas.ScanOut)
def start_scan(project_id: int, body: schemas.ScanCreate, db: Session = Depends(get_db)):
    project = db.get(models.Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="找不到專案")

    scan_row = models.ScanResult(
        project_id=project_id, scan_type=body.scan_type, port_range=body.port_range, status="pending",
    )
    db.add(scan_row)
    db.commit()
    db.refresh(scan_row)

    project_dir = PROJECTS_DIR / project.project_dir_name
    threading.Thread(target=scan.run_scan_background, args=(scan_row.id, project_dir), daemon=True).start()
    return scan_row


@router.get("", response_model=list[schemas.ScanOut])
def list_scans(project_id: int, db: Session = Depends(get_db)):
    return db.query(models.ScanResult).filter_by(project_id=project_id).order_by(models.ScanResult.id.desc()).all()


@router.get("/{scan_id}", response_model=schemas.ScanOut)
def get_scan(project_id: int, scan_id: int, db: Session = Depends(get_db)):
    s = db.get(models.ScanResult, scan_id)
    if not s or s.project_id != project_id:
        raise HTTPException(status_code=404, detail="找不到掃描紀錄")
    return s
