"""projects.py — 專案建立、列表、詳情、報告下載（設計文件 5.8、5.9 節）"""
import shutil

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from .. import audit, models, schemas
from ..config import PROJECTS_DIR
from ..db import get_db
from ..orchestrator import _orchestrators, _orchestrators_lock

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.post("", response_model=schemas.ProjectOut)
def create_project(body: schemas.ProjectCreate, db: Session = Depends(get_db)):
    target = db.get(models.Target, body.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="找不到目標")
    if not target.scope_confirmed:
        raise HTTPException(status_code=400, detail="此目標尚未完成測試範圍確認")

    project = models.Project(
        name=body.name, target_id=body.target_id, operator_name=body.operator_name,
        max_interruption_sec=max(0, body.max_interruption_sec),
        recovery_wait_sec=max(0, body.recovery_wait_sec),
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    audit.log(db, body.operator_name, "create_project", target_ref=target.ip_or_host,
               detail={"project_id": project.id, "name": project.name})
    return project


@router.get("", response_model=list[schemas.ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    return db.query(models.Project).order_by(models.Project.created_at.desc()).all()


@router.get("/{project_id}", response_model=schemas.ProjectOut)
def get_project(project_id: int, db: Session = Depends(get_db)):
    project = db.get(models.Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="找不到專案")
    return project


@router.delete("/{project_id}")
def delete_project(project_id: int, db: Session = Depends(get_db)):
    """刪除專案（連同資料庫紀錄與 data/projects/{id}_.../ 底下的所有檔案，
    含 log／封包擷取檔／報告 HTML/PDF/JSON，一次刪乾淨）。這是不可逆操作，
    前端必須先跳確認對話框；正在執行測試佇列中的專案不允許刪除，避免刪到一半
    Orchestrator 還在背景寫入這個專案的資料。"""
    project = db.get(models.Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="找不到專案")

    with _orchestrators_lock:
        orch = _orchestrators.get(project_id)
    if orch is not None and orch.is_running:
        raise HTTPException(
            status_code=400,
            detail="這個專案目前正在執行測試佇列，請先在「執行」頁按「停止」或「緊急停止」再刪除。",
        )

    project_name = project.name
    target_ref = project.target.ip_or_host if project.target else ""
    dir_name = project.project_dir_name

    db.delete(project)
    db.commit()

    with _orchestrators_lock:
        _orchestrators.pop(project_id, None)

    project_dir = PROJECTS_DIR / dir_name
    if project_dir.exists():
        shutil.rmtree(project_dir, ignore_errors=True)

    audit.log(db, "", "delete_project", target_ref=target_ref,
               detail={"project_id": project_id, "name": project_name})
    return {"deleted": True, "project_id": project_id}


@router.get("/{project_id}/report")
def get_report_info(project_id: int, db: Session = Depends(get_db)):
    report = (
        db.query(models.Report)
        .filter_by(project_id=project_id)
        .order_by(models.Report.generated_at.desc())
        .first()
    )
    if not report:
        return {"available": False}
    return {
        "available": True,
        "html_url": f"/api/projects/{project_id}/report/html",
        "pdf_url": f"/api/projects/{project_id}/report/pdf" if report.pdf_path else None,
        "json_url": f"/api/projects/{project_id}/report/json",
    }


@router.get("/{project_id}/report/html")
def get_report_html(project_id: int, db: Session = Depends(get_db)):
    report = _latest_report(db, project_id)
    return FileResponse(report.html_path, media_type="text/html")


@router.get("/{project_id}/report/pdf")
def get_report_pdf(project_id: int, db: Session = Depends(get_db)):
    report = _latest_report(db, project_id)
    if not report.pdf_path:
        raise HTTPException(status_code=404, detail="尚未產生 PDF（可能未安裝 weasyprint），請改用 HTML 版本")
    return FileResponse(report.pdf_path, media_type="application/pdf",
                          filename=f"project_{project_id}_report.pdf")


@router.get("/{project_id}/report/json")
def get_report_json(project_id: int, db: Session = Depends(get_db)):
    report = _latest_report(db, project_id)
    return FileResponse(report.json_path, media_type="application/json")


def _latest_report(db: Session, project_id: int) -> models.Report:
    report = (
        db.query(models.Report)
        .filter_by(project_id=project_id)
        .order_by(models.Report.generated_at.desc())
        .first()
    )
    if not report:
        raise HTTPException(status_code=404, detail="此專案尚未產生報告（測試佇列全部完成後才會自動產生）")
    return report
