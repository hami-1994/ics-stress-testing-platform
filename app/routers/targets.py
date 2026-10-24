"""targets.py — 標的設定 + 測試範圍確認閘門（設計文件 5.1 節）+ 目標清單管理"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import audit, models, schemas
from ..db import get_db

router = APIRouter(prefix="/api/targets", tags=["targets"])


def _with_project_count(db: Session, target: models.Target) -> schemas.TargetOut:
    count = db.query(models.Project).filter_by(target_id=target.id).count()
    out = schemas.TargetOut.model_validate(target)
    out.project_count = count
    return out


@router.post("", response_model=schemas.TargetOut)
def create_target(body: schemas.TargetCreate, db: Session = Depends(get_db)):
    if not body.scope_confirmed:
        raise HTTPException(
            status_code=400,
            detail="未勾選測試範圍確認，無法建立目標（請確認已取得對此目標進行壓力測試之授權）",
        )
    if not body.operator_name.strip():
        raise HTTPException(status_code=400, detail="請填寫操作者姓名")

    target = models.Target(
        ip_or_host=body.ip_or_host.strip(),
        description=body.description,
        scope_confirmed=True,
        confirmed_at=datetime.utcnow(),
        confirmed_by=body.operator_name.strip(),
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    audit.log(db, body.operator_name, "confirm_target_scope", target_ref=target.ip_or_host,
               detail={"target_id": target.id, "description": body.description})
    return _with_project_count(db, target)


@router.get("", response_model=list[schemas.TargetOut])
def list_targets(db: Session = Depends(get_db)):
    targets = db.query(models.Target).order_by(models.Target.created_at.desc()).all()
    return [_with_project_count(db, t) for t in targets]


@router.get("/{target_id}", response_model=schemas.TargetOut)
def get_target(target_id: int, db: Session = Depends(get_db)):
    target = db.get(models.Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="找不到目標")
    return _with_project_count(db, target)


@router.patch("/{target_id}", response_model=schemas.TargetOut)
def update_target(target_id: int, body: schemas.TargetUpdate, db: Session = Depends(get_db)):
    """只開放改描述。IP/主機名不能改——改了等於是另一個測試範圍，
    要重新建立目標並重新走一次測試範圍確認，不能沿用舊的確認紀錄。"""
    target = db.get(models.Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="找不到目標")
    target.description = body.description
    db.commit()
    db.refresh(target)
    return _with_project_count(db, target)


@router.delete("/{target_id}")
def delete_target(target_id: int, operator_name: str = "", db: Session = Depends(get_db)):
    target = db.get(models.Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="找不到目標")

    project_count = db.query(models.Project).filter_by(target_id=target_id).count()
    if project_count > 0:
        raise HTTPException(
            status_code=400,
            detail=f"此目標仍有 {project_count} 個專案使用中，無法刪除（避免專案/報告失去對應的目標紀錄）",
        )

    audit.log(db, operator_name, "delete_target", target_ref=target.ip_or_host,
               detail={"target_id": target.id})
    db.delete(target)
    db.commit()
    return {"ok": True}
