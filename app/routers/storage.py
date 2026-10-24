"""
app/routers/storage.py — 封包擷取檔案的跨專案儲存空間管理

使用者回報：工具用久了，各專案累積的 pcap 檔案可能很大、佔用磁碟空間，需要一個地方
能「容易選擇要刪除哪些大檔案」——這不是單一專案內的事（使用者是對整個工具的磁碟用量
有疑慮），所以這裡刻意做成跨專案的全域清單，預設依檔案大小由大到小排序，並支援勾選
多筆一次刪除。

刪除語意：只刪除實際磁碟上的檔案（釋放空間），但保留 CaptureFile 這筆資料庫紀錄本身
（連同刪除前的大小/刪除時間/操作者），讓歷史報告與這個管理清單事後還看得出「這裡曾經
有一個多大的檔案、什麼時候被誰刪除」，不是整筆資料憑空消失、無法追溯。
"""
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import audit, models
from ..db import get_db

router = APIRouter(prefix="/api/storage", tags=["storage"])


def _capture_row(c: models.CaptureFile) -> dict:
    run = c.test_run
    project = run.project if run else None
    target = project.target if project else None
    path = Path(c.file_path) if c.file_path else None
    file_exists = bool(path and path.exists())
    return {
        "id": c.id,
        "project_id": project.id if project else None,
        "project_name": project.name if project else "",
        "target": target.ip_or_host if target else "",
        "test_run_id": run.id if run else None,
        "run_name": run.test_item_name if run else "",
        "attempt_no": run.attempt_no if run else None,
        "mode": c.mode,
        "size_bytes": c.size_bytes,
        "deleted": c.deleted,
        "deleted_at": c.deleted_at.isoformat() if c.deleted_at else None,
        "deleted_by": c.deleted_by,
        "file_exists": file_exists,
        "run_ended_at": run.ended_at.isoformat() if run and run.ended_at else None,
    }


@router.get("/captures")
def list_captures(db: Session = Depends(get_db), include_deleted: bool = True):
    """列出所有專案的封包擷取檔案，預設依大小由大到小排序，方便使用者快速找到佔空間
    最兇的檔案。include_deleted=false 可以只看還存在的檔案。"""
    q = db.query(models.CaptureFile)
    if not include_deleted:
        q = q.filter_by(deleted=False)
    rows = q.all()
    items = [_capture_row(c) for c in rows]
    items.sort(key=lambda r: r["size_bytes"], reverse=True)
    active_total = sum(r["size_bytes"] for r in items if not r["deleted"])
    deleted_total = sum(r["size_bytes"] for r in items if r["deleted"])
    return {
        "items": items,
        "summary": {
            "active_count": sum(1 for r in items if not r["deleted"]),
            "active_bytes": active_total,
            "deleted_count": sum(1 for r in items if r["deleted"]),
            "deleted_bytes_freed": deleted_total,
        },
    }


@router.get("/captures/{capture_id}/download")
def download_capture(capture_id: int, db: Session = Depends(get_db)):
    c = db.get(models.CaptureFile, capture_id)
    if not c:
        raise HTTPException(status_code=404, detail="找不到這個封包檔案紀錄")
    if c.deleted:
        raise HTTPException(status_code=404, detail="這個檔案已被刪除，無法下載")
    if not c.file_path or not Path(c.file_path).exists():
        raise HTTPException(status_code=404, detail="磁碟上找不到這個檔案（可能已被移除）")
    filename = Path(c.file_path).name
    media_type = "application/vnd.tcpdump.pcap" if c.mode in ("pcap", "both") else "text/plain"
    return FileResponse(c.file_path, media_type=media_type, filename=filename)


class BulkDeleteBody(BaseModel):
    ids: list[int]
    operator_name: str = ""


@router.post("/captures/delete")
def bulk_delete_captures(body: BulkDeleteBody, db: Session = Depends(get_db)):
    """刪除勾選的封包檔案（釋放磁碟空間），保留資料庫紀錄與稽核軌跡。"""
    if not body.ids:
        raise HTTPException(status_code=400, detail="沒有指定要刪除的檔案")

    freed_bytes = 0
    deleted_ids: list[int] = []
    errors: list[dict] = []

    for cid in body.ids:
        c = db.get(models.CaptureFile, cid)
        if not c:
            errors.append({"id": cid, "error": "找不到這筆紀錄"})
            continue
        if c.deleted:
            continue  # 已經刪過了，視為成功（冪等），不重複計入
        path = Path(c.file_path) if c.file_path else None
        try:
            if path and path.exists():
                os.remove(path)
        except OSError as e:
            errors.append({"id": cid, "error": str(e)})
            continue
        from datetime import datetime as _dt
        c.deleted = True
        c.deleted_at = _dt.utcnow()
        c.deleted_by = body.operator_name or ""
        freed_bytes += c.size_bytes
        deleted_ids.append(cid)

    db.commit()

    if deleted_ids:
        audit.log(
            db, body.operator_name, "delete_capture_files",
            target_ref=",".join(str(i) for i in deleted_ids),
            detail={"deleted_ids": deleted_ids, "freed_bytes": freed_bytes, "errors": errors},
        )

    return {"deleted_ids": deleted_ids, "freed_bytes": freed_bytes, "errors": errors}
