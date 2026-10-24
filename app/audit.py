"""
app/audit.py — 稽核 log 寫入工具（設計文件第 8 節：只新增不修改/刪除）。
沒有提供任何 update/delete 的 API 路由，這是「唯讀不可竄改」的落地方式之一。
"""
from sqlalchemy.orm import Session

from . import models


def log(db: Session, operator_name: str, action: str, target_ref: str = "", detail: dict | None = None):
    entry = models.AuditLog(
        operator_name=operator_name or "",
        action=action,
        target_ref=target_ref,
        detail_json=detail or {},
    )
    db.add(entry)
    db.commit()
    return entry
