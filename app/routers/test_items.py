"""test_items.py — 測項庫查詢（設計文件 5.5 節，依協定分類）＋
測項管理（命名/預設參數覆寫、啟用停用）與健康檢查（設計文件第 20 節）。
"""
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, plugin_healthcheck, registry
from ..db import get_db

router = APIRouter(prefix="/api/test-items", tags=["test-items"])


@router.get("")
def list_test_items(db: Session = Depends(get_db)):
    """對外/測試佇列頁使用：疊加測項管理覆寫層（enabled/health/自訂命名/自訂預設參數）。"""
    return registry.load_registry_with_config(db)


@router.get("/by-category")
def list_test_items_by_category(db: Session = Depends(get_db)):
    grouped = defaultdict(list)
    for item in registry.load_registry_with_config(db):
        grouped[item["category"]].append(item)
    return grouped


@router.get("/health")
def list_test_item_health(db: Session = Depends(get_db)):
    """測項管理頁專用：只看健康檢查/啟用狀態相關欄位，並附上最近一次全體健康檢查的統計。"""
    items = registry.load_registry_with_config(db)
    ok = sum(1 for i in items if i.get("health_status") == "ok")
    error = sum(1 for i in items if i.get("health_status") == "error")
    unknown = sum(1 for i in items if i.get("health_status") == "unknown")
    disabled = sum(1 for i in items if not i.get("enabled", True))
    return {
        "summary": {"total": len(items), "ok": ok, "error": error, "unknown": unknown, "disabled": disabled},
        "items": items,
    }


@router.post("/healthcheck/run")
def run_healthcheck(db: Session = Depends(get_db)):
    """手動觸發重新對全部測項跑一次健康檢查（install.sh 安裝完成後也會呼叫同一套邏輯，
    見 scripts/run_healthcheck.py）。不會改動使用者已手動調整過的 enabled 狀態，
    只有「全新、尚未有紀錄」的測項才會依這次檢查結果決定預設 enabled 值。"""
    return plugin_healthcheck.run_all_healthchecks(db)


@router.patch("/{module}")
def update_test_item_config(module: str, body: dict, db: Session = Depends(get_db)):
    """測項管理頁：啟用/停用、自訂顯示名稱、自訂預設參數、引擎偏好。
    body 可包含：enabled(bool) / custom_name(str) / custom_params_json(dict) /
    engine_mode(str，"native"／"concurrent"／null 代表恢復系統建議預設) /
    engine_workers(int／null 代表恢復系統預設並發數)，只更新有出現在 body 裡的
    欄位（PATCH 語意），未出現的欄位維持原值。"""
    if module not in {e["module"] for e in registry.TEST_ITEMS}:
        raise HTTPException(status_code=404, detail=f"未註冊的測項模組：{module}")

    cfg = db.query(models.TestItemConfig).filter_by(module=module).one_or_none()
    if cfg is None:
        cfg = models.TestItemConfig(module=module, enabled=True, health_status="unknown")
        db.add(cfg)

    if "enabled" in body:
        cfg.enabled = bool(body["enabled"])
    if "custom_name" in body:
        cfg.custom_name = str(body["custom_name"] or "").strip()
    if "custom_params_json" in body:
        val = body["custom_params_json"]
        if val is not None and not isinstance(val, dict):
            raise HTTPException(status_code=400, detail="custom_params_json 必須是物件（key/value）")
        # 自訂預設參數一樣要落在 plugin 自己 get_param_schema() 的
        # min~max 區間內，後端硬檢查（不能只靠前端），避免存進一個之後套用到佇列會被
        # runs.py 擋下、卻搞不清楚為什麼的「壞掉的預設值」。
        if val:
            mod = registry.get_module(module)
            problem = registry.validate_params_against_schema(mod.get_param_schema(), val)
            if problem:
                raise HTTPException(status_code=400, detail=f"參數超出允許範圍，無法儲存為預設值：{problem}")
        cfg.custom_params_json = val or {}
    if "engine_mode" in body:
        val = body["engine_mode"]
        if val is not None and val not in registry.ENGINE_MODE_LABELS:
            raise HTTPException(
                status_code=400,
                detail=f"engine_mode 必須是 {sorted(registry.ENGINE_MODE_LABELS)} 其中之一，或 null（恢復系統建議預設）",
            )
        cfg.engine_mode = val
    if "engine_workers" in body:
        val = body["engine_workers"]
        if val is not None:
            try:
                val = int(val)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="engine_workers 必須是整數，或 null（恢復系統預設並發數）")
            if not (1 <= val <= 32):
                raise HTTPException(status_code=400, detail="engine_workers 可調範圍：1 ~ 32")
        cfg.engine_workers = val

    db.commit()
    db.refresh(cfg)

    merged = {
        item["module"]: item for item in registry.load_registry_with_config(db)
    }.get(module)
    return merged
