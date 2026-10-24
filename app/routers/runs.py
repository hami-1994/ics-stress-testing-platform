"""
runs.py — 測試佇列（Test Plan）建立與執行控制（設計文件 5.5、5.6 節）
"""
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from .. import audit, models, registry, schemas
from ..config import MAX_DURATION_SEC
from ..db import get_db
from ..orchestrator import get_orchestrator

router = APIRouter(prefix="/api/projects/{project_id}/runs", tags=["runs"])


@router.get("", response_model=list[schemas.TestRunOut])
def list_runs(project_id: int, db: Session = Depends(get_db)):
    return (
        db.query(models.TestRun)
        .filter_by(project_id=project_id)
        .order_by(models.TestRun.order_index)
        .all()
    )


@router.post("", response_model=schemas.TestRunOut)
def add_run(project_id: int, body: schemas.TestRunCreate, db: Session = Depends(get_db)):
    project = db.get(models.Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="找不到專案")

    try:
        mod = registry.get_module(body.test_item_module)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 測項管理／健康檢查閘門——被停用（含健康檢查失敗預設停用）的測項
    # 不可被加入測試佇列，避免使用者不小心排入一個依賴缺漏、實際上跑不動的測項卡住佇列。
    ok, reason = registry.is_enabled(body.test_item_module, db)
    if not ok:
        raise HTTPException(status_code=400, detail=reason)

    protocol = getattr(mod, "PROTOCOL", "TCP")
    if protocol != "L2" and body.port_id is None:
        raise HTTPException(
            status_code=400,
            detail=f"「{getattr(mod, 'NAME', body.test_item_module)}」不是 Layer2 測項，必須指定目標 Port",
        )
    if body.port_id is not None:
        port_entry = db.get(models.PortEntry, body.port_id)
        if not port_entry or port_entry.project_id != project_id:
            raise HTTPException(status_code=400, detail="指定的 Port 不存在於此專案")

    # 參數區間後端硬檢查，不能只靠前端（跟 duration 的處理方式一致）。
    problem = registry.validate_params_against_schema(mod.get_param_schema(), body.params_json or {})
    if problem:
        raise HTTPException(status_code=400, detail=f"參數超出允許範圍，無法加入佇列：{problem}")

    duration = max(1, min(int(body.duration_sec), MAX_DURATION_SEC))  # 後端硬上限，不能只靠前端

    max_order = (
        db.query(models.TestRun).filter_by(project_id=project_id).count()
    )
    run = models.TestRun(
        project_id=project_id, port_id=body.port_id, order_index=max_order,
        test_item_module=body.test_item_module,
        test_item_name=getattr(mod, "NAME", body.test_item_module),
        category=getattr(mod, "CATEGORY", "一般"),
        params_json=body.params_json, duration_sec=duration,
        capture_mode=body.capture_mode, status="pending",
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


@router.patch("/{run_id}", response_model=schemas.TestRunOut)
def update_run(project_id: int, run_id: int, body: schemas.TestRunUpdate, db: Session = Depends(get_db)):
    """編輯還沒開始執行的測項（Port/參數/時長/擷取模式）。已在跑/已結束的項目不能改，
    避免跟已經寫進報告的紀錄對不起來——想改的話用「刪除」重加一筆。"""
    run = db.get(models.TestRun, run_id)
    if not run or run.project_id != project_id:
        raise HTTPException(status_code=404, detail="找不到此測試項目")
    if run.status != "pending":
        raise HTTPException(status_code=400, detail="只有還沒開始執行（pending）的項目可以編輯")

    if body.port_id is not None:
        mod = registry.get_module(run.test_item_module)
        if getattr(mod, "PROTOCOL", "TCP") != "L2":
            port_entry = db.get(models.PortEntry, body.port_id)
            if not port_entry or port_entry.project_id != project_id:
                raise HTTPException(status_code=400, detail="指定的 Port 不存在於此專案")
        run.port_id = body.port_id
    if body.params_json is not None:
        mod_for_validate = registry.get_module(run.test_item_module)
        problem = registry.validate_params_against_schema(mod_for_validate.get_param_schema(), body.params_json)
        if problem:
            raise HTTPException(status_code=400, detail=f"參數超出允許範圍，無法儲存：{problem}")
        run.params_json = body.params_json
    if body.duration_sec is not None:
        run.duration_sec = max(1, min(int(body.duration_sec), MAX_DURATION_SEC))
    if body.capture_mode is not None:
        run.capture_mode = body.capture_mode

    db.commit()
    db.refresh(run)
    return run


@router.delete("/{run_id}")
def delete_run(project_id: int, run_id: int, db: Session = Depends(get_db)):
    run = db.get(models.TestRun, run_id)
    if not run or run.project_id != project_id:
        raise HTTPException(status_code=404, detail="找不到此測試項目")
    if run.status == "running":
        raise HTTPException(status_code=400, detail="執行中的項目無法刪除，請先停止")
    db.delete(run)
    db.commit()
    return {"ok": True}


@router.post("/start")
def start_queue(project_id: int, operator_name: str = "", db: Session = Depends(get_db)):
    project = db.get(models.Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="找不到專案")
    result = get_orchestrator(project_id).start()
    audit.log(db, operator_name or project.operator_name, "start_test_queue",
               target_ref=str(project_id), detail=result)
    return result


@router.post("/stop")
def stop_current(project_id: int, operator_name: str = "", db: Session = Depends(get_db)):
    project = db.get(models.Project, project_id)
    result = get_orchestrator(project_id).stop_current()
    audit.log(db, operator_name or (project.operator_name if project else ""),
               "stop_current_test", target_ref=str(project_id), detail=result)
    return result


@router.post("/skip")
def skip_current(project_id: int, operator_name: str = "", db: Session = Depends(get_db)):
    """跳過目前正在執行的測項：直接中止它（狀態標成 skipped，不算通過/失敗），
    報告會保留跳過前已經蒐集到的結果與監控資料，並註明是使用者主動跳過。
    跟「停止」不一樣的地方：跳過之後佇列會自動接續下一項，不會暫停等待「恢復」。"""
    project = db.get(models.Project, project_id)
    result = get_orchestrator(project_id).skip_current()
    audit.log(db, operator_name or (project.operator_name if project else ""),
               "skip_current_test", target_ref=str(project_id), detail=result)
    return result


@router.post("/resume")
def resume_queue(project_id: int, operator_name: str = "", db: Session = Depends(get_db)):
    project = db.get(models.Project, project_id)
    stopped_run = (
        db.query(models.TestRun)
        .filter_by(project_id=project_id, status="stopped")
        .order_by(models.TestRun.order_index)
        .first()
    )

    # 因「攻擊端自身資源過載」被自動中止而暫停的佇列：這一項幾乎沒有真的測到什麼（一啟動就被
    # 保護機制中止），操作者確認資源恢復後，重測這一項再接續，跟「停止」的處理方式一樣。
    if not stopped_run:
        stopped_run = (
            db.query(models.TestRun)
            .filter_by(project_id=project_id, verdict="aborted_self_protect")
            .order_by(models.TestRun.order_index.desc())
            .first()
        )

    if stopped_run:
        stopped_run.status = "pending"
        stopped_run.attempt_no += 1
        stopped_run.started_at = None
        stopped_run.ended_at = None
        stopped_run.interruption_sec = 0.0
        stopped_run.recovered = None
        stopped_run.recovery_wait_used_sec = 0.0
        stopped_run.verdict = "unknown"
        stopped_run.stability_verdict = "unknown"
        stopped_run.recovery_verdict = "unknown"
        stopped_run.aborted_by_interruption = False
        stopped_run.skip_reason = ""
        db.commit()
        result = get_orchestrator(project_id).start()
        audit.log(db, operator_name or (project.operator_name if project else ""),
                   "resume_test_queue", target_ref=str(project_id),
                   detail={"resumed_run_id": stopped_run.id, "attempt_no": stopped_run.attempt_no})
        return result

    # 沒有被「停止」的項目——可能是因為「測項結束後恢復檢查失敗」而暫停的佇列
    # （見 orchestrator._run_loop：recovered is False 時會自動暫停，不會自動往下一項）。
    # 這種情況下不重測該項目（它的中斷/未恢復紀錄要如實留在報告裡），
    # 操作者確認裝置狀況沒問題後，直接讓佇列從下一個 pending 項目繼續即可。
    unrecovered_run = (
        db.query(models.TestRun)
        .filter_by(project_id=project_id, recovered=False)
        .order_by(models.TestRun.order_index.desc())
        .first()
    )
    pending_count = db.query(models.TestRun).filter_by(project_id=project_id, status="pending").count()
    if unrecovered_run and pending_count > 0:
        result = get_orchestrator(project_id).start()
        audit.log(db, operator_name or (project.operator_name if project else ""),
                   "confirm_recovery_and_continue", target_ref=str(project_id),
                   detail={"unrecovered_run_id": unrecovered_run.id})
        return result

    raise HTTPException(status_code=400, detail="沒有已停止、可恢復的測試項目，也沒有因服務未恢復而暫停的佇列")


@router.get("/{run_id}/log/download")
def download_run_log(project_id: int, run_id: int, db: Session = Depends(get_db)):
    """讓使用者在歷史專案／執行紀錄裡直接下載某一次測項執行的完整 log 檔（stdout.log），
    不用自己去翻伺服器檔案系統路徑。"""
    run = db.query(models.TestRun).filter_by(project_id=project_id, id=run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="找不到測項")
    if not run.log_path or not Path(run.log_path).exists():
        raise HTTPException(status_code=404, detail="找不到這次執行的 log 檔（可能尚未執行或檔案已被移除）")
    return FileResponse(
        run.log_path, media_type="text/plain",
        filename=f"project{project_id}_run{run_id}_attempt{run.attempt_no}.log",
    )


@router.post("/kill-switch")
def kill_switch(project_id: int, operator_name: str = "", db: Session = Depends(get_db)):
    project = db.get(models.Project, project_id)
    result = get_orchestrator(project_id).emergency_stop()
    audit.log(db, operator_name or (project.operator_name if project else ""),
               "emergency_stop", target_ref=str(project_id), detail=result)
    return result
