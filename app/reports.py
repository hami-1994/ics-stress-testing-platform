"""
app/reports.py — 報告產生（設計文件 5.8 節）

流程：組結構化 JSON -> 套 Jinja2 HTML 模板 -> 若環境有裝 weasyprint 就順便產 PDF
（沒裝也沒關係，HTML 版本本來就能在瀏覽器開/列印，不會因為 PDF 套件沒裝就整個失敗）。

這一版加強「一般使用者（非工程師）也看得懂」的呈現方式：
  - 測項參數／執行結果不再直接丟原始 JSON，而是轉成「參數說明：數值」的中文對照
    （參數說明取自各測項 plugin 的 get_param_schema() 裡的 desc；結果欄位用固定的
    中文對照表，對照不到的欄位照樣顯示，只是沒有中文說明）。
  - 監控摘要除了 min/max/avg，還會統計「異常(critical)」「警示(warn)」次數
    （由 app/health.py 在測試當下就已經逐筆判斷好，寫進 CSV 的 level 欄位，這裡只是彙總）。
  - 每個測項都有明確的通過/失敗/警示/無法判斷（pass/warn/fail/unknown）判定，
    判定邏輯與門檻見 app/orchestrator.py 的 _compute_verdict()。
  - 報告最前面插入「總覽 Summary」，用圖示＋顏色列出哪些測項的哪些監控器有異常、
    哪些測項被判定 fail，讓人不用逐項往下讀就能抓到重點。
"""
import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from . import models, registry
from .config import BASE_DIR, PROJECTS_DIR
from .monitors import REGISTRY as MONITOR_REGISTRY

_env = Environment(loader=FileSystemLoader(str(BASE_DIR / "app" / "templates")))

# ---- 人類可讀對照表 ----

_RESULT_LABELS = {
    "ok": "成功次數", "fail": "失敗次數", "errors": "錯誤次數", "error": "錯誤訊息",
    "timeouts": "逾時次數", "elapsed_sec": "實際執行秒數", "returncode": "程式結束代碼",
    "frames_sent": "已送出封包數", "packets_sent": "已送出封包數", "sent": "已送出數量",
    "received": "已收到數量", "connections": "連線數", "requests": "請求數",
    "connected": "是否成功連線", "row_count": "取樣筆數", "success": "成功次數",
    "bytes_sent": "已送出位元組數", "attempts": "嘗試次數", "failures": "失敗次數",
    "closed": "已關閉連線數", "opened": "已開啟連線數", "queries": "查詢次數",
    "responses": "回應次數", "no_response": "無回應次數", "churns": "churn 循環次數",
    # 「高並發加速版」引擎（見 app/plugins/common.py）
    # 執行時會在回傳結果附加這兩個欄位，說明這次執行實際用的是哪種引擎/幾條並發執行緒。
    "engine_mode": "執行引擎", "engine_workers": "並發執行緒數",
}

_MONITOR_METRIC_LABELS = {
    "rtt_ms": "延遲 (ms)", "loss": "是否丟包", "up": "服務是否存活",
    "latency_ms": "延遲 (ms)", "cpu_percent": "CPU 使用率 (%)", "mem_percent": "記憶體使用率 (%)",
    "load1": "1分鐘負載平均", "bps_sent": "送出頻寬 (bps)", "bps_recv": "接收頻寬 (bps)",
    "pps_sent": "送出封包速率 (pps)", "pps_recv": "接收封包速率 (pps)",
    "errin": "接收錯誤累計數", "errout": "送出錯誤累計數",
    "dropin": "接收丟棄累計數", "dropout": "送出丟棄累計數",
    "total": "連線總數", "established": "已建立連線數", "syn_sent": "SYN_SENT 數",
    "syn_recv": "SYN_RECV 數", "time_wait": "TIME_WAIT 數", "close_wait": "CLOSE_WAIT 數",
    "closing": "CLOSING/LAST_ACK 數",
}

_VERDICT_LABELS = {
    "pass": ("通過", "✅", "verdict-pass"),
    "warn": ("通過（有警示）", "⚠️", "verdict-warn"),
    "fail": ("未通過", "❌", "verdict-fail"),
    "unknown": ("無法判斷（未啟用判定用監控器）", "❔", "verdict-unknown"),
    "skipped": ("已跳過（使用者中止執行）", "⏭️", "verdict-skipped"),
    "aborted_self_protect": ("已中止（攻擊端主機資源保護）", "🛡️", "verdict-selfprotect"),
    "unreachable": ("無法測試（目標 Port 從一開始就無回應）", "🚫", "verdict-unreachable"),
}

# Summary 總覽卡片顯示順序（連同 label/icon 一起，count 從 verdict_counts 動態取）
# 判定拆成「過程穩定性」／「恢復能力」兩個獨立維度後，「中斷超標但事後恢復」這種情況
# 不是介於 warn/fail 之間的模糊「異常」狀態，而是明確算「過程穩定性 fail」，綜合判定
# （verdict）直接是 fail，細節由下面兩個維度呈現。
_VERDICT_ORDER = ["pass", "warn", "fail", "unreachable", "skipped", "aborted_self_protect", "unknown"]

# 判定拆成兩個獨立維度分別呈現——一個是測試過程連線和服務狀態，一個是受攻擊後的恢復能力，
# 跟 app/orchestrator.py 的
# _compute_axis_verdicts() 算出來的 stability_verdict／recovery_verdict 對應。
_STABILITY_LABELS = {
    "pass": ("過程穩定，無中斷", "🟢", "verdict-pass"),
    "warn": ("過程曾短暫中斷（在可接受範圍內）", "🟡", "verdict-warn"),
    "fail": ("過程中斷超過可接受秒數", "🔴", "verdict-fail"),
    "unknown": ("無法判斷（未啟用判定用監控器）", "❔", "verdict-unknown"),
    "na": ("不適用", "⚪", "verdict-skipped"),
}
_RECOVERY_LABELS = {
    "pass": ("結束後已恢復", "🟢", "verdict-pass"),
    "fail": ("結束後未如期恢復", "🔴", "verdict-fail"),
    "unknown": ("無法判斷（未檢查或無可用監控器）", "❔", "verdict-unknown"),
    "na": ("不適用", "⚪", "verdict-skipped"),
}

_LEVEL_LABELS = {
    "ok": ("正常", "🟢"), "warn": ("警示", "🟡"), "critical": ("異常", "🔴"), "na": ("不適用", "⚪"),
}


def _humanize_params(module_path: str, params: dict) -> list[dict]:
    schema = {}
    try:
        mod = registry.get_module(module_path)
        schema = mod.get_param_schema() or {}
    except Exception:  # noqa: BLE001  舊資料的測項模組路徑可能已經不存在，不能讓報告整個產生失敗
        schema = {}
    rows = []
    for key, value in (params or {}).items():
        desc = schema.get(key, {}).get("desc", "")
        rows.append({"key": key, "label": desc or key, "value": value})
    return rows


_ENGINE_MODE_VALUE_LABELS = {"native": "標準版", "concurrent": "高並發加速版"}


def _humanize_result(result: dict) -> list[dict]:
    rows = []
    for key, value in (result or {}).items():
        label = _RESULT_LABELS.get(key, key)
        if key == "engine_mode":
            value = _ENGINE_MODE_VALUE_LABELS.get(value, value)
        rows.append({"key": key, "label": label, "value": value})
    return rows


def _monitor_display_name(monitor_type: str) -> str:
    mod = MONITOR_REGISTRY.get(monitor_type)
    return getattr(mod, "NAME", monitor_type) if mod else monitor_type


def _test_type_of(module_path: str) -> tuple[str, str, str]:
    """回傳 (test_type, label, icon)，取自 app/registry.py 的 TEST_TYPE_LABELS 對照表。
    舊資料的測項模組路徑可能已經不存在（例如測項被移除/改名），不能讓報告整個產生失敗。"""
    try:
        mod = registry.get_module(module_path)
        test_type = getattr(mod, "TEST_TYPE", "traffic")
    except Exception:  # noqa: BLE001
        test_type = "traffic"
    info = registry.TEST_TYPE_LABELS.get(test_type, registry.TEST_TYPE_LABELS["traffic"])
    return test_type, info["label"], info["icon"]


# 「判定用」監控器：這幾種監控器取樣後由 app/health.py 判斷出的 level（ok/warn/critical）
# 會被拿去累計中斷秒數、決定通過/失敗判定（見 app/orchestrator.py 的 _HEALTH_MONITOR_TYPES）。
# 只有「攻擊端自我資源監控」（CPU/記憶體，量的是攻擊端自己的狀態、不是標的健康狀態）是
# 「診斷用」——有異常值得留意，但不會讓測項被判定為未通過，也不會觸發提前中止。
#
# 除了 self_resource 以外全部算判定用：可接受最長連續服務中斷秒數這個指標也涵蓋
# 連線本身這個網路連線服務，不只侷限在開在 Port 上的服務，這裡統一定義給 Summary
# 矩陣表跟監控摘要說明共用，跟 app/orchestrator.py 的 _HEALTH_MONITOR_TYPES 保持一致。
_VERDICT_DETERMINING_TYPES = ("service", "udp", "arp", "ping", "iface", "tcp")


def _monitor_role_label(monitor_type: str) -> str:
    return "判定用" if monitor_type in _VERDICT_DETERMINING_TYPES else "診斷用"


def _build_report_data(db, project_id: int) -> dict:
    project = db.get(models.Project, project_id)
    target = project.target
    runs = list(project.runs)

    run_rows = []
    failed_items, warn_items, monitor_alerts = [], [], []
    skipped_items, unreachable_items = [], []
    # 按「過程穩定性」／「恢復能力」兩個獨立維度分別收集有問題的測項，
    # 讓摘要跟總覽可以分開點名「哪些項目是過程本身不穩定、哪些項目是事後沒恢復」——同一個
    # 測項可能同時出現在兩個清單裡（過程也不穩、事後也沒恢復），不是互斥分類。
    stability_fail_items, stability_warn_items, recovery_fail_items = [], [], []

    # 注意：display_no 是「該專案測試佇列內從 1 開始」的序號，跟網頁「本次專案測試佇列」表格
    # 的 # 欄位（app.js renderRunLiveTable 用陣列索引 i+1）算法一致，跟資料庫全域自動遞增的
    # r.id（跨所有專案共用一個序號）是兩回事。報告一律顯示 display_no，不顯示 r.id，避免跟網頁
    # 上看到的編號對不起來。
    for i, r in enumerate(runs, start=1):
        monitors_summary = {}
        run_dir = PROJECTS_DIR / project.project_dir_name / "runs" / f"run_{r.id}_attempt{r.attempt_no}" / "monitors"
        if run_dir.exists():
            for csv_file in run_dir.glob("*.csv"):
                summary = _summarize_csv(csv_file)
                summary["display_name"] = _monitor_display_name(csv_file.stem)
                summary["role"] = _monitor_role_label(csv_file.stem)
                monitors_summary[csv_file.stem] = summary
                if summary.get("critical_count") or summary.get("warn_count"):
                    monitor_alerts.append({
                        "run_id": r.id, "display_no": i, "name": r.test_item_name,
                        "port": r.port.port if r.port else None,
                        "monitor": csv_file.stem, "monitor_name": _monitor_display_name(csv_file.stem),
                        "critical_count": summary.get("critical_count", 0),
                        "warn_count": summary.get("warn_count", 0),
                    })

        verdict_label, verdict_icon, verdict_css = _VERDICT_LABELS.get(r.verdict, _VERDICT_LABELS["unknown"])
        stability_label, stability_icon, stability_css = _STABILITY_LABELS.get(
            r.stability_verdict, _STABILITY_LABELS["unknown"])
        recovery_label, recovery_icon, recovery_css = _RECOVERY_LABELS.get(
            r.recovery_verdict, _RECOVERY_LABELS["unknown"])
        test_type, test_type_label, test_type_icon = _test_type_of(r.test_item_module)
        item = {
            "id": r.id, "display_no": i, "port": r.port.port if r.port else None,
            "protocol": r.port.protocol if r.port else r.category,
            "name": r.test_item_name, "category": r.category,
            "test_type": test_type, "test_type_label": test_type_label, "test_type_icon": test_type_icon,
            "params": r.params_json, "params_readable": _humanize_params(r.test_item_module, r.params_json),
            "duration_sec": r.duration_sec,
            "capture_mode": r.capture_mode, "status": r.status,
            "attempt_no": r.attempt_no,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "ended_at": r.ended_at.isoformat() if r.ended_at else None,
            "result_summary": r.result_summary_json,
            "result_readable": _humanize_result(r.result_summary_json),
            "monitors_summary": monitors_summary,
            "log_path": r.log_path,
            "captures": [{"file": c.file_path, "size_bytes": c.size_bytes, "mode": c.mode} for c in r.captures],
            "interruption_sec": r.interruption_sec,
            "recovered": r.recovered,
            "recovery_wait_used_sec": r.recovery_wait_used_sec,
            "aborted_by_interruption": r.aborted_by_interruption,
            "skip_reason": r.skip_reason,
            "verdict": r.verdict, "verdict_label": verdict_label, "verdict_icon": verdict_icon,
            "verdict_css": verdict_css,
            "stability_verdict": r.stability_verdict, "stability_label": stability_label,
            "stability_icon": stability_icon, "stability_css": stability_css,
            "recovery_verdict": r.recovery_verdict, "recovery_label": recovery_label,
            "recovery_icon": recovery_icon, "recovery_css": recovery_css,
        }
        run_rows.append(item)

        if r.verdict == "fail":
            failed_items.append(item)
        elif r.verdict == "warn":
            warn_items.append(item)
        elif r.verdict == "skipped":
            skipped_items.append(item)
        elif r.verdict == "unreachable":
            unreachable_items.append(item)

        if r.stability_verdict == "fail":
            stability_fail_items.append(item)
        elif r.stability_verdict == "warn":
            stability_warn_items.append(item)
        if r.recovery_verdict == "fail":
            recovery_fail_items.append(item)

    verdict_counts = {k: 0 for k in _VERDICT_ORDER}
    for r in runs:
        verdict_counts[r.verdict if r.verdict in verdict_counts else "unknown"] += 1

    # 兩個維度各自的統計（給 Summary 的兩排卡片用）
    stability_counts = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0, "na": 0}
    recovery_counts = {"pass": 0, "fail": 0, "unknown": 0, "na": 0}
    for r in runs:
        stability_counts[r.stability_verdict if r.stability_verdict in stability_counts else "unknown"] += 1
        recovery_counts[r.recovery_verdict if r.recovery_verdict in recovery_counts else "unknown"] += 1

    # ---- 測項 × 監控器 交叉比對矩陣（Summary 用，讓人一眼看出「哪一項的哪個監控器」出問題）----
    monitor_columns = []
    _seen_types = set()
    for mc in project.monitors:
        if not mc.enabled or mc.type in _seen_types:
            continue
        _seen_types.add(mc.type)
        monitor_columns.append({
            "type": mc.type, "name": _monitor_display_name(mc.type),
            "role": _monitor_role_label(mc.type),
            "verdict_determining": mc.type in _VERDICT_DETERMINING_TYPES,
        })

    matrix_rows = []
    for item in run_rows:
        ms = item["monitors_summary"]
        cells = []
        for col in monitor_columns:
            s = ms.get(col["type"])
            if s is None:
                cell = {"status": "no_data", "icon": "—", "detail": "未取得資料（可能提前中止或未成功啟動）"}
            elif s.get("not_applicable"):
                cell = {"status": "na", "icon": "⚪", "detail": "不適用"}
            elif s.get("critical_count"):
                cell = {"status": "critical", "icon": "🔴", "detail": f"異常 {s['critical_count']} 次"}
            elif s.get("warn_count"):
                cell = {"status": "warn", "icon": "🟡", "detail": f"警示 {s['warn_count']} 次"}
            elif s.get("row_count"):
                cell = {"status": "ok", "icon": "🟢", "detail": "正常"}
            else:
                cell = {"status": "no_data", "icon": "—", "detail": "未取得資料"}
            cells.append(cell)
        matrix_rows.append({
            "run_id": item["id"], "display_no": item["display_no"], "name": item["name"], "category": item["category"],
            "port": item["port"],
            "test_type": item["test_type"],
            "test_type_label": item["test_type_label"], "test_type_icon": item["test_type_icon"],
            "verdict": item["verdict"], "verdict_label": item["verdict_label"],
            "verdict_icon": item["verdict_icon"], "verdict_css": item["verdict_css"],
            "stability_label": item["stability_label"], "stability_icon": item["stability_icon"],
            "stability_css": item["stability_css"],
            "recovery_label": item["recovery_label"], "recovery_icon": item["recovery_icon"],
            "recovery_css": item["recovery_css"],
            "cells": cells,
        })

    total_runs = len(runs)
    pass_like = verdict_counts.get("pass", 0) + verdict_counts.get("warn", 0)
    fail_like = verdict_counts.get("fail", 0)
    pass_rate = round(100 * pass_like / total_runs, 1) if total_runs else None
    exec_summary = _build_exec_summary(
        target_desc=target.description or target.ip_or_host,
        total_runs=total_runs, verdict_counts=verdict_counts, pass_rate=pass_rate,
        stability_counts=stability_counts, recovery_counts=recovery_counts,
        stability_fail_items=stability_fail_items, recovery_fail_items=recovery_fail_items,
    )
    report_id = f"ICSSTP-{project.id:05d}-{datetime.utcnow().strftime('%Y%m%d')}"

    return {
        "report_id": report_id,
        "project": {
            "id": project.id, "name": project.name, "operator_name": project.operator_name,
            "status": project.status,
            "created_at": project.created_at.isoformat() if project.created_at else None,
            "closed_at": project.closed_at.isoformat() if project.closed_at else None,
            "max_interruption_sec": project.max_interruption_sec,
            "recovery_wait_sec": project.recovery_wait_sec,
        },
        "target": {
            "ip_or_host": target.ip_or_host, "description": target.description,
            "scope_confirmed": target.scope_confirmed,
            "confirmed_by": target.confirmed_by,
            "confirmed_at": target.confirmed_at.isoformat() if target.confirmed_at else None,
        },
        "runs": run_rows,
        "summary": {
            "total_runs": len(runs),
            "verdict_counts": verdict_counts,
            "verdict_cards": [
                {"key": k, "count": verdict_counts[k], "label": _VERDICT_LABELS[k][0],
                 "icon": _VERDICT_LABELS[k][1], "css": _VERDICT_LABELS[k][2]}
                for k in _VERDICT_ORDER
            ],
            "failed_items": failed_items,
            "warn_items": warn_items,
            "skipped_items": skipped_items,
            "unreachable_items": unreachable_items,
            "monitor_alerts": monitor_alerts,
            "has_any_issue": bool(failed_items or warn_items or monitor_alerts),
            "matrix_columns": monitor_columns,
            "matrix_rows": matrix_rows,
            "pass_rate": pass_rate,
            "exec_summary": exec_summary,
            # 兩個獨立判定維度的統計卡片＋各自的問題清單：一個是測試過程連線和服務狀態，
            # 一個是受攻擊後的恢復能力。
            "stability_counts": stability_counts,
            "recovery_counts": recovery_counts,
            "stability_cards": [
                {"key": k, "count": stability_counts[k], "label": _STABILITY_LABELS[k][0],
                 "icon": _STABILITY_LABELS[k][1], "css": _STABILITY_LABELS[k][2]}
                for k in ("pass", "warn", "fail", "unknown", "na") if stability_counts[k] > 0 or k in ("pass", "fail")
            ],
            "recovery_cards": [
                {"key": k, "count": recovery_counts[k], "label": _RECOVERY_LABELS[k][0],
                 "icon": _RECOVERY_LABELS[k][1], "css": _RECOVERY_LABELS[k][2]}
                for k in ("pass", "fail", "unknown", "na") if recovery_counts[k] > 0 or k in ("pass", "fail")
            ],
            "stability_fail_items": stability_fail_items,
            "stability_warn_items": stability_warn_items,
            "recovery_fail_items": recovery_fail_items,
        },
        "generated_at": datetime.utcnow().isoformat(),
    }


def _build_exec_summary(target_desc: str, total_runs: int, verdict_counts: dict, pass_rate,
                         stability_counts: dict, recovery_counts: dict,
                         stability_fail_items: list, recovery_fail_items: list) -> str:
    """給不想逐項往下讀的主管/認證單位看的一段話摘要（自動產生，非樣板套話）。

    分別描述「過程穩定性」「恢復能力」兩個獨立維度的結果，不只給一句「未通過」帶過，
    而是明確點名是過程本身不穩定、還是事後沒恢復（同一個測項可能同時出現在兩份清單裡）。
    """
    if total_runs == 0:
        return f"本次針對「{target_desc}」建立的測試專案尚未執行任何測項，無可供摘要之結果。"

    n_fail = verdict_counts.get("fail", 0)
    n_pass = verdict_counts.get("pass", 0)
    n_warn = verdict_counts.get("warn", 0)
    n_unknown = verdict_counts.get("unknown", 0)

    n_stab_fail = stability_counts.get("fail", 0)
    n_stab_warn = stability_counts.get("warn", 0)
    n_rec_fail = recovery_counts.get("fail", 0)

    parts = [
        f"本次針對「{target_desc}」共執行 {total_runs} 項壓力測試項目，綜合判定 {n_pass} 項"
        f"通過、{n_warn} 項通過但有警示、{n_fail} 項未通過"
        f"（{pass_rate}% 屬於「通過或可接受範圍內」）。"
    ]
    parts.append(
        f"拆成兩個獨立維度來看：「測試過程連線和服務狀態」方面，{n_stab_fail} 項出現連續"
        f"中斷秒數超過可接受上限（過程本身不穩定，判定該維度未通過）、{n_stab_warn} 項曾"
        f"短暫中斷但仍在可接受範圍內，其餘過程全程穩定；「受攻擊後的恢復能力」方面，"
        f"{n_rec_fail} 項在測試結束後的觀察時間內未能恢復正常。"
    )
    if n_stab_fail > 0:
        names = "、".join(f"「{it['name']}」" for it in stability_fail_items[:5])
        more = f" 等共 {n_stab_fail} 項" if n_stab_fail > 5 else ""
        parts.append(
            f"過程穩定性未通過的測項：{names}{more}——代表測試過程中連續中斷時間超過設定"
            f"門檻，建議優先檢視這些項目對應的通訊協定/服務堆疊在高流量下的處理能力（例如"
            f"連線數上限、佇列深度、異常封包容錯）。"
        )
    if n_rec_fail > 0:
        names = "、".join(f"「{it['name']}」" for it in recovery_fail_items[:5])
        more = f" 等共 {n_rec_fail} 項" if n_rec_fail > 5 else ""
        parts.append(
            f"恢復能力未如預期的測項：{names}{more}——代表停止攻擊後服務沒有在可接受時間"
            f"內恢復正常，建議檢視是否需要強化自我復原機制（例如連線逾時釋放、看門狗重啟、"
            f"資源回收邏輯）。"
        )
    if n_stab_fail == 0 and n_rec_fail == 0:
        parts.append("本次測試沒有測項在「過程穩定性」或「恢復能力」任一維度被判定未通過。")
    if n_unknown > 0:
        parts.append(
            f"另有 {n_unknown} 項測試因未啟用任何判定用監控器（見下方「測項結果總覽表」的"
            f"判定用/診斷用分類），兩個維度都無法自動判定，僅供流量/行為觀察參考。"
        )
    return " ".join(parts)


def _summarize_csv(csv_path: Path) -> dict:
    import csv as csv_mod

    numeric_cols: dict[str, list[float]] = {}
    row_count = 0
    critical_count = 0
    warn_count = 0
    na_count = 0
    critical_reasons: list[str] = []
    try:
        with open(csv_path, newline="") as f:
            reader = csv_mod.DictReader(f)
            for row in reader:
                row_count += 1
                level = row.get("level")
                if level == "critical":
                    critical_count += 1
                    reason = row.get("level_reason") or ""
                    if reason and reason not in critical_reasons:
                        critical_reasons.append(reason)
                elif level == "warn":
                    warn_count += 1
                elif level == "na":
                    na_count += 1
                for k, v in row.items():
                    if k in ("ts", "level", "level_reason") or v in (None, ""):
                        continue
                    try:
                        numeric_cols.setdefault(k, []).append(float(v))
                    except ValueError:
                        pass
    except OSError:
        return {"row_count": 0}

    summary = {
        "row_count": row_count, "critical_count": critical_count, "warn_count": warn_count,
        "critical_reasons": critical_reasons[:5],  # 只列前 5 種不重複的異常原因，避免報告被洗版
        # 這一輪取樣全部都是「不適用」（例如 service/udp 監控器碰上沒有 Port 的 L2 測項）：
        # 不該顯示成「🟢 全程正常」誤導使用者以為有測到，改顯示「⚪ 不適用」。
        "not_applicable": row_count > 0 and na_count == row_count,
    }
    metrics = {}
    for k, vals in numeric_cols.items():
        if not vals:
            continue
        metrics[k] = {
            "label": _MONITOR_METRIC_LABELS.get(k, k),
            "min": round(min(vals), 2), "max": round(max(vals), 2),
            "avg": round(sum(vals) / len(vals), 2),
        }
    summary["metrics"] = metrics
    return summary


def generate_report(db, project_id: int) -> dict:
    project = db.get(models.Project, project_id)
    data = _build_report_data(db, project_id)

    report_dir = PROJECTS_DIR / project.project_dir_name / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    json_path = report_dir / "report.json"
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    template = _env.get_template("report_template.html")
    html = template.render(**data)
    html_path = report_dir / "report.html"
    html_path.write_text(html, encoding="utf-8")

    pdf_path = report_dir / "report.pdf"
    pdf_ok = False
    pdf_error = None
    try:
        from weasyprint import HTML  # 選用套件，沒裝也不影響 HTML 報告

        HTML(string=html, base_url=str(report_dir)).write_pdf(str(pdf_path))
        pdf_ok = True
    except ImportError:
        pdf_error = "未安裝 weasyprint，僅產生 HTML 報告（可用瀏覽器開啟或列印成 PDF）"
    except Exception as e:  # noqa: BLE001  weasyprint 系統依賴（cairo/pango）沒裝齊時常見
        pdf_error = f"PDF 產生失敗：{e}（可用瀏覽器開啟 report.html 另存/列印成 PDF）"

    report = models.Report(
        project_id=project_id,
        html_path=str(html_path),
        pdf_path=str(pdf_path) if pdf_ok else "",
        json_path=str(json_path),
    )
    db.add(report)
    db.commit()

    return {"html_path": str(html_path), "pdf_path": str(pdf_path) if pdf_ok else None, "pdf_error": pdf_error}
