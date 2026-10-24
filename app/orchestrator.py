"""
app/orchestrator.py — Test Orchestrator（設計文件 5.6 節：佇列 + 狀態機）

行為對齊設計文件的決策：
  - 佇列依序執行（Port × 測項），不同時跑多個測項，監控數據才不會互相干擾。
  - 「停止」：終止目前這一項的子行程/迴圈，狀態設為 stopped，不會自動往下一項推進。
  - 「恢復」：把被停止的那一項重設成 pending（attempt_no +1）重新測，完成後自動接續佇列。
  - 「緊急停止」：不管在哪一項，立刻停止並把剩餘佇列全部標成 stopped，專案保持 open
    （不會自動產報告/關閉），需要操作者確認後才會關閉專案。
"""
import threading
import time
from datetime import datetime
from pathlib import Path

from . import audit, capture, events, health, models, reports
from .config import PROJECTS_DIR
from .db import SessionLocal
from .monitors import REGISTRY as MONITOR_REGISTRY
from .monitors.base import MonitorRunner
from . import registry as test_registry
from .plugins import common as plugin_common

# 「判定用」監控器種類：中斷秒數統計、通過/失敗判定、結束後恢復檢查都看這幾種監控器。
#
# 除了 self_resource（攻擊端自身 CPU/記憶體，量的是攻擊端自己的狀態、不是標的健康狀態）以外，
# 其餘全部監控器種類都算判定用——ping（是否還能連通標的）、網路介面監控的「carrier 鏈路
# 訊號」（Kali 網卡若與標的直接對接，可以反映對方 link down，見 monitors/iface_monitor.py
# 開頭說明）、TCP 連線狀態監控，都一併納入；可接受的最長連續中斷秒數這個指標也涵蓋連線
# 本身這個面向，不只侷限在開在 Port 上的服務，因為壓力測試本身也包含測試連線是否會被
# 攻擊而中斷。是否構成「中斷」統一交給 app/health.py 的 evaluate_sample() 判斷
# （level == critical 才算），不再各自用 raw 的 up 欄位判斷——這樣「即時中斷判定」「結束後
# 恢復判定」用的是同一套標準，也讓每種監控器要在什麼條件下才算「異常到會影響判定」的邏輯
# 集中在 health.py 一處維護（例如網路介面監控刻意把「攻擊流量造成的封包計數器誤差/丟包」
# 降級成 warn、只有 carrier 斷訊才算 critical，避免攻擊端自己送出大量流量時被誤判成標的
# 斷線，見 health.py 的 iface 分支說明）。
#
# 顯示/取樣順序：service（探測的就是受測 Port 本身，訊號最明確）> udp > arp（鏈路層）>
# ping（是否能連通）> iface（Kali 自己網卡的鏈路訊號）> tcp（連線狀態分布，目前
# health.py 對這個類型沒有定義 critical 條件，實務上不會觸發中斷判定，但結構上已經
# 一併納入判定範圍，供之後有需要時擴充判斷條件）。
#
# 恢復判定要求：只要專案有設定、且對這次測項適用的監控器種類，必須全部都回報「正常」
# 才視為真的恢復——只挑「優先序最高的一種」來判斷會出現「ARP／鏈路層已經有回應（裝置
# 還在網路上），但實際要測的 Port 服務根本還沒重新啟動」卻被誤判成已恢復、進而自動接續
# 下一項的情況，因此改成要求所有適用種類都恢復正常，見 `_pick_recovery_monitors()` /
# `_all_monitors_recovered()`。
_HEALTH_MONITOR_TYPES = ("service", "udp", "arp", "ping", "iface", "tcp")

_orchestrators: dict[int, "ProjectOrchestrator"] = {}
_orchestrators_lock = threading.Lock()


def get_orchestrator(project_id: int) -> "ProjectOrchestrator":
    with _orchestrators_lock:
        if project_id not in _orchestrators:
            _orchestrators[project_id] = ProjectOrchestrator(project_id)
        return _orchestrators[project_id]


_AUTO_RESUME_POLL_INTERVAL_SEC = 3.0   # 資源監控輪詢間隔
_AUTO_RESUME_REQUIRED_OK_STREAK = 3    # 連續幾次「正常」取樣才視為真的恢復（避免資源在門檻邊緣抖動就誤判恢復）
_AUTO_RESUME_HEARTBEAT_SEC = 60.0      # 資源持續未恢復時，每隔多久推一次「還在等待」的提示（避免使用者以為卡住了）


class ProjectOrchestrator:
    def __init__(self, project_id: int):
        self.project_id = project_id
        self.thread: threading.Thread | None = None
        self.kill_switch = threading.Event()
        self.current_stop_event: threading.Event | None = None
        self.is_running = False
        # 記錄「目前這個 stop_event 是被誰、為什麼觸發的」，_execute() 結束後要靠這個判斷
        # 該把 run.status 設成什麼（stopped/skipped/failed），而不是只看 stop_event 有沒有被設。
        # 可能值：None / "user_stop" / "user_skip" / "kill_switch" /
        #        "interruption_threshold"（連續中斷超過可接受秒數，自動提前中止）/
        #        "self_resource_critical"（攻擊端自身資源過載，自動中止保護攻擊端主機）
        self._stop_reason: str | None = None
        # 攻擊端資源保護觸發後，背景監看資源是否恢復、恢復了就自動接續佇列（不需要操作者手動按
        # 「恢復」）。這個 event 用來取消正在監看的 watcher（例如操作者手動恢復了、或按了緊急停止）。
        self._auto_resume_cancel = threading.Event()
        self._auto_resume_thread: threading.Thread | None = None

    # ---------- 對外操作 ----------

    def start(self):
        if self.is_running and self.thread and self.thread.is_alive():
            return {"ok": False, "message": "已在執行中"}
        # 不管這次 start() 是操作者手動按「恢復」還是別的路徑呼叫的，都代表佇列即將真的開始跑了，
        # 先前因資源保護而啟動的背景「等資源恢復自動接續」watcher（如果還在跑）就不需要了，
        # 取消它避免之後重複觸發一次 start()。
        self._auto_resume_cancel.set()
        self.kill_switch.clear()
        self.is_running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        return {"ok": True}

    def stop_current(self):
        """停止目前正在跑的測項（單純停止，不影響佇列後面尚未執行的項目，它們維持 pending，
        佇列會暫停，需要操作者按「恢復」才會重測這一項並接續）。"""
        if self.current_stop_event:
            self._stop_reason = "user_stop"
            self.current_stop_event.set()
            return {"ok": True}
        return {"ok": False, "message": "目前沒有執行中的測項"}

    def skip_current(self):
        """跳過目前正在跑的測項：中止它但不判定通過/失敗，佇列會自動接續下一項
        （跟「停止」的差別：停止會暫停佇列等待人工「恢復」，跳過則直接往下一項走）。"""
        if self.current_stop_event:
            self._stop_reason = "user_skip"
            self.current_stop_event.set()
            return {"ok": True}
        return {"ok": False, "message": "目前沒有執行中的測項"}

    def emergency_stop(self):
        """全域緊急停止：立刻中斷目前測項，並把佇列裡其餘 pending 的項目都標成 stopped。"""
        self.kill_switch.set()
        self._auto_resume_cancel.set()  # 緊急停止也要連同取消正在背景等資源恢復的 watcher
        if self.current_stop_event:
            self._stop_reason = "kill_switch"
            self.current_stop_event.set()
        db = SessionLocal()
        try:
            pending = (
                db.query(models.TestRun)
                .filter_by(project_id=self.project_id, status="pending")
                .all()
            )
            for r in pending:
                r.status = "stopped"
            db.commit()
        finally:
            db.close()
        events.broadcast(self.project_id, "alert", {"level": "critical", "message": "已觸發緊急停止"})
        return {"ok": True}

    # ---------- 內部執行邏輯 ----------

    def _run_loop(self):
        db = SessionLocal()
        try:
            while True:
                if self.kill_switch.is_set():
                    break
                run = (
                    db.query(models.TestRun)
                    .filter_by(project_id=self.project_id, status="pending")
                    .order_by(models.TestRun.order_index)
                    .first()
                )
                if run is None:
                    break
                self._execute(db, run)
                if run.status == "stopped":
                    break  # 使用者手動停止／緊急停止：需要操作者明確「恢復」才會繼續，不自動往下一項
                if run.recovered is False:
                    # 結束後等待時間內服務沒有恢復：這一項的「未通過」判定已經確定、不會再改變，
                    # 但佇列不應該因此整個卡住等操作者手動按「恢復」——改為背景持續
                    # 監看標的服務，恢復正常後自動接續下一項（不重測這一項，見 _start_auto_continue_watch）。
                    # 只有在佇列裡還有其他 pending 項目時才需要啟動 watcher；如果這已經是最後一項，
                    # 下面的 remaining_pending 判斷會直接把專案關閉、產生報告，不用多等一次。
                    has_more = (
                        db.query(models.TestRun)
                        .filter_by(project_id=self.project_id, status="pending")
                        .count() > 0
                    )
                    if has_more:
                        self._start_auto_continue_watch(run)
                    break
                if self._stop_reason == "self_resource_critical":
                    # 攻擊端自身資源過載，暫停佇列避免繼續加重負擔——但不用等操作者手動按「恢復」，
                    # 背景啟動一個 watcher 持續監看攻擊端資源，資源真的恢復到健康水準後自動重測
                    # 這一項並接續佇列（操作者當然還是可以隨時手動按「恢復」提早接續，或按緊急停止
                    # 取消等待）。
                    self._start_auto_resume_watch(run.id)
                    break
                # 使用者主動「跳過」(run.status == "skipped") 或
                # 因中斷超標被提前中止但事後成功恢復 (run.aborted_by_interruption)：兩者都自動往下一項

            remaining_pending = (
                db.query(models.TestRun)
                .filter_by(project_id=self.project_id, status="pending")
                .count()
            )
            if remaining_pending == 0 and not self.kill_switch.is_set():
                self._finalize_project(db)
        finally:
            self.is_running = False
            self.current_stop_event = None
            db.close()

    def _execute(self, db, run: models.TestRun):
        stop_event = threading.Event()
        self.current_stop_event = stop_event
        self._stop_reason = None

        project = run.project
        target = project.target
        port_number = run.port.port if run.port else None

        # ---- 測項管理／健康檢查閘門（二次防呆） ----
        # routers/runs.py 的 add_run() 已經在「加入佇列」當下擋過一次，這裡是執行前
        # 最後一道防線：涵蓋「加入佇列之後、真正輪到執行之前，使用者才在測項管理頁
        # 把它停用」這種時間差情況，避免已經停用/健康檢查失敗的測項仍被排入執行。
        item_ok, item_reason = test_registry.is_enabled(run.test_item_module, db)
        if not item_ok:
            self._handle_disabled_test_item(db, run, item_reason)
            return

        # ---- 開始前的目標存活預檢查 ----
        # 對一個標的沒有開放的 Port 建立測項（例如 Modbus TCP 502 但標的根本沒開這個
        # 服務），跑完之後如果被判定「未通過」，會誤導使用者以為是壓力測試造成的影響——
        # 但實際上是這個 Port 從頭到尾就沒辦法連，屬於「根本無法測試」，跟「測試把服務
        # 打掛了」是完全不同的兩件事，不該用同一種「未通過」結果混在一起。
        # 這裡只針對「需要實際 TCP 應用層握手」的測項（PROTOCOL == "TCP" 且有指定 Port）
        # 做一次快速連線探測（2 秒逾時）；UDP／Layer2 測項沒有可靠的通用判斷方式，維持原行為。
        # 探測失敗就不執行測項本體（不浪費整個 duration），直接標成「無法測試」並自動接續
        # 下一項（不暫停佇列，因為這不是需要操作者介入確認裝置狀況的情況）。
        try:
            precheck_mod = test_registry.get_module(run.test_item_module)
        except Exception:  # noqa: BLE001  模組路徑異常就不做預檢查，交給後面原本的錯誤處理流程
            precheck_mod = None
        if (precheck_mod is not None and port_number is not None
                and getattr(precheck_mod, "PROTOCOL", "TCP") == "TCP"
                and not plugin_common.tcp_precheck(target.ip_or_host, port_number, timeout=2.0)):
            self._handle_unreachable_port(db, run, project, port_number)
            return

        run.status = "running"
        run.started_at = datetime.utcnow()
        db.commit()
        events.broadcast(self.project_id, "test_started", {
            "test_run_id": run.id, "port": port_number,
            "item_name": run.test_item_name, "params": run.params_json,
            "duration_sec": run.duration_sec, "attempt_no": run.attempt_no,
        })

        run_dir = PROJECTS_DIR / project.project_dir_name / "runs" / f"run_{run.id}_attempt{run.attempt_no}"
        run_dir.mkdir(parents=True, exist_ok=True)

        # ---- 監控器 ----
        health.reset_state()  # 避免上一個測項殘留的介面錯誤基準值影響這次的異常判斷
        # service_tracker：追蹤這次測項執行期間，「判定用」監控器（見 _HEALTH_MONITOR_TYPES，
        # 除了 self_resource 以外的全部監控器都算判定用）偵測到的「最長連續中斷
        # 秒數」：不管監控有沒有出現異常都繼續丟封包，一旦超過「可接受最長
        # 連續中斷秒數」就直接停止測項、進入恢復等待——這裡偵測到超標時會主動觸發
        # stop_event，讓測項提前中止（跟使用者手動按停止走同一個 stop_event，但用
        # _stop_reason 區分原因）。「是否算中斷」統一用 app/health.py 算出來的 level==critical
        # 判斷（metrics["level"] 由下面 _sample_with_health() 在呼叫這裡之前就已經算好），
        # 不再各自看每種監控器自己的 raw 欄位（例如 up）——這樣才能讓 ping/iface/tcp
        # 這些沒有明確 up/down 欄位的監控器也能一併納入判定，且跟 UI 上看到的顏色狀態、
        # 報告裡的異常次數統計是同一套標準。
        service_tracker = {"down_since": None, "max_interruption": 0.0}
        abort_triggered = {"value": False}

        def _track_interruption(monitor_type: str, metrics: dict):
            if monitor_type not in _HEALTH_MONITOR_TYPES:
                return
            now = metrics.get("ts", time.time())
            is_down = metrics.get("level") == "critical"
            if is_down:
                if service_tracker["down_since"] is None:
                    service_tracker["down_since"] = now
                streak = now - service_tracker["down_since"]
                if streak > service_tracker["max_interruption"]:
                    service_tracker["max_interruption"] = streak
                if (not abort_triggered["value"] and project.max_interruption_sec > 0
                        and streak > project.max_interruption_sec and not stop_event.is_set()):
                    abort_triggered["value"] = True
                    self._stop_reason = "interruption_threshold"
                    since_start = now - _exec_start_ts
                    reason = ("目標從測試開始就沒有回應" if since_start <= project.max_interruption_sec + 1.5
                               else f"連續中斷 {round(streak, 1)} 秒，超過可接受上限 {project.max_interruption_sec} 秒")
                    events.broadcast(self.project_id, "alert", {
                        "level": "critical",
                        "message": f"測項 #{run.id}（{run.test_item_name}）{reason}，已自動提前中止並進入恢復等待。",
                    })
                    stop_event.set()
            else:
                service_tracker["down_since"] = None

        def _check_self_resource_critical(monitor_type: str, metrics: dict, level: str):
            """攻擊端自身資源監控出現 critical（CPU/記憶體過載）時，立刻中止目前測項，
            避免繼續加重攻擊端主機負擔、影響攻擊端本身的可用性。"""
            if monitor_type != "self_resource" or level != "critical":
                return
            if abort_triggered["value"] or stop_event.is_set():
                return
            abort_triggered["value"] = True
            self._stop_reason = "self_resource_critical"
            events.broadcast(self.project_id, "alert", {
                "level": "critical",
                "message": (f"發起測試的主機（Kali）自身資源過載（{metrics.get('level_reason', '')}），"
                             f"已自動中止測項 #{run.id}（{run.test_item_name}）以保護攻擊端主機，佇列將暫停。"),
            })
            stop_event.set()

        _exec_start_ts = time.time()
        monitor_configs = db.query(models.MonitorConfig).filter_by(project_id=project.id, enabled=True).all()
        monitor_runners: list[MonitorRunner] = []
        for mc in monitor_configs:
            mod = MONITOR_REGISTRY.get(mc.type)
            if not mod:
                continue
            cfg = {**(mc.config_json or {}), "target": target.ip_or_host, "port": port_number}
            # service/udp 監控器需要一個具體 Port 才能運作；如果這次測項本身沒有 Port
            # （典型情況：Layer 2 通訊協定測項，例如 EtherCAT/PROFINET DCP/ARP 相關測項），
            # 硬跑下去只會每秒都拿到「缺少 target/port」的錯誤，顯示成刺眼的紅色異常，
            # 容易讓操作者誤以為標的出問題，但其實只是這種監控器本來就不適用於無 Port
            # 的測項。這裡直接短路掉，
            # 不呼叫真正的 sample()，固定回一筆「不適用」的樣本（灰色中性狀態），
            # 也不計入中斷秒數統計（_track_interruption 只看 level == critical，na 樣本的
            # level 是 "na"，不會誤觸發）。
            not_applicable = mc.type in ("service", "udp") and not port_number

            def _sample_with_health(config, _mod=mod, _mtype=mc.type, _run_id=run.id, _na=not_applicable):
                """先取樣，再統一套用 app/health.py 的異常判斷，把 level/reason 一起塞進
                metrics 裡——這樣 CSV（給報告用）跟 WebSocket 即時推播（給前端上色用）
                看到的是同一份、同一套標準判斷出來的結果。"""
                if _na:
                    return {
                        "up": None, "level": "na",
                        "level_reason": "此測項無對應 Port（Layer 2 通訊協定或未選擇 Port），此監控器不適用於本次測試",
                    }
                metrics = _mod.sample(config)
                ev = health.evaluate_sample(_mtype, metrics, key=f"{_run_id}:{_mtype}:{metrics.get('iface', '')}")
                metrics["level"] = ev["level"]
                metrics["level_reason"] = ev["reason"]
                return metrics

            def _on_sample(monitor_type, metrics, _run_id=run.id):
                _track_interruption(monitor_type, metrics)
                _check_self_resource_critical(monitor_type, metrics, metrics.get("level", "ok"))
                events.broadcast(self.project_id, "monitor_sample", {
                    "test_run_id": _run_id, "monitor": monitor_type, "metrics": metrics,
                })

            runner = MonitorRunner(
                monitor_type=mc.type, sample_fn=_sample_with_health, config=cfg,
                csv_path=run_dir / "monitors" / f"{mc.type}.csv",
                on_sample=_on_sample, interval=1.0,
            )
            runner.start()
            monitor_runners.append(runner)

        # ---- 封包擷取 ----
        cap_handle = capture.start_capture(
            run.capture_mode, target.ip_or_host, port_number, run_dir / "capture", run.id,
        )

        # ---- log 串流 ----
        log_path = run_dir / "stdout.log"
        log_f = open(log_path, "a")

        def log_fn(line: str, _run_id=run.id):
            log_f.write(f"{line}\n")
            log_f.flush()
            events.broadcast(self.project_id, "log_line", {"test_run_id": _run_id, "line": line})

        # ---- 進度提示（每 2 秒推一次）----
        progress_stop = threading.Event()

        def _progress_ticker(_run_id=run.id, _duration=run.duration_sec, _start=datetime.utcnow(),
                              _name=run.test_item_name, _port=port_number):
            while not progress_stop.wait(2.0):
                elapsed = (datetime.utcnow() - _start).total_seconds()
                events.broadcast(self.project_id, "test_progress", {
                    "test_run_id": _run_id,
                    "item_name": _name, "port": _port,
                    "elapsed_sec": round(elapsed, 1),
                    "remaining_sec": max(0, round(_duration - elapsed, 1)),
                })

        ticker = threading.Thread(target=_progress_ticker, daemon=True)
        ticker.start()

        # ---- 呼叫測項 plugin ----
        # 依測項管理頁的引擎偏好（未手動設定時，依
        # TEST_TYPE 走系統建議預設，見 registry.get_effective_engine()）決定要
        # 直接呼叫 mod.run()（標準版），還是透過 plugin_common.run_concurrent_workers()
        # 包一層（高並發加速版，多執行緒平行執行同一個 run()，見該函式完整設計說明）。
        try:
            mod = test_registry.get_module(run.test_item_module)
            engine_mode, engine_workers = test_registry.get_effective_engine(run.test_item_module, db)
            log_fn(f"[+] 開始執行測項：{run.test_item_name}（第 {run.attempt_no} 次嘗試，引擎："
                   f"{'高並發加速版' if engine_mode == 'concurrent' else '標準版'}）")
            if engine_mode == "concurrent":
                result = plugin_common.run_concurrent_workers(
                    mod.run, target=target.ip_or_host, port=port_number, protocol=run.category,
                    duration=run.duration_sec, params=run.params_json,
                    stop_event=stop_event, log_fn=log_fn,
                    workers=engine_workers or plugin_common.CONCURRENT_ENGINE_WORKERS,
                    param_schema=mod.get_param_schema(),
                )
            else:
                result = mod.run(
                    target=target.ip_or_host, port=port_number, protocol=run.category,
                    duration=run.duration_sec, params=run.params_json,
                    stop_event=stop_event, log_fn=log_fn,
                )
        except Exception as e:  # noqa: BLE001  plugin 出錯不該讓 Orchestrator 整個掛掉
            result = {"error": str(e)}
            log_fn(f"[!] 測項執行例外：{e}")
        finally:
            progress_stop.set()

        for r in monitor_runners:
            r.stop()
        # 注意：log_f 要等封包擷取收尾（可能會用 log_fn 記錄擷取失敗原因）結束後才關閉，
        # 不能在上面的 finally 就關掉，不然這裡沒辦法再寫東西進去。
        for cap_info in cap_handle.stop():
            if cap_info.get("file"):
                db.add(models.CaptureFile(
                    test_run_id=run.id, file_path=cap_info["file"],
                    size_bytes=cap_info.get("size_bytes", 0), mode=cap_info.get("mode", run.capture_mode),
                ))
                if not cap_info.get("size_bytes"):
                    log_fn(f"[!] 封包擷取（{cap_info.get('mode')}）產生的檔案大小是 0，"
                           f"原因：{cap_info.get('error') or '未知（tshark 沒有留下明確錯誤訊息）'}")
            elif cap_info.get("error"):
                log_fn(f"[!] 封包擷取（{cap_info.get('mode')}）失敗，未產生檔案：{cap_info['error']}")
        log_f.close()

        run.ended_at = datetime.utcnow()
        run.result_summary_json = result or {}
        run.log_path = str(log_path)
        stop_reason = self._stop_reason  # 先存一份，_recovery_check/後續處理不會再動到 self._stop_reason

        if stop_reason == "user_skip":
            run.status = "skipped"
            run.skip_reason = "使用者手動跳過執行"
        elif stop_reason == "self_resource_critical":
            run.status = "failed"
            run.skip_reason = "發起測試的主機（Kali）自身資源過載（CPU/記憶體），已自動中止此測項以保護攻擊端主機"
        elif stop_reason == "interruption_threshold":
            run.status = "completed"  # 視為「有拿到結果的正常結束」，交給 verdict 邏輯判斷是否有恢復
            run.aborted_by_interruption = True
        elif stop_reason in ("user_stop", "kill_switch") or stop_event.is_set():
            run.status = "stopped"
        elif result and result.get("error"):
            run.status = "failed"
        else:
            run.status = "completed"
        run.interruption_sec = round(service_tracker["max_interruption"], 1)
        db.commit()

        events.broadcast(self.project_id, "test_completed", {
            "test_run_id": run.id, "status": run.status, "summary": result,
            "interruption_sec": run.interruption_sec, "skip_reason": run.skip_reason,
        })
        self.current_stop_event = None

        # ---- 結束後恢復檢查 ----
        # 緊急停止：佇列已經整個中止，不需要再等恢復。
        # 使用者主動跳過／攻擊端自身資源過載：不需要繼續佔用時間等待，直接結束這一項。
        skip_recovery_check = self.kill_switch.is_set() or stop_reason in ("user_skip", "self_resource_critical")
        if not skip_recovery_check:
            self._recovery_check(run, project, target.ip_or_host, port_number, monitor_configs)
        else:
            run.recovered = None
            run.recovery_wait_used_sec = 0.0

        run.verdict, run.stability_verdict, run.recovery_verdict = self._compute_axis_verdicts(
            run, project, monitor_configs, stop_reason)
        db.commit()
        events.broadcast(self.project_id, "run_verdict", {
            "test_run_id": run.id, "verdict": run.verdict,
            "stability_verdict": run.stability_verdict, "recovery_verdict": run.recovery_verdict,
            "interruption_sec": run.interruption_sec,
            "recovered": run.recovered, "recovery_wait_used_sec": run.recovery_wait_used_sec,
        })

    def _handle_disabled_test_item(self, db, run: "models.TestRun", reason: str):
        """測項在排入佇列之後、真正執行之前才被使用者於「測項管理」頁
        停用（或健康檢查判定異常而預設停用），比照 _handle_unreachable_port() 的模式：
        不執行測項本體、不啟動監控器/封包擷取，標成專屬判定，且不暫停佇列、自動接續
        下一項——因為這不是需要操作者介入確認裝置狀況的情況，而是測項本身環境依賴的問題。"""
        now = datetime.utcnow()
        full_reason = f"此測項未執行：{reason}，已自動跳過、接續下一項。如需執行請先至「測項管理」頁確認並重新啟用。"

        run.status = "completed"
        run.started_at = now
        run.ended_at = now
        run.result_summary_json = {"error": reason}
        run.log_path = ""
        run.skip_reason = full_reason
        run.interruption_sec = 0.0
        run.aborted_by_interruption = False
        run.recovered = None
        run.recovery_wait_used_sec = 0.0
        run.verdict = "unreachable"
        run.stability_verdict = "na"
        run.recovery_verdict = "na"
        db.commit()

        events.broadcast(self.project_id, "test_started", {
            "test_run_id": run.id, "port": run.port.port if run.port else None,
            "item_name": run.test_item_name, "params": run.params_json,
            "duration_sec": run.duration_sec, "attempt_no": run.attempt_no,
        })
        events.broadcast(self.project_id, "alert", {"level": "warn", "message": f"測項 #{run.id}（{run.test_item_name}）{full_reason}"})
        events.broadcast(self.project_id, "test_completed", {
            "test_run_id": run.id, "status": run.status, "summary": run.result_summary_json,
            "interruption_sec": run.interruption_sec, "skip_reason": run.skip_reason,
        })
        events.broadcast(self.project_id, "run_verdict", {
            "test_run_id": run.id, "verdict": run.verdict,
            "stability_verdict": run.stability_verdict, "recovery_verdict": run.recovery_verdict,
            "interruption_sec": run.interruption_sec,
            "recovered": run.recovered, "recovery_wait_used_sec": run.recovery_wait_used_sec,
        })

    def _handle_unreachable_port(self, db, run: "models.TestRun", project: "models.Project", port_number: int):
        """目標 Port 從測試開始前的連線探測就已經無回應：不是壓力測試造成的影響，是根本
        沒辦法測。標成專屬的 unreachable 判定（跟「未通過」明確區分），不執行測項本體、
        不啟動監控器/封包擷取，且不暫停佇列——直接自動接續下一項。"""
        now = datetime.utcnow()
        reason = (f"目標 Port {port_number} 在測試開始前的連線探測就已無回應（連線被拒絕或逾時 2 秒），"
                  f"研判是該 Port 本身未開放/未提供服務，並非本次壓力測試造成的影響，"
                  f"已判定為「無法測試」並自動跳過、接續下一項。")

        run.status = "completed"
        run.started_at = now
        run.ended_at = now
        run.result_summary_json = {"error": "目標 Port 從測試開始前就無回應，無法進行本次測試"}
        run.log_path = ""
        run.skip_reason = reason
        run.interruption_sec = 0.0
        run.aborted_by_interruption = False
        run.recovered = None
        run.recovery_wait_used_sec = 0.0
        run.verdict = "unreachable"
        run.stability_verdict = "na"
        run.recovery_verdict = "na"
        db.commit()

        events.broadcast(self.project_id, "test_started", {
            "test_run_id": run.id, "port": port_number,
            "item_name": run.test_item_name, "params": run.params_json,
            "duration_sec": run.duration_sec, "attempt_no": run.attempt_no,
        })
        events.broadcast(self.project_id, "alert", {"level": "warn", "message": f"測項 #{run.id}（{run.test_item_name}）{reason}"})
        events.broadcast(self.project_id, "test_completed", {
            "test_run_id": run.id, "status": run.status, "summary": run.result_summary_json,
            "interruption_sec": run.interruption_sec, "skip_reason": run.skip_reason,
        })
        events.broadcast(self.project_id, "run_verdict", {
            "test_run_id": run.id, "verdict": run.verdict,
            "stability_verdict": run.stability_verdict, "recovery_verdict": run.recovery_verdict,
            "interruption_sec": run.interruption_sec,
            "recovered": run.recovered, "recovery_wait_used_sec": run.recovery_wait_used_sec,
        })
        audit.log(db, project.operator_name, "test_unreachable_auto_skip",
                   target_ref=str(run.id), detail={"port": port_number, "test_item": run.test_item_name})
        self.current_stop_event = None

    def _pick_recovery_monitors(self, monitor_configs: list["models.MonitorConfig"],
                                 target_ip: str, port_number: int | None):
        """收集這次測項『所有』算判定用、且對本次測項適用的監控器設定，回傳
        [(check_type, check_mod, check_cfg), ...]（依 _HEALTH_MONITOR_TYPES 順序，可能是
        空清單，代表無法判斷服務是否恢復）。共用給 _recovery_check()（測項結束後等待恢復）與
        _auto_continue_watch_loop()（等待逾時、佇列暫停後，背景持續監看直到恢復才自動
        接續下一項，見自動接續機制）——兩處挑選監控器的邏輯必須完全
        一致，不然可能出現「結束後判定沒恢復，但背景 watcher 卻用不同監控器組合判斷
        『已恢復』」這種自相矛盾的情況。

        回傳「全部適用的監控器」而不是只挑一種——避免只看 ARP（鏈路層，
        裝置在網路上還有回應）就誤判成「已恢復」，但實際要測的 Port 服務根本還沒重新啟動。
        是否「已恢復」由 `_all_monitors_recovered()` 判斷：清單裡每一種都要回報正常才算數。
        """
        monitors = []
        for want_type in _HEALTH_MONITOR_TYPES:
            mc = next((m for m in monitor_configs if m.type == want_type), None)
            if not mc:
                continue
            # service/udp 需要具體 Port 才能用來判斷恢復；這次測項沒有 Port（例如 L2 測項）
            # 就跳過這個類型，不代表整個放棄——清單裡其他適用的類型（例如 arp）依然有效。
            if want_type in ("service", "udp") and port_number is None:
                continue
            check_mod = MONITOR_REGISTRY.get(want_type)
            check_cfg = {**(mc.config_json or {}), "target": target_ip, "port": port_number}
            monitors.append((want_type, check_mod, check_cfg))
        return monitors

    @staticmethod
    def _all_monitors_recovered(monitors: list[tuple[str, object, dict]], key_prefix: str) -> tuple[bool, list[str]]:
        """對傳入的監控器清單各取樣一次，回傳 (是否全部正常, 尚未恢復的監控器中文名稱清單)。
        監控器應該要在全部監控器都恢復到正常狀態，才視為已經恢復——
        清單裡只要有任何一種還沒恢復，整體就視為「尚未恢復」。空清單視為「無法判斷」，
        由呼叫端另外處理（不應該呼叫這個函式）。

        統一改用 app/health.py 的 evaluate_sample() 判斷「這筆樣本算不算
        正常」（level != critical），而不是各自看 raw 的 up 欄位——這樣才能讓沒有明確
        up/down 欄位的監控器（ping 的 loss、iface 的 carrier、tcp 的連線狀態分布）也能
        一併納入恢復判斷，不用每種監控器都各寫一套「怎樣算正常」的邏輯，跟即時中斷判定
        （_track_interruption）、報告的異常次數統計用同一套標準。key_prefix 是這次恢復
        監看的識別字串（例如 f"recovery:{run.id}" 或 f"continue:{run.id}"），讓 iface
        監控器的錯誤/丟包差值追蹤（health.py 的 _last_values 狀態表）在「恢復監看期間」
        用自己獨立的基準值，跟「測項執行期間」的統計互不干擾。"""
        not_ok_labels = []
        for check_type, check_mod, check_cfg in monitors:
            try:
                metrics = check_mod.sample(check_cfg)
                ev = health.evaluate_sample(check_type, metrics, key=f"{key_prefix}:{check_type}")
                level = ev["level"]
            except Exception:  # noqa: BLE001  取樣本身出錯，比照「還沒恢復」處理，不讓例外中斷監看
                level = "critical"
            # na（不適用，理論上不會出現在這裡，因為 _pick_recovery_monitors 已經做過適用性
            # 過濾）跟 ok/warn 都視為「正常」，只有 critical 才算「還沒恢復」。
            is_ok = level != "critical"
            if not is_ok:
                label = getattr(check_mod, "NAME", None) or check_type
                not_ok_labels.append(label)
        return (len(not_ok_labels) == 0, not_ok_labels)

    def _recovery_check(self, run: "models.TestRun", project: "models.Project",
                         target_ip: str, port_number: int | None,
                         monitor_configs: list["models.MonitorConfig"]):
        """測項結束後，等待 project.recovery_wait_sec 秒，確認服務有沒有恢復。
        使用者可設定停止後幾秒內服務應該要恢復，不能恢復就判斷為失敗；每個測項結束後
        等待設定的恢復時間，監控是否恢復，都恢復之後再往下一項測。用專案有設定、且對
        本次測項適用的『全部』判定用監控器
        （見 _HEALTH_MONITOR_TYPES，除了攻擊端自我資源以外的全部監控器種類都算）
        一起判斷，要全部同時回報正常才算「已恢復」（見 _all_monitors_recovered() 的說明——
        只看其中一種可能誤判，例如裝置對 ARP 有回應但實際 Port 服務還沒重新啟動）；一種
        都沒有設定就無法判斷，recovered 標 None（未知）。
        """
        monitors = self._pick_recovery_monitors(monitor_configs, target_ip, port_number)

        if not monitors:
            run.recovered = None
            run.recovery_wait_used_sec = 0.0
            return

        wait_limit = max(0, project.recovery_wait_sec)
        start = time.time()
        events.broadcast(self.project_id, "alert", {
            "level": "info",
            "message": f"測項 #{run.id}（{run.test_item_name}）已結束，等待服務恢復中（最多 {wait_limit} 秒）...",
        })

        recovered = False
        not_ok_labels: list[str] = []
        recovery_key = f"recovery:{run.id}"
        while time.time() - start < wait_limit:
            if self.kill_switch.is_set():
                break
            recovered, not_ok_labels = self._all_monitors_recovered(monitors, recovery_key)
            if recovered:
                break
            time.sleep(1.0)

        run.recovered = recovered
        run.recovery_wait_used_sec = round(time.time() - start, 1)

        if wait_limit <= 0:
            return  # 使用者把恢復等待時間設為 0，視同不檢查
        if recovered:
            events.broadcast(self.project_id, "alert", {
                "level": "ok",
                "message": f"服務已於 {run.recovery_wait_used_sec} 秒內恢復正常（監控器全部回報正常）。",
            })
        else:
            still_down = "、".join(not_ok_labels) if not_ok_labels else "監控器"
            events.broadcast(self.project_id, "alert", {
                "level": "critical",
                "message": (f"測項 #{run.id}（{run.test_item_name}）結束後 "
                             f"{run.recovery_wait_used_sec} 秒內服務仍未恢復（尚未恢復：{still_down}），"
                             f"已判定「未通過」，佇列暫停中；背景會持續監看標的服務，等到全部監控器都"
                             f"恢復正常後才會自動接續下一項，不需要一直守在畫面前"
                             f"（操作者仍可隨時手動按「恢復」提早接續，或按緊急停止）。"),
            })

    def _compute_axis_verdicts(self, run: "models.TestRun", project: "models.Project",
                                monitor_configs: list["models.MonitorConfig"],
                                stop_reason: str | None = None) -> tuple[str, str, str]:
        """判定拆成兩個獨立維度，回傳
        (overall_verdict, stability_verdict, recovery_verdict) 三元組：測試過程有沒有任何
        攻擊端自我資源監控器以外的監控器出現中斷秒數超過可接受的秒數（過程穩定性），以及
        測試結束之後是否在恢復等待秒數內恢復（恢復能力），兩個層面分開判定、互不稀釋。

        兩個維度定義：
          - stability_verdict（測試過程連線和服務狀態）：這次測項「執行期間」，判定用監控器
            （_HEALTH_MONITOR_TYPES，除了攻擊端自我資源以外全部）偵測到的最長連續中斷秒數
            有沒有超過 project.max_interruption_sec。超過就是 fail——**不管事後有沒有
            恢復都一樣是 fail**：中斷超標本身就是這個維度的未通過，恢復與否是另一個獨立
            維度的事，不會互相稀釋。中斷有出現但沒超過門檻算 warn（維持既有的過程輕微
            異常語意），完全沒中斷才是 pass。
          - recovery_verdict（受攻擊後的恢復能力）：測項「結束後」是否在
            project.recovery_wait_sec 內恢復正常（run.recovered），沒有可用來判斷的監控器
            或這次沒有做恢復檢查（例如緊急停止）則是 unknown。
          - overall_verdict（綜合，向下相容既有畫面）：兩個維度只要有一個 fail，整體就是
            fail（不管另一個維度是不是 pass）；都沒有 fail、但任一個是 warn 或 recovery
            是 unknown（代表沒辦法完全確認正常），整體是 warn；兩者都乾淨 pass 才是 pass。
          skipped／aborted_self_protect 兩個特殊狀態維持最優先判斷，這兩種情況下不評斷任何
          維度，兩個子維度都標成 na（不適用）。
        """
        if stop_reason == "user_skip" or run.status == "skipped":
            return "skipped", "na", "na"
        if stop_reason == "self_resource_critical":
            return "aborted_self_protect", "na", "na"

        # 判斷「這次測項有沒有至少一種『真的用得上』的判定用監控器」（見 _HEALTH_MONITOR_TYPES，
        # 除了攻擊端自我資源以外的全部監控器種類都算判定用）：arp/ping/iface/tcp
        # 永遠適用，service/udp 則要這次測項有指定 Port 才算數——避免 L2 測項明明只設定了
        # service 監控器（對這次測項不適用）卻被當成「有判定用監控」，結果因為
        # interruption_sec 永遠是 0 而誤判成 pass（應該是 unknown 才對）。這裡的適用性規則
        # 要跟 _pick_recovery_monitors() 完全一致。
        port_number = run.port.port if run.port else None
        has_health_monitor = any(
            mc.type in _HEALTH_MONITOR_TYPES and not (mc.type in ("service", "udp") and port_number is None)
            for mc in monitor_configs
        )
        if not has_health_monitor:
            return "unknown", "unknown", "unknown"

        # -- 維度 1：測試過程連線和服務狀態 --
        if run.interruption_sec > project.max_interruption_sec:
            stability = "fail"
        elif run.interruption_sec > 0:
            stability = "warn"
        else:
            stability = "pass"

        # -- 維度 2：受攻擊後的恢復能力 --
        if run.recovered is False:
            recovery = "fail"
        elif run.recovered is True:
            recovery = "pass"
        else:
            recovery = "unknown"  # 沒有可用來判斷恢復的監控器，或這次跳過了恢復檢查（例如緊急停止）

        # -- 綜合（向下相容既有「一眼看整體」的畫面） --
        if stability == "fail" or recovery == "fail":
            overall = "fail"
        elif stability == "warn" or recovery == "unknown":
            overall = "warn"
        else:
            overall = "pass"

        return overall, stability, recovery

    def _start_auto_resume_watch(self, failed_run_id: int):
        """啟動背景 thread，持續監看攻擊端自我資源監控，資源恢復到健康水準後自動重測
        被中止的那一項並接續佇列。對應使用者需求：「資源保護終止之後，應該要視資源狀況
        恢復開始繼續執行」，不需要每次都手動按「恢復」。"""
        if self._auto_resume_thread and self._auto_resume_thread.is_alive():
            return  # 理論上不會同時有兩個 watcher，防呆
        self._auto_resume_cancel.clear()
        self._auto_resume_thread = threading.Thread(
            target=self._auto_resume_watch_loop, args=(failed_run_id,), daemon=True,
        )
        self._auto_resume_thread.start()

    def _auto_resume_watch_loop(self, failed_run_id: int):
        db = SessionLocal()
        try:
            project = db.get(models.Project, self.project_id)
            if not project:
                return
            mc = next((m for m in project.monitors if m.type == "self_resource" and m.enabled), None)
            if mc is None:
                # 理論上不會發生（會走到這裡代表 self_resource 監控器剛剛才觸發過），
                # 防呆：沒有監控器設定就沒辦法判斷資源有沒有恢復，直接放棄背景等待，
                # 維持原本「需要操作者手動按恢復」的行為。
                return
            self_resource_mod = MONITOR_REGISTRY.get("self_resource")
            cfg = mc.config_json or {}

            events.broadcast(self.project_id, "alert", {
                "level": "info",
                "message": (f"攻擊端主機資源過載保護已觸發，佇列暫停中；背景持續監看資源狀況，"
                             f"恢復到健康水準後會自動重測測項 #{failed_run_id} 並接續佇列"
                             f"（不需要手動按「恢復」，也可以隨時手動提前接續或緊急停止）。"),
            })

            ok_streak = 0
            last_heartbeat = time.time()
            while not self._auto_resume_cancel.is_set() and not self.kill_switch.is_set():
                try:
                    metrics = self_resource_mod.sample(cfg)
                    ev = health.evaluate_sample("self_resource", metrics)
                    level = ev["level"]
                except Exception:  # noqa: BLE001  取樣本身出錯不該讓 watcher 掛掉，當作還沒恢復繼續等
                    level = "critical"

                if level == "ok":
                    ok_streak += 1
                else:
                    if ok_streak > 0:
                        ok_streak = 0  # 資源在門檻邊緣抖動，重新累計連續正常次數
                    now = time.time()
                    if now - last_heartbeat >= _AUTO_RESUME_HEARTBEAT_SEC:
                        last_heartbeat = now
                        events.broadcast(self.project_id, "alert", {
                            "level": "info",
                            "message": f"攻擊端主機資源仍偏高（{metrics.get('cpu_percent')}% CPU／"
                                        f"{metrics.get('mem_percent')}% 記憶體），持續等待恢復中...",
                        })

                if ok_streak >= _AUTO_RESUME_REQUIRED_OK_STREAK:
                    break
                if self._auto_resume_cancel.wait(_AUTO_RESUME_POLL_INTERVAL_SEC):
                    break  # cancel 被設定，wait() 提早回傳 True

            if self._auto_resume_cancel.is_set() or self.kill_switch.is_set():
                return  # 被取消（操作者手動恢復/緊急停止），不用自己再觸發一次

            # 確認這一項還是原本那個因資源保護中止的項目、而且還沒被別的路徑處理掉，才動它
            run = db.get(models.TestRun, failed_run_id)
            if not run or run.project_id != self.project_id or run.verdict != "aborted_self_protect":
                return
            if self.is_running:
                return  # 佇列已經因為別的原因（例如操作者手動恢復）重新在跑了，不用再啟動一次

            run.status = "pending"
            run.attempt_no += 1
            run.started_at = None
            run.ended_at = None
            run.interruption_sec = 0.0
            run.recovered = None
            run.recovery_wait_used_sec = 0.0
            run.verdict = "unknown"
            run.stability_verdict = "unknown"
            run.recovery_verdict = "unknown"
            run.aborted_by_interruption = False
            run.skip_reason = ""
            db.commit()

            events.broadcast(self.project_id, "alert", {
                "level": "ok",
                "message": f"攻擊端主機資源已恢復正常，自動重測測項 #{failed_run_id} 並接續佇列。",
            })
            audit.log(db, project.operator_name, "auto_resume_after_self_protect",
                       target_ref=str(self.project_id),
                       detail={"resumed_run_id": run.id, "attempt_no": run.attempt_no})
            self.start()
        finally:
            db.close()

    def _start_auto_continue_watch(self, run: "models.TestRun"):
        """啟動背景 thread，持續監看『標的服務』是否恢復。中斷超過恢復等待秒數時，判定
        結果（未通過）已經確定，但仍需要持續監控直到設備完全恢復，再自動接續下一個測項，
        避免執行的工程師必須一直守在畫面前等待。

        跟 _start_auto_resume_watch()（攻擊端資源保護自動恢復）的關鍵差異：那個情境是測項
        幾乎沒真的測到什麼（一啟動就被保護機制中止），所以恢復後要「重測」；這裡的情境是
        測項已經完整跑完、判定結果（未通過）已經確定且不應該改變，只是標的服務還沒恢復、
        不適合馬上讓下一項接著打上去——所以恢復後只需要讓佇列直接接續「下一項」，不重測
        這一項（跟 routers/runs.py 的 resume_queue() 對『recovered is False』情況的手動
        處理邏輯完全一致，這裡只是把它自動化，操作者仍可隨時手動按「恢復」提早接續）。"""
        if self._auto_resume_thread and self._auto_resume_thread.is_alive():
            return  # 理論上不會同時有兩個 watcher，防呆
        self._auto_resume_cancel.clear()
        self._auto_resume_thread = threading.Thread(
            target=self._auto_continue_watch_loop, args=(run.id,), daemon=True,
        )
        self._auto_resume_thread.start()

    def _auto_continue_watch_loop(self, waiting_run_id: int):
        db = SessionLocal()
        try:
            run = db.get(models.TestRun, waiting_run_id)
            if not run:
                return
            project = run.project
            target = project.target
            port_number = run.port.port if run.port else None
            monitor_configs = db.query(models.MonitorConfig).filter_by(project_id=project.id, enabled=True).all()
            monitors = self._pick_recovery_monitors(monitor_configs, target.ip_or_host, port_number)
            if not monitors:
                # 沒有能判斷服務死活的監控器（理論上不會發生：_recovery_check 已經用同一套
                # _pick_recovery_monitors 判斷過，能走到這裡代表當初有找到監控器）。防呆，
                # 維持原行為（需要操作者手動按恢復）。
                return

            events.broadcast(self.project_id, "alert", {
                "level": "info",
                "message": (f"測項 #{run.id}（{run.test_item_name}）的「未通過」判定不會改變，"
                             f"背景持續監看標的服務狀態（全部監控器都恢復正常才算數），恢復後會自動"
                             f"接續佇列跑下一項（不會重測這一項；也可以隨時手動提早接續或緊急停止）。"),
            })

            ok_streak = 0
            last_heartbeat = time.time()
            continue_key = f"continue:{waiting_run_id}"
            while not self._auto_resume_cancel.is_set() and not self.kill_switch.is_set():
                is_ok, not_ok_labels = self._all_monitors_recovered(monitors, continue_key)

                if is_ok:
                    ok_streak += 1
                else:
                    if ok_streak > 0:
                        ok_streak = 0  # 服務在門檻邊緣抖動，重新累計連續正常次數
                    now = time.time()
                    if now - last_heartbeat >= _AUTO_RESUME_HEARTBEAT_SEC:
                        last_heartbeat = now
                        still_down = "、".join(not_ok_labels) if not_ok_labels else "監控器"
                        events.broadcast(self.project_id, "alert", {
                            "level": "info",
                            "message": (f"標的服務仍未恢復（尚未恢復：{still_down}），持續等待中"
                                         f"（測項 #{run.id} 的判定已確定，不會改變）..."),
                        })

                if ok_streak >= _AUTO_RESUME_REQUIRED_OK_STREAK:
                    break
                if self._auto_resume_cancel.wait(_AUTO_RESUME_POLL_INTERVAL_SEC):
                    break  # cancel 被設定，wait() 提早回傳 True

            if self._auto_resume_cancel.is_set() or self.kill_switch.is_set():
                return  # 被取消（操作者手動恢復/緊急停止），不用自己再觸發一次
            if self.is_running:
                return  # 佇列已經因為別的原因（例如操作者手動恢復）重新在跑了，不用再啟動一次

            events.broadcast(self.project_id, "alert", {
                "level": "ok",
                "message": f"標的服務已恢復正常，自動接續佇列（測項 #{run.id} 維持原「未通過」判定，不會重測）。",
            })
            audit.log(db, project.operator_name, "auto_continue_after_target_recovery",
                       target_ref=str(self.project_id), detail={"paused_run_id": run.id})
            self.start()
        finally:
            db.close()

    def _finalize_project(self, db):
        project = db.get(models.Project, self.project_id)
        if not project:
            return
        project.status = "closed"
        project.closed_at = datetime.utcnow()
        db.commit()
        try:
            reports.generate_report(db, project.id)
        except Exception as e:  # noqa: BLE001  報告產生失敗不該掩蓋「測試已完成」這件事
            events.broadcast(self.project_id, "alert", {
                "level": "warn", "message": f"報告產生失敗：{e}",
            })
        events.broadcast(self.project_id, "project_closed", {"report_ready": True})
