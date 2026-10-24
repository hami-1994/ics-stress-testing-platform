"""
app/models.py — SQLAlchemy ORM models

對應設計文件第 4 節「核心資料模型」，並套用第 3 節（單一操作者，operator_name 取代
帳號系統）與第 5.1 節（測試範圍確認改成輕量勾選，不做正式授權文件）的最新調整。
"""
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_or_host: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(String(500), default="")
    # 5.1 節：輕量測試範圍確認，取代正式授權文件管理
    scope_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    confirmed_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    projects: Mapped[list["Project"]] = relationship(back_populates="target")


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    operator_name: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(20), default="open")  # open/closed
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # 通過條件（使用者可設定，對應「報告要看得出來最後判定結果是不是有通過」）：
    #   - max_interruption_sec：測試過程中，服務可以接受連續中斷幾秒，超過就判定該測項異常
    #   - recovery_wait_sec：每個測項結束後，等待這麼多秒讓服務恢復，時間到還沒恢復就判定失敗
    max_interruption_sec: Mapped[int] = mapped_column(Integer, default=5)
    recovery_wait_sec: Mapped[int] = mapped_column(Integer, default=30)

    target: Mapped["Target"] = relationship(back_populates="projects")
    scans: Mapped[list["ScanResult"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    ports: Mapped[list["PortEntry"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    monitors: Mapped[list["MonitorConfig"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    runs: Mapped[list["TestRun"]] = relationship(back_populates="project", cascade="all, delete-orphan",
                                                  order_by="TestRun.order_index")
    reports: Mapped[list["Report"]] = relationship(back_populates="project", cascade="all, delete-orphan")

    @property
    def project_dir_name(self) -> str:
        ts = self.created_at.strftime("%Y%m%d_%H%M") if self.created_at else "unknown"
        safe_target = (self.target.ip_or_host if self.target else "target").replace("/", "_").replace(":", "_")
        return f"{self.id}_{safe_target}_{ts}"


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    scan_type: Mapped[str] = mapped_column(String(50), default="tcp_syn")
    port_range: Mapped[str] = mapped_column(String(255), default="1-65535")
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending/running/completed/failed
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    raw_xml_path: Mapped[str] = mapped_column(String(500), default="")
    error: Mapped[str] = mapped_column(Text, default="")

    project: Mapped["Project"] = relationship(back_populates="scans")


class PortEntry(Base):
    __tablename__ = "port_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")  # tcp/udp
    service_name: Mapped[str] = mapped_column(String(120), default="")
    banner: Mapped[str] = mapped_column(String(500), default="")
    state: Mapped[str] = mapped_column(String(20), default="open")
    selected: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(10), default="scan")  # scan/manual
    note: Mapped[str] = mapped_column(String(500), default="")

    project: Mapped["Project"] = relationship(back_populates="ports")


class MonitorConfig(Base):
    __tablename__ = "monitor_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    type: Mapped[str] = mapped_column(String(30))  # iface/ping/tcp/self_resource/service
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)

    project: Mapped["Project"] = relationship(back_populates="monitors")


class TestRun(Base):
    __tablename__ = "test_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    port_id: Mapped[int | None] = mapped_column(ForeignKey("port_entries.id"), nullable=True)
    order_index: Mapped[int] = mapped_column(Integer, default=0)

    test_item_module: Mapped[str] = mapped_column(String(255))  # 例如 plugins.generic.tcp_syn_flood
    test_item_name: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(80))
    params_json: Mapped[dict] = mapped_column(JSON, default=dict)
    duration_sec: Mapped[int] = mapped_column(Integer, default=300)
    capture_mode: Mapped[str] = mapped_column(String(10), default="none")  # none/pcap/summary/both

    status: Mapped[str] = mapped_column(String(20), default="pending")
    # pending/running/paused... 依設計文件 5.6：pending/running/completed/failed/stopped
    attempt_no: Mapped[int] = mapped_column(Integer, default=1)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    result_summary_json: Mapped[dict] = mapped_column(JSON, default=dict)
    log_path: Mapped[str] = mapped_column(String(500), default="")

    # 通過/失敗判定（對應設計文件「報告通過條件」）：
    #   - interruption_sec：本次測試過程中偵測到的最長連續服務中斷秒數（由 service 監控器推算）
    #   - recovered：測項結束後，是否在 recovery_wait_sec 內恢復正常
    #   - recovery_wait_used_sec：實際等了幾秒才確認恢復（或等到逾時放棄）
    #   - verdict：pass / fail / warn / unknown（沒有啟用 service 監控器時無法判定，標 unknown）
    interruption_sec: Mapped[float] = mapped_column(default=0.0)
    recovered: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    recovery_wait_used_sec: Mapped[float] = mapped_column(default=0.0)
    # verdict 可能值：pass / warn / fail / unknown / skipped（使用者手動跳過）/
    # aborted_self_protect（因發起測試的主機自身資源過載被自動中止保護）/ unreachable
    # （目標 Port 從開始前就無回應，非壓力測試造成）。
    # 由 stability_verdict／recovery_verdict 兩個獨立維度綜合算出
    # （見 app/orchestrator.py 的 _compute_axis_verdicts()），這個欄位保留給「一眼看整體
    # 有沒有問題」的綜合結果／向下相容既有畫面。**沒有 interrupted_recovered 這個值**
    # ——中斷超標本身就是 stability_verdict=fail，不管事後恢不恢復，這個維度都是未通過。
    verdict: Mapped[str] = mapped_column(String(30), default="unknown")
    # 判定拆成兩個獨立維度：測試過程有沒有任何攻擊端自我資源監控器以外的監控器出現
    # 中斷秒數超過可接受的秒數，如果有就判定測試不通過；另外如果測試結束之後，超過
    # 恢復等待秒數可接受的值，則判定恢復能力不符合預期：
    #   - stability_verdict（測試過程連線和服務狀態）：pass / warn / fail / unknown / na
    #     ——這次測試「執行期間」有沒有任何判定用監控器連續中斷秒數超過可接受上限。
    #   - recovery_verdict（受攻擊後的恢復能力）：pass / fail / unknown / na
    #     ——測項「結束後」是否在可接受時間內恢復正常。
    # na（不適用）用在 skipped／aborted_self_protect／unreachable 這些整項都不評斷的情況。
    stability_verdict: Mapped[str] = mapped_column(String(20), default="unknown")
    recovery_verdict: Mapped[str] = mapped_column(String(20), default="unknown")
    # 這一項是否曾經因為「連續中斷秒數超過可接受上限」被 Orchestrator 提前中止（不同於使用者手動停止）
    aborted_by_interruption: Mapped[bool] = mapped_column(Boolean, default=False)
    # 使用者手動跳過的原因／系統自動跳過的原因（例如自我資源保護觸發）
    skip_reason: Mapped[str] = mapped_column(String(500), default="")

    project: Mapped["Project"] = relationship(back_populates="runs")
    port: Mapped["PortEntry | None"] = relationship()
    captures: Mapped[list["CaptureFile"]] = relationship(back_populates="test_run", cascade="all, delete-orphan")


class CaptureFile(Base):
    __tablename__ = "capture_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    test_run_id: Mapped[int] = mapped_column(ForeignKey("test_runs.id"))
    file_path: Mapped[str] = mapped_column(String(500))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    mode: Mapped[str] = mapped_column(String(10), default="pcap")
    # 封包檔案管理（磁碟空間治理）：使用者可以手動刪除實際檔案釋放空間，但保留這筆紀錄
    # 本身（連同刪除前的大小），讓歷史報告/檔案管理清單仍看得出「這裡曾經有一個多大的檔案、
    # 何時被誰刪除」，而不是整筆資料憑空消失、事後無法追溯。
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    deleted_by: Mapped[str] = mapped_column(String(100), default="")

    test_run: Mapped["TestRun"] = relationship(back_populates="captures")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    html_path: Mapped[str] = mapped_column(String(500), default="")
    pdf_path: Mapped[str] = mapped_column(String(500), default="")
    json_path: Mapped[str] = mapped_column(String(500), default="")

    project: Mapped["Project"] = relationship(back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    operator_name: Mapped[str] = mapped_column(String(120), default="")
    action: Mapped[str] = mapped_column(String(80))
    target_ref: Mapped[str] = mapped_column(String(255), default="")
    detail_json: Mapped[dict] = mapped_column(JSON, default=dict)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TestItemConfig(Base):
    """測項管理／健康檢查資料表（設計文件第 20 節）。

    對應 registry.py TEST_ITEMS 裡的每一個模組「最多」有一筆對應紀錄（沒有紀錄
    的模組視為預設值：enabled=True、health_status="unknown"，尚未跑過健康檢查）。
    這張表只存「使用者的覆寫/健康檢查結果」，不是測項本身的定義來源——NAME/
    CATEGORY/PROTOCOL/get_param_schema() 的預設值一律仍以 registry.py 載入的
    plugin 模組為準，這裡的 custom_name/custom_params_json 只是「疊加」上去的
    使用者覆寫層，plugin 原始程式碼完全不受影響，也不會因為覆寫值有問題就整個
    測項模組壞掉（覆寫值格式錯誤時，merge 邏輯會直接忽略該筆覆寫並退回原始預設值）。

    enabled=False 的測項不可被加入測試佇列（見 orchestrator.py 的
    guard_enabled()／routers/runs.py 的 add_run() 檢查），避免使用者不小心排入
    一個依賴缺漏、實際上跑不動的測項而卡住整條佇列。
    """
    __tablename__ = "test_item_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    module: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # ok / error / unknown（unknown = 尚未跑過健康檢查，例如剛新增的測項、
    # 或使用者手動用舊版資料庫升級上來、還沒重跑過 healthcheck）
    health_status: Mapped[str] = mapped_column(String(20), default="unknown")
    health_detail: Mapped[str] = mapped_column(Text, default="")
    checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # 使用者自訂覆寫（測項管理頁：命名、預設參數調整）；皆可為空，為空時使用
    # plugin 模組本身的 NAME / get_param_schema() 預設值。
    custom_name: Mapped[str] = mapped_column(String(255), default="")
    custom_params_json: Mapped[dict] = mapped_column(JSON, default=dict)

    # 「高並發加速版」引擎偏好（見
    # app/plugins/common.py 的 run_concurrent_workers()／app/registry.py 的
    # DEFAULT_ENGINE_MODE_BY_TEST_TYPE）。
    #   engine_mode: None（未設定，沿用系統依 TEST_TYPE 決定的建議預設值）／
    #                "native"（標準版，單一執行緒的既有行為）／
    #                "concurrent"（高並發加速版，多執行緒平行執行同一測項）。
    #   engine_workers: None（未設定，沿用 common.py 的 CONCURRENT_ENGINE_WORKERS
    #                   系統預設值）／使用者在測項管理頁自訂的並發執行緒數。
    # 刻意用 nullable + None 代表「跟隨系統建議」而不是把某個固定值當預設寫進資料庫，
    # 這樣日後如果調整「建議預設策略」，所有還沒被使用者手動覆寫過的測項會自動套用
    # 新策略，不需要一筆一筆資料庫紀錄跟著改——跟 custom_name/custom_params_json
    # 「使用者覆寫層」疊加在 plugin 預設值之上的既有設計精神一致。
    engine_mode: Mapped[str | None] = mapped_column(String(20), nullable=True, default=None)
    engine_workers: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)

    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
