"""app/schemas.py — Pydantic 請求/回應模型"""
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TargetCreate(BaseModel):
    ip_or_host: str
    description: str = ""
    operator_name: str
    scope_confirmed: bool  # 前端必須勾選才能傳 true，對應 5.1 節的測試範圍確認閘門


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ip_or_host: str
    description: str
    scope_confirmed: bool
    confirmed_at: datetime | None
    confirmed_by: str
    created_at: datetime
    project_count: int = 0  # 有幾個專案在用這個目標，管理清單/擋刪除用


class TargetUpdate(BaseModel):
    description: str  # 只開放改描述；IP/主機名不能改，改了等於是另一個測試範圍，要重新建立+重新確認


class ProjectCreate(BaseModel):
    name: str
    target_id: int
    operator_name: str
    max_interruption_sec: int = 5   # 可接受的最長連續服務中斷秒數，超過判定該測項異常
    recovery_wait_sec: int = 30     # 測項結束後等待服務恢復的秒數，逾時未恢復判定失敗


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    target_id: int
    operator_name: str
    status: str
    created_at: datetime
    closed_at: datetime | None
    max_interruption_sec: int = 5
    recovery_wait_sec: int = 30


class ScanCreate(BaseModel):
    scan_type: str = "tcp_syn"  # tcp_syn | tcp_connect | udp
    port_range: str = "1-65535"


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    scan_type: str
    port_range: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    error: str


class PortEntryCreate(BaseModel):
    port: int
    protocol: str = "tcp"
    service_name: str = ""
    note: str = ""


class PortEntryUpdate(BaseModel):
    selected: bool | None = None
    note: str | None = None


class PortEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    port: int
    protocol: str
    service_name: str
    banner: str
    state: str
    selected: bool
    source: str
    note: str


class MonitorConfigIn(BaseModel):
    type: str
    enabled: bool = True
    config_json: dict = {}


class MonitorConfigOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    type: str
    enabled: bool
    config_json: dict


class TestRunCreate(BaseModel):
    port_id: int | None = None
    test_item_module: str
    params_json: dict = {}
    duration_sec: int = 300
    capture_mode: str = "none"


class TestRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    port_id: int | None
    order_index: int
    test_item_module: str
    test_item_name: str
    category: str
    params_json: dict
    duration_sec: int
    capture_mode: str
    status: str
    attempt_no: int
    started_at: datetime | None
    ended_at: datetime | None
    result_summary_json: dict
    interruption_sec: float = 0.0
    recovered: bool | None = None
    recovery_wait_used_sec: float = 0.0
    verdict: str = "unknown"
    stability_verdict: str = "unknown"
    recovery_verdict: str = "unknown"
    aborted_by_interruption: bool = False
    skip_reason: str = ""


class TestRunUpdate(BaseModel):
    """只允許編輯還沒開始執行（pending）的測項：Port、參數、時長、擷取模式。"""
    port_id: int | None = None
    params_json: dict | None = None
    duration_sec: int | None = None
    capture_mode: str | None = None
