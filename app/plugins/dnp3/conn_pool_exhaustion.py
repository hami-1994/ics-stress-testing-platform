"""
測項：DNP3 TCP 連線池飽和測試
分類：DNP3
實作：沿用通用 TCP Connection Flood（原生 socket，可被 stop_event 統一收尾）。
"""
from ..generic.tcp_conn_flood import get_param_schema, run  # noqa: F401

NAME = "DNP3 TCP 連線池飽和測試"
CATEGORY = "DNP3"
PROTOCOL = "TCP"
DEFAULT_PORT = 20000
TEST_TYPE = "resource"  # 連線型：建立大量完整 TCP 連線並保持開啟，屬連線池飽和攻擊
