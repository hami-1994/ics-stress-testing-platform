"""
測項：IEC104 TCP 連線池飽和測試
分類：IEC 60870-5-104
實作：沿用通用 TCP Connection Flood（原生 socket，可被 stop_event 統一收尾）。
"""
from ..generic.tcp_conn_flood import get_param_schema, run  # noqa: F401

NAME = "IEC104 TCP 連線池飽和測試"
CATEGORY = "IEC 60870-5-104"
PROTOCOL = "TCP"
DEFAULT_PORT = 2404
TEST_TYPE = "resource"  # 連線型：建立大量完整 TCP 連線並保持開啟，屬連線池飽和攻擊
