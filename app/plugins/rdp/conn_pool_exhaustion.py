"""
測項：RDP 連線池飽和測試
分類：RDP（預設埠 3389/TCP）
說明：沿用通用 TCP Connection Flood（app.plugins.generic.tcp_conn_flood）：
     建立大量 TCP 連線並保持開啟，測試終端伺服器/RDP 閘道器對同時連線數的上限
     與資源耗盡行為，不涉及任何 RDP 協定內容或憑證。

安全設計：與底層 generic.tcp_conn_flood 一致——純 TCP 層級連線保持，不偽造
     來源位址，不涉及任何形式的驗證嘗試。
"""
from ..generic.tcp_conn_flood import get_param_schema, run  # noqa: F401

NAME = "RDP 連線池飽和測試"
CATEGORY = "RDP"
PROTOCOL = "TCP"
DEFAULT_PORT = 3389
TEST_TYPE = "resource"  # TCP 連線池飽和（建立大量連線並保持開啟）
