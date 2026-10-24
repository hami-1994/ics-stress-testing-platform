"""
測項：Modbus TCP Master 連線池飽和測試
分類：Modbus TCP
說明：多數 Modbus TCP Slave/Gateway 對同時連線數有限制（常見僅個位數到數十），
     建立大量並保持連線可測試其連線池上限與異常處理行為。

實作：直接沿用通用 TCP Connection Flood（原生 socket + threading），可透過
     stop_event 統一控制連線的建立與收尾，避免以背景 shell 程序建立大量連線時
     難以統一停止/回收的問題。
"""
from ..generic.tcp_conn_flood import get_param_schema, run  # noqa: F401  行為完全相同，故直接複用

NAME = "Modbus TCP Master 連線池飽和測試"
CATEGORY = "Modbus TCP"
PROTOCOL = "TCP"
DEFAULT_PORT = 502
TEST_TYPE = "resource"  # 佔滿 TCP 連線池上限
