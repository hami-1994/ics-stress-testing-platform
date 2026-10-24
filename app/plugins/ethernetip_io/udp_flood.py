"""
測項：Implicit I/O（EtherNet/IP）UDP 2222 爆發衝擊
分類：EtherNet/IP (CIP)
說明：EtherNet/IP 的 Implicit（即時 I/O）通訊使用 UDP 2222，
     大量偽 I/O 封包可能干擾即時性 I/O 資料交換。

實作：直接沿用通用 UDP Flood（含速率限制），預設埠改為 2222。
"""
from ..generic.udp_flood import get_param_schema, run  # noqa: F401

NAME = "Implicit I/O UDP 2222 爆發衝擊"
CATEGORY = "EtherNet/IP (CIP)"
PROTOCOL = "UDP"
DEFAULT_PORT = 2222
TEST_TYPE = "traffic"  # UDP flood，靠封包速率/頻寬造成負擔
