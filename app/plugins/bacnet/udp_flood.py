"""
測項：BACnet/IP UDP 通用流量衝擊
分類：BACnet（樓宇自動化，預設埠 47808/UDP）
實作：直接沿用通用 UDP Flood（含速率限制），預設埠改為 47808。
"""
from ..generic.udp_flood import get_param_schema, run  # noqa: F401

NAME = "BACnet/IP UDP 流量衝擊"
CATEGORY = "BACnet"
PROTOCOL = "UDP"
DEFAULT_PORT = 47808
TEST_TYPE = "traffic"  # 流量型：通用 UDP 封包洪水，靠封包速率/頻寬本身造成負擔
