"""
測項：SSH 連線池飽和測試（Pre-auth 連線耗盡）
分類：SSH（預設埠 22/TCP）
說明：沿用通用 TCP Connection Flood（app.plugins.generic.tcp_conn_flood）：
     建立大量 TCP 連線並保持開啟（不送出任何 SSH 資料，純 TCP 層級保持），
     測試 sshd 的 MaxStartups pre-auth 連線併發上限。

安全設計：與底層 generic.tcp_conn_flood 一致——僅止於 TCP 層級連線保持，
     不涉及 SSH 協定內容，因此不可能有任何形式的認證嘗試；不偽造來源位址。
"""
from ..generic.tcp_conn_flood import get_param_schema, run  # noqa: F401

NAME = "SSH 連線池飽和測試（Pre-auth 連線耗盡）"
CATEGORY = "SSH"
PROTOCOL = "TCP"
DEFAULT_PORT = 22
TEST_TYPE = "resource"  # TCP 連線池飽和（建立大量連線並保持開啟）
