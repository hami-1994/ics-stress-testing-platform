"""
測項：SMB/CIFS 連線耗盡測試
分類：SMB/CIFS（標準埠 445/TCP）
說明：SMB/CIFS（445/TCP）常見於檔案伺服器、NAS，也常出現在 ICS/工控環境的
     HMI/工程站上（用於韌體/專案檔共享），且不少工控機台的 SMB 服務版本老舊、
     資源限制嚴格。沿用同專案 s7/conn_pool_exhaustion.py、rpc/conn_churn_flood.py
     一致的做法，以真正的 TCP 交握測試連線池/資源耗盡行為。

限制說明：本測項「不」實作 SMB2 Negotiate Protocol Request/Session
Setup（MS-SMB2 規範的訊息格式複雜，且不同 Windows/Samba 版本的協商細節有
差異，貿然手刻容易出錯），因此測到的是「TCP accept/連線資源上限」而非
「SMB Session 層級」的資源上限。若需要更貼近 SMB 協定層級的負載測試（例如
Negotiate/Session Setup 循環），建議改用 Impacket 等成熟的 SMB 協定實作。

實作：沿用通用 TCP Connection Flood（app.plugins.generic.tcp_conn_flood）。
"""
from ..generic.tcp_conn_flood import get_param_schema, run  # noqa: F401

NAME = "SMB/CIFS 連線耗盡測試"
CATEGORY = "SMB/CIFS"
PROTOCOL = "TCP"
DEFAULT_PORT = 445
TEST_TYPE = "resource"  # TCP 連線池飽和（建立大量連線並保持開啟）
