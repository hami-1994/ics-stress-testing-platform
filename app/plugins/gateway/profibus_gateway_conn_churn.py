"""
測項：PROFIBUS-DP 轉乙太網路閘道器連線耗盡測試
分類：工控閘道器 (Gateway)（無單一標準埠——不同廠牌的 PROFIBUS-DP/Ethernet
     Gateway 差異很大：Siemens IE/PB-Link 走 S7 的 102/TCP 堆疊、Anybus/HMS
     系列走各自的組態通訊埠、部分裝置對外提供 Modbus TCP 502 做資料橋接，
     建立測項時請依受測閘道器實際開放的管理/資料埠自行填入）
說明：PROFIBUS-DP 本身是現場匯流排（無 IP 定址概念），要從 IP 網路測試現場
     匯流排背後的裝置，一定得透過「PROFIBUS-DP 轉乙太網路閘道器」，這類閘道器
     本身的 TCP/IP 通訊堆疊（管理介面、組態通訊、資料橋接通訊埠）就是常見的
     攻擊面/壓力測試標的——閘道器韌體資源通常比一般 IT 設備更有限。

實作：與同專案 gateway/niagara_fox_conn_churn.py 相同做法，沿用通用 TCP
Connection Flood（app.plugins.generic.tcp_conn_flood）建立大量連線並保持。

重要限制：PROFIBUS-DP-to-Ethernet 閘道器並沒有單一業界標準的應用層
協定可循（不像 Modbus/S7 有公開規範），各廠牌差異極大，因此本測項刻意只做
「TCP 連線層級」的資源耗盡測試（連線建立/保持/資源回收），不嘗試對特定廠牌
組出可能不正確的應用層封包。若需要更貼近實際協定行為的測試，請先用
Wireshark 對受測閘道器的實際管理/資料通訊埠做封包截取，確認協定格式後再
視需要擴充。
"""
from ..generic.tcp_conn_flood import get_param_schema, run  # noqa: F401

NAME = "PROFIBUS-DP 轉乙太網路閘道器連線耗盡測試"
CATEGORY = "工控閘道器 (Gateway)"
PROTOCOL = "TCP"
TEST_TYPE = "resource"  # 連線型：建立大量完整 TCP 連線並保持開啟，屬連線池飽和攻擊
