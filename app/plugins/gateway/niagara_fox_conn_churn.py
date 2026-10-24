"""
測項：Niagara Fox / CODESYS 工控閘道器連線耗盡測試
分類：工控閘道器 (Gateway)（Niagara Fox 標準埠 1911/TCP，TLS 加密版 foxs 為
     4911/TCP；CODESYS Gateway 常見埠 1200 或 2455/TCP，依廠牌/版本而定，可於
     建立測項時自行改埠）
說明：Niagara Fox（Tridium Niagara Framework 私有協定）與 CODESYS Gateway
     都是樓宇自動化/工控整合常見的閘道器協定，許多 BMS（Building Management
     System）與 PLC 工程站都是透過這兩種協定與後端站台/控制器通訊。兩者皆為
     廠商私有二進位/文字混合協定，公開文件不如 Modbus/S7 完整，因此本測項
     沿用同專案 s7/conn_pool_exhaustion.py、ssh/conn_pool_exhaustion.py 的
     一致做法：以真正的 TCP 交握（connect + 保持連線）測「連線池/資源耗盡」，
     而非嘗試手刻可能出錯的私有應用層協定內容。

實作：沿用通用 TCP Connection Flood（app.plugins.generic.tcp_conn_flood），
以分批 spawn 執行緒方式建立大量連線並保持到測試結束或被停止。

重要限制（設計精神比照 s7/conn_pool_exhaustion.py 的「進階建議」段落）：
  - 這裡「不」實作 Fox 協定的版本協商/hello 交換（已知公開資料顯示其第一步
    大致是類似 `fox a 1 -1\\r\\n` 的文字版本宣告，但後續 hello 訊息格式涉及
    廠牌版本差異，未經過對真實 Niagara Station 的封包截取驗證，貿然手刻可能
    產生不正確或誤導性的封包，故本測項刻意只做到 TCP 層級）；CODESYS Gateway
    協定亦然。
  - 因此本測項測到的是「作業系統 TCP accept/連線資源上限」，而非「應用層
    Session/認證前資源上限」。若需要更貼近真實協定行為的測試，建議先用
    Wireshark 對受測閘道器實際運作流量做封包截取，確認 Fox/CODESYS 應用層
    握手格式後再擴充本模組。
"""
from ..generic.tcp_conn_flood import get_param_schema, run  # noqa: F401

NAME = "Niagara Fox / CODESYS 閘道器連線耗盡測試"
CATEGORY = "工控閘道器 (Gateway)"
PROTOCOL = "TCP"
DEFAULT_PORT = 1911  # 修正：Niagara Fox 協定標準埠為 1911/TCP（TLS 版 foxs 為 4911），原值 1962 有誤
TEST_TYPE = "resource"  # 連線型：建立大量完整 TCP 連線並保持開啟，屬連線池飽和攻擊
