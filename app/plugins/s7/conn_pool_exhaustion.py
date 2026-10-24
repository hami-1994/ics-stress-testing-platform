"""
測項：Siemens S7 通訊協定連線池耗盡
分類：Siemens S7
實作：沿用通用 TCP Connection Flood（原生 socket，可被 stop_event 統一收尾）。

進階建議（未實作，供未來擴充）：
  純 TCP connect 只測到作業系統層的連線數上限，並未真正進行 S7comm/COTP 的
  Session 建立（COTP Connection Request + S7 Setup Communication）。若要更貼近
  真實 PLC 的連線池行為，可改用 python-snap7（pip install python-snap7）呼叫
  client.connect() 建立「真正的」S7 連線後保持不斷開，會比單純 TCP handshake
  更精準地測出 PLC 韌體對同時 S7 連線數的限制（多數 S7-300/400/1200/1500
  對外可同時開啟的連線數都相當有限）。
"""
from ..generic.tcp_conn_flood import get_param_schema, run  # noqa: F401

NAME = "Siemens S7 連線池耗盡測試"
CATEGORY = "Siemens S7"
PROTOCOL = "TCP"
DEFAULT_PORT = 102
TEST_TYPE = "resource"  # 佔滿 TCP 連線池上限
