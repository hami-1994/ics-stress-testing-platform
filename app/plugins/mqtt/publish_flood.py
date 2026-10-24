"""
測項：MQTT PUBLISH 高頻率洪水
分類：MQTT
說明：單一（或少量）連線持續高頻率對指定 topic 發布訊息，測試 Broker 的訊息路由/
     轉發吞吐量上限，以及訂閱端（其他裝置）在大量訊息湧入時的處理能力。
需求套件：pip install paho-mqtt
"""
import time

from ..common import RateLimiter, clamp_duration

NAME = "MQTT PUBLISH 高頻率洪水"
CATEGORY = "MQTT"
PROTOCOL = "TCP"
DEFAULT_PORT = 1883
TEST_TYPE = "traffic"  # 單一連線上以高訊息速率造成負擔的洪水攻擊


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 700000, "min": 1, "max": 800000, "desc": "每秒發布訊息數"},
        "topic": {"type": "string", "default": "stress-test/flood", "desc": "發布目標 topic"},
        "payload_size": {"type": "int", "default": 64, "min": 1, "max": 65536, "desc": "訊息內容大小(bytes)"},
        "qos": {"type": "int", "default": 0, "min": 0, "max": 2, "desc": "MQTT QoS 等級"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        log_fn("[!] 未安裝 paho-mqtt，請先執行 pip install paho-mqtt")
        return {"published": 0, "error": "paho-mqtt not installed"}

    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 700))
    topic = params.get("topic", "stress-test/flood")
    size = int(params.get("payload_size", 64))
    qos = int(params.get("qos", 0))
    payload = b"x" * size

    client = mqtt.Client(client_id=f"stress-test-pub-{int(time.time())}")
    try:
        client.connect(target, port, keepalive=max(duration + 30, 60))
    except OSError as e:
        log_fn(f"[!] 無法連線 {target}:{port}: {e}")
        return {"published": 0, "error": str(e)}
    client.loop_start()

    limiter = RateLimiter(rate)
    published, errors = 0, 0
    start = time.time()

    log_fn(f"[+] 開始 PUBLISH -> topic={topic} @ {rate}/s, qos={qos}")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            client.publish(topic, payload, qos=qos)
            published += 1
        except Exception as e:  # noqa: BLE001
            errors += 1
            if errors <= 5:
                log_fn(f"[!] publish error: {e}")

    client.loop_stop()
    client.disconnect()

    return {"published": published, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
