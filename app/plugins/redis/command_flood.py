"""
測項：Redis PING 指令高頻率洪水
分類：Redis（標準埠 6379/TCP）
說明：Redis 常見於快取層，也常出現在 IoT 平台後端（裝置狀態快取、訊息佇列）
     且不少部署對外暴露卻未設密碼/未做網路隔離。以受控速率在單一持久連線上
     重複送出 PING 指令，測試 Redis 單執行緒事件迴圈對高頻指令的處理能力
     （Redis 為單執行緒架構，指令處理是嚴格序列化的，高頻率指令對回應延遲的
     影響會直接反映事件迴圈的飽和程度）。

實作：純標準函式庫 socket，依 Redis RESP（REdis Serialization Protocol）
標準格式組出 PING 指令：
    *1\\r\\n$4\\r\\nPING\\r\\n
  （RESP Array，1 個元素，Bulk String "PING"）預期回應 "+PONG\\r\\n"。

安全設計（重要）：
  - 只使用 PING 這個唯讀、無副作用的指令，不執行任何會員資料的 SET/DEL/
    FLUSHALL/CONFIG 等指令，不會修改或清除任何資料。
  - 不嘗試 AUTH/任何密碼組合（no credential attempts）；不偽造來源位址。
  - 速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。
需求：無額外套件，純標準函式庫。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "Redis PING 指令高頻率洪水"
CATEGORY = "Redis"
PROTOCOL = "TCP"
DEFAULT_PORT = 6379
TEST_TYPE = "traffic"  # 單一連線上以高指令速率造成負擔的洪水攻擊

_PING_CMD = b"*1\r\n$4\r\nPING\r\n"


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 1000000, "min": 1, "max": 1000000, "desc": "每秒送出 PING 指令數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 1000))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((target, port))
    except OSError as e:
        log_fn(f"[!] 無法連線 {target}:{port}: {e}")
        return {"sent": 0, "error": str(e)}

    limiter = RateLimiter(rate)
    sent, recv, errors = 0, 0, 0
    start = time.time()

    log_fn(f"[+] Redis PING 洪水 -> {target}:{port} @ {rate}/s（唯讀指令，不修改任何資料）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            sock.sendall(_PING_CMD)
            sent += 1
            try:
                sock.settimeout(0.2)
                resp = sock.recv(64)
                if resp.startswith(b"+PONG"):
                    recv += 1
            except socket.timeout:
                pass
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")
            break

    sock.close()
    return {"commands_sent": sent, "pong_received": recv, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
