"""
測項：Modbus 廣播（Unit ID 0）寫入風暴 + Transaction ID 快速循環
分類：Modbus TCP
說明：Modbus 規範保留 Unit ID 0 作為「廣播」位址，語意上是給 Modbus RTU/ASCII 匯流排
使用（所有站點都要處理但依規範不得回應）；許多 Modbus TCP-to-RTU/ASCII 閘道器會把對
Unit ID 0 的請求轉發到底下整條序列埠匯流排上的「所有」裝置。因此對閘道器高頻率
送出廣播寫入，會直接對整條下游序列匯流排造成負載，而非僅影響單一裝置，是評估
「閘道器→序列匯流排」這種常見架構真實負載上限的重要情境。

由於廣播請求依規範不會有回應，client 端可以不必等待/比對回覆就送出下一筆，天然形成
「Transaction ID 快速循環」的效果（16-bit Transaction ID 在測試期間會快速走完並回卷），
因此本測項將廣播風暴與 Transaction ID 快速循環兩種測試情境合併實作。

實作：原生 socket 直接組 MBAP + FC06（Write Single Register）ADU（Unit ID 固定為 0），
不使用 pymodbus 高階 client——因為 pymodbus 對廣播請求預設仍會等待/預期回應逾時，
會拖慢每一輪的實際發送節奏，改用底層 socket 送出後以非阻塞方式檢查是否有非預期回應
（若閘道器/裝置違反規範對廣播請求回應，也一併記錄下來，本身就是一個有意義的發現）。
"""
import socket
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "Modbus 廣播（Unit 0）寫入風暴"
CATEGORY = "Modbus TCP"
PROTOCOL = "TCP"
DEFAULT_PORT = 502
TEST_TYPE = "traffic"  # 廣播封包洪水，對整條下游序列匯流排造成負擔


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 80000, "min": 1, "max": 80000, "desc": "每秒送出廣播寫入次數"},
        "register_addr": {"type": "int", "default": 100, "min": 0, "max": 65535, "desc": "寫入暫存器位址"},
        "write_value": {"type": "int", "default": 0, "min": 0, "max": 65535, "desc": "寫入值"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 150))
    addr = int(params.get("register_addr", 100))
    value = int(params.get("write_value", 0))
    unit_id = 0  # 廣播位址，依 Modbus 規範固定為 0，不開放使用者調整

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((target, port))
    except OSError as e:
        log_fn(f"[!] 無法連線 {target}:{port}：{e}")
        return {"frames_sent": 0, "connected": False, "error": str(e)}
    sock.setblocking(False)

    limiter = RateLimiter(rate)
    sent, unexpected_responses, errors = 0, 0, 0
    start = time.time()
    txn = 1

    log_fn(f"[+] 開始 Modbus 廣播寫入風暴 @ {rate}/s，Unit ID=0（廣播），addr={addr}, value={value}")

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        pdu = struct.pack(">BHH", 0x06, addr, value)  # FC06 Write Single Register
        mbap = struct.pack(">HHHB", txn, 0x0000, len(pdu) + 1, unit_id)
        txn = (txn + 1) % 0xFFFF
        try:
            sock.sendall(mbap + pdu)
            sent += 1
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")
        try:
            resp = sock.recv(256)
            if resp:
                unexpected_responses += 1
        except BlockingIOError:
            pass
        except OSError:
            pass

    try:
        sock.close()
    except OSError:
        pass

    elapsed = time.time() - start
    log_fn(
        f"[+] 完成，送出 {sent} 個廣播寫入請求（意外收到回應 {unexpected_responses} 次，"
        f"代表裝置未依規範忽略廣播），錯誤 {errors} 次"
    )
    return {
        "frames_sent": sent,
        "unexpected_responses": unexpected_responses,
        "errors": errors,
        "elapsed_sec": round(elapsed, 1),
    }
