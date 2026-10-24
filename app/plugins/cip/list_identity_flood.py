"""
測項：EtherNet/IP List Identity 探索請求風暴
分類：EtherNet/IP (CIP)（UDP 44818，Encapsulation List Identity 命令）
說明：List Identity（Encapsulation Command 0x63）是 EtherNet/IP 標準定義的裝置探索
命令，正常使用情境是掃描工具對網段送出，裝置收到後要組出包含廠牌/型號/序號等資訊
的 Identity CPF 回應。由於每次請求裝置都要重新組出並送回一份回應，高頻率送出可
測試裝置 UDP encapsulation 服務對探索請求的處理裕度（部分低階閘道器/嵌入式裝置在
高頻率探索下曾觀察到回應延遲飆升甚至服務中斷的情況）。

封包格式依 ODVA CIP Networks Library Volume 2（EtherNet/IP Adaptation）公開規範的
Encapsulation Header 組成（Command/Length/SessionHandle/Status/SenderContext/Options，
共 24 bytes，List Identity 請求不含任何 Command-Specific Data），此為公開文件定義的
標準格式；專案內未逐一以真實硬體比對驗證每個廠牌實作是否完全遵循規範。
需求：無額外套件（純標準函式庫 socket + struct）。
"""
import socket
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "EtherNet/IP List Identity 探索請求風暴"
CATEGORY = "EtherNet/IP (CIP)"
PROTOCOL = "UDP"
DEFAULT_PORT = 44818
TEST_TYPE = "resource"  # 裝置識別回應組字串成本，非單純比流量大小


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 200000, "min": 1, "max": 200000, "desc": "每秒送出 List Identity 請求數"},
    }


def _build_list_identity(sender_context: bytes) -> bytes:
    command = 0x63  # List Identity
    length = 0x0000  # 請求不含 Command-Specific Data
    session_handle = 0x00000000
    status = 0x00000000
    options = 0x00000000
    return struct.pack("<HHII8sI", command, length, session_handle, status, sender_context, options)


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 500))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    limiter = RateLimiter(rate)
    sent, responses, errors = 0, 0, 0
    start = time.time()
    seq = 0

    log_fn(f"[+] EtherNet/IP List Identity 探索風暴 -> {target}:{port} @ {rate}/s, {duration}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        seq += 1
        ctx = struct.pack(">Q", seq)[-8:]
        pkt = _build_list_identity(ctx)
        try:
            sock.sendto(pkt, (target, port))
            sent += 1
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")
        try:
            sock.recvfrom(1024)
            responses += 1
        except BlockingIOError:
            pass
        except OSError:
            pass

    sock.close()
    elapsed = time.time() - start
    log_fn(f"[+] 完成，送出 {sent} 個 List Identity 請求，收到回應 {responses} 次，錯誤 {errors} 次")
    return {"requests_sent": sent, "responses": responses, "errors": errors, "elapsed_sec": round(elapsed, 1)}
