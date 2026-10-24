"""
測項：mDNS 查詢請求洪水
分類：mDNS (物聯網服務發現)（標準埠 5353/UDP）
說明：mDNS（Multicast DNS, RFC 6762）是區域網路內裝置互相發現服務的常見機制
     （Apple Bonjour、Chromecast、印表機、許多 IoT 裝置的服務探索都靠它），
     封包格式與一般 DNS 完全相同，只是走 5353/UDP。以受控速率重複送出標準 DNS
     格式的查詢封包，測試裝置的 mDNS responder 對高頻查詢的處理能力。

實作：手刻最小 DNS Message 格式（RFC 1035 §4），不依賴 dnspython 等套件：
     Header(12 bytes: ID/Flags/QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT) + Question
     (QNAME 標籤序列 + QTYPE + QCLASS)。

安全設計（重要）：
  - 一律以 unicast 直接送往 Orchestrator 傳入的 target:5353（不送往 mDNS 群播位址
    224.0.0.251），避免影響同網段其他非受測裝置。依 RFC 6762 §5.4，多數 mDNS
    responder 對「QU（unicast-response）」查詢一樣會回應，足以達成壓力測試效果；
    未設定 QU bit（本測項不強求對方一定回應，純以送出查詢量做為壓力來源）。
  - 不偽造來源位址，不構成放大攻擊反射面；速率透過 RateLimiter 控制；duration
    經 clamp_duration() 限制。
需求：無額外套件，純標準函式庫。
"""
import random
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "mDNS 查詢請求洪水"
CATEGORY = "mDNS (物聯網服務發現)"
PROTOCOL = "UDP"
DEFAULT_PORT = 5353
TEST_TYPE = "traffic"  # 流量型：高頻率查詢洪水，靠封包速率本身造成負擔

_QTYPE_PTR = 12
_QTYPE_ANY = 255


def _encode_qname(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        b = label.encode("utf-8")[:63]
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _build_dns_query(qname: str, qtype: int, txid: int) -> bytes:
    header = txid.to_bytes(2, "big") + b"\x00\x00" + b"\x00\x01" + b"\x00\x00\x00\x00\x00\x00"
    question = _encode_qname(qname) + qtype.to_bytes(2, "big") + (1).to_bytes(2, "big")  # QCLASS=IN
    return header + question


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 500000, "min": 1, "max": 500000, "desc": "每秒送出查詢數"},
        "query_name": {"type": "string", "default": "_services._dns-sd._udp.local", "desc": "查詢名稱（預設為 mDNS 服務列表探索名稱）"},
        "query_type": {"type": "string", "default": "PTR", "desc": "查詢類型：PTR 或 ANY"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 500))
    qname = params.get("query_name", "_services._dns-sd._udp.local")
    qtype = _QTYPE_ANY if str(params.get("query_type", "PTR")).upper() == "ANY" else _QTYPE_PTR

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)

    limiter = RateLimiter(rate)
    sent, recv, errors = 0, 0, 0
    start = time.time()

    log_fn(f"[+] mDNS 查詢洪水 -> {target}:{port} @ {rate}/s，query={qname}")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        txid = random.randint(0, 0xFFFF)
        pkt = _build_dns_query(qname, qtype, txid)
        try:
            sock.sendto(pkt, (target, port))
            sent += 1
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
    return {"queries_sent": sent, "responses_received": recv, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
