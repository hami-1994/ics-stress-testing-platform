"""
測項：DNS 查詢請求洪水（隨機子網域，防快取命中）
分類：DNS（標準埠 53/UDP）
說明：DNS 查詢洪水是最基礎、最常見的通用壓力測試技巧之一，用來測試 DNS
     Server/Resolver 對高併發查詢的處理能力與回應延遲劣化情況。本測項在每次
     查詢的網域名稱前面加上隨機字串（cache-busting），避免查詢被 Resolver 的
     快取直接擋掉、測不到後端真正的解析負載——這是業界壓力測試 DNS 服務時的
     標準做法（例如 dnsperf/queryperf 等工具的隨機化查詢選項）。

實作：手刻最小 DNS Message 格式（RFC 1035 §4），不依賴 dnspython 等套件：
     Header(12 bytes) + Question(QNAME + QTYPE + QCLASS)，邏輯與同專案
     mdns/query_flood.py 相同（mDNS 封包格式與標準 DNS 完全相同，只是走
     不同埠），此處獨立實作一份是因為兩者分類/情境不同、避免跨套件相依。

安全設計：不偽造來源位址；只送往 Orchestrator 傳入的單一 target:53，不會對
公開的第三方 DNS 服務發送（不构成 DNS 反射放大攻擊）；速率透過 RateLimiter
控制；duration 經 clamp_duration() 限制。
需求：無額外套件，純標準函式庫。
"""
import random
import socket
import string
import time

from ..common import RateLimiter, clamp_duration

NAME = "DNS 查詢請求洪水（隨機子網域）"
CATEGORY = "DNS"
PROTOCOL = "UDP"
DEFAULT_PORT = 53
TEST_TYPE = "traffic"  # 流量型：高頻率查詢洪水，靠封包速率本身造成負擔

_QTYPE_A = 1


def _encode_qname(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        b = label.encode("utf-8")[:63]
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _build_dns_query(qname: str, qtype: int, txid: int) -> bytes:
    flags = 0x0100  # RD=1（recursion desired）
    header = txid.to_bytes(2, "big") + flags.to_bytes(2, "big") + b"\x00\x01" + b"\x00\x00\x00\x00\x00\x00"
    question = _encode_qname(qname) + qtype.to_bytes(2, "big") + (1).to_bytes(2, "big")  # QCLASS=IN
    return header + question


def _rand_label(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 2000000, "min": 1, "max": 2000000, "desc": "每秒送出查詢數"},
        "base_domain": {"type": "string", "default": "example.com", "desc": "基底網域，每次查詢前會加上隨機子網域避免命中快取"},
        "randomize_subdomain": {"type": "bool", "default": True, "desc": "是否每次查詢加上隨機子網域（防快取），關閉則固定查同一名稱"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 2000))
    base_domain = params.get("base_domain", "example.com")
    randomize = bool(params.get("randomize_subdomain", True))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)

    limiter = RateLimiter(rate)
    sent, recv, errors = 0, 0, 0
    start = time.time()

    log_fn(f"[+] DNS 查詢洪水 -> {target}:{port} @ {rate}/s，base_domain={base_domain}，隨機子網域={randomize}")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        txid = random.randint(0, 0xFFFF)
        qname = f"{_rand_label()}.{base_domain}" if randomize else base_domain
        pkt = _build_dns_query(qname, _QTYPE_A, txid)
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
