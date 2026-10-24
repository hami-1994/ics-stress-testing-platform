"""
測項：SNMP GetNext 快速走訪洪水（Walk-style）
分類：SNMP（預設埠 161/UDP）
說明：模擬 `snmpwalk` 慣用的 GetNextRequest 循序走訪模式，但以受控高頻率
     連續對一組常見 MIB 子樹起始 OID 送出 GetNext（依序輪替 oid_list 中的
     OID，而非追蹤真正回應的下一個 OID），測試 SNMP Agent 對連續走訪查詢的
     負載能力——很多嵌入式設備的 Agent 在收到大量 GetNext 時 CPU 占用會明顯
     上升，是常見的可用性測試面向。

實作：重用同目錄 `_ber.py` 既有的低階 BER 編碼函式（encode_integer /
     encode_octetstring / encode_null / encode_oid / encode_sequence），
     在本模組內組出 GetNextRequest-PDU（context tag 0xA1），不修改 _ber.py。
需求：無額外套件，純標準函式庫。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration
from ._ber import (
    encode_integer,
    encode_null,
    encode_octetstring,
    encode_oid,
    encode_sequence,
)

NAME = "SNMP GetNext 快速走訪洪水（Walk-style）"
CATEGORY = "SNMP"
PROTOCOL = "UDP"
DEFAULT_PORT = 161
TEST_TYPE = "traffic"  # 流量型：高頻率 GetNext 查詢洪水，靠封包速率本身造成 Agent 負擔

_DEFAULT_OID_LIST = "1.3.6.1.2.1.1,1.3.6.1.2.1.2.2,1.3.6.1.2.1.4"


def _build_getnext(community: str, oid: str, request_id: int, version: int = 0) -> bytes:
    """組出 GetNextRequest-PDU（tag 0xA1）。version=0 為 SNMPv1，1 為 SNMPv2c。"""
    varbind = encode_sequence(encode_oid(oid) + encode_null())
    varbind_list = encode_sequence(varbind)
    pdu_body = (
        encode_integer(request_id)
        + encode_integer(0)  # error-status
        + encode_integer(0)  # error-index
        + varbind_list
    )
    pdu = encode_sequence(pdu_body, tag=0xA1)
    msg_body = encode_integer(version) + encode_octetstring(community.encode()) + pdu
    return encode_sequence(msg_body)


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 300000, "min": 1, "max": 300000, "desc": "每秒 GetNext 查詢次數"},
        "community": {"type": "string", "default": "public", "desc": "SNMP community string"},
        "oid_list": {
            "type": "string", "default": _DEFAULT_OID_LIST,
            "desc": "以逗號分隔的起始 OID 清單，會依序輪替送出 GetNext",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 350))
    community = params.get("community", "public")
    oid_list = [o.strip() for o in str(params.get("oid_list", _DEFAULT_OID_LIST)).split(",") if o.strip()]
    if not oid_list:
        oid_list = _DEFAULT_OID_LIST.split(",")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)

    limiter = RateLimiter(rate)
    sent, recv, errors = 0, 0, 0
    request_id = 1
    idx = 0
    start = time.time()

    log_fn(f"[+] SNMP GetNext 走訪洪水 -> {target}:{port} @ {rate}/s，OID 清單共 {len(oid_list)} 個")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        oid = oid_list[idx % len(oid_list)]
        idx += 1
        pkt = _build_getnext(community, oid, request_id)
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
