"""
測項：SNMPv1 GetRequest 高頻率洪水（community/OID 輪替）
分類：SNMP（預設埠 161/UDP）
說明：以受控速率重複送出 SNMPv1 GetRequest，並在一組可設定的 community
     string 與 OID 之間輪替，測試 SNMP Agent 對「內容多變」查詢流量的
     解析負載（每個 community string 都要重新做字串比對、每個 OID 都要
     重新查表），比固定單一 community/OID 的洪水更貼近真實網路中混合
     多台 NMS/掃描工具查詢的情境。

重要澄清：
  - community_list 的用途是「產生內容多變的查詢流量」以貼近真實負載情境，
    不是設計來對外部系統做未授權存取嘗試——本測項的 target 本來就必須是
    已完成授權確認、屬於受測團隊自身的裝置（由 Orchestrator 保證，見
    common.py 說明），因此這裡的 community 清單並非「破解」用途。
  - 預設清單僅含教學/測試常見的 "public"／"private" 兩個示例值，使用者可
    自行替換為受測裝置實際設定的 community string，用於單純的效能負載
    測試，而非取得非授權存取。
需求：無額外套件，純標準函式庫，重用 `_ber.py` 既有的 build_snmp_get_request()。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration
from ._ber import build_snmp_get_request

NAME = "SNMPv1 GetRequest 高頻率洪水（community/OID 輪替）"
CATEGORY = "SNMP"
PROTOCOL = "UDP"
DEFAULT_PORT = 161
TEST_TYPE = "traffic"  # 流量型：高頻率 GetRequest 查詢洪水，靠封包速率本身造成 Agent 負擔

_DEFAULT_COMMUNITIES = "public,private"
_DEFAULT_OIDS = "1.3.6.1.2.1.1.1.0,1.3.6.1.2.1.1.3.0,1.3.6.1.2.1.1.5.0"


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 300000, "min": 1, "max": 300000, "desc": "每秒查詢次數"},
        "community_list": {
            "type": "string", "default": _DEFAULT_COMMUNITIES,
            "desc": "以逗號分隔、輪替使用的 community string 清單（建議填受測裝置實際設定值）",
        },
        "oid_list": {
            "type": "string", "default": _DEFAULT_OIDS,
            "desc": "以逗號分隔、輪替查詢的 OID 清單",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 350))
    communities = [c.strip() for c in str(params.get("community_list", _DEFAULT_COMMUNITIES)).split(",") if c.strip()]
    oids = [o.strip() for o in str(params.get("oid_list", _DEFAULT_OIDS)).split(",") if o.strip()]
    if not communities:
        communities = _DEFAULT_COMMUNITIES.split(",")
    if not oids:
        oids = _DEFAULT_OIDS.split(",")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)

    limiter = RateLimiter(rate)
    sent, recv, errors = 0, 0, 0
    request_id = 1
    idx = 0
    start = time.time()

    log_fn(
        f"[+] SNMPv1 GetRequest 洪水 -> {target}:{port} @ {rate}/s，"
        f"community 輪替 {len(communities)} 個、OID 輪替 {len(oids)} 個"
    )
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        community = communities[idx % len(communities)]
        oid = oids[idx % len(oids)]
        idx += 1
        pkt = build_snmp_get_request(community, oid, request_id)
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
