"""
測項：UPnP/SSDP M-SEARCH 探索請求洪水
分類：UPnP/SSDP (物聯網)（標準埠 1900/UDP）
說明：SSDP（Simple Service Discovery Protocol）是 UPnP 裝置探索機制的基礎，
     幾乎所有消費性/工業 IoT 裝置（路由器、NAS、IP Camera、智慧插座等）只要支援
     UPnP 都會監聽 1900/UDP 並回應 M-SEARCH 探索請求。這也是實務上知名的
     UDP 反射放大攻擊面之一（SSDP amplification），因此是常見的壓力測試/
     健壯性測試項目。

封包內容：標準 UPnP/SSDP M-SEARCH 請求（純文字，依 UPnP Device Architecture
規範格式），非自訂內容：
    M-SEARCH * HTTP/1.1\\r\\n
    HOST: <target>:1900\\r\\n
    MAN: "ssdp:discover"\\r\\n
    MX: <mx>\\r\\n
    ST: <search_target>\\r\\n
    \\r\\n

安全設計（重要）：
  - 本測項一律以「單點 unicast」直接送往 Orchestrator 傳入的 target（不送往
    239.255.255.250 群播位址），避免對同網段其他非受測裝置造成無關的放大流量；
    多數 UPnP 裝置堆疊即使收到 unicast M-SEARCH 仍會依協定回應，足以達到壓力
    測試效果。
  - 不偽造來源位址（沒有 IP spoofing），因此不構成放大攻擊的反射面。
  - 速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。
需求：無額外套件，純標準函式庫。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "UPnP/SSDP M-SEARCH 探索請求洪水"
CATEGORY = "UPnP/SSDP (物聯網)"
PROTOCOL = "UDP"
DEFAULT_PORT = 1900
TEST_TYPE = "traffic"  # M-SEARCH 請求速率造成負擔的洪水攻擊

_DEFAULT_ST_LIST = "ssdp:all,upnp:rootdevice,urn:schemas-upnp-org:device:InternetGatewayDevice:1"


def _build_msearch(target: str, port: int, st: str, mx: int) -> bytes:
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {target}:{port}\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: {mx}\r\n"
        f"ST: {st}\r\n"
        "\r\n"
    )
    return msg.encode("ascii")


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 300000, "min": 1, "max": 300000, "desc": "每秒送出請求數"},
        "mx_sec": {"type": "int", "default": 1, "min": 1, "max": 5, "desc": "MX 欄位（要求裝置隨機延遲 0~MX 秒後回應，值愈小回應愈集中）"},
        "st_list": {"type": "string", "default": _DEFAULT_ST_LIST, "desc": "以逗號分隔、輪替使用的 ST（Search Target）清單"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 300))
    mx = int(params.get("mx_sec", 1))
    st_list = [s.strip() for s in str(params.get("st_list", _DEFAULT_ST_LIST)).split(",") if s.strip()]
    if not st_list:
        st_list = _DEFAULT_ST_LIST.split(",")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)

    limiter = RateLimiter(rate)
    sent, recv, errors = 0, 0, 0
    idx = 0
    start = time.time()

    log_fn(f"[+] SSDP M-SEARCH 洪水 -> {target}:{port} @ {rate}/s，ST 輪替 {len(st_list)} 個")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        st = st_list[idx % len(st_list)]
        idx += 1
        pkt = _build_msearch(target, port, st, mx)
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
    return {"requests_sent": sent, "responses_received": recv, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
