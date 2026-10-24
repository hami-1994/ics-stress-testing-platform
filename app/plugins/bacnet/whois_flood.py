"""
測項：BACnet Who-Is 廣播風暴
分類：BACnet（樓宇自動化，UDP 47808）
說明：Who-Is 是 BACnet 標準定義的裝置探索廣播（每台 BACnet 裝置開機時都可能送出/回應），
     以高頻率重複廣播，測試同網段內裝置對探索廣播的處理負荷、以及是否會被大量觸發
     Unicast I-Am 回應造成廣播風暴放大效果。

封包內容：固定的 BACnet/IP Who-Is 廣播封包位元組序列（BVLC Original-Broadcast-NPDU +
NPDU + Unconfirmed-Request Who-Is APDU），此為 BACnet 標準規範中公開定義的標準封包格式，
非自訂/偽造內容：
    81 0B 00 0C 01 20 FF FF 00 FF 10 08

重要限制：這裡送出的是「不指定範圍」的 Who-Is（探詢所有裝置），會讓網段內每台
BACnet 裝置都回應，測試前務必確認是在受測、已授權的隔離網段執行，避免影響其他
生產中的樓宇自動化系統。
需求：無額外套件，純標準函式庫（原生 UDP broadcast socket）。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "BACnet Who-Is 廣播風暴"
CATEGORY = "BACnet"
PROTOCOL = "UDP"
DEFAULT_PORT = 47808
TEST_TYPE = "traffic"  # 流量型：Who-Is 探索廣播洪水，靠封包速率本身造成負擔

_WHOIS_PACKET = bytes.fromhex("81 0B 00 0C 01 20 FF FF 00 FF 10 08".replace(" ", ""))


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 90000, "min": 1, "max": 90000, "desc": "每秒廣播次數"},
        "broadcast_addr": {"type": "string", "default": "255.255.255.255", "desc": "廣播位址（建議填受測網段的 directed broadcast，例如 192.168.1.255）"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 250))
    bcast_addr = params.get("broadcast_addr", "255.255.255.255")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    limiter = RateLimiter(rate)
    sent, errors = 0, 0
    start = time.time()

    log_fn(f"[+] BACnet Who-Is 廣播 -> {bcast_addr}:{port} @ {rate}/s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            sock.sendto(_WHOIS_PACKET, (bcast_addr, port))
            sent += 1
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")
    sock.close()

    return {"broadcasts_sent": sent, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
