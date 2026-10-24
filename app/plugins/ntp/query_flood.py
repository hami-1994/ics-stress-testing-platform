"""
測項：NTP Client 查詢請求洪水
分類：NTP（標準埠 123/UDP）
說明：NTP 查詢洪水是通用壓力測試的常見手法之一，也是歷史上知名的 UDP 反射
     放大攻擊向量（NTP monlist 濫用），因此本測項刻意只使用「標準用戶端模式
     時間查詢」（NTP Client Mode Request），完全不使用歷史上被濫用的 MODE_PRIVATE
     （mode 7，含 monlist 指令）——不觸碰任何放大攻擊相關功能，單純測試 NTP
     服務本身對高頻標準查詢的處理能力。

實作：手刻最小合法 NTP 封包（RFC 5905 §7.3），48 bytes 標準長度：
    Byte0: LI(2 bit)=0, VN(3 bit)=4, Mode(3 bit)=3(client) => 0x23
    Byte1-47: 其餘欄位（Stratum/Poll/Precision/Root Delay/Dispersion/
              Reference ID/四組時間戳）皆填 0，讓 Server 自行依請求時間填寫
              回應（不需要用戶端預先計算任何時間戳即可觸發合法回應）。

安全設計（重要）：
  - 一律以本機真實來源位址直接送往 Orchestrator 傳入的單一 target，「不」做
    來源位址偽造（IP Spoofing），因此不構成放大攻擊的反射面——這與歷史上
    NTP amplification 攻擊「偽造受害者來源位址、將放大流量導向第三方」的
    手法本質不同，本測項單純是「對自己授權目標做標準查詢速率測試」。
  - 速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。
需求：無額外套件，純標準函式庫。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "NTP Client 查詢請求洪水"
CATEGORY = "NTP"
PROTOCOL = "UDP"
DEFAULT_PORT = 123
TEST_TYPE = "traffic"  # 流量型：高頻率查詢洪水，靠封包速率本身造成負擔

_NTP_CLIENT_PACKET = bytes([0x23]) + b"\x00" * 47  # LI=0,VN=4,Mode=3(client)，其餘欄位填零


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 500000, "min": 1, "max": 500000, "desc": "每秒送出查詢數"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 500))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)

    limiter = RateLimiter(rate)
    sent, recv, errors = 0, 0, 0
    start = time.time()

    log_fn(f"[+] NTP 查詢洪水 -> {target}:{port} @ {rate}/s（僅標準 client mode 查詢，不使用 monlist）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            sock.sendto(_NTP_CLIENT_PACKET, (target, port))
            sent += 1
            try:
                sock.recv(1024)
                recv += 1
            except socket.timeout:
                pass
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")

    sock.close()
    return {"queries_sent": sent, "responses_received": recv, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
