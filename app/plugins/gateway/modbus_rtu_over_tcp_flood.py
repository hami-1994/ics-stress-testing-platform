"""
測項：Modbus RTU-over-TCP 閘道器高頻率讀取洪水
分類：工控閘道器 (Gateway)（常見埠因廠牌而異，例如 MOXA NPort 系列 Raw/TCP
     Server 模式常用 4001，部分裝置沿用 502，可於建立測項時自行改埠）
說明：許多序列轉乙太網路閘道器（serial-to-Ethernet converter，例如 MOXA
     NPort、Advantech EKI 系列）在設定為「TCP Server / Raw 模式」時，是把
     RS-485/RS-232 上的「原始 Modbus RTU 位元組序列（含 CRC16）」直接透傳到
     TCP，「沒有」標準 Modbus TCP 的 MBAP header（transaction id/protocol id/
     length/unit id）封裝——這與同專案 modbus/fc03_high_freq_read.py（走標準
     Modbus TCP + pymodbus）是不同的線路格式，因此獨立成一個測項，測試閘道器
     對「RTU 訊框透傳 + CRC 驗證」路徑的高頻處理能力，這也是許多老舊工控環境
     常見的實際部署方式（PLC 本身只懂 RTU，靠閘道器接上乙太網路）。

實作：手刻標準 Modbus RTU 訊框（Function Code 03, Read Holding Registers）：
    Unit-ID(1) + FC(1)=0x03 + StartAddr(2, big-endian) + Quantity(2, big-endian)
    + CRC16(2, little-endian，多項式 0xA001，Modbus 標準演算法，公開規範）
  直接以 TCP socket 送出這段 RTU 位元組序列（無 MBAP header），並嘗試讀取
  閘道器透傳回來的 RTU 回應（同樣含 CRC16）。

安全設計：只做「讀取」功能碼（FC03），不送出任何寫入指令；不偽造來源位址；
速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。

重要限制：不同閘道器廠牌的「Raw 模式」埠號、逾時斷線行為差異
很大，且需要閘道器背後確實接了會回應該 Unit-ID 的 RTU 從站才會有 DATA 回應
（沒接則通常會逾時無回應，屬正常現象、不代表測試失敗）；正式使用前建議先用
Wireshark 確認閘道器實際使用的埠與訊框格式。
需求：無額外套件，純標準函式庫。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "Modbus RTU-over-TCP 閘道器高頻率讀取洪水"
CATEGORY = "工控閘道器 (Gateway)"
PROTOCOL = "TCP"
DEFAULT_PORT = 4001
TEST_TYPE = "traffic"  # 流量型：單一連線上高頻率讀取請求洪水，靠請求速率本身造成負擔


def _crc16_modbus(data: bytes) -> bytes:
    """Modbus CRC16，多項式 0xA001（標準 Modbus 規範，公開演算法）。"""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])  # little-endian


def _build_rtu_read_holding(unit_id: int, addr: int, count: int) -> bytes:
    body = bytes([unit_id, 0x03]) + addr.to_bytes(2, "big") + count.to_bytes(2, "big")
    return body + _crc16_modbus(body)


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 200000, "min": 1, "max": 200000, "desc": "每秒送出讀取請求數"},
        "unit_id": {"type": "int", "default": 1, "min": 0, "max": 247, "desc": "RTU Slave ID"},
        "register_addr": {"type": "int", "default": 0, "min": 0, "max": 65535, "desc": "起始暫存器位址"},
        "register_count": {"type": "int", "default": 10, "min": 1, "max": 125, "desc": "一次讀取數量"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 200))
    unit_id = int(params.get("unit_id", 1))
    addr = int(params.get("register_addr", 0))
    count = int(params.get("register_count", 10))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((target, port))
    except OSError as e:
        log_fn(f"[!] 無法連線 {target}:{port}: {e}")
        return {"sent": 0, "error": str(e)}

    frame = _build_rtu_read_holding(unit_id, addr, count)
    limiter = RateLimiter(rate)
    sent, recv, errors = 0, 0, 0
    start = time.time()

    log_fn(f"[+] Modbus RTU-over-TCP 讀取洪水 -> {target}:{port} @ {rate}/s，unit_id={unit_id}")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        try:
            sock.sendall(frame)
            sent += 1
            try:
                sock.settimeout(0.2)
                resp = sock.recv(256)
                if resp:
                    recv += 1
            except socket.timeout:
                pass
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")
            break

    sock.close()
    return {"requests_sent": sent, "responses_received": recv, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
