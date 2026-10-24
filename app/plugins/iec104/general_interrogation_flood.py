"""
測項：IEC 60870-5-104 General Interrogation (C_IC_NA_1) 應用層洪水
分類：IEC 60870-5-104（預設埠 2404）
說明：既有的 iec104/testfr_flood.py 雖然也是送 IEC104 標準訊框，但 TESTFR 屬於
     U-format 的連線層/心跳控制訊框，尚未進到 ASDU 應用層資料交換。本測項改為
     組出完整的 I-format APDU，內含 ASDU Type ID = 100（0x64, C_IC_NA_1，
     「總召喚命令」/General Interrogation），這是 SCADA 主站對 RTU/閘道器最常見
     的例行輪詢命令之一（要求對方回報目前所有資料點的最新狀態），屬於標準、
     非破壞性的「讀取/輪詢」類命令，而非任何 C_SC_NA_1/C_DC_NA_1/C_SE_* 等
     實際下達控制指令（單點/雙點命令、設定值）的寫入型操作——完全比照平台安全
     規則第 4 點的範圍限制。本測項用意是測 Controlled Station 對「高頻率總召喚
     請求」的應用層處理能力（例如是否會因為每次總召喚都要重新輪詢/打包大量資料
     點而造成 CPU 負載飆高、回應延遲，這是很多老舊 RTU/閘道器實務上已知的弱點）。

APDU 格式（欄位配置已比對 IEC 60870-5-104 公開規格與業界慣用的封包
     擷取範例，信心度高；U-format 控制欄位的 bit 配置並與本專案既有、已在正式
     環境使用的 iec104/testfr_flood.py 之 TESTFR act 位元組 `43 00 00 00` 互相
     驗證一致（本模組用同一套 bit 配置算式推出 STARTDT act = `07 00 00 00`，
     兩者都是「bits0-1=11b 表示 U-format，其餘某一 bit 對應特定功能」的同一種
     編碼規則，只是功能 bit 不同）：
       - APCI：START(0x68, 1 byte) + APDU長度(1 byte) + 控制欄位(4 bytes)
       - I-format 控制欄位：
           octet1 = (送方序號 send_seq & 0x7F) << 1   # bit0=0 表示 I-format
           octet2 = (send_seq >> 7) & 0xFF
           octet3 = (收方序號 recv_seq & 0x7F) << 1   # bit0 固定 0
           octet4 = (recv_seq >> 7) & 0xFF
       - ASDU（本測項固定內容）：
           Type ID          = 0x64 (100, C_IC_NA_1)
           可變結構限定詞 VSQ = 0x01（SQ=0，單一資訊物件）
           傳輸原因 COT       = 0x06, 0x00（6=Activation 主動啟動；不設 Test 位元；
                                原發地址 ORG 固定 0，未使用）
           ASDU共通地址 CA    = 2 bytes，little-endian，可設定（見 common_address 參數）
           資訊物件地址 IOA   = 0x00, 0x00, 0x00（C_IC_NA_1 規格規定 IOA 固定為 0，不使用）
           召喚限定詞 QOI     = 0x14（20 = station interrogation，全站總召喚）

STARTDT 交握：真實連線需先送 STARTDT act（U-format）並進入「資料傳輸狀態」後，
     Controlled Station 才會受理 I-format 的 ASDU。本測項會送出 STARTDT act 後，
     在 startdt_wait_sec 時限內嘗試讀取/比對 STARTDT confirm（`68 04 0B 00 00 00`），
     若時限內收到就記錄已確認進入資料傳輸狀態；若逾時或收到的內容不是預期格式，
     也不會中止測試，而是照規格假設已進入資料傳輸狀態並直接開始送 I-frame——
     這是刻意的簡化設計：短暫等待 STARTDT confirm 後即視為連線就緒並繼續，
     而非無限期等待，以避免單一連線卡住整個高速 flood 流程。

序號（send/receive sequence）處理的設計限制（重要）：
     完整合規的 IEC104 實作必須做雙向序號流量控制（例如追蹤對方已確認到第幾個
     I-frame、未確認訊框數不可超過 k window、逾時要送 S-format 等），這需要
     完整、可靠地重組/解析對方傳來的每一個 APDU。本測項為避免在高速 flood 迴圈
     中對「不可靠的 TCP 資料流重組」寫出隱藏 bug（例如一次 recv() 可能包含
     0、1 或多個 APDU，也可能只包含半個 APDU），刻意採用簡化、低風險的策略：
       1. 主迴圈每次送出前，用非阻塞 recv() 嘗試讀一次目前可讀的資料，若讀到的
          「前 6 bytes」剛好符合 I-format 表頭，就把其中的送方序號（對方觀點）
          取出、+1 後作為我方下次要回填的 recv_seq——這是 best-effort 的近似
          做法，不保證涵蓋每一個對方送來的 I-frame（尤其資料被 TCP 分片時），
          僅用來讓我方送出的 recv_seq 大致上是合理遞增、而非恆為 0 的無意義值。
       2. 為了避免序號長時間累積漂移、或未確認訊框數超過對方的 k window 導致
          對方認定違反流量控制而関閉連線後，我方序號與對方認知不同步，這裡改用
          「送出 reconnect_after_frames 個 I-frame 後，主動斷線並重新走一次
          STARTDT 交握、序號歸零重來」的方式定期重置雙方狀態——這是在無法保證
          序號追蹤完全正確的前提下，以定期斷線重連換取穩定性的設計取捨。
       3. 若目標主動關閉連線（recv() 收到空字串）或送出時發生連線層錯誤，也會
          觸發同一套重連邏輯，不會讓單次連線問題中斷整個測試。
     此設計未於本開發環境對真實 IEC104 outstation/RTU 做過端到端驗證（環境內
     無可連線的真實裝置），正式使用前建議先對測試用 outstation（如 lib60870、
     OpenMUC j60870 模擬器或實際 RTU 測試環境）驗證封包確實被接受。
需求：無額外套件（純標準函式庫 socket + struct），與本分類既有的 testfr_flood.py
     風格一致。
"""
import socket
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "IEC104 General Interrogation (總召喚) 應用層洪水"
CATEGORY = "IEC 60870-5-104"
PROTOCOL = "TCP"
DEFAULT_PORT = 2404
TEST_TYPE = "traffic"  # 流量型：以受控速率持續送出合法的總召喚 ASDU，靠應用層處理負擔造成壓力

_STARTDT_ACT = 0x07
_STARTDT_CON = 0x0B
_STARTDT_CON_FRAME = bytes([0x68, 0x04, _STARTDT_CON, 0x00, 0x00, 0x00])

_TYPE_ID_C_IC_NA_1 = 0x64  # 100
_VSQ_SINGLE = 0x01
_COT_ACTIVATION = 0x06
_QOI_STATION_GLOBAL = 0x14  # 20


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {
            "type": "int", "default": 200000, "min": 1, "max": 200000,
            "desc": "每秒送出的 General Interrogation 應用層訊框數",
        },
        "common_address": {
            "type": "int", "default": 1, "min": 0, "max": 65535,
            "desc": "ASDU 共同位址（Common Address，2 bytes）。預設 1 為一般常見的單一"
                    "站址設定；若要測試裝置對全域廣播位址 65535（0xFFFF）的回應行為可自行"
                    "調整，但預設採用具體位址而非廣播更貼近真實 SCADA 主站的例行輪詢行為",
        },
        "reconnect_after_frames": {
            "type": "int", "default": 200, "min": 10, "max": 5000,
            "desc": "每送出多少個 I-frame 後主動斷線、重新走 STARTDT 交握並歸零序號"
                    "（避免長時間 flood 下序號/未確認訊框數與對方認知漂移不同步，"
                    "詳見模組 docstring 的限制說明）",
        },
        "startdt_wait_sec": {
            "type": "float", "default": 1.0, "min": 0.2, "max": 5.0,
            "desc": "每次（重）連線後，等待 STARTDT confirm 回應的時限秒數；逾時或格式"
                    "不符也不中止，會直接假設已進入資料傳輸狀態並繼續",
        },
    }


def _build_u_frame(function_byte: int) -> bytes:
    return bytes([0x68, 0x04, function_byte, 0x00, 0x00, 0x00])


def _build_gi_activation(send_seq: int, recv_seq: int, common_address: int) -> bytes:
    ctrl = bytes([
        (send_seq & 0x7F) << 1,
        (send_seq >> 7) & 0xFF,
        (recv_seq & 0x7F) << 1,
        (recv_seq >> 7) & 0xFF,
    ])
    cot = bytes([_COT_ACTIVATION, 0x00])  # COT=6(Activation)，Test=0，ORG(原發地址)固定0
    ca = struct.pack("<H", common_address & 0xFFFF)  # little-endian，符合 IEC104 慣例
    ioa = bytes([0x00, 0x00, 0x00])  # C_IC_NA_1 的 IOA 規格固定為 0，不使用
    asdu = bytes([_TYPE_ID_C_IC_NA_1, _VSQ_SINGLE]) + cot + ca + ioa + bytes([_QOI_STATION_GLOBAL])
    body = ctrl + asdu
    return bytes([0x68, len(body)]) + body


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 400))
    common_address = int(params.get("common_address", 1))
    reconnect_after = int(params.get("reconnect_after_frames", 200))
    startdt_wait = float(params.get("startdt_wait_sec", 1.0))

    state = {"sock": None, "send_seq": 0, "recv_seq": 0, "frames_this_session": 0}

    def _connect_and_startdt():
        old = state.get("sock")
        if old is not None:
            try:
                old.close()
            except OSError:
                pass
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((target, port))
        s.sendall(_build_u_frame(_STARTDT_ACT))
        s.settimeout(startdt_wait)
        try:
            resp = s.recv(64)
            if resp[:6] == _STARTDT_CON_FRAME:
                log_fn("[+] 已收到 STARTDT confirm，連線進入資料傳輸狀態")
            else:
                log_fn("[i] STARTDT 回應內容非預期格式，仍假設已進入資料傳輸狀態並繼續")
        except socket.timeout:
            log_fn("[i] 未於時限內收到 STARTDT confirm，仍假設已進入資料傳輸狀態並繼續")
        except OSError as e:
            log_fn(f"[i] 讀取 STARTDT confirm 時發生錯誤（{e}），仍假設已進入資料傳輸狀態並繼續")
        s.setblocking(False)  # 之後主迴圈用非阻塞方式 best-effort 讀取，不拖慢送出速率
        state["sock"] = s
        state["send_seq"] = 0
        state["recv_seq"] = 0
        state["frames_this_session"] = 0

    try:
        _connect_and_startdt()
    except OSError as e:
        log_fn(f"[!] 無法連線 {target}:{port}: {e}")
        return {"frames_sent": 0, "errors": 1, "error": str(e)}

    limiter = RateLimiter(rate)
    sent, errors, reconnects, transient_skips = 0, 0, 0, 0
    error_logged = 0
    start = time.time()

    log_fn(
        f"[+] 開始送出 IEC104 General Interrogation (C_IC_NA_1) @ {rate}/s "
        f"-> {target}:{port}, CA={common_address}, 每 {reconnect_after} 個訊框重連一次序號"
    )

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        sock = state["sock"]

        # best-effort 讀取對方送來的 I-frame，更新我方下次要回填的 recv_seq
        # （不保證涵蓋每一筆，詳見模組 docstring 的限制說明）；若對方已關閉連線
        # （recv 回傳空字串）則視為連線層錯誤，走下面統一的重連邏輯。
        peer_closed = False
        try:
            data = sock.recv(256)
            if data == b"":
                peer_closed = True
            elif data and len(data) >= 6 and data[0] == 0x68 and (data[2] & 0x01) == 0:
                peer_send_seq = (data[3] << 7) | (data[2] >> 1)
                state["recv_seq"] = (peer_send_seq + 1) % 32768
        except (BlockingIOError, socket.timeout):
            pass
        except OSError:
            peer_closed = True

        if peer_closed:
            errors += 1
            if error_logged < 5:
                error_logged += 1
                log_fn("[!] 連線已被對方關閉，嘗試重新連線")
            try:
                _connect_and_startdt()
                reconnects += 1
            except OSError as e:
                log_fn(f"[!] 重新連線失敗，中止測試：{e}")
                break
            continue

        frame = _build_gi_activation(state["send_seq"], state["recv_seq"], common_address)
        try:
            sock.sendall(frame)
        except BlockingIOError:
            # 傳送緩衝區暫時滿了，不視為連線錯誤，跳過這一輪、下一輪再試
            transient_skips += 1
            continue
        except OSError as e:
            errors += 1
            if error_logged < 5:
                error_logged += 1
                log_fn(f"[!] send error: {e}")
            try:
                _connect_and_startdt()
                reconnects += 1
            except OSError as e2:
                log_fn(f"[!] 重新連線失敗，中止測試：{e2}")
                break
            continue

        sent += 1
        state["send_seq"] = (state["send_seq"] + 1) % 32768
        state["frames_this_session"] += 1

        if state["frames_this_session"] >= reconnect_after:
            try:
                _connect_and_startdt()
                reconnects += 1
            except OSError as e:
                log_fn(f"[!] 定期重連失敗，中止測試：{e}")
                break

    try:
        if state["sock"] is not None:
            state["sock"].close()
    except OSError:
        pass

    elapsed = time.time() - start
    log_fn(
        f"[+] 完成，送出 {sent} 個 General Interrogation 訊框，錯誤 {errors} 次，"
        f"重連 {reconnects} 次，暫時跳過 {transient_skips} 次"
    )
    return {
        "frames_sent": sent,
        "errors": errors,
        "reconnects": reconnects,
        "transient_skips": transient_skips,
        "elapsed_sec": round(elapsed, 1),
    }
