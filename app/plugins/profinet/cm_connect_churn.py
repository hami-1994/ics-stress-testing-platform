"""
測項：PROFINET CM (Context Manager) Connect 請求快速循環
分類：PROFINET（UDP 34964，PROFINET CM/RPC 服務埠）
說明：真實 PROFINET 的 AR（Application Relation）建立，是由 IO-Controller 透過
DCE/RPC-over-UDP（RPC Endpoint 埠 34964）送出 Connect.req，內含 ARBlockReq /
IOCRBlockReq / ExpectedSubmoduleBlockReq 等一連串巢狀 Block 才能完成，欄位/區塊
結構複雜，且需要與目標裝置的實際模組組態相符才能真正建立連線。

限制說明：目前 Python 生態圈沒有現成、可直接拿來組出完整合規 Connect.req
的函式庫（scapy 沒有內建完整的 PROFINET CM/RPC layer）。本測項僅依 PROFINET/
DCE-RPC 公開規格「盡力」組出一個簡化版 RPC-over-UDP 標頭（Object/Interface/
Activity UUID 以全零或序號占位，OperationNumber 固定為 Connect），並未包含真正
合法的 AR/IOCR Block 內容，因此對真實裝置而言幾乎必然會被判定為格式錯誤並回覆
RPC Fault 或直接忽略——這是預期且可接受的結果。此測項的目的不是「成功建立 AR」，
而是測試 IO-Device 的 RPC 服務端點對「大量、快速、格式相似但不完整」的 Connect
請求的輸入驗證健全性與資源回收行為（例如是否會因為每次收到請求就配置暫存的連線
追蹤資源，快速重複送出造成資源緩慢增長）。如需嚴謹、可實際建立 AR 的 CM 層測試，
建議改用廠商工具（如 Siemens PRONETA/TIA）或專用 PROFINET 測試儀。
需求：無額外套件（純標準函式庫 socket + struct）。
"""
import socket
import struct
import time

from ..common import RateLimiter, clamp_duration

NAME = "PROFINET CM Connect 請求快速循環"
CATEGORY = "PROFINET"
PROTOCOL = "UDP"
DEFAULT_PORT = 34964
TEST_TYPE = "resource"  # 連線型：Connect 請求快速循環，測 RPC 端點連線追蹤資源回收行為


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 80000, "min": 1, "max": 80000, "desc": "每秒送出 Connect 請求數"},
    }


def _build_connect_req(seq: int) -> bytes:
    """組一個簡化版 RPC-over-UDP 標頭，OperationNumber=0 對應 Connect。
    ObjectUUID/InterfaceUUID 以全零占位，ActivityUUID 前 4 bytes 帶入序號方便追蹤，
    不含真正的 ARBlockReq 等 Block 內容，詳見模組 docstring 的限制說明。"""
    version = 4
    packet_type = 0  # 0 = Request
    flags1 = 0
    flags2 = 0
    data_rep = b"\x00\x00\x00"
    serial_high = 0
    object_uuid = b"\x00" * 16
    interface_uuid = b"\x00" * 16
    activity_uuid = struct.pack(">I", seq & 0xFFFFFFFF) + b"\x00" * 12
    server_boot_time = 0
    interface_version = 1
    sequence_number = seq & 0xFFFFFFFF
    operation_number = 0  # 0 = Connect
    interface_hint = 0xFFFF
    activity_hint = 0xFFFF
    body_length = 0  # 不附加任何 Block 內容
    fragment_number = 0
    auth_proto = 0
    serial_low = 0

    header = (
        struct.pack(">BBBB", version, packet_type, flags1, flags2)
        + data_rep
        + struct.pack(">B", serial_high)
        + object_uuid
        + interface_uuid
        + activity_uuid
        + struct.pack(">III", server_boot_time, interface_version, sequence_number)
        + struct.pack(">HHHHH", operation_number, interface_hint, activity_hint, body_length, fragment_number)
        + struct.pack(">BB", auth_proto, serial_low)
    )
    return header


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 150))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    limiter = RateLimiter(rate)
    sent, responses, errors = 0, 0, 0
    seq = 0
    start = time.time()

    log_fn(f"[+] PROFINET CM Connect 請求快速循環 -> {target}:{port} @ {rate}/s, {duration}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        seq += 1
        pkt = _build_connect_req(seq)
        try:
            sock.sendto(pkt, (target, port))
            sent += 1
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")
        try:
            sock.recvfrom(512)
            responses += 1
        except BlockingIOError:
            pass
        except OSError:
            pass

    sock.close()
    elapsed = time.time() - start
    log_fn(f"[+] 完成，送出 {sent} 個 Connect 請求，收到回應/Fault {responses} 次，錯誤 {errors} 次")
    return {"requests_sent": sent, "responses": responses, "errors": errors, "elapsed_sec": round(elapsed, 1)}
