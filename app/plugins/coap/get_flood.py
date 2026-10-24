"""
測項：CoAP GET 請求洪水
分類：CoAP (物聯網)（預設埠 5683/UDP）
說明：CoAP（Constrained Application Protocol, RFC 7252）是物聯網/嵌入式裝置常用的
     輕量應用層協定，設計目標就是給資源受限裝置使用，因此其封包解析器往往也比
     較「輕量」、缺乏對高頻率請求的緩衝保護。本測項以受控速率重複送出合法的
     CoAP GET 請求（可設定訊息型態 CON/NON、URI 路徑），測試裝置的 CoAP stack
     對高頻請求的處理能力。

實作：純標準函式庫手刻 CoAP 封包（4-byte 固定 header + Token + Uri-Path 選項），
     不依賴 aiocoap 等第三方套件，格式依 RFC 7252 §3 標準規範組出：
       Byte0: Ver(2 bit)=01, Type(2 bit)=CON(00)/NON(01), TKL(4 bit)=token 長度
       Byte1: Code = 0x01 (GET)
       Byte2-3: Message ID（每則遞增亂數起點，避免與先前訊息混淆）
       Token: 隨機 token bytes
       Options: Uri-Path（選項編號 11），依 '/' 切分路徑逐段編碼
     Uri-Path 選項編碼僅實作 RFC 7252 §3.1 的「Option Delta/Length < 13」直接編碼與
     「13~268（1 byte 擴充）」兩種情形，足以涵蓋一般短路徑（例如
     /.well-known/core），未涵蓋極長路徑（>268 bytes）的多階擴充編碼。

安全設計：
  - CON（Confirmable）模式下會嘗試 recv 一次 ACK（短逾時，非必要，僅供統計），
    NON（Non-confirmable）模式則不等待回應，兩種都不會造成放大攻擊——本測項一律
    以本機真實來源位址直接送往單一 target，不做來源偽造，也不使用 CoAP 群播位址
    （224.0.1.187）做群播放大測試。
  - 速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。

重要限制：手刻的 CoAP 封包格式雖依公開 RFC 7252 規範實作，但未在
真實 CoAP 裝置上做過相容性驗證，正式使用前建議先用 Wireshark（內建 CoAP 解析器）
確認目標裝置有正確回應（4.xx/2.xx 等），如有落差請以實際封包截取結果為準調整。
需求：無額外套件，純標準函式庫。
"""
import os
import random
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "CoAP GET 請求洪水"
CATEGORY = "CoAP (物聯網)"
PROTOCOL = "UDP"
DEFAULT_PORT = 5683
TEST_TYPE = "traffic"  # GET 請求速率造成負擔的洪水攻擊


def _encode_uri_path_options(path: str) -> bytes:
    segments = [s for s in path.strip("/").split("/") if s]
    out = b""
    prev_num = 0
    option_num = 11  # Uri-Path
    for seg in segments:
        value = seg.encode("utf-8")[:255]
        delta = option_num - prev_num
        length = len(value)
        d_ext = b""
        l_ext = b""
        if delta < 13:
            d_nibble = delta
        elif delta < 269:
            d_nibble = 13
            d_ext = bytes([delta - 13])
        else:
            d_nibble = 14
            d_ext = (delta - 269).to_bytes(2, "big")
        if length < 13:
            l_nibble = length
        elif length < 269:
            l_nibble = 13
            l_ext = bytes([length - 13])
        else:
            l_nibble = 14
            l_ext = (length - 269).to_bytes(2, "big")
        out += bytes([(d_nibble << 4) | l_nibble]) + d_ext + l_ext + value
        prev_num = option_num
    return out


def _build_coap_get(msg_id: int, token: bytes, path: str, confirmable: bool) -> bytes:
    type_bits = 0x00 if confirmable else 0x10  # 00=CON, 01=NON
    header = bytes([0x40 | type_bits | len(token), 0x01]) + msg_id.to_bytes(2, "big") + token
    options = _encode_uri_path_options(path)
    return header + options


def get_param_schema() -> dict:
    return {
        "rate_pps": {"type": "int", "default": 1500000, "min": 1, "max": 1500000, "desc": "每秒送出請求數"},
        "path": {"type": "string", "default": "/.well-known/core", "desc": "CoAP 請求路徑（Uri-Path）"},
        "confirmable": {"type": "bool", "default": True, "desc": "True=CON（會嘗試等待 ACK 做統計）/ False=NON（不等待）"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_pps", 2500))
    path = params.get("path", "/.well-known/core")
    confirmable = bool(params.get("confirmable", True))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)

    limiter = RateLimiter(rate)
    sent, recv, errors = 0, 0, 0
    msg_id = random.randint(0, 0xFFFF)
    start = time.time()

    log_fn(f"[+] CoAP GET 洪水 -> {target}:{port} @ {rate}/s，path={path}，{'CON' if confirmable else 'NON'}")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        msg_id = (msg_id + 1) & 0xFFFF
        token = os.urandom(2)
        pkt = _build_coap_get(msg_id, token, path, confirmable)
        try:
            sock.sendto(pkt, (target, port))
            sent += 1
            if confirmable:
                try:
                    sock.recv(2048)
                    recv += 1
                except socket.timeout:
                    pass
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")

    sock.close()
    return {"requests_sent": sent, "responses_received": recv, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
