"""
測項：BACnet ReadProperty 高頻率讀取洪水
分類：BACnet（標準埠 47808/UDP）
說明：與同分類既有的 whois_flood.py（廣播探索）、udp_flood.py（通用 UDP 流量）
     互補：Who-Is 測的是「探索/廣播」負載，本測項測的是「對已知裝置實例做
     ReadProperty 讀值」這種正常運作情境下最頻繁出現的服務類型，更貼近實際
     BMS（Building Management System）對 BACnet 裝置高頻輪詢的負載型態。

實作：手刻 BACnet/IP Unicast 封包（BVLC + NPDU + APDU），依 ASHRAE 135
（BACnet）標準格式組出 Confirmed-Request 的 ReadProperty 服務：
    BVLC: Original-Unicast-NPDU（0x81 0x0A + 總長度 2 bytes）
    NPDU: Version=0x01, Control=0x04（無路由，期望回應）
    APDU: Confirmed-Request(0x00) + max-segs/max-apdu(0x05) + Invoke-ID
          + Service-Choice=0x0C(readProperty)
          + Object-Identifier（context tag 0，4 bytes：object-type<<22|instance）
          + Property-Identifier（context tag 1）

安全設計：只使用「讀取」服務（ReadProperty），不送出任何 WriteProperty 等
會變更裝置狀態的服務；一律 unicast 送往 Orchestrator 傳入的單一 target，不做
群播；速率透過 RateLimiter 控制；duration 經 clamp_duration() 限制。

重要限制：ReadProperty 必須
指定「真實存在」的裝置實例編號（device_instance）與物件，若填錯（例如受測
裝置實際的 Device Instance 不是預設值）會收到 Error-PDU 或完全無回應——這
是正常現象、不代表測試失敗，請先用本分類的 Who-Is/I-Am 測項或 BACnet 掃描
工具找出受測裝置實際的 Device Instance 後再填入。封包位元組格式雖依標準
規範組出，但未在真實 BACnet 裝置上做過相容性驗證，正式使用前建議先用
Wireshark（內建 BACnet 解析器）確認。
需求：無額外套件，純標準函式庫。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "BACnet ReadProperty 高頻率讀取洪水"
CATEGORY = "BACnet"
PROTOCOL = "UDP"
DEFAULT_PORT = 47808
TEST_TYPE = "traffic"  # 流量型：ReadProperty 高頻率讀取請求洪水，靠請求速率本身造成負擔

_OBJECT_TYPE_DEVICE = 8
_PROP_OBJECT_NAME = 77


def _encode_object_id(obj_type: int, instance: int) -> bytes:
    val = ((obj_type & 0x3FF) << 22) | (instance & 0x3FFFFF)
    return bytes([0x0C]) + val.to_bytes(4, "big")


def _encode_property_id(prop_id: int) -> bytes:
    if prop_id < 256:
        return bytes([0x19, prop_id])
    return bytes([0x1A]) + prop_id.to_bytes(2, "big")


def _build_read_property(invoke_id: int, obj_type: int, instance: int, prop_id: int) -> bytes:
    apdu = (
        bytes([0x00, 0x05, invoke_id & 0xFF, 0x0C])  # Confirmed-Request, max-segs/apdu, invoke-id, service=readProperty
        + _encode_object_id(obj_type, instance)
        + _encode_property_id(prop_id)
    )
    npdu = bytes([0x01, 0x04])  # version=1, control（無路由，期望回應）
    body = npdu + apdu
    total_len = 4 + len(body)
    bvlc = bytes([0x81, 0x0A]) + total_len.to_bytes(2, "big")
    return bvlc + body


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 100000, "min": 1, "max": 100000, "desc": "每秒送出讀取請求數"},
        "device_instance": {"type": "int", "default": 1, "min": 0, "max": 4194303, "desc": "受測裝置的 Device Instance（請填實際值，可先用 Who-Is 測項探索）"},
        "object_type": {"type": "int", "default": 8, "min": 0, "max": 1023, "desc": "物件類型（預設 8=Device 物件）"},
        "property_id": {"type": "int", "default": 77, "min": 0, "max": 4194303, "desc": "屬性 ID（預設 77=Object_Name，Device 物件必定支援）"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 150))
    instance = int(params.get("device_instance", 1))
    obj_type = int(params.get("object_type", _OBJECT_TYPE_DEVICE))
    prop_id = int(params.get("property_id", _PROP_OBJECT_NAME))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)

    limiter = RateLimiter(rate)
    sent, recv, errors = 0, 0, 0
    invoke_id = 0
    start = time.time()

    log_fn(f"[+] BACnet ReadProperty 洪水 -> {target}:{port} @ {rate}/s，device_instance={instance}")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        invoke_id = (invoke_id + 1) & 0xFF
        pkt = _build_read_property(invoke_id, obj_type, instance, prop_id)
        try:
            sock.sendto(pkt, (target, port))
            sent += 1
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
