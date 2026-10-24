"""
app/registry.py — 測項庫註冊表（對應設計文件 5.5 節）

每個項目對應 app/plugins/ 底下一個模組，模組需提供：
    NAME / CATEGORY / PROTOCOL / DEFAULT_PORT(可選)
    get_param_schema() -> dict
    run(target, port, protocol, duration, params, stop_event, log_fn) -> dict

分類依通訊協定（一般 / HTTP-Web / Modbus TCP / ... / IEC 61850(GOOSE)），
不限定協定的放在「一般」。要擴充新測項/協定，照同樣合約寫一個模組、
在下面 TEST_ITEMS 註冊一筆即可，其他程式碼都不用改。
"""
import importlib
from functools import lru_cache

TEST_ITEMS = [
    # ---- 一般（不限通訊協定）----
    {"module": "app.plugins.generic.tcp_syn_flood", "category": "一般"},
    {"module": "app.plugins.generic.tcp_conn_flood", "category": "一般"},
    {"module": "app.plugins.generic.udp_flood", "category": "一般"},

    # ---- HTTP / Web ----
    {"module": "app.plugins.http.http_get_flood", "category": "HTTP/Web"},
    {"module": "app.plugins.http.slow_header", "category": "HTTP/Web"},
    {"module": "app.plugins.http.slow_read", "category": "HTTP/Web"},
    {"module": "app.plugins.http.slowloris_tool", "category": "HTTP/Web"},
    {"module": "app.plugins.http.http_post_flood", "category": "HTTP/Web"},

    # ---- Modbus TCP（流量型）----
    {"module": "app.plugins.modbus.syn_flood", "category": "Modbus TCP"},
    {"module": "app.plugins.modbus.conn_pool_exhaustion", "category": "Modbus TCP"},
    {"module": "app.plugins.modbus.fc03_high_freq_read", "category": "Modbus TCP"},
    {"module": "app.plugins.modbus.fc16_write_flood", "category": "Modbus TCP"},
    {"module": "app.plugins.modbus.fc01_fc02_coil_read_flood", "category": "Modbus TCP"},
    {"module": "app.plugins.modbus.fc05_fc15_coil_write_flood", "category": "Modbus TCP"},
    {"module": "app.plugins.modbus.broadcast_unit0_flood", "category": "Modbus TCP"},
    {"module": "app.plugins.modbus.malformed_pdu_boundary_test", "category": "Modbus TCP"},

    # ---- Modbus TCP（資源消耗型：讀改寫鎖競爭／裝置識別組字串／未讀回應佇列／半送出連線）----
    {"module": "app.plugins.modbus.fc22_mask_write_flood", "category": "Modbus TCP"},
    {"module": "app.plugins.modbus.fc43_device_id_flood", "category": "Modbus TCP"},
    {"module": "app.plugins.modbus.pipeline_queue_exhaustion", "category": "Modbus TCP"},
    {"module": "app.plugins.modbus.slow_mbap_header_exhaustion", "category": "Modbus TCP"},

    # ---- EtherNet/IP (CIP) ----
    {"module": "app.plugins.ethernetip_io.udp_flood", "category": "EtherNet/IP (CIP)"},
    {"module": "app.plugins.cip.session_exhaustion", "category": "EtherNet/IP (CIP)"},
    {"module": "app.plugins.cip.forward_open_close_churn", "category": "EtherNet/IP (CIP)"},
    {"module": "app.plugins.cip.list_identity_flood", "category": "EtherNet/IP (CIP)"},
    {"module": "app.plugins.cip.ucmm_unconnected_flood", "category": "EtherNet/IP (CIP)"},

    # ---- OPC UA ----
    {"module": "app.plugins.opcua.syn_flood", "category": "OPC UA"},
    {"module": "app.plugins.opcua.hello_flood", "category": "OPC UA"},
    {"module": "app.plugins.opcua.getendpoints_flood", "category": "OPC UA"},
    {"module": "app.plugins.opcua.create_session_churn", "category": "OPC UA"},
    {"module": "app.plugins.opcua.subscription_churn", "category": "OPC UA"},

    # ---- Siemens S7 ----
    {"module": "app.plugins.s7.syn_flood", "category": "Siemens S7"},
    {"module": "app.plugins.s7.conn_pool_exhaustion", "category": "Siemens S7"},
    {"module": "app.plugins.s7.setup_communication_exhaustion", "category": "Siemens S7"},
    {"module": "app.plugins.s7.setup_communication_churn", "category": "Siemens S7"},

    # ---- EtherCAT ----
    {"module": "app.plugins.ethercat.l2_frame_flood", "category": "EtherCAT"},
    {"module": "app.plugins.ethercat.broadcast_read_flood", "category": "EtherCAT"},
    {"module": "app.plugins.ethercat.malformed_length_boundary_test", "category": "EtherCAT"},
    {"module": "app.plugins.ethercat.al_state_forcing", "category": "EtherCAT"},

    # ---- PROFINET ----
    {"module": "app.plugins.profinet.dcp_flood", "category": "PROFINET"},
    {"module": "app.plugins.profinet.rt_cyclic_flood", "category": "PROFINET"},
    {"module": "app.plugins.profinet.cm_connect_churn", "category": "PROFINET"},
    {"module": "app.plugins.profinet.alarm_flood", "category": "PROFINET"},

    # ---- DNP3 ----
    {"module": "app.plugins.dnp3.syn_flood", "category": "DNP3"},
    {"module": "app.plugins.dnp3.conn_pool_exhaustion", "category": "DNP3"},
    {"module": "app.plugins.dnp3.link_status_flood", "category": "DNP3"},
    {"module": "app.plugins.dnp3.read_flood", "category": "DNP3"},

    # ---- IEC 60870-5-104 ----
    {"module": "app.plugins.iec104.syn_flood", "category": "IEC 60870-5-104"},
    {"module": "app.plugins.iec104.conn_pool_exhaustion", "category": "IEC 60870-5-104"},
    {"module": "app.plugins.iec104.testfr_flood", "category": "IEC 60870-5-104"},
    {"module": "app.plugins.iec104.general_interrogation_flood", "category": "IEC 60870-5-104"},

    # ---- BACnet ----
    {"module": "app.plugins.bacnet.udp_flood", "category": "BACnet"},
    {"module": "app.plugins.bacnet.whois_flood", "category": "BACnet"},
    {"module": "app.plugins.bacnet.cov_subscription_flood", "category": "BACnet"},
    {"module": "app.plugins.bacnet.foreign_device_registration_flood", "category": "BACnet"},

    # ---- MQTT ----
    {"module": "app.plugins.mqtt.connect_flood", "category": "MQTT"},
    {"module": "app.plugins.mqtt.publish_flood", "category": "MQTT"},

    # ---- SNMP ----
    {"module": "app.plugins.snmp.getbulk_flood", "category": "SNMP"},
    {"module": "app.plugins.snmp.getnext_walk_flood", "category": "SNMP"},
    {"module": "app.plugins.snmp.v1_get_flood", "category": "SNMP"},

    # ---- IEC 61850 GOOSE ----
    {"module": "app.plugins.iec61850_goose.goose_flood", "category": "IEC 61850 (GOOSE)"},

    # ---- FTP ----
    {"module": "app.plugins.ftp.conn_churn_flood", "category": "FTP"},
    {"module": "app.plugins.ftp.pasv_data_churn", "category": "FTP"},

    # ---- SSH ----
    {"module": "app.plugins.ssh.banner_flood", "category": "SSH"},
    {"module": "app.plugins.ssh.conn_pool_exhaustion", "category": "SSH"},

    # ---- RDP ----
    {"module": "app.plugins.rdp.x224_conn_flood", "category": "RDP"},
    {"module": "app.plugins.rdp.conn_pool_exhaustion", "category": "RDP"},

    # ---- RPC ----
    {"module": "app.plugins.rpc.epm_bind_flood", "category": "RPC"},
    {"module": "app.plugins.rpc.conn_churn_flood", "category": "RPC"},

    # ---- 網路層 (ARP/ICMP/IGMP/LLDP) ----
    {"module": "app.plugins.netlayer.arp_request_flood", "category": "網路層 (ARP/ICMP/IGMP/LLDP)"},
    {"module": "app.plugins.netlayer.icmp_echo_flood", "category": "網路層 (ARP/ICMP/IGMP/LLDP)"},
    {"module": "app.plugins.netlayer.igmp_flood", "category": "網路層 (ARP/ICMP/IGMP/LLDP)"},
    {"module": "app.plugins.netlayer.lldp_frame_flood", "category": "網路層 (ARP/ICMP/IGMP/LLDP)"},
    {"module": "app.plugins.netlayer.bpdu_stp_flood", "category": "網路層 (ARP/ICMP/IGMP/LLDP)"},

    # ==== 以下為新增：IoT / 工控補強測項 ====

    # ---- CoAP (物聯網) ----
    {"module": "app.plugins.coap.get_flood", "category": "CoAP (物聯網)"},

    # ---- UPnP/SSDP (物聯網) ----
    {"module": "app.plugins.upnp.ssdp_msearch_flood", "category": "UPnP/SSDP (物聯網)"},

    # ---- mDNS (物聯網服務發現) ----
    {"module": "app.plugins.mdns.query_flood", "category": "mDNS (物聯網服務發現)"},

    # ---- RTSP/ONVIF (IP攝影機) ----
    {"module": "app.plugins.rtsp.request_churn", "category": "RTSP/ONVIF (IP攝影機)"},

    # ---- Telnet ----
    {"module": "app.plugins.telnet.conn_churn_flood", "category": "Telnet"},

    # ---- TFTP (韌體更新) ----
    {"module": "app.plugins.tftp.rrq_flood", "category": "TFTP (韌體更新)"},

    # ---- LoRaWAN Gateway Bridge ----
    {"module": "app.plugins.lorawan.push_data_flood", "category": "LoRaWAN Gateway Bridge"},

    # ---- 一般（新增：WebSocket）----
    {"module": "app.plugins.generic.websocket_conn_churn", "category": "一般"},

    # ---- IEC 61850 (MMS) ----
    {"module": "app.plugins.iec61850_mms.conn_churn", "category": "IEC 61850 (MMS)"},

    # ---- 工控閘道器 (Gateway) ----
    {"module": "app.plugins.gateway.niagara_fox_conn_churn", "category": "工控閘道器 (Gateway)"},
    {"module": "app.plugins.gateway.modbus_rtu_over_tcp_flood", "category": "工控閘道器 (Gateway)"},
    {"module": "app.plugins.gateway.profibus_gateway_conn_churn", "category": "工控閘道器 (Gateway)"},

    # ---- BACnet（新增：ReadProperty）----
    {"module": "app.plugins.bacnet.read_property_flood", "category": "BACnet"},

    # ==== 工控協定補強（FINS/KNX 新分類 + 既有分類應用層測項）====

    # ---- FINS (Omron PLC) ----
    {"module": "app.plugins.fins.memory_area_read_flood", "category": "FINS (Omron PLC)"},
    {"module": "app.plugins.fins.tcp_conn_exhaustion", "category": "FINS (Omron PLC)"},

    # ---- KNX/IP (建築自動化) ----
    {"module": "app.plugins.knx.search_request_flood", "category": "KNX/IP (建築自動化)"},
    {"module": "app.plugins.knx.tunnel_connect_exhaustion", "category": "KNX/IP (建築自動化)"},

    # ---- DNS ----
    {"module": "app.plugins.dns.query_flood", "category": "DNS"},

    # ---- NTP ----
    {"module": "app.plugins.ntp.query_flood", "category": "NTP"},

    # ---- Redis ----
    {"module": "app.plugins.redis.command_flood", "category": "Redis"},

    # ---- SMB/CIFS ----
    {"module": "app.plugins.smb.session_conn_churn", "category": "SMB/CIFS"},

    # ---- VNC ----
    {"module": "app.plugins.vnc.conn_churn", "category": "VNC"},
]


# 攻擊手法類型（人看得懂的中文標籤 + icon，給前端/報告顯示用）。分類邏輯見各 plugin 檔頭
# 的 TEST_TYPE 屬性：traffic=流量型／resource=資源占用型。
# 分為兩類，只需要能一眼分辨「這是不是靠流量/頻寬硬打」跟「這是不是針對伺服器端有限
# 資源做針對性消耗」：連線池飽和、畸形封包/邊界值測試本質上都是消耗被測端某種有限
# 資源（連線槽、解析器狀態、鎖等），統一歸入「資源占用型」。
TEST_TYPE_LABELS = {
    "traffic": {"label": "流量型", "icon": "🌊", "desc": "靠封包速率/頻寬本身造成負擔的洪水攻擊"},
    "resource": {"label": "資源占用型", "icon": "🧠",
                 "desc": "針對伺服器端有限資源（連線池/記憶體/鎖/佇列/逾時計時器/解析器狀態）做針對性消耗，"
                         "包含連線建立-關閉循環、畸形封包與邊界值測試"},
}

# 「高並發加速版」引擎（見 app/plugins/common.py
# 的 run_concurrent_workers() 完整設計說明）的顯示中繼資料，以及「使用者尚未手動
# 指定偏好時，系統依 TEST_TYPE 建議的預設引擎」。
#
# 為什麼「流量型」預設建議 concurrent、「資源占用型」預設維持 native：
#   - 流量型測項普遍是單一 Python 迴圈驅動（RateLimiter + scapy/socket），單一
#     執行緒實際能送達的速率通常明顯低於 schema 宣告的可調上限（CPython 逐包
#     物件建構/呼叫開銷），高並發版能讓實際送達速率更接近已核准的上限，效果
#     提升「有感」且風險可控（見 common.py 的加總不變量說明）。
#   - 資源占用型測項（連線池飽和、session 循環等）多半已經在單一 run() 內部自己
#     用「分批 spawn 執行緒」的方式達到高併發（例如 tcp_conn_flood.py 一次就能
#     嘗試建立上萬條連線），真正的瓶頸通常是「目標裝置本身能接受的連線數上限」
#     而不是「攻擊端能不能發起更多請求」，再疊加一層高並發引擎邊際效益有限、
#     卻會讓攻擊端同時活動的執行緒數再往上疊，因此預設維持標準版；使用者仍可在
#     測項管理頁針對個別資源占用型測項手動切換為高並發版。
DEFAULT_ENGINE_MODE_BY_TEST_TYPE = {"traffic": "concurrent", "resource": "native"}

ENGINE_MODE_LABELS = {
    "native": {"label": "標準版", "desc": "單一執行緒的既有實作行為"},
    "concurrent": {"label": "高並發加速版",
                   "desc": "多執行緒平行執行同一測項，讓實際送達速率更接近已核准的上限（總負載不變，見 common.py 說明）"},
}


@lru_cache
def load_registry() -> list[dict]:
    items = []
    for entry in TEST_ITEMS:
        mod = importlib.import_module(entry["module"])
        test_type = getattr(mod, "TEST_TYPE", "traffic")
        items.append({
            "module": entry["module"],
            "name": getattr(mod, "NAME", entry["module"]),
            "category": getattr(mod, "CATEGORY", entry["category"]),
            "protocol": getattr(mod, "PROTOCOL", "TCP"),
            "default_port": getattr(mod, "DEFAULT_PORT", None),
            "test_type": test_type,
            "test_type_label": TEST_TYPE_LABELS.get(test_type, TEST_TYPE_LABELS["traffic"])["label"],
            "test_type_icon": TEST_TYPE_LABELS.get(test_type, TEST_TYPE_LABELS["traffic"])["icon"],
            "param_schema": mod.get_param_schema(),
        })
    return items


def load_registry_with_config(db) -> list[dict]:
    """在 load_registry() 的基礎上疊加 TestItemConfig（測項管理／
    健康檢查）的覆寫層——enabled、health_status/health_detail/checked_at，以及
    custom_name/custom_params_json（若使用者有自訂命名/預設參數）。

    沒有對應 TestItemConfig 紀錄的測項（例如全新安裝、尚未跑過健康檢查一次）一律
    視為 enabled=True、health_status="unknown"，維持「預設可用」（真正的『預設不
    使用』只在健康檢查『跑過且失敗』時才會發生，見 plugin_healthcheck.py），
    避免使用者還沒來得及跑健康檢查就發現所有測項都被停用而困惑。
    """
    from . import models  # 延遲匯入避免 models.py <-> registry.py 循環匯入

    items = load_registry()
    cfg_by_module = {c.module: c for c in db.query(models.TestItemConfig).all()}
    merged = []
    for item in items:
        cfg = cfg_by_module.get(item["module"])
        out = dict(item)
        if cfg is not None:
            out["enabled"] = cfg.enabled
            out["health_status"] = cfg.health_status
            out["health_detail"] = cfg.health_detail
            out["checked_at"] = cfg.checked_at.isoformat() if cfg.checked_at else None
            if cfg.custom_name:
                out["display_name"] = cfg.custom_name
            else:
                out["display_name"] = out["name"]
            if cfg.custom_params_json:
                # 覆寫值只疊加「有出現在使用者自訂裡的欄位」的 default，其餘 param_schema
                # 結構（min/max/desc/type）一律以 plugin 模組本身為準，避免使用者自訂值
                # 格式錯誤時把整個參數表弄壞。
                merged_schema = {k: dict(v) for k, v in out["param_schema"].items()}
                for pname, pval in cfg.custom_params_json.items():
                    if pname in merged_schema:
                        merged_schema[pname]["default"] = pval
                out["param_schema"] = merged_schema
            out["engine_mode"] = cfg.engine_mode or DEFAULT_ENGINE_MODE_BY_TEST_TYPE.get(out["test_type"], "native")
            out["engine_mode_is_default"] = cfg.engine_mode is None
            out["engine_workers"] = cfg.engine_workers  # None = 沿用 common.py 系統預設值
        else:
            out["enabled"] = True
            out["health_status"] = "unknown"
            out["health_detail"] = ""
            out["checked_at"] = None
            out["display_name"] = out["name"]
            out["engine_mode"] = DEFAULT_ENGINE_MODE_BY_TEST_TYPE.get(out["test_type"], "native")
            out["engine_mode_is_default"] = True
            out["engine_workers"] = None
        out["engine_mode_label"] = ENGINE_MODE_LABELS.get(out["engine_mode"], {}).get("label", out["engine_mode"])
        merged.append(out)
    return merged


def get_effective_engine(module_path: str, db) -> tuple[str, int | None]:
    """給 Orchestrator 執行測項前查詢「這個測項目前該用哪個引擎」。
    回傳 (engine_mode, engine_workers)——engine_workers 為 None 時代表沿用
    app/plugins/common.py 的 CONCURRENT_ENGINE_WORKERS 系統預設值。"""
    from . import models

    mod = get_module(module_path)
    test_type = getattr(mod, "TEST_TYPE", "traffic")
    cfg = db.query(models.TestItemConfig).filter_by(module=module_path).one_or_none()
    if cfg is None or cfg.engine_mode is None:
        return DEFAULT_ENGINE_MODE_BY_TEST_TYPE.get(test_type, "native"), (cfg.engine_workers if cfg else None)
    return cfg.engine_mode, cfg.engine_workers


def is_enabled(module_path: str, db) -> tuple[bool, str]:
    """給 API 層（新增測項到佇列）與 Orchestrator 執行前防呆共用的閘門檢查。
    回傳 (是否可用, 若不可用的原因說明)。沒有 TestItemConfig 紀錄視為可用
    （尚未跑過健康檢查，不應阻擋使用者使用）。"""
    from . import models

    cfg = db.query(models.TestItemConfig).filter_by(module=module_path).one_or_none()
    if cfg is None:
        return True, ""
    if not cfg.enabled:
        reason = "此測項目前已在「測項管理」頁面被停用"
        if cfg.health_status == "error" and cfg.health_detail:
            reason += f"（健康檢查偵測到異常：{cfg.health_detail}）"
        return False, reason
    return True, ""


def get_module(module_path: str):
    if module_path not in {e["module"] for e in TEST_ITEMS}:
        raise ValueError(f"未註冊的測項模組：{module_path}")
    return importlib.import_module(module_path)


def validate_params_against_schema(schema: dict, params: dict) -> str:
    """參數如果超出區間，應該要有資訊讓使用者知道，同時不能存檔——
    前端（測試佇列表單／編輯／測項管理預設參數）已經擋一次，但這裡是
    後端硬檢查，不能只靠前端（呼應本檔案其他地方、duration 也是前後端都夾一次的作法）。
    schema 是 plugin 的 get_param_schema() 回傳值；params 是使用者送進來的實際參數字典。
    只檢查 schema 裡有定義 min/max 的 int/float 欄位；params 裡沒出現的 key 不檢查
    （允許只覆寫部分參數，其餘沿用 schema 預設值）。
    回傳空字串代表全部合法；否則回傳可直接顯示給使用者看的錯誤訊息（可能包含多個欄位）。
    """
    if not isinstance(params, dict):
        return "參數必須是物件（key/value）"
    problems = []
    for key, spec in (schema or {}).items():
        if spec.get("type") not in ("int", "float"):
            continue
        if key not in params:
            continue
        value = params[key]
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            problems.append(f"「{key}」不是合法數字（目前值：{value!r}）")
            continue
        lo = spec.get("min")
        hi = spec.get("max")
        if lo is not None and value < lo:
            problems.append(f"「{key}」目前輸入 {value}，低於允許下限 {lo}（允許範圍 {lo} ~ {hi}）")
        elif hi is not None and value > hi:
            problems.append(f"「{key}」目前輸入 {value}，超出允許上限 {hi}（允許範圍 {lo} ~ {hi}）")
    return "；".join(problems)
