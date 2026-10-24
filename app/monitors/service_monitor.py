"""
服務可用性監控（協定層級探測）

與純 TCP connect 檢查的差異：
  TCP 檢查只驗證埠號是否開啟，即使服務已被攻擊癱瘓仍顯示 UP。
  本監控器實際執行協定交握，能偵測應用層阻斷攻擊效果。

支援 30 種協定探測：

  通用:
    tcp          純 TCP 連線檢查（通用 fallback）

  常見服務:
    http         HTTP GET 請求
    https        HTTPS (TLS + HTTP GET)
    ssh          SSH 版本 Banner 檢查
    ftp          FTP Banner 檢查 (220)
    telnet       Telnet 連線 / IAC 協商
    rdp          RDP X.224 Negotiation
    vnc          VNC (RFB) 版本 Banner
    redis        Redis PING/PONG
    dns          DNS 查詢 (UDP)
    ntp          NTP Client 查詢 (UDP)
    smb          SMB Negotiate Protocol

  工控協定 (ICS/SCADA):
    modbus       Modbus TCP FC03 Read Holding Registers
    cip-session  CIP RegisterSession (EtherNet/IP)
    cip-ucmm     CIP UCMM SendRRData
    enip-udp     EtherNet/IP ListIdentity (UDP)
    s7           Siemens S7comm COTP + Setup Communication
    opcua        OPC UA Hello/Acknowledge
    iec104       IEC 60870-5-104 STARTDT
    dnp3         DNP3 Link Status Request
    bacnet       BACnet/IP Who-Is (UDP)
    fins         FINS/TCP Node Address Handshake (Omron)
    knx          KNX/IP Search Request (UDP)

  IoT / 多媒體:
    mqtt         MQTT CONNECT/CONNACK
    rtsp         RTSP OPTIONS
    coap         CoAP Confirmable GET (UDP)
    snmp         SNMP GetRequest sysDescr (UDP)
    ssdp         SSDP M-SEARCH (UDP)
    mdns         mDNS 查詢 (UDP)
    tftp         TFTP RRQ 探測 (UDP)

根據 port 自動判斷協定（可透過 config 的 protocol 欄位覆蓋）。

三級判定：
  UP       — 協定交握完全成功，服務正常運作
  DEGRADED — 部分協定操作成功但完整功能受損
  DOWN     — 協定交握失敗，服務不可用
"""
import socket
import struct
import time

try:
    import ssl as _ssl
except ImportError:
    _ssl = None

# ═══════════════════════════════════════════════════════════════
# 模組介面（供平台 MonitorRunner 匯入使用）
# ═══════════════════════════════════════════════════════════════

TYPE = "service"
NAME = "服務可用性監控（協定層級）"

# ── 依埠號自動偵測協定 ──
PROTOCOL_BY_PORT = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    53:    "dns",
    69:    "tftp",
    80:    "http",
    102:   "s7",
    123:   "ntp",
    161:   "snmp",
    443:   "https",
    445:   "smb",
    502:   "modbus",
    554:   "rtsp",
    1883:  "mqtt",
    1900:  "ssdp",
    2404:  "iec104",
    3389:  "rdp",
    3671:  "knx",
    4840:  "opcua",
    5353:  "mdns",
    5683:  "coap",
    5900:  "vnc",
    6379:  "redis",
    9600:  "fins",
    20000: "dnp3",
    44818: "cip-session",
    47808: "bacnet",
}

PROTOCOL_LABELS = {
    "tcp":         "TCP Connect",
    "http":        "HTTP GET",
    "https":       "HTTPS (TLS + HTTP GET)",
    "ssh":         "SSH Banner",
    "ftp":         "FTP Banner (220)",
    "telnet":      "Telnet Banner / IAC",
    "rdp":         "RDP X.224 Negotiation",
    "vnc":         "VNC (RFB) Banner",
    "redis":       "Redis PING/PONG",
    "dns":         "DNS Query (UDP)",
    "ntp":         "NTP Client (UDP)",
    "smb":         "SMB Negotiate",
    "modbus":      "Modbus FC03",
    "cip-session": "CIP RegisterSession",
    "cip-ucmm":    "CIP UCMM (SendRRData)",
    "enip-udp":    "EtherNet/IP ListIdentity (UDP)",
    "s7":          "S7comm COTP + Setup",
    "opcua":       "OPC UA Hello",
    "iec104":      "IEC 104 STARTDT",
    "dnp3":        "DNP3 Link Status",
    "bacnet":      "BACnet/IP Who-Is (UDP)",
    "fins":        "FINS/TCP Handshake",
    "knx":         "KNX/IP Search (UDP)",
    "mqtt":        "MQTT CONNECT",
    "rtsp":        "RTSP OPTIONS",
    "coap":        "CoAP GET (UDP)",
    "snmp":        "SNMP GetRequest (UDP)",
    "ssdp":        "SSDP M-SEARCH (UDP)",
    "mdns":        "mDNS Query (UDP)",
    "tftp":        "TFTP RRQ (UDP)",
}


# ═══════════════════════════════════════════════════════════════
# 輔助函式
# ═══════════════════════════════════════════════════════════════

def _ms(t0):
    """回傳自 t0 起的毫秒數。"""
    return round((time.monotonic() - t0) * 1000, 1)


def _dnp3_crc(data: bytes) -> int:
    """DNP3 CRC-16 (reflected polynomial 0xA6BC)."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return crc ^ 0xFFFF


# ═══════════════════════════════════════════════════════════════
# 封包建構
# ═══════════════════════════════════════════════════════════════

# ── EtherNet/IP / CIP ──

def _build_register_session():
    ctx = b"PROBE\x00\x00\x00"
    hdr = struct.pack("<HHII8sI", 0x0065, 4, 0, 0, ctx, 0)
    return hdr + struct.pack("<HH", 1, 0)


def _build_unregister_session(session_handle):
    ctx = b"PROBE\x00\x00\x00"
    return struct.pack("<HHII8sI", 0x0066, 0, session_handle, 0, ctx, 0)


def _build_ucmm_request(session_handle):
    cip_service = 0x0E
    cip_path = bytes([0x20, 0x01, 0x24, 0x01])
    cip_data = struct.pack("<H", 0x01)
    cip_req = struct.pack("BB", cip_service, len(cip_path) // 2) + cip_path + cip_data
    cpf_null = struct.pack("<HH", 0x0000, 0x0000)
    cpf_data = struct.pack("<HH", 0x00B2, len(cip_req)) + cip_req
    cpf = struct.pack("<H", 2) + cpf_null + cpf_data
    srr_data = struct.pack("<IH", 0, 0) + cpf
    ctx = b"PROBE\x00\x00\x00"
    hdr = struct.pack("<HHII8sI", 0x006F, len(srr_data), session_handle, 0, ctx, 0)
    return hdr + srr_data


def _build_list_identity():
    ctx = b"PROBE\x00\x00\x00"
    return struct.pack("<HHII8sI", 0x0063, 0, 0, 0, ctx, 0)


# ── Modbus ──

def _build_modbus_read(txn_id=1, unit_id=1):
    pdu = struct.pack(">BHH", 0x03, 0x0000, 0x0001)
    mbap = struct.pack(">HHHB", txn_id, 0x0000, len(pdu) + 1, unit_id)
    return mbap + pdu


# ── S7comm ──

def _build_s7_cotp_cr():
    """TPKT + COTP Connection Request (S7-300 TSAP)."""
    return bytes([
        0x03, 0x00, 0x00, 0x16,              # TPKT header, length=22
        0x11,                                 # COTP length indicator (17)
        0xE0,                                 # CR (Connection Request)
        0x00, 0x00,                           # DST-REF
        0x00, 0x01,                           # SRC-REF
        0x00,                                 # Class 0
        0xC0, 0x01, 0x0A,                     # TPDU size = 1024
        0xC1, 0x02, 0x01, 0x00,               # Source TSAP
        0xC2, 0x02, 0x01, 0x02,               # Destination TSAP
    ])


def _build_s7_setup():
    """TPKT + COTP DT + S7 Setup Communication."""
    return bytes([
        0x03, 0x00, 0x00, 0x19,              # TPKT header, length=25
        0x02, 0xF0, 0x80,                     # COTP DT, last fragment
        0x32,                                 # S7 protocol ID
        0x01,                                 # Job (request)
        0x00, 0x00,                           # Redundancy identification
        0x00, 0x01,                           # PDU reference
        0x00, 0x08,                           # Parameter length = 8
        0x00, 0x00,                           # Data length = 0
        0xF0,                                 # Setup communication function
        0x00,                                 # Reserved
        0x00, 0x01,                           # Max AmQ calling
        0x00, 0x01,                           # Max AmQ called
        0x01, 0xE0,                           # PDU length = 480
    ])


# ── OPC UA ──

def _build_opcua_hello(target, port):
    """OPC UA Hello message."""
    endpoint = f"opc.tcp://{target}:{port}".encode("utf-8")
    body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0)
    body += struct.pack("<I", len(endpoint)) + endpoint
    msg_size = 8 + len(body)
    return b"HELF" + struct.pack("<I", msg_size) + body


# ── IEC 60870-5-104 ──

def _build_iec104_startdt():
    """IEC 104 STARTDT act (U-frame)."""
    return bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])


# ── DNP3 ──

def _build_dnp3_link_status(dst=1, src=3):
    """DNP3 Request Link States frame (FC=9)."""
    header_data = bytes([
        0x05,                                 # Length (5 = ctrl+dst+src)
        0xC9,                                 # Control: DIR=1, PRM=1, FC=9
    ]) + struct.pack("<HH", dst, src)
    crc = _dnp3_crc(header_data)
    return b"\x05\x64" + header_data + struct.pack("<H", crc)


# ── FINS/TCP ──

def _build_fins_tcp_hello():
    """FINS/TCP Node Address Data Send (connection handshake)."""
    return bytes([
        0x46, 0x49, 0x4E, 0x53,              # "FINS" magic
        0x00, 0x00, 0x00, 0x0C,              # Length = 12
        0x00, 0x00, 0x00, 0x00,              # Command: Node Addr Data Send
        0x00, 0x00, 0x00, 0x00,              # Error code: 0
        0x00, 0x00, 0x00, 0x00,              # Client node: auto-assign
    ])


# ── RDP ──

def _build_rdp_cr():
    """TPKT + X.224 Connection Request with RDP Negotiation."""
    return bytes([
        0x03, 0x00, 0x00, 0x13,              # TPKT header, length=19
        0x0E,                                 # X.224 length indicator
        0xE0,                                 # CR (Connection Request)
        0x00, 0x00,                           # DST-REF
        0x00, 0x00,                           # SRC-REF
        0x00,                                 # Class 0
        0x01,                                 # RDP Negotiation Request type
        0x00,                                 # Flags
        0x08, 0x00,                           # RDP Neg length = 8
        0x03, 0x00, 0x00, 0x00,              # Requested protocols (TLS | CredSSP)
    ])


# ── SMB ──

def _build_smb1_negotiate():
    """SMB1 Negotiate Protocol Request with NT LM 0.12 dialect."""
    smb = (
        b'\xff\x53\x4d\x42'                  # Protocol: \xFFSMB
        b'\x72'                               # Command: Negotiate
        b'\x00\x00\x00\x00'                  # Status
        b'\x18'                               # Flags
        b'\x53\xc8'                           # Flags2 (LE)
        b'\x00\x00'                           # PID High
        b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature
        b'\x00\x00'                           # Reserved
        b'\x00\x00'                           # Tree ID
        b'\xff\xfe'                           # Process ID
        b'\x00\x00'                           # User ID
        b'\x00\x00'                           # Multiplex ID
        b'\x00'                               # Word Count: 0
        b'\x0c\x00'                           # Byte Count: 12
        b'\x02NT LM 0.12\x00'                # Dialect
    )
    netbios = b'\x00' + struct.pack(">I", len(smb))[1:]
    return netbios + smb


# ── MQTT ──

def _build_mqtt_connect():
    """MQTT 3.1.1 CONNECT with clean session."""
    client_id = b"probe"
    var_header = (
        b'\x00\x04MQTT'                      # Protocol name
        b'\x04'                               # Protocol level (3.1.1)
        b'\x02'                               # Connect flags: Clean Session
        b'\x00\x3C'                           # Keep alive = 60s
    )
    payload = struct.pack(">H", len(client_id)) + client_id
    remaining = len(var_header) + len(payload)
    return bytes([0x10, remaining]) + var_header + payload


# ── SNMP ──

_SNMP_GET_SYSDESCR = bytes([
    0x30, 0x29,                                                     # SEQUENCE (41B)
    0x02, 0x01, 0x01,                                               # INTEGER: version=1 (v2c)
    0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,               # OCTET STRING: "public"
    0xA0, 0x1C,                                                     # GetRequest-PDU (28B)
    0x02, 0x04, 0x00, 0x00, 0x00, 0x01,                             # request-id=1
    0x02, 0x01, 0x00,                                               # error-status=0
    0x02, 0x01, 0x00,                                               # error-index=0
    0x30, 0x0E,                                                     # VarBindList (14B)
    0x30, 0x0C,                                                     # VarBind (12B)
    0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,   # OID: sysDescr.0
    0x05, 0x00,                                                     # NULL
])

# ── DNS ──

def _build_dns_query(txn_id=0x1234):
    """DNS A query for root domain (minimal probe)."""
    header = struct.pack(">HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)
    qname = b'\x00'                           # root "."
    return header + qname + struct.pack(">HH", 1, 1)  # A, IN


# ── NTP ──

_NTP_CLIENT = bytes([0x1B]) + b'\x00' * 47   # LI=0, VN=3, Mode=3 (client), 48B total

# ── BACnet ──

_BACNET_WHOIS = bytes([
    0x81, 0x0A, 0x00, 0x08,                  # BVLC: Original-Unicast, length=8
    0x01, 0x04,                               # NPDU: version=1, expecting reply
    0x10, 0x08,                               # APDU: Unconfirmed-Request, Who-Is
])

# ── CoAP ──

def _build_coap_get(msg_id=1):
    """CoAP Confirmable GET /.well-known/core."""
    header = bytes([0x40, 0x01]) + struct.pack(">H", msg_id)
    opt1 = bytes([0xBB]) + b'.well-known'     # Uri-Path, delta=11, len=11
    opt2 = bytes([0x04]) + b'core'            # Uri-Path, delta=0, len=4
    return header + opt1 + opt2


# ── KNX/IP ──

_KNX_SEARCH = bytes([
    0x06, 0x10,                               # Header size=6, protocol=0x10
    0x02, 0x01,                               # SEARCH_REQUEST
    0x00, 0x0E,                               # Total length=14
    0x08, 0x01,                               # HPAI: length=8, UDP
    0x00, 0x00, 0x00, 0x00,                   # IP=0.0.0.0
    0x00, 0x00,                               # Port=0
])

# ── mDNS ──

def _build_mdns_query():
    """mDNS query for _services._dns-sd._udp.local PTR."""
    header = struct.pack(">HHHHHH", 0, 0x0000, 1, 0, 0, 0)
    qname = b'\x09_services\x07_dns-sd\x04_udp\x05local\x00'
    return header + qname + struct.pack(">HH", 12, 1)  # PTR, IN


# ── TFTP ──

_TFTP_RRQ = struct.pack(">H", 1) + b"_probe_\x00octet\x00"


# ═══════════════════════════════════════════════════════════════
# 探測函式 — 每個回傳 (status, latency_ms, detail_str)
#   status:  "UP" / "DEGRADED" / "DOWN"
# ═══════════════════════════════════════════════════════════════

# ────────────────────────── 通用 TCP ──────────────────────────

def _probe_tcp(target, port, timeout):
    """純 TCP connect 探測（fallback）。"""
    t0 = time.monotonic()
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return "UP", _ms(t0), "TCP 連線成功"
    except socket.timeout:
        return "DOWN", _ms(t0), "連線逾時"
    except ConnectionRefusedError:
        return "DOWN", _ms(t0), "連線被拒 (TCP RST)"
    except OSError as e:
        return "DOWN", _ms(t0), str(e)


# ────────────────────────── TCP Banner ──────────────────────────

def _probe_ssh(target, port, timeout):
    """SSH Banner 探測。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        banner = sock.recv(256)
        elapsed = _ms(t0)
        if not banner:
            return "DOWN", elapsed, "空回應"
        text = banner.decode("utf-8", errors="replace").strip()
        if text.startswith("SSH-"):
            return "UP", elapsed, text[:64]
        return "DEGRADED", elapsed, f"非標準 Banner: {text[:48]}"
    except socket.timeout:
        return "DOWN", _ms(t0), "Banner 讀取逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_ftp(target, port, timeout):
    """FTP Banner 探測 (期待 220 回應)。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        banner = sock.recv(1024)
        elapsed = _ms(t0)
        if not banner:
            return "DOWN", elapsed, "空回應"
        text = banner.decode("utf-8", errors="replace").strip()
        if text.startswith("220"):
            return "UP", elapsed, text[:64]
        if text[:3].isdigit():
            return "DEGRADED", elapsed, f"FTP {text[:3]}: {text[4:48]}"
        return "DEGRADED", elapsed, f"非標準: {text[:48]}"
    except socket.timeout:
        return "DOWN", _ms(t0), "Banner 讀取逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_telnet(target, port, timeout):
    """Telnet Banner / IAC 協商探測。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        data = sock.recv(512)
        elapsed = _ms(t0)
        if not data:
            return "DOWN", elapsed, "空回應"
        if data[0] == 0xFF:  # IAC
            return "UP", elapsed, f"IAC 協商 ({len(data)}B)"
        text = data.decode("utf-8", errors="replace").strip()
        if text:
            return "UP", elapsed, f"Banner: {text[:48]}"
        return "UP", elapsed, f"回應 {len(data)}B"
    except socket.timeout:
        # Telnet 伺服器可能不主動發送 — TCP 連上即視為 UP
        return "UP", _ms(t0), "TCP 已連線 (伺服器未主動發送)"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_vnc(target, port, timeout):
    """VNC (RFB) Banner 探測。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        banner = sock.recv(256)
        elapsed = _ms(t0)
        if not banner:
            return "DOWN", elapsed, "空回應"
        text = banner.decode("utf-8", errors="replace").strip()
        if text.startswith("RFB"):
            return "UP", elapsed, text[:32]
        return "DEGRADED", elapsed, f"非標準: {text[:48]}"
    except socket.timeout:
        return "DOWN", _ms(t0), "Banner 讀取逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_redis(target, port, timeout):
    """Redis PING/PONG 探測。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"PING\r\n")
        resp = sock.recv(256)
        elapsed = _ms(t0)
        if not resp:
            return "DOWN", elapsed, "空回應"
        text = resp.decode("utf-8", errors="replace").strip()
        if text == "+PONG":
            return "UP", elapsed, "PONG"
        if text.startswith("-"):
            return "DEGRADED", elapsed, f"錯誤: {text[:48]}"
        return "UP", elapsed, text[:48]
    except socket.timeout:
        return "DOWN", _ms(t0), "回應逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ────────────────────────── HTTP / HTTPS ──────────────────────────

def _probe_http(target, port, timeout):
    """HTTP GET / 探測。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        req = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode("utf-8"))
        resp = sock.recv(2048)
        elapsed = _ms(t0)
        if not resp:
            return "DOWN", elapsed, "空回應"
        line = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        if line.startswith("HTTP/"):
            parts = line.split(" ", 2)
            code = int(parts[1]) if len(parts) > 1 else 0
            reason = parts[2] if len(parts) > 2 else ""
            if 200 <= code < 400:
                return "UP", elapsed, f"{code} {reason}"
            elif 500 <= code < 600:
                return "DEGRADED", elapsed, f"{code} {reason}"
            else:
                return "UP", elapsed, f"{code} {reason}"
        return "DEGRADED", elapsed, f"非 HTTP 回應: {line[:48]}"
    except socket.timeout:
        return "DOWN", _ms(t0), "回應逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_https(target, port, timeout):
    """HTTPS (TLS + HTTP GET) 探測。"""
    if _ssl is None:
        return _probe_tcp(target, port, timeout)
    t0 = time.monotonic()
    sock = None
    try:
        raw = socket.create_connection((target, port), timeout=timeout)
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        sock = ctx.wrap_socket(raw, server_hostname=target)
        sock.settimeout(timeout)
        req = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode("utf-8"))
        resp = sock.recv(2048)
        elapsed = _ms(t0)
        if not resp:
            return "DOWN", elapsed, "TLS 成功但無 HTTP 回應"
        line = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        if line.startswith("HTTP/"):
            parts = line.split(" ", 2)
            code = int(parts[1]) if len(parts) > 1 else 0
            reason = parts[2] if len(parts) > 2 else ""
            if 200 <= code < 400:
                return "UP", elapsed, f"TLS OK, {code} {reason}"
            elif 500 <= code < 600:
                return "DEGRADED", elapsed, f"TLS OK, {code} {reason}"
            else:
                return "UP", elapsed, f"TLS OK, {code} {reason}"
        return "DEGRADED", elapsed, f"TLS OK, 非 HTTP: {line[:40]}"
    except _ssl.SSLError as e:
        return "DOWN", _ms(t0), f"TLS 錯誤: {e}"
    except socket.timeout:
        return "DOWN", _ms(t0), "連線逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ────────────────────────── Remote Access ──────────────────────────

def _probe_rdp(target, port, timeout):
    """RDP X.224 Connection Request 探測。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(_build_rdp_cr())
        resp = sock.recv(256)
        elapsed = _ms(t0)
        if not resp:
            return "DOWN", elapsed, "空回應"
        if len(resp) < 7:
            return "DEGRADED", elapsed, f"回應過短 ({len(resp)}B)"
        # TPKT(4) + X.224 CC(0xD0) or Redirect(0x03)
        if resp[4] >= 2:
            pdu_type = resp[5]
            if pdu_type == 0xD0:
                return "UP", elapsed, "X.224 Connection Confirm"
            elif pdu_type == 0xE0:
                return "DEGRADED", elapsed, "X.224 Connection Request (echo)"
            else:
                return "UP", elapsed, f"X.224 回應 (PDU=0x{pdu_type:02X})"
        return "UP", elapsed, f"RDP 回應 ({len(resp)}B)"
    except socket.timeout:
        return "DOWN", _ms(t0), "回應逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_mqtt(target, port, timeout):
    """MQTT CONNECT/CONNACK 探測。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(_build_mqtt_connect())
        resp = sock.recv(256)
        elapsed = _ms(t0)
        if not resp:
            return "DOWN", elapsed, "空回應"
        if len(resp) < 4:
            return "DEGRADED", elapsed, f"回應過短 ({len(resp)}B)"
        pkt_type = (resp[0] >> 4) & 0x0F
        if pkt_type == 2:  # CONNACK
            rc = resp[3] if len(resp) > 3 else -1
            if rc == 0:
                return "UP", elapsed, "CONNACK accepted"
            rc_names = {
                1: "unacceptable protocol",
                2: "identifier rejected",
                3: "server unavailable",
                4: "bad credentials",
                5: "not authorized",
            }
            return "DEGRADED", elapsed, f"CONNACK rc={rc}: {rc_names.get(rc, 'unknown')}"
        return "DEGRADED", elapsed, f"非預期封包 (type={pkt_type})"
    except socket.timeout:
        return "DOWN", _ms(t0), "回應逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_rtsp(target, port, timeout):
    """RTSP OPTIONS 探測。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        req = f"OPTIONS rtsp://{target}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        sock.sendall(req.encode("utf-8"))
        resp = sock.recv(1024)
        elapsed = _ms(t0)
        if not resp:
            return "DOWN", elapsed, "空回應"
        line = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        if line.startswith("RTSP/"):
            parts = line.split(" ", 2)
            code = int(parts[1]) if len(parts) > 1 else 0
            return "UP", elapsed, f"RTSP {code}"
        return "DEGRADED", elapsed, f"非 RTSP: {line[:48]}"
    except socket.timeout:
        return "DOWN", _ms(t0), "回應逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_smb(target, port, timeout):
    """SMB Negotiate Protocol 探測。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(_build_smb1_negotiate())
        resp = sock.recv(1024)
        elapsed = _ms(t0)
        if not resp:
            return "DOWN", elapsed, "空回應"
        if len(resp) < 8:
            return "DEGRADED", elapsed, f"回應過短 ({len(resp)}B)"
        # NetBIOS(4) + SMB magic
        magic = resp[4:8]
        if magic == b'\xffSMB':
            return "UP", elapsed, "SMB1 Negotiate Response"
        elif magic == b'\xfeSMB':
            return "UP", elapsed, "SMB2 Negotiate Response"
        return "DEGRADED", elapsed, f"非 SMB magic: {magic.hex()}"
    except socket.timeout:
        return "DOWN", _ms(t0), "回應逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ────────────────────────── 工控 TCP ──────────────────────────

def _probe_cip_session(target, port, timeout):
    """CIP RegisterSession 探測。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        sock.sendall(_build_register_session())
        resp = sock.recv(28)
        elapsed = _ms(t0)
        if len(resp) < 24:
            return "DOWN", elapsed, f"回應不完整 ({len(resp)}B)"
        cmd, length, session_handle, status = struct.unpack_from("<HHII", resp, 0)
        if cmd != 0x0065:
            return "DOWN", elapsed, f"非預期命令 0x{cmd:04X}"
        if status != 0:
            return "DOWN", elapsed, f"RegisterSession 拒絕 (status=0x{status:08X})"
        if session_handle == 0:
            return "DOWN", elapsed, "Session Handle=0 (配額已滿)"
        detail = f"handle=0x{session_handle:08X}"
        try:
            sock.sendall(_build_unregister_session(session_handle))
            detail += " (已釋放)"
        except Exception:
            detail += " (釋放失敗)"
        return "UP", elapsed, detail
    except socket.timeout:
        return "DOWN", _ms(t0), "連線逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_cip_ucmm(target, port, timeout):
    """CIP UCMM (SendRRData) 探測。

    三級：UP=Register+UCMM 皆成功, DEGRADED=Register 成功但 UCMM 失敗, DOWN=Register 失敗。
    """
    t0 = time.monotonic()
    sock = None
    session_handle = 0
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        sock.sendall(_build_register_session())
        resp = sock.recv(28)
        if len(resp) < 24:
            return "DOWN", _ms(t0), f"RegisterSession 回應不完整 ({len(resp)}B)"
        cmd, length, session_handle, status = struct.unpack_from("<HHII", resp, 0)
        if status != 0 or session_handle == 0:
            return "DOWN", _ms(t0), \
                f"RegisterSession 失敗 (status=0x{status:08X}, handle=0x{session_handle:08X})"
        sock.sendall(_build_ucmm_request(session_handle))
        resp2 = sock.recv(512)
        elapsed = _ms(t0)
        if len(resp2) < 28:
            try:
                sock.sendall(_build_unregister_session(session_handle))
            except Exception:
                pass
            return "DEGRADED", elapsed, \
                f"UCMM 回應不完整 ({len(resp2)}B), handle=0x{session_handle:08X}"
        cmd2, _, _, status2 = struct.unpack_from("<HHII", resp2, 0)
        if cmd2 != 0x006F or status2 != 0:
            try:
                sock.sendall(_build_unregister_session(session_handle))
            except Exception:
                pass
            return "DEGRADED", elapsed, \
                f"UCMM 錯誤 (cmd=0x{cmd2:04X}, status=0x{status2:08X})"
        try:
            sock.sendall(_build_unregister_session(session_handle))
        except Exception:
            pass
        return "UP", elapsed, f"UCMM 正常, handle=0x{session_handle:08X} (已釋放)"
    except socket.timeout:
        if session_handle:
            return "DEGRADED", _ms(t0), f"UCMM 逾時, handle=0x{session_handle:08X}"
        return "DOWN", _ms(t0), "連線逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_modbus(target, port, timeout):
    """Modbus TCP FC03 探測。

    三級：UP=FC03 正常, DEGRADED=Modbus 例外 (0x83), DOWN=連線失敗。
    """
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        txn_id = int(time.time()) & 0xFFFF
        sock.sendall(_build_modbus_read(txn_id=txn_id))
        resp = sock.recv(256)
        elapsed = _ms(t0)
        if len(resp) < 9:
            if len(resp) == 0:
                return "DOWN", elapsed, "空回應 (連線可能被佔滿)"
            return "DOWN", elapsed, f"回應不完整 ({len(resp)}B)"
        fc = resp[7]
        if fc == 0x03:
            byte_count = resp[8] if len(resp) > 8 else 0
            detail = f"FC03 正常, {byte_count}B 資料"
            if len(resp) >= 11:
                reg_val = struct.unpack_from(">H", resp, 9)[0]
                detail += f", reg[0]=0x{reg_val:04X}"
            return "UP", elapsed, detail
        elif fc == 0x83:
            exc_code = resp[8] if len(resp) > 8 else 0
            exc_names = {1: "ILLEGAL_FUNCTION", 2: "ILLEGAL_DATA_ADDRESS",
                         3: "ILLEGAL_DATA_VALUE", 4: "SLAVE_DEVICE_FAILURE",
                         5: "ACKNOWLEDGE", 6: "SLAVE_DEVICE_BUSY"}
            return "DEGRADED", elapsed, \
                f"例外: {exc_names.get(exc_code, f'0x{exc_code:02X}')}"
        return "DEGRADED", elapsed, f"非預期 FC=0x{fc:02X}"
    except socket.timeout:
        return "DOWN", _ms(t0), "連線逾時 (TCP 已連線但無 Modbus 回應)"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_s7(target, port, timeout):
    """Siemens S7comm COTP + Setup Communication 探測。

    三級：UP=S7 Setup 成功, DEGRADED=COTP CC 成功但 S7 失敗, DOWN=COTP CR 失敗。
    """
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)

        # Step 1: COTP Connection Request
        sock.sendall(_build_s7_cotp_cr())
        resp = sock.recv(256)
        elapsed = _ms(t0)
        if len(resp) < 7:
            return "DOWN", elapsed, f"COTP 回應過短 ({len(resp)}B)"
        if resp[5] != 0xD0:  # COTP CC (Connection Confirm)
            return "DOWN", elapsed, f"COTP 拒絕 (PDU=0x{resp[5]:02X})"

        # Step 2: S7 Setup Communication
        sock.sendall(_build_s7_setup())
        resp2 = sock.recv(256)
        elapsed = _ms(t0)
        if len(resp2) < 12:
            return "DEGRADED", elapsed, f"S7 回應過短 ({len(resp2)}B)"
        # TPKT(4) + COTP(3) + S7 header
        s7_offset = 7  # after TPKT + COTP DT
        if len(resp2) > s7_offset and resp2[s7_offset] == 0x32:
            msg_type = resp2[s7_offset + 1] if len(resp2) > s7_offset + 1 else 0
            if msg_type == 0x03:  # Ack-Data
                pdu_size = 0
                if len(resp2) >= s7_offset + 18:
                    pdu_size = struct.unpack_from(">H", resp2, s7_offset + 16)[0]
                return "UP", elapsed, f"S7 Setup OK, PDU={pdu_size}"
            return "DEGRADED", elapsed, f"S7 回應類型=0x{msg_type:02X}"
        return "DEGRADED", elapsed, "COTP CC 成功, S7 回應格式異常"
    except socket.timeout:
        return "DOWN", _ms(t0), "連線逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_opcua(target, port, timeout):
    """OPC UA Hello/Acknowledge 探測。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(_build_opcua_hello(target, port))
        resp = sock.recv(512)
        elapsed = _ms(t0)
        if len(resp) < 8:
            return "DOWN", elapsed, f"回應過短 ({len(resp)}B)"
        msg_type = resp[:3]
        if msg_type == b"ACK":
            return "UP", elapsed, f"OPC UA Acknowledge ({len(resp)}B)"
        elif msg_type == b"ERR":
            err_code = struct.unpack_from("<I", resp, 8)[0] if len(resp) >= 12 else 0
            return "DEGRADED", elapsed, f"OPC UA Error (code=0x{err_code:08X})"
        return "DEGRADED", elapsed, f"非預期: {msg_type.decode('ascii', errors='replace')}"
    except socket.timeout:
        return "DOWN", _ms(t0), "連線逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_iec104(target, port, timeout):
    """IEC 60870-5-104 STARTDT act / con 探測。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(_build_iec104_startdt())
        resp = sock.recv(64)
        elapsed = _ms(t0)
        if len(resp) < 6:
            return "DOWN", elapsed, f"回應過短 ({len(resp)}B)"
        if resp[0] != 0x68:
            return "DOWN", elapsed, f"非 IEC 104 起始碼 (0x{resp[0]:02X})"
        ctrl = resp[2]
        if ctrl == 0x0B:
            return "UP", elapsed, "STARTDT con (確認)"
        elif ctrl == 0x07:
            return "DEGRADED", elapsed, "收到 STARTDT act echo (未確認)"
        elif ctrl == 0x43:
            return "DEGRADED", elapsed, "TESTFR con (非預期)"
        return "UP", elapsed, f"U-frame 回應 (ctrl=0x{ctrl:02X})"
    except socket.timeout:
        return "DOWN", _ms(t0), "連線逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_dnp3(target, port, timeout):
    """DNP3 Link Status Request 探測 (TCP)。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(_build_dnp3_link_status())
        resp = sock.recv(256)
        elapsed = _ms(t0)
        if len(resp) < 10:
            if len(resp) == 0:
                return "DOWN", elapsed, "空回應"
            return "DOWN", elapsed, f"回應過短 ({len(resp)}B)"
        if resp[0:2] == b'\x05\x64':
            ctrl = resp[3]
            return "UP", elapsed, f"DNP3 Link 回應 (ctrl=0x{ctrl:02X})"
        return "DEGRADED", elapsed, f"非 DNP3 起始碼: {resp[:4].hex()}"
    except socket.timeout:
        return "DOWN", _ms(t0), "連線逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_fins(target, port, timeout):
    """FINS/TCP Node Address Handshake 探測 (Omron)。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(_build_fins_tcp_hello())
        resp = sock.recv(64)
        elapsed = _ms(t0)
        if len(resp) < 16:
            return "DOWN", elapsed, f"回應過短 ({len(resp)}B)"
        if resp[:4] != b'FINS':
            return "DOWN", elapsed, f"非 FINS magic: {resp[:4].hex()}"
        cmd = struct.unpack_from(">I", resp, 8)[0]
        err = struct.unpack_from(">I", resp, 12)[0]
        if cmd == 0x00000001 and err == 0:
            return "UP", elapsed, "FINS/TCP Handshake OK"
        elif err != 0:
            return "DEGRADED", elapsed, f"FINS error=0x{err:08X}"
        return "UP", elapsed, f"FINS cmd=0x{cmd:08X}"
    except socket.timeout:
        return "DOWN", _ms(t0), "連線逾時"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ────────────────────────── UDP 探測 ──────────────────────────

def _probe_enip_udp(target, port, timeout):
    """EtherNet/IP ListIdentity UDP 探測。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_list_identity(), (target, port))
        resp, addr = sock.recvfrom(1024)
        elapsed = _ms(t0)
        if len(resp) < 24:
            return "DOWN", elapsed, f"回應不完整 ({len(resp)}B)"
        cmd, length, _, status = struct.unpack_from("<HHII", resp, 0)
        if cmd != 0x0063 or status != 0:
            return "DOWN", elapsed, f"異常回應 (cmd=0x{cmd:04X}, status=0x{status:08X})"
        detail = f"ListIdentity 正常, {len(resp)}B"
        if len(resp) >= 63:
            try:
                name_len = resp[62]
                if 0 < name_len < 64 and len(resp) >= 63 + name_len:
                    product = resp[63:63 + name_len].decode("ascii", errors="replace")
                    detail += f", {product}"
            except Exception:
                pass
        return "UP", elapsed, detail
    except socket.timeout:
        return "DOWN", _ms(t0), "UDP 逾時"
    except OSError as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_snmp(target, port, timeout):
    """SNMP GetRequest sysDescr.0 (UDP, community=public)。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_SNMP_GET_SYSDESCR, (target, port))
        resp, addr = sock.recvfrom(2048)
        elapsed = _ms(t0)
        if not resp or len(resp) < 2:
            return "DOWN", elapsed, "空回應"
        if resp[0] != 0x30:
            return "DOWN", elapsed, f"非 SNMP 回應 (0x{resp[0]:02X})"
        # 嘗試解析 sysDescr 值
        detail = f"SNMP 回應 ({len(resp)}B)"
        try:
            # 簡易解析：搜尋第一個長字串（sysDescr 值）
            idx = resp.find(b'\x04', 20)  # OCTET STRING after OID
            if idx > 0 and idx + 2 < len(resp):
                slen = resp[idx + 1]
                if 0 < slen < 200 and idx + 2 + slen <= len(resp):
                    desc = resp[idx + 2:idx + 2 + slen].decode("utf-8", errors="replace")
                    detail = desc[:64]
        except Exception:
            pass
        return "UP", elapsed, detail
    except socket.timeout:
        return "DOWN", _ms(t0), "UDP 逾時 (設備無回應或 community 不符)"
    except OSError as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_dns(target, port, timeout):
    """DNS Query 探測 (UDP)。"""
    t0 = time.monotonic()
    sock = None
    try:
        txn_id = int(time.time()) & 0xFFFF
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_dns_query(txn_id), (target, port))
        resp, addr = sock.recvfrom(512)
        elapsed = _ms(t0)
        if len(resp) < 12:
            return "DOWN", elapsed, f"回應過短 ({len(resp)}B)"
        flags = struct.unpack_from(">H", resp, 2)[0]
        qr = (flags >> 15) & 1
        rcode = flags & 0x0F
        if qr != 1:
            return "DEGRADED", elapsed, "收到非回應封包"
        if rcode == 0:
            return "UP", elapsed, f"DNS 正常 (NOERROR, {len(resp)}B)"
        elif rcode == 5:
            return "UP", elapsed, "DNS REFUSED (服務存活但拒絕查詢)"
        elif rcode == 2:
            return "DEGRADED", elapsed, "DNS SERVFAIL"
        return "UP", elapsed, f"DNS rcode={rcode}"
    except socket.timeout:
        return "DOWN", _ms(t0), "UDP 逾時"
    except OSError as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_ntp(target, port, timeout):
    """NTP Client 探測 (UDP Mode 3)。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_NTP_CLIENT, (target, port))
        resp, addr = sock.recvfrom(256)
        elapsed = _ms(t0)
        if len(resp) < 48:
            return "DOWN", elapsed, f"回應過短 ({len(resp)}B)"
        mode = resp[0] & 0x07
        if mode == 4:  # Server
            stratum = resp[1]
            return "UP", elapsed, f"NTP Server (stratum={stratum})"
        elif mode == 3:
            return "DEGRADED", elapsed, "NTP Mode 3 echo"
        return "UP", elapsed, f"NTP mode={mode}"
    except socket.timeout:
        return "DOWN", _ms(t0), "UDP 逾時"
    except OSError as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_bacnet(target, port, timeout):
    """BACnet/IP Who-Is 探測 (UDP)。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_BACNET_WHOIS, (target, port))
        resp, addr = sock.recvfrom(1024)
        elapsed = _ms(t0)
        if len(resp) < 4:
            return "DOWN", elapsed, f"回應過短 ({len(resp)}B)"
        if resp[0] != 0x81:
            return "DOWN", elapsed, f"非 BACnet 回應 (0x{resp[0]:02X})"
        bvlc_func = resp[1]
        if bvlc_func in (0x00, 0x04, 0x0A, 0x0B):
            # 檢查是否有 I-Am APDU
            npdu_start = 4
            if len(resp) > npdu_start + 2:
                apdu_start = npdu_start + 2
                if resp[apdu_start] == 0x10 and resp[apdu_start + 1] == 0x00:
                    return "UP", elapsed, f"BACnet I-Am 回應 ({len(resp)}B)"
            return "UP", elapsed, f"BACnet 回應 (func=0x{bvlc_func:02X}, {len(resp)}B)"
        return "DEGRADED", elapsed, f"BACnet func=0x{bvlc_func:02X}"
    except socket.timeout:
        return "DOWN", _ms(t0), "UDP 逾時 (設備可能不支援 unicast Who-Is)"
    except OSError as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_coap(target, port, timeout):
    """CoAP Confirmable GET /.well-known/core 探測 (UDP)。"""
    t0 = time.monotonic()
    sock = None
    try:
        msg_id = int(time.time()) & 0xFFFF
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_coap_get(msg_id), (target, port))
        resp, addr = sock.recvfrom(1500)
        elapsed = _ms(t0)
        if len(resp) < 4:
            return "DOWN", elapsed, f"回應過短 ({len(resp)}B)"
        ver = (resp[0] >> 6) & 0x03
        msg_type = (resp[0] >> 4) & 0x03
        code_class = (resp[1] >> 5) & 0x07
        code_detail = resp[1] & 0x1F
        if ver != 1:
            return "DEGRADED", elapsed, f"CoAP 版本={ver}"
        code_str = f"{code_class}.{code_detail:02d}"
        if msg_type == 2:  # ACK
            if code_class == 2:
                return "UP", elapsed, f"CoAP ACK {code_str} ({len(resp)}B)"
            elif code_class == 4:
                return "UP", elapsed, f"CoAP ACK {code_str} (資源不存在但服務正常)"
            return "UP", elapsed, f"CoAP ACK {code_str}"
        elif msg_type == 3:  # RST
            return "DEGRADED", elapsed, f"CoAP RST"
        return "UP", elapsed, f"CoAP type={msg_type} {code_str}"
    except socket.timeout:
        return "DOWN", _ms(t0), "UDP 逾時"
    except OSError as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_knx(target, port, timeout):
    """KNX/IP Search Request 探測 (UDP)。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_KNX_SEARCH, (target, port))
        resp, addr = sock.recvfrom(256)
        elapsed = _ms(t0)
        if len(resp) < 6:
            return "DOWN", elapsed, f"回應過短 ({len(resp)}B)"
        if resp[0] != 0x06 or resp[1] != 0x10:
            return "DOWN", elapsed, f"非 KNX/IP 回應"
        svc_type = struct.unpack_from(">H", resp, 2)[0]
        if svc_type == 0x0202:
            return "UP", elapsed, f"KNX/IP Search Response ({len(resp)}B)"
        return "UP", elapsed, f"KNX/IP service=0x{svc_type:04X}"
    except socket.timeout:
        return "DOWN", _ms(t0), "UDP 逾時"
    except OSError as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_ssdp(target, port, timeout):
    """SSDP M-SEARCH 探測 (UDP, unicast)。"""
    t0 = time.monotonic()
    sock = None
    try:
        req = (
            f"M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {target}:{port}\r\n"
            f'MAN: "ssdp:discover"\r\n'
            f"MX: 1\r\n"
            f"ST: ssdp:all\r\n"
            f"\r\n"
        ).encode("utf-8")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(req, (target, port))
        resp, addr = sock.recvfrom(2048)
        elapsed = _ms(t0)
        if not resp:
            return "DOWN", elapsed, "空回應"
        text = resp.decode("utf-8", errors="replace")
        if "HTTP/1.1 200" in text or "HTTP/1.0 200" in text:
            return "UP", elapsed, f"SSDP 回應 ({len(resp)}B)"
        return "UP", elapsed, f"SSDP 回應: {text.split(chr(13))[0][:48]}"
    except socket.timeout:
        return "DOWN", _ms(t0), "UDP 逾時 (設備可能不回應 unicast M-SEARCH)"
    except OSError as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_mdns(target, port, timeout):
    """mDNS 查詢 _services._dns-sd._udp.local 探測 (UDP)。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_mdns_query(), (target, port))
        resp, addr = sock.recvfrom(1500)
        elapsed = _ms(t0)
        if len(resp) < 12:
            return "DOWN", elapsed, f"回應過短 ({len(resp)}B)"
        flags = struct.unpack_from(">H", resp, 2)[0]
        qr = (flags >> 15) & 1
        if qr == 1:
            ancount = struct.unpack_from(">H", resp, 6)[0]
            return "UP", elapsed, f"mDNS 回應 ({ancount} answers, {len(resp)}B)"
        return "UP", elapsed, f"mDNS 回應 ({len(resp)}B)"
    except socket.timeout:
        return "DOWN", _ms(t0), "UDP 逾時"
    except OSError as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _probe_tftp(target, port, timeout):
    """TFTP RRQ 探測 (UDP) — 發送不存在檔名，期待 ERROR 回應。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_TFTP_RRQ, (target, port))
        # TFTP 伺服器從隨機 port 回應，recvfrom 不限來源
        resp, addr = sock.recvfrom(512)
        elapsed = _ms(t0)
        if len(resp) < 4:
            return "DOWN", elapsed, f"回應過短 ({len(resp)}B)"
        opcode = struct.unpack_from(">H", resp, 0)[0]
        if opcode == 5:  # ERROR
            err_code = struct.unpack_from(">H", resp, 2)[0]
            err_msg = resp[4:].split(b'\x00', 1)[0].decode("utf-8", errors="replace")
            return "UP", elapsed, f"TFTP ERROR {err_code}: {err_msg[:32]}"
        elif opcode == 3:  # DATA
            return "UP", elapsed, "TFTP DATA (檔案存在)"
        return "UP", elapsed, f"TFTP opcode={opcode}"
    except socket.timeout:
        return "DOWN", _ms(t0), "UDP 逾時"
    except OSError as e:
        return "DOWN", _ms(t0), str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════
# 探測器註冊表
# ═══════════════════════════════════════════════════════════════

PROBES = {
    # 通用
    "tcp":         _probe_tcp,
    # 常見服務
    "http":        _probe_http,
    "https":       _probe_https,
    "ssh":         _probe_ssh,
    "ftp":         _probe_ftp,
    "telnet":      _probe_telnet,
    "rdp":         _probe_rdp,
    "vnc":         _probe_vnc,
    "redis":       _probe_redis,
    "dns":         _probe_dns,
    "ntp":         _probe_ntp,
    "smb":         _probe_smb,
    # 工控
    "modbus":      _probe_modbus,
    "cip-session": _probe_cip_session,
    "cip-ucmm":    _probe_cip_ucmm,
    "enip-udp":    _probe_enip_udp,
    "s7":          _probe_s7,
    "opcua":       _probe_opcua,
    "iec104":      _probe_iec104,
    "dnp3":        _probe_dnp3,
    "bacnet":      _probe_bacnet,
    "fins":        _probe_fins,
    "knx":         _probe_knx,
    # IoT / 多媒體
    "mqtt":        _probe_mqtt,
    "rtsp":        _probe_rtsp,
    "coap":        _probe_coap,
    "snmp":        _probe_snmp,
    "ssdp":        _probe_ssdp,
    "mdns":        _probe_mdns,
    "tftp":        _probe_tftp,
}

SUPPORTED_PROTOCOLS = sorted(PROBES.keys())


def _auto_detect_protocol(port):
    """依埠號自動偵測協定。"""
    return PROTOCOL_BY_PORT.get(port, "tcp")


# ═══════════════════════════════════════════════════════════════
# 模組介面：sample(config) → dict
# ═══════════════════════════════════════════════════════════════

def sample(config: dict) -> dict:
    """平台 MonitorRunner 呼叫的統一介面。

    config keys:
        target   — 目標 IP（必要）
        port     — 目標埠號（必要）
        protocol — 明確指定協定；不給則依 port 自動判斷
        timeout  — 探測逾時秒數（預設 2.0）
    """
    target = config.get("target", "")
    port = config.get("port")
    if not target or not port:
        return {"error": "缺少 target/port"}

    port = int(port)
    protocol = config.get("protocol") or _auto_detect_protocol(port)
    if protocol == "auto":
        protocol = _auto_detect_protocol(port)
    timeout = float(config.get("timeout", 2.0))

    probe_fn = PROBES.get(protocol, _probe_tcp)

    try:
        status, latency_ms, detail = probe_fn(target, port, timeout)
    except Exception as e:
        return {
            "up": False, "latency_ms": None,
            "status": "DOWN", "protocol": protocol,
            "detail": f"探測例外: {e}",
        }

    return {
        "up": status == "UP",
        "latency_ms": latency_ms,
        "status": status,           # UP / DEGRADED / DOWN
        "protocol": protocol,       # 實際使用的探測協定
        "detail": detail,           # 人類可讀的探測結果
    }
