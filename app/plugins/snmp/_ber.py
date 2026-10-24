"""
plugins/snmp/_ber.py — 最小 BER/ASN.1 編碼器，僅供本模組組 SNMP 封包使用。

不依賴 pysnmp 等第三方套件，用標準函式庫就能組出合法的 SNMP GetRequest /
GetBulkRequest 封包，減少部署依賴。這不是通用 BER 函式庫，只實作 SNMP 會用到的
幾種型別（INTEGER / OCTET STRING / NULL / OID / SEQUENCE / 各種 PDU context tag）。
"""


def encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(value)) + value


def encode_integer(n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    else:
        negative = n < 0
        b = []
        v = n if not negative else (~n)
        while v:
            b.insert(0, v & 0xFF)
            v >>= 8
        if not b:
            b = [0]
        if negative:
            b = [(~x) & 0xFF for x in b]
            # 兩補數簡化：僅支援本模組會用到的非負值（request-id/error-status等）
        body = bytes(b)
        if body[0] & 0x80 and not negative:
            body = b"\x00" + body
    return encode_tlv(0x02, body)


def encode_octetstring(s: bytes) -> bytes:
    return encode_tlv(0x04, s)


def encode_null() -> bytes:
    return encode_tlv(0x05, b"")


def encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.strip(".").split(".")]
    first = parts[0] * 40 + parts[1]
    body = bytearray([first])
    for p in parts[2:]:
        if p < 0x80:
            body.append(p)
        else:
            chunk = []
            v = p
            while v:
                chunk.insert(0, v & 0x7F)
                v >>= 7
            for i in range(len(chunk) - 1):
                chunk[i] |= 0x80
            body.extend(chunk)
    return encode_tlv(0x06, bytes(body))


def encode_sequence(content: bytes, tag: int = 0x30) -> bytes:
    return encode_tlv(tag, content)


def build_snmp_get_request(community: str, oid: str, request_id: int) -> bytes:
    """SNMPv1 GetRequest-PDU（tag 0xA0）。"""
    varbind = encode_sequence(encode_oid(oid) + encode_null())
    varbind_list = encode_sequence(varbind)
    pdu_body = (
        encode_integer(request_id)
        + encode_integer(0)  # error-status
        + encode_integer(0)  # error-index
        + varbind_list
    )
    pdu = encode_sequence(pdu_body, tag=0xA0)
    msg_body = encode_integer(0) + encode_octetstring(community.encode()) + pdu  # version=0 (v1)
    return encode_sequence(msg_body)


def build_snmp_v2c_getbulk(community: str, oid: str, request_id: int,
                            non_repeaters: int = 0, max_repetitions: int = 10) -> bytes:
    """SNMPv2c GetBulkRequest-PDU（tag 0xA5）。"""
    varbind = encode_sequence(encode_oid(oid) + encode_null())
    varbind_list = encode_sequence(varbind)
    pdu_body = (
        encode_integer(request_id)
        + encode_integer(non_repeaters)
        + encode_integer(max_repetitions)
        + varbind_list
    )
    pdu = encode_sequence(pdu_body, tag=0xA5)
    msg_body = encode_integer(1) + encode_octetstring(community.encode()) + pdu  # version=1 (v2c)
    return encode_sequence(msg_body)
