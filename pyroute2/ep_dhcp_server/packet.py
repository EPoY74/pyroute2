import struct
from dataclasses import dataclass
from typing import Dict, Any


# BOOTP fixed header: 236 bytes
BOOTp_FORMAT = "!BBBBIHHIIII16s64s128s"
BOOTp_LEN = struct.calcsize(BOOTp_FORMAT)

MAGIC_COOKIE = b"\x63\x82\x53\x63"


@dataclass
class DhcpMessage:
    # BOOTP op: 1 = request, 2 = reply
    op: int
    # transaction ID
    xid: int
    # MAC клиента в виде "de:ad:be:ef:00:01"
    chaddr: str
    # 1=DISCOVER, 2=OFFER, 3=REQUEST, 5=ACK...
    dhcp_message_type: int
    # сырые опции (на будущее, пока можем туда же класть 53)
    options: Dict[int, Any]


def parse_bootp_header(data: bytes) -> dict:
    """
    Парсит 236 байт BOOTP-заголовка и возвращает словарь
    с базовыми полями (op, htype, hlen, xid, chaddr).
    """
    if len(data) < BOOTp_LEN:
        raise ValueError(f"BOOTP header too short: {len(data)} bytes")

    (
        op,
        htype,
        hlen,
        hops,
        xid,
        secs,
        flags,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        chaddr_raw,
        sname,
        file,
    ) = struct.unpack(BOOTp_FORMAT, data[:BOOTp_LEN])

    # Берём только первые hlen байт MAC-адреса
    hw_bytes = chaddr_raw[:hlen]
    chaddr_str = ":".join(f"{b:02x}" for b in hw_bytes)

    return {
        "op": op,
        "htype": htype,
        "hlen": hlen,
        "hops": hops,
        "xid": xid,
        "secs": secs,
        "flags": flags,
        "ciaddr": ciaddr,
        "yiaddr": yiaddr,
        "siaddr": siaddr,
        "giaddr": giaddr,
        "chaddr": chaddr_str,
        # sname и file пока не используем, но при желании можно добавить
    }


def parse_dhcp_options(data: bytes) -> dict:
    """
    Парсит DHCP-опции после BOOTP-заголовка.
    Возвращает словарь с интересующими нас полями, например:
    {"dhcp_message_type": 1}
    """

    if len(data) < BOOTp_LEN + len(MAGIC_COOKIE):
        err = "Packet too short to contain BOOTP header and magic cookie"
        raise ValueError(err)

    # 1. Проверяем magic cookie
    cookie = data[BOOTp_LEN:BOOTp_LEN + 4]
    if cookie != MAGIC_COOKIE:
        raise ValueError(f"Invalid DHCP magic cookie: {cookie!r}")

    # 2. Начинаем разбор опций после cookie
    pos = BOOTp_LEN + 4
    options: dict[str, object] = {}

    while pos < len(data):
        code = data[pos]
        pos += 1

        if code == 0:
            # Padding, пропускаем
            continue

        if code == 255:
            # End
            break

        if pos >= len(data):
            err = "Unexpected end of packet while reading option length"
            raise ValueError(err)

        length = data[pos]
        pos += 1

        if pos + length > len(data):
            raise ValueError("Option length goes beyond packet end")

        value = data[pos:pos + length]
        pos += length

        # Нас пока интересует только опция 53 (DHCP Message Type)
        if code == 53 and length == 1:
            options["dhcp_message_type"] = value[0]

        # Остальные опции сейчас игнорируем

    return options


def parse_dhcp_message(data: bytes) -> DhcpMessage:
    """
    Высокоуровневый парсер DHCP:
    комбинирует BOOTP-заголовок и DHCP-опции
    в один объект DhcpMessage.
    """
    raise NotImplementedError("parse_dhcp_message is not implemented yet")
