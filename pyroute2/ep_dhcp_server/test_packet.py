import struct

from .packet import (
    parse_bootp_header,
    parse_dhcp_options,
    DhcpMessage,
    parse_dhcp_message,
)


def make_dummy_discover() -> bytes:
    """
    Собираем минимальный DHCPDISCOVER:
    - 236 байт BOOTP-заголовка
    - 4 байта magic cookie 0x63825363
    - опция 53 (DHCP Message Type) = 1 (DISCOVER)
    - опция 255 (End)
    """
    BOOTREQUEST = 1
    HTYPE_ETHERNET = 1
    HLEN_ETHERNET = 6

    xid = 0x12345678  # просто тестовый XID
    # MAC-адрес клиента: de:ad:be:ef:00:01
    # (остальное дополняем нулями до 16 байт)
    chaddr = bytes.fromhex("de ad be ef 00 01") + b"\x00" * 10

    bootp_fixed = struct.pack(
        "!BBBBIHHIIII16s64s128s",
        BOOTREQUEST,     # op
        HTYPE_ETHERNET,  # htype
        HLEN_ETHERNET,   # hlen
        0,               # hops
        xid,             # xid
        0,               # secs
        0,               # flags
        0, 0, 0, 0,      # ciaddr, yiaddr, siaddr, giaddr
        chaddr,          # chaddr (16 байт)
        b"\x00" * 64,    # sname
        b"\x00" * 128,   # file
    )

    magic_cookie = b"\x63\x82\x53\x63"
    options = magic_cookie + bytes([
        53, 1, 1,  # Опция 53, длина 1, значение 1 (DISCOVER)
        255,       # End
    ])

    return bootp_fixed + options


def test_parse_bootp_basic():
    payload = make_dummy_discover()

    header = parse_bootp_header(payload)

    # Базовые поля BOOTP
    assert header["op"] == 1
    assert header["htype"] == 1
    assert header["hlen"] == 6
    assert header["xid"] == 0x12345678

    # MAC клиента в человекочитаемом виде
    assert header["chaddr"] == "de:ad:be:ef:00:01"


def test_parse_dhcp_message_type():
    payload = make_dummy_discover()
    options = parse_dhcp_options(payload)

    # В make_dummy_discover мы закладывали:
    # опция 53, длина 1, значение 1 (DHCPDISCOVER)
    # Проверяем значение, что это dhcp, то есть тип 1
    assert options["dhcp_message_type"] == 1


def test_parse_dhcp_message_combines_header_and_options():
    payload = make_dummy_discover()

    msg = parse_dhcp_message(payload)

    # Проверяем, что это именно DhcpMessage
    assert isinstance(msg, DhcpMessage)

    # Поля из BOOTP-заголовка
    assert msg.op == 1
    assert msg.xid == 0x12345678
    assert msg.chaddr == "de:ad:be:ef:00:01"

    # Поле из DHCP-опций
    assert msg.dhcp_message_type == 1  # DHCPDISCOVER

