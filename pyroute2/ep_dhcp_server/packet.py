import struct


# BOOTP fixed header: 236 bytes
BOOTp_FORMAT = "!BBBBIHHIIII16s64s128s"
BOOTp_LEN = struct.calcsize(BOOTp_FORMAT)


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
