import socket

# EtherType for IPv4
ETH_P_IP = 0x0800

IFACE = 'eth0'


def open_raw_socket(iface: str) -> socket.socket:
    """Open a raw socket on the specified interface."""
    # AF_PACKET — уровень Ethernet (L2), SOCK_RAW — сырые пакеты
    sock = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP)
    )
    sock.bind((iface, 0))
    return sock


def main() -> None:
    sock = open_raw_socket(IFACE)
    print(f"[*] Listening on interface {IFACE} for IPv4 packets (raw)...")

    while True:
        data, addr = sock.recvfrom(65535)
        print(f"[+] Got packet: {len(addr)}, bytes addr = {addr}")


if __name__ == "__main__":
    main()
