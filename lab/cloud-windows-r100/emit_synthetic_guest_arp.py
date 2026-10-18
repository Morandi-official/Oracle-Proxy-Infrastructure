"""R100 ephemeral guest-side TAP ARP frame. No socket, external route or DNS.

Runs only within the unique Linux CI namespace and inserts one synthetic
benchmark-network Ethernet/ARP frame through the TAP's guest-facing FD.
"""
import fcntl
import os
import struct
import time

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

def main():
    if os.environ.get("R100_SYNTHETIC_TAP") != "CI_ONLY":
        raise SystemExit("R100_REFUSED_UNAUTHORIZED_TAP_FRAME")
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
    try:
        ifreq = struct.pack("16sH", b"tap0", IFF_TAP | IFF_NO_PI)
        fcntl.ioctl(fd, TUNSETIFF, ifreq)
        guest_mac = bytes.fromhex("020000000102")
        host_mac = b"\xff" * 6
        # Ethernet broadcast; ARP request who-has 198.18.100.1,
        # sender 198.18.100.2 inside RFC 2544 benchmarking range.
        arp = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) +
               guest_mac + bytes([198, 18, 100, 2]) +
               b"\x00" * 6 + bytes([198, 18, 100, 1]))
        frame = host_mac + guest_mac + bytes.fromhex("0806") + arp
        for _ in range(3):
            if os.write(fd, frame) != len(frame):
                raise SystemExit("R100_SYNTHETIC_TAP_FRAME_WRITE_FAILED")
            time.sleep(0.25)
        print("R100_GUEST_FACING_TAP_SYNTHETIC_ARP_SENT")
    finally:
        os.close(fd)

if __name__ == "__main__":
    main()
