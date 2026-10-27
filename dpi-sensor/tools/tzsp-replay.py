#!/usr/bin/env python3
"""Replay a classic pcap (Ethernet or raw IP) to the sensor as TZSP, the way a
MikroTik's mangle `action=sniff-tzsp` sends it. For testing the sensor without
a router:

    tzsp-replay.py capture.pcap [host] [port]
"""
import socket
import struct
import sys


def frames(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        magic = struct.unpack("<I", hdr[:4])[0]
        endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            _, _, incl, _ = struct.unpack(endian + "IIII", rec)
            yield linktype, f.read(incl)


def main():
    path = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 37008
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    for linktype, data in frames(path):
        # TZSP v1, type 0 (received), encapsulation 1 (Ethernet) or 7 (raw), then END.
        encap = 1 if linktype == 1 else 7
        if linktype == 113:  # Linux cooked capture: strip its 16-byte header
            data, encap = data[16:], 7
        s.sendto(struct.pack(">BBH", 1, 0, encap) + b"\x01" + data, (host, port))
        sent += 1
    print(f"sent {sent} frames", file=sys.stderr)


if __name__ == "__main__":
    main()
