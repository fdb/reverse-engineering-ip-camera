#!/usr/bin/env python3
"""
Fake Kalay / CS2 PPPP supernode, v0.1

Listens on UDP/32100 and speaks just enough of the Throughtek/Kalay supernode
protocol to convince the camera (DID CFEOA-417739-RTFUU) that it's successfully
registered. Goal is to advance the cam's state machine past DEV_LGN so it opens
its CBS session port and tells us about it via `update hole lan=...`.

Protocol primitives (from pcaps + decomp):

  header = F1 <type:u8> <len:u16 big-endian>
  types seen cam→server:
    0x00 HELLO          (body empty)
    0x12 DEV_LGN_CRC    (body = 44 bytes, first 22 static encrypted DID,
                          remaining 22 per-session)
  types server→cam we synthesize:
    0x01 HELLO_ACK      (body = 16B sockaddr_in of cam's observed src:
                          AF_INET(2) + port(u16) + ip(u32) + 8B padding)
    0x13 DEV_LGN_ACK    (body = 8B, replayed verbatim from a real supernode
                          capture — cam seems to only check "length is 8 + arrives")

All received packets and all sent replies are logged with a hex dump and a
Kalay-type decode. Run in foreground so we see activity live, or background
for long unattended sessions.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import sys
import time
from datetime import datetime

PORT = 32100
BIND = ""  # all interfaces

# Kalay message type names we care about
TYPES = {
    0x00: "HELLO",     0x01: "HELLO_ACK",
    0x02: "HELLO_TO",  0x03: "HELLO_TO_ACK",
    0x10: "LST_REQ",   0x11: "LST_REQ_ACK",
    0x12: "DEV_LGN",   0x13: "DEV_LGN_ACK",
    0x20: "P2P_REQ",   0x21: "P2P_REQ_ACK",
    0x30: "LAN_SEARCH", 0x41: "LAN_RESPONSE",
    0x40: "P2P_RDY",   0x42: "PUNCH_PKT",
    0xd0: "DRW",       0xd1: "DRW_ACK",
    0xe0: "ALIVE",     0xe1: "ALIVE_ACK",
}

# DEV_LGN_ACK body we observed from a real supernode answering a real cam in
# pcap1/pcap2. 8 bytes. The meaning is opaque but the cam accepted it from
# 123.56.74.245, 47.89.232.167 and 8.134.120.63 unchanged, so replaying it is
# the best first guess.
DEV_LGN_ACK_BODY = bytes.fromhex("a02aaac73b7755c9")


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(direction: str, addr: tuple, data: bytes, note: str = "") -> None:
    mtype_name = "?"
    mlen = None
    if len(data) >= 4 and data[0] == 0xF1:
        mtype_name = TYPES.get(data[1], f"UNK_0x{data[1]:02x}")
        mlen = int.from_bytes(data[2:4], "big")
    arrow = "◀" if direction == "rx" else "▶"
    length_str = f"{len(data):3}B"
    body_str = f"body={mlen}" if mlen is not None else ""
    print(
        f"[{ts()}] {arrow} {addr[0]}:{addr[1]:<5} "
        f"{length_str}  {mtype_name:<12} {body_str:<10} "
        f"{data.hex()}  {note}",
        flush=True,
    )


# Synthetic public IP we echo to the cam as its "NAT-observed" address. We
# can't use the real MASQUERADE'd source (192.168.5.1) because that's RFC1918
# and the cam's rebinding filter rejects private IPs in supernode responses.
# 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — guaranteed unroutable on the
# public internet but not RFC1918, so it passes the "is this a public IP?"
# check without accidentally colliding with any real service.
FAKE_PUBLIC_IP = "203.0.113.37"


def make_hello_ack(cam_addr: tuple) -> bytes:
    """Build HELLO_ACK with a plausible-looking public endpoint for the cam.

    The real CS2 supernode writes a 16-byte sockaddr_in-style struct with the
    NAT-observed endpoint of the cam. We use FAKE_PUBLIC_IP as a non-RFC1918
    stand-in for the cam's "public" address so the cam's rebinding filter
    accepts the response. We preserve the source port from the cam's actual
    packet — that part is safe, since the cam sees the same source port on
    its own socket regardless of NAT translation.
    """
    ip_bytes = ipaddress.IPv4Address(FAKE_PUBLIC_IP).packed
    port_bytes = struct.pack(">H", cam_addr[1] & 0xFFFF)
    family = struct.pack(">H", 2)  # AF_INET
    padding = b"\x00" * 8
    body = family + port_bytes + ip_bytes + padding
    assert len(body) == 16
    header = struct.pack(">BBH", 0xF1, 0x01, len(body))
    return header + body


def make_dev_lgn_ack() -> bytes:
    """Replay the 8-byte ACK body observed from a real supernode."""
    header = struct.pack(">BBH", 0xF1, 0x13, len(DEV_LGN_ACK_BODY))
    return header + DEV_LGN_ACK_BODY


def main() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((BIND, PORT))
    print(f"[{ts()}] fake Kalay supernode bound on UDP/{PORT}", flush=True)
    print(f"[{ts()}] will answer HELLO → HELLO_ACK and DEV_LGN → DEV_LGN_ACK", flush=True)

    while True:
        try:
            data, addr = s.recvfrom(4096)
        except KeyboardInterrupt:
            print(f"\n[{ts()}] stopping")
            return
        except OSError as e:
            print(f"[{ts()}] recv error: {e}")
            continue

        log("rx", addr, data)

        if len(data) < 4 or data[0] != 0xF1:
            continue

        mtype = data[1]
        if mtype == 0x00:  # HELLO
            reply = make_hello_ack(addr)
            s.sendto(reply, addr)
            log("tx", addr, reply, note="→ HELLO_ACK")
        elif mtype == 0x12:  # DEV_LGN_CRC
            reply = make_dev_lgn_ack()
            s.sendto(reply, addr)
            log("tx", addr, reply, note="→ DEV_LGN_ACK (replayed)")
        else:
            # Unknown type — log but don't respond. May need to add more handlers.
            log("rx", addr, data, note="(no responder for this type)")


if __name__ == "__main__":
    main()
