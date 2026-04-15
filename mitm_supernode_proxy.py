#!/usr/bin/env python3
"""
UDP MITM proxy for the cam's Kalay supernode traffic.

Architecture (per cam client session):

  cam (192.168.5.1:X after MASQUERADE)
       │
       │  UDP datagram to us:32100
       ▼
  us (192.168.5.233:32100)  ── per-client socket ──>  real supernode (8.134.120.63:32100)
       ▲                                              │
       │           reply from real supernode          │
       └──────────────────────────────────────────────┘
       forward reply back to cam

The cam talks to what it thinks is one supernode at 9.9.9.9 (DNAT'd to us).
We de-multiplex on (src_ip, src_port) — each cam session gets its own upstream
socket, and we remember the mapping so that when the supernode replies we can
forward back to the correct cam session.

Three hard-coded upstreams are available (one per real supernode). We route
each (cam_src_ip, cam_src_port) to a consistent upstream so that the
supernode's state isn't spread across boxes. First-come-first-served:
a new cam session picks the next upstream in round-robin.

Every packet in each direction is logged with hex + Kalay type decode.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

INJECT_FILE = Path("/tmp/cam-listen/inject.json")

LISTEN_PORT = 32100

# Real supernodes extracted from the first pcap. Any is fine — Kalay clients
# are designed to handle HA across them.
UPSTREAMS = [
    ("8.134.120.63", 32100),    # Aliyun Shenzhen
    ("47.89.232.167", 32100),   # Aliyun US-West
    ("123.56.74.245", 32100),   # Aliyun Beijing
]

KALAY_TYPES = {
    0x00: "HELLO",     0x01: "HELLO_ACK",
    0x02: "HELLO_TO",  0x03: "HELLO_TO_ACK",
    0x10: "LST_REQ",   0x11: "LST_REQ_ACK",
    0x12: "DEV_LGN",   0x13: "DEV_LGN_ACK",
    0x20: "P2P_REQ",   0x21: "P2P_REQ_ACK",
    0x30: "LAN_SEARCH", 0x41: "LAN_RESPONSE",
    0x40: "P2P_RDY",   0x42: "PUNCH_PKT",
    0xd0: "DRW",       0xd1: "DRW_ACK",
    0xe0: "ALIVE",     0xe1: "ALIVE_ACK",
    0xf9: "REPORT_SESSION_RDY",
}


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def decode_kalay(data: bytes) -> str:
    if len(data) < 4 or data[0] != 0xF1:
        return f"raw({len(data)}B)"
    mtype = data[1]
    mlen = int.from_bytes(data[2:4], "big")
    name = KALAY_TYPES.get(mtype, f"UNK_0x{mtype:02x}")
    return f"{name}/{len(data)}B(body={mlen})"


def log(direction: str, cam_addr: tuple, upstream_addr: tuple, data: bytes) -> None:
    arrow = "▶ fwd" if direction == "cam→server" else "◀ ret"
    print(
        f"[{ts()}] {arrow}  {cam_addr[0]}:{cam_addr[1]:<5} <-> {upstream_addr[0]}:{upstream_addr[1]:<5}  "
        f"{decode_kalay(data):<32}  {data.hex()[:64]}",
        flush=True,
    )


class Session:
    """One cam←→supernode UDP session."""
    __slots__ = ("cam_addr", "upstream_addr", "upstream_sock", "last_seen")

    def __init__(self, cam_addr: tuple, upstream_addr: tuple):
        self.cam_addr = cam_addr
        self.upstream_addr = upstream_addr
        self.upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Bind to ephemeral; the OS picks a port.
        self.upstream_sock.bind(("", 0))
        self.last_seen = time.time()


def session_key(cam_addr: tuple) -> tuple:
    return (cam_addr[0], cam_addr[1])


def main() -> None:
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(("", LISTEN_PORT))
    print(f"[{ts()}] MITM supernode proxy listening on UDP/{LISTEN_PORT}  pid={os.getpid()}", flush=True)
    print(f"[{ts()}] upstreams: {UPSTREAMS}", flush=True)
    print(f"[{ts()}] inject: write JSON to {INJECT_FILE}, then `kill -USR1 {os.getpid()}`", flush=True)

    sessions: dict[tuple, Session] = {}
    lock = threading.Lock()
    upstream_rr = 0  # round-robin index for new sessions

    # Injection: SIGUSR1 makes us read INJECT_FILE and send the described
    # packet(s) from our :32100 socket. This lets us inject crafted frames
    # into a cam session with the right source-address so the cam's reverse
    # conntrack rewrites them to src=9.9.9.9:32100, matching the cam's
    # established supernode 4-tuple.
    def on_sigusr1(signum, frame):
        try:
            spec = json.loads(INJECT_FILE.read_text())
            targets = spec if isinstance(spec, list) else [spec]
            for t in targets:
                host, port = t["target"].split(":")
                port = int(port)
                payload = bytes.fromhex(t["hex"])
                listen_sock.sendto(payload, (host, port))
                print(
                    f"[{ts()}] ✳ INJECT  → {host}:{port:<5} {decode_kalay(payload):<32}  {payload.hex()[:80]}",
                    flush=True,
                )
        except Exception as e:
            print(f"[{ts()}] inject error: {type(e).__name__}: {e}", flush=True)

    signal.signal(signal.SIGUSR1, on_sigusr1)

    def upstream_listener(sess: Session) -> None:
        """One thread per session: read from upstream, forward back to cam."""
        s = sess.upstream_sock
        s.settimeout(2.0)
        while True:
            try:
                data, src = s.recvfrom(4096)
            except socket.timeout:
                # session expires after 300s of idle
                if time.time() - sess.last_seen > 300:
                    with lock:
                        sessions.pop(session_key(sess.cam_addr), None)
                    try: s.close()
                    except Exception: pass
                    print(f"[{ts()}] session expired: {sess.cam_addr}", flush=True)
                    return
                continue
            except OSError:
                return
            sess.last_seen = time.time()
            log("server→cam", sess.cam_addr, src, data)
            # Forward to original cam endpoint
            try:
                listen_sock.sendto(data, sess.cam_addr)
            except Exception as e:
                print(f"[{ts()}] forward to cam failed: {e}", flush=True)

    while True:
        try:
            data, cam_addr = listen_sock.recvfrom(4096)
        except KeyboardInterrupt:
            return
        except OSError:
            continue

        key = session_key(cam_addr)
        with lock:
            sess = sessions.get(key)
            if sess is None:
                upstream = UPSTREAMS[upstream_rr % len(UPSTREAMS)]
                upstream_rr += 1
                sess = Session(cam_addr, upstream)
                sessions[key] = sess
                t = threading.Thread(target=upstream_listener, args=(sess,), daemon=True)
                t.start()
                print(f"[{ts()}] new session: {cam_addr} → {upstream}", flush=True)
        sess.last_seen = time.time()
        log("cam→server", cam_addr, sess.upstream_addr, data)
        try:
            sess.upstream_sock.sendto(data, sess.upstream_addr)
        except Exception as e:
            print(f"[{ts()}] forward to upstream failed: {e}", flush=True)


if __name__ == "__main__":
    main()
