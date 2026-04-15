#!/usr/bin/env python3
"""
Fake-V360-app probe for the Cloudbirds / V360 Pro IP camera.

Modes
-----
  probe.py listen          Combined mode — listen passively on UDP/8899 AND
                           broadcast the YH probe on UDP/18523 every 2 s in
                           parallel. This is what the real app effectively
                           does after joining the camera's HAP-xxxxx AP.
                           Ctrl-C to stop.

  probe.py passive         Only listen on UDP/8899 (no outbound packets).

  probe.py active          Only send the 4-byte YH broadcast to 18523 and
                           wait briefly for a reply.

Everything is local — no cloud, no tokens, no SSID/password leak.

Reference: decompiled com.qianniao.add.device.SearchDeviceByUDP and
SearchDeviceByMulticast from V360 Pro 6.5.0.
"""
from __future__ import annotations

import socket
import struct
import sys
import threading
import time
from datetime import datetime

YH_PROBE = struct.pack(">H", 18521) + b"\x01\x01"  # b"YH\x01\x01"
BCAST = "255.255.255.255"
PROBE_PORT = 18523
BEACON_PORT = 8899


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(tag: str, msg: str, *, color: str = "") -> None:
    colors = {"green":"\x1b[32m","cyan":"\x1b[36m","orange":"\x1b[33m","red":"\x1b[31m","dim":"\x1b[2m","":""}
    reset = "\x1b[0m" if color else ""
    sys.stdout.write(f"{colors.get(color,'')}[{ts()}] {tag:<9} {msg}{reset}\n")
    sys.stdout.flush()


def hexdump(b: bytes, width: int = 16) -> str:
    # Compact cat-able hexdump: "0000  59 48 01 01                                     YH.."
    lines = []
    for off in range(0, len(b), width):
        chunk = b[off:off+width]
        hx = " ".join(f"{c:02x}" for c in chunk)
        hx = hx.ljust(width * 3 - 1)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        lines.append(f"  {off:04x}  {hx}  {asc}")
    return "\n".join(lines)


def local_ipv4_for(dest: str = "8.8.8.8") -> str:
    """Figure out which local interface IP we'd use to reach `dest`.
    Uses a UDP socket connect() trick — no packet is sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dest, 1))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


def parse_yh_reply(data: bytes) -> dict | None:
    """Reply layout from SearchDeviceByMulticast.kt:
       bytes[0:2] must be b'YH', then
         ip  = bytes[4:20]   (16B, zero-padded ASCII)
         mac = bytes[84:90]  (6B)
         did = bytes[-24:-4] (20B, zero-padded ASCII)
    Not seen in the wild on Throughtek-Kalay firmware — 18523 seems unused
    there — but we keep the parser for older CS2-only cams.
    """
    if len(data) < 90 or data[0:2] != b"YH":
        return None
    def trim(b: bytes) -> str:
        return b.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
    return {
        "did": trim(data[-24:-4]),
        "mac": ":".join(f"{x:02x}" for x in data[84:90]),
        "ip":  trim(data[4:20]),
    }


def parse_iotcare_beacon(data: bytes) -> dict | None:
    """Throughtek Kalay "IoTCare" LAN beacon on UDP/8899. Format is a plain
    ASCII string: '<tag>:<DID>:<tag>', where tag is typically 'iotcare_lan'
    and DID is the canonical CS2/Kalay form 'AAAAA-NNNNNN-BBBBB' (5 letters,
    6 digits, 5 letters). Example:

        iotcare_lan:CFEOA-417739-RTFUU:iotcare_lan
    """
    try:
        s = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    parts = s.split(":")
    if len(parts) != 3:
        return None
    tag_a, did, tag_b = parts
    if tag_a != tag_b or "_" not in tag_a:
        return None
    # Loose DID shape check — don't be strict, different OEMs use variants.
    if not (10 <= len(did) <= 32 and "-" in did):
        return None
    return {"tag": tag_a, "did": did}


# ─── listeners ────────────────────────────────────────────────────────────────

def passive_listener(stop: threading.Event) -> None:
    """Bind UDP/8899 and print every packet that arrives, without ever replying."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(1.0)  # short so we can check stop flag
    try:
        s.bind(("", BEACON_PORT))
    except OSError as e:
        log("8899", f"bind failed: {e}", color="red")
        return
    log("8899", f"listening on UDP/{BEACON_PORT} (mirroring SearchDeviceByUDP.kt)", color="cyan")
    while not stop.is_set():
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError as e:
            log("8899", f"recv error: {e}", color="red")
            return
        log("8899", f"◀ {addr[0]}:{addr[1]}  len={len(data)}", color="green")
        print(hexdump(data))
        parsed = parse_iotcare_beacon(data)
        if parsed:
            log("8899", f"cam={addr[0]}  did={parsed['did']}  tag={parsed['tag']}", color="orange")
        else:
            try:
                decoded = data.decode("utf-8", errors="replace")
                log("8899", f"utf8: {decoded!r}", color="dim")
            except Exception:
                pass
    s.close()


def probe_listener(sock: socket.socket, stop: threading.Event) -> None:
    """Watch the same socket we send YH probes from — replies come back here."""
    sock.settimeout(1.0)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            return
        log("18523", f"◀ {addr[0]}:{addr[1]}  len={len(data)}", color="green")
        print(hexdump(data))
        parsed = parse_yh_reply(data)
        if parsed:
            log("18523", f"parsed did={parsed['did']!r} mac={parsed['mac']} ip={parsed['ip']!r}", color="orange")


def yh_broadcaster(sock: socket.socket, stop: threading.Event, interval: float = 2.0) -> None:
    """Send the 4-byte YH probe periodically (the app fires 4× at 500ms; we just keep going)."""
    log("18523", f"broadcasting {YH_PROBE.hex()} → {BCAST}:{PROBE_PORT} every {interval}s", color="cyan")
    n = 0
    while not stop.is_set():
        try:
            sock.sendto(YH_PROBE, (BCAST, PROBE_PORT))
            n += 1
            log("18523", f"▶ probe #{n}", color="dim")
        except OSError as e:
            log("18523", f"send error: {e}", color="red")
        stop.wait(interval)


# ─── modes ────────────────────────────────────────────────────────────────────

def mode_listen(*, quiet: bool = False) -> None:
    """Combined listener. `quiet=True` drops the 18523 YH broadcaster — useful
    now that we know the Kalay firmware never answers on 18523 and we just
    want a clean view of the 8899 beacons."""
    local = local_ipv4_for()
    log("init", f"local IPv4 looks like {local}  (Ctrl-C to stop)", color="orange")

    stop = threading.Event()
    threads = [threading.Thread(target=passive_listener, args=(stop,), daemon=True)]

    probe_sock = None
    if not quiet:
        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        probe_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe_sock.bind(("", 0))
        threads.append(threading.Thread(target=probe_listener, args=(probe_sock, stop), daemon=True))
        threads.append(threading.Thread(target=yh_broadcaster, args=(probe_sock, stop), daemon=True))

    for t in threads:
        t.start()
    try:
        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
        log("init", "stopping…", color="dim")
        stop.set()
        if probe_sock is not None:
            probe_sock.close()
        time.sleep(0.3)


def mode_passive(timeout: float = 30.0) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(timeout)
    s.bind(("", BEACON_PORT))
    log("8899", f"listening for {timeout:.0f}s", color="cyan")
    try:
        data, addr = s.recvfrom(4096)
    except socket.timeout:
        log("8899", "timeout — nothing arrived", color="red")
        return
    log("8899", f"◀ {addr[0]}:{addr[1]}  len={len(data)}", color="green")
    print(hexdump(data))


def mode_active(timeout: float = 4.0) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(timeout)
    s.bind(("", 0))
    log("18523", f"▶ 4× YH probe to {BCAST}:{PROBE_PORT}", color="cyan")
    for _ in range(4):
        s.sendto(YH_PROBE, (BCAST, PROBE_PORT))
        time.sleep(0.5)
    try:
        while True:
            data, addr = s.recvfrom(4096)
            log("18523", f"◀ {addr[0]}:{addr[1]}  len={len(data)}", color="green")
            print(hexdump(data))
            parsed = parse_yh_reply(data)
            if parsed:
                log("18523", f"parsed {parsed}", color="orange")
    except socket.timeout:
        log("18523", "no more replies", color="dim")


def main() -> None:
    args = sys.argv[1:]
    mode = args[0] if args else "listen"
    quiet = "--quiet" in args or "-q" in args
    if mode == "listen":
        mode_listen(quiet=quiet)
    elif mode == "passive":
        mode_passive()
    elif mode == "active":
        mode_active()
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
