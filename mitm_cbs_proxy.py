#!/usr/bin/env python3
"""
MITM TLS proxy for the cam's CBS control-plane traffic.

Architecture:
  cam → UDM (DNAT TCP 443 → 8443) → us (terminate TLS with fake cert)
                                        → we open TLS to real upstream
                                        → forward request
                                        ← forward response
                                        ← re-encrypted back to cam

We log the cleartext HTTP request and response for every call. The cam sees
valid-to-it traffic (via our self-signed cert, which it accepts because it
doesn't cert-pin) and advances its state machine using REAL cloud responses.

Hard-coded upstream IP to bypass the UDM's dnsmasq which points everything
at 9.9.9.9 (our own DNAT loop target).
"""
from __future__ import annotations

import socket
import ssl
import sys
import threading
from datetime import datetime
from pathlib import Path

LISTEN_PORT = 8443

# Real public IP for user.hapseemate.cn captured from the original pcap2.
# Hard-coded to bypass the UDM dnsmasq 9.9.9.9 sinkhole.
UPSTREAM_HOST = "user.hapseemate.cn"
UPSTREAM_IP = "190.92.254.71"
UPSTREAM_PORT = 443

CERT_DIR = Path("/tmp/cam-listen/fake-cbs-certs")
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(tag: str, addr: tuple, msg: str) -> None:
    print(f"[{ts()}] {tag:<8} {addr[0]}:{addr[1]:<5}  {msg}", flush=True)


def parse_sni(data: bytes) -> str | None:
    """Minimal TLS ClientHello parser to extract SNI before we terminate TLS."""
    if len(data) < 5 or data[0] != 0x16:
        return None
    body = data[5:5 + int.from_bytes(data[3:5], "big")]
    if not body or body[0] != 0x01:
        return None
    i = 1 + 3 + 2 + 32
    if i >= len(body): return None
    i += 1 + body[i]
    if i + 2 > len(body): return None
    i += 2 + int.from_bytes(body[i:i+2], "big")
    if i + 1 > len(body): return None
    i += 1 + body[i]
    if i + 2 > len(body): return None
    ext_end = i + 2 + int.from_bytes(body[i:i+2], "big"); i += 2
    while i + 4 <= ext_end:
        ext_type = int.from_bytes(body[i:i+2], "big")
        ext_len = int.from_bytes(body[i+2:i+4], "big")
        ext_data = body[i+4:i+4+ext_len]; i += 4 + ext_len
        if ext_type == 0x00 and len(ext_data) > 5:
            nlen = int.from_bytes(ext_data[3:5], "big")
            return ext_data[5:5+nlen].decode("ascii", errors="replace")
    return None


def pipe(src, dst, tag, addr, stop_on_empty: bool = True):
    """Relay bytes from src to dst, logging along the way."""
    try:
        total = 0
        while True:
            chunk = src.recv(16384)
            if not chunk:
                if stop_on_empty:
                    return total
                continue
            total += len(chunk)
            try:
                dst.sendall(chunk)
            except Exception as e:
                log(tag, addr, f"pipe send failed: {e}")
                return total
            # Log printable snippets (HTTP headers/bodies will often be readable)
            snippet = chunk[:512]
            try:
                decoded = snippet.decode("utf-8", errors="replace")
                # Only log if it looks like text
                if decoded and any(c.isprintable() or c in "\r\n" for c in decoded[:20]):
                    print(f"[{ts()}] {tag:<8} {addr[0]}:{addr[1]:<5}  ({len(chunk)}B)", flush=True)
                    print(decoded.rstrip(), flush=True)
            except Exception:
                pass
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        log(tag, addr, f"pipe ended: {e}")
        return total


def handle(client_sock: socket.socket, addr: tuple, server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext) -> None:
    log("ACCEPT", addr, "new connection")
    upstream_sock = None
    upstream_tls = None
    client_tls = None

    try:
        # 1. Peek at ClientHello to get SNI
        client_sock.settimeout(5)
        peek = client_sock.recv(2048, socket.MSG_PEEK)
        sni = parse_sni(peek) or UPSTREAM_HOST
        log("ACCEPT", addr, f"SNI: {sni}")

        # 2. Terminate TLS with our fake cert (cam side)
        client_tls = server_ctx.wrap_socket(client_sock, server_side=True)
        log("ACCEPT", addr, f"downstream TLS OK  {client_tls.cipher()}")

        # 3. Open TLS to the real upstream using the SNI
        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream_sock.settimeout(8)
        upstream_sock.connect((UPSTREAM_IP, UPSTREAM_PORT))
        upstream_tls = client_ctx.wrap_socket(upstream_sock, server_hostname=sni)
        log("UPSTRM", addr, f"connected to {UPSTREAM_IP}:{UPSTREAM_PORT} SNI={sni}  {upstream_tls.cipher()}")

        # 4. Read the cam's request, forward to upstream, read response, forward back.
        # HTTP/1.1 is request/response, so we can do a simple read-until-close or
        # read-until-double-crlf dance.
        client_tls.settimeout(5)
        req = b""
        while True:
            try:
                chunk = client_tls.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            req += chunk
            if b"\r\n\r\n" in req:
                # For GET requests with no body, we have the full request here
                if req.startswith((b"GET ", b"HEAD ", b"OPTIONS ", b"DELETE ")):
                    break
                # For POST/PUT, look for Content-Length or chunked
                break  # good enough for now; most CBS calls are GET

        log("REQ", addr, f"{len(req)}B cleartext:")
        print(req.decode("utf-8", errors="replace").rstrip(), flush=True)

        upstream_tls.sendall(req)
        upstream_tls.settimeout(8)

        resp = b""
        try:
            while True:
                chunk = upstream_tls.recv(8192)
                if not chunk:
                    break
                resp += chunk
                # stop at a reasonable size
                if len(resp) > 65536:
                    break
                # If we've seen the full content per Content-Length, break
                if b"\r\n\r\n" in resp:
                    head, body = resp.split(b"\r\n\r\n", 1)
                    lower = head.lower()
                    if b"content-length:" in lower:
                        try:
                            for line in lower.split(b"\r\n"):
                                if line.startswith(b"content-length:"):
                                    cl = int(line.split(b":", 1)[1].strip())
                                    if len(body) >= cl:
                                        raise StopIteration
                                    break
                        except StopIteration:
                            break
                        except Exception:
                            pass
        except StopIteration:
            pass
        except socket.timeout:
            pass

        log("RESP", addr, f"{len(resp)}B from upstream:")
        print(resp.decode("utf-8", errors="replace").rstrip(), flush=True)

        # Forward response to cam
        try:
            client_tls.sendall(resp)
            log("RESP", addr, "forwarded to cam")
        except Exception as e:
            log("RESP", addr, f"forward to cam failed: {e}")

    except ssl.SSLError as e:
        log("ERROR", addr, f"TLS: {e}")
    except socket.timeout:
        log("ERROR", addr, "socket timeout")
    except Exception as e:
        log("ERROR", addr, f"{type(e).__name__}: {e}")
    finally:
        for s in (client_tls, client_sock, upstream_tls, upstream_sock):
            try:
                if s:
                    s.close()
            except Exception:
                pass


def main() -> None:
    # Server context for downstream (cam-facing) — use our fake cert
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    server_ctx.set_ciphers("ALL:@SECLEVEL=0")

    # Client context for upstream (cloud-facing) — validate normally.
    # Use the default CA bundle; SNI must match or the real cloud will reject.
    client_ctx = ssl.create_default_context()
    client_ctx.check_hostname = True
    client_ctx.verify_mode = ssl.CERT_REQUIRED

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("", LISTEN_PORT))
    srv.listen(16)
    print(f"[{ts()}] MITM CBS TLS proxy listening on :{LISTEN_PORT}", flush=True)
    print(f"[{ts()}] upstream: {UPSTREAM_HOST} → {UPSTREAM_IP}:{UPSTREAM_PORT}", flush=True)

    while True:
        try:
            conn, addr = srv.accept()
        except KeyboardInterrupt:
            print(f"[{ts()}] stopping")
            return
        t = threading.Thread(target=handle, args=(conn, addr, server_ctx, client_ctx), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
