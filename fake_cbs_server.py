#!/usr/bin/env python3
"""
Fake CBS (control backend service) TLS server, v0.1

Binds TCP/8443 (unprivileged; the UDM should port-rewrite :443 → :8443 for
cam traffic) and accepts any inbound connection. Presents a self-signed TLS
cert and tries to complete the handshake.

Three layers of logging, each conditional on how far the cam's TLS client
gets:

1. RAW    — every accepted TCP connection and the first bytes received
            before TLS handshake completion. We always see at least the
            ClientHello (which gives us SNI and cipher info).
2. TLS    — if the handshake succeeds (meaning the cam doesn't cert-pin), we
            log the application-layer request. For CBS this should be an
            HTTP GET /index.html?... with the cam's session parameters.
3. REPLY  — we respond with a canned HTTP response that looks like what the
            real CBS server would return (empty for now; we'll fill in once
            we see what the cam wants).

On cert mismatch the cam will probably abort the handshake. That's still
useful — we get to see the ClientHello and SNI, which tells us whether the
cam performs any custom validation.
"""
from __future__ import annotations

import socket
import ssl
import struct
import sys
import threading
import tempfile
import subprocess
from datetime import datetime
from pathlib import Path

PORT = 8443
BIND = ""

# Precomputed self-signed cert with CN=*.hapseemate.cn and SAN covering the
# hostnames the cam expects. Regenerated on first run.
CERT_DIR = Path("/tmp/cam-listen/fake-cbs-certs")


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(tag: str, addr: tuple, msg: str) -> None:
    print(f"[{ts()}] {tag:<6} {addr[0]}:{addr[1]:<5}  {msg}", flush=True)


# Canned JSON responses by endpoint. We don't know the real schemas, so we
# guess at plausible "success with no data" envelopes based on the CBS log
# strings we extracted from libCBSClient.so. Tune per endpoint as we see
# which ones the cam accepts (retry cadence drop = accepted).
def _pick_response_for(request_line: str) -> str:
    path = ""
    if request_line.startswith(("GET ", "POST ")):
        try:
            path = request_line.split(" ", 2)[1].split("?", 1)[0]
        except IndexError:
            pass
    if "didBindUserId" in path:
        # "No existing binding" — tells the cam no user account is bound yet.
        # If the cam then tries a different endpoint, we know we advanced.
        return '{"code":0,"msg":"success","data":{"bound":false,"userId":null}}'
    # Default envelope with success code.
    return '{"code":0,"msg":"success","data":null}'


def generate_cert() -> tuple[Path, Path]:
    """Generate a self-signed cert covering the cam's expected hostnames.
    Uses openssl CLI (pre-installed on macOS) so we don't need cryptography pkg."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    cert = CERT_DIR / "server.crt"
    key = CERT_DIR / "server.key"
    if cert.exists() and key.exists():
        return cert, key

    cfg = CERT_DIR / "openssl.cnf"
    cfg.write_text(
        """
[req]
distinguished_name = req_dn
x509_extensions = v3_req
prompt = no

[req_dn]
CN = *.hapseemate.cn

[v3_req]
subjectAltName = @san

[san]
DNS.1 = *.hapseemate.cn
DNS.2 = hapseemate.cn
DNS.3 = user.hapseemate.cn
DNS.4 = *.cloudbirds.cn
DNS.5 = *.hapsee.cn
DNS.6 = *.dayunlinks.cn
DNS.7 = dayunlinks.cn
DNS.8 = *.philipsiot.com
DNS.9 = philipsiot.com
DNS.10 = birds-public.philipsiot.com
"""
    )
    subprocess.run(
        [
            "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
            "-days", "3650",
            "-keyout", str(key), "-out", str(cert),
            "-config", str(cfg),
        ],
        check=True, capture_output=True,
    )
    return cert, key


def parse_client_hello(data: bytes) -> dict:
    """Minimal TLS ClientHello parser — just enough to extract SNI."""
    out: dict = {"bytes_seen": len(data)}
    if len(data) < 5 or data[0] != 0x16:  # not a TLS handshake record
        return out
    out["record_type"] = "handshake"
    rec_len = int.from_bytes(data[3:5], "big")
    out["record_len"] = rec_len
    body = data[5:5 + rec_len]
    if not body or body[0] != 0x01:
        return out  # not ClientHello
    out["is_client_hello"] = True
    # Walk past: handshake type(1) + length(3) + version(2) + random(32)
    i = 1 + 3 + 2 + 32
    if i >= len(body):
        return out
    sid_len = body[i]; i += 1 + sid_len
    if i + 2 > len(body):
        return out
    cs_len = int.from_bytes(body[i:i+2], "big"); i += 2 + cs_len
    if i + 1 > len(body):
        return out
    comp_len = body[i]; i += 1 + comp_len
    if i + 2 > len(body):
        return out
    ext_len = int.from_bytes(body[i:i+2], "big"); i += 2
    ext_end = i + ext_len
    while i + 4 <= ext_end:
        ext_type = int.from_bytes(body[i:i+2], "big")
        ext_data_len = int.from_bytes(body[i+2:i+4], "big")
        ext_data = body[i+4:i+4+ext_data_len]
        i += 4 + ext_data_len
        if ext_type == 0x00 and len(ext_data) > 5:  # server_name
            # list_len(2) + type(1) + name_len(2) + name
            name_len = int.from_bytes(ext_data[3:5], "big")
            out["sni"] = ext_data[5:5+name_len].decode("ascii", errors="replace")
    return out


def handle_conn(sock: socket.socket, addr: tuple, ctx: ssl.SSLContext) -> None:
    log("RAW", addr, "accepted")
    try:
        # Peek at the first bytes BEFORE wrapping TLS, so we always see the
        # ClientHello even if the handshake later fails.
        sock.settimeout(3)
        peek = sock.recv(1024, socket.MSG_PEEK)
        parsed = parse_client_hello(peek)
        log("RAW", addr, f"ClientHello {parsed}")
        log("RAW", addr, f"first32hex: {peek[:32].hex()}")

        tls_sock = ctx.wrap_socket(sock, server_side=True)
        log("TLS", addr, f"handshake OK  cipher={tls_sock.cipher()}")

        # Read any application-layer data the cam sends
        data = b""
        try:
            while True:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 8192 or b"\r\n\r\n" in data:
                    break
        except socket.timeout:
            pass

        if data:
            head = data[:1024]
            log("TLS", addr, f"app data ({len(data)}B):")
            try:
                print(head.decode("utf-8", errors="replace"), flush=True)
            except Exception:
                print(head.hex(), flush=True)

        # Build a response tailored to the endpoint the cam requested. The
        # real hapseemate API returns JSON envelopes with fields like
        # code/msg/data; without the Spring source we guess at values that
        # indicate "no error, no binding yet" which should let the cam
        # advance past this step without succeeding at user-account lookup.
        request_line = data.split(b"\r\n", 1)[0].decode("ascii", errors="replace") if data else ""
        body_json = _pick_response_for(request_line)
        body_bytes = body_json.encode()
        reply = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json; charset=utf-8\r\n"
            b"Server: nginx/1.18.0\r\n"
            b"Content-Length: " + str(len(body_bytes)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        ) + body_bytes
        try:
            tls_sock.sendall(reply)
            log("TLS", addr, f"sent 200 OK ({len(body_bytes)}B) {body_json}")
        except Exception as e:
            log("TLS", addr, f"send failed: {e}")
        tls_sock.close()
    except ssl.SSLError as e:
        log("RAW", addr, f"TLS handshake failed: {e}")
    except Exception as e:
        log("RAW", addr, f"handler error: {type(e).__name__}: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main() -> None:
    cert, key = generate_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    # Be permissive — accept whatever cipher/version the cam offers
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers("ALL:@SECLEVEL=0")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND, PORT))
    srv.listen(16)
    print(f"[{ts()}] fake CBS TLS server on TCP/{PORT}  (cert: {cert})", flush=True)

    while True:
        try:
            conn, addr = srv.accept()
        except KeyboardInterrupt:
            print(f"[{ts()}] stopping")
            return
        t = threading.Thread(target=handle_conn, args=(conn, addr, ctx), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
