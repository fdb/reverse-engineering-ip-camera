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

Block 2 multi-cloud extension (2026-04-15):
  - SNI suffix allowlist replaces hardcoded upstream host/IP.
  - Stub DNS resolver points directly at 1.1.1.1:53, bypassing the Mac's
    system resolver (which goes through the UDM sinkhole).
  - Per-connection structured capture dumps as JSON under captures/ota/.
"""
from __future__ import annotations

import base64
import json
import os
import random
import socket
import ssl
import struct
import sys
import threading
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

LISTEN_PORT = 8443

# SNI suffix allowlist. Matches are dot-aligned and case-insensitive:
# "foo.hapseemate.cn" matches ".hapseemate.cn", but "evilhapseemate.cn" does
# not. Bare "hapseemate.cn" also matches (the suffix check strips the leading
# dot for the exact-host case).
UPSTREAM_SNI_ALLOWLIST = (
    ".hapseemate.cn",
    ".cloudbirds.cn",
    ".dayunlinks.cn",
    ".philipsiot.com",
)
UPSTREAM_PORT = 443

CERT_DIR = Path("/tmp/cam-listen/fake-cbs-certs")
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"

# Capture destination. Absolute path derived from __file__ so the proxy works
# regardless of CWD. One timestamped subdir per proxy process.
REPO_ROOT = Path(__file__).resolve().parent
CAPTURE_ROOT = REPO_ROOT / "captures" / "ota"
PROXY_START_ISO = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
CAPTURE_DIR = CAPTURE_ROOT / PROXY_START_ISO

# Per-proxy global counter for exchange IDs, shared across threads.
_counter_lock = threading.Lock()
_exchange_counter = 0

# Lazy-create the capture dir on first accepted connection.
_capture_dir_ready = False
_capture_dir_lock = threading.Lock()


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(tag: str, addr: tuple, msg: str) -> None:
    print(f"[{ts()}] {tag:<8} {addr[0]}:{addr[1]:<5}  {msg}", flush=True)


# ---------------------------------------------------------------------------
# Stub DNS resolver (1.1.1.1)
# ---------------------------------------------------------------------------
#
# The Mac's system resolver routes through the UDM's dnsmasq, which is
# sinkholing our target hostnames to 203.0.113.37. Using it would make this
# proxy connect to its own sinkhole. We hand-roll a minimal DNS-over-UDP
# client against 1.1.1.1 to avoid a dnspython dependency.

_DNS_SERVER = ("1.1.1.1", 53)
_resolve_cache: dict[str, str] = {}
_resolve_cache_lock = threading.Lock()


def _encode_qname(hostname: str) -> bytes:
    out = bytearray()
    for label in hostname.rstrip(".").split("."):
        if not label:
            raise ValueError(f"empty label in hostname: {hostname!r}")
        b = label.encode("ascii")
        if len(b) > 63:
            raise ValueError(f"label too long: {label!r}")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _read_name(msg: bytes, off: int) -> int:
    """Advance past a DNS name at offset off, honoring pointer compression.
    Returns the new offset *after* the name. We don't need the decoded value."""
    while True:
        if off >= len(msg):
            raise ValueError("truncated name")
        length = msg[off]
        if length == 0:
            return off + 1
        if (length & 0xC0) == 0xC0:
            # Two-byte pointer. Done.
            return off + 2
        off += 1 + length


def resolve_a(hostname: str, timeout: float = 5.0) -> str:
    """Resolve hostname → first A-record IPv4, via 1.1.1.1:53.

    Caches results for the lifetime of the process (no TTL eviction).
    Raises on any failure.
    """
    hostname = hostname.rstrip(".").lower()
    with _resolve_cache_lock:
        cached = _resolve_cache.get(hostname)
    if cached:
        return cached

    txid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(hostname) + struct.pack(">HH", 1, 1)  # A, IN
    query = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(query, _DNS_SERVER)
        resp, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    if len(resp) < 12:
        raise ValueError(f"short DNS response ({len(resp)}B)")
    rtxid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", resp[:12])
    if rtxid != txid:
        raise ValueError(f"txid mismatch {rtxid} != {txid}")
    rcode = flags & 0x000F
    if rcode != 0:
        raise ValueError(f"DNS rcode {rcode} for {hostname}")
    if an == 0:
        raise ValueError(f"no answers for {hostname}")

    # Skip the question section.
    off = 12
    for _ in range(qd):
        off = _read_name(resp, off)
        off += 4  # QTYPE + QCLASS

    # Walk the answer section looking for an A record.
    for _ in range(an):
        off = _read_name(resp, off)
        if off + 10 > len(resp):
            raise ValueError("truncated RR header")
        rtype, rclass, _ttl, rdlen = struct.unpack(">HHIH", resp[off:off + 10])
        off += 10
        if off + rdlen > len(resp):
            raise ValueError("truncated RDATA")
        if rtype == 1 and rclass == 1 and rdlen == 4:
            ip = ".".join(str(b) for b in resp[off:off + 4])
            with _resolve_cache_lock:
                _resolve_cache[hostname] = ip
            return ip
        off += rdlen

    raise ValueError(f"no A record in answer for {hostname}")


# ---------------------------------------------------------------------------
# SNI allowlist check
# ---------------------------------------------------------------------------

def sni_allowed(sni: str) -> bool:
    if not sni:
        return False
    s = sni.lower().rstrip(".")
    for suffix in UPSTREAM_SNI_ALLOWLIST:
        suf = suffix.lower()
        # Allow both "foo.hapseemate.cn" and bare "hapseemate.cn"
        if s.endswith(suf):
            return True
        if suf.startswith(".") and s == suf[1:]:
            return True
    return False


# ---------------------------------------------------------------------------
# TLS ClientHello SNI parser (unchanged)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Capture helpers
# ---------------------------------------------------------------------------

def _ensure_capture_dir() -> None:
    global _capture_dir_ready
    with _capture_dir_lock:
        if _capture_dir_ready:
            return
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
        _capture_dir_ready = True


def _next_exchange_id() -> int:
    global _exchange_counter
    with _counter_lock:
        _exchange_counter += 1
        return _exchange_counter


def _decode_body_text(body: bytes) -> Optional[str]:
    """Return body decoded as UTF-8 iff valid AND mostly printable, else None."""
    if not body:
        return ""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Treat control chars (except \t \n \r) as non-printable.
    printable = sum(
        1 for ch in text if ch.isprintable() or ch in "\t\n\r"
    )
    if printable / max(1, len(text)) < 0.95:
        return None
    return text


def _parse_http_headers(head: bytes) -> tuple[list[str], dict[str, str]]:
    """Parse the first line + headers out of a raw HTTP head block.
    Returns (start_line_tokens, headers_dict). Empty tokens on failure."""
    try:
        text = head.decode("iso-8859-1")
    except Exception:
        return [], {}
    lines = text.split("\r\n")
    if not lines:
        return [], {}
    start_tokens = lines[0].split(" ", 2)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()
    return start_tokens, headers


def _parse_http_message(raw: bytes, is_request: bool) -> dict:
    """Parse a raw HTTP/1.x message into structured fields. Returns dict with
    at least body_b64 populated; structured fields are None on ambiguous
    inputs (HTTP/2, unusual framing). Never raises."""
    out: dict = {
        "headers": None,
        "body_b64": base64.b64encode(raw).decode("ascii") if raw else "",
        "body_text": None,
    }
    if is_request:
        out.update(method=None, path=None, http_version=None)
    else:
        out.update(status_code=None, reason=None, http_version=None)

    if not raw:
        return out

    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        # No complete header block — dump raw only.
        return out

    head = raw[:sep]
    body = raw[sep + 4:]
    tokens, headers = _parse_http_headers(head)
    if not tokens or not headers and len(tokens) < 2:
        return out

    # Honor Content-Length / Transfer-Encoding: chunked. We relied on the
    # caller to have already read until EOF or CL-bounded, so we mostly
    # just record what's there. De-chunking is best-effort.
    te = headers.get("Transfer-Encoding", "").lower()
    if "chunked" in te:
        body = _dechunk(body)

    out["headers"] = headers
    out["body_b64"] = base64.b64encode(body).decode("ascii") if body else ""
    out["body_text"] = _decode_body_text(body)

    if is_request:
        if len(tokens) >= 3:
            out["method"] = tokens[0]
            out["path"] = tokens[1]
            out["http_version"] = tokens[2]
    else:
        if len(tokens) >= 2:
            out["http_version"] = tokens[0]
            try:
                out["status_code"] = int(tokens[1])
            except ValueError:
                out["status_code"] = None
            out["reason"] = tokens[2] if len(tokens) >= 3 else ""

    return out


def _dechunk(body: bytes) -> bytes:
    """Best-effort HTTP chunked decode. Returns the original body on any
    parse error — we'd rather keep the raw bytes than drop data."""
    out = bytearray()
    i = 0
    try:
        while i < len(body):
            crlf = body.find(b"\r\n", i)
            if crlf < 0:
                return bytes(body)
            size_line = body[i:crlf].split(b";", 1)[0].strip()
            if not size_line:
                i = crlf + 2
                continue
            size = int(size_line, 16)
            i = crlf + 2
            if size == 0:
                return bytes(out)
            if i + size > len(body):
                return bytes(body)
            out.extend(body[i:i + size])
            i += size + 2  # skip trailing CRLF
        return bytes(out)
    except Exception:
        return bytes(body)


def dump_exchange(
    exchange_id: int,
    sni: str,
    upstream_ip: Optional[str],
    client_addr: tuple,
    req_raw: bytes,
    resp_raw: bytes,
    req_ts: str,
    resp_ts: str,
) -> None:
    """Write the request/response JSON pair for this exchange. Never raises."""
    try:
        _ensure_capture_dir()
        partial = not req_raw or not resp_raw
        n = f"{exchange_id:04d}"

        req_obj = {
            "timestamp": req_ts,
            "sni": sni,
            "upstream_ip": upstream_ip,
            "client_addr": [client_addr[0], client_addr[1]],
        }
        req_obj.update(_parse_http_message(req_raw, is_request=True))
        if partial:
            req_obj["partial"] = True

        resp_obj = {"timestamp": resp_ts}
        resp_obj.update(_parse_http_message(resp_raw, is_request=False))
        if partial:
            resp_obj["partial"] = True

        req_path = CAPTURE_DIR / f"{n}-request.json"
        resp_path = CAPTURE_DIR / f"{n}-response.json"
        req_path.write_text(json.dumps(req_obj, indent=2, ensure_ascii=False))
        resp_path.write_text(json.dumps(resp_obj, indent=2, ensure_ascii=False))
        log("CAPTURE", client_addr, f"wrote {req_path.name} + {resp_path.name}"
            + (" (partial)" if partial else ""))
    except Exception as e:
        log("CAPTURE", client_addr, f"dump failed: {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------

def handle(
    client_sock: socket.socket,
    addr: tuple,
    server_ctx: ssl.SSLContext,
    client_ctx: ssl.SSLContext,
) -> None:
    log("ACCEPT", addr, "new connection")
    _ensure_capture_dir()
    exchange_id = _next_exchange_id()

    upstream_sock = None
    upstream_tls = None
    client_tls = None

    sni: str = ""
    upstream_ip: Optional[str] = None
    req_raw = b""
    resp_raw = b""
    req_ts = ""
    resp_ts = ""

    try:
        # 1. Peek at ClientHello to extract SNI (pre-termination).
        client_sock.settimeout(5)
        peek = client_sock.recv(2048, socket.MSG_PEEK)
        sni = parse_sni(peek) or ""
        log("ACCEPT", addr, f"SNI: {sni!r}")

        # 2. SNI allowlist gate.
        if not sni_allowed(sni):
            log("REJECT", addr, f"REJECT unknown SNI: {sni!r}")
            return

        # 3. Resolve upstream via stub resolver (bypasses UDM sinkhole).
        try:
            upstream_ip = resolve_a(sni)
        except Exception as e:
            log("RESOLVE", addr, f"failed for {sni}: {type(e).__name__}: {e}")
            return
        log("RESOLVE", addr, f"{sni} → {upstream_ip}")

        # 4. Terminate TLS with our fake cert (cam side).
        client_tls = server_ctx.wrap_socket(client_sock, server_side=True)
        log("ACCEPT", addr, f"downstream TLS OK  {client_tls.cipher()}")

        # 5. Open TLS to the real upstream using the resolved IP + SNI.
        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream_sock.settimeout(8)
        upstream_sock.connect((upstream_ip, UPSTREAM_PORT))
        upstream_tls = client_ctx.wrap_socket(upstream_sock, server_hostname=sni)
        log("UPSTRM", addr, f"connected to {upstream_ip}:{UPSTREAM_PORT} SNI={sni}  {upstream_tls.cipher()}")

        # 6. Read the cam's request, forward to upstream, read response, forward back.
        client_tls.settimeout(5)
        req_ts = datetime.now().isoformat()
        while True:
            try:
                chunk = client_tls.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            req_raw += chunk
            if b"\r\n\r\n" in req_raw:
                if req_raw.startswith((b"GET ", b"HEAD ", b"OPTIONS ", b"DELETE ")):
                    break
                break  # good enough for now; most CBS calls are GET

        log("REQ", addr, f"{len(req_raw)}B cleartext:")
        print(req_raw.decode("utf-8", errors="replace").rstrip(), flush=True)

        upstream_tls.sendall(req_raw)
        upstream_tls.settimeout(8)

        resp_ts = datetime.now().isoformat()
        try:
            while True:
                chunk = upstream_tls.recv(8192)
                if not chunk:
                    break
                resp_raw += chunk
                if len(resp_raw) > 65536:
                    break
                if b"\r\n\r\n" in resp_raw:
                    head, body = resp_raw.split(b"\r\n\r\n", 1)
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

        log("RESP", addr, f"{len(resp_raw)}B from upstream:")
        print(resp_raw.decode("utf-8", errors="replace").rstrip(), flush=True)

        try:
            client_tls.sendall(resp_raw)
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
        # Only dump if we got past the SNI gate (sni allowed). Otherwise
        # there's nothing interesting — a rejected handshake would just
        # pollute captures/ota with empties.
        if sni and sni_allowed(sni):
            if not req_ts:
                req_ts = datetime.now().isoformat()
            if not resp_ts:
                resp_ts = datetime.now().isoformat()
            dump_exchange(
                exchange_id=exchange_id,
                sni=sni,
                upstream_ip=upstream_ip,
                client_addr=addr,
                req_raw=req_raw,
                resp_raw=resp_raw,
                req_ts=req_ts,
                resp_ts=resp_ts,
            )


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
    print(f"[{ts()}] SNI allowlist: {', '.join(UPSTREAM_SNI_ALLOWLIST)}", flush=True)
    print(f"[{ts()}] capture dir: {CAPTURE_DIR}", flush=True)

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
