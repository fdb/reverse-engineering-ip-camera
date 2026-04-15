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
import signal
import socket
import ssl
import struct
import sys
import threading
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

# Default TLS listen port. Can be overridden via env MITM_CBS_LISTEN_PORT
# for testing (so test harnesses don't collide with the production :8443
# instance). Per spec §5, this single port also handles plain HTTP via
# first-byte sniffing.
LISTEN_PORT = int(os.environ.get("MITM_CBS_LISTEN_PORT", "8443"))

# Legacy SNI suffix allowlist from Session 6. Kept as a hard-coded default
# that apply_veto() falls back on if veto.yaml is missing or malformed, so
# the proxy fails safe to "forward known-good hosts, default-capture
# everything else" even without config. New policy lives in veto.yaml.
UPSTREAM_SNI_ALLOWLIST = (
    ".hapseemate.cn",
    ".cloudbirds.cn",
    ".dayunlinks.cn",
    ".philipsiot.com",
)
UPSTREAM_PORT = 443

# Per-connection raw dump size cap (spec §3). Applied independently to
# client-side and upstream-side dump files.
RAW_DUMP_MAX_BYTES = 1 * 1024 * 1024  # 1 MB

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


# ---------------------------------------------------------------------------
# Veto policy config (captures/veto.yaml)
# ---------------------------------------------------------------------------
#
# Loaded at startup, replaced on SIGHUP. Shape after load:
#   {
#     "default_mode": "capture",
#     "policies": [
#       {"match_suffix": ".hapseemate.cn", "mode": "forward", "note": "..."},
#       ...
#     ],
#   }
#
# Accessed by worker threads — guarded by a lock; readers snapshot the
# whole dict under the lock and then release before doing per-connection
# work.

VETO_CONFIG_PATH = REPO_ROOT / "captures" / "veto.yaml"

_VALID_MODES = ("forward", "capture", "drop")
_veto_config_lock = threading.Lock()
_veto_config: dict = {
    "default_mode": "capture",
    "policies": [],
}


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
# Minimal YAML parser for veto.yaml
# ---------------------------------------------------------------------------
#
# We intentionally avoid a PyYAML dependency — the proxy should run on
# a stock CPython install. The format we accept is exactly the shape of
# the initial veto.yaml shipped in the repo:
#
#   default_mode: capture
#   policies:
#     - match_suffix: .foo.cn
#       mode: forward
#       note: "Some note"
#
# Blank lines and `#`-prefixed comments are ignored. Quoted strings
# (single or double) have quotes stripped. No nested mappings beyond
# what the schema requires. If the file violates the expected shape,
# the caller falls back to the last good config.


def _parse_veto_yaml(text: str) -> dict:
    result: dict = {"default_mode": "capture", "policies": []}
    current_policy: Optional[dict] = None
    in_policies = False

    def unquote(v: str) -> str:
        v = v.strip()
        if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
            return v[1:-1]
        return v

    for raw_line in text.splitlines():
        # Strip trailing comments only when `#` is preceded by whitespace
        # or at the start of the line — preserves `#` inside quoted values.
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        # Simple trailing-comment strip: a " #" outside quotes.
        if " #" in line:
            # naive but sufficient for our schema — no embedded " #" in values
            stripped = line
            in_q: Optional[str] = None
            cut = None
            for i, ch in enumerate(stripped):
                if in_q:
                    if ch == in_q:
                        in_q = None
                elif ch in ("'", '"'):
                    in_q = ch
                elif ch == "#" and i > 0 and stripped[i - 1] == " ":
                    cut = i
                    break
            if cut is not None:
                line = stripped[:cut].rstrip()

        indent = len(line) - len(line.lstrip(" "))
        content = line.lstrip(" ")

        if indent == 0:
            # Top-level key: value
            if current_policy is not None:
                result["policies"].append(current_policy)
                current_policy = None
            in_policies = False
            if ":" not in content:
                continue
            key, _, val = content.partition(":")
            key = key.strip()
            val = val.strip()
            if key == "policies":
                in_policies = True
            elif key == "default_mode":
                result["default_mode"] = unquote(val)
            # Other top-level keys silently ignored.
            continue

        # Indented — must be inside policies list.
        if not in_policies:
            continue

        if content.startswith("- "):
            # New list item. Commit previous.
            if current_policy is not None:
                result["policies"].append(current_policy)
            current_policy = {}
            content = content[2:].strip()
            if ":" in content:
                key, _, val = content.partition(":")
                current_policy[key.strip()] = unquote(val)
            continue

        # Continuation of current_policy.
        if current_policy is None:
            continue
        if ":" not in content:
            continue
        key, _, val = content.partition(":")
        current_policy[key.strip()] = unquote(val)

    if current_policy is not None:
        result["policies"].append(current_policy)

    # Validate policy shape; drop any malformed entry.
    clean_policies = []
    for p in result["policies"]:
        if not isinstance(p, dict):
            continue
        suffix = p.get("match_suffix")
        mode = p.get("mode")
        if not suffix or mode not in _VALID_MODES:
            continue
        clean_policies.append({
            "match_suffix": suffix,
            "mode": mode,
            "note": p.get("note", ""),
        })
    result["policies"] = clean_policies
    if result.get("default_mode") not in _VALID_MODES:
        result["default_mode"] = "capture"
    return result


def load_veto_config(path: Path = VETO_CONFIG_PATH) -> Optional[dict]:
    """Re-read the veto policy file from disk. Returns the parsed dict on
    success, None on any failure (caller keeps the previously loaded config)."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[{ts()}] veto: read error: {type(e).__name__}: {e}", flush=True)
        return None
    try:
        parsed = _parse_veto_yaml(text)
    except Exception as e:
        print(f"[{ts()}] veto: parse error: {type(e).__name__}: {e}", flush=True)
        return None
    return parsed


def _install_veto_config(parsed: dict) -> None:
    with _veto_config_lock:
        global _veto_config
        _veto_config = parsed
    n = len(parsed["policies"])
    print(
        f"[{ts()}] veto: loaded default={parsed['default_mode']} with {n} policies",
        flush=True,
    )
    for p in parsed["policies"]:
        print(f"[{ts()}] veto:   {p['mode']:<7} {p['match_suffix']}", flush=True)


def reload_veto_config() -> None:
    parsed = load_veto_config()
    if parsed is None:
        print(f"[{ts()}] veto: reload kept previous config", flush=True)
        return
    _install_veto_config(parsed)


def _suffix_match(sni: str, suffix: str) -> bool:
    """Dot-aligned suffix match. Identical semantics to the Session 6
    sni_allowed() helper: `.foo.cn` matches `x.foo.cn` and `foo.cn`, but
    not `evilfoo.cn`."""
    if not sni or not suffix:
        return False
    s = sni.lower().rstrip(".")
    suf = suffix.lower()
    if suf.startswith("."):
        return s.endswith(suf) or s == suf[1:]
    # Non-leading-dot suffixes match as a plain right-anchored host match
    # with a dot boundary (so `app-measurement.com` matches
    # `www.app-measurement.com` and `app-measurement.com` itself).
    return s == suf or s.endswith("." + suf)


def apply_veto(sni: str) -> tuple[str, str]:
    """Return (mode, note) for the given SNI under the current policy.

    Thread-safe: snapshots the config under the lock, then evaluates the
    snapshot without holding the lock.
    """
    with _veto_config_lock:
        cfg = _veto_config
        policies = list(cfg["policies"])
        default_mode = cfg["default_mode"]
    for p in policies:
        if _suffix_match(sni, p["match_suffix"]):
            return p["mode"], p.get("note", "")
    return default_mode, "(default)"


# ---------------------------------------------------------------------------
# SNI allowlist check (legacy Session 6 helper, kept for telemetry/compat)
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


class RawDump:
    """Per-connection raw byte dump file with a 1MB size cap.

    Not shared across threads by design — each handle belongs to exactly
    one connection handler. No locking needed. The cap is applied
    independently to each instance (so client + upstream dumps each get
    their own 1MB budget).
    """

    def __init__(self, path: Path, client_addr: tuple, label: str) -> None:
        self.path = path
        self._addr = client_addr
        self._label = label
        self._written = 0
        self._truncated = False
        self._fh = None
        try:
            self._fh = open(path, "wb")
        except Exception as e:
            log("RAWERR", client_addr, f"open {path.name}: {e}")

    def write(self, data: bytes) -> None:
        if not data or self._fh is None or self._truncated:
            return
        room = RAW_DUMP_MAX_BYTES - self._written
        if room <= 0:
            self._mark_truncated()
            return
        try:
            if len(data) <= room:
                self._fh.write(data)
                self._written += len(data)
            else:
                self._fh.write(data[:room])
                self._written += room
                self._mark_truncated()
        except Exception as e:
            log("RAWERR", self._addr, f"write {self.path.name}: {e}")

    def _mark_truncated(self) -> None:
        if self._truncated or self._fh is None:
            return
        self._truncated = True
        try:
            self._fh.write(b"\n[TRUNCATED AT 1048576 BYTES]\n")
        except Exception:
            pass
        log("TRUNCATE", self._addr, f"{self.path.name} hit {RAW_DUMP_MAX_BYTES}B cap")

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.flush()
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    @property
    def bytes_written(self) -> int:
        return self._written


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
# Canned responses
# ---------------------------------------------------------------------------

CANNED_504 = (
    b"HTTP/1.1 504 Gateway Timeout\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)


def _rst_close(sock: socket.socket) -> None:
    """Close with SO_LINGER {1,0} so the peer sees a TCP RST."""
    try:
        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_LINGER,
            struct.pack("ii", 1, 0),
        )
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


def _read_http_request(sock: socket.socket, initial: bytes = b"") -> bytes:
    """Read an HTTP/1.x request head (up through the \r\n\r\n boundary).
    Best-effort — returns whatever we managed to read even on timeout.

    Does not read the body beyond what arrived with the headers. For the
    capture-mode use case we only need the request line + headers to log
    what the client was trying to do."""
    buf = bytearray(initial)
    sock.settimeout(5)
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        except Exception:
            break
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _extract_http_host(req_head: bytes) -> str:
    for line in req_head.split(b"\r\n"):
        if not line:
            break
        if b":" not in line:
            continue
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"host":
            return v.strip().decode("ascii", errors="replace")
    return ""


def _extract_http_start_line(req_head: bytes) -> str:
    nl = req_head.find(b"\r\n")
    if nl < 0:
        return req_head.decode("latin-1", errors="replace")
    return req_head[:nl].decode("latin-1", errors="replace")


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
    n = f"{exchange_id:04d}"

    # Per-connection raw dumps (client side always opened; upstream only
    # written to in forward mode). File handles are NOT shared across
    # threads — each RawDump instance is local to this handler.
    client_raw = RawDump(CAPTURE_DIR / f"{n}-client.bin", addr, "client")
    upstream_raw = RawDump(CAPTURE_DIR / f"{n}-upstream.bin", addr, "upstream")
    plaintext_client_raw = RawDump(
        CAPTURE_DIR / f"{n}-plaintext-client.bin", addr, "plaintext-client"
    )
    plaintext_upstream_raw = RawDump(
        CAPTURE_DIR / f"{n}-plaintext-upstream.bin", addr, "plaintext-upstream"
    )

    upstream_sock = None
    upstream_tls = None
    client_tls = None

    sni: str = ""
    upstream_ip: Optional[str] = None
    req_raw = b""
    resp_raw = b""
    req_ts = ""
    resp_ts = ""
    mode: str = ""

    try:
        client_sock.settimeout(5)

        # --------------------------------------------------------------
        # First-byte sniff: TLS handshake (0x16) vs plain ASCII HTTP.
        # --------------------------------------------------------------
        try:
            first_peek = client_sock.recv(1, socket.MSG_PEEK)
        except Exception as e:
            log("ERROR", addr, f"first-byte peek failed: {e}")
            return
        if not first_peek:
            log("ACCEPT", addr, "empty connection, closed")
            return

        first_byte = first_peek[0]
        if first_byte == 0x16:
            proto = "tls"
        elif 0x41 <= first_byte <= 0x5A or 0x61 <= first_byte <= 0x7A:
            proto = "http"
        else:
            log("DROP", addr, f"unknown first byte 0x{first_byte:02x}, closing")
            return

        log("SNIFF", addr, f"first_byte=0x{first_byte:02x} proto={proto}")

        # ==============================================================
        # Plain HTTP branch (§5 unified port)
        # ==============================================================
        if proto == "http":
            head = _read_http_request(client_sock)
            client_raw.write(head)
            plaintext_client_raw.write(head)
            host = _extract_http_host(head)
            start_line = _extract_http_start_line(head)
            sni = host  # reuse the "sni" field for logging semantics
            log("REQ", addr, f"HTTP {start_line} Host={host!r}")

            mode, note = apply_veto(host)
            log("VETO", addr, f"mode={mode} host={host} note={note}")

            if mode == "drop":
                _rst_close(client_sock)
                client_sock = None  # don't re-close in finally
                return

            if mode == "forward":
                # Attempt to forward plain HTTP upstream. On any failure
                # fall back to capture mode (so the cam still gets a 504
                # instead of a dead socket).
                try:
                    if not host:
                        raise ValueError("no Host header")
                    upstream_ip = resolve_a(host)
                    log("RESOLVE", addr, f"{host} → {upstream_ip}")
                    upstream_sock = socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM
                    )
                    upstream_sock.settimeout(8)
                    upstream_sock.connect((upstream_ip, 80))
                except Exception as e:
                    log("FORWARD_FAIL", addr, f"→ capture: {type(e).__name__}: {e}")
                    mode = "capture"

                if mode == "forward":
                    try:
                        upstream_sock.sendall(head)
                        up_buf = bytearray()
                        upstream_sock.settimeout(8)
                        while True:
                            try:
                                chunk = upstream_sock.recv(8192)
                            except socket.timeout:
                                break
                            if not chunk:
                                break
                            up_buf.extend(chunk)
                            upstream_raw.write(chunk)
                            plaintext_upstream_raw.write(chunk)
                            if len(up_buf) > 256 * 1024:
                                break
                        resp_raw = bytes(up_buf)
                        try:
                            client_sock.sendall(resp_raw)
                        except Exception as e:
                            log("RESP", addr, f"forward-to-cam failed: {e}")
                        log("RESP", addr, f"forwarded {len(resp_raw)}B HTTP")
                    except Exception as e:
                        log("FORWARD_FAIL", addr, f"mid-stream: {e}")
                        mode = "capture"

            if mode == "capture":
                try:
                    client_sock.sendall(CANNED_504)
                    log("CANNED", addr, "504 Gateway Timeout → cam (HTTP)")
                except Exception as e:
                    log("CANNED", addr, f"send failed: {e}")

            req_raw = head
            return

        # ==============================================================
        # TLS branch
        # ==============================================================
        peek = client_sock.recv(2048, socket.MSG_PEEK)
        sni = parse_sni(peek) or ""
        log("ACCEPT", addr, f"SNI: {sni!r}")

        mode, note = apply_veto(sni)
        log("VETO", addr, f"mode={mode} sni={sni} note={note}")

        if mode == "drop":
            # Do NOT terminate TLS — just RST the underlying TCP socket
            # after the SNI has been read.
            _rst_close(client_sock)
            client_sock = None
            return

        # For forward mode, try the stub resolver BEFORE terminating
        # TLS. If resolution fails, fall back to capture mode so the cam
        # still gets a clean 504 instead of a dead handshake.
        if mode == "forward":
            try:
                upstream_ip = resolve_a(sni)
                log("RESOLVE", addr, f"{sni} → {upstream_ip}")
            except Exception as e:
                log(
                    "FORWARD_FAIL",
                    addr,
                    f"→ capture: resolve {sni}: {type(e).__name__}: {e}",
                )
                mode = "capture"

        # Terminate TLS with our fake cert (cam side). Wrap the raw
        # client socket into an SSLSocket — for raw-dump purposes we
        # can't capture the ciphertext and the plaintext from the same
        # wrapped socket, so we write plaintext to -plaintext-client.bin
        # and leave -client.bin empty for the TLS branch. (The TLS
        # keylog file makes ciphertext recovery possible offline.)
        try:
            client_tls = server_ctx.wrap_socket(client_sock, server_side=True)
            log("ACCEPT", addr, f"downstream TLS OK  {client_tls.cipher()}")
        except Exception as e:
            log("ERROR", addr, f"downstream TLS handshake: {e}")
            return

        # For forward mode, open upstream TLS now.
        if mode == "forward":
            try:
                upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                upstream_sock.settimeout(8)
                upstream_sock.connect((upstream_ip, UPSTREAM_PORT))
                upstream_tls = client_ctx.wrap_socket(
                    upstream_sock, server_hostname=sni
                )
                log(
                    "UPSTRM",
                    addr,
                    f"connected to {upstream_ip}:{UPSTREAM_PORT} SNI={sni}  "
                    f"{upstream_tls.cipher()}",
                )
            except Exception as e:
                log("FORWARD_FAIL", addr, f"→ capture: upstream TLS: {e}")
                mode = "capture"

        # Read the cam's request off the terminated TLS socket.
        client_tls.settimeout(5)
        req_ts = datetime.now().isoformat()
        while True:
            try:
                chunk = client_tls.recv(4096)
            except socket.timeout:
                break
            except Exception:
                break
            if not chunk:
                break
            req_raw += chunk
            plaintext_client_raw.write(chunk)
            if b"\r\n\r\n" in req_raw:
                break

        log("REQ", addr, f"{len(req_raw)}B cleartext {_extract_http_start_line(req_raw)!r}")

        if mode == "capture":
            try:
                client_tls.sendall(CANNED_504)
                log("CANNED", addr, "504 Gateway Timeout → cam (TLS)")
            except Exception as e:
                log("CANNED", addr, f"send failed: {e}")
            resp_ts = datetime.now().isoformat()
            return

        # Forward mode proper: send request upstream, relay response.
        try:
            upstream_tls.sendall(req_raw)
            upstream_tls.settimeout(8)
            resp_ts = datetime.now().isoformat()
            while True:
                try:
                    chunk = upstream_tls.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                resp_raw += chunk
                plaintext_upstream_raw.write(chunk)
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
        except Exception as e:
            log("FORWARD_FAIL", addr, f"upstream IO: {e}")

        log("RESP", addr, f"{len(resp_raw)}B from upstream")

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
        client_raw.close()
        upstream_raw.close()
        plaintext_client_raw.close()
        plaintext_upstream_raw.close()
        # Dump structured JSON only for exchanges where we actually got a
        # cleartext request (forward or capture TLS paths). Skip for drop
        # mode and for failed-handshake cases.
        if sni and mode in ("forward", "capture") and req_raw:
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
                resp_raw=resp_raw if mode == "forward" else CANNED_504,
                req_ts=req_ts,
                resp_ts=resp_ts,
            )


def _sighup_handler(signum, frame) -> None:
    print(f"[{ts()}] SIGHUP: reloading veto config", flush=True)
    reload_veto_config()


def main() -> None:
    # Load veto policy from disk (or fall back to default capture-all).
    parsed = load_veto_config()
    if parsed is None:
        print(
            f"[{ts()}] veto: {VETO_CONFIG_PATH} missing or unreadable — "
            f"using default-capture policy with legacy SNI allowlist",
            flush=True,
        )
        # Synthesize a default config from the legacy SNI allowlist so
        # the Session 6 behavior is preserved when veto.yaml is absent.
        parsed = {
            "default_mode": "capture",
            "policies": [
                {"match_suffix": s, "mode": "forward", "note": "legacy allowlist"}
                for s in UPSTREAM_SNI_ALLOWLIST
            ],
        }
    _install_veto_config(parsed)

    # SIGHUP → reload veto.yaml
    try:
        signal.signal(signal.SIGHUP, _sighup_handler)
    except (AttributeError, ValueError) as e:
        print(f"[{ts()}] SIGHUP handler not installed: {e}", flush=True)

    # Ensure the capture dir exists early so the TLS keylog file has a
    # home to live in.
    _ensure_capture_dir()

    # Server context for downstream (cam-facing) — use our fake cert
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    server_ctx.set_ciphers("ALL:@SECLEVEL=0")

    # Client context for upstream (cloud-facing) — validate normally.
    # Use the default CA bundle; SNI must match or the real cloud will reject.
    client_ctx = ssl.create_default_context()
    client_ctx.check_hostname = True
    client_ctx.verify_mode = ssl.CERT_REQUIRED

    # TLS key material logging (NSS keylog format) — so Wireshark can
    # decrypt the raw -client.bin / -upstream.bin dumps later. One
    # shared file per proxy session, appended to by both the server
    # and client SSL contexts.
    keylog_path = CAPTURE_DIR / "tls-keylog.txt"
    try:
        server_ctx.keylog_filename = str(keylog_path)
        client_ctx.keylog_filename = str(keylog_path)
        print(f"[{ts()}] TLS keylog: {keylog_path}", flush=True)
    except Exception as e:
        print(f"[{ts()}] TLS keylog unavailable: {e}", flush=True)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_host = os.environ.get("MITM_CBS_BIND", "")
    srv.bind((bind_host, LISTEN_PORT))
    srv.listen(16)
    print(
        f"[{ts()}] MITM CBS proxy listening on "
        f"{bind_host or '*'}:{LISTEN_PORT} (TLS+HTTP unified)",
        flush=True,
    )
    print(f"[{ts()}] veto config: {VETO_CONFIG_PATH}", flush=True)
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
