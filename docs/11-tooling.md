# 11 · Tooling reference

Every script in the project root, what it does, how to run it, and
where its logs land. Listed in rough order of "when you&rsquo;d use it
during the attack chain".

## `wifiqr.py` — offline Wi-Fi QR generator

**Purpose**: generate the Wi-Fi provisioning QR code that the
camera&rsquo;s imager will read to join a network. Bypasses the vendor
app&rsquo;s `getDidByToken` cloud step, so your SSID and password never
leave the LAN.

**Format**: the QR encodes the literal string `"S" + ssid + "\n" +
pwd + "\n"`. Not JSON, not Wi-Fi standard format — just a plain
newline-delimited blob the cam firmware knows how to parse.

**Usage**:

```sh
./wifiqr.py MyHomeWifi                   # prompts for pwd via getpass
./wifiqr.py MyHomeWifi s3cret            # pwd on CLI (shell history warning)
./wifiqr.py MyHomeWifi s3cret -o qr.png  # also save PNG
./wifiqr.py MyHomeWifi s3cret --invert   # flip black/white if cam misreads
./wifiqr.py MyHomeWifi s3cret --border 4 # wider quiet zone
```

**Dependencies**: `qrcode[pil]` — declared as PEP 723 inline script
metadata. On first run, `uv run` auto-installs into a cached venv.
Works with bare `python3` too if `qrcode` is already installed.

**Physical use**: hold the terminal with the ASCII-art QR about 15-25
cm in front of the cam&rsquo;s lens. The cam will "ding" or change its LED
when it reads the code.

## `probe.py` — UDP discovery tool

**Purpose**: watch for (or trigger) UDP traffic from the cam on the
LAN. Three modes, one listener, with Kalay beacon parsing built in.

**Modes**:

```sh
./probe.py listen              # default — combined beacon listen + active probe
./probe.py listen --quiet      # only passive, no active probes
./probe.py passive             # one-shot 30s listen on UDP/8899
./probe.py active              # fire the YH 59 48 01 01 probe to 18523
```

**What it catches**:

- **8899 beacon** (iotcare_lan) — the cam&rsquo;s 30-second post-Wi-Fi-join
  announcement. `probe.py` parses the ASCII format and extracts the
  DID via `parse_iotcare_beacon()`.
- **18523 multicast** — sends a `59 48 01 01` ("YH" + version) UDP
  broadcast and listens for replies. Parses the legacy CS2 response
  format via `parse_yh_reply()`. **This path is empty in our Kalay
  firmware** — the cam doesn&rsquo;t respond on 18523 — but it was the
  original `AddDeviceViewMode.searchDeviceByMulticast` discovery
  mechanism in the Java code.
- **Other UDP traffic** — logs hex dumps for anything that arrives on
  those sockets.

**Not caught**: LAN_SEARCH on 32108 (use `inject_p2p_req.py` or a
one-shot Python snippet for that).

## `fake_supernode.py` — canned Kalay responder (legacy)

**Purpose**: answer `HELLO` with `HELLO_ACK`, answer `DEV_LGN_CRC`
with a replayed `DEV_LGN_ACK`. Was the first thing we built before
we had the MITM pipeline working.

**Status**: superseded by `mitm_supernode_proxy.py`. Kept in the tree
as a reference implementation of the "serve from cache" approach
we&rsquo;ll want for the final airgap mode.

**Key constants**:

```python
DEV_LGN_ACK_BODY = bytes.fromhex("a02aaac73b7755c9")  # deterministic
FAKE_PUBLIC_IP   = "203.0.113.37"                     # TEST-NET-3
```

Both are documented upstream in
[`04-wire-format-kalay.md`](04-wire-format-kalay.md).

## `fake_cbs_server.py` — canned TLS CBS server (legacy)

**Purpose**: terminate TLS with a self-signed `*.hapseemate.cn` cert
and return canned JSON envelopes for CBS endpoints. The first version
we built before we pivoted to real MITM forwarding.

**Status**: superseded by `mitm_cbs_proxy.py`, kept for reference.

**Notable features**:

- Auto-generates a self-signed cert on first run via `openssl req`
  to `/tmp/cam-listen/fake-cbs-certs/server.{crt,key}`.
- Parses TLS ClientHello SNI before wrapping the socket, so even if
  TLS handshake later fails we still log what hostname the client
  was asking for.
- Has a response dispatcher keyed on the request URL — add new
  endpoint handlers in `_pick_response_for()`.

Ships with a best-guess `{"code":0,"msg":"success","data":null}`
envelope that did NOT actually satisfy the cam — the real schema has
a typo and different field names. See
[`05-wire-format-cbs.md`](05-wire-format-cbs.md).

## `mitm_supernode_proxy.py` — **ACTIVE** UDP MITM

**Purpose**: accept cam&rsquo;s UDP Kalay traffic on port `32100`, forward
to one of three real Aliyun supernodes, forward replies back. Every
packet is logged with hex + Kalay message-type decode.

**Architecture**: one per-cam-session upstream socket (keyed on the
cam&rsquo;s MASQUERADE&rsquo;d `(ip, port)` tuple), each with its own reader
thread. New sessions round-robin across the three configured
supernodes. Sessions expire after 300 seconds of idle.

**SIGUSR1 injection**: writes a JSON file at
`/tmp/cam-listen/inject.json`, then `kill -USR1 <pid>` the proxy. On
SIGUSR1, the proxy reads the file and sends each described packet
from its own `:32100` socket. Used by `inject_p2p_req.py`.

**Usage**:

```sh
python3 mitm_supernode_proxy.py 2>&1 | tee /tmp/cam-listen/mitm_supernode.log &
```

**Log format**:

```
[HH:MM:SS.xxx] ▶ fwd  192.168.5.1:1097 <-> 8.134.120.63:32100  DEV_LGN/48B(body=44)  f112002c…
[HH:MM:SS.xxx] ◀ ret  192.168.5.1:1097 <-> 8.134.120.63:32100  DEV_LGN_ACK/12B(body=8)  f1130008a02aaac73b7755c9
[HH:MM:SS.xxx] new session: ('192.168.5.1', 16106) → ('47.89.232.167', 32100)
[HH:MM:SS.xxx] session expired: ('192.168.5.1', 1097)
[HH:MM:SS.xxx] ✳ INJECT  → 192.168.5.1:XXXX PUNCH_PKT/24B(body=20) f141…
```

**Configuration constants** (top of file):

```python
LISTEN_PORT = 32100
UPSTREAMS = [
    ("8.134.120.63", 32100),    # Aliyun Shenzhen
    ("47.89.232.167", 32100),   # Aliyun US-West
    ("123.56.74.245", 32100),   # Aliyun Beijing
]
INJECT_FILE = Path("/tmp/cam-listen/inject.json")
```

## `mitm_cbs_proxy.py` — **ACTIVE** TLS MITM

**Purpose**: accept the cam&rsquo;s TLS connection on port `8443`,
terminate with self-signed cert, open outbound TLS to real
`user.hapseemate.cn` (hard-coded to `190.92.254.71` to bypass the
Mac&rsquo;s own DNS which would otherwise route to `9.9.9.9`), forward
the cleartext request, log both request and response.

**Architecture**: blocking per-connection handler threads. Not
pipelined — each CBS request is a short-lived accept → read request
→ forward → read response → forward response → close.

**Usage**:

```sh
python3 mitm_cbs_proxy.py 2>&1 | tee /tmp/cam-listen/mitm_cbs.log &
```

**Log format**:

```
[HH:MM:SS.xxx] ACCEPT   192.168.5.1:XXXX  new connection
[HH:MM:SS.xxx] ACCEPT   192.168.5.1:XXXX  SNI: user.hapseemate.cn
[HH:MM:SS.xxx] ACCEPT   192.168.5.1:XXXX  downstream TLS OK  ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1.2', 256)
[HH:MM:SS.xxx] UPSTRM   192.168.5.1:XXXX  connected to 190.92.254.71:443 SNI=user.hapseemate.cn  ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1.2', 256)
[HH:MM:SS.xxx] REQ      192.168.5.1:XXXX  240B cleartext:
GET /preadd/didBindUserId?relatInfo=…&did=…&utcTime=…&devType=1&netType=1&eleType=1 HTTP/1.1
[HH:MM:SS.xxx] RESP     192.168.5.1:XXXX  280B from upstream:
HTTP/1.1 200
...
{"mssage":"success","status":"200"}
[HH:MM:SS.xxx] RESP     192.168.5.1:XXXX  forwarded to cam
```

**Configuration constants**:

```python
LISTEN_PORT = 8443
UPSTREAM_HOST = "user.hapseemate.cn"
UPSTREAM_IP = "190.92.254.71"
UPSTREAM_PORT = 443
CERT_FILE = Path("/tmp/cam-listen/fake-cbs-certs/server.crt")
KEY_FILE  = Path("/tmp/cam-listen/fake-cbs-certs/server.key")
```

## `inject_p2p_req.py` — craft and fire P2P_REQ packets

**Purpose**: build a valid 40-byte Kalay `P2P_REQ (0x20)` packet and
fire it via SIGUSR1 to the running supernode MITM.

**Usage**:

```sh
./inject_p2p_req.py \
  --peer-ip 192.168.5.233 \
  --peer-port 41234 \
  --did-prefix APPID \
  --did-suffix XXXXX \
  --lgn 1 \
  --cam-session "192.168.5.1:1097,192.168.5.1:16106"
```

**Caveat**: the cam&rsquo;s device-role dispatcher does NOT accept `0x20`.
This script is kept for reference and as a harness for other message
types — see `build_p2p_req()` for the wire format. For PunchPkt or
other types, copy the function and adjust the type byte + body
layout.

## `build_docs.py` — static site generator

**Purpose**: build a VuePress-style static site from `docs/*.md` into
the `dist/` directory. Each markdown file becomes an HTML page with a
sidebar of all docs, a dark/light mode toggle, syntax-highlighted
code blocks, and readable typography.

**Usage**:

```sh
./build_docs.py
# or
python3 build_docs.py
# or (via uv, which installs deps in a cached venv)
uv run build_docs.py
```

**Dependencies** (declared inline with PEP 723):

- `markdown>=3.5` (with `fenced_code`, `codehilite`, `tables`, `toc`,
  `attr_list` extensions)
- `pygments>=2.17` (for syntax highlighting)

Everything else — the page template, the base CSS, and the Pygments
color palette for both light and dark modes — is inlined in the
script itself so the file is self-contained.

**Output**: writes `dist/*.html`, one per markdown source file.
`README.md` becomes `index.html`; everything else keeps its stem.
No external CSS or JS files are generated — each page is standalone.

**When to run**: every time you touch `docs/*.md`. The CLAUDE.md rule
at the project root says "after touching docs/, regenerate the static
site with `python3 build_docs.py` so dist/ stays in sync."

## `explainer.html` / `explainer-deep.html` — interactive explainers

Two single-file HTML presentations that walk through the project at
different levels of detail.

- **`explainer.html`** — 8-slide "quick intro" from the first RE
  session. Still useful as a high-level overview. References the
  state-of-knowledge from Session 1-2.
- **`explainer-deep.html`** — 14-slide comprehensive version covering
  the cloud topology, Kalay wire format, state machine, attack chain,
  and findings from sessions 1-4. Most up-to-date of the two.

Both are self-contained single HTML files with inline CSS and JS. They
use Mermaid via CDN for sequence/state diagrams. Open in any browser:

```sh
open explainer-deep.html
```

Keyboard navigation: arrow keys / space / click the bottom nav dots.
There&rsquo;s a clickable message-type grid on one of the slides that
opens a per-type byte-level breakdown on click.

These are reference artifacts — don&rsquo;t regenerate them when you
update `docs/`. They are snapshot-in-time presentations, not living
documents. The living documentation is `docs/` itself (rendered via
`build_docs.py`).

## `ghidra_scripts/DecompilePunchTo.java` — Ghidra headless script

**Purpose**: post-analysis script for Ghidra headless. Given a
loaded `libPPCS_API.so`, looks up a configured list of symbol
substrings (Write_PunchTo, Send_PunchTo, Write_P2PReq, etc.) and
dumps their decompilation to a text file.

**Status**: unused. We ended up using `llvm-objdump` directly
because the functions are small enough to read as raw assembly.
Kept in the tree in case a more complex RE session needs Ghidra&rsquo;s
decompiler output.

**Usage**:

```sh
GHIDRA=/opt/homebrew/Cellar/ghidra/12.0.4/libexec
"$GHIDRA/support/analyzeHeadless" /tmp/ghidra-cam cam_re \
  -import extracted/lib/arm64-v8a/libPPCS_API.so \
  -scriptPath /Users/fdb/ReverseEngineering/cloudbirds-ip-cam/ghidra_scripts \
  -postScript DecompilePunchTo.java \
  -deleteProject
```

Output lands in `/tmp/ghidra-cam/decompile.txt`. Note: Ghidra
requires a JDK; the first run will fail with "Unable to locate a
Java Runtime" if no JDK is in `$PATH`.

## Runtime log locations

All MITM log files land under `/tmp/cam-listen/`:

| File | Writer | Content |
|---|---|---|
| `mitm_supernode.log` | `mitm_supernode_proxy.py` | UDP Kalay traffic, both directions |
| `mitm_cbs.log` | `mitm_cbs_proxy.py` | TCP TLS traffic + cleartext HTTP |
| `fake_supernode.log` | `fake_supernode.py` (legacy) | Canned-responder Kalay traffic |
| `fake_cbs.log` | `fake_cbs_server.py` (legacy) | Canned TLS responses |
| `peer_listener.log` | ad-hoc Python oneliners | Incoming packets on port 41234 etc. |
| `udp32100.log` | earlier passive listener | Kalay traffic (before we had the MITM) |
| `inject.json` | `inject_p2p_req.py` | Injection target queue for SIGUSR1 |
| `fake-cbs-certs/` | `fake_cbs_server.py` | Self-signed TLS cert material |

_Last updated: 2026-04-15 — Session 6_

## Quick commands cheat sheet

```sh
# Is everything alive?
lsof -iUDP:32100 -iTCP:8443 -n -P
ps aux | grep -E 'mitm_supernode|mitm_cbs|fake_' | grep -v grep

# What is the cam doing right now?
tail -20 /tmp/cam-listen/mitm_supernode.log

# Is the cam responsive?
python3 -c "import socket; s=socket.socket(2,2); s.settimeout(2); s.sendto(bytes.fromhex('f1300000'),('192.168.5.37',32108)); d,a=s.recvfrom(4096); print(a, d.hex())"

# Check iptables counters on the UDM
ssh root@192.168.5.1 'iptables -t nat -L PREROUTING -v -n --line-numbers'

# List all Kalay-related symbols in libPPCS_API.so
nm -D extracted/lib/arm64-v8a/libPPCS_API.so | grep -iE "Proto_(Send|Read|Write)_" | sort -k3

# Disassemble a specific function
/opt/homebrew/opt/llvm/bin/llvm-objdump -d \
  --disassemble-symbols='_Z29cs2p2p_PPPP_Proto_Send_P2PReq...' \
  extracted/lib/arm64-v8a/libPPCS_API.so
```
