# 04 · Kalay / CS2 PPPP wire format

The UDP protocol spoken between the camera and its supernodes, and
also — in a different mode — between the camera and an app-side client.
Every message type we have observed or disassembled is documented
here at byte resolution.

**Provenance legend** used throughout this doc:

| Tag | Meaning |
|---|---|
| _observed_ | Seen directly in a pcap or MITM log |
| _disassembled_ | Extracted from `llvm-objdump` or Ghidra output |
| _inferred_ | Deduced from indirect evidence (symbol names, function shapes, context) |
| _guessed_ | Best hypothesis but not verified |

## Common header — always 4 bytes

```
offset  size  field        description
[0..1)   1    magic = 0xF1 Kalay / CS2 PPPP magic byte
[1..2)   1    type         message type (see catalog below)
[2..4)   2    length BE    body size in bytes (0..65535)
[4..)         body         format depends on type
```

The total packet length is always `4 + body_length`. There is no
trailing CRC or checksum at the packet level — integrity depends on
UDP&rsquo;s own checksum. Body contents may have an additional inline CRC
or XOR obfuscation; see per-type notes.

### Endianness

- Length field: big-endian.
- Integer fields inside bodies: mostly big-endian, converted by
  `cs2p2p_htonAddr` or explicit `rev w` (byte-reverse) instructions.
- Strings: written with `strncpy` from a null-terminated source
  (counted length 7, with the 8th byte staying at zero from a
  pre-initializing `memset` or `stp xzr, xzr`).
- `sockaddr_in` structs: written as `family BE · port BE · ipv4 BE ·
  8 bytes zero` via `cs2p2p_htonAddr`, which byte-swaps every field
  regardless of the host endianness.

## Message type catalog

### `0x00` — HELLO  (4 bytes)   _observed, disassembled_

```
f1 00 00 00
```

Empty body. The camera sends this to each supernode at the start of a
new session to prime the NAT table and learn its own public endpoint.
Sent 3× per session (one per supernode region).

Symbol: `cs2p2p_PPPP_Proto_Send_Hello`. Trivial — just writes
`f1 00 00 00`. Disassembled function body is ~5 instructions.

### `0x01` — HELLO_ACK  (20 bytes)   _observed, disassembled_

```
f1 01 00 10  <sockaddr_in: 16 bytes>
```

Sent by the supernode in reply to HELLO. The 16-byte body is a
`sockaddr_in` struct containing the NAT-translated endpoint of the
client as seen from the supernode&rsquo;s perspective:

```
offset   size  field              example (from pcap)
[0..2)    2    sin_family BE      00 02   (AF_INET)
[2..4)    2    sin_port BE        e4 0d   (port 58381)
[4..8)    4    sin_addr BE        25 25 33 b2  (home WAN IP)
[8..16)   8    padding            00 00 00 00 00 00 00 00
```

**Critical for the rebinding filter** _(observed)_: the cam validates
the IP in the body. With an RFC1918 IP in our fake HELLO_ACK the cam
silently refused to advance its state machine and kept retrying HELLO.
After changing to a non-RFC1918 IP (TEST-NET-3 `203.0.113.37`) the cam
immediately advanced to the next phase and started sending the
previously-unseen `0xF9 REPORT_SESSION_RDY`. **Inference**: the cam runs
a DNS-rebinding-style filter on this field and rejects private IPs.
That&rsquo;s why our `fake_supernode.py` echoes `203.0.113.37`.

### `0x12` — DEV_LGN_CRC  (48 bytes)   _observed, partially disassembled_

```
f1 12 00 2c  <44 bytes obfuscated body>
```

Device login / registration. Sent by the camera to the supernode every
~30 seconds as a keepalive. The body is **obfuscated** — high-entropy
binary output, not cleartext. The obfuscation function is presumably
`cs2p2p__P2P_Proprietary_Decrypt` (the "Decrypt" name is misleading —
it&rsquo;s called on both encrypt and decrypt paths). Whether it&rsquo;s pure XOR,
a stream cipher, or a block cipher is **unverified** _(see
`13-open-questions.md`)_.

Observed body structure, inferred from diffing bodies across sessions:

- Bytes `[0..22)`: **static** per cam boot — constant for a given DID
  within one boot cycle
- Bytes `[22..44)`: **rotates** per session — a nonce or timestamp that
  changes every time the cam rebinds sockets

The function that builds it is `cs2p2p_PPPP_Proto_Write_DevLgn_CRC` —
we have not fully disassembled it, but we know it calls
`cs2p2p_PPPP_CRCEnc` for CRC wrapping and
`cs2p2p_PPPP_DecodeString` for the A-P → raw-bytes decoding of the
init key _(inferred)_.

**Replay semantics** _(observed)_: we can replay a captured
`DEV_LGN_CRC` body verbatim and the supernode will accept it — within
a single cam boot cycle. Across a cam reboot, the body changes and the
old one becomes stale.

### `0x13` — DEV_LGN_ACK  (12 bytes)   _observed_

```
f1 13 00 08  a0 2a aa c7 3b 77 55 c9
```

Supernode&rsquo;s reply. **The 8-byte body is a deterministic constant for
this DID** _(observed)_. Captured byte-identical from three different
supernodes (Aliyun Shenzhen, US-West, Beijing) and across many session
attempts, including across cam reboots.

**Interpretation** _(guessed)_: almost certainly an HMAC or hash of
the DID keyed on the vendor init key — which would explain the
cross-supernode determinism. We have not verified this by computing
the HMAC ourselves.

**Practical use**: we hardcode this body in `fake_supernode.py` and the
cam accepts it without re-verification:

```python
DEV_LGN_ACK_BODY = bytes.fromhex("a02aaac73b7755c9")
```

### `0x20` — P2P_REQ  (40 bytes) — client→supernode   _disassembled_

```
f1 20 00 24  <36-byte body>
```

The client-side "I want to connect to device X" message. Sent by the
APP to the supernode asking it to relay a connection request to the
target camera.

Body layout (decoded from `Proto_Write_P2PReq @ 0xd6b4` and
`Proto_Read_P2PReq @ 0xd70c`):

```
offset    size  field                notes
[0..8)     8    char[8] prefix       strncpy 7 bytes + null pad
[8..12)    4    u32 BE lgn           session/login id
[12..20)   8    char[8] suffix       strncpy 7 bytes + null pad
[20..36)  16    sockaddr_in          target peer endpoint
```

The DID in the body is the CAM&rsquo;s DID (the target being looked up),
not the app&rsquo;s DID. The sockaddr_in is the APP&rsquo;s own endpoint (where
it wants the cam to connect back).

**Body plaintext on the client side** _(disassembled)_: `Write_P2PReq`
copies strings with `strncpy`, writes the session id via `rev w`
(byte-swap), and calls `htonAddr` on the sockaddr — no call to the
obfuscation helper. So the bytes that leave the client are in cleartext.
**Server-side semantics**: the supernode may still validate fields
against its own registry (e.g., reject unknown client DIDs) — we don&rsquo;t
know.

⚠️ **Injecting this directly to the cam does NOT work** _(observed)_.
The camera&rsquo;s `thread_recv_Proto` dispatcher has no `cmp w0, #0x20` in
its immediate-value branches, so the packet appears to be silently
dropped. This is consistent with `P2P_REQ` being a client-role
message: the camera is the target of the request, not the handler.
The handler is the supernode. See [`13-open-questions.md`](13-open-questions.md).

### `0x30` — LAN_SEARCH  (4 bytes) — LAN-local discovery   _observed_

```
f1 30 00 00
```

Empty body, sent as UDP broadcast or unicast to `cam-ip:32108`.
Any peer on the LAN can send it — no auth required.

The camera&rsquo;s `thread_recv_LanSearch` thread (bound to UDP/32108 on the
cam side) handles type `0x30` and responds with a `0x41 LAN_RESPONSE`.
This is how the app does on-LAN discovery even when the cloud is
unreachable. Responses always work against this cam even during deep
cloud-MITM state, which means it&rsquo;s a completely separate thread from
`thread_recv_Proto`.

### `0x41` (LAN_RESPONSE variant)  (24 bytes)   _observed_

```
f1 41 00 14  <20-byte plaintext DID struct>
```

Reply to LAN_SEARCH, sent back from `thread_recv_LanSearch` on the cam
side. **Unencrypted** — the body is the canonical DID struct format:

```
offset    size  field              example bytes
[0..8)     8    DID prefix (ASCII) "CFEOA"   43 46 45 4f 41 00 00 00
[8..12)    4    serial BE u32      417739    00 06 5f cb
[12..20)   8    DID suffix (ASCII) "RTFUU"   52 54 46 55 55 00 00 00
```

This is the ONLY DID-bearing message type we have complete byte-level
visibility into. Unencrypted because LAN discovery happens before any
session exists, so there&rsquo;s no session context to derive an obfuscation
key from.

> **About the `0x41` collision**: the same type byte is also used by
> `PUNCH_PKT` (below) with a different body format. These are handled
> by **different threads** on **different sockets**:
>
> - `LAN_RESPONSE` is emitted by `thread_recv_LanSearch` on UDP/32108
>   (the well-known LAN discovery port)
> - `PUNCH_PKT` is emitted/received via `thread_recv_Proto` on an
>   ephemeral session socket (per-peer, after supernode rendezvous)
>
> Each thread has its own socket and knows which body shape to expect.
> CS2 PPPP reuses type numbers across contexts; context = socket.

### `0x40` — PUNCH_TO  (20 bytes) — client→relay only   _disassembled_

```
f1 40 00 10  <sockaddr_in: 16 bytes>
```

Sent by a client to a relay saying "please punch over to this
endpoint". Body is a single `sockaddr_in` identifying the target.

Function: `cs2p2p_PPPP_Proto_Send_PunchTo @ 0xd8e8`. No
`Write_PunchTo` exists as a separate symbol — the function inlines
its header construction via `Write_Header` + `htonAddr`.

`thread_recv_Proto`&rsquo;s immediate-value branches do NOT include
`cmp w0, #0x40` _(disassembled)_, which is consistent with the cam&rsquo;s
device role not having a handler for inbound `PUNCH_TO`. PUNCH_TO is
a client-role message — it&rsquo;s what an app would SEND to a relay.

### `0x41` (PUNCH_PKT variant)  (24 bytes) — peer-to-peer hole punch   _disassembled_

```
f1 41 00 14  <20-byte body>
```

Peer-to-peer hole-punching message. Body layout:

```
offset    size  field              notes
[0..8)     8    char[8] name1      strncpy 7 + null pad
[8..12)    4    u32 BE lgn         session id
[12..20)   8    char[8] name2      strncpy 7 + null pad
```

**No sockaddr_in** — the endpoint is implicit in the UDP 4-tuple.

Functions:
- `cs2p2p_PPPP_Proto_Write_PunchPkt @ 0xe818`
- `cs2p2p_PPPP_Proto_Read_PunchPkt @ 0xe868`
- `cs2p2p_PPPP_Proto_Send_PunchPkt @ 0xe8bc`

`Send_PunchPkt` has **one** `sockaddr_in*` parameter (the destination),
not two — because PunchPkt is sent directly peer-to-peer, not through
a relay.

**The cam&rsquo;s `thread_recv_Proto` DOES call `Read_PunchPkt`**
_(disassembled)_, which means the cam has a handler for type `0x41` on
its session socket. This is one of the better candidates for future
injection attempts.

### `0xF9` — REPORT_SESSION_RDY  (88 bytes)   _observed, disassembled_

```
f1 f9 00 54  <84-byte obfuscated body>
```

Sent by the cam to the supernode after a successful HELLO/DEV_LGN
cycle. Publishes the cam&rsquo;s WAN, LAN, and relay endpoints to the
supernode so that peer lookups can find them later.

**Sample hex from a real capture** (2026-04-15, DID
`CFEOA-417739-RTFUU`):

```
f1 f9 00 54 03 78 c9 9e 2a 7c 0c 89 7d 9f 0d 76
72 1b fb ec 57 3f be 74 1b 42 f7 e0 a9 22 35 f5
19 1a eb 45 e8 42 08 79 36 32 f7 56 9d d9 eb 85
ca d2 c6 59 56 b8 5b 31 be 76 24 69 1f 50 f7 1c
65 77 df aa 37 19 e1 22 35 f4 4e c2 f5 3e 3c e2
ac c0 a8 a3 1e b6 69 df
```

**No reply observed in our captures** _(observed)_. The cam forwards
`0xF9` to the real supernode (via MITM) and the supernode returns
nothing. Note: this has only been tested in the "no peer asking for
this cam" state — in a different state (app actively looking for the
cam) the supernode may send the cam a different message type as a
follow-up. We have not exercised that path yet.

Function: `cs2p2p_PPPP_Proto_Send_ReportSessionRdy`. The C++ mangled
symbol has **three** `sockaddr_in*` arguments:

```
_Z39cs2p2p_PPPP_Proto_Send_ReportSessionRdyPKciP11sockaddr_iniPcjS3_ccttS2_S2_S2_tcc
```

So the 84-byte body encodes WAN, LAN, and relay endpoints plus some
extra scalar metadata. Full layout is unknown because we haven&rsquo;t
reversed the obfuscation function that wraps the bytes — see
[`13-open-questions.md`](13-open-questions.md).

## Types the cam dispatches on (device role) — partial analysis

**Caveat before reading this section**: this comes from grepping
`cmp w0, #0xNN` in `cs2p2p_PPPP_thread_recv_Proto @ 0x1ebe8`. The
function is ~9000 instructions and we have not fully traced it —
there could be more types handled via jump tables, nested branches,
or register values other than `w0`. So treat this as **at least**
these types, not necessarily a complete list.

Immediate-value compares we found in `thread_recv_Proto`:

```
0x13   DEV_LGN_ACK _(known)_ — the cam expects replies from its supernode
0x30   LAN_SEARCH  _(known)_ — probably also handled here in addition to
                                the dedicated thread_recv_LanSearch
0x31   (unknown — adjacent to LAN_SEARCH, possibly LAN_NOTIFY variant)
0x3f   (unknown — Kalay-era type)
0x52   (unknown — Kalay-era type)
0x55   (unknown — Kalay-era type)
0xdb   (unknown — high-number range, near DRW family)
0xdc   (unknown — high-number range, near DRW family)
```

**Observed to NOT be in that immediate-compare set**: `0x00 HELLO`,
`0x01 HELLO_ACK`, `0x12 DEV_LGN`, `0x20 P2P_REQ`, `0x40 PUNCH_TO`,
`0x42`, `0xd0 DRW`, `0xf9 REPORT_SESSION_RDY`. These either aren&rsquo;t
incoming for the device role, are handled by a different thread
(`thread_recv_DRW` for `0xd0`, `thread_recv_LanSearch` for `0x30/0x41`
LAN_RESPONSE, `thread_recv_FW_DCResponse` for something unknown), or
route through a path we haven&rsquo;t found.

**Functions that the dispatcher calls** (from `bl` instructions inside
`thread_recv_Proto`):

```
Proto_Read_RlyTo, Proto_Read_RlyRdy, Proto_Read_PunchPkt,
Proto_Read_P2PRdy, Proto_Read_RlyPortAck, Proto_Read_TryLanTcp,
Proto_Read_DCHeader, Proto_Read_TCPRSStart

Proto_Send_P2PRdy, Proto_Send_PunchPkt, Proto_Send_P2PReq,
Proto_Send_RlyPkt, Proto_Send_RlyReq, Proto_Send_RlyPort,
Proto_Send_RlyHello, Proto_Send_SSDDevLgn, Proto_Send_SSDP2PReq,
Proto_Send_TryLanTcp, Proto_Send_DevLgn_CRC

_P2P_Proprietary_Decrypt   ← every obfuscated body passes through here
__UpdateMyLocalAddr        ← self-address discovery
```

**The call list is more authoritative than the `cmp` list.** Every
`Read_*` function here is a real parser the cam uses. So the cam
**does** handle at least: `PunchPkt`, `P2PRdy`, `RlyTo`, `RlyRdy`,
`RlyPortAck`, `TryLanTcp`, `DCHeader`, `TCPRSStart`. Whichever types
those Read functions correspond to are in the device role&rsquo;s actual
accepted set.

## Thread topology (cam side)

The cam has **four** receive threads, one per socket-class, all found
by grepping `thread_recv_*` symbols in `libPPCS_API.so`:

| Thread | Likely socket | What it parses |
|---|---|---|
| `thread_recv_Proto` | main session socket | Session control (dispatch listed above) |
| `thread_recv_DRW` | main session socket | Video/audio data frames (`0xD0` family) |
| `thread_recv_LanSearch` | UDP 32108 | LAN_SEARCH probes from local clients |
| `thread_recv_FW_DCResponse` | unknown | "Firewall Destination Check Response" — probably part of the relay-server flow |

The `recv_LanSearch` thread is why `f1 30 00 00` broadcasts to
UDP/32108 always get a reply — it&rsquo;s a dedicated responder on a
dedicated socket. We haven&rsquo;t disassembled the other three in depth.

## Obfuscation layer

Some message bodies — confirmed for `DEV_LGN_CRC` and
`REPORT_SESSION_RDY`, unknown for others — are **obfuscated** before
being sent. We know this is happening because the bytes we observe in
pcaps are high-entropy (visually random), while the symbol `strncpy`
path for plaintext messages (`P2P_REQ`, `PUNCH_PKT`, `LAN_RESPONSE`)
produces clearly-structured bytes.

The obfuscation is done by the library function
`cs2p2p__P2P_Proprietary_Decrypt` (the "Decrypt" name is misleading —
it&rsquo;s called on both encrypt and decrypt paths). Key derivation almost
certainly uses the vendor init key passed to `PPCS_Initialize` as the
seed, but the exact cipher is **unknown**:

- It could be a simple XOR stream with a key derived from
  `INIT_KEY` (most common in older CS2 PPPP)
- It could be a block cipher (AES-CBC is a common choice in Kalay-era
  libraries)
- It could be a hand-rolled Feistel or similar, given Throughtek&rsquo;s
  history of proprietary crypto

**We have not reversed this.** For our current attacks we don&rsquo;t need
to — replay works for deterministic responses. For future attacks
that need to craft novel encrypted bodies (e.g., a fake DEV_LGN for a
different DID) we would need to reverse it. See
[`13-open-questions.md`](13-open-questions.md).

For the "fake client" approach (see
[`14-next-steps.md`](14-next-steps.md)), we also don&rsquo;t need to reverse
the obfuscation — we call the library functions directly via
`PPCS_Connect` and let them do the work.

## DRW IOCTRL commands (second layer, inside `0xD0` data frames)

The Kalay message type `0xD0 DRW` is a generic envelope for a
**data read/write channel**. Its payload is not interpreted by the
Kalay library itself; instead, the cam and the client send each other
"IOCTRL" frames inside the DRW body, and the cam&rsquo;s application-layer
code (the part of the cam firmware above Kalay) dispatches on those.

### IOCTRL frame layout (observed from decompiled client code)

An IOCTRL is a 16-bit **type code** followed by a command-specific
payload. We haven&rsquo;t yet captured a DRW payload on the wire (the cam
won&rsquo;t open a DRW channel for us yet — see the "device role dispatch"
section above), but we have the full IOCTRL catalog from the
decompiled app&rsquo;s `ppcs/sdk/cmd/CMD.java`. Each command is sent via
`Connect.sendCmd(type, buffer)` inside `P2pSDK.java`, which in turn
wraps the bytes into a DRW frame and writes to the session socket.

### IOCTRL types of direct RE interest

| Type | Name | Payload | Purpose | Source |
|---|---|---|---|---|
| `0x8116` (33046) | `IOTYPE_USER_IPCAM_SET_UPGRADE_REQ` | **36 bytes: one LE `int32 0` + 32 zero bytes** | **Trigger cam firmware self-upgrade.** Zero-payload "do it" — no URL, no version, no signature, no nonce. The cam interprets this as "go fetch and install whatever your baked-in update server offers." | `ppcs/sdk/cmd/CMD.java:2554-2576` |
| `0x8117` (33047) | `IOTYPE_USER_IPCAM_SET_UPGRADE_RESP` | (reply-side) | Cam&rsquo;s acknowledgement / progress response to the above | `CMD.java:2554-2576` |
| `0x812d` (33069) | `IOTYPE_HOST_DOWNLOAD_FILE` | (download recorded clips from SD card) | **Reverse direction** — app downloading from cam. Note this is NOT firmware push; it&rsquo;s SD-card clip retrieval. | `CMD.java:3245-3248` |

**Security implication of `0x8116`**: there is no authentication on
the upgrade command. Any party that can send a DRW frame to the cam
(i.e., anyone who can establish a DRW session) can force-upgrade it.
The client-side "battery > 25%" check at
`com/qianniao/setting/fragment/DeviceInfoFragment.java:198-209` is a
UX gate only, bypassable by sending the IOCTRL directly. Documented
in [`07-defenses.md`](07-defenses.md).

**Why this matters for firmware capture**: the app does not download
firmware itself (per Session 6 Wave 3 static analysis — see
[`12-session-log.md`](12-session-log.md)). The upgrade flow is
100% app-triggers-cam-self-fetch. Therefore **capturing the firmware
binary in flight requires intercepting the cam&rsquo;s own outbound HTTPS
traffic during a self-update cycle**, not the app&rsquo;s. Our router-side
MITM is the right tool for this; the app-side MITM would see only the
`0x8116` trigger. See [`14-next-steps.md`](14-next-steps.md).

_Last updated: 2026-04-15 — Session 6_
