# 17 · Portability to other cams

Most of what&rsquo;s in this project applies, with varying degrees of
adaptation, to the wider family of Chinese IP cameras that ship on
the Throughtek Kalay / CS2 PPPP stack. This file is a guide for
someone who has a different camera and wants to know which pieces of
our work they can reuse verbatim and which they&rsquo;ll need to adapt.

## The OEM family

Brands we know share the Kalay / CS2 PPPP protocol family, either
entirely or in large part:

- **V360 Pro / HapSee / HapSee Mate** (Cloudbirds, Dayunlinks) —
  this project&rsquo;s target
- **Yoosee** — one of the most popular cheap cam brands
- **Sricam**
- **V380** / **V380 Pro**
- **YI** (older models)
- **EseeCloud**
- **CamHi**
- **XMEye** (some models; others use a different "dvrip" stack)
- **Hundreds of AliExpress no-name brands** with names like
  "Smart Camera", "Mini WiFi Cam", etc.

Not all of these use exactly the same Kalay build, but they all use
the same underlying CS2 Network protocol family. Knowledge transfers
at the **concept** level (Kalay header format, the supernode
rendezvous architecture, NAT hole-punching via `PunchPkt`) even when
specifics differ.

## What transfers VERBATIM

### The Kalay UDP wire format header

```
F1 <type:u8> <body_len:u16 BE> <body...>
```

The 4-byte header is the same across every Kalay device we&rsquo;ve seen
documented. Our `probe.py`&rsquo;s `parse_iotcare_beacon()` and the
injection hex-builder in `inject_p2p_req.py` use this header format
unchanged.

### The canonical DID struct

```
[0..8)    char[8] prefix (strncpy 7 + null pad)
[8..12)   u32 BE serial
[12..20)  char[8] suffix
```

This 20-byte DID encoding shows up in LAN_RESPONSE, P2P_REQ,
PunchPkt, and others. Any cam in the family uses the same format —
only the alphabet of the prefix/suffix letters differs per OEM.

### The LAN_SEARCH discovery probe

`f1 30 00 00` broadcast to UDP/32108 always gets a LAN_RESPONSE back
(type `0x41`, 20-byte body = canonical DID struct). Every Kalay cam
we&rsquo;ve encountered responds to this, and it&rsquo;s the most reliable "is
this cam alive" probe across brands.

### The MITM architecture

The DNAT + MASQUERADE chain at the router + Python proxies on the
Mac works for any cam in the family. The only things to change are:

- The cam&rsquo;s IP in the iptables `-s` clause
- The cloud hostnames in the dnsmasq override (different OEMs use
  different domains — Yoosee uses `yoosee.co`, Sricam uses
  `sricam.com`, etc.)
- The list of hardcoded fallback supernode IPs (capture them in an
  initial pcap before adding overrides)

### The general attack playbook

1. Unpack the APK
2. Identify the OEM SDK namespace (`com.qianniao.*`, `com.jwkj.*`,
   `com.v380.*`, etc.)
3. Confirm Kalay by looking for `libPPCS_API.so` or `libLibPPCS_API*.so`
4. Extract the vendor init key from `PPCS_Initialize()` call sites
5. Stand up the DNS + DNAT pipeline
6. Use `mitm_supernode_proxy.py` (rename hosts as needed) to
   intercept and observe

## What needs adapting

### Vendor init key

The 80-character A-P encoded init key in
[`01-hardware.md`](01-hardware.md) is specific to Dayunlinks /
Cloudbirds. Every OEM has its own. Extract yours from the decompiled
`P2pSDK.java` (or wherever the JNI bridge lives) — look for the call
to `PPCS_APIs.PPCS_Initialize(someKey.toByteArray())`.

You need the correct init key or the supernode will reject your
device&rsquo;s registration.

### Cloud hostnames

Each OEM has its own cloud domains. Capture a pcap on first boot
(before applying any overrides) and grep for DNS queries. Typical
patterns:

- `p2p<N>.<brand>.cn` or `p2p.<brand>.com` for supernodes
- `user.<brand-api>.cn` or `api.<brand>.com` for CBS-style HTTPS
- NTP wrapped via `ntp.<brand>.cn` → CNAME to real pool

### CBS endpoint format

The `/preadd/didBindUserId` endpoint with the `"mssage":"success"`
typo is specific to the Cloudbirds backend. Other OEMs have their
own endpoints with their own schemas. You&rsquo;ll need to capture your
cam&rsquo;s real response via MITM and update
`mitm_cbs_proxy.py`&rsquo;s canned-response bank accordingly.

Rules of thumb:

- Chinese OEM backends frequently have typos or unusual field names
  preserved for backwards compatibility. Don&rsquo;t "correct" anything
  without testing.
- Response Content-Type is often `text/plain;charset=ISO-8859-1`
  even when the body is JSON. Don&rsquo;t normalize.

### The `iotcare_lan` beacon format

Our cam&rsquo;s 8899 beacon is the ASCII string
`iotcare_lan:<DID>:iotcare_lan`. Other OEMs may use different
prefix tags or formats — some don&rsquo;t beacon at all. `probe.py`&rsquo;s
beacon parser would need an extra pattern for each variant.

### Message-type dispatch

The set of Kalay message types that the device-role `thread_recv_Proto`
actually dispatches on is per-OEM-build. Our cam accepts at least 8
types (`0x13, 0x30, 0x31, 0x3f, 0x52, 0x55, 0xdb, 0xdc`). A different
build of the library may handle a different set. Re-run the
`llvm-objdump` + grep on the target cam&rsquo;s `libPPCS_API.so` to find out.

## What DOESN&rsquo;T transfer

- **Exact IP addresses and session ports** — all captured values
  (`8.134.120.63`, `190.92.254.71`, `192.168.5.37`, port `12301`,
  etc.) are per-device or per-session. Don&rsquo;t hardcode them in your
  own setup.
- **The `DEV_LGN_ACK` constant `a02aaac73b7755c9`** — this is
  DID-specific. Your cam will have its own 8-byte constant. Capture
  it from a real DEV_LGN round-trip.
- **The `utcTime` sample value** in captured CBS requests — it&rsquo;s a
  timestamp from the capture date.
- **Frederik&rsquo;s real WAN IP** that appears in the HELLO_ACK bodies.

## Useful external references

- **[CVE-2021-28372](https://nvd.nist.gov/vuln/detail/CVE-2021-28372)**
  — a well-documented Kalay vulnerability that exposed the protocol
  details to the security community. Still the most comprehensive
  public writeup of the CS2 PPPP architecture.
- **Mandiant&rsquo;s Kalay research** (various blog posts 2021-2024) —
  detailed explanations of how the supernode rendezvous works,
  including several non-obvious details about session negotiation.
- **GitHub projects to survey**: `yoosee-py`, `sricam-p2p`,
  `v380-decoder`, anything matching `kalay python` or `cs2p2p`.
  Several have working client-side implementations that would save
  us the effort of writing our own.

## Test plan for porting

If you&rsquo;re adapting this project to another cam, do these steps in
order and stop at the first failure:

1. **Wi-Fi provisioning**: does `wifiqr.py`&rsquo;s `S<ssid>\n<pwd>\n` QR
   format work? If not, check the target cam&rsquo;s
   `WifiScanQrcodeFragment` equivalent for its expected format.
2. **8899 beacon**: does `probe.py listen` see anything on port
   8899 within 30 seconds of the cam joining Wi-Fi? If not, the
   target OEM may use a different beacon port or format.
3. **LAN_SEARCH**: does `f1 30 00 00` to UDP/32108 produce a reply?
   This is the most portable primitive — if it doesn&rsquo;t work, either
   the port is different or the cam isn&rsquo;t Kalay.
4. **Initial pcap**: capture the cam&rsquo;s outbound traffic from a
   clean power-cycle, grep for DNS queries and the supernode
   session setup. Identify the equivalent of our cloud topology.
5. **DNS + DNAT override**: redirect to a sink IP and confirm the
   cam accepts a fake HELLO_ACK with a TEST-NET-3 IP.
6. **TLS MITM**: if the target has a CBS-like HTTPS control plane,
   confirm cert pinning is absent by testing with a self-signed
   cert.
7. **Adapt `mitm_supernode_proxy.py`&rsquo;s upstream list** to point at
   the target OEM&rsquo;s real supernodes.

_Last updated: 2026-04-15 — Session 6_
