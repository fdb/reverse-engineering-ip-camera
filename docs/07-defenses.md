# 07 · Vendor defenses

What the vendor did to make local interception harder, what it missed,
and how each piece affects our attack.

## Summary

| Defense | Present? | Effective? | Our bypass |
|---|---|---|---|
| DNS rebinding filter | ✅ yes | 🔶 partial | Non-RFC1918 DNS override + IP-level DNAT |
| TLS certificate pinning | ❌ no | — | None needed |
| TLS public key pinning | ❌ no | — | None needed |
| Kalay body obfuscation | ✅ yes | 🔶 partial | Replay known-good packets |
| Hardcoded supernode IP | ✅ yes | 🔶 partial | Dedicated IP-level DNAT rule |
| Session nonce in DEV_LGN | ✅ yes | ✅ yes | Not broken — cam regenerates per session |
| App-side telemetry | ✅ yes | ✅ yes | We don&rsquo;t run the app |
| Pre-QR cloud check | ✅ yes | ✅ yes | We don&rsquo;t run the app |
| Device auth in CBS | 🔶 unknown | 🔶 unknown | Obfuscated blobs in request — semantics unknown |
| Firmware code signing | ❓ unknown | — | Not yet investigated |
| Rate limiting | 🔶 not observed | — | None needed so far, see note below |

## DNS rebinding filter

**What it does**: the camera&rsquo;s firmware wraps `getaddrinfo()` (or the
equivalent C call) for its known control-plane hostnames with a
post-resolution check. If the returned A record is in RFC1918 address
space (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), the firmware
**silently refuses to attempt a TCP connection** to that address. It
keeps re-resolving DNS hoping for a different answer.

**Why it exists**: this is a textbook defense against **DNS rebinding
attacks**, where a malicious local DNS server redirects a cam&rsquo;s cloud
hostname to a local honeypot on the same LAN. Without the filter, a
router-level attacker could trivially impersonate the vendor cloud.

**How we know it exists**: we proved it by comparison. With `dnsmasq`
pointing `user.hapseemate.cn` at `192.168.5.233` (RFC1918), the cam
resolved the DNS correctly (we saw the query succeed) but **never
attempted a TCP connection**. With `dnsmasq` pointing it at
`9.9.9.9` (public, not RFC1918), the cam immediately started hammering
TCP/443.

**Which hostnames are filtered**: not all of them. The cam&rsquo;s NTP
lookups return public IPs naturally, and those work. The cam doesn&rsquo;t
filter them because NTP responses are expected to be public. Our
hypothesis: the filter is a whitelist of hostnames that MUST resolve
to public IPs. At least these are on the list:

- `user.hapseemate.cn`
- `p2p5.cloudbirds.cn`
- `p2p6.cloudbirds.cn`
- `alive.hapsee.cn`

**Our bypass**: DNS override to a non-RFC1918 sink (we use `9.9.9.9`,
which is real Quad9 — for production we should switch to TEST-NET-3
`203.0.113.x`). The cam passes the filter and attempts a TCP connect
to the sink IP. Our router (UDM) then DNAT-rewrites the destination
to our Mac&rsquo;s LAN IP before the packet leaves the UDM. From the cam&rsquo;s
point of view it&rsquo;s connecting to `9.9.9.9`; from the Mac&rsquo;s point of
view the packet arrives at the local LAN.

**Why it&rsquo;s only partially effective**: the filter stops naive DNS
attacks but does nothing against a router-level NAT attacker. Our
attack is precisely that — we own the router, so we can rewrite at
L3 below where the cam&rsquo;s filter operates. The filter would be
much stronger if combined with TLS pinning (which isn&rsquo;t present) or
with certificate-embedded IP addresses (also not present).

## TLS cert / key pinning — absent

The camera accepts any TLS certificate that:

1. Matches the SNI hostname it sent (`user.hapseemate.cn`)
2. Validates a TLS handshake (signs the key exchange)

It does NOT verify:

- Certificate authority chain (CA bundle not checked)
- Certificate fingerprint (no pinning)
- Public key fingerprint (no pinning)
- Expiry date (probably — not tested rigorously)

Our `fake_cbs_server.py` ships a self-signed cert generated via
`openssl req -x509 -nodes -newkey rsa:2048` with a SAN block covering
all the known hostnames. The cam completes TLS 1.2 handshake with
this cert every time, negotiating
`ECDHE-RSA-AES256-GCM-SHA384`.

**This is the vendor&rsquo;s biggest mistake.** If TLS pinning were in
place, we would have a much harder fight — we&rsquo;d need to either find a
firmware flash dump to extract the pinned public key, or use some
kind of out-of-band cert replacement. Neither is impossible but both
are substantially more work than "write a Python TLS server".

## Kalay body obfuscation

Several message bodies — confirmed for `DEV_LGN_CRC` (44 B) and
`REPORT_SESSION_RDY` (84 B) — are obfuscated. We **have not verified
which specific cipher**: it could be a simple XOR stream with a key
derived from `INIT_KEY`, a block cipher, or a hand-rolled proprietary
scheme. The function is probably `cs2p2p__P2P_Proprietary_Decrypt`
(which confusingly is called on both encrypt and decrypt paths).

**Why this is only partially effective as a defense**:

- For replay-based attacks, we don&rsquo;t NEED to decrypt. Replaying a
  captured body verbatim works for at least these cases:
  - `DEV_LGN_ACK` is a deterministic 8-byte constant
    (`a02aaac73b7755c9`) for a given DID, so we replay it forever
  - A `DEV_LGN_CRC` body from one keepalive round is replayable for
    other rounds within the same cam boot cycle
- The only attacks that **require** breaking the obfuscation are
  those that need to **craft** (not replay) a body with novel
  contents — e.g., a fake `DEV_LGN` claiming to be a different DID,
  or a custom `REPORT_SESSION_RDY` with an attacker-chosen endpoint
  set. We haven&rsquo;t attempted any of these.

**How to reverse it**: disassemble
`cs2p2p__P2P_Proprietary_Decrypt` in `libPPCS_API.so` and trace how
it uses the vendor init key. If it&rsquo;s pure XOR with a static key, the
reversal is trivial. If it&rsquo;s a block cipher or proprietary scheme,
it may take real effort. Not done yet.

## Hardcoded supernode IP

One of the three supernodes (`123.56.74.245`, Aliyun Beijing) is
hardcoded in the firmware — the cam never does a DNS lookup for it.
We confirmed this by observing that the DNS log shows zero queries
for any hostname resolving to that IP, yet the cam sends UDP/32100
traffic to it every 30 seconds.

**Implication**: a DNS-only interception is not sufficient. The IP
has to be caught at L3. We added a dedicated rule:

```sh
iptables -t nat -A PREROUTING \
  -s 192.168.5.37 \
  -d 123.56.74.245 \
  -j DNAT --to-destination 192.168.5.233
```

Without this rule, 1/3 of the cam&rsquo;s Kalay traffic would still reach
the real cloud.

## Session nonce in DEV_LGN

The DEV_LGN_CRC body contains a per-session nonce that rotates on
every cam reboot. This is not a "defense against us" per se, but it
does mean we can&rsquo;t replay a DEV_LGN from one cam boot session into
another — the cam&rsquo;s supernode state would reject it as a stale
credential.

In our setup this is moot because the cam generates fresh DEV_LGNs
every 30 seconds and we observe them all. But if we tried to use a
pcap from yesterday&rsquo;s boot to register today&rsquo;s cam, it wouldn&rsquo;t work.

## App-side telemetry (we avoid this entirely)

When the Android app is used for provisioning, it performs a step
called `getDidByToken`: before showing the Wi-Fi QR code, it POSTs
your home SSID and password to
`birds-user.hapseemate.cn/preadd/checkDidByToken` to get a
pre-allocated DID. **This leaks your Wi-Fi credentials to the vendor
cloud even before any camera is involved.**

We avoid this completely by using our own `wifiqr.py` script to build
the QR offline. No vendor-cloud round-trip, no credential leakage.
This isn&rsquo;t a "defense" the cam enforces — it&rsquo;s a convenience feature
the app uses — but it&rsquo;s a meaningful privacy escape hatch.

## Rate limiting — not observed (but one caveat)

We have hammered the cam with:

- Full 65535-port UDP LAN_SEARCH spray at ~7k pps
- Repeated SIGUSR1 injections of P2P_REQ
- Port-scanning probes

During those tests the cam kept responding normally. There&rsquo;s no
obvious connection-rate limit.

**Caveat**: during one of the 2026-04-15 sessions the cam went silent
for ~20 minutes mid-way through our injection experiments, then
recovered on its own. We assumed it was a watchdog-style crash and
restart (the cam was still ping-responsive the whole time), but we
can&rsquo;t completely rule out that the cam&rsquo;s code entered some kind of
long-interval backoff after enough anomalous packets. This is in
[`12-open-questions.md`](12-open-questions.md) as an unresolved item.
For now we treat it as "no observed rate limiting", but mentally
asterisked.

_Last updated: 2026-04-15 — Session 5_

## Firmware code signing — unknown

We have not performed a firmware update against this camera during
the investigation, so we don&rsquo;t know whether OTA firmware is signed
or encrypted. Things to check in a future session:

- Does the cam speak to a specific OTA endpoint? (Probably
  `public.dayunlinks.cn` based on the Android app&rsquo;s `Api.java`.)
- Does it verify a signature on the downloaded blob?
- Can we substitute a modified firmware image via the MITM?

If firmware signing is weak or absent, that opens a much more
powerful attack surface — we could flash custom firmware that
disables cloud traffic entirely.
