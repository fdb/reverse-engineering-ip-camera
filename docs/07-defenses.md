# 07 · Vendor defenses

What the vendor did to make local interception harder, what it missed,
and how each piece affects our attack.

## Summary

| Defense | Present? | Effective? | Our bypass |
|---|---|---|---|
| DNS rebinding filter | ✅ yes | 🔶 partial | Non-RFC1918 DNS override + IP-level DNAT |
| TLS certificate pinning (cam) | ❌ no | — | None needed |
| TLS public key pinning (cam) | ❌ no | — | None needed |
| **TLS trust on Android app** | ❌ **actively broken (allow-all)** | — | None needed — app allow-alls every cert (`com/qianniao/base/http/HttpClient.java:71-105`) |
| **`/domainname/all` AES-128-ECB obfuscation** | ✅ present | ❌ useless | Key `URL_KEY = "24QLQzq5DZjy4boX"` baked into `com/qianniao/base/utils/AesUtil.java`; ECB mode means no IV; decryptable offline. One MITM of this single response rewrites every downstream API host the app uses. |
| **Firmware upgrade endpoint authentication** | ❌ **none** | — | `dev-silent-upgrade.cloudbirds.cn/ota/device/version/upgrade/query` accepts cleartext DID in the query string with no HMAC, no nonce, no cookie, no session token. Fake DIDs (`FAKEA-000000-AAAAA`) receive the same response as real DIDs, so there&rsquo;s no DID validation. Captured and verified Session 7 Wave 4. |
| **Firmware integrity (on-cam, inferred)** | 🔶 **MD5 only** | ❌ trivially spoofable | The upgrade-check response schema has an `md5` field but no signature/public-key field (`03-cloud-topology.md` §"Cam firmware upgrade endpoint"). This strongly implies the cam verifies downloaded firmware by computing MD5 and comparing to the server-provided value — with no asymmetric cryptography. Since MD5 is collision-broken, any party controlling the download path can ship modified firmware plus a crafted MD5. **Not yet proven**; inference from response schema. A firmware dump would confirm or refute. |
| **Firmware upgrade authentication** | ❌ none | — | Kalay IOCTRL `0x8116` is a zero-payload "upgrade yourself" trigger with no auth, no nonce, no signature — whoever can reach the cam over DRW can force-upgrade it. |
| **Client-side battery check on upgrade** | ✅ present | ❌ client-side only | `DeviceInfoFragment.java:198-209` refuses upgrade if `batteryVolume <= 25`, but this is a UX gate — sending IOCTRL `0x8116` directly bypasses it entirely. |
| Kalay body obfuscation | ✅ yes | 🔶 partial | Replay known-good packets |
| Hardcoded supernode IP | ✅ yes | 🔶 partial | Dedicated IP-level DNAT rule |
| Session nonce in DEV_LGN | ✅ yes | ✅ yes | Not broken — cam regenerates per session |
| App-side telemetry | ✅ yes | ✅ yes | We don&rsquo;t run the app |
| Pre-QR cloud check | ✅ yes | ✅ yes | We don&rsquo;t run the app |
| Device auth in CBS | 🔶 unknown | 🔶 unknown | Obfuscated blobs in request — semantics unknown |
| Firmware code signing (on-cam) | ❓ unknown | — | Client does not sign or verify anything (no download path on client, per Session 6 Wave 3 APK RE). Whether the cam itself verifies downloaded firmware is untested and remains an open question. |
| Rate limiting | 🔶 not observed | — | None needed so far, see note below |

## AES key table (baked into the APK)

Five AES-128 keys are hardcoded in
`decompiled/sources/com/qianniao/base/utils/AesUtil.java:14-20`:

| Field name | Literal | What it protects |
|---|---|---|
| `DATA_KEY` | `"iyy17m8d2ah9care"` | Unknown — grep call sites to identify |
| `DOMAIN_KEY` | `"GO9gbwFjTcP9QOXR"` | Misleading name — NOT used for `/domainname/all`. Unknown payload class. |
| `URL_KEY` | `"24QLQzq5DZjy4boX"` | **`/domainname/all` response values** — each field is an AES-128-ECB ciphertext of a URL. |
| `WEB_KEY` | `"iyy18m8d25h9care"` | Unknown — possibly WebView content encryption |
| `XIAODUAI_KEY` | `"aiy20m8c24h4care"` | Unknown — the name "xiaodu ai" hints at a voice assistant integration |

**All five use ECB mode**, per the native `AesC.decrypt` JNI signature in
`decompiled/sources/org/openssl/aes/AesC.java:13` — the function takes no
IV parameter. ECB leaks structural information for any payload longer than
one block; if any long payloads flow through these keys, identical
plaintext blocks produce identical ciphertext blocks.

## `/domainname/all` one-shot backend takeover

**What it is.** On every SplashActivity boot, the app calls
`POST https://public.dayunlinks.cn/domainname/all` and receives an
encrypted JSON dictionary mapping every service name the app knows
(`user`, `push`, `pay`, `privacy`, `support`, etc.) to a URL. The app
decrypts this locally with `URL_KEY` and stores the URLs in `URLConfig`
(`com/qianniao/splash/SplashActivity.java:148-175`). Every subsequent API
call — login, device list, firmware check, push polling — reads its
target host from `URLConfig`.

**Why it matters.** Because the app&rsquo;s TLS trust is allow-all and the
decryption key is baked into the APK (so we can forge ciphertexts just as
easily as we can read them), a single MITM of this one response gives
the attacker full control over every downstream API hostname the app
will contact for the rest of its lifetime. The `URL_KEY` is static
across every install, so the forged response is universally valid.

**Why that&rsquo;s a "defense" in this table.** It&rsquo;s the vendor&rsquo;s attempt
at an obfuscation layer — presumably to make host substitution harder for
casual reverse engineers, or to allow runtime host rotation without an
APK update. As a security mechanism it fails open: it delivers none of
its apparent goals but adds a single point of takeover that wouldn&rsquo;t
exist if the hosts were just hardcoded.

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

**Our bypass**: DNS override to a non-RFC1918 sink. As of Session 6
we use `203.0.113.37` (TEST-NET-3, RFC 5737) — a reserved
documentation range that no real service operates on, so a DNAT miss
drops packets into the void instead of hitting a real third party.
Earlier sessions used `9.9.9.9` (real Quad9), which works but leaks
DNAT-missed packets to Quad9&rsquo;s logs; see `09-router-setup.md` for
the sink-IP rationale and `ERRATA.md` entry ERR-009 for the history
of this change. The cam passes the filter and attempts a TCP connect
to the sink IP. Our router (UDM) then DNAT-rewrites the destination
to our Mac&rsquo;s LAN IP before the packet leaves the UDM. From the
cam&rsquo;s point of view it&rsquo;s connecting to `203.0.113.37`; from the
Mac&rsquo;s point of view the packet arrives at the local LAN.

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
[`13-open-questions.md`](13-open-questions.md) as an unresolved item.
For now we treat it as "no observed rate limiting", but mentally
asterisked.

_Last updated: 2026-04-15 — Session 6_

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
