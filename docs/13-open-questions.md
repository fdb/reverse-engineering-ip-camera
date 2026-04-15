# 13 · Open questions

Everything we don&rsquo;t know yet, ordered roughly by priority. When
something here is resolved, move the finding into the appropriate
reference doc (usually `04-wire-format-kalay.md` or
`05-wire-format-cbs.md`) and leave a one-line pointer here
explaining where it went.

## Quick-answerable (10 minutes or less)

These are unknowns that could probably be resolved in a single
command or short test. Pick them off first.

### Is the CBS typo actually load-bearing?

Test: while the MITM is running, modify `mitm_cbs_proxy.py` to
rewrite the outgoing response body, replacing `"mssage"` with
`"message"` (corrected spelling) before forwarding to the cam. Watch
whether the cam goes back into hot-retry mode or stays satisfied.
One-line patch. Documents whether the typo is actually required or
it&rsquo;s some other field in the response that the cam parses.

### Does the cam accept non-RFC1918 IPs OTHER than `9.9.9.9` and `203.0.113.37`?

Test: temporarily rewrite dnsmasq to point `user.hapseemate.cn` at
different sink IPs and see which ones the cam tries to connect to.
Candidates: a random Aliyun range (to test if there&rsquo;s a
"must-be-Chinese-IP" whitelist), an AWS range, a cloudflare range,
an RFC 5737 documentation range. Three or four test IPs × 10 seconds
each tells us whether the filter is a pure RFC1918 check or
something more elaborate.

### Does the DEV_LGN_ACK really work for any session?

Test: in `mitm_supernode_proxy.py`, instead of forwarding DEV_LGN to
the real supernode, reply immediately with the canned
`a02aaac73b7755c9` constant. Watch if the cam advances its state
machine as if a real ACK had arrived. Tests whether the ACK is
really deterministic-per-DID or whether some session context matters.

### Can we ping the cam&rsquo;s `:32108` from a different Mac source port?

LAN_SEARCH works from any port we&rsquo;ve tried, but is there a port-based
filter we haven&rsquo;t noticed? Test: source-spoof from port `32100` and
see if behavior changes. (Answer will likely be "no change" but worth
confirming.)

## Protocol-level unknowns

## Protocol-level unknowns

### What message type does the supernode send to notify the cam of a peer?

**Priority: highest.** This is the single blocker to retrieving video.
The cam&rsquo;s `thread_recv_Proto` dispatcher accepts 8 message types
(`0x13, 0x30, 0x31, 0x3f, 0x52, 0x55, 0xdb, 0xdc`) but we don&rsquo;t know
which one carries a "peer wants to connect" payload, and we don&rsquo;t
know the body format of any of the non-trivial ones.

**Plan**: the "fake client via real supernode" approach — write a
minimal Python client that speaks the app-side protocol to the real
supernode, asking for our cam&rsquo;s DID. The real supernode then sends
the correct notification to the cam through our MITM pipe, and we
observe it in cleartext in `/tmp/cam-listen/mitm_supernode.log`. See
[`14-next-steps.md`](14-next-steps.md).

**Alternative plan**: run the vendor Android app in an isolated
emulator for 5 seconds against this cam, capture the traffic, observe
the notification. Less pure but probably fastest.

### What are message types `0x31`, `0x3f`, `0x52`, `0x55`, `0xdb`, `0xdc`?

**Priority: high.** These are the types the cam&rsquo;s dispatcher
explicitly handles that we haven&rsquo;t identified.

- `0x31` — adjacent to `0x30 LAN_SEARCH`. Possibly an ack variant
  or a LAN notification subtype.
- `0x3f` — close to `0x40 PUNCH_TO`. Could be a Kalay variant of
  an older CS2 message.
- `0x52`, `0x55` — mid-range Kalay-era extensions. No clues from
  symbol names.
- `0xdb`, `0xdc` — high range, close to the `0xD0 DRW` family.
  Could be DRW session control (init / close / reconfigure).

**Plan**: each type should be visible if the cam sends one of them.
Setting up a longer passive capture (run the MITM for hours, collect
everything unusual) would probably surface them, especially during
session setup after a successful peer connect.

### What&rsquo;s inside the XOR-obfuscated bodies?

**Priority: medium.** The `DEV_LGN_CRC (0x12)` body is 44 bytes of
obfuscated data, the `REPORT_SESSION_RDY (0xF9)` body is 84 bytes.
We can replay them but not read or construct them.

**Plan**: disassemble `cs2p2p__P2P_Proprietary_Decrypt` (the
obfuscation function) in `libPPCS_API.so` and reverse the key
schedule. The key is derived from the vendor init key passed to
`PPCS_Initialize`.

**Why we don&rsquo;t need this urgently**: the replay approach works for
keeping the cam registered. Decryption would only matter if we want
to construct novel encrypted bodies for a different DID.

### What does `cs2p2p_PPPP_DecodeString` actually do?

Despite the name, we suspect it&rsquo;s the XOR-obfuscation routine.
Symbol: `_Z24cs2p2p_PPPP_DecodeStringPcS_i`. Takes two `char*` and
an `int`. Need to disassemble and confirm.

### What&rsquo;s the app-side DEV_LGN / login sequence?

**Priority: high** (needed for fake client approach). We know the
**device-role** login sequence (HELLO → DEV_LGN_CRC → DEV_LGN_ACK).
We don&rsquo;t know whether a **client-role** login has the same or a
different handshake. Possibilities:

- It uses the same HELLO but with a different follow-up message
  (maybe `RSLgn` = Relay Server Login).
- It uses a completely different handshake built on top of a
  client-side init flow we haven&rsquo;t seen.

**Plan**: disassemble `PPCS_Connect` in `libPPCS_API.so` to see what
the client-role path does. Or observe it from the wire by running
the Android app once.

## CBS HTTPS unknowns

### What other CBS endpoints does the cam call?

**Priority: medium.** We&rsquo;ve only seen `/preadd/didBindUserId`. The
`libCBSClient.so` strings hint at at least:

- `GET /index.html?key=...&deviceId=...&sid=...&liveinterval=...` —
  some kind of long-poll / session config endpoint. Never observed
  on the wire.
- `http_post:...` — at least one POST endpoint we haven&rsquo;t triggered.

**Plan**: run the MITM for longer and see if the cam calls anything
new. Or trigger edge cases like OTA update check, motion detection,
live streaming request.

### What&rsquo;s the OTA update endpoint?

**Priority: medium, long-term.** Status: **app-side fully answered in
Session 6 Wave 3, cam-side still open.**

**What we learned (app side):**

- The app calls `POST https://public.dayunlinks.cn/public/checkVer` on
  every startup. Captured live in Session 6 as exchange 0017.
  Response: `{"ver":0,"message":"The app version is the latest","status":200}`.
  We are currently on V360 Pro 6.5.0 and the server agrees.
- `/public/checkDevVer` (the _device_ version check) is only fired
  once a cam has been bound to the user&rsquo;s account. We did not
  trigger it because the fake-DID manual-add flow does local LAN
  discovery first and never calls the backend for validation.
  Triggering it requires binding a real cam, which is parked as a
  future step in [`14-next-steps.md`](14-next-steps.md).
- The `public.dayunlinks.cn` host CNAMEs through
  `birds-public.philipsiot.com` to Signify / Philips IoT
  infrastructure at `190.92.254.74`. See
  [`03-cloud-topology.md`](03-cloud-topology.md).

**What we learned (cam side, via APK static analysis):**

The Android app **does not download firmware**. Session 6 Wave 3 RE of
`decompiled/sources/com/qianniao/**` showed that the entire firmware
update protocol from the app&rsquo;s side is a single Kalay IOCTRL command:

```
IOTYPE_USER_IPCAM_SET_UPGRADE_REQ = 0x8116
payload = 36 bytes, all zero
```

sent via `P2pSDK.updateDeviceFlash(did)` (see
[`04-wire-format-kalay.md`](04-wire-format-kalay.md) §DRW IOCTRL
commands). There is no URL in the payload, no signature, no version
selector. The cam is expected to self-fetch firmware from its own
baked-in update server after receiving this command. This means
**capturing the firmware binary requires cam-side interception, not
app-side** — which is good news because our router-side MITM pipeline
is already positioned for exactly that.

**Still unknown**:
- **Where does the cam fetch firmware from?** This is now the central
  question. The cam-internal update URL is not visible anywhere in
  the Android APK, because the app doesn&rsquo;t know or care. Options to
  discover it:
  1. Trigger a real update via the bind-real-cam path, watch the
     cam&rsquo;s outbound HTTPS on the router-side MITM. (See
     [`14-next-steps.md`](14-next-steps.md).)
  2. Teardown + UART + grep the cam filesystem for hostnames, once
     we have a physical dump.
  3. Static analysis of the `libCBSClient.so` ARM binary (we have a
     copy from the APK, but it is the client-side library — the cam
     has a different, probably similar but not identical copy).
- **Does the cam verify a firmware signature before flashing?**
  Client-side signature verification does not exist (because the
  client doesn&rsquo;t touch the firmware). On-cam verification is
  untested. Major question for future physical-access sessions.
- **Request body / HMAC on `checkDevVer`**. We know the endpoint
  exists from `Api.java:266-267` but haven&rsquo;t seen a request yet.

### Does the cam verify signature on OTA firmware?

Unknown — and Session 6&rsquo;s APK RE narrows where the answer lives.

The **client** does not verify anything (no hash, no signature, no
public key in the Android APK — because the client doesn&rsquo;t touch
the firmware). Whatever validation exists is **entirely on the cam
itself**, running in the cam&rsquo;s own firmware, which we don&rsquo;t have
a copy of.

If no on-cam signature check: we can flash custom firmware trivially
once we know the update URL and can MITM the cam&rsquo;s download.

If there is an on-cam signature check: we&rsquo;d need to find the public
key, which is probably baked into the cam&rsquo;s u-boot or init binary —
which again requires a firmware dump.

**This question is blocked on physical firmware extraction OR on
capturing a real update cycle through the router-side MITM.** See
[`14-next-steps.md`](14-next-steps.md).

### Where does the cam fetch firmware from?

**Priority: high** (moved up from implicit to explicit in Session 6).
The Android app never sees the firmware URL — it just sends the
Kalay IOCTRL `0x8116` and trusts the cam to handle the rest. So the
URL is stored on the cam itself, either as a baked-in string or
fetched from the cam&rsquo;s own initial-config path.

**Plan**: bind the real cam to the throwaway test account on the
emulator, tap "Check for updates" in the cam detail view, and
watch `mitm_cbs.log` + `mitm_supernode.log` for any HTTPS call the
cam initiates that we haven&rsquo;t seen in its normal keepalive traffic
(currently limited to `user.hapseemate.cn/preadd/didBindUserId`
and the Kalay supernode HA trio). Documented as a Session 7 step in
[`14-next-steps.md`](14-next-steps.md).

## Hardware unknowns

### What SoC does the cam use?

Unknown. Probably Hisilicon or similar low-end ARM. Would determine
whether we can run existing exploit chains, whether UART debug is
likely to be exposed, etc.

**Plan**: physical teardown, photograph board, identify chip markings.

### Is there a UART debug console?

Unknown. Very likely yes — cheap Chinese cams almost always expose
UART pads. Would give us a root shell and a way to dump firmware.

**Plan**: teardown + continuity-check candidate UART pads. Boot at
various baud rates while logging.

### Is there an SPI flash chip we can dump?

Unknown. Would give us the full firmware image without having to
rely on OTA capture.

**Plan**: identify the flash chip in-circuit, use `flashrom` +
CH341A programmer to dump.

### Why is ONE supernode hardcoded and not the other two?

`123.56.74.245` (Aliyun Beijing) is hardcoded in firmware and never
resolved via DNS. The other two supernodes (`8.134.120.63`,
`47.89.232.167`) are DNS-resolved from `p2p5.cloudbirds.cn` and
`p2p6.cloudbirds.cn`. Why the asymmetry?

Possible reasons:

- The hardcoded IP is a **bootstrap fallback** used when DNS is
  broken (which could happen if the Wi-Fi network doesn&rsquo;t have a
  working upstream DNS resolver).
- The hardcoded IP is a **failsafe** if the vendor decides to
  migrate the p2p5/p2p6 DNS entries to different servers — the cam
  always has at least one guaranteed working path.
- The hardcoded IP is a **firmware-version marker** — different
  firmware revisions might have different hardcoded fallbacks, and
  we could use this to fingerprint the version.

Not investigated further. Worth noting for any inventory of Kalay
devices where you want to identify the firmware version without
triggering a boot sequence.

## Infrastructure unknowns

### Why does the cam occasionally go fully silent for 20+ minutes?

Observed during our Session 3 / 4 debugging: the cam stopped sending
any traffic between ~00:36 and ~00:57 on 2026-04-15. We assumed a
crash but the cam was ping-responsive the whole time. Possibly:

- The cam&rsquo;s main loop entered a sleep state due to repeated session
  failures
- The cam&rsquo;s DEV_LGN retry backoff hit a cap
- Our injection spam confused its state machine into a long retry
  interval

**Plan**: run the MITM for a long stretch and grep for any period
of unexpected silence. Correlate with what we injected at the time.

### Does the cam have a watchdog that reboots it after silent periods?

Unknown. Would explain some of the "I rebooted it and now it&rsquo;s
back" behavior we&rsquo;ve seen, but not proven.

### What does `libnms.so` do?

The symbol table is stripped, we only see header strings. "NMS"
probably stands for "Network Management Service". Possible candidates:

- On-device RPC for config / admin
- A local HTTP server we haven&rsquo;t found
- A ByteDance-specific telemetry layer (the string
  `com.pgl.ssdk.ces.a` appears, which is a ByteDance SDK)

**Plan**: disassemble the exported symbols, see what sockets it
opens, trace network activity to identify what it actually does.

## Attack-chain edge cases

### Does the DNS rebinding filter have any other gating conditions?

We confirmed it rejects RFC1918 IPs for control-plane hostnames.
But:

- Does it check for public-IP ranges that are actually valid (e.g.,
  a Chinese public IP range)?
- Does it have a blocklist of specific IPs we should avoid?
- Does it whitelist only specific public IP ranges (e.g., Aliyun)?

**Plan**: probe by trying a handful of synthetic public IPs as the
dnsmasq target and see which ones the cam accepts. TEST-NET-3 works;
`9.9.9.9` works; a random AWS IP should work too. A blocklist or
whitelist would become apparent.

### Can we run multiple cameras simultaneously on the same MITM?

Unknown — we only have one cam to test. The `mitm_supernode_proxy.py`
code is per-session, so it should handle multiple cams fine, but the
iptables rules are hardcoded to a single cam IP. Trivial to extend
if needed.

### What happens if the UDM reboots mid-session?

conntrack state is lost on reboot. Our iptables rules don&rsquo;t
persist without a boot script. So a cold-boot of the UDM would
break the MITM until we restore both.

**Plan**: move the iptables rules into `/data/on_boot.d/` as a
proper boot script. Add dnsmasq config to a persistent location.

## Meta

### Is there an existing Python implementation of CS2 PPPP we can reuse?

There are a few open-source projects that have cracked parts of CS2
PPPP for various OEM cameras (Yoosee, Sricam, V380, etc). Haven&rsquo;t
surveyed them yet. If one of them has a working client-side
implementation with the right init key format, we could bootstrap
from it instead of writing a fake client from scratch.

**Plan**: search GitHub for "PPCS_Initialize", "Throughtek Kalay",
"CS2 PPPP" Python implementations.

_Last updated: 2026-04-15 — Session 6_
