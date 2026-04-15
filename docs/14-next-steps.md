# 14 · Next steps

Concrete ordered plan for the next session(s). Each step includes
the "why", the specific commands / code, and the expected outcome
that tells you whether to proceed or fall back to an alternative.

> **Note**: `NEXT_STEPS.md` at the project root (the older version of
> this file) has been deprecated in favor of this doc. If you find an
> outdated copy of next-steps at the root, trust this one.

**Primary objective (as of Session 6):** capture the cam&rsquo;s
**firmware binary** in flight during a self-update cycle.

**Status update (Session 8):** Step A was executed in Session 8. We
captured the complete cam firmware upgrade endpoint
(`dev-silent-upgrade.cloudbirds.cn/ota/device/version/upgrade/query`),
its full response schema (including the `url`, `md5`, `size`, `soc`
fields), and its deterministic "code=13016 / up-to-date" behavior
across 28 DID prefixes, 6 spoofed versions, 5 HTTP methods, 15+
sibling paths, and two independent APK versions (6.5.0 + 6.8.7).
**We did NOT obtain a firmware binary** — the cam is genuinely on the
latest version and the server has no download URL to emit for this DID.

See [`03-cloud-topology.md`](03-cloud-topology.md) §"Cam firmware
upgrade endpoint" for the full endpoint documentation, and
[`13-open-questions.md`](13-open-questions.md) §"Where does the cam
fetch firmware from" for the exhaustive probe list. The firmware-binary
goal is now blocked on either (a) Qianniao releasing new firmware, or
(b) acquiring a second cam on an older firmware. See Step E below.

**Secondary blocker (from Session 5, still unresolved):** we can observe
everything the cam sends, but we can&rsquo;t get it to open a DRW data
session because we don&rsquo;t know which Kalay message type the real
supernode uses to tell the cam "here&rsquo;s a peer." Injection attempts
with `P2P_REQ (0x20)` and `PUNCH_TO (0x40)` are silently dropped by the
cam&rsquo;s device-role dispatcher, which accepts only types
`0x13, 0x30, 0x31, 0x3f, 0x52, 0x55, 0xdb, 0xdc`. This still matters
for video capture and for directly crafting an `0x8116` IOCTRL to the
cam — see Step C below — but the firmware capture path (Step A) does
not depend on it.

The rest of this doc assumes you&rsquo;ve read [`00-overview.md`](00-overview.md)
and [`08-attack-chain.md`](08-attack-chain.md).

## Step E — Buy a second Qianniao cam on older firmware

**Priority: high** (Session 9+ recommended primary path). Given the
Session 8 negative result on firmware capture from our current cam,
the cheapest guaranteed path to a firmware binary is to acquire a
second cam that&rsquo;s shipped with older firmware.

**Why this works**: Qianniao&rsquo;s upgrade server is DID-keyed — it
looks up "what&rsquo;s the latest firmware for THIS specific DID" and
returns 13016 ("up to date") when no newer mapping exists. Our cam&rsquo;s
DID `CFEOA-417739-RTFUU` is mapped to `V30904.1.149build20250721`
(the same version we&rsquo;re running). But a cam that sat in an
AliExpress / Taobao / Amazon warehouse for a few weeks before
shipping will be running an older firmware version, and the server
WILL offer it an upgrade during its first cold-boot check — which we
capture with the Wave 4 pipeline intact.

### Candidate products (any of these should work)

All are published by Shenzhen Qianniao Xiangyun Technology Co., Ltd.
and share the same Kalay + CBS backend stack:

- **V360 Pro** branded cams — the same physical product family as
  our current cam. DID prefix `CFEOA-*`. Cheapest, most direct
  comparison.
- **HapSee / HapSeeMate+** branded cams — different retail brand,
  same OEM. DID prefix unknown but suspected `HAPSE*` or similar.
- **KeepEyes** — third Qianniao brand (App Store verified). Likely
  different DID prefix, may be on a different firmware track.
- **Philips Home Camera** — Qianniao&rsquo;s Philips-branded line.
  Confirmed from both Session 6 DNS (via `birds-public.philipsiot.com`
  CNAME) and Session 7 aiseebling / `www.cloudbirds.cn` HTML
  comments. Usually more expensive but has the strongest brand
  credibility for a white-label OEM product.
- **Smaint** / **Xinshian** / **Yunkankan** — other confirmed
  reseller brands seen in `aiseebling.com` / `www.cloudbirds.cn`
  HTML. Availability varies by market.

### Procedure once the cam arrives

1. Run Phase 0 preflight on [`09-router-setup.md`](09-router-setup.md)
   to check/restore the MITM pipeline state.
2. Re-apply the Wave 4 default-deny pipeline via
   `scripts/phase2_veto_gate_apply.sh`, adapted to the new cam&rsquo;s
   source IP if it differs from `192.168.5.37`. (Set a DHCP
   reservation on the UDM before provisioning so the IP is stable.)
3. Provision the new cam&rsquo;s Wi-Fi via `wifiqr.py` (no vendor app
   needed — bypasses the `getDidByToken` telemetry step).
4. **Let the cam cold-boot through the MITM**. Within 30-60 seconds
   of Wi-Fi association, the cam will autonomously hit
   `dev-silent-upgrade.cloudbirds.cn/ota/device/version/upgrade/query`
   with its own DID and shipped version.
5. **Watch the capture directory** for the exchange. If the server
   returns a non-empty `url` field, copy it out.
6. **Fetch the firmware binary separately** from the captured URL.
   Use `curl` from the Mac with the cam&rsquo;s User-Agent and headers
   replayed from the capture. This is Phase 7 from the Wave 4 spec
   — gated on owner approval because it leaks our WAN IP to the
   cam&rsquo;s update server.
7. **Run binwalk / file / strings** on the downloaded binary to
   confirm it&rsquo;s a real firmware image (not an encrypted blob).
8. **Document everything** in `docs/12-session-log.md` Session 9 entry.

### Risks / considerations

- **DID prefix mismatch**: if the new cam&rsquo;s DID prefix maps to a
  completely different firmware track, the response schema might
  differ slightly. Have the capture pipeline generous enough to log
  unknown fields.
- **Cam might come pre-upgraded**: very new stock may have been
  firmware-refreshed before shipping. Try to buy older stock or from
  a seller with high turnover.
- **Not all Qianniao brands share the same upgrade infrastructure**:
  the Philips brand in particular may point at a different OEM
  backend (that&rsquo;s what the `birds-public.philipsiot.com` CNAME in
  Session 6 suggested). If the Philips cam hits a different upgrade
  server than `dev-silent-upgrade.cloudbirds.cn`, we&rsquo;d learn
  something about brand-specific OEM segmentation.

## Step A — Firmware capture via bind-real-cam (Session 8 executed, no binary obtained)

**Goal**: get a copy of the cam&rsquo;s own firmware binary by letting the
normal app flow trigger a self-update cycle, with the cam&rsquo;s
outbound traffic going through our router-side MITM.

> ✅ **Session 8 execution status**: the full flow was executed end
> to end. The cam was factory-reset and re-provisioned, its cold-boot
> upgrade check was captured
> (`dev-silent-upgrade.cloudbirds.cn/ota/device/version/upgrade/query`),
> and the complete response schema was documented. But the server
> returned `code=13016 / "version is latest"` for every query we
> crafted — 28 DID prefixes, 6 version spoofs, 5 HTTP methods, 15+
> sibling paths, both 6.5.0 and 6.8.7 APK versions. **No download URL
> was emitted** because our cam&rsquo;s DID is genuinely mapped to the
> latest firmware server-side. The Wave 4 pipeline works; the cam is
> just "too new." See Step E above for the follow-up path.

### Risk assessment first

This step **binds the real cam to a throwaway account**. Implications:

- The cam&rsquo;s prior binding to the owner&rsquo;s primary account may be
  invalidated or put in a "shared" state, depending on the OEM backend
  logic.
- On unbind (undoing this), the cam may factory-reset its user state
  (stored creds, customised settings).
- We are **not** flashing anything to the cam. The goal is just to
  observe the cam&rsquo;s outbound HTTPS during a version check.
- If the cam is already on the latest firmware version (likely — cam is
  fresh), the update server may return "no update" without emitting any
  download URL, and we learn nothing beyond the check endpoint. Have a
  plan for forcing the cam to think it&rsquo;s outdated.

### Sub-steps

1. **Verify pipeline**. Run the preflight rule from
   [`09-router-setup.md`](09-router-setup.md) Phase 0. `dig
   @192.168.5.1 user.hapseemate.cn` must return `203.0.113.37` and the
   camre-tagged iptables rules must be in place. Also confirm
   `mitm_cbs_proxy.py` and `mitm_supernode_proxy.py` are running and
   capturing to `captures/ota/<ts>/`.
2. **Enumerate new hostnames first**. Before triggering the bind, scan
   `libCBSClient.so` for any embedded hostname strings that might be
   the cam&rsquo;s own update URL. Use `strings /path/to/extracted/lib/arm64-v8a/libCBSClient.so | grep -iE 'http|\.cn|\.com|upgrade|fw'`.
   Add any new hostnames found to the dnsmasq sinkhole list in
   `/run/dnsmasq.dhcp.conf.d/cam-override.conf` and re-apply Phase 1
   of `09-router-setup.md` before proceeding. **This is critical** —
   if the cam&rsquo;s update URL points at a hostname we&rsquo;re not
   intercepting, the firmware bytes will stream directly to the real
   update server and we&rsquo;ll see nothing useful in the MITM log.
3. **Launch the emulator** (`camtest` AVD, already created in
   Session 6 and preserved at `~/.android/avd/camtest.avd`), start
   the V360 Pro app, and log in with the Session 6 throwaway account
   (`deep.pack3852@fastmail.com`, masked). Re-enable `adb reverse
   tcp:443 tcp:8443`.
4. **Add the cam by real DID** (`CFEOA-417739-RTFUU`). Use the
   `Scan to add` or `QR code add` flow. The app will hit
   `/preadd/didBindUserId` and related endpoints; these should all
   land in the cbs-proxy capture dir.
5. **Tap the cam in the list → Settings → "Firmware" / "Check for
   updates"**. This should fire `/public/checkDevVer` against
   `public.dayunlinks.cn` (seen via our proxy) AND, upon receipt of
   an available update, send an `0x8116` IOCTRL to the cam over a
   DRW session that the app itself opens.
6. **Watch the supernode + cbs logs for new hostnames**. The cam&rsquo;s
   self-fetch will probably hit a hostname we haven&rsquo;t seen. If DNS
   sinkhole is in place for it, the cbs proxy captures the stream.
   If not, it leaks to the real cloud — repeat step 2 with the new
   hostname and retry.
7. **If the cam is "already latest"**, the server won&rsquo;t emit a
   download URL. Workarounds:
   - **Spoof a downgraded version in the request**. Requires intercepting
     the `checkDevVer` request body, decoding it, and replacing the
     version string. Possible but requires parsing the request format.
   - **Unbind and re-bind** to see if that triggers a mandatory update
     check with a fresh timestamp. Low-confidence.
   - **Wait for the vendor to push a newer release**. Opportunistic,
     not actionable now.

**Fallback**: if Step A cannot be completed this session (privacy
concerns about binding, vendor refuses bind, etc.), defer to Step C
(direct IOCTRL injection, once DRW access is solved) or Step D
(physical extraction).

## Step B — Offline decryption of remaining AES-protected payloads

**Goal**: catalog every use of the five AES keys baked into
`AesUtil.java` (`DATA_KEY`, `DOMAIN_KEY`, `URL_KEY`, `WEB_KEY`,
`XIAODUAI_KEY`). `URL_KEY` was cracked and used in Session 6 to decrypt
the `/domainname/all` response (see [`03-cloud-topology.md`](03-cloud-topology.md)).
The other four are still mystery-data.

**How**: grep `decompiled/sources/com/qianniao/**` for each field
name, identify call sites, log what payload types flow through each
key, then decrypt any captured payloads we have that use those keys.
Very quick — mostly reading, no tooling required. Could be a
subagent task.

## Step C — Direct IOCTRL `0x8116` injection

**Goal**: force the cam to upgrade without going through the app at
all. Send the Kalay DRW frame `0xD0` + IOCTRL `0x8116` (36 zero
bytes) directly.

**Blocker**: we don&rsquo;t yet have DRW access. The cam will not open a
DRW session for us because we can&rsquo;t pass the device-role dispatcher
check (see secondary blocker at the top of this doc). Solving this
unlocks (a) video capture via DRW and (b) direct firmware upgrade
via `0x8116` — one shared prerequisite.

Reference: [`04-wire-format-kalay.md`](04-wire-format-kalay.md) §DRW
IOCTRL commands for the full command catalog.

## Step D — Physical firmware extraction (fallback if Step A fails)

**Goal**: get the cam&rsquo;s firmware by opening it. See
[`13-open-questions.md`](13-open-questions.md) §"Does the cam verify
signature on OTA firmware" for the tradeoffs. Rough plan:

1. Teardown, photograph the PCB, identify the main SoC (probably a
   Hisilicon or similar low-end ARM; chip markings TBD).
2. Identify the SPI/eMMC flash chip. For SPI, desolder OR use a test
   clip + CH341A programmer. For eMMC, lift the chip or find test
   pads.
3. Dump the full flash image. Parse with `binwalk` to find the
   filesystem partitions.
4. Mount/extract the root filesystem. Grep for update-related
   hostnames, public keys, verification logic.

Higher effort than Step A but guaranteed to yield a firmware dump.

## Step 0 — Survey existing open-source Kalay clients (10 min)

Before writing anything from scratch, spend 10 minutes searching
GitHub for prior RE work on CS2 PPPP / Throughtek Kalay. Several
people have cracked parts of the protocol for other OEMs (Yoosee,
Sricam, V380, YI). If one of them has a working client-side
implementation with the right init-key format, we can bootstrap from
it instead of reinventing everything.

Search terms:

- `"PPCS_Initialize" python`
- `"Throughtek Kalay" implementation`
- `"CS2 PPPP" reverse engineering`
- `kalay p2p client python`
- `iotcare_lan beacon`

If we find a working implementation, skip to Step 2c (observe the
notification) and use the existing client to generate the traffic.
The `libPPCS_API.so` we have is likely to be similar enough that the
same code will work with our vendor&rsquo;s init key.

## Step 1 — Verify the MITM pipeline is still running

Before any new work, confirm nothing has fallen over:

```sh
lsof -iUDP:32100 -iTCP:8443 -n -P
tail -20 /tmp/cam-listen/mitm_supernode.log
tail -20 /tmp/cam-listen/mitm_cbs.log
ssh root@192.168.5.1 'iptables -t nat -L PREROUTING -v -n --line-numbers'
ping -c 2 192.168.5.37
```

If any piece is missing, see [`09-router-setup.md`](09-router-setup.md)
for how to restore it.

## Step 2 — Fake client approach (primary path)

**Goal**: impersonate an app-side client asking the real supernode
to connect to our cam. The supernode handles the hard part (sending
the correct notification to the cam) and our MITM observes that
notification in cleartext.

### Step 2a — Decide on implementation strategy

Three options, pick one:

1. **Python client from scratch** — write ~200 lines that speak
   enough app-side Kalay to trigger a notification. Requires
   disassembling the client-side login sequence from `PPCS_Connect`
   in `libPPCS_API.so`. Most educational, slowest.

2. **dlopen the native library in Docker ARM64** — use a Linux
   ARM64 container on the Mac (via Rosetta2), write a ~50-line C
   wrapper that calls `PPCS_Initialize(vendor_key)` and
   `PPCS_Connect(did, mode=0, 0)`. Fast, reuses vendor code.
   Needs Bionic → glibc compatibility work.

3. **Android emulator with a minimal test APK** — ~30 lines of
   Kotlin that does nothing except the PPCS library calls, bundled
   with the native libs, installed on an emulator. Emulator&rsquo;s
   traffic goes through our Mac so the MITM captures everything.
   Fastest to first capture, least pure.

**Recommended**: start with option 3 (Android emulator). Once we
have one captured notification from the real supernode, we can
replay it forever via SIGUSR1 injection without any further emulator
runs.

### Step 2b — Build / run the client

**For option 3**, the workflow is:

1. Install Android Studio on the Mac (if not already). Android SDK
   Manager → install a recent system image.
2. Create an emulator AVD. Any recent API level is fine.
3. Create a new Android Studio project "CamTest" with an empty
   Activity. Language: Kotlin.
4. Copy the three native libs from `extracted/lib/arm64-v8a/` into
   `app/src/main/jniLibs/arm64-v8a/`:
   - `libPPCS_API.so`
   - `libCBSClient.so`
   - `libc++_shared.so`
5. Add the JNI binding class (copy `PPCS_APIs.java` from
   `decompiled/sources/com/p2p/pppp_api/` to the same package
   path in your new project).
6. In `MainActivity.onCreate`, call:

   ```kotlin
   PPCS_APIs.PPCS_Initialize(
       ("EEGDFHBLKGJIGEJCECHIFFEKHKNAHBNAHAFJBECFADJELOLDDPAKCHOEGCLGJPLDACMCKODGOGMNBHCCJDMH\u0000").toByteArray()
   )
   val session = PPCS_APIs.PPCS_Connect("CFEOA-417739-RTFUU", 0, 0)
   // keep the session alive — MITM captures the traffic
   ```

7. Build, install, run on the emulator. Configure the emulator&rsquo;s
   network to go through the Mac (emulator runs on the host, so
   its outbound DNS naturally goes to Mac&rsquo;s configured resolver).
8. Also make sure the emulator&rsquo;s DNS resolves cloudbirds.cn to
   `9.9.9.9` — may need to override the emulator&rsquo;s network config
   via `adb shell setprop` or a custom AVD.

### Step 2c — Observe the captured notification

As the emulator app calls `PPCS_Connect`, the real supernode will:

1. Receive a client login / P2PReq from the emulator
2. Look up the cam in its registry
3. Send SOMETHING to the cam&rsquo;s registered endpoint (which is our
   MITM proxy address)

Our `mitm_supernode_proxy.py` will log that packet. Look for any
message type OTHER than the usual `HELLO/DEV_LGN/DEV_LGN_ACK/F9`:

```sh
grep -vE "HELLO|DEV_LGN|REPORT_SESSION|UNK" /tmp/cam-listen/mitm_supernode.log | tail -20
```

**Expected result**: at least one new packet with a type byte we
haven&rsquo;t seen before. Capture its full hex dump — that&rsquo;s the rosetta
stone.

### Step 2d — Replay the captured notification

Once you have one good notification:

1. Copy its hex into `inject.json` targeting the cam&rsquo;s current
   session ports
2. `kill -USR1 <supernode-proxy-pid>` to fire the injection
3. Watch `/tmp/cam-listen/mitm_supernode.log` for the cam&rsquo;s reaction
   — should be new message types as it proceeds into session
   establishment
4. Simultaneously run a peer listener (`nc -ul 41234` or
   `python3 -c` oneliner) on whatever endpoint the notification
   claimed was "the peer"

**Expected result**: the cam starts sending packets toward the
claimed peer endpoint. We receive a `PUNCH_PKT` or similar at our
listener. From there, we&rsquo;re in the data path.

## Step 3 — Parse the data channel

**Goal**: once the cam is sending video, decode it.

### Step 3a — Disassemble `thread_recv_DRW`

Symbol: `_Z27cs2p2p_PPPP_thread_recv_DRWPv @ 0x1c9cc`. The main
receive loop for data channel frames. This will reveal:

- The DRW body framing: channel ID, sequence number, data
- Any inline CRC or length fields
- How multiple channels (video / audio / control) are demuxed

### Step 3b — Extract raw H.264

Most cheap cams send H.264 with a very thin wrapper: a 1-byte
channel ID, a 2-byte sequence number, then raw NAL units. Once we
know the wrapper we can strip it and feed the bytes directly to
ffmpeg or VLC.

Expected starting command:

```sh
mkfifo /tmp/cam.h264
ffplay /tmp/cam.h264 &
python3 drw_parser.py  /tmp/cam-listen/mitm_supernode.log > /tmp/cam.h264
```

### Step 3c — Handle audio if present

AAC or PCM, muxed into a separate DRW channel. Usually easier than
video — typically 8 kHz PCM for two-way-audio cams.

## Step 4 — Transition to airgap mode

**Goal**: remove the dependency on the real Chinese cloud entirely.
Serve all cloud responses from local canned data.

### Step 4a — Build the canned response bank

Collect every observed request/response pair from the MITM logs into
a JSON config file:

```json
{
  "cbs": {
    "/preadd/didBindUserId": {
      "content_type": "text/plain;charset=ISO-8859-1",
      "body": "{\"mssage\":\"success\",\"status\":\"200\"}"
    }
  },
  "kalay": {
    "HELLO_ACK": {"ip": "203.0.113.37", "template": "f101001000020000<port_be>cb0071250000000000000000"},
    "DEV_LGN_ACK": "f1130008a02aaac73b7755c9",
    // ...
  }
}
```

### Step 4b — Rewrite MITM proxies in "serve" mode

Modify `mitm_cbs_proxy.py` and `mitm_supernode_proxy.py` to match
incoming requests against the canned bank instead of forwarding to
real upstreams. When a request doesn&rsquo;t match anything in the bank,
log it loudly so we can add it.

### Step 4c — Block egress at the UDM

Add a firewall rule to drop all cam-originating WAN traffic except
NTP:

```sh
iptables -I FORWARD -s 192.168.5.37 -o eth4 -j DROP
iptables -I FORWARD -s 192.168.5.37 -o eth4 -p udp --dport 123 -j ACCEPT
```

(eth4 is the WAN interface on UDM. Confirm with `ip route`.)

### Step 4d — Full power cycle test

Reboot the UDM, reboot the cam, verify:

- Cam still provisions via our QR
- Cam&rsquo;s outbound traffic is all contained within the LAN
- Our MITM serves canned responses
- We can trigger a P2P session and pull video
- No Aliyun traffic leaves the house

## Fallback: if the fake client approach fails

If the real supernode rejects our fake client&rsquo;s login, or if the
notification we capture doesn&rsquo;t make the cam react as expected, try:

### Fallback A — Run the real vendor app for 5 seconds

Install the Android V360 Pro app on a throwaway emulator, let it
connect to the cam once, capture everything. Learn the protocol
from that single observation. Uninstall.

### Fallback B — Disassemble `Proto_Send_SSDP2PReq`

The Kalay-specific variant that the cam might actually listen for.
Symbol: `_Z32cs2p2p_PPPP_Proto_Send_SSDP2PReqPKciP11sockaddr_inPcjS3_S2_`.
Could reveal a different wire format than the classic CS2 P2P_REQ
we already decoded.

### Fallback C — Disassemble `thread_recv_Proto` fully

The function is ~9000 instructions. Painful but tractable. Trace
each `cmp w0, #0xNN` branch and see what handler it routes to.
That tells us the exact semantics of every accepted type.

## Time budget

Rough estimates for a focused session:

| Step | Estimate |
|---|---|
| 1. Verify pipeline | 5 min |
| 2a-b. Build fake client (option 3 Android) | 45-90 min |
| 2c. Observe notification | 10 min |
| 2d. Replay and confirm | 20-40 min |
| 3a. Disassemble thread_recv_DRW | 30-60 min |
| 3b. H.264 extraction prototype | 60-120 min |
| 3c. Audio support | 30-60 min |
| 4. Airgap transition | 60-120 min |

**Total to "airgap working video"**: 4-8 hours of focused work.
Most of that is in step 2 (getting the first capture) and step 3
(understanding DRW). Steps 0, 1 and 4 are relatively mechanical.

_Last updated: 2026-04-15 — Session 6_
