# 14 · Next steps

Concrete ordered plan for the next session(s). Each step includes
the "why", the specific commands / code, and the expected outcome
that tells you whether to proceed or fall back to an alternative.

> **Note**: `NEXT_STEPS.md` at the project root (the older version of
> this file) has been deprecated in favor of this doc. If you find an
> outdated copy of next-steps at the root, trust this one.

**Current blocker** (carries over from the session log): we can
observe everything the cam sends, but we can&rsquo;t get it to open a
data session because we don&rsquo;t know which Kalay message type the
real supernode uses to tell the cam "here&rsquo;s a peer". Our injection
attempts with `P2P_REQ (0x20)` and `PUNCH_TO (0x40)` are silently
dropped by the cam&rsquo;s device-role dispatcher, which accepts only
types `0x13, 0x30, 0x31, 0x3f, 0x52, 0x55, 0xdb, 0xdc`.

The rest of this doc assumes you&rsquo;ve read [`00-overview.md`](00-overview.md)
and [`08-attack-chain.md`](08-attack-chain.md).

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
