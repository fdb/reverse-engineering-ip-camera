# Wave 4 — Veto gate for cam egress + firmware URL capture

**Date:** 2026-04-15
**Session origin:** Session 6 (spec authored during), targeting Session 7 for execution
**Status:** Draft, awaiting owner approval
**Target executor:** A Claude Code session with full project access

---

## 0. Why this spec exists

Session 6 Wave 3 established that the Android client does **not** download
firmware. Instead, the app sends the cam a zero-payload Kalay IOCTRL
(`IOTYPE_USER_IPCAM_SET_UPGRADE_REQ = 0x8116`, 36 bytes of zeros — see
[`docs/04-wire-format-kalay.md`](../../04-wire-format-kalay.md) §DRW
IOCTRL commands) and the cam then **self-fetches firmware from its own
baked-in update server**. That means the firmware bytes never touch the
app-side network path, and app-side MITM is fundamentally the wrong
layer to observe them. The right layer is the **cam-side MITM**, which
we already have running through the UDM router DNAT chain.

The remaining unknown is: **which host does the cam contact for
firmware, and can we capture the URL in flight without the cam
actually installing what it downloads?** That&rsquo;s this spec&rsquo;s target.

The owner has explicitly authorised:

- Binding the real cam to a throwaway account (accepting potential
  conflicts with the existing primary-account binding).
- Possibly bricking the cam (it is cheap; replacement is cheap).
- Extensive modifications to the cam&rsquo;s network-visible state.

The owner has explicitly **not** authorised:

- Physical teardown of the cam (plastic is fragile; already attempted
  once, cam cannot be opened non-destructively). Firmware extraction
  via hardware methods is **a last resort** after all software paths
  are exhausted.
- Anything that would compromise other devices on the home LAN, the
  owner&rsquo;s privacy, or third-party cloud infrastructure.

---

## 1. Goals

Prioritised, highest-value first:

1. **Capture the cam&rsquo;s firmware download URL(s)** — the absolute
   minimum deliverable. One HTTPS or HTTP URL, fully qualified, as
   sent by the cam during an update cycle.
2. **Discover every hostname the cam reaches during a full update
   cycle** — not just the firmware host. Useful for the broader
   "where does this cam phone home" map in
   [`docs/03-cloud-topology.md`](../../03-cloud-topology.md).
3. **Prevent the cam from actually installing new firmware unless
   explicitly promoted** — default posture: capture the intent, stop
   before the bytes finish transferring, cam stays on current firmware.
4. **Collect raw byte dumps of everything** (TLS ciphertext, plaintext
   after termination, UDP) so future sessions can revisit with new
   tools or keys without re-running the cam flow.
5. **Optionally, if the URL looks promising and passes review**,
   separately `curl` the URL from the Mac to retrieve the firmware
   binary for offline analysis. This step is explicit and gated —
   not automatic.

**Non-goals** for this spec:

- Flashing custom firmware onto the cam.
- Full-protocol reverse engineering of the cam&rsquo;s upgrade wire
  format (that&rsquo;s a future session once we have a firmware binary).
- Automating the emulator UI driving (already demonstrated in
  Session 6 Wave 3; re-apply the same pattern).
- Making the veto gate generic enough to handle non-cam clients on
  the LAN. It only needs to work for the one source IP.

---

## 2. The veto model, precisely

The veto is a **declarative policy** evaluated per TLS connection in
`mitm_cbs_proxy.py`, not a runtime prompt. A Claude Code session
reads the captured data, updates the policy file, and sends SIGHUP
to the proxy. The proxy applies the new policy on the next
connection. The workflow is async, not interactive.

### Policy modes (exactly three)

| Mode | TLS terminated? | Request captured? | Response forwarded to cam? | Default for unknown SNI? |
|---|---|---|---|---|
| `forward` | ✅ yes | ✅ yes | ✅ yes — cam sees real response | ❌ no |
| `capture` | ✅ yes | ✅ yes | ❌ no — cam sees canned HTTP 504 Gateway Timeout with empty body | ✅ **yes (default)** |
| `drop` | ❌ no | ❌ no (just the SNI) | ❌ no — TCP RST immediately after SNI read | ❌ no |

**Rationale**:

- `forward` is for hosts we trust the cam to talk to (the existing
  hapseemate / cloudbirds / dayunlinks / philipsiot families — the
  ones already in the Session 6 SNI suffix allowlist).
- `capture` is the default for everything else, including the
  firmware-fetching hostname we&rsquo;re trying to discover. The cam makes
  the request, the proxy reads the full request line (method, path,
  headers, any body), then sends back a `504 Gateway Timeout` with
  empty body so the cam&rsquo;s own update code path sees a "server
  down, try later" and abandons the install. We get the URL, the cam
  stays on current firmware.
- `drop` is a sharper knife for hosts we actively want to suppress
  (e.g., analytics we&rsquo;re tired of seeing in the log). Rarely used.

### Why `504` specifically, and not `404` or a RST

- `504 Gateway Timeout` is semantically honest: "the upstream did
  not respond in time." Both OkHttp on the app side and most cam
  firmware HTTP clients treat this as a retryable transient error and
  will not escalate to a failure state or reset state.
- `404` would tell the cam "this URL does not exist on this server,"
  which some update daemons interpret as "permanently unavailable,
  clear this update entry." We don&rsquo;t want to poison the cam&rsquo;s
  internal state.
- TCP RST makes the cam think the proxy crashed mid-request and
  triggers aggressive retry loops — noisy.

### Config file format

Path: `captures/veto.yaml` (relative to repo root — NOT in the
`captures/ota/` session subdirectory, because it&rsquo;s per-proxy-run,
not per-capture-session).

```yaml
# mitm_cbs_proxy.py veto policy
# Reloaded on SIGHUP. Edit and SIGHUP the proxy to apply.
#
# Modes: forward | capture | drop

default_mode: capture    # anything not matched below falls here

policies:
  # Known-safe host families — forward so cam/app works normally
  - match_suffix: .hapseemate.cn
    mode: forward
    note: "Primary CBS control-plane host family."
  - match_suffix: .cloudbirds.cn
    mode: forward
    note: "Dayunlinks public brand; serves NTP wrappers and supernodes."
  - match_suffix: .dayunlinks.cn
    mode: forward
    note: "public.dayunlinks.cn is the OTA version check host family."
  - match_suffix: .philipsiot.com
    mode: forward
    note: "CNAME target for public.dayunlinks.cn via birds-public."

  # Observation-only for known-noisy analytics (drop silently)
  - match_suffix: app-measurement.com
    mode: drop
    note: "Firebase Analytics. Not relevant to cam RE."
```

Matching rules:

1. Iterate policies in order.
2. For each policy, test whether the connection&rsquo;s SNI
   **dot-aligned-suffix-matches** `match_suffix`. That means
   `foo.hapseemate.cn` matches `.hapseemate.cn`, `hapseemate.cn`
   also matches `.hapseemate.cn`, but `evilhapseemate.cn` does NOT
   match `.hapseemate.cn`. (Session 6&rsquo;s SNI allowlist already
   implements this rule — reuse the same helper.)
3. First match wins.
4. No match → apply `default_mode`.

### Per-SNI logging

Every connection, regardless of mode, produces a line in
`/tmp/cam-listen/mitm_cbs.log` tagged with the applied mode:

```
[11:42:03.128] ACCEPT   192.168.5.37:51299  new connection
[11:42:03.129] ACCEPT   192.168.5.37:51299  SNI: 'ota.mystery.com'
[11:42:03.130] VETO     192.168.5.37:51299  mode=capture (default) host=ota.mystery.com
[11:42:03.133] REQ      192.168.5.37:51299  GET /firmware/v6_5_0/v360pro.bin HTTP/1.1
[11:42:03.133] CANNED   192.168.5.37:51299  504 Gateway Timeout, empty body → cam
[11:42:03.134] CAPTURE  192.168.5.37:51299  wrote 0047-request.json + 0047-response.json
[11:42:03.134] RAW      192.168.5.37:51299  wrote 0047-client.bin + 0047-upstream.bin (0 bytes)
```

The `VETO` line is the critical new log output — it tells the
reviewer (or a future Claude Code session) exactly which policy
fired and why.

---

## 3. Raw byte dump

Every TCP connection produces, in addition to the structured
request/response JSON from Session 6:

- `captures/ota/<session>/<NNNN>-client.bin` — every byte the cam
  sent, as it arrived at the proxy. Ciphertext if the cam wrapped it
  in TLS (which it will), plaintext if not.
- `captures/ota/<session>/<NNNN>-upstream.bin` — every byte the
  upstream sent back, if the mode was `forward`. Empty file in
  `capture` mode.
- `captures/ota/<session>/<NNNN>-plaintext-client.bin` — the cam&rsquo;s
  bytes after TLS termination, as HTTP wire format. Useful even when
  the JSON parsed version is truncated.
- `captures/ota/<session>/<NNNN>-plaintext-upstream.bin` — upstream
  bytes after TLS termination, if `forward`.
- `captures/ota/<session>/<NNNN>-tls-keylog.txt` — the TLS master
  secrets in NSS keylog format, so Wireshark can decrypt the `.bin`
  files if we want to load them there later. Python&rsquo;s `ssl` module
  exposes `SSLContext.keylog_filename`. Use this.

The UDP supernode proxy already does per-packet logging in its
existing text log; no raw dump change is required there. The raw
dumps apply only to `mitm_cbs_proxy.py`.

**Size discipline**: for any connection, if the cumulative body size
exceeds **1 MB**, the proxy stops writing to the raw dump file for
that connection and writes a marker `[TRUNCATED AT 1048576 BYTES]`.
The size cap prevents runaway disk use during a firmware download
where the veto accidentally let something through. This is a safety
valve — the normal path (capture mode) doesn&rsquo;t stream anything
large.

---

## 4. Default-deny egress with universal DNAT (UDM side)

This is the biggest architectural change to the router-side MITM.
Previously, only traffic to the sink IP (`203.0.113.37`) and the
hardcoded supernode IP (`123.56.74.245`) was DNAT&rsquo;d to the Mac.
**Now, everything the cam sends outbound (except NTP) gets
DNAT&rsquo;d**, regardless of destination IP.

### New Phase (call it "Phase 3a" for the router-setup doc)

```sh
# camre-veto: catch-all DNAT for cam outbound traffic.
# This replaces the need to enumerate every sink IP — instead, we
# rewrite any packet sourced from the cam to land on the Mac, except
# NTP which is explicitly allowed through to real servers.

CAM=192.168.5.37
MAC=192.168.5.233
MARKER=camre-veto

# Allow NTP through unmolested (cam needs real time for TLS cert validation)
iptables -t nat -I PREROUTING 2 -s $CAM -p udp --dport 123 \
  -j ACCEPT -m comment --comment "$MARKER-ntp-allow"

# TCP port 443 (HTTPS) → Mac:8443 (TLS MITM)
iptables -t nat -I PREROUTING 3 -s $CAM -p tcp --dport 443 \
  -j DNAT --to-destination $MAC:8443 -m comment --comment "$MARKER-tls"

# TCP port 80 (HTTP plaintext) → Mac:8080 (new HTTP MITM; see §5)
iptables -t nat -I PREROUTING 3 -s $CAM -p tcp --dport 80 \
  -j DNAT --to-destination $MAC:8080 -m comment --comment "$MARKER-http"

# All other TCP → Mac:8443 (catch-all, will be rejected there but logged)
iptables -t nat -A PREROUTING -s $CAM -p tcp \
  -j DNAT --to-destination $MAC:8443 -m comment --comment "$MARKER-tcp-catchall"

# UDP (not 123) → Mac:32100 (supernode-proxy-style catch-all)
iptables -t nat -A PREROUTING -s $CAM -p udp \
  -j DNAT --to-destination $MAC:32100 -m comment --comment "$MARKER-udp-catchall"

# FORWARD chain backup — anything that somehow escapes the PREROUTING
# catch-alls above (e.g., raw IP or unusual protocol) gets LOGged and
# DROPped at the br4→eth4 boundary. This should never fire; if it
# does we learned something new about the cam.
iptables -I FORWARD 1 -i br4 -o eth4 -s $CAM -p udp --dport 123 \
  -j ACCEPT -m comment --comment "$MARKER-fwd-ntp"
iptables -I FORWARD 2 -i br4 -o eth4 -s $CAM \
  -j LOG --log-prefix "CAMRE-UNEXPECTED: " --log-level 6 \
  -m comment --comment "$MARKER-fwd-log"
iptables -I FORWARD 3 -i br4 -o eth4 -s $CAM \
  -j DROP -m comment --comment "$MARKER-fwd-drop"
```

### What this does

- **Cam → Mac** for everything port 443 (TLS MITM), everything port
  80 (HTTP MITM), any other TCP (lands on 8443 and gets rejected
  loudly), and any UDP except NTP (lands on 32100 and is parsed as
  Kalay or logged as unknown).
- **Cam → real NTP servers** for port 123 unchanged — the cam needs
  accurate time for TLS cert validity checks, and the NTP wrapper
  hosts are benign CNAMEs to public pool sources.
- **Any escape** (cam tries a raw IP protocol, ICMP, etc.) hits the
  FORWARD-chain LOG+DROP combo. The LOG line tags with
  `CAMRE-UNEXPECTED:` so we can grep dmesg/journald for it. If this
  ever fires, it&rsquo;s a finding worth documenting.

### Compatibility with existing Phase 1

**This replaces the narrower Phase 1 DNAT rules**, not adds to them.
The narrower rules (DNAT 203.0.113.37 and 123.56.74.245 specifically)
are strict subsets of the catch-all, so removing them during Phase 3a
apply is correct. Phase 4 teardown removes everything via the
`camre` comment marker match and is unchanged.

---

## 5. New HTTP proxy on port 8080

The cam may fetch firmware over plain HTTP, not HTTPS. Cheap OEM
cameras sometimes do this because HTTPS handshakes are expensive on
low-powered SoCs and because the cam&rsquo;s firmware predates widespread
TLS adoption. We need to be ready.

New file: `mitm_http_proxy.py`. Scope:

- Listen on `0.0.0.0:8080`.
- Accept plain HTTP (no TLS).
- Parse the request line to extract `Host: ` header.
- Apply the same `veto.yaml` policy as `mitm_cbs_proxy.py` (identical
  `forward` / `capture` / `drop` semantics).
- In `capture` mode, return `HTTP/1.1 504 Gateway Timeout` with an
  empty body.
- In `forward` mode, resolve `Host:` via the same stub resolver as
  the TLS proxy (1.1.1.1:53 direct, bypassing system resolver), open
  a plain TCP connection to the real upstream, relay request and
  response.
- Dump raw bytes to the same `captures/ota/<session>/` directory,
  with the same `<NNNN>-*.bin` naming convention. Shared counter
  across both proxies so the timeline is coherent.
- Shared `veto.yaml` — edited once, reloaded by both proxies on
  SIGHUP.

Alternative: extend `mitm_cbs_proxy.py` to also listen on 8080 and
detect HTTP vs TLS by peeking at the first byte (TLS records start
with `0x16`, HTTP requests start with an ASCII letter). One process,
two ports, one codebase. This is cleaner and recommended.

---

## 6. The exact phased plan

### Phase 0 — preflight (5 min, read-only)

Standard router-state preflight from [`docs/09-router-setup.md`](../../09-router-setup.md)
Phase 0 (`dig @192.168.5.1 user.hapseemate.cn → 203.0.113.37`, plus
`lsof` check that the existing proxies are running). If the pipeline
is already broken, fix it before proceeding.

### Phase 1 — extend `mitm_cbs_proxy.py` with veto + raw logging (60 min)

1. Add YAML config loading for `captures/veto.yaml`. Use `yaml`
   module if available, else a minimal hand-parser (we don&rsquo;t use
   complex YAML features). No new dependencies preferred.
2. Add `apply_veto(sni)` function that returns one of
   `("forward", note)`, `("capture", note)`, `("drop", note)`.
3. Modify the `handle()` function&rsquo;s SNI check to call `apply_veto`
   instead of the current plain allowlist check. Branch three ways.
4. Add `capture` mode implementation: after TLS is terminated and
   the first request bytes are read from the cam, parse the HTTP
   request line + headers, then write a canned
   `HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n`
   response back to the cam. Close the connection.
5. Add `drop` mode: after reading SNI, close the underlying socket
   with a socket-level RST (set `SO_LINGER` to `{1, 0}` and close).
6. Add raw byte dumping: on connection acceptance, open two files
   (`<NNNN>-client.bin` and `<NNNN>-upstream.bin`) in the current
   session capture dir; write every byte read from the cam to the
   first, every byte read from the upstream (if `forward`) to the
   second. Flush on connection close.
7. Add TLS keylog: set `SSLContext.keylog_filename` to
   `<session>/<NNNN>-tls-keylog.txt`.
8. Add the 1 MB raw-dump safety cap (write a
   `[TRUNCATED AT 1048576 BYTES]` marker and stop appending).
9. Add SIGHUP handler that re-reads `veto.yaml`.
10. Add the unified listener on 8080 with first-byte sniffing (TLS
    vs HTTP); this subsumes the new HTTP proxy described in §5.
11. Test offline: run the proxy, connect with `openssl s_client` and
    a raw `curl` to 127.0.0.1:8443, verify that:
    - SNI `user.hapseemate.cn` → forwarded to real upstream (1 upstream byte visible in upstream.bin)
    - SNI `nonsense.example.com` → 504 response seen by client
    - Plain HTTP `curl -H 'Host: foo.bar' http://127.0.0.1:8080/` → 504 response
    - SIGHUP triggers policy reload (log line)
    - Raw dumps exist with expected content
12. `python3 -m py_compile mitm_cbs_proxy.py` green, AST parses,
    sibling `mitm_supernode_proxy.py` untouched.

**Deliverable**: modified `mitm_cbs_proxy.py` + new `captures/veto.yaml`
with the initial policy from §2.

### Phase 2 — apply Phase 3a router rules (15 min)

1. Read the current PREROUTING/FORWARD state:
   `ssh root@192.168.5.1 'iptables-save | grep -F camre'`. Note
   what&rsquo;s there.
2. **Phase 4 teardown** (remove the Session 6 narrow rules) to
   start from a clean slate. Run the teardown loop from
   [`docs/09-router-setup.md`](../../09-router-setup.md) Phase 4
   verbatim. This is surgical — only touches camre-tagged rules.
3. Verify rules are gone: `iptables-save | grep -F camre` should
   return nothing.
4. Apply Phase 3a (the block in §4 above), dropped in as a
   pasteable SSH heredoc.
5. Verify with `dig @192.168.5.1 user.hapseemate.cn` → still
   `203.0.113.37` (dnsmasq unchanged).
6. Verify rules: `iptables -t nat -L PREROUTING -v -n --line-numbers`
   shows the new camre-veto rules.
7. Ping the cam: `ping -c 2 192.168.5.37` still works (ICMP is not
   affected by PREROUTING NAT on the cam-to-Mac path; the cam
   remains reachable from the LAN side).
8. Watch the cam&rsquo;s immediate reaction via the supernode proxy log —
   it&rsquo;s ping-ponging DEV_LGN every 30 seconds; those packets should
   continue to land on 192.168.5.233:32100 as before. No change
   expected.

**Deliverable**: UDM in Phase 3a state, old Phase 1 torn down, dig
and ping both green, cam&rsquo;s normal heartbeat still visible.

### Phase 3 — boot emulator and log in (10 min)

Re-run the Session 6 Wave 3 setup for the emulator path:

```sh
export ANDROID_SDK_ROOT=/opt/homebrew/share/android-commandlinetools
export PATH=$ANDROID_SDK_ROOT/emulator:$ANDROID_SDK_ROOT/platform-tools:$PATH
emulator -avd camtest -writable-system -no-snapshot &
adb wait-for-device
until [ "$(adb shell getprop sys.boot_completed | tr -d '\r')" = "1" ]; do sleep 2; done
adb reverse tcp:443 tcp:8443
# /system/etc/hosts was persisted from Session 6 in the AVD state; verify
adb shell cat /system/etc/hosts | grep dayunlinks
```

Launch the app. Log in with the Session 6 throwaway account
(`deep.pack3852@fastmail.com`, password is stored locally). If the
app rejects the session token, re-register via the UI.

**Deliverable**: the emulator is booted, the app is on the "My
camera / No device" home screen, logged in.

### Phase 4 — bind the real cam (20 min)

The highest-risk phase. Accept that the real cam&rsquo;s existing binding
to the owner&rsquo;s primary account may be invalidated.

1. Physically prepare the cam for pairing: long-press reset button
   until the LED indicates AP mode / pairing mode. (Exact procedure:
   check the cam manual or observe the LED state; varies by model.)
2. In the app, tap **+ → Scan to add** or **Add hotspot**. Whichever
   flow actually works in the emulator is fine.
3. If the flow needs the cam&rsquo;s own hotspot, we&rsquo;ll hit a problem:
   the emulator can&rsquo;t join a Wi-Fi network, it uses the host&rsquo;s
   NAT. Fallback: use the **QR code add** flow which generates a QR
   in the app for the cam to scan — this is the wifiqr.py-style
   flow. The cam physically sees the QR on the emulator screen if
   you hold the cam up to the emulator window.
4. Watch the cbs proxy log in a separate terminal
   (`tail -F /tmp/cam-listen/mitm_cbs.log`) as the bind proceeds.
   Expected sequence (approximately):
   - App calls `/preadd/checkDidByToken` → `forward` (known host)
   - App calls `/preadd/didBindUserId` → `forward`
   - App may call `/device/suit/queryDevs.html` → `forward`
   - App sends a Kalay `0x8116` IOCTRL to the cam (not visible on
     cbs proxy, visible as a DRW frame on supernode proxy if we can
     parse it — probably we can&rsquo;t yet)
5. Watch the supernode proxy log for new UDP traffic from the
   cam&rsquo;s side initiating new sessions.
6. Watch `dmesg | grep CAMRE-UNEXPECTED` for anything dropped at
   the FORWARD chain (should be nothing).

**Deliverable**: cam appears as "online" in the app&rsquo;s device list,
or an error from the bind flow that tells us what went wrong.

### Phase 5 — trigger the update check (10 min)

1. In the app, tap the newly-bound cam → Settings → "About" /
   "Firmware" / "Check for updates" (exact label depends on the
   localisation).
2. Watch the cbs proxy log. Expected:
   - App calls `/public/checkDevVer` → `forward` (known host) → we
     see the server&rsquo;s response telling the app whether an update
     is available, and if so, probably a version string or a
     download URL.
3. **If the server says "no update available"**: pivot to the
   downgrade-spoof contingency (§7) or accept the partial result
   (URL is still in the response, it&rsquo;s just stale).
4. If the server says "update available" and the cam receives the
   `0x8116` IOCTRL, **the cam itself will now start reaching out to
   its own update server**. This traffic will originate from
   `192.168.5.37`, not from the emulator, and will land on our Mac
   via the Phase 3a DNAT catch-all.

**Deliverable**: something new appears in the cbs proxy log with
source IP `192.168.5.37` and an unfamiliar SNI. That&rsquo;s the cam&rsquo;s
own update path.

### Phase 6 — capture the firmware URL (the payoff) (15 min)

1. The cbs proxy, per the default `capture` mode, will have parsed
   the cam&rsquo;s HTTP request line and headers, written them to
   `<NNNN>-request.json`, and sent the cam a `504 Gateway Timeout`
   with empty body.
2. Read the captured request JSON:
   ```sh
   ls captures/ota/<latest-session>/ | tail -20
   python3 -c "
   import json, sys
   r = json.load(open(sys.argv[1]))
   print('SNI:', r['sni'])
   print('Method:', r['method'])
   print('Path:', r['path'])
   print('Headers:')
   for k, v in r['headers'].items():
       print(f'  {k}: {v}')
   " captures/ota/<session>/<NNNN>-request.json
   ```
3. Construct the full URL:
   `https://<sni>/<path>` (or `http://` if the capture came from the
   plain HTTP proxy). That&rsquo;s the firmware URL.
4. Document it in a new file:
   ```
   captures/ota/<session>/FIRMWARE_URL.txt
   ```
   with the URL, timestamp, sending IP (should be cam IP
   `192.168.5.37`), and any captured headers that look like they
   might be required for the real request (User-Agent, Range,
   authorisation, etc.).
5. The cam will retry the download a few times, each retry
   producing another capture. Let the retries happen — extra data
   is free.
6. After ~3 retries, the cam will either give up or continue
   retrying indefinitely. Either way we have what we need.

**Deliverable**: `FIRMWARE_URL.txt` in the capture dir with the
firmware host, path, and request headers. This is the spec&rsquo;s
primary success criterion.

### Phase 7 — fetch the firmware separately (optional, 15 min, gated)

**Only proceed if Phase 6 produced a URL that looks plausible AND
the owner has explicitly approved this step.** Fetching the
firmware from the cam&rsquo;s update server is an action that shows up
in that server&rsquo;s logs as "a download from the owner&rsquo;s WAN IP,"
which is a minor OPSEC consideration.

1. From the Mac, with the MITM proxies still running:
   ```sh
   curl -v -o /tmp/captured-firmware.bin -H "User-Agent: <same as cam>" <URL>
   ```
   Replicate any headers the cam sent that look load-bearing.
2. Check what came back:
   ```sh
   file /tmp/captured-firmware.bin
   ls -la /tmp/captured-firmware.bin
   head -c 64 /tmp/captured-firmware.bin | xxd
   binwalk /tmp/captured-firmware.bin
   ```
3. Common outcomes:
   - **200 OK + binary blob with ELF / squashfs / uboot magic** →
     jackpot. Move to `extracted/firmware/<version>.bin` (which is
     already gitignored) and document in
     [`docs/12-session-log.md`](../../12-session-log.md).
   - **200 OK + encrypted blob (high entropy from byte 0)** →
     partial win. We have the shape and can&rsquo;t read it yet, but
     the URL + size are still valuable intel.
   - **403 / 404 / auth required** → the endpoint requires
     per-device credentials the cam has that we didn&rsquo;t replay.
     Capture the response for future reference and note the auth
     mechanism.
4. **Do NOT** under any circumstances write these bytes to the cam.
   The cam is still running its old firmware because Phase 6 fed it
   a `504`; leave it that way.

**Deliverable**: either `extracted/firmware/<version>.bin` (locally
only, gitignored), or a documented failure mode explaining why the
fetch didn&rsquo;t work.

### Phase 8 — teardown and cleanup (10 min)

1. Kill the emulator: `adb emu kill`
2. Stop the proxies:
   `ps aux | grep mitm_cbs_proxy | awk '{print $2}' | xargs kill`
   (and the same for `mitm_supernode_proxy`).
3. UDM Phase 4 teardown: remove all `camre` comment-tagged iptables
   rules and delete `cam-override.conf`.
4. Restart main dnsmasq one more time to return the UDM to normal
   DNS behaviour: `kill $(cat /run/dnsmasq-main.pid)`.
5. **Attempt to unbind the cam from the throwaway account** via the
   app&rsquo;s device settings. Best-effort — if the unbind fails or
   the rebinding conflict persists, document the state and move on.
6. Factory-reset the cam if necessary to re-bind to the owner&rsquo;s
   primary account. Document the reset procedure (usually long-press
   the reset button for 10+ seconds, watch for LED pattern change).
7. Commit the new docs and any modifications to `mitm_cbs_proxy.py`
   to a new branch or directly to main per owner preference.

**Deliverable**: all state rolled back. Cam rebound to primary
account (or at least the unbind attempted and the result
documented). Session state committed to git.

---

## 7. Contingencies

### Server returns "no update available"

The cam is already on the latest firmware version known to the
backend, so the update check doesn&rsquo;t trigger a download. Options:

1. **Inspect the checkDevVer response body** — even a "no update"
   response usually includes the LATEST known version string and
   CHANGELOG, which tells us what version *would* be offered if we
   downgraded. That&rsquo;s still useful intel.
2. **Spoof a downgraded version** — intercept the cam-side
   `checkDevVer` request and rewrite its "current version" field to
   something old, so the server offers an update. Requires
   understanding the request body format first. Add this as a new
   intermediate phase if we get to it.
3. **Wait for a real release** — opportunistic, not actionable
   this session.

### Bind flow fails entirely

The app refuses to bind the cam (wrong region, cam rejects pairing,
etc.). Options:

1. Try a different bind method (Scan to add vs Add hotspot vs QR
   code add). Session 6 only tried Network cable binding.
2. Attempt bind via the Wi-Fi AP mode — requires the cam to actually
   enter AP mode and the emulator to join it, which is the
   problematic path.
3. Concede and document the failure.

### The cam goes quiet entirely

If binding succeeds but the cam doesn&rsquo;t start reaching out to new
hosts, one of:

1. The cam doesn&rsquo;t periodically check for firmware on its own — it
   only checks when explicitly told via `0x8116`. In that case we
   need to ensure the `0x8116` command is actually reaching the cam
   (check the supernode proxy log for the app→cam DRW frame).
2. The cam&rsquo;s internal state says "already up to date" without
   contacting a server. In that case we&rsquo;re back to the downgrade
   spoof contingency.

### Proxy crashes mid-capture

The 1 MB raw-dump cap is a safety valve, not crash protection. If
the proxy crashes:

1. Check the last raw dump file for partial data — sometimes enough
   to know what was flowing.
2. Check the Python exception log (proxy logs to stdout; redirect
   to a file for persistence).
3. Restart the proxy and retry Phases 4-6. Raw dumps from the new
   run go to a new session directory.

### Cam bricks during capture

Per the owner&rsquo;s authorisation, the cam being bricked is acceptable
but still worth documenting. If the cam stops responding:

1. Physical power cycle (unplug, replug).
2. If still dead: factory reset via reset button.
3. If still dead: the cam is a paperweight. Document what we had
   just before (last few captures, last log lines) as a post-mortem
   for future work. The captured firmware URL and any fetched
   firmware binary are still valuable.

---

## 8. Safety / constraints

- **Owner authorisation required** at each of these gates:
  - Start of Phase 4 (bind real cam — changes cam state)
  - Start of Phase 7 (fetch firmware from real server — uses owner&rsquo;s
    WAN IP, visible in server logs)
  - End of Phase 8 (factory reset cam — destroys current state)
- **No physical teardown** of the cam. The owner has explicitly
  ruled this out until every software path is exhausted.
- **No writes to the cam&rsquo;s filesystem or flash** at any point.
  This means: no flashing custom firmware, no pushing configuration
  via Kalay writes, no file uploads through the app. Read-only-ish
  posture.
- **No interference with the home LAN beyond the cam** — the Phase
  3a rules are scoped to `-s 192.168.5.37` specifically, not the
  whole `br4` interface. Other devices on the cam VLAN (if any) are
  unaffected.
- **Capture files remain local**. `captures/` is already
  gitignored. Do NOT commit any capture files even if they look
  harmless — they may contain session tokens, real IP addresses, or
  brand strings that belong in the knowledge base as prose, not as
  raw data.
- **Fetched firmware binary (if obtained) goes in
  `extracted/firmware/<version>.bin`** which is also gitignored
  (add to `.gitignore` if not already present).
- **If Phase 7 returns something that looks like it might contain
  credentials or encryption keys** (e.g., `binwalk` finds an
  `/etc/shadow` or an RSA private key in the image), treat that as
  sensitive and do not commit or share outside the project.

---

## 9. Success criteria

Primary:

- [ ] At least **one firmware download URL** captured in
      `captures/ota/<session>/FIRMWARE_URL.txt`, with host, path,
      headers, and source IP (should be `192.168.5.37`).
- [ ] The cam did NOT complete a firmware installation during this
      session (verifiable by: cam still responds, cam&rsquo;s own
      version string in subsequent checkVer responses is unchanged).
- [ ] `mitm_cbs_proxy.py` extended with the veto modes, raw dumps,
      and `veto.yaml` config, working end-to-end.
- [ ] UDM in Phase 3a state (default-deny egress via catch-all
      DNAT) during the capture.
- [ ] All changes committed to git with informative messages.

Secondary (nice-to-have):

- [ ] The firmware binary itself downloaded separately via Phase 7
      and stored locally at `extracted/firmware/<version>.bin`.
- [ ] At least one NEW hostname added to
      [`docs/03-cloud-topology.md`](../../03-cloud-topology.md).
- [ ] A documented answer to "what&rsquo;s in the checkDevVer response
      body" — even a screenshot of the JSON shape is valuable.

---

## 10. Stop conditions

- 🛑 **90 minutes of elapsed execution time** — firmware capture
  rabbit-holes can eat a day; 90 minutes is the fair cutoff.
- 🛑 **Proxy changes break the existing cam heartbeat** — if applying
  Phase 3a causes the cam to fall off the Kalay supernode (no more
  DEV_LGN visible on supernode log for >2 minutes), stop and
  investigate. The veto gate should NOT affect the Kalay UDP path
  because it uses the supernode proxy, not the cbs proxy — if it
  does, we&rsquo;ve made a mistake in the rules.
- 🛑 **Unbind fails and cam is stuck on throwaway account** — not a
  blocker for the investigation, but worth a stop to document and
  think about whether to factory-reset.
- 🛑 **Phase 7 curl returns a password-protected response** — do
  not attempt to crack or brute-force. Document and stop.
- 🛑 **Any finding that looks like a vulnerability in a third-party
  service** (not the cam itself) — do not probe, do not exploit,
  just document.
- 🛑 **Cam enters a boot loop or refuses to respond after Phase 6** —
  power cycle once, then if still dead, stop and document. Do not
  try to recover via JTAG / serial / etc. (we don&rsquo;t have hardware
  access).

---

## 11. Relationship to existing docs

This spec expands on:

- [`docs/14-next-steps.md`](../../14-next-steps.md) Step A
  (firmware capture via bind-real-cam) — this spec IS Step A in
  executable form. Once executed, `14-next-steps.md` Step A can be
  marked as in-progress or done, depending on outcome.

- [`docs/09-router-setup.md`](../../09-router-setup.md) — this
  spec&rsquo;s Phase 3a should eventually land in `09-router-setup.md`
  as a new Phase (probably Phase 3a or Phase 3b, alongside the
  existing optional Phase 3 which is just a simple WAN block). If
  the veto approach works, the router setup doc should be updated
  to recommend Phase 3a as the default for capture sessions.

This spec is a **sibling of** [`2026-04-15-ota-discovery-design.md`](2026-04-15-ota-discovery-design.md)
(Session 6&rsquo;s primary spec) — not a replacement. That one established
the app-side discovery infrastructure; this one builds on it to
target the cam-side capture question.

This spec is **independent of** [`2026-04-15-aiseebling-money-trail-design.md`](2026-04-15-aiseebling-money-trail-design.md)
— the aiseebling OSINT task can run in parallel or after this
spec; neither depends on the other.

---

## 12. Acceptance and next step

If the owner approves this spec:

1. Commit the spec as part of a "docs: Wave 4 spec" commit.
2. In the next session, follow Phases 0-8 in order.
3. Produce a new session log entry in
   [`docs/12-session-log.md`](../../12-session-log.md) with the
   outcome (URL, or failure mode, or partial findings).
4. If a firmware URL was captured, invoke a **new** spec for
   offline firmware analysis (binwalk, filesystem extraction,
   native-binary RE of the cam&rsquo;s update handler). That spec is
   out of scope for this one.

If the owner wants changes:

1. Edit this file in place and re-commit.
2. Do not start execution until the spec has been re-reviewed.

_Authored: 2026-04-15 — Session 6_
