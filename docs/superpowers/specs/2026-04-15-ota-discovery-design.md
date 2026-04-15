# OTA Discovery Pivot — Design Spec

**Date:** 2026-04-15
**Session:** 6
**Status:** Draft, awaiting user review
**Supersedes in part:** `docs/13-next-steps.md` Step 2 (fake client) — temporarily deprioritized in favor of OTA discovery path.

## Background and motivation

Session 5 left us blocked on a specific Kalay protocol unknown: the
cam's device-role dispatcher only accepts message types
`0x13, 0x30, 0x31, 0x3f, 0x52, 0x55, 0xdb, 0xdc`, and we cannot inject
a `P2P_REQ (0x20)` or `PUNCH_TO (0x40)` to trick it into opening a data
session. Fallbacks A–C in `docs/13-next-steps.md` are all viable but
each involves further Kalay reverse engineering.

Instead of pushing harder on Kalay, we pivot to an **already-parked open
question** from `docs/12-open-questions.md:143`: the OTA (firmware
update) endpoint. Two compelling reasons to prefer this path this
session:

1. **Zero protocol unknowns.** OTA rides plain HTTPS through our
   existing `mitm_cbs_proxy.py`. Discovery cost is bounded to the
   app-side trigger work; the interception infrastructure already
   exists.
2. **Higher-leverage outcome.** If the captured OTA flow reveals
   unsigned firmware, we have a code-execution primitive that
   sidesteps the entire Kalay data-channel reverse engineering
   project. If it reveals signed firmware, we at least learn the
   signing format — which is itself actionable intel for future
   sessions and answers `docs/12-open-questions.md:154`.

A **third discovery surfaced during preflight**: `public.dayunlinks.cn`
CNAMEs to `birds-public.philipsiot.com`, meaning the OTA backend is
hosted on Philips Signify IoT infrastructure, not a Chinese cloud.
This has implications for the expected security posture of the update
pipeline and should be documented regardless of Block outcome.

## Preflight finding that reshaped this session

During initial router-state inspection, we discovered the MITM
pipeline was **silently broken**:

- `iptables` counters showed thousands of packets hitting the
  `cam→9.9.9.9→Mac` DNAT rules, suggesting the pipeline was healthy.
- `dig @192.168.5.1 user.hapseemate.cn` returned `190.92.254.71`
  (the real Chinese cloud), proving the DNS overrides were gone.
- Resolution: the Unifi controller regenerates
  `/run/dnsmasq.dns.conf.d/*.conf` on every settings apply, wiping
  manual overrides. The documented path in `docs/09-mitm-setup.md`
  (`/run/dnsmasq.conf.d/`) was also **wrong** — the real path is
  `/run/dnsmasq.dns.conf.d/`, and any attempt to restore overrides
  via that wrong path silently failed.
- The high iptables counters were **stale** — frozen from Session 5
  when the pipeline last worked.

This is a textbook "stale evidence masquerading as success" failure
mode. It reshaped the design: Block 0 (router state restoration)
now precedes all OTA work, and a preflight rule gets added to
CLAUDE.md so future sessions catch this class of failure before
it wastes time.

## Scope

In scope:

- Replacing `docs/09-mitm-setup.md` with a new, script-shaped,
  ephemeral-by-design `docs/09-router-setup.md`.
- Cascading renumber of `docs/10`–`docs/16` (and `docs/README.md` index,
  cross-references in body text).
- Adding a router-state preflight rule to `CLAUDE.md`.
- Extending `mitm_cbs_proxy.py` for SNI-dispatched multi-cloud upstream
  with stub resolver via `1.1.1.1`.
- Extending `fake_cbs_server.py` cert SAN list.
- Adding a structured capture directory and per-exchange JSON dump.
- Setting up an Android emulator (commandlinetools path, `google_apis`
  system image) to run the vendor APK.
- Grepping decompiled sources for cert pinning before emulator config.
- Triggering an OTA check from the app, capturing the request/response
  pair, and — if offered — capturing the firmware binary.
- Updating `docs/03-cloud-topology.md` with the Philips IoT finding.
- Updating `docs/12-open-questions.md` as items are answered.

Out of scope:

- Flashing any firmware to the cam. Ever, this session.
- Crafting a malicious firmware image.
- MITM-rewriting the firmware binary in flight.
- Static reverse engineering of the OTA verifier on the cam side
  (that's a future session if firmware turns out to be signed).
- Enabling br4 WAN egress block (Phase 3) — that's for the airgap
  transition session, not this one.
- Resuming the fake-client / Kalay injection work from
  `docs/13-next-steps.md` Step 2.

## Design blocks

The work decomposes into five independent blocks. Block 0 is a
hard prerequisite for Blocks 1–4; Blocks 1 and 2 can happen in
parallel after Block 0; Block 3 depends on Block 2; Block 4
depends on Block 3.

### Block 0 — Router-setup doc and restoration

**Target file:** `docs/09-router-setup.md` (replaces
`docs/09-mitm-setup.md`). Script-shaped, ephemeral, organized as
four phases plus a teardown. Assumes `ssh root@192.168.5.1`.

**Phase 0 — Preflight (read-only):**

```sh
# On the Mac:
for h in p2p5.cloudbirds.cn user.hapseemate.cn public.dayunlinks.cn; do
  printf "%-30s → %s\n" "$h" "$(dig @192.168.5.1 +short "$h" | head -1)"
done
ssh root@192.168.5.1 'iptables -t nat -L PREROUTING -v -n --line-numbers'
ssh root@192.168.5.1 'ls -la /run/dnsmasq.dhcp.conf.d/cam-override.conf 2>&1'
ssh root@192.168.5.1 'ps -ef | grep "[d]nsmasq"   # confirm --conf-dir is .dhcp.conf.d/'
```

Interpret: if `dig` returns anything other than the chosen sink
(`203.0.113.37`), Phase 1 must be run before anything else.

**Phase 1 — Apply MITM layer:**

```sh
# On the UDM via SSH:
SINK=203.0.113.37
# Path is /run/dnsmasq.dhcp.conf.d/ — that is the MAIN dnsmasq's
# --conf-dir per `ps -ef`, despite the historical "dhcp" name in
# the path. The similarly-named /run/dnsmasq.dns.conf.d/ holds
# main.conf as --conf-file but is NOT a conf-dir, so address=
# directives dropped there are ignored. See ERRATA ERR-010.
OVERRIDE=/run/dnsmasq.dhcp.conf.d/cam-override.conf
cat > "$OVERRIDE" <<EOF
# camre: cam cloud sinkhole
address=/cloudbirds.cn/$SINK
address=/hapseemate.cn/$SINK
address=/hapsee.cn/$SINK
address=/dayunlinks.cn/$SINK
address=/philipsiot.com/$SINK
EOF
# Full restart — SIGHUP does NOT reload --conf-dir files (per the
# dnsmasq manual; SIGHUP only rereads --hostsdir and /etc/ethers).
# The UDM supervisor at PPID 5063 respawns dnsmasq with its original
# args immediately after the kill.
kill $(cat /run/dnsmasq-main.pid)

CAM=192.168.5.37
MAC=192.168.5.233
MARKER="camre"

# TCP 443 → Mac:8443
iptables -t nat -I PREROUTING 2 -s $CAM -p tcp -d $SINK --dport 443 \
  -j DNAT --to-destination $MAC:8443 -m comment --comment "$MARKER"
iptables -t nat -I PREROUTING 2 -s $CAM -p tcp -d 123.56.74.245 --dport 443 \
  -j DNAT --to-destination $MAC:8443 -m comment --comment "$MARKER"

# Any-proto catch-all (UDP Kalay)
iptables -t nat -A PREROUTING -s $CAM -d $SINK \
  -j DNAT --to-destination $MAC -m comment --comment "$MARKER"
iptables -t nat -A PREROUTING -s $CAM -d 123.56.74.245 \
  -j DNAT --to-destination $MAC -m comment --comment "$MARKER"

# Return-path
iptables -t nat -A POSTROUTING -s $CAM -d $MAC -j MASQUERADE \
  -m comment --comment "$MARKER"
```

**Phase 2 — Verify:**

```sh
# Mac side: expect all three to return 203.0.113.37
for h in p2p5.cloudbirds.cn user.hapseemate.cn public.dayunlinks.cn; do
  printf "%-30s → %s\n" "$h" "$(dig @192.168.5.1 +short "$h" | head -1)"
done
# UDM side: expect five comment-marked rules. Use -F literal match
# because iptables-save renders --comment values bare (no quotes)
# when they contain no spaces — see ERRATA ERR-010.
ssh root@192.168.5.1 "iptables-save | grep -F camre"
```

**Phase 3 — Block br4 WAN egress (OPTIONAL, not for this session):**

```sh
# DO NOT RUN during OTA discovery. Reserved for airgap mode.
iptables -I FORWARD 1 -i br4 -o eth4 -p udp --dport 123 -j ACCEPT \
  -m comment --comment "camre-allow-ntp"
iptables -I FORWARD 2 -i br4 -o eth4 -j DROP \
  -m comment --comment "camre-block-wan"
```

**Phase 4 — Teardown:**

```sh
# UDM side: explicitly iterate each table we touched, so we never
# need to recover table context from iptables-save output.
for t in nat filter; do
  iptables-save -t "$t" \
    | grep -F camre \
    | sed 's/^-A /-D /' \
    | while IFS= read -r rule; do
        # shellcheck disable=SC2086
        iptables -t "$t" $rule 2>/dev/null
      done
done
rm -f /run/dnsmasq.dhcp.conf.d/cam-override.conf
kill $(cat /run/dnsmasq-main.pid)   # supervisor respawns
```

**Sink IP rationale:** `203.0.113.37` is TEST-NET-3 (RFC 5737),
reserved for documentation, conventionally unrouted on the public
internet. Already tested and proven to work per
`docs/12-open-questions.md:25`. Strictly safer than `9.9.9.9`
(which is real Quad9 DNS — DNAT misses leak packets to a real
third party with logs).

**Ephemeral contract:** every rule and override file survives only
until the next Unifi GUI settings-apply OR UDM reboot. When either
happens, re-run Phase 1. This is a feature: it forces the setup to
be readable, checked-in to the repo, and reconstructible from scratch.

### Block 1 — CLAUDE.md preflight rule

Add a new section to `CLAUDE.md` directly after the existing
"Network-switching rule":

> **Router-state preflight rule**
>
> Before starting any cam session, confirm the MITM pipeline is
> actually in the state you think it is. The UDM's Unifi controller
> can silently regenerate dnsmasq config on any settings apply, which
> erases our overrides while iptables counters remain from the last
> working session — a failure mode that looks healthy under casual
> inspection. **`dig` is the source of truth, not packet counters.**
> Run the `Phase 0 — Preflight` block from `docs/09-router-setup.md`
> before anything else. If `dig` from the Mac does not return
> `203.0.113.37` for `user.hapseemate.cn` and friends, stop and
> re-run Phase 1 before touching anything else. Never trust "it was
> working last session" — verify each session from scratch.

### Block 2 — MITM proxy multi-cloud extension

**Changes to `mitm_cbs_proxy.py`:**

1. Replace the hardcoded `UPSTREAM_HOST` and `UPSTREAM_IP` constants
   with an SNI suffix allowlist:
   ```python
   UPSTREAM_SNI_ALLOWLIST = {
       ".hapseemate.cn",
       ".cloudbirds.cn",
       ".dayunlinks.cn",
       ".philipsiot.com",
   }
   ```
   Connections whose SNI matches no suffix are rejected with a
   loud `REJECT unknown SNI` log line.

2. On each accepted connection, resolve the upstream IP **via a
   stub resolver pointed at `1.1.1.1:53`** — not the Mac's system
   resolver. The system resolver routes through the UDM's dnsmasq,
   which is now sinkholing those hostnames, so using it would make
   the proxy try to connect to its own sinkhole. The stub resolver
   is a small hand-rolled UDP DNS query (~80 LoC) to avoid adding
   `dnspython` as a dependency.

3. Pass the resolved IP as the TCP connect target, pass the SNI
   as `server_hostname` when wrapping the upstream socket.

4. Add a new capture hook: after a TLS session terminates, write
   a structured JSON pair to
   `captures/ota/YYYY-MM-DDTHH-MM-SS/<N>-request.json` and
   `<N>-response.json`. Includes method, path, headers, body (base64
   if non-printable), timestamps. Block 4 consumes this.

**Changes to `fake_cbs_server.py`:**

Extend the self-signed cert SAN list (lines 97-100) to include:

- `*.dayunlinks.cn`
- `dayunlinks.cn`
- `*.philipsiot.com`
- `philipsiot.com`
- `birds-public.philipsiot.com`

Delete the cached cert file under `/tmp/cam-listen/fake-cbs-certs/`
so the next proxy start regenerates it.

### Block 3 — Emulator-based OTA trigger

> **Major simplification from Wave 1 Agent D finding.** Static
> analysis of `decompiled/sources/com/qianniao/base/http/HttpClient.java:71-105`
> confirmed that the V360 Pro app ships with an **allow-all
> X509TrustManager and HostnameVerifier** — every TLS connection
> accepts every certificate with no pinning, no hostname check, no
> `networkSecurityConfig`, and no Frida/root detection. Therefore
> the entire CA-push-to-system-store path in this block is
> unnecessary. We do NOT need `-writable-system`, `adb root`,
> `adb remount`, `/system/etc/security/cacerts/`, or Magisk. The
> app will accept the self-signed cert from `fake_cbs_server.py`
> without any additional configuration. See
> `docs/07-defenses.md` for the finding.

**3a — Install Android command-line tooling (macOS):**

```sh
brew install --cask android-commandlinetools
yes | sdkmanager --licenses
sdkmanager "platform-tools" "emulator" \
  "system-images;android-34;google_apis;arm64-v8a" \
  "platforms;android-34"
avdmanager create avd -n camtest \
  -k "system-images;android-34;google_apis;arm64-v8a" \
  --device pixel_6
```

`google_apis` is still preferred over `google_play` (no Play Protect
interference, cleaner debug surface), but it&rsquo;s no longer a
correctness requirement — any recent ARM64 system image will work
since we don&rsquo;t need to modify `/system` at all.

**3b — Cert pinning static check:** completed in Wave 1 (Agent D).
Result: **no pinning, no custom trust stack worth bypassing, no
root/Frida detection.** Documented in `docs/07-defenses.md` and
`docs/12-session-log.md` Session 6 entry. No action required in
Wave 3.

**3c — Install vendor APK:**

```sh
emulator -avd camtest -no-snapshot &
adb wait-for-device
adb install "V360 Pro_6.5.0_APKPure.apk"
```

That&rsquo;s it — no root, no remount, no cert push. The app trusts
every cert unconditionally, so pointing it at our MITM is sufficient
on its own.

**3d — Emulator-to-MITM path via Mac-local sinkhole:**

The emulator uses the Mac's DNS resolver, not the UDM's. Add the
target hostnames to Mac `/etc/hosts` pointing at `127.0.0.1`:

```
127.0.0.1 user.hapseemate.cn
127.0.0.1 p2p5.cloudbirds.cn
127.0.0.1 public.dayunlinks.cn
127.0.0.1 birds-public.philipsiot.com
```

Use `pfctl` to redirect `tcp:127.0.0.1:443` → `tcp:127.0.0.1:8443`
so the proxy doesn't need a privileged bind:

```sh
echo 'rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 443 -> 127.0.0.1 port 8443' | \
  sudo pfctl -ef -
```

This forms a **parallel sinkhole path**: the UDM dnsmasq handles
the cam; the Mac `/etc/hosts` + `pfctl` handles the emulator.
Independent paths → no shared failure modes.

**3e — Trigger the OTA check:**

- Launch the app on the emulator
- Create a throwaway account (avoid using a real account)
- Add the cam by DID (offline QR flow if needed — the cam does
  not need to be online for the app-side version-check flow to
  reach the server)
- Navigate: cam detail → settings → "Firmware" / "About" /
  "Check for updates"
- Watch `/tmp/cam-listen/mitm_cbs.log` for new entries

### Block 4 — Capture, success criteria, stop conditions

**What we capture, in value order:**

1. The OTA check request (hostname, path, method, headers, body).
2. The OTA check response (JSON with version and URL fields).
3. The firmware download URL, resolved to a real IP.
4. The firmware binary itself, via proxy or out-of-band `curl`.
5. Any HMAC / signature material from the request, traceable back
   to `Api.java`.

**Capture destinations:**

- `/tmp/cam-listen/mitm_cbs.log` — human-readable tailing log
  (unchanged from current behavior).
- `captures/ota/<ISO-timestamp>/<N>-request.json` + `<N>-response.json`
  — structured per-exchange dump (new, written by the Block 2
  capture hook).
- `captures/ota/<ISO-timestamp>/firmware.bin` — firmware binary
  if captured.

**Success criteria (Block 4 done):**

- [ ] At least one complete OTA-check request/response pair captured.
- [ ] Firmware download URL + real IP documented in
      `docs/03-cloud-topology.md`.
- [ ] Firmware binary captured OR clean reason documented for why
      not (e.g., "response says up-to-date, no URL emitted").
- [ ] `docs/12-open-questions.md:143` (OTA endpoint) updated from
      open to answered/partially-answered.
- [ ] `docs/11-session-log.md` entry written for Session 6.
- [ ] Philips IoT CNAME finding documented in
      `docs/03-cloud-topology.md`.

**Stop conditions (bail out, do not escalate):**

- 🛑 Cert pinning defeats direct CA push AND Frida hook attempts
  after 45 minutes total — document, fall back to static RE of
  `Api.java` in a future session.
- 🛑 App refuses to log in / function due to undetermined
  MITM detection — document, same fallback.
- 🛑 OTA check returns "up-to-date" and cannot be coaxed into
  offering a download URL even with spoofed old-version requests
  — document, shift to crafting the check request ourselves from
  the captured format.
- 🛑 Response contains a signed firmware manifest we can't verify
  the key for — **not a stop condition, this is information**.
  Capture it, mark `docs/12-open-questions.md:154` as
  "probably signed," proceed.

**Explicit non-goals for Block 4:**

- No flashing to the cam.
- No crafting of a malicious firmware.
- No in-flight MITM rewrite of the firmware binary.
- No enabling Phase 3 (br4 WAN egress block).

## Implementation ordering and dependencies

```
Block 0 (router-setup.md + restoration)  ─┐
                                          ├─→ Block 1 (CLAUDE.md preflight rule)
                                          │
                                          └─→ Block 2 (MITM multi-cloud)
                                                │
                                                └─→ Block 3 (emulator + OTA trigger)
                                                     │
                                                     └─→ Block 4 (capture + criteria)
```

Block 0 must complete before anything else — no point configuring
anything on top of a broken pipeline. Block 1 is a pure docs change
and can ship in parallel with Block 2. Blocks 3 and 4 are strictly
sequential. The renumber cascade (new task #8) should happen as
part of Block 0's execution.

## Doc renumber cascade

Current → new mapping. Old `09-mitm-setup.md` splits: its router-
side content becomes the new `09-router-setup.md`; its Mac-side
proxy start/stop/verify content migrates into a brand new
`10-mitm-mac-side.md`. Everything from old `10-tooling.md` onward
shifts up by one slot.

| Old slot | Old name | New slot | New name | Content change |
|---|---|---|---|---|
| 09 | `mitm-setup.md` | 09 | `router-setup.md` | **Replaced.** Router-only, script-shaped, ephemeral phases. |
| (new) | — | 10 | `mitm-mac-side.md` | **New file.** Mac-side proxy start/stop/verify content extracted from old `09-mitm-setup.md`. |
| 10 | `tooling.md` | 11 | `tooling.md` | Unchanged content, shifted slot. |
| 11 | `session-log.md` | 12 | `session-log.md` | Unchanged content, shifted slot. |
| 12 | `open-questions.md` | 13 | `open-questions.md` | Unchanged content, shifted slot. |
| 13 | `next-steps.md` | 14 | `next-steps.md` | Unchanged content, shifted slot. |
| 14 | `glossary.md` | 15 | `glossary.md` | Unchanged content, shifted slot. |
| 15 | `debugging.md` | 16 | `debugging.md` | Unchanged content, shifted slot. |
| 16 | `portability.md` | 17 | `portability.md` | Unchanged content, shifted slot. |

All cross-references in doc body text and `docs/README.md` index
must be updated. `docs/ERRATA.md` gets a note about the renumber.
`build_docs.py` should be verified to still work after the renumber
(it likely takes all `*.md` so no change needed).

## Risks and open questions for the implementation

1. **Unifi GUI config-apply timing.** If you hit "Apply" in the
   Unifi GUI mid-session for any reason, the dnsmasq override file
   disappears and the pipeline breaks until Phase 1 is re-run.
   Mitigation: don't touch the GUI during a session; preflight
   after any break.

2. **Cam DHCP reservation.** The `CAM=192.168.5.37` constant in
   Phase 1 is a DHCP lease, not a static assignment. If the cam
   gets a new IP, Phase 1 doesn't match. Mitigation: set a static
   DHCP reservation in the Unifi GUI (one-time, persists across
   settings applies) or detect the cam's current IP at script time
   via `arp` / `ip neigh show`.

3. **TEST-NET allowlist.** `docs/12-open-questions.md:23` flags an
   unresolved question about which non-RFC1918 sink IPs the cam
   accepts. We're picking `203.0.113.37` because it's already
   known-good. If it unexpectedly fails, the fallback is the
   previously-used `9.9.9.9` — documented loudly as a regression.

4. **APK version drift.** `V360 Pro_6.5.0_APKPure.apk` is the
   version we have. If the real OTA check returns a server-side
   requirement like "must use app >= 6.6.0", we may need a newer
   APK. Mitigation: capture the response anyway, look for version
   gate, document, acquire newer APK if needed.

5. **Philips IoT TLS may be stricter.** `philipsiot.com` is
   Signify-operated infra. It's more likely than the Chinese cloud
   to have modern TLS requirements (no weak ciphers, maybe HSTS
   preload, maybe ALPN quirks). The stub resolver approach should
   cover this, but if it doesn't, the proxy's `ssl.SSLContext`
   needs a review pass.

6. **Firmware capture size.** Firmware images for cheap IP cams
   range from 4–32 MB. `/tmp/cam-listen/` is not the right place
   for a binary that size to live long-term. Mitigation: the
   `captures/ota/` dir is inside the repo root and persistent;
   add it to `.gitignore` (binary artifacts don't belong in git).

## Acceptance and next step

If this spec passes user review, the next action is invoking the
`superpowers:writing-plans` skill to turn the five blocks into a
numbered, dependency-ordered implementation plan with explicit
verification points.

_Authored: 2026-04-15 — Session 6_
