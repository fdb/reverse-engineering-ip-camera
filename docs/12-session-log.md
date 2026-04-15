_Last updated: 2026-04-15 — Session 7_

# 12 · Session log

Chronological record of what we learned and when. Update this file
at the end of every session with bullet points for anything
non-obvious you figured out. Think of it as the project&rsquo;s changelog.

## 2026-04-14 — Session 1: Initial RE and provisioning

- **Starting state**: zero knowledge. Had the APK only.
- **Installed tooling**: `jadx` 1.5.5 via Homebrew for APK
  decompilation.
- **Identified the OEM stack**: `com.qianniao.*` package tree, Kalay
  P2P via `libPPCS_API.so`, HAP- SSID prefix traces back to HapSee.
- **Found the provisioning code path**: `WifiScanQrcodeFragment.kt`
  generates a QR of literal format `S<ssid>\n<pwd>\n`. No JSON, no
  standard Wi-Fi QR format — just a plain string.
- **Built `wifiqr.py`**: offline QR generator that matches the exact
  format. Bypasses the vendor&rsquo;s `getDidByToken` telemetry step.
  First attempt used `qr.print_ascii(tty=True)` which errored when
  stdout was a StringIO; rewrote the half-block renderer from
  scratch from the raw `get_matrix()` output.
- **Reversed the 8899 beacon and 18523 "YH" multicast paths** by
  reading `SearchDeviceByUDP.kt` and `SearchDeviceByMulticast.kt`.
- **Wrote first version of `probe.py`** with both passive 8899
  listen and active 18523 broadcast modes.
- **Initial explainer**: first version of `explainer.html` (8 slides),
  covering the discovery protocol as understood from static analysis
  only.

## 2026-04-14 — Session 2: Wire capture + DNS rebinding discovery

- **First pcap captures** (`camera_phonehome*.pcap`) after putting
  the cam on isolated Wi-Fi. DNS queries, NTP wrappers, TLS to
  hapseemate, UDP to three supernodes all immediately visible.
- **Confirmed Kalay wire format** `0xF1 <type> <len BE>` with bodies
  matching observed message types. `DEV_LGN_ACK` body captured as
  deterministic constant `a02aaac73b7755c9`.
- **First fake supernode** (`fake_supernode.py`): canned
  `HELLO_ACK` with an RFC1918 IP. Cam accepted DEV_LGN_CRC replays
  but never advanced to new message types.
- **Debugged the "cam never tries TCP 443 to Mac" issue**: turned out
  the cam was filtering RFC1918 DNS answers for cloud hostnames.
  Discovered this by comparison: resolving `user.hapseemate.cn` to
  `192.168.5.233` produced no TCP SYN; resolving to `9.9.9.9`
  produced immediate SYN storms.
- **Identified the DNS rebinding filter** as the single meaningful
  vendor defense. Wrote up the theory in what&rsquo;s now
  [`07-defenses.md`](07-defenses.md).
- **Switched dnsmasq override to `9.9.9.9`** and added iptables DNAT
  rules on the UDM to redirect to the Mac. First time we saw actual
  traffic arrive at `192.168.5.233`.
- **SOURCE OF THE MASQUERADE CONFUSION**: tcpdump filter
  `host 192.168.5.37` saw zero packets even though the DNAT
  counters were incrementing. Realized that after MASQUERADE the
  cam&rsquo;s source IP is rewritten to `192.168.5.1` (the UDM), not its
  original `.37`. Updated filters accordingly.
- **Captured the first real CBS response** via a mitm TLS terminator
  that actually forwarded to the real cloud:
  `{"mssage":"success","status":"200"}`. **The typo is preserved
  verbatim**; our earlier guess envelopes with `"message"` did not
  satisfy the cam.

## 2026-04-14 → 2026-04-15 — Session 3: Full MITM + 0xF9 discovery

- **Built `mitm_cbs_proxy.py`**: TLS MITM with self-signed
  `*.hapseemate.cn` cert. Terminates downstream TLS, opens upstream
  TLS to real 190.92.254.71, forwards cleartext. Works first try —
  the cam does not pin certs.
- **Observed** the `GET /preadd/didBindUserId?relatInfo=…&did=…&utcTime=…`
  request in cleartext. DID and relatInfo are base64url-encoded
  encrypted blobs (32 B each). `utcTime` is an unencrypted Unix
  timestamp used as a replay-attack mitigation.
- **Fixed HELLO_ACK to use a non-RFC1918 IP** (`203.0.113.37`,
  TEST-NET-3). Immediately the cam started sending a new Kalay
  message type we&rsquo;d never seen: `0xF9 REPORT_SESSION_RDY`, 88 bytes,
  84-byte XOR-obfuscated body.
- **Matched `0xF9` to `Proto_Send_ReportSessionRdy`** from
  `libPPCS_API.so` symbol table. The function signature has three
  `sockaddr_in*` args — WAN, LAN, and relay endpoints — which means
  the encrypted body carries the cam&rsquo;s full endpoint triple. This
  is what the supernode uses to route peers to the cam later.
- **Pivoted to full UDP MITM** (`mitm_supernode_proxy.py`) — instead
  of faking Kalay responses, forward everything to the real
  supernodes and return their real responses to the cam. Immediately
  saw the real `HELLO_ACK` response with Frederik&rsquo;s actual WAN IP
  `37.37.51.178` baked into the sockaddr, and confirmed the cam
  accepts it without issue.
- **Confirmed DEV_LGN_ACK is deterministic** across three different
  supernodes (Shenzhen, US-West, Beijing), across multiple session
  nonces, and across cam reboots. Always `a02aaac73b7755c9`.
- **Confirmed `0xF9` is fire-and-forget**: supernodes never send a
  reply. Cam updates internal state and proceeds.
- **Added SIGUSR1 injection hook** to `mitm_supernode_proxy.py`:
  reads JSON from `/tmp/cam-listen/inject.json`, sends each
  described packet from the same `:32100` socket. This lets us
  inject crafted frames that arrive at the cam with the correct
  reverse-NAT rewrite (`src = 9.9.9.9:32100`).
- **Wrote `inject_p2p_req.py`**: builds a 40-byte `P2P_REQ (0x20)`
  packet and fires it via SIGUSR1. First attempt targeted dead
  session ports and saw no response. Second attempt against live
  sessions (`1097`, `16106`) also silent — type `0x20` is not in
  the cam&rsquo;s device-role dispatch.

## 2026-04-15 — Session 4: llvm-objdump deep dive

- **Frederik independently disassembled `Proto_Send_PunchTo`** via
  `llvm-objdump` and wrote detailed notes in
  `Proto_Write_PunchTo.md`. Key findings:
  - `Write_PunchTo` does not exist as a separate function — it&rsquo;s
    inlined into `Send_PunchTo`.
  - PUNCH_TO body is 16 B = single sockaddr_in, type byte `0x40`,
    total 20 bytes.
  - `Send_PunchTo` is symmetric: the same function is used by both
    client and server roles, with the semantics depending on
    whether `dst` or `target` refers to a supernode or a peer.
  - PUNCH_TO is client→relay only — device-role code path likely
    ignores it entirely.
- **Claude followed up** by disassembling `Read_P2PReq`,
  `Write_P2PReq`, `Send_P2PReq`, and decoding the full 40-byte
  packet format: `did_prefix(8) + lgn_u32_BE(4) + did_suffix(8) +
  sockaddr_in(16)`. Body has no auth/nonce/CRC. Plaintext end to
  end.
- **Located `thread_recv_Proto @ 0x1ebe8`**: the cam&rsquo;s main
  receive-loop dispatcher. Extracted its `cmp w0, #0xNN`
  instructions to find the whitelist of message types the
  device role actually handles:
  `0x13, 0x30, 0x31, 0x3f, 0x52, 0x55, 0xdb, 0xdc`. None of our
  guessed injection types (`0x20, 0x40, 0x42`) are in the list.
- **Also extracted the function call graph** of `thread_recv_Proto`:
  it calls `Read_PunchPkt`, `Read_P2PRdy`, `Read_DCHeader`,
  `Read_TryLanTcp`, `Read_RlyRdy`, `Read_RlyTo`, `Read_RlyPortAck`,
  `Read_TCPRSStart`, plus the decryption helper
  `_P2P_Proprietary_Decrypt`. These are the readers that actually
  get called — so the cam handles message types that route into
  them, not the type bytes we were guessing.
- **Built `explainer-deep.html`**: comprehensive 14-slide interactive
  documentation of everything we know.
- **Pivoted strategy**: decided the cleanest next step is to build
  a "fake app client" that speaks the app-side protocol to the real
  supernode. Instead of injecting crafted packets to the cam, ask
  the real supernode to look up the cam, let it send whatever the
  correct notification is, observe that notification in our MITM
  logs (which gives us the format for free).
- **Created `docs/` directory and initialized git**. This document.
  From now on, update this file at the end of every session.

## 2026-04-15 — Session 5: Docs infrastructure + review pass

- **Goal**: turn the scratch notes from sessions 1-4 into a full
  living documentation set and ship a static site renderer for it.
- **Created `docs/`** with 16 files: README + 14 numbered reference /
  how-to / log docs + this session log. ~3,000 lines total.
- **Wrote `build_docs.py`** — a ~400-line self-contained static site
  generator that turns `docs/*.md` into `dist/*.html` using
  python-markdown with codehilite. Core logic is <60 lines of
  Python; everything else is inlined CSS and template. Supports
  dark/light mode via CSS vars + localStorage toggle.
- **Added a `docs/` living-document rule** to the project CLAUDE.md
  telling future sessions to update `docs/` in the same turn as any
  new finding and rebuild the site.
- **Review pass over `docs/`** as a technical reviewer: caught 8
  factually-suspect claims that were stated as facts but were
  actually inferences or guesses. Examples:
  - "Cam accepts exactly 8 message types" softened to "at least 8
    via `cmp` branches in a 9000-instruction function" — the
    analysis wasn&rsquo;t exhaustive enough to claim completeness.
  - "Bodies are XOR-scrambled" softened to "obfuscated by
    `_P2P_Proprietary_Decrypt`, cipher unverified" — we haven&rsquo;t
    actually disassembled the cipher yet.
  - "No device auth in CBS" corrected to "unknown auth" — the
    `relatInfo` and `did` parameters are 32-byte obfuscated blobs
    whose semantics we don&rsquo;t understand, so we can&rsquo;t claim absence.
  - "Three receive threads" corrected to four (added
    `thread_recv_FW_DCResponse`).
  - "The `mssage` typo is load-bearing" softened — we verified a
    generic `{"code":0,...}` response fails, but we never actually
    tested a corrected `{"message":"success","status":"200"}` to
    prove the typo itself is required.
- **Added provenance tags** throughout `docs/04-wire-format-kalay.md`:
  _observed_ / _disassembled_ / _inferred_ / _guessed_ labels on
  each claim so the reader can distinguish between "seen on the
  wire" and "we think this because of symbol names".
- **Added the first real hex dump** of a captured `0xF9
  REPORT_SESSION_RDY` body to the wire-format doc, for future
  obfuscation-reversal work.
- **Added `docs/16-debugging.md`** — debug cookbook covering common
  pipeline failure modes with symptoms, diagnosis commands, and
  fixes.
- **Added `docs/17-portability.md`** — what&rsquo;s reusable for other
  Kalay/CS2 cams vs. what&rsquo;s cam-specific.
- **Added `docs/ERRATA.md`** — tracks corrections and "we used to
  say X, now we say Y" updates.
- **Deleted `NEXT_STEPS.md`** at the project root — content was a
  near-duplicate of `docs/14-next-steps.md`, replaced with a stub
  pointing at the canonical copy.
- **Built and tested the site** with Playwright MCP. Screenshots
  verified: dark mode loads by default, toggle works, sidebar
  navigation works, code blocks are syntax-highlighted, typography
  is readable at the stated max content width.
- **Status at end**: docs/ is a clean, consistent, reviewed
  reference. Fakie-client approach is still the recommended next
  technical step — documented fully in `docs/14-next-steps.md`.

## 2026-04-15 — Session 6: OTA discovery pivot + router-state restoration

- **Goal of the session**: pivot from the stalled Kalay fake-client
  path to investigating the firmware OTA update flow. Capture the
  app-side OTA version check to identify the update endpoint and
  (if possible) the firmware binary.
- **Pre-work finding — MITM pipeline was silently broken**: `dig`
  preflight showed `user.hapseemate.cn`, `p2p5.cloudbirds.cn` and
  `public.dayunlinks.cn` all resolving to real cloud IPs, not the
  sink. Root cause: the Unifi controller regenerates
  `/run/dnsmasq.dns.conf.d/*.conf` on every settings-apply, which
  wiped the Session 5 `address=` overrides. The `iptables` counters
  still showed thousands of healthy-looking packets — these were
  **stale** from before the override was lost. Classic "stale
  evidence masquerading as success." Documented in `ERRATA.md`
  entry ERR-009.
- **Key finding: V360 Pro app ships with allow-all TLS trust.** Static
  analysis of `decompiled/sources/com/qianniao/base/http/HttpClient.java:71-105`
  found a custom `X509TrustManager` with an empty `checkServerTrusted()`
  method plus a `HostnameVerifier` that returns `true` unconditionally.
  No `networkSecurityConfig`, no `CertificatePinner`, no root/Frida
  detection. Every HTTPS call the app makes is trivially MITM-able.
  This simplifies Wave 3 emulator setup dramatically — no CA push
  needed, no `-writable-system` image, no Frida hooks. Documented in
  `07-defenses.md`.
- **Key finding: OTA backend is Philips IoT, not Chinese cloud.**
  `public.dayunlinks.cn` CNAMEs through `birds-public.philipsiot.com`
  to `190.92.254.74` — Signify-operated infrastructure. Worth
  flagging for OEM-family portability work. Documented in
  `03-cloud-topology.md`.
- **Identified OTA endpoints** (static analysis, not yet captured
  live): `GET https://public.dayunlinks.cn/public/checkDevVer` and
  `GET https://public.dayunlinks.cn/public/checkVer`. Also discovered
  additional app-side hosts: `birds-user.hapseemate.cn`,
  `wechat.hapseemate.cn`, `ai-voice.cloudbirds.cn`,
  `apppush-hapseemate.dayunlinks.cn`.
- **Doc restructure**: old `docs/09-mitm-setup.md` was conflating
  two independent concerns (router-side config and Mac-side proxy
  ops) AND had the wrong dnsmasq path (`/run/dnsmasq.conf.d/` →
  should have been `/run/dnsmasq.dns.conf.d/`). Replaced with:
  - `docs/09-router-setup.md` — script-shaped, ephemeral, four
    phases (Preflight / Apply / Verify / Optional br4 egress block /
    Teardown) with comment-marker pattern (`-m comment "camre"`)
    for surgical rule removal.
  - `docs/10-mitm-mac-side.md` — clean standalone reference for
    the Python proxies on the Mac.
  - Everything from old slot 10 through old slot 16 shifted up
    by one to slots 11–17. See ERRATA entry ERR-009 for the full
    rename map.
- **Sink IP switched** from `9.9.9.9` (real Quad9) to `203.0.113.37`
  (TEST-NET-3, RFC 5737). Lower OPSEC footprint: a DNAT miss drops
  the packet instead of leaking to Quad9&rsquo;s logs. Already
  known-good per pre-existing test in (then) `12-open-questions.md`.
- **MITM proxy upgraded for multi-cloud**: `mitm_cbs_proxy.py` now
  SNI-dispatches against an allowlist
  (`{hapseemate.cn, cloudbirds.cn, dayunlinks.cn, philipsiot.com}`)
  and resolves upstream IPs live via a hand-rolled DNS stub pointing
  at `1.1.1.1:53` (so it doesn&rsquo;t go through the Mac&rsquo;s system
  resolver, which is sinkholing those hostnames). Each completed
  exchange is dumped as JSON to
  `captures/ota/<ISO-timestamp>/<NNNN>-{request,response}.json` for
  structured querying. Cert SAN list extended on
  `fake_cbs_server.py` to cover dayunlinks and philipsiot domains.
- **Preflight rule added to `CLAUDE.md`**: `dig` is the source of
  truth for MITM pipeline health, not packet counters. Every
  session must start by running Phase 0 of `09-router-setup.md`
  before any other work. Prevents the Session 5 → Session 6
  silent-break scenario from recurring.
- **Design spec**: `docs/superpowers/specs/2026-04-15-ota-discovery-design.md`
  documents the whole pivot (five blocks), with explicit stop
  conditions for Wave 3 and a firm "no flashing firmware this
  session" rule.
- **Blockers hit**: none unresolved. Wave 3 (emulator OTA trigger +
  capture) is pending interactive execution by Frederik.
- **Artifacts produced**: `docs/09-router-setup.md`,
  `docs/10-mitm-mac-side.md`, renumber cascade of 10→17,
  `docs/superpowers/specs/2026-04-15-ota-discovery-design.md`,
  modified `mitm_cbs_proxy.py` (SNI dispatch + stub resolver +
  structured capture), modified `fake_cbs_server.py` (SAN list),
  preflight rule in `CLAUDE.md`, updates to
  `03-cloud-topology.md` / `07-defenses.md` / `13-open-questions.md`.
- **Status at Wave 2 end**: router-state restoration script written,
  emulator tooling not yet installed, spec and supporting scaffolding
  ready; Wave 3 was a ~20-minute interactive run after `brew install`.

### Wave 3 (executed) — live capture of the app&rsquo;s OTA flow

- **Router Phase 1 applied live.** Discovered ERR-010 in the process
  (wrong dnsmasq dir + SIGHUP insufficiency). After correction, `dig
  @192.168.5.1 user.hapseemate.cn → 203.0.113.37` for all five target
  hostnames. Cam-side pipeline confirmed alive by observing live
  DEV_LGN / DEV_LGN_ACK heartbeats in `mitm_supernode.log` from
  192.168.5.1:* to the real Aliyun supernodes — first time the cam
  has actually routed through our MITM since Session 5 broke it.
- **Emulator tooling**: `brew install --cask android-commandlinetools`
  + `sdkmanager` to install `platform-tools`, `emulator`,
  `system-images;android-34;google_apis;arm64-v8a`, `platforms;android-34`.
  Requires Temurin JDK on PATH; `/opt/homebrew/share/android-commandlinetools/emulator/emulator`
  is NOT auto-symlinked by brew and needs an explicit PATH export.
  Documented in `CLAUDE.md`.
- **AVD**: created `camtest` (pixel_6 profile, arm64-v8a, google_apis,
  API 34) preserved at `~/.android/avd/camtest.avd` for future reuse.
- **Trust-path trick**: discovered via Wave 1 Agent D that the V360
  Pro app uses an allow-all `X509TrustManager` + allow-all
  `HostnameVerifier` (`com/qianniao/base/http/HttpClient.java:71-105`).
  **No CA push, no `-writable-system`, no Frida required** — the app
  accepts any self-signed cert. This cut Wave 3 trust setup from
  ~30 min (Magisk flow) to ~0 min (just use the existing
  `fake_cbs_server.py` cert).
- **Traffic capture path**: edited `/system/etc/hosts` on the emulator
  to sinkhole all target hostnames to `127.0.0.1`, then
  `adb reverse tcp:443 tcp:8443` to forward the emulator&rsquo;s `127.0.0.1:443`
  connections to the Mac&rsquo;s `127.0.0.1:8443` where `mitm_cbs_proxy.py`
  listens. Clean, sudo-free, pfctl-free. Emulator stayed isolated
  from the Mac&rsquo;s real DNS resolver throughout.
- **Captured 14 exchanges** in `captures/ota/2026-04-15T10-58-07/`
  during app cold-start + consent + account registration + login +
  home-screen + an attempted add-device flow. (The `captures/` dir is
  gitignored because it contains session tokens and a real public IP.)
- **Key finding 1 — the app-level OTA endpoint confirmed empirically**:
  exchange 0017 is `POST public.dayunlinks.cn/public/checkVer`, which
  the app calls automatically on every SplashActivity. Response:
  `{"ver":0,"message":"The app version is the latest","status":200}`.
- **Key finding 2 — `/domainname/all` is a one-shot backend
  substitution surface**: exchange 0003 is the app&rsquo;s startup
  directory fetch, which returns an encrypted JSON dict mapping
  every service name to a URL. Decrypted offline with
  `AesUtil.URL_KEY = "24QLQzq5DZjy4boX"` (AES-128-ECB, PKCS7 padded).
  All 10 fields revealed, 4 of them brand-new hostnames — documented
  in `03-cloud-topology.md`. One new OEM brand surfaced:
  `payment.aiseebling.com`. One anomaly: `cancellation` is plain
  `http://`, not `https://`.
- **Key finding 3 — the client does NOT download firmware**
  (Wave 3 APK static analysis, Agent F). `DeviceVer` has no URL
  field; no `@Streaming` Retrofit methods in the `qianniao`
  packages; no `FileOutputStream` writes from HTTP bodies. The
  upgrade trigger is a single Kalay IOCTRL:
  `IOTYPE_USER_IPCAM_SET_UPGRADE_REQ = 0x8116` with a **36-byte
  all-zero payload** — no URL, no auth, no signature. The cam
  self-fetches from its own baked-in update server. Documented in
  `04-wire-format-kalay.md` §DRW IOCTRL commands.
- **Key finding 4 — implication for firmware capture**: since the
  app doesn&rsquo;t touch firmware bytes, capturing the binary in
  flight requires **cam-side interception**, not app-side. Our
  router-side MITM pipeline is already positioned for exactly that.
  Session 7&rsquo;s primary objective is to trigger a real update cycle
  via the bind-real-cam flow and catch the cam&rsquo;s self-fetch
  traffic. Documented as Step A in `14-next-steps.md`.
- **Key finding 5 — bonus vendor security notes**:
  - The `/user/login.html` response body includes a `pwd` field
    containing base64-encoded bytes (`iPm9akcdXTmb2AHyfpvegg==`,
    18 bytes). Either a session token mis-named, or the vendor is
    round-tripping a reversible transform of the password — either
    way suspicious. Noted in `03-cloud-topology.md`.
  - The client-side "battery > 25% required for upgrade" check at
    `DeviceInfoFragment.java:198-209` is a pure UX gate. Sending
    `0x8116` directly bypasses it.
  - Five AES-128 keys are baked into `com/qianniao/base/utils/AesUtil.java`
    (DATA_KEY, DOMAIN_KEY, URL_KEY, WEB_KEY, XIAODUAI_KEY), all in
    ECB mode. Cataloged in `07-defenses.md`. URL_KEY cracked and
    used this session.
  - `payment.aiseebling.com` surfaces a **fifth OEM brand** in the
    supply chain alongside Qianniao / Cloudbirds / HapSee / Signify-Philips.
    First reference we have to this domain.
- **Ground truth on supported countries**: the
  `/user/getOpenCountryCode` endpoint returns
  `["CN","TW","TH","US","VN","MY","MX","RU"]`. Belgium is not on
  the list — Frederik registered anyway because the backend
  doesn&rsquo;t hard-enforce.
- **Status at end of Wave 3**: primary Session 6 goals achieved
  (OTA discovery + pipeline restoration + APK RE). Emulator cleanly
  shut down (`adb emu kill`); AVD preserved. MITM proxies and
  router rules left running for potential cam-side activity
  capture. Three commits on main:
  - `7082b81` docs restructure + renumber cascade (Wave 1)
  - `4051a21` OTA discovery scaffolding + findings (Wave 2)
  - `06c7fc2` ERR-010 dnsmasq path + restart method (Wave 3 mid-run)
  - (this session&rsquo;s Wave 3 findings pending one more commit)

## 2026-04-15 — Session 7: Aiseebling.com money-trail OSINT

- **Goal of the session**: follow up on the Session 6 loose end —
  `URLConfig.pay → https://payment.aiseebling.com`, the one URL
  from the decrypted `/domainname/all` dictionary that didn&rsquo;t
  match any known brand cluster. Spec lives at
  `docs/superpowers/specs/2026-04-15-aiseebling-money-trail-design.md`.
  Passive OSINT only; no active probing, no forms, no payment
  activity.
- **Headline verdict**: `aiseebling.com` is **operated by the same
  Qianniao OEM cluster that publishes the V360 Pro app itself**. It
  is not a third-party payment partner and not a separate OEM. It is
  the OEM&rsquo;s own shared white-label payment / deep-link endpoint.
  Full writeup in [`18-aiseebling-investigation.md`](18-aiseebling-investigation.md).
- **Key finding — the homepage is a self-disclosing multi-brand
  shell.** `https://aiseebling.com/` serves a Vue/React/Vite SPA
  whose `<head>` contains the currently-active brand&rsquo;s
  `<title>` and `<link rel="icon">`, plus **seven commented-out
  sibling `<title>` tags naming parallel legal entities** and
  eight commented-out sibling brand logos. The first line of the
  file is literally `<!-- 千鸟物联logo 、dayunlinks -->`, naming
  the Dayunlinks brand in plain ASCII. The currently-active brand
  is `深圳市安芯看看物联科技有限公司` (Shenzhen Anxinkankan IoT
  Technology Co., Ltd.).
- **Key finding — Play Store disclosure nails the entity.** Google
  Play&rsquo;s mandatory developer disclosure for
  `com.dayunlinks.cloudbirds` names "Shenzhen Qianniao Xiangyun
  Technology Co., Ltd., No. 42 Longcheng Street, Longgang District,
  Shenzhen" — which is an exact English translation of
  `深圳市千鸟祥云技术有限公司`, one of the commented entities on
  the aiseebling homepage. Two independent sources, same entity.
  The `com.qianniao.*` Java package root from earlier sessions is
  now pinned to a real registered company.
- **Key finding — domain is brand-new and Tencent-stacked.**
  Registered 2025-07-11 via DNSPod (Tencent subsidiary; registrant
  country CN, privacy-shielded). Apex on Tencent Cloud Beijing
  (`43.139.108.230`, AS45090). `payment.aiseebling.com` on Huawei
  Cloud HK ELB (`189.1.221.131`). `universallink.aiseebling.com` on
  Huawei Cloud Shenzhen. Tencent-run MX (`mxbiz1.qq.com`) and SPF.
  The ~9-month age plus zero Wayback snapshots plus zero indexed
  web references confirms it&rsquo;s a fresh operator-controlled
  endpoint, not a legacy brand.
- **Supply-chain implication**: the Qianniao OEM runs at least
  **nine sibling brand faces** out of the same Shenzhen-Longgang
  codebase — `千鸟物联`, `云看看`, `安芯看看`, `欣视安`, `飞利浦`
  (Philips!), `千鸟智云`, `开心看Pro` / HapSee, `smaint`,
  `intellicared`. All share the same `aiseebling.com` payment
  endpoint. The Philips-branded build option is particularly
  notable given Session 6&rsquo;s finding that `public.dayunlinks.cn`
  CNAMEs through `birds-public.philipsiot.com` — Signify/Philips
  sits in the OEM&rsquo;s reseller roster, not just as accidental
  upstream infrastructure.
- **Blockers hit**: QCC (企查查) company-detail page behind Alibaba
  WAF with JS challenge — spec stop condition, documented. USPTO
  TESS, WIPO Brand DB, and CNIPA all JS-rendered SPAs that plain
  WebFetch cannot drive — tooling gap. GitHub code search gated
  behind sign-in. Wayback Machine API returns zero snapshots for
  either host (itself a finding). Apple App Store 404 on the V360
  Pro product URL — app appears de-listed from US store.
- **Artifacts produced**: one new doc
  [`18-aiseebling-investigation.md`](18-aiseebling-investigation.md),
  cross-reference updates to `03-cloud-topology.md` and `README.md`,
  this session-log entry. No scripts, no code, no captures.
- **Status at end**: primary goal achieved. Success criteria
  satisfied on legal-entity identification, country, and
  brand-cluster cross-reference (spec §6). MITM pipeline and
  router state untouched (the investigation was 100% off-cam).
  `aiseebling.com` is now fully demystified and can be treated as
  "Qianniao OEM shared payment endpoint" in all future references.

## Template for new session entries

```
## YYYY-MM-DD — Session N: <short title>

- **Goal of the session**: what we set out to do
- **Key finding 1**: short factual description + reference to the
  doc file it's documented in
- **Key finding 2**: ...
- **Blockers hit**: what didn't work and why
- **Artifacts produced**: new scripts, new docs, new pcaps
- **Status at end**: where the project is at the end of the session
```
