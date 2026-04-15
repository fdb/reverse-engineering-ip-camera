_Last updated: 2026-04-15 — Session 5_

# 11 · Session log

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
- **Added `docs/15-debugging.md`** — debug cookbook covering common
  pipeline failure modes with symptoms, diagnosis commands, and
  fixes.
- **Added `docs/16-portability.md`** — what&rsquo;s reusable for other
  Kalay/CS2 cams vs. what&rsquo;s cam-specific.
- **Added `docs/ERRATA.md`** — tracks corrections and "we used to
  say X, now we say Y" updates.
- **Deleted `NEXT_STEPS.md`** at the project root — content was a
  near-duplicate of `docs/13-next-steps.md`, replaced with a stub
  pointing at the canonical copy.
- **Built and tested the site** with Playwright MCP. Screenshots
  verified: dark mode loads by default, toggle works, sidebar
  navigation works, code blocks are syntax-highlighted, typography
  is readable at the stated max content width.
- **Status at end**: docs/ is a clean, consistent, reviewed
  reference. Fakie-client approach is still the recommended next
  technical step — documented fully in `docs/13-next-steps.md`.

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
