# 00 · Overview

## Project purpose

Frederik owns a very cheap Chinese IP camera branded "Cloudbirds" (vendor:
Dayunlinks). The intended user experience is: install the vendor Android app
"V360 Pro", register an account, let the app scan a QR code to provision
the camera, then view live video via the cloud. **Everything goes through
Chinese servers.** The app, the cam&rsquo;s firmware, and the cloud stack
all trust the Cloudbirds backend with your Wi-Fi password, your video
stream, and your device ID.

The goal of this project is to **use the camera without the vendor app and
without letting it phone home.** Ideally the final state is:

- Camera runs on an isolated VLAN with no internet access
- Wi-Fi provisioning happens without the vendor app (we generate the QR
  code ourselves)
- Live video is pulled directly from the camera over the LAN with a
  script we control
- No Chinese server ever learns the camera&rsquo;s existence

Along the way we also want to **understand the protocol**. Documenting it
means this work is useful for anyone with a similar cam (and there are
*many* similar cams — the Qianniao OEM stack ships in dozens of brands).

## The camera under test

| Field | Value |
|---|---|
| Brand | Cloudbirds |
| Vendor | Dayunlinks (Chinese OEM) |
| Model | sold as "V360 Pro" compatible |
| Android app | V360 Pro 6.5.0 (APK size ~209 MB) |
| DID | `CFEOA-417739-RTFUU` |
| App package | `com.dayunlinks.cloudbirds` |
| OEM namespace | `com.qianniao.*` |
| Native P2P | Throughtek Kalay (formerly CS2 Network PPPP) |
| Native lib | `libPPCS_API.so` + `libCBSClient.so` |

## Network topology

```
internet ──┐                               ┌── real Kalay supernodes (Aliyun)
           │                               │   real hapseemate.cn cloud (AWS ELB)
           │                               │
  +--------┴--------+                      │
  │  UDM Dream      │                      │
  │  Router         │                      │
  │  192.168.5.1    │                      │
  │  - dnsmasq      │                      │
  │    override     │                      │
  │  - iptables     │                      │
  │    DNAT         │                      │
  +--------┬--------+                      │
           │                               │
      ─────┴─────── cam-isolated VLAN ─────┘
       │         │
       │         │
  ┌────┴────┐ ┌──┴──────────────┐
  │ Mac     │ │ Cam              │
  │ .5.233  │ │ .5.37            │
  │         │ │ CFEOA-417739-    │
  │ MITM    │ │ RTFUU            │
  │ proxies │ │ Kalay firmware   │
  │ wifiqr  │ │                  │
  │ fake-   │ │ all outbound     │
  │ client  │ │ DNAT'd → Mac     │
  │ (future)│ │                  │
  └─────────┘ └──────────────────┘
```

## Current state (2026-04-15)

### ✅ Solved

- **Provisioning without the app**: generate the Wi-Fi QR code ourselves
  via `wifiqr.py`. The cam&rsquo;s imager reads the QR and joins our
  network. No vendor cloud round-trip required for this step.
- **Network interception**: full MITM pipeline on the Mac. Every packet
  the cam sends — UDP Kalay traffic AND TCP HTTPS — is intercepted,
  decrypted (in the TLS case), forwarded to the real backend, and
  logged in cleartext.
- **Protocol decode**: the Kalay UDP 4-byte header, the CS2 PPPP family
  of message types, the CBS HTTPS API envelope, and the camera&rsquo;s state
  machine are all documented at byte resolution.
- **DNS rebinding bypass**: the camera has one meaningful defense — a
  filter that rejects RFC1918 IPs for cloud hostnames. We bypass it by
  pointing DNS at a non-RFC1918 sink (`9.9.9.9`) and DNAT-rewriting the
  traffic at the router.
- **Response schema capture**: the real cloud&rsquo;s response to the
  `/preadd/didBindUserId` CBS endpoint was captured in cleartext, typo
  and all (`{"mssage":"success","status":"200"}`). We would never have
  guessed this from static analysis.

### ❌ Blocked (current session checkpoint)

- **Triggering a data session on demand**: the cam is in "fully
  registered, waiting for peer" state. To make it open a data channel
  and start streaming video, we need to simulate an inbound connection
  request from the app side. We have the P2P_REQ wire format fully
  decoded but injecting it directly does not work, because the cam&rsquo;s
  device-role dispatcher does not parse type `0x20`.
- **Video data channel parsing**: once the cam starts sending DRW
  frames (`0xD0`) we&rsquo;ll need to understand the framing layer inside
  DRW bodies. Untouched so far.
- **XOR obfuscation reversing**: the 44-byte `DEV_LGN_CRC` body and the
  84-byte `REPORT_SESSION_RDY` body are XOR-scrambled with a per-vendor
  init key. We can replay them but not read or modify. Not urgent if we
  go the "fake client" route — we just let the real library do the
  encoding.

### 🔜 Next move

**Run a minimal fake client against the real supernode** (see
[`14-next-steps.md`](14-next-steps.md)). The idea: instead of crafting
fake packets to inject into the cam&rsquo;s session, we ask the real
supernode to do the work for us. We impersonate an "app" that wants to
connect to the cam, send a legitimate `P2P_REQ` to the supernode, and
let it send the correct (unknown-format) notification to the cam. Our
MITM proxy will observe the notification in cleartext — that one
observation unlocks the entire supernode→cam protocol.

## Headline protocol facts

- Everything the camera cares about is **UDP** _(observed)_. Zero TCP
  ports open (verified with a 107-port `nc -z` sweep).
- The cam uses **three parallel Kalay supernodes** simultaneously for
  HA _(observed)_. One supernode IP is hardcoded in firmware; the other
  two are DNS-resolved.
- The `thread_recv_Proto` dispatcher has immediate-value compares for
  **at least** 8 Kalay message types: `0x13, 0x30, 0x31, 0x3f, 0x52,
  0x55, 0xdb, 0xdc` _(disassembled)_. The function is ~9000 instructions
  and we have not fully traced it — there may be more types handled via
  jump tables or nested branches, and other receive threads
  (`thread_recv_DRW`, `thread_recv_FW_DCResponse`,
  `thread_recv_LanSearch`) handle different type sets on different
  sockets. Injection attempts with `0x20 P2P_REQ` and `0x40 PUNCH_TO`
  were silently dropped, which is consistent with those types not
  being in the device-role path.
- The CBS HTTPS API uses a **hand-written Java backend** with a typo
  (`"mssage"` instead of `"message"`) in the observed response body
  _(observed)_. We verified that a generic `{"code":0,...}` response
  does not satisfy the cam; we have **not** explicitly tested a
  corrected `{"message":"success","status":"200"}`, so whether the typo
  itself is load-bearing is technically unverified.
- The cam is **not TLS cert-pinning** _(observed)_. Our self-signed
  `*.hapseemate.cn` certificate is accepted. This is the single biggest
  security gap in the vendor stack.

## Where everything lives

For the canonical inventory of scripts, flags, and log locations, see
[`11-tooling.md`](11-tooling.md). In broad strokes:

- **Scripts** — `wifiqr.py`, `probe.py`, `mitm_*.py`, `fake_*.py`,
  `inject_p2p_req.py`, `build_docs.py`
- **Static explainers** — `explainer.html`, `explainer-deep.html`
- **Decompiled code** — `extracted/` and `decompiled/` (gitignored,
  regenerate via `unzip` + `jadx`)
- **Ad-hoc RE notes** — `Proto_Write_PunchTo.md`
- **Ghidra integration** — `ghidra_scripts/`
- **This documentation set** — `docs/`
- **Generated site** — `dist/` (gitignored; rebuild via
  `python3 build_docs.py`)

_Last updated: 2026-04-15 — Session 6_
