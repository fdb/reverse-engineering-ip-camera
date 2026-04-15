# Cloudbirds IP Cam — Reverse Engineering Documentation

This directory is the **living knowledge base** for the project. Update it
whenever you learn something new. Nothing here is final; every file should
grow over time as the picture gets clearer.

## About this project

This is **security research on a device I own**, performed on **my own
network**, for **my own use**. The goal is to understand and control a
cheap commercial IP camera so that it doesn&rsquo;t send my Wi-Fi credentials
and video stream to a Chinese cloud I have no trust relationship with.

Things this project deliberately does **not** do:

- Redistribute vendor binaries (the APK, decompiled sources, and native
  `.so` files are all `.gitignore`'d — reproduce from the publicly
  available APK if you want them)
- Attack devices or cloud services owned by others
- Publish vendor secrets beyond what&rsquo;s needed to explain the attack
- Aid in mass exploitation of cameras in the wild

The code and documentation are shared so that other people investigating
the Qianniao / Kalay / CS2 PPPP OEM family — which ships in dozens of
brands — have a reference to work from. Everything here applies, with
varying degrees of adaptation, to Yoosee, Sricam, V380, YI, HapSee, and
many other app brands that share the same backend stack.

## How to build the static site

The `docs/*.md` files are plain markdown. Run:

```sh
python3 build_docs.py
```

from the project root, which writes `dist/*.html` — a VuePress-style
static site you can open in any browser. Every time you change anything
in `docs/`, rebuild.

## Who this is for

## Who this is for

Anyone (including a future you, or a new Claude session) picking up the
project from cold. The goal is that reading `docs/` in order should teach
the reader:

1. What we are trying to do and why
2. What the camera actually is (hardware + software stack)
3. Which cloud services it talks to and what it asks them
4. The exact wire format of every protocol it speaks (with provenance
   tags on every claim so you can tell observation from inference)
5. How our MITM interception works, end to end
6. Which scripts do what, and how to run them
7. Chronological history of what we&rsquo;ve learned so far
8. What we still don&rsquo;t know and the next things to try
9. How to debug when the pipeline misbehaves
10. What parts of this work transfer to other cams in the same OEM family

## Reading order

The files are numbered in a suggested reading order. You can skip around
freely — each file stands alone as a reference — but if you&rsquo;re new to
the project, read them in sequence.

| # | File | Topic |
|---|---|---|
| 00 | [overview.md](00-overview.md) | Goals, current state, headline results |
| 01 | [hardware.md](01-hardware.md) | Device identity, OEM family, DID encoding |
| 02 | [architecture.md](02-architecture.md) | Software stack, native libraries |
| 03 | [cloud-topology.md](03-cloud-topology.md) | Hostnames, IPs, cloud services |
| 04 | [wire-format-kalay.md](04-wire-format-kalay.md) | Kalay UDP protocol — every type we&rsquo;ve seen |
| 05 | [wire-format-cbs.md](05-wire-format-cbs.md) | CBS HTTPS control plane |
| 06 | [state-machine.md](06-state-machine.md) | Cam lifecycle from boot to idle |
| 07 | [defenses.md](07-defenses.md) | Vendor security features and what we break |
| 08 | [attack-chain.md](08-attack-chain.md) | Full interception architecture |
| 09 | [router-setup.md](09-router-setup.md) | UDM dnsmasq + iptables, ephemeral script-shaped setup |
| 10 | [mitm-mac-side.md](10-mitm-mac-side.md) | Starting, verifying, and stopping the Mac-side MITM proxies |
| 11 | [tooling.md](11-tooling.md) | Every script, flag, and log location |
| 12 | [session-log.md](12-session-log.md) | Chronological RE progress |
| 13 | [open-questions.md](13-open-questions.md) | Known unknowns, ordered by priority |
| 14 | [next-steps.md](14-next-steps.md) | Concrete actions to take next |
| 15 | [glossary.md](15-glossary.md) | Terms, acronyms, external references |
| 16 | [debugging.md](16-debugging.md) | Debug cookbook: symptom → diagnosis → fix |
| 17 | [portability.md](17-portability.md) | What transfers to other cams in the OEM family |
| — | [ERRATA.md](ERRATA.md) | Log of corrections and claim updates |

## How to update

- **Small corrections**: edit inline, commit with a one-liner message.
- **New findings**: append to the relevant file; if the finding invalidates
  an earlier claim, update that claim AND add a `session-log.md` entry with
  the date and what changed.
- **New protocols / message types**: add to `wire-format-kalay.md` as its
  own subsection with the full byte layout.
- **New scripts**: add an entry to `tooling.md` explaining purpose and usage.
- **Resolved unknowns**: move the item from `open-questions.md` to the
  appropriate reference doc, and leave a pointer in session-log.md.

## Conventions

- **Hex bytes** are lowercase with spaces: `f1 20 00 24`.
- **Port numbers** are decimal unless prefixed with `0x`.
- **IPs** are written verbatim; if we are referring to a "real" public
  address that&rsquo;s sensitive, sanitize it to `37.x.x.178` style.
- **Quoting actual wire data** use triple backticks with language `text`
  so it doesn&rsquo;t get mangled.
- **Demangled C++ names** — prefer the friendly name like
  `Proto_Send_P2PReq` over the full Itanium mangling.
- **Offsets into structs** use `[start..end)` half-open notation. Example:
  `[4..12)` means "bytes 4, 5, 6, 7, 8, 9, 10, 11" — 8 bytes total.
- **Provenance tags** — in reference docs, claims are tagged as
  _observed_, _disassembled_, _inferred_, or _guessed_. See
  [`04-wire-format-kalay.md`](04-wire-format-kalay.md) for the legend.

_Last updated: 2026-04-15 — Session 6_
