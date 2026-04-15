# Errata

A running log of corrections to previous versions of these docs.
Append new entries to the top. Each entry should have a date, the
file(s) affected, what we used to say, what we say now, and why.

This document exists because the knowledge base is a living document
and confidence calibration is not cheap — sometimes we realize in
session N that something we wrote in session N-2 was overstated or
wrong. Tracking those corrections here prevents the same issue from
being re-introduced and gives future readers a sense of which parts
of the docs are battle-tested vs. recently rewritten.

## 2026-04-15 — Session 5 review pass

Self-review pass on the initial docs dump. No external reviewer yet.
All eight items below were identified by re-reading the docs with a
skeptical eye after writing them.

### ERR-001: "Cam accepts exactly 8 message types" was overstated

- **Files**: `00-overview.md`, `04-wire-format-kalay.md`,
  `06-state-machine.md`
- **Was**: "The cam&rsquo;s device-side state machine accepts exactly 8
  Kalay message types: `0x13, 0x30, 0x31, 0x3f, 0x52, 0x55, 0xdb,
  0xdc`."
- **Now**: "The `thread_recv_Proto` dispatcher has immediate-value
  compares for **at least** these 8 types. The function is ~9000
  instructions; there may be more types handled via jump tables,
  nested branches, or other receive threads."
- **Why**: we only grepped `cmp w0, #0xNN` in a 9000-instruction
  function. That&rsquo;s a lower bound, not a complete enumeration. The
  function could also use computed-goto dispatch, lookup tables, or
  register values other than `w0`.

### ERR-002: "Bodies are XOR-scrambled" was a guess, not a fact

- **Files**: `04-wire-format-kalay.md`, `07-defenses.md`
- **Was**: "DEV_LGN_CRC and REPORT_SESSION_RDY bodies are
  XOR-scrambled with a key derived from the vendor init key."
- **Now**: "Bodies are **obfuscated** by a function named
  `cs2p2p__P2P_Proprietary_Decrypt`. Whether it&rsquo;s pure XOR, a stream
  cipher, or a block cipher is **unverified**."
- **Why**: we never actually disassembled the obfuscation function.
  "XOR" was inferred from the function being called on both encrypt
  and decrypt paths (which is consistent with XOR symmetry but also
  with any symmetric cipher).

### ERR-003: "No device auth in CBS" was a miscall

- **Files**: `07-defenses.md`
- **Was**: "Device auth in CBS: ❌ no"
- **Now**: "Device auth in CBS: 🔶 unknown — request includes
  encrypted `relatInfo` and `did` blobs whose semantics we haven&rsquo;t
  reversed"
- **Why**: the `relatInfo` and `did` query parameters are 32-byte
  opaque blobs. We don&rsquo;t know what&rsquo;s inside, so we can&rsquo;t claim
  absence of auth. The opacity itself is a form of auth — the
  server presumably checks that the decrypted content matches what
  it expects.

### ERR-004: "Three receive threads" was wrong

- **Files**: `02-architecture.md`, `04-wire-format-kalay.md`
- **Was**: "The cam has three receive threads: `recv_Proto`,
  `recv_DRW`, `recv_LanSearch`"
- **Now**: "The cam has **four** receive threads: `recv_Proto`,
  `recv_DRW`, `recv_LanSearch`, `recv_FW_DCResponse`"
- **Why**: I grepped `nm -D` for `thread_recv_*` symbols and found a
  fourth one I&rsquo;d overlooked initially. The fourth thread is
  `cs2p2p_PPPP_thread_recv_FW_DCResponse` which handles something
  related to firewall destination checking in the relay-server flow.

### ERR-005: "The CBS typo is load-bearing" was half-verified

- **Files**: `00-overview.md`, `05-wire-format-cbs.md`
- **Was**: "A hand-rolled response with the correct spelling
  `{"message":"success","status":"200"}` would NOT satisfy the cam —
  we verified this experimentally."
- **Now**: "We verified that a `{"code":0,"msg":"success","data":null}`
  response does not satisfy the cam. We did NOT explicitly test
  `{"message":"success","status":"200"}` (corrected spelling only).
  So strictly, we don&rsquo;t know whether the typo itself is required,
  or whether it&rsquo;s the `status:"200"` field or something else in the
  exact byte sequence that matters."
- **Why**: I had two different non-working canned responses in my
  memory and mentally merged them. On re-reading, the actual
  untested case is the minimal "fix the typo" variant. That&rsquo;s now
  documented as a quick-answerable open question.

### ERR-006: "80-character hexadecimal-ish strings" was vague

- **Files**: `01-hardware.md`
- **Was**: "80-character hexadecimal-ish strings"
- **Now**: "Every character is a letter A-P, which is 16 possible
  values per char, i.e. each character encodes 4 bits (base-16
  using letters instead of digits `0-9a-f`). 80 characters × 4
  bits = 320 bits = 40 bytes of key material."
- **Why**: "hexadecimal-ish" was a hedge. On closer look, the keys
  are clearly using A-P as a 16-character alphabet for 4 bits each.
  That&rsquo;s a base-16 encoding with letters instead of digits, which
  is a specific and documentable choice — not a vague "looks
  hex-like".

### ERR-007: P2P_REQ "plaintext end-to-end" needed a disclaimer

- **Files**: `04-wire-format-kalay.md`
- **Was**: "Body has ZERO auth, nonce, or CRC. Plaintext end-to-end."
- **Now**: "Body plaintext on the client side (disassembled). Server-
  side semantics: the supernode may still validate fields against
  its own registry — we don&rsquo;t know."
- **Why**: "plaintext end-to-end" was meant to describe what the
  client side emits, but a careful reader would interpret it as
  "the server doesn&rsquo;t check anything". We never tested server-side
  validation of arbitrary P2P_REQ bodies, so we can&rsquo;t claim that.

### ERR-008: "0xF9 is fire and forget" needed context

- **Files**: `00-overview.md`, `04-wire-format-kalay.md`
- **Was**: "The supernode does NOT reply to `0xF9`. Confirmed by
  capture: our MITM proxy forwarded the packet to the real
  supernode and saw zero responses back. State update only."
- **Now**: "No reply observed in our captures. Note: this has only
  been tested in the 'no peer asking for this cam' state. In a
  different state (app actively looking for the cam) the supernode
  may send a follow-up. We have not exercised that path."
- **Why**: we observed silence in exactly one context. Generalizing
  to "never replies" is an unjustified extrapolation from a single
  observation window.

## Template for new entries

```markdown
### ERR-NNN: <short title>

- **Files**: which files the correction affected
- **Was**: previous claim (quoted or paraphrased)
- **Now**: corrected claim
- **Why**: what new information or realization caused the correction
```

_Last updated: 2026-04-15 — Session 5_
