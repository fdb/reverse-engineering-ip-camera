# Cloudbirds IP cam RE project

**Read `docs/README.md` first** — it&rsquo;s the index to a 19-file living
knowledge base covering the hardware, protocol, MITM attack chain,
tooling, and current state. Every session-relevant fact lives there.

**Update `docs/` in the same turn as any new finding.** New wire-format
details → `docs/04-wire-format-kalay.md`. New scripts → `docs/11-tooling.md`.
Session bullet → `docs/12-session-log.md`. Corrected claims → `docs/ERRATA.md`.
After touching `docs/`, rebuild with `uv run build_docs.py` (the
GitHub Actions workflow at `.github/workflows/pages.yml` deploys
automatically on push to main).

## Network-switching rule

Never run tools or scripts that require Frederik&rsquo;s machine to be on a
different Wi-Fi network than it currently is — specifically, don&rsquo;t run
`probe.py`, `nmap`, or any other network probe against the camera&rsquo;s
`HAP-xxxxx` AP. Doing so would kick the laptop off its current internet
connection, which also kills my own network access for the rest of the
session.

Instead: hand Frederik the exact command to run himself, and wait for him
to paste the output back. Applies to anything that needs the cam&rsquo;s own
AP (UDP 8899 passive listen, UDP 18523 broadcast probe, PPPP on UDP 8000,
etc.). Read-only inspection of files, decompiled sources, and pcaps he
provides is fine.

## Router-state preflight rule

Before starting any cam session, confirm the MITM pipeline is actually in
the state you think it is. The UDM&rsquo;s Unifi controller can silently
regenerate dnsmasq config on any settings apply, which erases our overrides
while iptables counters remain from the last working session — a failure
mode that looks healthy under casual inspection. **`dig` is the source of
truth, not packet counters.** Run the `Phase 0 — Preflight` block from
[`docs/09-router-setup.md`](docs/09-router-setup.md) before anything else.
If `dig @192.168.5.1 user.hapseemate.cn` does not return `203.0.113.37`,
stop and re-run Phase 1 before touching anything else. Never trust "it was
working last session" — verify each session from scratch.
