# Cloudbirds IP cam RE project

**Read `docs/README.md` first** — it&rsquo;s the index to a 19-file living
knowledge base covering the hardware, protocol, MITM attack chain,
tooling, and current state. Every session-relevant fact lives there.

**Update `docs/` in the same turn as any new finding.** New wire-format
details → `docs/04-wire-format-kalay.md`. New scripts → `docs/10-tooling.md`.
Session bullet → `docs/11-session-log.md`. Corrected claims → `docs/ERRATA.md`.
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
