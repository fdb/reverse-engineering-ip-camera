# Cloudbirds IP cam reverse-engineering project

## docs/ is a living document — keep it in sync

The `docs/` folder is the canonical knowledge base for this project.
Whenever you learn something new, discover a blocker, change an approach,
or ship a new script, update the relevant doc file in the same turn.

- **New findings** → add to the right reference doc (usually
  `docs/04-wire-format-kalay.md` or `docs/05-wire-format-cbs.md`), and
  append a dated entry to `docs/11-session-log.md`.
- **New scripts or behaviour changes** → update `docs/10-tooling.md`.
- **Resolved unknowns** → move the item out of `docs/12-open-questions.md`
  into the appropriate reference doc, leaving a short pointer.
- **New next steps** → add to `docs/13-next-steps.md`.

Never let a session end with new knowledge only in memory or in chat —
always capture it in `docs/` before wrapping up, because the person who
reads this next (including a future Claude) will only see `docs/`, not
the chat history. After touching `docs/`, regenerate the static site
with `python3 build_docs.py` so `dist/` stays in sync.

## Network-switching rule

Never run tools or scripts that require Frederik's machine to be on a
different Wi-Fi network than it currently is — specifically, don't run
`probe.py`, `nmap`, or any other network probe against the camera's
`HAP-xxxxx` AP. Doing so would kick the laptop off its current internet
connection, which also kills my own network access for the rest of the
session.

Instead: hand Frederik the exact command to run himself, and wait for him
to paste the output back.

This applies to anything that needs the camera's own AP (UDP 8899 passive
listen, UDP 18523 broadcast probe, PPPP on UDP 8000, etc.). Read-only
inspection of files, decompiled sources, and pcaps he provides is fine.
