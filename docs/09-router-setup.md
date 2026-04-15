# 09 · Router setup

Router-side (UDM Dream Router) configuration for the MITM pipeline.
This file is a **script-shaped cookbook**: every phase is a block of
commands you can paste top-to-bottom into an SSH session on the UDM
(or, for Phase 0, into a shell on the Mac). It deliberately carries
no persistence plumbing — see "Ephemeral contract" below.

The upstream architectural picture (why these rules exist, how
conntrack glues everything together, what the packet trace looks
like) is in [`08-attack-chain.md`](08-attack-chain.md). The Mac-side
proxy start/stop/verify steps live in
[`10-mitm-mac-side.md`](10-mitm-mac-side.md) — run those **after**
Phase 1 here.

## Prerequisites

- **Hardware**: a UDM-series Unifi router. Tested on the UDM Dream
  Router; UDM, UDM Pro, and UDM-SE should behave identically. Other
  Linux-based routers work on the same principles but the dnsmasq
  override directory and iptables invocation path will differ.
- **SSH access**: `ssh root@192.168.5.1` to the UDM. Credentials are
  configured in Unifi Network → Settings → System → Device
  Authentication.
- **Mac on the LAN**: `192.168.5.233` in the examples below. This is
  where the proxies from [`10-mitm-mac-side.md`](10-mitm-mac-side.md)
  bind.
- **Cam already provisioned**: `192.168.5.37` in the examples. If the
  cam isn&rsquo;t on the network yet, use `wifiqr.py` (see
  [`11-tooling.md`](11-tooling.md)) to generate an offline provisioning
  QR.

## Sink IP rationale

We sinkhole every cam-cloud hostname to **`203.0.113.37`**. This is
TEST-NET-3 from RFC 5737 — the documentation prefix, conventionally
unrouted on the public internet. Any DNAT rule that fails to match
(wrong source IP, rule deleted, wrong table) simply drops the packet
into a black hole instead of leaking it.

The earlier docs used `9.9.9.9`, which is real Quad9 public DNS. A
DNAT miss with that sink would leak cam traffic to a real third party
that keeps logs — and worse, any *other* client on the same VLAN
that happens to use Quad9 for DoH would also be redirected into our
MITM. TEST-NET-3 has neither problem.

## Ephemeral contract

**Every rule and file in this doc survives only until the next Unifi
GUI settings-apply OR UDM reboot**, whichever comes first. When that
happens, the Unifi controller rewrites `/run/dnsmasq.dns.conf.d/` and
flushes custom iptables rules, and your pipeline silently breaks.

This is a **feature**, not a bug. The intended workflow is:

1. At the start of each session, run Phase 0 (Preflight) to see what
   state the router is in.
2. If the pipeline is gone, re-run Phase 1 (Apply). It takes ~10
   seconds and the exact commands live here, checked into the repo.
3. When the session ends, run Phase 4 (Teardown) — or just leave the
   rules to expire on their own.

The upside: the router&rsquo;s persistent config stays pristine, nothing
survives a reboot to surprise you later, and the canonical definition
of "the MITM setup" is this file rather than some handwritten shell
script rotting in `/data/on_boot.d/`.

The downside: **do not touch the Unifi GUI mid-session**. If you hit
"Apply" on anything — even an unrelated setting — the dnsmasq
override disappears and the pipeline breaks until you re-run Phase 1.

Every rule we add carries `-m comment --comment "camre"` so teardown
can find exactly our rules without touching Unifi&rsquo;s native ones.

---

## Phase 0 — Preflight (read-only)

Run from the Mac. This tells you whether the pipeline is up, down,
or in the dangerous "half-up" state where iptables counters look
healthy but dnsmasq has forgotten its overrides.

```sh
# Mac side: dig is the source of truth. Expect 203.0.113.37 for all three.
for h in p2p5.cloudbirds.cn user.hapseemate.cn public.dayunlinks.cn; do
  printf "%-30s → %s\n" "$h" "$(dig @192.168.5.1 +short "$h" | head -1)"
done

# UDM side: iptables rule table and override file presence.
ssh root@192.168.5.1 'iptables -t nat -L PREROUTING -v -n --line-numbers'
ssh root@192.168.5.1 'ls -la /run/dnsmasq.dns.conf.d/'
```

**Interpretation:**

- If `dig` returns `203.0.113.37` for every hostname **and**
  `iptables` shows the `camre`-commented rules **and**
  `cam-override.conf` exists — pipeline is healthy, skip to
  [`10-mitm-mac-side.md`](10-mitm-mac-side.md).
- If `dig` returns anything else (the real Chinese cloud IP, the
  real Philips IoT IP, `NXDOMAIN`, etc.) — the dnsmasq override is
  gone. Run Phase 1.
- If `dig` looks fine but iptables counters are zero — the cam hasn&rsquo;t
  emitted traffic recently, which is expected during idle. Not a
  failure.
- **Dangerous case**: `dig` returns real cloud IPs **but** iptables
  counters are nonzero and high. Those counters are stale — frozen
  from the last working session. The pipeline is broken and has been
  since the last Unifi settings-apply. Re-run Phase 1. This exact
  failure mode bit us in Session 6 and is why `dig` is the source of
  truth, not packet counters.

---

## Phase 1 — Apply MITM layer

Run on the UDM via `ssh root@192.168.5.1`. Pasteable top-to-bottom.

```sh
SINK=203.0.113.37
OVERRIDE=/run/dnsmasq.dns.conf.d/cam-override.conf

cat > "$OVERRIDE" <<EOF
# camre: cam cloud sinkhole
address=/cloudbirds.cn/$SINK
address=/hapseemate.cn/$SINK
address=/hapsee.cn/$SINK
address=/dayunlinks.cn/$SINK
address=/philipsiot.com/$SINK
EOF
killall -HUP dnsmasq

CAM=192.168.5.37
MAC=192.168.5.233
MARKER="camre"

# TCP 443 → Mac:8443 (TLS MITM)
iptables -t nat -I PREROUTING 2 -s $CAM -p tcp -d $SINK --dport 443 \
  -j DNAT --to-destination $MAC:8443 -m comment --comment "$MARKER"
iptables -t nat -I PREROUTING 2 -s $CAM -p tcp -d 123.56.74.245 --dport 443 \
  -j DNAT --to-destination $MAC:8443 -m comment --comment "$MARKER"

# Any-proto catch-all (UDP Kalay on :32100, etc.)
iptables -t nat -A PREROUTING -s $CAM -d $SINK \
  -j DNAT --to-destination $MAC -m comment --comment "$MARKER"
iptables -t nat -A PREROUTING -s $CAM -d 123.56.74.245 \
  -j DNAT --to-destination $MAC -m comment --comment "$MARKER"

# Return-path source rewrite
iptables -t nat -A POSTROUTING -s $CAM -d $MAC -j MASQUERADE \
  -m comment --comment "$MARKER"
```

Notes:

- **`/run/dnsmasq.dns.conf.d/`** is the correct path on current UDM
  firmware. Earlier revisions of this doc pointed at
  `/run/dnsmasq.conf.d/`, which does not exist on modern UDM builds
  — edits there silently had no effect and the pipeline appeared to
  work only because of stale state. See [`ERRATA.md`](ERRATA.md).
- **TCP rules are inserted at position 2**, before the any-proto
  catch-alls. If you `-A` them to the end, the catch-all fires first
  for TCP traffic (it has no `-p` filter) and the cam&rsquo;s TLS packets
  land on Mac:443 instead of Mac:8443.
- **`123.56.74.245`** is the hardcoded fallback IP the cam dials if
  DNS resolution fails, so we DNAT it even though nothing resolves
  to it any more. Belt and braces.

Now jump to [`10-mitm-mac-side.md`](10-mitm-mac-side.md) and start
the Mac-side proxies.

---

## Phase 2 — Verify

Two independent checks. Run both every time.

### Check A — `dig` as source of truth (Mac side)

```sh
for h in p2p5.cloudbirds.cn user.hapseemate.cn public.dayunlinks.cn; do
  printf "%-30s → %s\n" "$h" "$(dig @192.168.5.1 +short "$h" | head -1)"
done
```

Every line must end in `203.0.113.37`. If any line shows a real
public IP, Phase 1&rsquo;s dnsmasq write did not take effect — most
likely because the Unifi GUI regenerated
`/run/dnsmasq.dns.conf.d/` in between. Re-run Phase 1.

**Why `dig` and not iptables counters?** Because the two can
disagree. In Session 6 we hit a case where iptables counters showed
thousands of packets on the DNAT rules (suggesting success) but
`dig` returned the real Chinese cloud IP (proving the overrides
were gone). The counters were stale from the previous session and
the cam was dialling the real cloud directly — no DNAT rule
matched, no counter incremented for the new traffic, and the old
numbers looked healthy. `dig` catches this; counters do not.

### Check B — iptables comment marker (UDM side)

```sh
ssh root@192.168.5.1 "iptables-save | grep -- '--comment \"camre\"'"
```

Expect five lines: two TCP DNATs (sink and fallback IP), two
any-proto DNATs, and one POSTROUTING MASQUERADE. If you see fewer,
Phase 1&rsquo;s iptables block partially failed — re-run it (the
rules are idempotent only via the `-I`/`-A` pattern shown; re-running
will add duplicates, so tear down first with Phase 4 if in doubt).

Optional counter inspection (counters are a *signal*, not
*evidence*):

```sh
ssh root@192.168.5.1 'iptables -t nat -L PREROUTING -v -n --line-numbers'
```

Counters incrementing after a cam power-cycle is a good sign.
Counters stuck at zero *during* cam activity means the rules
aren&rsquo;t matching — wrong source IP, wrong chain, wrong table, or
a UBIOS hook consuming packets earlier in the chain. See
[`16-debugging.md`](16-debugging.md).

---

## Phase 3 — Block br4 WAN egress (OPTIONAL)

> ⚠️ **DO NOT RUN during the OTA-discovery session or any session that
> needs the cam to reach the real cloud.** This phase enforces an
> airgap: after it runs, the cam can only talk to the Mac via the
> MITM pipeline and to nothing else on the WAN. It&rsquo;s reserved for
> the future "permanent airgap" mode, not for interception work.

```sh
# br4 = cam-isolated VLAN bridge, eth4 = WAN interface. Adjust if
# your UDM uses different interface names.
iptables -I FORWARD 1 -i br4 -o eth4 -p udp --dport 123 -j ACCEPT \
  -m comment --comment "camre-allow-ntp"
iptables -I FORWARD 2 -i br4 -o eth4 -j DROP \
  -m comment --comment "camre-block-wan"
```

Rationale: the cam needs NTP at boot (to validate TLS cert expiry
and stamp logs) but nothing else. The first rule allows UDP/123,
the second drops everything else leaving br4 towards the WAN. DNAT
traffic going to the Mac on br0 is unaffected because it never
crosses br4→eth4.

Phase 4 will clean these up because they also carry a `camre-`
comment prefix.

---

## Phase 4 — Teardown

Reverse everything Phases 1 and 3 did. The loop below finds all
`camre`-commented rules across `nat` and `filter` tables, flips
`-A`/`-I` to `-D`, and deletes them. It never touches non-`camre`
rules.

```sh
# UDM side:
for t in nat filter; do
  iptables-save -t "$t" \
    | grep -- '--comment "camre' \
    | sed 's/^-A /-D /' \
    | while IFS= read -r rule; do
        # shellcheck disable=SC2086
        iptables -t "$t" $rule 2>/dev/null
      done
done

rm -f /run/dnsmasq.dns.conf.d/cam-override.conf
killall -HUP dnsmasq
```

Verify nothing remains:

```sh
iptables-save | grep -- '--comment "camre' || echo "clean"
ls -la /run/dnsmasq.dns.conf.d/cam-override.conf 2>&1 | grep -q 'No such' \
  && echo "override removed"
```

Mac-side proxy teardown is in
[`10-mitm-mac-side.md`](10-mitm-mac-side.md).

---

## Troubleshooting

See [`16-debugging.md`](16-debugging.md) for the full symptom →
diagnosis → fix cookbook. Common router-side issues:

- **`dig` returns real cloud IP after Phase 1** — Unifi GUI
  settings-apply happened between Phase 1 and now. Re-run Phase 1.
- **Rule counters stay at zero during cam activity** — cam may have
  been re-DHCP&rsquo;d onto a different IP. Check with
  `ip neigh show | grep ether` on the UDM and update `CAM=` in
  Phase 1.
- **TCP traffic lands on Mac:443 instead of Mac:8443** — TCP DNAT
  rules ended up after the any-proto catch-alls. Tear down, re-apply
  Phase 1, and confirm the `-I PREROUTING 2` position with
  `iptables -t nat -L PREROUTING -v -n --line-numbers`.

The failure-modes section of [`08-attack-chain.md`](08-attack-chain.md)
covers the underlying theory.

_Last updated: 2026-04-15 — Session 6_
