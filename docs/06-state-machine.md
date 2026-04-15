# 06 · Camera state machine

The camera runs a deterministic state machine from boot. Every
transition (except the last, `P2P SESSION`) has been observed on the
wire in at least one pcap. This document describes each state and
what triggers transitions between them.

## State diagram

```
  ┌──────────┐
  │ POWER-ON │
  └────┬─────┘
       │  kernel boot, userspace init
       ▼
  ┌──────────┐
  │   DHCP   │  — gets LAN IP from router
  └────┬─────┘
       │  lease acquired
       ▼
  ┌──────────────────┐
  │ BEACON (8899)    │  — broadcasts iotcare_lan:<DID>:iotcare_lan
  │                  │    every ~500ms for ~30 seconds total
  └────┬─────────────┘
       │  beacon window expires
       ▼
  ┌──────────────────────┐
  │ CLOUD REGISTER       │  — NTP sync, DNS resolution,
  │                      │    HELLO/DEV_LGN to 3 supernodes,
  │                      │    CBS HTTPS call to hapseemate,
  │                      │    REPORT_SESSION_RDY fire-and-forget
  └────┬─────────────────┘
       │  all initial calls complete
       ▼
  ┌──────────────────────┐
  │ WAITING              │  — 30s DEV_LGN keepalive per session,
  │                      │    no active video
  │                      │    NO CBS retries (already satisfied)
  └────┬─────────────────┘
       │  peer wants to connect
       │  (supernode sends some notification type we haven't
       │   identified yet; cam's dispatch accepts it)
       ▼
  ┌──────────────────────┐
  │ P2P SESSION          │  — direct UDP data channel with peer,
  │                      │    DRW frames carry H.264 video,
  │                      │    ALIVE/ALIVE_ACK heartbeat
  └────┬─────────────────┘
       │  session closed or timed out
       ▼
  ┌──────────────────────┐
  │ WAITING              │  — back to steady state
  └──────────────────────┘
```

## State details

### POWER-ON

The cam reads power, boots its SoC, runs Linux kernel init, mounts
root filesystem, starts the Wi-Fi client, tries to join the configured
SSID. This takes 15-25 seconds typically.

If no Wi-Fi is configured, the cam drops back into **AP mode** —
broadcasts an `HAP-` SSID with no password and waits for a client to
present a QR code via its imager. See [`09-mitm-setup.md`](09-mitm-setup.md)
for how we use this for provisioning.

### DHCP

Standard DHCP client. Our UDM assigns the cam a LAN IP (usually
`192.168.5.37` but the last octet can vary with lease rotation). The
cam sends exactly 2 DHCP frames (Request + Ack).

### BEACON (UDP/8899)

**Important: this is a one-shot announcement phase, not a persistent
service.** The cam broadcasts an ASCII beacon to
`<subnet>.255:8899` for the first ~30 seconds after joining Wi-Fi,
then the responder thread **stops permanently** until next reboot.

Beacon format (42 bytes of ASCII):

```
iotcare_lan:CFEOA-417739-RTFUU:iotcare_lan
```

Source port rotates per-beacon (not a fixed ephemeral), which
indicates the cam opens a new UDP socket for each beacon blast and
closes it. Cadence is ~500ms between beacons, so the window contains
about 60 beacons total.

**Implication for the app**: the Android app&rsquo;s `SearchDeviceByUDP`
class binds UDP/8899 with an 8-second timeout and waits for a beacon
to arrive. If the app is slow to bind (more than 30 seconds after the
cam joins Wi-Fi), it misses the window and has to use the
multicast/LAN_SEARCH discovery path instead.

**Implication for us**: if we want to catch the beacon, we need to
have `probe.py listen` running BEFORE the cam joins Wi-Fi. Otherwise
it&rsquo;s too late.

### CLOUD REGISTER

This is the busy phase where the cam rapidly runs through:

1. **NTP sync** — 5 parallel NTP requests (one per `ntp_dyzl_ipc_address_N`
   wrapper). The cam is satisfied when any one replies.
2. **DNS resolution** — `p2p5.cloudbirds.cn`, `p2p6.cloudbirds.cn`,
   `user.hapseemate.cn`, `alive.hapsee.cn`.
3. **Kalay HELLO → HELLO_ACK** to all three supernode IPs (2 via DNS,
   1 hardcoded). Three parallel sessions opened.
4. **Kalay DEV_LGN_CRC → DEV_LGN_ACK** on all three sessions. At this
   point the cam believes it is "registered".
5. **CBS HTTPS** call to `/preadd/didBindUserId` on hapseemate. Must
   complete successfully or the cam enters a retry loop.
6. **REPORT_SESSION_RDY (0xF9)** fire-and-forget on all three
   sessions. No reply expected; the cam updates its internal state
   and proceeds.

The whole phase takes about 5-8 seconds on a healthy network with our
MITM in the middle. Without the MITM, add 200-500 ms for the AWS ELB
round-trip to hapseemate.

### WAITING

The steady state the cam spends most of its lifetime in. Every
**30 seconds**, it sends a DEV_LGN_CRC on each of its registered
sessions and receives a DEV_LGN_ACK back. That&rsquo;s it. No CBS traffic,
no new message types, nothing else.

We have observed the cam stay in WAITING for 20+ minutes without
issue. The steady-state cadence never varies.

**This is the state the cam is in right now** (as of the most recent
capture). All our injection attempts target this state, and the cam
silently ignores them.

### P2P SESSION (theoretical — not yet observed)

The state we want to get the cam INTO. Once triggered, the cam:

1. Receives some (as yet unidentified) "peer connect request" message
   from the supernode — probably a Kalay-specific variant like
   `SSDPunchTo` or `SSDP2PReq`.
2. Opens a NEW UDP session to the peer&rsquo;s endpoint carried in that
   message.
3. Exchanges `PunchPkt (0x41)` messages with the peer to establish the
   NAT path.
4. Starts sending `DRW (0xD0)` frames carrying H.264 video / audio.
5. Responds to `ALIVE (0xE0)` with `ALIVE_ACK (0xE1)` as keepalive.
6. On session termination, either an explicit close or a timeout,
   returns to WAITING.

We have seen exactly zero packets of this state.

## Session rollover within WAITING

One subtlety: the cam periodically rebinds its per-supernode sockets
to **new ephemeral source ports**. We&rsquo;ve seen a cam go through ports
`10107 → 1094 → 1095 → 12301 → 1097 → 16106` over a few minutes of
steady-state operation. Each rollover creates a "new session" from
our MITM&rsquo;s perspective.

The cam maintains both OLD and NEW sessions in parallel — the
rollover doesn&rsquo;t replace, it adds. This is part of the Kalay NAT
hole-punching strategy: by varying source ports, the cam can build up
multiple NAT mappings simultaneously so that any peer with a matching
path can punch through.

**This means**: when you fire a SIGUSR1 injection, target the MOST
RECENT session ports, not an old captured set. Session ports from
10 minutes ago may already have been closed or recycled.

## Reboot behavior

When the cam reboots:

- All session state is lost. Re-registers from scratch.
- The beacon window fires again (fresh 30s).
- New ephemeral source ports (different from last boot).
- NEW per-session nonces in DEV_LGN_CRC bodies (the first ~22 bytes
  stay constant, the remaining ~22 bytes are new).
- Same DEV_LGN_ACK constant (`a02aaac73b7755c9`) — confirmed
  deterministic across reboots.
- Same LAN_RESPONSE body — deterministic based on DID alone.

Reboots are easily triggered by pulling power. No software reset
command has been observed.

## Cam failure modes

### "Can&rsquo;t reach cloud, infinite retry"

If the CBS HTTPS call fails (fake server returns the wrong envelope,
or the TCP connection is RST&rsquo;d), the cam retries at ~2.5-second
intervals. This is the hot-retry mode we saw before we&rsquo;d built the
MITM. It eats battery but is otherwise benign. Fix: make sure
`/preadd/didBindUserId` returns the canonical
`{"mssage":"success","status":"200"}`.

### "Wrong IP in HELLO_ACK"

If our fake HELLO_ACK contains an RFC1918 IP, the cam silently
rejects the response and keeps retrying HELLO. Fix: echo any
non-RFC1918 IP, e.g. TEST-NET-3 `203.0.113.37` as our code does. See
the `FAKE_PUBLIC_IP` constant in `fake_supernode.py`.

_Last updated: 2026-04-15 — Session 5_

### "Silent drop" (current blocker)

Any injected packet the cam doesn&rsquo;t recognize is silently dropped.
There&rsquo;s no error feedback, no log line, no increased retry rate — the
cam just continues its 30-second keepalive. That makes it hard to
debug: you send a packet and wait, and if nothing happens you have to
assume it was dropped. This is why we pivoted to the "fake client via
real supernode" approach in [`13-next-steps.md`](13-next-steps.md).
