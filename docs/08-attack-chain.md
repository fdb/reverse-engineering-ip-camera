# 08 · Full attack chain

How all the pieces fit together to redirect every byte the camera
produces into our Mac in cleartext. This is the architecture diagram
plus a packet-by-packet trace of what happens when the cam makes a
cloud request.

## Diagram

```
                          ┌──────────────────────────────┐
                          │   Camera 192.168.5.37        │
                          │   DID CFEOA-417739-RTFUU     │
                          │   Kalay firmware             │
                          │                              │
                          │   sends to 9.9.9.9:443 TLS   │
                          │   and 9.9.9.9:32100 UDP      │
                          └───────────────┬──────────────┘
                                          │  on the Cam-Isolated VLAN
                                          │
                                          ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │   UDM Dream Router 192.168.5.1                                         │
  │                                                                        │
  │   dnsmasq:                                                             │
  │     address=/cloudbirds.cn/9.9.9.9                                     │
  │     address=/hapseemate.cn/9.9.9.9                                     │
  │     address=/hapsee.cn/9.9.9.9                                         │
  │                                                                        │
  │   iptables PREROUTING nat:                                             │
  │     1. UBIOS_PREROUTING_JUMP                                           │
  │     2. -s cam -p tcp -d 9.9.9.9     --dport 443 DNAT → Mac:8443        │
  │     3. -s cam -p tcp -d 123.56.74.245 --dport 443 DNAT → Mac:8443      │
  │     4. -s cam -d 9.9.9.9         DNAT → Mac (any-proto, any-port)      │
  │     5. -s cam -d 123.56.74.245   DNAT → Mac (any-proto, any-port)      │
  │                                                                        │
  │   iptables POSTROUTING nat:                                            │
  │     MASQUERADE -s cam -d 192.168.5.233  (custom rule)                  │
  │     UBIOS default MASQ also fires for any non-WAN-sourced traffic      │
  │                                                                        │
  │   kernel conntrack tracks cam ↔ Mac mappings                           │
  │     so reverse packets get src rewritten back to 9.9.9.9:32100         │
  └────────────────────────────────────┬───────────────────────────────────┘
                                       │
                                       ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │   Mac 192.168.5.233                                                    │
  │                                                                        │
  │   mitm_cbs_proxy.py  — bind TCP/8443                                   │
  │     terminates TLS with self-signed *.hapseemate.cn cert               │
  │     opens outbound TLS to real user.hapseemate.cn (190.92.254.71)      │
  │     forwards request cleartext, logs, forwards response cleartext      │
  │                                                                        │
  │   mitm_supernode_proxy.py — bind UDP/32100                             │
  │     per-cam-session upstream socket (round-robin 3 real supernodes)    │
  │     forwards every packet verbatim, logs with Kalay decode             │
  │     SIGUSR1 hook: reads /tmp/cam-listen/inject.json and sends crafted  │
  │       packets from the same :32100 socket                              │
  │                                                                        │
  │   Mac's own outbound uses the Mac's normal default route via UDM WAN,│
  │   so traffic from the MITMs to the real cloud goes out through         │
  │   Frederik's real home IP 37.37.51.178                                │
  └────────────────────────────────────────────────────────────────────────┘
```

## Packet-by-packet trace — TCP case

1. **Cam DNS query**: `A? user.hapseemate.cn` → DNS on UDM
2. **UDM dnsmasq**: returns `9.9.9.9` (from override config)
3. **Cam TCP SYN**: `src=192.168.5.37:X dst=9.9.9.9:443`
4. **UDM PREROUTING rule #2 matches**: DNAT rewrite →
   `dst=192.168.5.233:8443`
5. **UDM POSTROUTING MASQUERADE fires**: `src` rewritten to
   `192.168.5.1:Y` (the UDM&rsquo;s LAN-side IP + a port the UDM picks)
6. **UDM conntrack entry created**:
   ```
   Original: 192.168.5.37:X → 9.9.9.9:443
   Reply   : 192.168.5.233:8443 → 192.168.5.1:Y
   ```
7. **Packet leaves UDM via br0** → arrives at Mac
8. **Mac kernel** sees `src=192.168.5.1:Y dst=192.168.5.233:8443`,
   delivers to socket bound on 8443 → `mitm_cbs_proxy.py`
9. **mitm_cbs_proxy** accepts the TCP connection:
   - Peeks at the first bytes to read the TLS ClientHello SNI
   - Terminates TLS using the self-signed `*.hapseemate.cn` cert
   - Opens an outbound TCP connection to `190.92.254.71:443` using
     Mac&rsquo;s normal default route
   - Upgrades the outbound to TLS using SNI from step 9a
   - Reads the cam&rsquo;s HTTP request in cleartext
   - Forwards it over the upstream TLS session
   - Reads the real cloud&rsquo;s response
   - Logs both
   - Forwards the response back down the cam-side TLS session
10. **Mac sends reply**: `src=192.168.5.233:8443 dst=192.168.5.1:Y`
11. **UDM conntrack reverses the NAT**: the reply matches the earlier
    entry, so `src` becomes `9.9.9.9:443` and `dst` becomes
    `192.168.5.37:X`
12. **Cam receives the reply** with headers that look (to its TCP
    stack) like they came from 9.9.9.9:443. The cam&rsquo;s session state
    accepts it.

**Latency added**: approximately 20-30 ms for the Mac-side forwarding,
plus the real AWS round-trip (~400 ms from Europe). The cam is
tolerant of this.

## Packet-by-packet trace — UDP case

Same principle, simpler:

1. **Cam sends**: `src=192.168.5.37:Xxxxx dst=9.9.9.9:32100` (Kalay
   HELLO)
2. **UDM PREROUTING rule #4 matches**: DNAT → `dst=192.168.5.233:32100`
3. **UDM POSTROUTING MASQUERADE**: `src` rewritten to
   `192.168.5.1:Yyyyy` (port-preserved where possible)
4. **UDM conntrack** creates bidirectional mapping
5. **Mac delivers** to `mitm_supernode_proxy.py` bound on `:32100`
6. **Proxy** looks up the cam session `(192.168.5.1, Yyyyy)` in its
   session table. If new, creates a new per-session upstream socket
   and starts a reader thread. Picks one of the three real supernodes
   round-robin.
7. **Proxy sends** the packet from its upstream socket (some ephemeral
   port on the Mac) to the real supernode `8.134.120.63:32100`
8. **Proxy&rsquo;s upstream reader thread** receives the reply from the real
   supernode
9. **Proxy forwards** the reply via the main `:32100` socket to the
   cam&rsquo;s MASQUERADE&rsquo;d session address `192.168.5.1:Yyyyy`
10. **UDM conntrack reverses**: the reply matches, rewrites src back
    to `9.9.9.9:32100` and dst back to `192.168.5.37:Xxxxx`
11. **Cam receives** as if from its supernode

## How conntrack makes this work

The magic that holds the whole attack together is Linux kernel UDP
conntrack on the UDM. Without it, we&rsquo;d have to manually craft every
packet with the right source to match the cam&rsquo;s session state.

With it, we just send to `192.168.5.1:Y` (the MASQ&rsquo;d cam address)
and the kernel automatically rewrites our source to look like the
expected supernode. This is also why our SIGUSR1 injection works
against the cam&rsquo;s live session ports — we send to the MASQ side, and
the kernel completes the trick.

**Caveat**: conntrack entries for UDP expire after 180 seconds of
idle by default. If the cam goes silent for too long, the entry is
GC&rsquo;d and any injection after that lands without reverse-NAT — the
cam sees `src=192.168.5.233:32100` (unrewritten) and drops it as
unsolicited. Mitigation: inject while the cam is actively sending
DEV_LGNs.

## Failure modes

### Rule not firing

**Symptom**: counters on the DNAT rule stay at 0 even after the cam
sends traffic.

**Common causes**:
- Rule was added with wrong source IP (cam had a different IP after
  DHCP lease renewal)
- Rule added in wrong chain (OUTPUT vs PREROUTING)
- Rule added on the wrong table (filter vs nat)
- UBIOS_PREROUTING_JUMP has a terminating handler that consumed the
  packet before our rule

**Debug**: `iptables -t nat -L PREROUTING -v -n --line-numbers`
on the UDM and check `pkts` on each rule.

### Packets arrive at Mac but MITM doesn&rsquo;t see them

**Symptom**: tcpdump on Mac sees the packets but our Python listener
doesn&rsquo;t.

**Common causes**:
- Listener crashed (check `ps aux | grep mitm`)
- Bound to wrong port
- Bound to wrong address (`127.0.0.1` instead of `0.0.0.0`)
- macOS firewall blocking incoming UDP — unlikely but possible

### MITM reply doesn&rsquo;t reach the cam

**Symptom**: the proxy logs "forwarded to cam" but the cam continues
retrying as if it never got the reply.

**Common causes**:
- conntrack entry expired, reverse-NAT failed
- Mac replied from wrong port (source port mismatch → no conntrack
  match)
- IP checksum bad (unlikely with Python)

**Debug**: run `tcpdump -i any -n host 192.168.5.37 and port 32100`
on the UDM simultaneously with a capture on the Mac. Compare the
packets in flight.

### Explicit test: "does the pipeline work right now"

```sh
# From the Mac, run:
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(bytes.fromhex('f1300000'), ('192.168.5.37', 32108))
data, addr = s.recvfrom(4096)
print(f'ok: reply from {addr}: {data.hex()}')
"
```

If the cam replies with `f1 41 00 14 43 46 45 4f 41 …`, the cam is
alive and its LAN_SEARCH responder is working. This test doesn&rsquo;t
exercise our MITM pipeline but it confirms the cam is online.

_Last updated: 2026-04-15 — Session 5_
