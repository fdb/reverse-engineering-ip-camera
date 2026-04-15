# 16 · Debug cookbook

A flat list of symptoms that have actually bitten us, the diagnosis
command that identifies the cause, and the fix. Use this as a lookup
table when something stops working.

## The cam is on the network but our MITM sees nothing

### Symptom

`tail -f /tmp/cam-listen/mitm_supernode.log` is silent for more than
30 seconds even though the cam is powered on and pingable.

### Diagnosis

```sh
# Is the cam alive at all?
ping -c 2 192.168.5.37

# Does LAN_SEARCH still work? (independent of cam's cloud state)
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(bytes.fromhex('f1300000'), ('192.168.5.37', 32108))
data, addr = s.recvfrom(4096)
print(f'LAN_SEARCH ok from {addr}: {data.hex()}')
"

# Are the UDM iptables rules firing?
ssh root@192.168.5.1 'iptables -t nat -L PREROUTING -v -n --line-numbers'
```

### Possible causes

1. **Cam was silent when we started the MITM**, so there&rsquo;s nothing
   yet to log. The cam only sends DEV_LGN keepalives every ~30s
   during WAITING state. Wait at least 40 seconds before worrying.
2. **DNAT counters are zero** — the cam either hasn&rsquo;t re-resolved
   its cloud hostnames since we added the rules, or the dnsmasq
   override is broken. Fix: reboot the cam OR verify the dnsmasq
   config is being read (`ls /run/dnsmasq.conf.d/` or wherever yours
   is).
3. **DNAT counters are non-zero but the Mac-side proxy isn&rsquo;t
   bound**. `lsof -iUDP:32100` should show a running Python process.
   If not, start `mitm_supernode_proxy.py`.
4. **DNAT counters are non-zero, Mac proxy is bound, but logs are
   empty**. Likely the MASQUERADE isn&rsquo;t rewriting correctly and
   packets arrive at the Mac from an unexpected source. Use tcpdump:
   ```sh
   sudo tcpdump -i any -n port 32100 -c 10
   ```

## tcpdump sees zero packets matching `host 192.168.5.37`

### Symptom

You ran `sudo tcpdump -i any host 192.168.5.37` to verify cam traffic
reaches the Mac, and you see "0 packets captured" while the MITM
proxies clearly show activity.

### Diagnosis

This is almost always **the MASQUERADE rewrite confusion**. After
UDM&rsquo;s `POSTROUTING -j MASQUERADE`, the cam&rsquo;s source IP is rewritten
from `192.168.5.37` to `192.168.5.1` (the UDM&rsquo;s LAN address). Your
filter on `host 192.168.5.37` no longer matches because `.37` is
nowhere in the packet headers by the time they reach the Mac.

### Fix

Filter on the Mac&rsquo;s own address or the expected ports instead:

```sh
sudo tcpdump -i any -n '(port 32100 or port 8443) and host 192.168.5.233'
```

Or capture **on the UDM** with the original source:

```sh
ssh root@192.168.5.1 'tcpdump -i any -n -c 30 host 192.168.5.37'
```

## SIGUSR1 injection fires but the cam doesn&rsquo;t react

### Symptom

`inject_p2p_req.py` runs, the supernode proxy log shows `✳ INJECT →
…`, but the cam continues its normal DEV_LGN cadence without any new
activity. No response on the peer listener either.

### Diagnosis

Several possible causes — work through them in order:

1. **Cam session ports are stale**. The supernode proxy expires its
   per-session state after 300 seconds of idle, and the cam rotates
   source ports on roughly the same cadence. If you target a port
   that&rsquo;s no longer active, your injection arrives at an empty
   conntrack entry and gets silently dropped.

   Fix: read the CURRENT session ports from the most recent log
   entries:
   ```sh
   grep -oE '192\.168\.5\.1:[0-9]+' /tmp/cam-listen/mitm_supernode.log | sort -u | tail
   ```
   Then target those in your `--cam-session` flag.

2. **Wrong message type**. `thread_recv_Proto` only dispatches on a
   short whitelist of types (see
   [`04-wire-format-kalay.md`](04-wire-format-kalay.md)), which does
   NOT include `0x20 P2P_REQ` or `0x40 PUNCH_TO`. Those types get
   parsed nowhere and the cam ignores them.

   Fix: use a type the cam actually handles — candidates are
   `PunchPkt (0x41)`, `P2PRdy (0x40)`, or one of the as-yet-unknown
   `0x31, 0x3f, 0x52, 0x55, 0xdb, 0xdc`.

3. **Wrong body shape**. The cam&rsquo;s parser expects specific byte
   layouts. For types we&rsquo;ve disassembled (`PunchPkt`, `P2PReq`,
   `PunchTo`) use the exact layouts from the reference doc. For
   types we haven&rsquo;t, capture a real packet first (see Fake Client
   approach in [`14-next-steps.md`](14-next-steps.md)).

4. **conntrack entry for that cam session has expired**. UDP
   conntrack default timeout is ~180 seconds. If the cam was quiet
   for longer than that, the reverse-NAT rewrite that makes our
   packet look like it came from `9.9.9.9:32100` will fail.

   Fix: wait for the next DEV_LGN from the cam, which will
   re-establish the conntrack entry, then inject immediately after.

## The cam&rsquo;s TCP 443 attempts get RST&rsquo;d

### Symptom

Cam retries TCP/443 every 2-3 seconds. `mitm_cbs.log` is empty or
shows only "connection reset" errors. In pcap, you see short TCP
flows with SYN → RST.

### Diagnosis

1. **`mitm_cbs_proxy.py` not running**. Check `lsof -iTCP:8443`.
2. **Port mismatch**. The cam&rsquo;s TCP goes to the destination port
   you DNAT&rsquo;d. If you forgot to specify `:8443` in `--to-destination`,
   it goes to port 443 on the Mac (which needs root to bind).

   Fix: confirm the rule has `--to-destination 192.168.5.233:8443`,
   not just `192.168.5.233`.

3. **The generic IP-level DNAT rule is matching first** and sending
   to port 443 instead of 8443. The TCP-specific rule needs to come
   **before** the generic any-proto rule in the iptables chain.

   Fix: inspect with
   `iptables -t nat -L PREROUTING -v -n --line-numbers` and confirm
   the TCP-specific rule has a lower line number than the any-proto
   one. If not, delete and re-insert with `-I PREROUTING 2` to put
   it at position 2.

## The cam rejects the HELLO_ACK and keeps retrying HELLO

### Symptom

Cam sends HELLO → our MITM forwards → supernode replies → our MITM
forwards back. The cam then immediately sends another HELLO instead
of advancing to DEV_LGN_CRC.

### Diagnosis

Almost certainly the **RFC1918 rebinding filter**. Your HELLO_ACK
body contains an IP the cam considers private, so it rejects the
reply. This can happen in three scenarios:

1. You&rsquo;re using a hand-crafted fake HELLO_ACK and accidentally
   embedded `192.168.5.233` or similar as the "public IP".
2. The real supernode reply contains your public IP which happens to
   be in a private-ish range (e.g., you&rsquo;re on a CG-NAT connection).
3. Your MITM is rewriting the reply body incorrectly.

### Fix

For a canned fake HELLO_ACK, use a TEST-NET-3 address like
`203.0.113.37`. For a real-forwarding MITM, verify that the supernode
is seeing your Mac&rsquo;s actual public IP by looking at the HELLO_ACK
body in the logs:

```sh
grep -A1 HELLO_ACK /tmp/cam-listen/mitm_supernode.log | tail -10
```

The 16-byte body should start with `00 02` (family), then 2 bytes
port BE, then 4 bytes IP BE. That IP should NOT be in
`10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16`.

## The fake_cbs_server complains about TLS handshake failure

### Symptom

`mitm_cbs.log` shows `TLS handshake failed: [SSL: …]` for every
incoming cam connection.

### Diagnosis

```sh
# Is the cert file present and readable?
ls -la /tmp/cam-listen/fake-cbs-certs/

# What cipher is the cam asking for?
openssl s_client -connect 192.168.5.233:8443 -debug < /dev/null 2>&1 | head -60
```

Common causes:

1. **Cert not generated** — first-run generation failed. Delete
   `/tmp/cam-listen/fake-cbs-certs/` and restart the proxy.
2. **Cipher too modern** — the cam might insist on an old cipher
   that our Python default rejects. Fix: in the proxy code, use
   `ctx.set_ciphers("ALL:@SECLEVEL=0")` to allow everything.
3. **SNI mismatch** — the cam wants `user.hapseemate.cn` but our
   cert doesn&rsquo;t include it in SAN. Verify with `openssl x509 -in
   server.crt -noout -text | grep DNS`.

## dnsmasq override isn&rsquo;t being honored

### Symptom

You added an `address=/hapseemate.cn/9.9.9.9` line, but `dig
user.hapseemate.cn @192.168.5.1` still returns the real `190.92.254.71`.

### Diagnosis

```sh
ssh root@192.168.5.1 '
  # What config files is dnsmasq actually reading?
  ps auxw | grep "[d]nsmasq"
  # That shows the command line. Look for -C / --conf-file / --conf-dir.

  # Did our file get clobbered by the GUI?
  ls -la /run/dnsmasq.conf.d/
  cat /run/dnsmasq.conf.d/99-cam-rebind.conf 2>/dev/null || echo "MISSING"
'
```

### Fix

The Unifi Network GUI regenerates `/run/dnsmasq.conf.d/` whenever
settings change. You need to either:

1. Put the override in Unifi&rsquo;s own DNS override UI (Settings →
   Networks → Advanced → DNS)
2. Or use a boot script in `/data/on_boot.d/` that re-creates the
   file on every boot
3. Or send `SIGHUP` to dnsmasq manually after re-creating the file

## The explainer HTMLs render weirdly after `build_docs.py`

### Symptom

Slides look off, code blocks unstyled, dark mode flicker.

### Diagnosis

The static site generator (`build_docs.py`) doesn&rsquo;t touch
`explainer.html` or `explainer-deep.html` — those are
hand-crafted HTML files, not generated from markdown. The site is
only generated from `docs/*.md` → `dist/*.html`.

### Fix

If you want to view the explainers, open them directly from the
project root:

```sh
open explainer-deep.html
```

They&rsquo;re not part of the `dist/` build output.

_Last updated: 2026-04-15 — Session 6_
