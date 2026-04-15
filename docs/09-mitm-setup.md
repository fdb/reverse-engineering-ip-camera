# 09 · MITM setup and operation

Step-by-step instructions to bring the interception pipeline up from
zero. Assumes a UDM-series Unifi router, a Mac on the same LAN, and
a cam already provisioned onto the network.

## Prerequisites

- **Hardware**: UDM Dream Router (or any UDM, UDM Pro, UDM-SE). Same
  principles apply to other Linux-based routers, but the paths to
  iptables and dnsmasq config differ.
- **Access**: SSH as `root@192.168.5.1` to the UDM. SSH credentials
  are configured in Unifi Network → Settings → System → Device
  Authentication.
- **Mac**: Python 3.10+ (we use `uv` for script shebangs but standard
  Python works for everything). No root privileges needed for any
  of the MITM code.
- **Cam**: already joined to the target Wi-Fi. If it isn&rsquo;t, use
  [`wifiqr.py`](../wifiqr.py) to generate an offline QR code and show
  it to the cam&rsquo;s imager. See [`10-tooling.md`](10-tooling.md) for
  `wifiqr.py` usage.

## Step 1 — dnsmasq override on the UDM

Edit the dnsmasq config on the UDM to redirect all cam-cloud
hostnames to a non-RFC1918 sink.

⚠️ **About the sink IP**: we use `9.9.9.9` as the sink because it&rsquo;s
memorable, but `9.9.9.9` is the real Quad9 public DNS resolver. If
any other client on the same VLAN tries to use Quad9 for DNS-over-
HTTPS, its DoH traffic will also be DNAT&rsquo;d to our Mac. For a clean
production setup, use a `203.0.113.x` TEST-NET-3 address instead
(RFC 5737 documentation prefix, conventionally not routed on the
public internet). You&rsquo;ll need to update the DNAT rules in step 2
to match whatever sink you chose.

On the UDM:

```sh
ssh root@192.168.5.1
cat >> /run/dnsmasq.conf.d/99-cam-rebind.conf <<'EOF'
address=/cloudbirds.cn/9.9.9.9
address=/hapseemate.cn/9.9.9.9
address=/hapsee.cn/9.9.9.9
EOF
# reload dnsmasq
killall -HUP dnsmasq
```

The exact path to the dnsmasq config directory **varies by Unifi
firmware version**. Common locations include
`/run/dnsmasq.conf.d/`, `/etc/dnsmasq.d/`, and
`/data/udapi-base/dnsmasq.conf.d/`. Find the one your running
instance uses:

```sh
ps auxw | grep '[d]nsmasq'         # shows the command-line args
ls -la /run/dnsmasq.conf.d/ 2>/dev/null
ls -la /etc/dnsmasq.d/    2>/dev/null
ls -la /data/udapi-base/dnsmasq.conf.d/ 2>/dev/null
```

**Persistence warning**: on UDM, the Unifi Network GUI will typically
regenerate `/run/dnsmasq.conf.d/` on every configuration push, which
clobbers manual edits. For a persistent setup you have three options:

1. Use Unifi Network&rsquo;s own DNS override UI (Settings → Networks →
   Advanced → DNS), which survives GUI pushes.
2. Put a script in `/data/on_boot.d/` that re-creates the override
   file at boot.
3. Use the Unifi controller&rsquo;s `config.gateway.json` mechanism if
   your controller supports it.

## Step 2 — iptables DNAT rules on the UDM

Add the DNAT rules that rewrite cam traffic to our Mac. SSH into the
UDM and run:

```sh
CAM=192.168.5.37
MAC=192.168.5.233

# --- TCP 443 → Mac:8443 (TLS MITM) ---
iptables -t nat -I PREROUTING 2 \
  -s $CAM -p tcp -d 9.9.9.9 --dport 443 \
  -j DNAT --to-destination $MAC:8443

iptables -t nat -I PREROUTING 2 \
  -s $CAM -p tcp -d 123.56.74.245 --dport 443 \
  -j DNAT --to-destination $MAC:8443

# --- Any-proto catch-all (UDP Kalay) ---
iptables -t nat -A PREROUTING \
  -s $CAM -d 9.9.9.9 \
  -j DNAT --to-destination $MAC

iptables -t nat -A PREROUTING \
  -s $CAM -d 123.56.74.245 \
  -j DNAT --to-destination $MAC

# --- Return-path source rewrite ---
iptables -t nat -A POSTROUTING \
  -s $CAM -d $MAC \
  -j MASQUERADE

# (The UDM's default UBIOS_POSTROUTING_USER_HOOK already has a
# catch-all MASQUERADE that handles non-WAN traffic, so this custom
# rule is usually redundant but harmless.)
```

**Important**: the TCP rules are inserted at position **2** (before the
generic catch-all at position 4 or 5) so they match first. If you
`-A` them to the end, the generic UDP catch-all will hit first for
TCP packets too — because it doesn&rsquo;t have a `-p` filter — and the
cam&rsquo;s TCP/443 traffic will land on Mac:443 instead of Mac:8443.

Verify rule order:

```sh
iptables -t nat -L PREROUTING -v -n --line-numbers
```

You should see the TCP-specific rules at positions 2 and 3,
above the any-proto catch-alls at positions 4 and 5.

**Persistence**: iptables rules do NOT survive UDM reboot. For a
long-lived setup, put the commands in
`/data/on_boot.d/15-cam-dnat.sh` with idempotent `-C` guards:

```sh
#!/bin/sh
set -e
CAM=192.168.5.37
MAC=192.168.5.233
for ip in 9.9.9.9 123.56.74.245; do
  iptables -t nat -C PREROUTING -s $CAM -p tcp -d $ip --dport 443 \
    -j DNAT --to-destination $MAC:8443 2>/dev/null \
    || iptables -t nat -I PREROUTING 2 -s $CAM -p tcp -d $ip --dport 443 \
        -j DNAT --to-destination $MAC:8443
  iptables -t nat -C PREROUTING -s $CAM -d $ip \
    -j DNAT --to-destination $MAC 2>/dev/null \
    || iptables -t nat -A PREROUTING -s $CAM -d $ip \
        -j DNAT --to-destination $MAC
done
iptables -t nat -C POSTROUTING -s $CAM -d $MAC -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s $CAM -d $MAC -j MASQUERADE
```

Then `chmod +x` and the UDM&rsquo;s `udm-boot` service (part of
[unifi-utilities](https://github.com/unifi-utilities/unifios-utilities))
will run it at boot.

## Step 3 — Start the MITMs on the Mac

On the Mac, in the project root:

```sh
mkdir -p /tmp/cam-listen
cd /Users/fdb/ReverseEngineering/cloudbirds-ip-cam

# UDP Kalay MITM
python3 mitm_supernode_proxy.py 2>&1 | tee /tmp/cam-listen/mitm_supernode.log &

# TCP TLS MITM
python3 mitm_cbs_proxy.py 2>&1 | tee /tmp/cam-listen/mitm_cbs.log &

# Verify they're bound
lsof -iUDP:32100 -iTCP:8443 -n -P
```

On first run, `mitm_cbs_proxy.py` will auto-generate a self-signed
cert under `/tmp/cam-listen/fake-cbs-certs/` using the Mac&rsquo;s
`openssl` CLI. Subsequent runs reuse the same cert.

**Expected output**:

```
mitm_supernode_proxy.py
  [HH:MM:SS] MITM supernode proxy listening on UDP/32100  pid=XXXXX
  [HH:MM:SS] upstreams: [('8.134.120.63', 32100), ('47.89.232.167', 32100), ('123.56.74.245', 32100)]
  [HH:MM:SS] inject: write JSON to /tmp/cam-listen/inject.json, then `kill -USR1 XXXXX`

mitm_cbs_proxy.py
  [HH:MM:SS] MITM CBS TLS proxy listening on :8443
  [HH:MM:SS] upstream: user.hapseemate.cn → 190.92.254.71:443
```

## Step 4 — Verify it&rsquo;s all working

Power-cycle the cam and watch the logs:

```sh
tail -f /tmp/cam-listen/mitm_supernode.log
tail -f /tmp/cam-listen/mitm_cbs.log
```

Within ~30 seconds of reboot you should see:

1. **UDP log**: `new session: ('192.168.5.1', XXXX) → (...)` followed
   by a burst of HELLO, DEV_LGN_CRC, DEV_LGN_ACK frames.
2. **TCP log**: `ACCEPT new connection`, `SNI: user.hapseemate.cn`,
   `downstream TLS OK`, `connected to 190.92.254.71:443 SNI=...`,
   then a `GET /preadd/didBindUserId?…` request and a `HTTP/1.1 200`
   response in cleartext.

After the initial burst, the cam settles into steady state and only
UDP traffic continues at 30-second intervals.

Also verify the iptables counters on the UDM:

```sh
ssh root@192.168.5.1 'iptables -t nat -L PREROUTING -v -n --line-numbers'
```

`pkts` on rules 2, 3, 4, 5 should be incrementing.

## Step 5 — Injecting packets

See [`10-tooling.md`](10-tooling.md) for the `inject_p2p_req.py` usage
and [`04-wire-format-kalay.md`](04-wire-format-kalay.md) for the
packet formats. Short version:

```sh
python3 inject_p2p_req.py \
  --peer-ip 192.168.5.233 --peer-port 41234 \
  --cam-session "192.168.5.1:PORT1,192.168.5.1:PORT2"
```

where `PORT1, PORT2` are current cam session ports read from the
latest `mitm_supernode.log` entries.

## Teardown

```sh
# Kill the Mac-side proxies
ps aux | grep -E 'mitm_supernode|mitm_cbs' | grep -v grep | awk '{print $2}' | xargs kill

# Remove the UDM iptables rules
ssh root@192.168.5.1 '
iptables -t nat -D PREROUTING -s 192.168.5.37 -p tcp -d 9.9.9.9 --dport 443 -j DNAT --to-destination 192.168.5.233:8443
iptables -t nat -D PREROUTING -s 192.168.5.37 -p tcp -d 123.56.74.245 --dport 443 -j DNAT --to-destination 192.168.5.233:8443
iptables -t nat -D PREROUTING -s 192.168.5.37 -d 9.9.9.9 -j DNAT --to-destination 192.168.5.233
iptables -t nat -D PREROUTING -s 192.168.5.37 -d 123.56.74.245 -j DNAT --to-destination 192.168.5.233
iptables -t nat -D POSTROUTING -s 192.168.5.37 -d 192.168.5.233 -j MASQUERADE
'

# Revert dnsmasq
ssh root@192.168.5.1 'rm /run/dnsmasq.conf.d/99-cam-rebind.conf && killall -HUP dnsmasq'
```

## Troubleshooting

See [`15-debugging.md`](15-debugging.md) for the full debug cookbook
covering common pipeline issues, and
[`08-attack-chain.md`](08-attack-chain.md) § "Failure modes" for the
theory of why things go wrong.

_Last updated: 2026-04-15 — Session 5_
