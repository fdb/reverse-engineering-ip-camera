# 03 · Cloud topology

Every host the camera reaches out to, what it wants from that host,
and how we intercept the traffic.

## The short version

```
  Cloudbirds cam
        │
        ├── UDP 123 ── NTP wrappers (3 hosts, all benign CNAMEs to pool.ntp.org etc.)
        │
        ├── UDP 32100 ── Kalay supernodes (3 hosts, HA cluster)
        │               • p2p5.cloudbirds.cn → 8.134.120.63 (Aliyun Shenzhen)
        │               • p2p6.cloudbirds.cn → 47.89.232.167 (Aliyun US-West)
        │               • 123.56.74.245 (HARDCODED — no DNS lookup)
        │
        ├── TCP 443 TLS ── CBS control plane
        │               • user.hapseemate.cn → 190.92.254.71 (AWS ELB)
        │
        └── DNS-only (no traffic observed yet)
                        • alive.hapsee.cn → 116.63.81.177
```

## Full host list with sources

All of this is captured from actual pcaps (`camera_phonehome*.pcap`).

### NTP (benign, leave alone)

| Hostname queried | CNAME chain | A record observed | Port |
|---|---|---|---|
| `ntp_dyzl_ipc_address_1.cloudbirds.cn` | → `pool.ntp.org` | `45.9.2.181`, `162.159.200.1`, … | UDP 123 |
| `ntp_dyzl_ipc_address_2.cloudbirds.cn` | → `time.windows.com` → `twc.trafficmanager.net` | `51.145.123.29` | UDP 123 |
| `ntp_dyzl_ipc_address_3.cloudbirds.cn` | → `ntp.aliyun.com` | `203.107.6.88` | UDP 123 |
| `ntp_dyzl_ipc_address_4.cloudbirds.cn` | → `pool.ntp.org` | varies | UDP 123 |
| `ntp_dyzl_ipc_address_5.cloudbirds.cn` | → `ntp4.aliyun.com` | `203.107.6.88` | UDP 123 |

The Cloudbirds DNS infrastructure wraps three or four independent real
NTP sources via CNAME, so the cam always gets a working NTP server even
if one upstream is down. It&rsquo;s oddly thorough for an otherwise-cheap
device.

**Why NTP matters for the attack:** the cam&rsquo;s CBS HTTPS requests
include a `utcTime` query parameter that&rsquo;s a Unix timestamp. If NTP is
broken, the timestamp will be wildly wrong (probably 1970-01-01 or the
RTC-default date) and the server will reject the request. We leave NTP
unblocked.

### Kalay supernodes (UDP 32100)

| Hostname | Real IP | Location | How cam reaches it |
|---|---|---|---|
| `p2p5.cloudbirds.cn` | `8.134.120.63` | Aliyun Shenzhen | DNS-resolved at boot |
| `p2p6.cloudbirds.cn` | `47.89.232.167` | Aliyun US-West | DNS-resolved at boot |
| — | `123.56.74.245` | Aliyun Beijing | **Hardcoded — no DNS lookup** |

The three supernodes form an HA cluster. The camera registers with all
three simultaneously and maintains parallel sessions, so that a client
asking the supernode for this camera can be directed via whichever
supernode it happens to be connected to.

**The hardcoded third IP is a gotcha**: dnsmasq overrides do nothing for
IP-level traffic. We have to catch it with a dedicated `iptables -d
123.56.74.245` DNAT rule.

**Protocol on 32100**: Kalay UDP (CS2 PPPP family). See
[`04-wire-format-kalay.md`](04-wire-format-kalay.md) for byte details.

### CBS control plane (TCP 443 TLS)

| Hostname | Real IP | Frontend | SNI |
|---|---|---|---|
| `user.hapseemate.cn` | `190.92.254.71` | **AWS Elastic Load Balancer** | `user.hapseemate.cn` |

The `Server: elb` header in the response confirms AWS ELB, which is
notable because the rest of the stack is Alibaba-hosted. Chinese OEMs
frequently put their international-facing APIs on AWS or Cloudflare to
dodge country-based firewall rules.

**Cert pinning status: NONE.** The camera happily accepts our
self-signed certificate as long as the hostname matches the SNI. This
is the single biggest vendor security mistake in the whole stack.

**Endpoints observed so far**: only `/preadd/didBindUserId`. See
[`05-wire-format-cbs.md`](05-wire-format-cbs.md).

**Endpoints from the Android app&rsquo;s `Api.java` (not observed from the
cam yet)** — dozens, including `/preadd/checkDidByToken`,
`/device/addDev2.html`, `/deviceShare/v2/share.html`,
`/drp/order/checkOrderState`, `/public/checkDevVer`, `/user/forgetpwd.html`.
Most are app-side user-management APIs the cam would never call. We
expect the cam&rsquo;s own traffic pattern to be limited to the
`/preadd/*` namespace plus potentially an OTA update check.

### DNS-only (no traffic observed yet)

| Hostname | Real IP | Purpose (inferred) |
|---|---|---|
| `alive.hapsee.cn` | `116.63.81.177` | Keepalive / "I&rsquo;m still online" heartbeat |

The cam did a DNS lookup for this host on some boot cycles but we never
saw it initiate an actual TCP or UDP session to the resolved IP. Might
be triggered by specific firmware states we haven&rsquo;t exercised.

## The two brand domains

This is the organizational quirk worth internalizing: the same physical
camera, registered at the same cloud backend, uses TWO independent
brand domains:

1. **`cloudbirds.cn`** — used for NTP wrappers and the Kalay supernode
   hosts (`p2p5`, `p2p6`). This is the Dayunlinks / Cloudbirds
   public-facing brand.
2. **`hapseemate.cn`** — used for the CBS HTTPS control plane
   (`user.hapseemate.cn`) and keepalive (`alive.hapsee.cn`). This is
   the HapSee app brand.

Why two brands? Because the OEM stack is sold to multiple apps — V360
Pro, HapSee, HapSee Mate all share the same backend. The camera&rsquo;s
firmware was compiled with both sets of hostnames baked in so it could
service any of the app brands. The Wi-Fi AP SSID prefix `HAP-` is an
artifact of the HapSee heritage.

## What the attack needs to intercept

For a complete MITM we need to capture or override:

| Domain/IP | Protocol | Our handling |
|---|---|---|
| `p2p5.cloudbirds.cn` | UDP 32100 Kalay | dnsmasq → 9.9.9.9 → DNAT to Mac:32100 → mitm_supernode_proxy |
| `p2p6.cloudbirds.cn` | UDP 32100 Kalay | same as above |
| `123.56.74.245` | UDP 32100 Kalay | **IP-level** DNAT to Mac:32100 (no DNS) |
| `user.hapseemate.cn` | TCP 443 TLS | dnsmasq → 9.9.9.9 → DNAT TCP/443 to Mac:8443 → mitm_cbs_proxy |
| `alive.hapsee.cn` | unknown | dnsmasq → 9.9.9.9 (no traffic observed yet, so nothing on Mac side) |
| NTP wrappers | UDP 123 | **Allowed through unmodified** (needed for `utcTime`) |

See [`08-attack-chain.md`](08-attack-chain.md) for the full routing
details and [`09-mitm-setup.md`](09-mitm-setup.md) for how to actually
configure it.

_Last updated: 2026-04-15 — Session 5_

## Public IP leakage (important OPSEC note)

When our MITM forwards the cam&rsquo;s UDP traffic to the real Kalay
supernodes, the source IP the supernode sees is Frederik&rsquo;s **real
home WAN IP**, not the cam&rsquo;s. This is because:

1. The cam sends to 9.9.9.9 (thinking it&rsquo;s the supernode)
2. UDM DNATs that to `192.168.5.233:32100`
3. Our Mac&rsquo;s MITM proxy receives it and forwards to the real supernode
4. The UDM WAN-NATs the Mac&rsquo;s outbound traffic through the home WAN IP

So from the real supernode&rsquo;s point of view, "the cam" appears to be on
Frederik&rsquo;s home IP (`37.37.51.178` as of 2026-04-15). The HELLO_ACK
response from the supernode contains that IP back, which our MITM
forwards unchanged to the cam — and the cam accepts it as its "public
endpoint".

**Implication**: the Kalay supernodes now know there&rsquo;s a device of DID
`CFEOA-417739-RTFUU` active on Frederik&rsquo;s home IP. This is unavoidable
as long as the MITM forwards traffic to the real cloud. In the final
"airgap" mode, the MITM will no longer forward — it will serve canned
responses from a local bank, and the supernodes will stop seeing any
traffic from the cam.
