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
| `time.nist.gov` | direct NIST | AAAA query only on cold boot — Session 7 Wave 4 | UDP 53 (DNS) |
| `ntp.tuna.tsinghua.edu.cn` | Tsinghua University NTP | queried on cold boot — Session 7 Wave 4 | UDP 53 (DNS) |

**Hardcoded DNS resolver (Session 7 Wave 4 finding)**: the cam ignores
the DHCP-assigned DNS server (Option 6) and queries directly to
**OpenDNS (`208.67.222.222`)** as its hardcoded resolver. Evidence:
conntrack entries captured before our Wave 4 DNS hijack took effect
showed `dst=208.67.222.222 sport=53XXX dport=53`. OpenDNS is an
unusual choice for a Chinese OEM — most bake in Alibaba `223.5.5.5`
or Google `8.8.8.8` — suggesting the firmware is built for
international distribution where OpenDNS is a reliable unblocked
resolver. This is a firmware fingerprint worth remembering when
working with other cams in the Qianniao OEM family.

**Wave 4 DNS hijack**: because the cam bypasses DHCP DNS, we had to
add an iptables DNAT rule to force its UDP/53 and TCP/53 traffic to
`192.168.5.1:53` (the UDM&rsquo;s dnsmasq) regardless of the original
destination. Without this rule, the cam&rsquo;s DNS queries get swept up
by the Wave 4 catch-all DNAT to Mac:32100 and break entirely,
preventing any hostname resolution. Rule is installed at PREROUTING
position 2 with the `camre-veto-dns-hijack-udp` / `-tcp` comment
markers. See [`09-router-setup.md`](09-router-setup.md) and the Wave
4 kick-off script.

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

### Cam firmware upgrade endpoint (captured Session 7 Wave 4)

| Hostname | Real IP | Frontend | Used by | SNI |
|---|---|---|---|---|
| `dev-silent-upgrade.cloudbirds.cn` | `139.9.220.198` | **Huawei Cloud China** | **cam-only** — autonomous cold-boot firmware check | `dev-silent-upgrade.cloudbirds.cn` |
| `license.cloudbirds.cn` | `110.41.70.176` | **Huawei Cloud China** (HA clone) | same Spring Boot app as `dev-silent-upgrade`, different zone | — |

Both hostnames point to the same Spring Boot service deployed in two
different Huawei Cloud zones — HA pair. `license.cloudbirds.cn` was
confirmed to serve the identical `/ota/device/version/upgrade/query`
response for identical queries. The "license" naming is a red herring;
it&rsquo;s not a license/activation endpoint, it&rsquo;s a second instance of
the firmware upgrade service. Probably part of the same pre-wildcard-cert
era from before Nov 2023 when each service had its own hostname and
subsequently got consolidated onto one shared service but both hostnames
were kept for backwards compatibility.

**What this endpoint is**: the cam&rsquo;s own firmware upgrade check. The
cam hits this URL autonomously during cold boot (observed on Session 7
at second 330 after Wi-Fi came up) without any app involvement. The
Android client never talks to this host — it&rsquo;s not in
`decompiled/sources/com/qianniao/**` or in the decrypted
`URLConfig` dictionary; it lives only in the cam&rsquo;s own firmware.

**Exact request format** (captured verbatim, cleartext after MITM):

```
GET /ota/device/version/upgrade/query
    ?did=<DID>                              ← cleartext, no auth
    &version=<V30904.1.149build20250721>   ← current firmware version
    &timeZone=8                             ← hardcoded UTC+8 China
    &uptime=<seconds_since_boot>
    &module=                                ← observed empty
HTTP/1.1
Host: dev-silent-upgrade.cloudbirds.cn
Accept: */*
```

**Response schema** (captured multiple times, all returned
`code=13016` "up to date" because no newer firmware exists for this
DID yet):

```json
{
  "code": "13016",
  "msg":  "版本是最新的，不需要升级",
  "data": {
    "taskCode":    "",
    "version":     "",   ← latest available firmware version
    "size":        "",   ← bytes
    "url":         "",   ← firmware download URL
    "description": "",   ← changelog
    "md5":         "",   ← MD5 integrity hash (no cryptographic signature)
    "upgradeTime": "",
    "soc":         "",   ← SoC identifier for multi-hardware support
    "isReboot":    "0",
    "rebootStart": "",
    "rebootEnd":   "",
    "rebootGap":   ""
  },
  "time": "2026-04-16 04:46:04"   ← server clock UTC+8
}
```

**Integrity model**: the response carries `md5` but no signature or
public key. Implies MD5-only verification on the cam side — a serious
cryptographic weakness (MD5 is collidable). Documented in
[`07-defenses.md`](07-defenses.md).

**Exhaustive probing summary (Session 8)**: we spent an extended
session trying to coax a non-empty `url` field out of the server. Every
combination returned the same `code=13016` ("up to date") response:

- **Spoofed version strings**: `V1.0`, `V1.0.0build20200101`,
  `V30000.1.001build20200101`, `V30900.1.0build20240101`,
  `V30904.1.100build20250101`, and more. All return 13016.
- **Spoofed uptime values**: 60s, 86400s. No effect.
- **Spoofed module values**: empty, `ipc`. No effect.
- **28 DID prefix variations**: `CFEOA`–`CFEOH` (letter sweep),
  `SMNTA`, `SMAIN`, `SMNT`, `SMT`, `HAPSA`, `HPSEE`, `HAPSE`,
  `PHILA`, `PHIL`, `PHI`, `XIANA`, `XSHIA`, `DGOK`, `BATE`, `PTZA`,
  `FTYC`, `TNPCHNA`, `XMSYSGB`, `TUYASA`, `VSTC`, `HXEUCAM`,
  `AAAAA`, `ZZZZZ`. All return 13016. Fake DIDs (`FAKEA-000000-AAAAA`,
  `CFEOA-000001-AAAAA`) are NOT rejected — they get the same default
  response, which means the server doesn&rsquo;t validate DID existence.
- **HTTP methods**: `OPTIONS` returns `Allow: GET, HEAD, OPTIONS`.
  `POST`/`PUT`/`DELETE` all return 405. Read-only endpoint.
- **Sibling path guesses**: 15+ paths under `/ota/device/version/*`
  and `/actuator/*` — all 404. The endpoint surface is exactly
  `/ota/device/version/upgrade/query` and nothing else reachable.

**Conclusion**: the server&rsquo;s behavior is consistent: return 13016 as
the default for any DID+version combo it doesn&rsquo;t have a specific
upgrade mapping for. Our cam on `V30904.1.149build20250721` is
genuinely the latest offering for this SKU. No probing trick will
conjure a download URL that doesn&rsquo;t exist server-side. Paths forward
are documented in [`14-next-steps.md`](14-next-steps.md).

**Authentication model**: **none**. DID is cleartext in the query
string, no HMAC, no nonce, no cookie. We confirmed this by probing
with fake DIDs (`FAKEA-000000-AAAAA`, `CFEOA-000001-AAAAA`) — the
server returned the same `code=13016` response rather than rejecting
the query, so unknown DIDs are not validated. This also means the
endpoint is trivially enumerable by any caller.

**Build timestamp coincidence**: the cam&rsquo;s current firmware
`V30904.1.149build20250721` is stamped 2025-07-21 — within the same
~2-week window as the `aiseebling.com` domain registration
(2025-07-11). Suggests a coordinated OEM release that introduced the
shared payment rail AND this firmware release together. See
[`18-aiseebling-investigation.md`](18-aiseebling-investigation.md)
for the brand-chain context.

### CBS control plane (TCP 443 TLS)

| Hostname | Real IP | Frontend | Used by | SNI |
|---|---|---|---|---|
| `user.hapseemate.cn` | `190.92.254.71` | **AWS Elastic Load Balancer** | cam + app (legacy + `URLConfig.user`) | `user.hapseemate.cn` |
| `birds-user.hapseemate.cn` | resolves at runtime | AWS ELB | app (hardcoded Retrofit base URL in `HttpClient.java:153`) | `birds-user.hapseemate.cn` |
| `wechat.hapseemate.cn` | resolves at runtime | AWS ELB | app (`URLConfig.cloud` + `URLConfig.cloudStorgeWeb` — single endpoint shared between two logical services) | — |
| `ai-voice.cloudbirds.cn` | resolves at runtime | unknown | app (voice commands) | — |
| `public.dayunlinks.cn` | **CNAME → `birds-public.philipsiot.com` → `190.92.254.74`** | **Philips Signify IoT infrastructure** | app `/public/checkVer`, `/public/checkDevVer`, `/public/checkAdv`, `/domainname/all`, `/publicLang/getLang` (`URLConfig.version`) | `public.dayunlinks.cn` |
| `apppush-hapseemate.dayunlinks.cn` | resolves at runtime | unknown (Philips IoT family?) | app push notifications (`URLConfig.push` + observed `/icp/getMsgVideoCall`) | — |
| `databuried.cloudbirds.cn` | resolves at runtime | unknown | app analytics / telemetry (`URLConfig.databuried`) — obtained via `/domainname/all` decryption, not yet observed on the wire | — |
| `support.cloudbirds.cn` | resolves at runtime | unknown | app support pages (`URLConfig.support`, HTTPS) **and** account cancellation (`URLConfig.cancellation`, plain **HTTP** — see anomaly note below) | — |
| `privacy-policy.dayunlinks.cn` | resolves at runtime | unknown | app privacy policy page (`URLConfig.privacy`) | — |
| **`payment.aiseebling.com`** | `189.1.221.131` (Huawei Cloud HK) | **Qianniao OEM shared white-label payment endpoint** | app payment (`URLConfig.pay`) — see [`18-aiseebling-investigation.md`](18-aiseebling-investigation.md) | — |

**Anomaly — the `cancellation` URL is plain `http://`, not `https://`.**
The decrypted `URLConfig.cancellation` field literally starts with
`http://support.cloudbirds.cn`, while the adjacent `URLConfig.support`
field points at `https://support.cloudbirds.cn` (same host, different
scheme). This is either a deliberate choice (the account-cancellation
page is opened in an external browser where a cleartext redirect to HTTPS
is acceptable) or an OEM copy-paste error. Either way it&rsquo;s notable:
any party on the network path between a cancelling user and the support
host can read the cancellation URL query parameters, which may contain a
session token.

The `Server: elb` header in the response confirms AWS ELB for the
primary hapseemate hosts, which is notable because the rest of the
stack is Alibaba-hosted. Chinese OEMs frequently put their
international-facing APIs on AWS or Cloudflare to dodge country-based
firewall rules.

**The Philips IoT finding (Session 6)**: `public.dayunlinks.cn`
CNAMEs through `birds-public.philipsiot.com` to Signify-operated
infrastructure. This is the first concrete evidence that the
OTA/update path is hosted on a Western IoT platform, not a Chinese
cloud. It implies:

- The OTA backend is probably subject to different security and
  uptime guarantees than `hapseemate.cn` (possibly stricter TLS,
  possibly signed firmware manifests).
- The OEM supply chain touches Signify/Philips in some capacity —
  worth flagging for anyone doing broader portability work on the
  Qianniao / Kalay / CS2 PPPP OEM family.

### Additional Qianniao OEM hostnames (discovered Session 8)

An extended passive-OSINT pass in Session 8 (via `site:` search engines,
DNS brute force, CT logs, and 6.8.7 APK decompile) surfaced ~15 new
hostnames across the Qianniao OEM infrastructure. Not all are used by
our cam, but they&rsquo;re cataloged here for future sessions and for
portability analysis of the broader OEM family.

| Hostname | Real IP | Purpose / evidence |
|---|---|---|
| `www.cloudbirds.cn` | `119.12.173.82` | Multi-brand white-label SPA (same template as `aiseebling.com`) |
| `public.cloudbirds.cn` | `110.41.143.85` | Default nginx welcome page (likely dormant) |
| `support.cloudbirds.cn` | `119.12.173.82` | Support portal (shared IP with `www.cloudbirds.cn`) |
| `databuried.cloudbirds.cn` | `110.41.45.210` | Titled "支付结果" (payment result) despite the name. Analytics + post-payment confirmation. |
| `iot.cloudbirds.cn` | `124.71.111.197` | **Internal admin console** titled "千鸟物联网IOT平台" (Qianniao IoT Network IOT Platform). Vite/Vue SPA. NOT probed — explicitly out of scope. |
| `file-server.dayunlinks.cn` | `190.92.254.71` | DNS alias for the primary CBS ELB (same IP as `user.hapseemate.cn`). Serves `/download/app/download.html` (dead stub landing page referenced in `AppUpdateManager.java:139`). |
| `glpt.dayunlinks.cn` | `139.159.136.15` | Admin login (千鸟物联网IOT platform console). Shared backend with `keepeyes-support.hapseemate.cn`. |
| `keepeyes-support.hapseemate.cn` | `139.159.136.15` | **KeepEyes brand** support portal. New Qianniao brand confirmed via App Store developer listing. Shared backend with `glpt.dayunlinks.cn`. |
| `app-file-cos-cdn.hapsee.cn` | `36.249.93.80` | **Tencent Cloud Object Storage CDN** edge. Confirmed via `server: tencent-cos` header and `x-cos-request-id`. Bucket is private (`403 AccessDenied` on all probes including `/?delimiter=/` bucket list). Strongly suspected host for actual APK / firmware binary downloads, but inaccessible without signed URLs. |
| `applive1.cloudbirds.cn`…`applive9.cloudbirds.cn` | varies | **DNS aliases for the Kalay supernode cluster**. `applive5.cloudbirds.cn` resolves to `8.134.120.63` — the same IP as `p2p5.cloudbirds.cn`. Same HA cluster, different naming scheme for client-side live-streaming traffic. |
| `keep_alive_app1.hapseemate.cn`…`keep_alive_app3.hapseemate.cn` | `47.74.225.75` etc. | App push-notification heartbeat relays on Aliyun Singapore |
| `ai-voice-web.cloudbirds.cn` | — | Voice-assistant web interface (hostname in 6.8.7 APK strings, not seen on the wire) |

### Shared-backend map (8+ distinct IPs for the Qianniao infrastructure)

Assembled from Session 8 DNS resolution sweeps:

| Backend IP | Hostnames sharing | Inferred role |
|---|---|---|
| `190.92.254.71` (AWS ELB) | `user.hapseemate.cn`, `file-server.dayunlinks.cn` | Primary CBS Spring Boot control plane (plus stub file server) |
| `139.9.220.198` (Huawei Cloud) | `dev-silent-upgrade.cloudbirds.cn` | Primary cam firmware upgrade service |
| `110.41.70.176` (Huawei Cloud) | `license.cloudbirds.cn` | HA clone of upgrade service |
| `110.41.45.210` (Huawei Cloud) | `databuried.cloudbirds.cn` | Analytics / payment-result |
| `110.41.143.85` (Huawei Cloud) | `public.cloudbirds.cn` | nginx welcome (dormant) |
| `119.12.173.82` (Huawei Cloud) | `www.cloudbirds.cn`, `support.cloudbirds.cn` | Static marketing + support UI |
| `124.71.111.197` (Huawei Cloud) | `iot.cloudbirds.cn` | Internal admin panel |
| `139.159.136.15` (Huawei Cloud) | `glpt.dayunlinks.cn`, `keepeyes-support.hapseemate.cn` | Shared admin/support backend |
| `36.249.93.80` (Tencent COS edge) | `app-file-cos-cdn.hapsee.cn` | Private Tencent COS bucket |

**Architecture observation**: the Qianniao OEM splits its infrastructure
between **AWS** (primary CBS control plane for international traffic),
**Huawei Cloud** (admin panels, upgrade services, analytics, static
pages), **Alibaba Cloud** (Kalay P2P supernodes — `p2p5/p2p6/applive*`),
and **Tencent COS** (CDN for file/APK/firmware hosting). That&rsquo;s
four separate cloud providers for one OEM stack — a pragmatic
multi-cloud setup probably driven by geographic performance (Aliyun is
fastest for mainland China Kalay P2P) and feature alignment (Tencent COS
is the Chinese-market standard for object storage). See
[`16-debugging.md`](16-debugging.md) if you&rsquo;re tracing unexpected
packets to any of these.

### App update endpoint (distinct from cam firmware — Session 8)

**`https://public.dayunlinks.cn/public/checkAppVer`** — the APP update
check, distinct from `/public/checkVer`. Captured unauthenticated
response schema:

```json
{
  "code": "200",
  "msg":  "成功",
  "data": {
    "dlCh":     "",        ← download channel
    "isUpdate": "0",       ← 0=latest, 1=optional, 2=force
    "content":  "Currently the latest version",
    "url32":    "",        ← 32-bit ARM APK URL
    "url64":    "",        ← 64-bit ARM APK URL
  },
  "time": "2026-04-16 05:36:40"
}
```

Unauthenticated, no parameters required for the basic "am I on the
latest" check. When an update IS available, `url32` and `url64` are
populated with APK download URLs — almost certainly pointing at
`app-file-cos-cdn.hapsee.cn` (the Tencent COS CDN), but our probe
returned empty fields because the client is on "latest" per the
server&rsquo;s lookup.

This is the REAL app-update endpoint used in 6.8.7; the older 6.5.0
`AppUpdateManager.java:139` still references the legacy
`http://file-server.dayunlinks.cn/download/app/download.html` path
which is a dead stub. The server infrastructure was migrated; the
6.5.0 APK just never got the update.

**Cert pinning status on the cam: NONE.** The camera happily accepts
our self-signed certificate as long as the hostname matches the SNI.
This is one of the biggest cam-side vendor security mistakes.

**TLS trust on the app (Session 6 static analysis)**: the V360 Pro
Android app is *deliberately* insecure. Its OkHttp client uses a
custom `X509TrustManager` whose `checkServerTrusted()` is empty, and
a custom `HostnameVerifier` that returns `true` unconditionally — see
`decompiled/sources/com/qianniao/base/http/HttpClient.java:71-105`.
The app accepts any cert from any host. Also documented in
`07-defenses.md`.

**Endpoints observed on the wire from the cam so far**: only
`/preadd/didBindUserId`. See [`05-wire-format-cbs.md`](05-wire-format-cbs.md).

**Endpoints from the Android app&rsquo;s `Api.java` (not observed from the
cam yet, some confirmed from app-side capture in Session 6)** —
dozens, including `/preadd/checkDidByToken`, `/device/addDev2.html`,
`/deviceShare/v2/share.html`, `/drp/order/checkOrderState`,
`/public/checkDevVer`, `/public/checkVer`, `/user/forgetpwd.html`.
Most are app-side user-management APIs the cam would never call. We
expect the cam&rsquo;s own traffic pattern to be limited to the
`/preadd/*` namespace plus potentially an OTA update check routed
through `public.dayunlinks.cn`.

### DNS-only (no traffic observed yet)

| Hostname | Real IP | Purpose (inferred) |
|---|---|---|
| `alive.hapsee.cn` | `116.63.81.177` | Keepalive / "I&rsquo;m still online" heartbeat |

The cam did a DNS lookup for this host on some boot cycles but we never
saw it initiate an actual TCP or UDP session to the resolved IP. Might
be triggered by specific firmware states we haven&rsquo;t exercised.

## The brand domains

As of Session 6, four brand domains are confirmed in the stack — three
from the earlier sessions plus one surfaced by decrypting
`/domainname/all`:

1. **`cloudbirds.cn`** — used for NTP wrappers, the Kalay supernode
   hosts (`p2p5`, `p2p6`), analytics (`databuried`), and support
   (`support`). The Dayunlinks / Cloudbirds public-facing brand.
2. **`hapseemate.cn`** — used for the CBS HTTPS control plane
   (`user.hapseemate.cn`, `birds-user.hapseemate.cn`,
   `wechat.hapseemate.cn`), keepalive (`alive.hapsee.cn`), and a
   handful of app-side utility endpoints. The HapSee app brand.
3. **`dayunlinks.cn`** — used for the `public` bootstrap host (OTA
   version checks, `/domainname/all` directory), push notifications
   (`apppush-hapseemate.dayunlinks.cn`), and privacy policy
   (`privacy-policy.dayunlinks.cn`). This is the company name behind
   Cloudbirds.
4. **`aiseebling.com`** — used for payment
   (`payment.aiseebling.com`) and an iOS Universal Link anchor
   (`universallink.aiseebling.com`). Session 7 OSINT traced it back
   to the **same Qianniao OEM cluster** that publishes the V360 Pro
   app: the homepage HTML is a white-label SPA whose commented-out
   `<title>` tags enumerate every sibling brand, including
   `深圳市千鸟祥云技术有限公司` ("Shenzhen Qianniao Xiangyun
   Technology Co., Ltd."), which Google Play Store independently
   lists as the developer of `com.dayunlinks.cloudbirds`. The
   currently-active brand on the domain is `安芯看看` ("AnXin
   KanKan" / Shenzhen Anxinkankan IoT Technology Co., Ltd.),
   hosted on Tencent Cloud Beijing (apex) + Huawei Cloud HK
   (payment). Registered 2025-07-11 via DNSPod.
   See [`18-aiseebling-investigation.md`](18-aiseebling-investigation.md).

Additionally, `public.dayunlinks.cn` CNAMEs through
`birds-public.philipsiot.com` to Signify / Philips IoT infrastructure
at `190.92.254.74`. That makes **Philips** a fifth entity in the
supply chain — probably the actual hosting provider for the
`public.dayunlinks.cn` service, which is the single most trust-critical
endpoint in the whole stack (it emits `/domainname/all`, which
bootstraps every other host).

**Why so many brands?** Because the OEM stack is sold to multiple apps
— V360 Pro, HapSee, HapSee Mate all share the same backend. The
camera&rsquo;s firmware was compiled with both sets of hostnames baked
in so it could service any of the app brands. The Wi-Fi AP SSID prefix
`HAP-` is an artifact of the HapSee heritage. The app&rsquo;s Java
package root `com.qianniao.*` suggests the OEM itself is Qianniao,
operating multiple brands above a shared codebase and backend.

## What the attack needs to intercept

For a complete MITM we need to capture or override:

| Domain/IP | Protocol | Our handling |
|---|---|---|
| `p2p5.cloudbirds.cn` | UDP 32100 Kalay | dnsmasq → `203.0.113.37` → DNAT to Mac:32100 → mitm_supernode_proxy |
| `p2p6.cloudbirds.cn` | UDP 32100 Kalay | same as above |
| `123.56.74.245` | UDP 32100 Kalay | **IP-level** DNAT to Mac:32100 (no DNS) |
| `user.hapseemate.cn` | TCP 443 TLS | dnsmasq → `203.0.113.37` → DNAT TCP/443 to Mac:8443 → mitm_cbs_proxy |
| `public.dayunlinks.cn` | TCP 443 TLS | dnsmasq → `203.0.113.37` → DNAT TCP/443 to Mac:8443 → mitm_cbs_proxy (SNI-dispatched) |
| `*.philipsiot.com` | TCP 443 TLS | dnsmasq → `203.0.113.37` → DNAT TCP/443 to Mac:8443 → mitm_cbs_proxy (SNI-dispatched) |
| `alive.hapsee.cn` | unknown | dnsmasq → `203.0.113.37` (no traffic observed yet, so nothing on Mac side) |
| NTP wrappers | UDP 123 | **Allowed through unmodified** (needed for `utcTime`) |

**Note on sink IP**: earlier sessions used `9.9.9.9` (real Quad9
DNS). Session 6 switched to `203.0.113.37` (TEST-NET-3, RFC 5737) —
a reserved documentation range that no real service operates on,
so a DNAT miss drops packets into the void instead of leaking to
Quad9&rsquo;s logs. See [`09-router-setup.md`](09-router-setup.md) for
the sink IP rationale.

See [`08-attack-chain.md`](08-attack-chain.md) for the full routing
details and [`09-router-setup.md`](09-router-setup.md) for how to actually
configure it.

_Last updated: 2026-04-15 — Session 7_

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
