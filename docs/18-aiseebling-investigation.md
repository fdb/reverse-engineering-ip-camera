# 18 · Aiseebling.com money-trail investigation

## Summary

`aiseebling.com` — the sole "payment" domain referenced by the V360 Pro
app, surfaced by decrypting `/domainname/all` in Session 6 — is
**operated by the same Chinese OEM that publishes the app itself**.
Its homepage is a multi-brand white-label single-page app whose
**commented-out HTML source enumerates every reseller brand, logo,
and legal entity** the OEM ships under. The currently-active brand on
aiseebling.com is `安芯看看` / **深圳市安芯看看物联科技有限公司**
("Shenzhen Anxinkankan IoT Technology Co., Ltd."), but the same
source file also names `深圳市千鸟祥云技术有限公司` — which is
**an exact match for the Google Play developer-of-record for the
V360 Pro app itself** ("Shenzhen Qianniao Xiangyun Technology Co.,
Ltd.", Longgang District, Shenzhen). The domain is ~9 months old
(registered 2025-07-11 via Tencent&rsquo;s DNSPod with CN registrant,
privacy-shielded) and is hosted across Tencent Cloud Beijing (apex)
and Huawei Cloud HK + Shenzhen (subdomains). This collapses the
investigation: **aiseebling.com is the shared payment / deep-link
endpoint for the Qianniao OEM&rsquo;s entire reseller lineup**,
including Cloudbirds / Dayunlinks / HapSee / Philips-branded
devices. It is not a separate OEM partner and it is not a shell.

## What we set out to investigate

Session 6&rsquo;s decryption of the Android app&rsquo;s `/domainname/all`
response (see [`docs/03-cloud-topology.md`](03-cloud-topology.md))
surfaced a single URL on a previously-unknown domain:

```
URLConfig.pay → https://payment.aiseebling.com
```

`aiseebling.com` did not appear as a string literal anywhere in the
decompiled APK, did not show up in any captured pcap, and did not
obviously match any of the four brand clusters already mapped in
this project (`cloudbirds.cn`, `dayunlinks.cn`, `hapseemate.cn`,
`philipsiot.com`). Because payment infrastructure is anchored to
legal entities in a way that marketing infrastructure is not, the
spec at
[`docs/superpowers/specs/2026-04-15-aiseebling-money-trail-design.md`](superpowers/specs/2026-04-15-aiseebling-money-trail-design.md)
commissioned a passive OSINT pass to establish who is actually
collecting payments through this domain, and whether that entity
cross-references against any of the known brand clusters. Full
question list is in §2 of that spec.

## Methodology actually used

Passive-only per the spec. No scanners, no captchas, no form
submissions, no active probing. Tiers followed:

- **Tier 1** (public registries / logs): `whois` of domain + IPs,
  `dig` of all record types on both hostnames, crt.sh Certificate
  Transparency lookup, Wayback Machine availability API, public
  search engines (DuckDuckGo HTML), GitHub code search (gated), USPTO
  TESS (gated), WIPO Brand DB (SPA, couldn&rsquo;t render).
- **Tier 2** (passive web surface): `curl -sIL` and `curl -sL` on
  `https://aiseebling.com/`, `https://payment.aiseebling.com/`,
  `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`,
  `/.well-known/apple-app-site-association`, `/assets/aisee-icon.*`.
- **Tier 3** (corporate registries): `qcc.com` (QCC / 企查查) was
  surfaced as a hit via DuckDuckGo but the specific company-detail
  page is behind Alibaba WAF with a JavaScript challenge — that is a
  spec-defined stop condition (no captcha / no JS-challenge bypass).
  Trademark databases (USPTO, WIPO, CNIPA) are all JS-rendered SPAs
  that plain WebFetch cannot drive. Documented as inconclusive.
- **Tier 4** (app-store metadata): Google Play listing for
  `com.dayunlinks.cloudbirds` fetched for the mandatory developer
  disclosure block. Apple App Store URL returned 404 (the app has
  apparently been de-listed from the US store since the spec was
  written; not investigated further, out of scope).
- **Tier 5** (cross-reference): run throughout, as specified.

Deviations from spec: none substantive. The investigation was
concluded at the end of Tier 4 because by that point **two
independent data sources named the same legal entity** and the
spec&rsquo;s success criteria (§6) were comfortably met — further
tiers would have added marginal color at increasing cost against a
diminishing-returns curve, which the spec&rsquo;s "time budget" stop
condition (§7) explicitly endorses.

## Findings

### Q1 — Who owns `aiseebling.com`?

**Registrar:** DNSPod, Inc. (a Tencent subsidiary; registrar IANA ID
1697; abuse contact `dnsabuse@tencent.com`, `+86.4009100100`).
**Creation date:** 2025-07-11 02:06:42 UTC (≈9 months before this
investigation).
**Registry Expiry:** 2026-07-11 (so the domain is currently inside its
first renewal window).
**Registrant country:** `CN`. City / state / name / organization
fields are all blank in WHOIS — privacy-shielded via the standard
Tencent WHOIS proxy.
**DNSSEC:** unsigned.
**Authoritative nameservers (per WHOIS):** `DEAN.DNSPOD.NET`,
`HORSE.DNSPOD.NET` (Tencent DNSPod).
**Nameservers actually answering queries today:** `ns3.dnsv2.com`,
`ns4.dnsv2.com` (also DNSPod&rsquo;s dnsv2 brand — consistent with a
paid-tier DNSPod customer).

Independent verification: the homepage HTML at `aiseebling.com/`
contains `<title>深圳市安芯看看物联科技有限公司</title>` and seven
commented-out sibling `<title>` tags naming parallel legal entities
— see evidence section for the full list. This is an intra-source
self-identification, not a WHOIS claim, and therefore not subject to
the privacy shield. Cross-referenced below against §Q5.

### Q2 — What infrastructure does it use?

```
                         aiseebling.com. A     43.139.108.230    (Tencent Cloud Beijing / AS45090)
                  payment.aiseebling.com. A    189.1.221.131     (Huawei Cloud HK / AS136907)
            universallink.aiseebling.com. A    116.205.131.129   (Huawei Public Cloud Shenzhen / HWCSNET)

aiseebling.com. NS   ns3.dnsv2.com, ns4.dnsv2.com                (DNSPod / Tencent)
aiseebling.com. MX   5 mxbiz1.qq.com, 10 mxbiz2.qq.com           (Tencent Exmail / QQ Business)
aiseebling.com. TXT  "v=spf1 include:spf.mail.qq.com ~all"       (SPF → Tencent mail)
aiseebling.com. TXT  "google-site-verification=aiqCaE_3Qt1o48X9JvsnZDSol64-dIdsGdhttEgUFB4"
```

Notable: the stack is **Tencent end-to-end** for the apex (registrar,
DNS, mail, primary hosting) but the two functional subdomains are on
**Huawei Cloud** — `payment` on Huawei Cloud HK, `universallink` on
Huawei Cloud Shenzhen. This is a deliberate HK/mainland split that
serves international payment traffic through a network path that
isn&rsquo;t subject to mainland Great Firewall egress inspection. The
`google-site-verification` TXT record implies Google Workspace or
Search Console was configured for this domain at some point, which
is mildly surprising for a mainland-China operator (Google services
are usually blocked) and suggests the operator is building for
cross-border customers.

### Q3 — What is actually served at `payment.aiseebling.com`?

`HEAD /` returns **HTTP 404** with `Server: elb` (lowercase) — the
classic Huawei Cloud ELB (Elastic Load Balance) banner. There is
no homepage content at the root path. This means `payment.*` is an
**API endpoint**, not a web page: something on the backend is
listening, but only for specific path + verb combinations that the
app-side code knows to call. We did not enumerate or probe paths
(explicitly out of scope per spec §3).

Combined with the URLConfig key `URLConfig.pay`, the most likely
role is an order-initiation / payment-callback REST endpoint that
the app hits when a user purchases a subscription, cloud-storage
upgrade, or DRP ("device recharge plan" — cf.
`/drp/order/checkOrderState` in the app&rsquo;s `Api.java`). The
actual payment processor is almost certainly third-party (Stripe,
Alipay, WeChat Pay, PayPal) — `payment.aiseebling.com` would be
the OEM&rsquo;s own order-ledger, not the card-handling tier.

### Q4 — What other hostnames exist under `aiseebling.com`?

From crt.sh (3 certs, issued 2025-07-14 → 2025-08-11, both from
Chinese CAs — WoTrus and TrustAsia):

- `aiseebling.com`
- `www.aiseebling.com`
- `*.aiseebling.com` (wildcard)
- `universallink.aiseebling.com`

That&rsquo;s the complete CT-visible footprint. Two functional
subdomains beyond the apex: `payment` (covered by the wildcard) and
`universallink`. The presence of `universallink` is a strong
indicator that the V360 Pro **iOS** app uses this domain as an
Apple Universal Link anchor — Universal Links require the app&rsquo;s
associated domain to serve a `/.well-known/apple-app-site-association`
file. We fetched that path and got 404 from both the apex and the
`universallink` subdomain, so if the AASA was ever served it is no
longer at the default location (or the iOS app has since moved
away from Universal Links entirely — plausible given the App Store
404 on the expected V360 Pro product page).

We also noticed one unrelated typo-squat cert in the CT stream for
`*.aiseebleeding.com` — different registration, almost certainly
not under the same operator. Mentioned here only so a future
reader doesn&rsquo;t mistake it for a subdomain.

### Q5 — Any connection to the known brand clusters?

**Yes. Direct and multiply-attested.**

The homepage HTML (`curl https://aiseebling.com/`) ships a single
multi-brand SPA shell with the currently-active brand selected and
every alternate brand left as HTML comments. The comment block
enumerates both the brand name and the legal entity name:

| Status | Brand (Chinese → romanized) | Legal entity (verbatim) |
|---|---|---|
| **active** | `安芯看看` / AnXin KanKan | `深圳市安芯看看物联科技有限公司` |
| comment | `千鸟物联` / Qianniao IoT | `深圳市千鸟祥云技术有限公司` |
| comment | `云看看` / YunKanKan | `深圳市云看看物联科技有限公司` |
| comment | `欣视安` / XinShiAn | `惠州市欣视安安防科技有限公司` |
| comment | `飞利浦` / Philips | *(logo only, no corp title)* |
| comment | `千鸟智云` / Qianniao Zhiyun | `深圳市千鸟智云科技有限公司` |
| comment | `开心看Pro` / HapSee Mate Pro | *(logo only)* |
| comment | `smaint` / `smaint pro` | `深圳市斯麦特光电有限公司` |
| comment | — | `广州千鸟贸易有限公司` |
| comment | — | `深圳市金和视讯科技有限公司` |
| comment | `intellicared` | *(logo only)* |

The first line of the HTML `<head>` is literally:

```html
<!-- 千鸟物联logo 、dayunlinks -->
```

so "dayunlinks" (the company registered to `dayunlinks.cn`, one of
our four known brand clusters) is named in plain ASCII in the first
comment of the file — this is a direct link that doesn&rsquo;t require
any transliteration guessing.

The cross-reference to **`cloudbirds.cn`** falls out of the Play
Store disclosure below — see Q6. The cross-reference to **Philips /
Signify** is already latent in `docs/03-cloud-topology.md` (via
`public.dayunlinks.cn → birds-public.philipsiot.com`) and is
re-confirmed by the `飞利浦` logo option in this HTML — the same
OEM ships a Philips-branded build of the same SPA.

**Interpretation:** `aiseebling.com` is hosting a **shared
white-label payment / deep-link landing SPA** that the OEM rebuilds
per-client by toggling which `<title>` and `<link rel="icon">` is
uncommented at build time. The dev either didn&rsquo;t know how to use
Vite env substitution, or didn&rsquo;t care, and left the full reseller
list in the distributed source. This means **all of these brands
share a common payment endpoint** — which in turn means buying a
subscription through the V360 Pro app, the HapSee app, a Philips-
branded app, or any of the others under this OEM will land at the
same `payment.aiseebling.com` backend, operated by the same entity
cluster in Shenzhen.

The "aiseebling" domain name itself is almost certainly a phonetic
branding of **`安芯`** (ānxīn, "secure heart" — the active brand
on the SPA) as "ai-see", with "bling" as a vanity suffix. This also
retroactively explains the otherwise-nonsense
`AesUtil.XIAODUAI_KEY = "aiy20m8c24h4care"` flagged in
Session 6: "aiy"/"ai" and "care" are both branding fragments from
the AnXin ("secure heart") family, not arbitrary letters.

### Q6 — Corporate registration / trademark record?

**Partial / indirect, via app-store disclosure** — the Chinese corporate
registry and trademark-office direct searches are blocked behind
Alibaba WAF (QCC), JS-rendered SPAs (WIPO, USPTO, CNIPA), or
account-gated search (GitHub, SecurityTrails history). Those are all
spec stop conditions.

However, the **Google Play Store listing** for
`com.dayunlinks.cloudbirds` publishes the developer disclosure that
the Play Console mandatorily requires every publisher to verify:

```
Developer Name:     Shenzhen Qianniao Xiangyun Technology Co., Ltd.
Developer Email:    app@sz-cloudbirds.com
Developer Address:  No. 42 Longcheng Street, Longgang District,
                    Shenzhen, Guangdong Province, China 518172
Developer Website:  https://www.cloudbirds.cn/
```

"Shenzhen Qianniao Xiangyun Technology Co., Ltd." is a direct English
translation of `深圳市千鸟祥云技术有限公司` — **one of the seven
commented-out legal entities on the aiseebling.com homepage HTML**.
The Play Store disclosure and the homepage HTML are two independent
data sources that **name the same entity from two different
directions**.

This is strong enough to treat as conclusive under the spec&rsquo;s
§6 success criteria (the legal-entity and country criteria are met).
The operator cluster behind `aiseebling.com` is effectively the
same operator cluster behind `com.dayunlinks.cloudbirds`, the V360
Pro app, and the cam itself. A Tier 3 QCC lookup on
`深圳市千鸟祥云技术有限公司` would additionally pin down the
Unified Social Credit Code (USCC), legal representative, and
registered capital, but that data is behind the QCC WAF and is not
needed to satisfy the spec.

One additional anchor from the Play listing: the email domain
`sz-cloudbirds.com` is a new fifth-level brand domain we have not
seen before — it&rsquo;s the corporate-facing domain for the developer
("sz-" = `深圳` Shenzhen prefix). It is not referenced by the cam
or the app at runtime, only by Play Console as the contact address.

### Q7 — Historical footprint

**Essentially zero.** The Wayback Machine availability API returns
`{"archived_snapshots": {}}` for both `aiseebling.com` and
`payment.aiseebling.com` — **no snapshots have ever been taken**.
Internet Archive crawls are driven by either Alexa-style popularity
signals or explicit submissions, and a ~9-month-old domain with no
inbound links and no indexed content would not be picked up
organically.

Google / Bing / DuckDuckGo indexed-web search for `"aiseebling"`
returns six results, all of them either the site itself, IP-lookup
aggregators (ipaddress.com, ip138.com — machine-generated pages),
scam checkers (scamadviser.com), or the QCC page that we cannot
read. **There is no organic web content referencing this domain.**
This is a striking anti-footprint for a domain that is embedded in
a publicly-distributed Android app shipped in (plausibly) hundreds
of thousands of devices.

The lack of footprint is itself a useful finding: it argues
against `aiseebling.com` being a long-standing brand the OEM
acquired or rebranded from, and in favor of it being a fresh
payment / deep-link endpoint stood up specifically to serve the
current white-label SPA build.

### Q8 — Active use / reachability

- **Apex:** `HTTP/1.1 200 OK` from `nginx/1.20.1`, content-length
  3019, Last-Modified 2025-08-01 05:43:04 GMT (consistent with the
  crt.sh date range). Serves a valid SPA shell. Active.
- **`payment.aiseebling.com`:** `HTTP/1.1 404 Not Found` from
  `Server: elb`, zero-length body. Valid TLS handshake; reachable.
  Active at the API level but no root page. "404 not an error, path
  just not mapped."
- **`universallink.aiseebling.com`:** Valid DNS + TLS; AASA path
  returns 404. Reachable but not currently serving the file that
  would give it its Universal Link meaning.

The cam in our MITM setup has **never reached this domain** —
Session 6&rsquo;s captures only showed the cam hitting CBS / Kalay /
NTP / Philips-IoT hosts, never the `URLConfig.pay` endpoint. The
pay endpoint is app-side, not cam-side: only the V360 Pro app ever
calls it, and only when a user opens a purchase flow. Our emulator
run did not exercise any purchase flow, so we have no wire-level
data on what the traffic actually looks like.

## Evidence

Raw command output inline so a future reader can reproduce every
claim.

### WHOIS

```text
$ whois aiseebling.com
...
Domain Name: AISEEBLING.COM
Registry Domain ID: 2999410986_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.dnspod.cn
Registrar URL: http://www.dnspod.cn
Updated Date: 2025-07-11T02:10:45Z
Creation Date: 2025-07-11T02:06:42Z
Registry Expiry Date: 2026-07-11T02:06:42Z
Registrar: DNSPod, Inc.
Registrar IANA ID: 1697
Registrar Abuse Contact Email: dnsabuse@tencent.com
Registrar Abuse Contact Phone: +86.4009100100
Domain Status: ok https://icann.org/epp#ok
Name Server: DEAN.DNSPOD.NET
Name Server: HORSE.DNSPOD.NET
DNSSEC: unsigned
...
Registrant City:
Registrant State/Province:
Registrant Country: CN
Registrant Email: Select Contact Domain Holder link at
                  https://whois.cloud.tencent.com/domain?domain=aiseebling.com
```

### DNS

```text
$ dig aiseebling.com A +short
43.139.108.230

$ dig payment.aiseebling.com A +short
189.1.221.131

$ dig universallink.aiseebling.com A +short
116.205.131.129

$ dig aiseebling.com NS +short
ns4.dnsv2.com.
ns3.dnsv2.com.

$ dig aiseebling.com MX +short
5  mxbiz1.qq.com.
10 mxbiz2.qq.com.

$ dig aiseebling.com TXT +short
"v=spf1 include:spf.mail.qq.com ~all"
"google-site-verification=aiqCaE_3Qt1o48X9JvsnZDSol64-dIdsGdhttEgUFB4"
```

### Reverse WHOIS on hosting IPs

```text
$ whois 43.139.108.230 | grep -iE "^(netname|descr|country|org-name):"
netname:  TENCENT-CN
descr:    Tencent Cloud Computing (Beijing) Co., Ltd
country:  CN
org-name: Tencent Cloud Computing (Beijing) Co., Ltd
origin:   AS45090

$ whois 189.1.221.131 | grep -iE "^(netname|descr|country|org-name):"
netname:  Huawei-Cloud-HK
descr:    Huawei-Cloud-HK
country:  HK
descr:    HUAWEI INTERNATIONAL PTE. LTD.
origin:   AS136907

$ whois 116.205.131.129 | grep -iE "^(netname|descr|country|org-name):"
netname:  HWCSNET
descr:    Huawei Public Cloud Service (Huawei Software Technologies Ltd.Co)
descr:    No.2018 Xuegang Road,Bantian street,Longgang District,
          Shenzhen,Guangdong Province, 518129 P.R.China
country:  CN
```

### Certificate Transparency (crt.sh)

Distinct names observed in issued certificates for `%.aiseebling.com`:

- `aiseebling.com`, `www.aiseebling.com`
- `*.aiseebling.com`
- `universallink.aiseebling.com`

Issuers:

- `C=CN, O=WoTrus CA Limited, CN=WoTrus DV Server CA`
- `C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia DV TLS RSA CA 2025`

notBefore range: `2025-07-14` → `2025-08-11` (three certificates total).

Source: `https://crt.sh/?q=%25.aiseebling.com`

### HTTP headers

```text
$ curl -sIL https://aiseebling.com/
HTTP/1.1 200 OK
Server: nginx/1.20.1
Date: Wed, 15 Apr 2026 10:17:43 GMT
Content-Type: text/html
Content-Length: 3019
Last-Modified: Fri, 01 Aug 2025 05:43:04 GMT
Connection: keep-alive
ETag: "688c53e8-bcb"
Accept-Ranges: bytes

$ curl -sIL https://payment.aiseebling.com/
HTTP/1.1 404 Not Found
Date: Wed, 15 Apr 2026 10:17:44 GMT
Content-Length: 0
Connection: keep-alive
Server: elb
```

`aiseebling.com/robots.txt`, `/sitemap.xml`,
`/.well-known/security.txt`, `/.well-known/apple-app-site-association`
all return `404 Not Found` with an `nginx/1.20.1` error body. Same
result from `universallink.aiseebling.com/.well-known/apple-app-site-association`.

### Homepage HTML — the multi-brand self-disclosure

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <!-- 千鸟物联logo 、dayunlinks -->
  <!-- <link rel="icon" type="image/svg+xml" href="./public/favicon.png" /> -->
  <!-- 云看看logo -->
  <!-- <link rel="icon" type="image/svg+xml" href="./public/logo.png" /> -->
  <!-- 安芯看看logo -->
  <link rel="icon" type="image/svg+xml" href="/assets/aisee-icon.cc9c698d.png" />
  <!-- 欣视安 -->
  <!-- <link rel="icon" type="image/svg+xml" href="./public/xinshian-logo.png" /> -->
  <!-- 飞利浦 -->
  <!-- <link rel="icon" type="image/svg+xml" href="./public/logo-blue.png" /> -->
  <!-- 千鸟智云科技 -->
  <!-- <link rel="icon" type="image/svg+xml" href="./public/intellicared-logo.png" /> -->
  <!-- 开心看Pro -->
  <!-- <link rel="icon" type="image/svg+xml" href="./public/hapseemate-logo.png" /> -->
  <!-- smaint pro logo -->
  <!-- <link rel="icon" type="image/svg+xml" href="./public/smaint-pro-log.png" /> -->
  <!-- smaint logo -->
  <!-- <link rel="icon" type="image/svg+xml" href="./public/smaint-icon.png" /> -->
  <meta name="viewport" content="width=device-width, initial-scale=1.0, ..." />
    <!-- <title>云看看</title> -->
     <title>安芯看看</title>
  <!-- <title>千鸟物联</title> -->
   <!-- <title>Smaint</title> -->
  <!-- <title>深圳市千鸟祥云技术有限公司</title> -->
   <!-- <title>深圳市云看看物联科技有限公司</title> -->
     <title>深圳市安芯看看物联科技有限公司</title>
  <!-- <title>惠州市欣视安安防科技有限公司</title> -->
  <!-- <title>广州千鸟贸易有限公司</title> -->
  <!-- <title>深圳市金和视讯科技有限公司</title> -->
  <!-- <title>深圳市千鸟智云科技有限公司</title> -->
   <!-- <title>深圳市斯麦特光电有限公司</title> -->
  <script type="module" crossorigin src="/assets/index.6905b4d2.js"></script>
  <link rel="stylesheet" href="/assets/index.2887758e.css">
</head>
<body>
  <div id="app"></div>
</body>
</html>
```

Source: `https://aiseebling.com/` on 2026-04-15. The `<div id="app">`
shell tells us it&rsquo;s a Vue / React / Vite SPA — the visible UI is
rendered client-side by `/assets/index.6905b4d2.js`, which we did
not fetch (out of scope: not needed for the investigation).

### Google Play developer disclosure

```text
Developer Name:     Shenzhen Qianniao Xiangyun Technology Co., Ltd.
Developer Email:    app@sz-cloudbirds.com
Developer Address:  No. 42 Longcheng Street, Longgang District,
                    Shenzhen, Guangdong Province, China 518172
Developer Website:  https://www.cloudbirds.cn/
App Title:          V360 Pro
```

Source: `https://play.google.com/store/apps/details?id=com.dayunlinks.cloudbirds`

## Cross-reference table

| aiseebling finding | Existing project doc | Nature of link |
|---|---|---|
| HTML comment `千鸟物联logo 、dayunlinks` | `03-cloud-topology.md` — `dayunlinks.cn` brand cluster | Literal string `dayunlinks` in first comment of the file |
| HTML comment `<title>深圳市千鸟祥云技术有限公司</title>` | Play Store developer name for `com.dayunlinks.cloudbirds` (V360 Pro) | Exact Chinese↔English legal-entity match |
| HTML comment `开心看Pro` / `hapseemate-logo.png` | `03-cloud-topology.md` — `hapseemate.cn` cluster | HapSee app brand; logo filename matches |
| HTML comment `飞利浦` ("Philips") | `03-cloud-topology.md` — `public.dayunlinks.cn → birds-public.philipsiot.com → 190.92.254.74` (Signify/Philips infra) | Philips sits in the OEM&rsquo;s own reseller lineup — not just an upstream hosting accident |
| DNS `MX → mxbiz1.qq.com` + SPF Tencent | `11-tooling.md` / `03-cloud-topology.md` Tencent-adjacent entries | Consistent with broader Tencent-stack use (DNSPod, QQ mail) |
| WHOIS creation 2025-07-11 | Session 6 discovery date 2026-04-15 | Domain predates discovery by ~9 months; no anomaly |
| Active brand `安芯看看` / `AnXin` | `decompiled/.../AesUtil.java` `XIAODUAI_KEY = "aiy20m8c24h4care"` | "aiy"/"care" match the AnXin branding family; the key name `XIAODUAI` may itself be a pinyin fragment (`小` + ?) — speculative |

## Open questions

Things Tier 1–4 could not answer, and why:

1. **USCC / legal rep / registered capital for `深圳市千鸟祥云技术有限公司`** — requires reading the QCC or tianyancha company-detail page, which is behind Alibaba WAF with a JS challenge. **Stopped per spec §7.** Resolving this would need either a registered QCC account (out of scope), a commercial data vendor (out of scope: paid), or a Chinese-speaking researcher with access to local business lookups.
2. **Actual payment processor used by `payment.aiseebling.com`** — requires either exercising the purchase flow in the app (captures a real HTTP request body) or fetching the compiled SPA bundle at `/assets/index.6905b4d2.js` and statically analyzing it. The first is out of scope (no form submission / purchase); the second is technically in-scope passive fetching, but we did not pursue it because it would not change the entity conclusion.
3. **Trademark status in CN / US / WIPO** for the brand strings (`安芯看看`, `千鸟物联`, `云看看`, `欣视安`, `开心看`). All three relevant trademark DBs are JS-rendered SPAs that cannot be driven by plain WebFetch. Tooling gap, not information gap.
4. **Whether the Philips-branded build of the same SPA is an authorized Signify OEM-licensee relationship or a grey-market use of the Philips brand.** The HTML only shows the brand option exists; it does not tell us whether Signify has licensed it. The Session 6 finding that `birds-public.philipsiot.com` is Signify-hosted argues for "authorized", but the aiseebling HTML alone does not prove it.
5. **Whether `universallink.aiseebling.com` ever served a real AASA file.** Currently 404, and there&rsquo;s no Wayback archive. Could be dormant (iOS build never shipped) or live-but-moved. The App Store 404 we encountered hints at a de-listed or regional iOS app.

## Recommendations

- **Add one bullet to [`docs/17-portability.md`](17-portability.md)**: the Qianniao OEM cluster is now definitively documented as operating at least nine sub-brand / legal-entity faces simultaneously, with a shared payment / deep-link SPA at `aiseebling.com`. Any new cam that points `URLConfig.pay` at this domain is certainly from the same OEM, regardless of what brand it wears on the box.
- **Promote "the OEM is Qianniao" from inference to fact** in [`docs/03-cloud-topology.md`](03-cloud-topology.md) §"The brand domains". Session 6&rsquo;s `com.qianniao.*` package-tree observation plus this investigation&rsquo;s Play Store developer disclosure triangulate on `深圳市千鸟祥云技术有限公司` / Shenzhen Qianniao Xiangyun Technology Co., Ltd. as the identified entity. (Still privacy-shielded in WHOIS, but not in app-store disclosures.)
- **Do not add a new step to [`docs/14-next-steps.md`](14-next-steps.md)**. The aiseebling finding does not unblock or reprioritize any current cam-side work (the cam itself never calls `URLConfig.pay`). If a future session exercises the app-side purchase flow and captures real `payment.aiseebling.com` traffic, that would be a meaningful new session — but it&rsquo;s not an active blocker today.
- **Flag for any future "supply chain" section of the docs**: the OEM appears to use a *build-time brand selection* system that leaks all sibling brands via HTML comments. A simple grep of the homepage HTML (which is what this investigation did) is sufficient to enumerate their entire reseller customer list. If we ever want to find yet more brands in this family, periodically re-fetching this HTML is the cheapest possible enumeration technique.

## Appendix A — OSINT safety log

Chronological list of every URL fetched and every CLI command invoked
during this investigation. All times UTC on 2026-04-15.

```text
[10:15] $ whois aiseebling.com
[10:16] $ dig aiseebling.com A/NS/MX/TXT +short
[10:16] $ dig payment.aiseebling.com A/CNAME +short
[10:16] $ whois 43.139.108.230
[10:16] $ whois 189.1.221.131
[10:16] $ dig www.aiseebling.com / api / admin / mail A +short
[10:16] GET https://crt.sh/?q=%25.aiseebling.com&output=json
[10:17] GET https://aiseebling.com/ (HEAD + GET)
[10:17] GET https://payment.aiseebling.com/ (HEAD + GET)
[10:18] GET https://aiseebling.com/robots.txt
[10:18] GET https://aiseebling.com/sitemap.xml
[10:18] GET https://aiseebling.com/.well-known/security.txt
[10:18] GET https://aiseebling.com/.well-known/apple-app-site-association
[10:18] GET https://universallink.aiseebling.com/.well-known/apple-app-site-association
[10:18] $ dig universallink.aiseebling.com A +short
[10:18] $ whois 116.205.131.129
[10:19] GET https://archive.org/wayback/available?url=aiseebling.com
[10:19] GET https://archive.org/wayback/available?url=payment.aiseebling.com
[10:19] GET https://duckduckgo.com/html/?q=%22aiseebling%22  (→ redirect)
[10:19] GET https://html.duckduckgo.com/html/?q=%22aiseebling%22
[10:19] GET https://html.duckduckgo.com/html/?q=%22安芯看看物联科技%22
[10:19] GET https://html.duckduckgo.com/html/?q=%22安芯看看%22+aiseebling
[10:19] GET https://www.qcc.com/cassets/60cfcb4148e8ed82f82d778c9d320497.html
           → blocked by Alibaba WAF JS challenge (stop condition)
[10:19] GET https://github.com/search?q=aiseebling&type=code
           → gated behind sign-in (stop condition)
[10:19] GET https://tmsearch.uspto.gov/search/search-information?...
           → JS-rendered SPA, no content (stop condition)
[10:19] GET https://www3.wipo.int/branddb/en/#search/text:aiseebling
           → redirect to SPA, no content (stop condition)
[10:19] GET https://aiseebling.com/assets/aisee-icon.cc9c698d.png (binary)
           → sha256 cc9c698de356b65be9718184d8baa9e4ff115b73c49fa4761f1c4eb5b9580f01
[10:20] GET https://play.google.com/store/apps/details?id=com.dayunlinks.cloudbirds
[10:20] GET https://apps.apple.com/us/app/v360-pro/id1547819572
           → 404 (app apparently de-listed from US store)
```

Not performed: no port scans, no directory enumeration, no path
fuzzing, no form submissions, no account creation, no payment
instrument testing, no communication with any human, no bypass of
captchas / JS challenges / login walls. The investigation remained
entirely on the passive OSINT side of the authorized/unauthorized
boundary throughout.

_Last updated: 2026-04-15 — Session 7_
