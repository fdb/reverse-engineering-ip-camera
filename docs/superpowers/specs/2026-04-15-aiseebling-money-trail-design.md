# Aiseebling.com money-trail — investigation spec

**Date:** 2026-04-15
**Session origin:** Session 6 (Cloudbirds IP cam RE project)
**Status:** Draft, awaiting investigator
**Target executor:** A fresh Claude Code session — **no prior project context is required**, only what is in this file plus the project `docs/` tree.

---

## 0. Before you start — orientation for a cold-start reader

You are picking up a spec-driven task inside a reverse-engineering
project that lives at
`/Users/fdb/ReverseEngineering/cloudbirds-ip-cam`. The project
investigates a cheap OEM IP camera branded as V360 Pro / Cloudbirds /
HapSee, so its owner can run it on an isolated home network without it
phoning home to Chinese cloud backends.

**Read these three files first, in order** — they contain everything
you need about the project:

1. `docs/README.md` — the index
2. `docs/00-overview.md` — headline results and goals
3. `docs/03-cloud-topology.md` — the full list of hostnames the app
   and cam reach out to, and what each one does

You do **not** need to read any code, run any proxies, or touch the
emulator / router state. This task is 100% OSINT and documentation.

---

## 1. Why this investigation exists

During Session 6, the main project decrypted the Android app&rsquo;s
`/domainname/all` response. That endpoint returns a JSON dictionary
where every service-name key maps to an AES-128-ECB ciphertext of a
URL; the app decrypts each value at runtime using
`AesUtil.URL_KEY = "24QLQzq5DZjy4boX"` (hardcoded in
`decompiled/sources/com/qianniao/base/utils/AesUtil.java`). Full
decrypted table is in `docs/03-cloud-topology.md` §"CBS control plane."

Nine of the ten decrypted URLs pointed at hostnames we already knew
about (under `cloudbirds.cn`, `dayunlinks.cn`, `hapseemate.cn`, or
`birds-public.philipsiot.com`). **One pointed at a domain we had
never seen anywhere in the stack before**:

```
URLConfig.pay → https://payment.aiseebling.com
```

`aiseebling.com` is a genuine anomaly:

- It does not appear as a string literal anywhere in the decompiled
  Java sources (grep `decompiled/sources/com/qianniao/**` for
  "aiseebling" — zero hits outside this one runtime-decrypted value).
- It does not appear in any captured network traffic (our Session 6
  emulator run never reached the payment flow).
- It is not related by spelling or pattern to any of the known brand
  domains (Cloudbirds, Dayunlinks, HapSee, Qianniao, Signify-Philips).
- The only other token "aiseebling" shows up in is as a substring
  possibility of `AesUtil.XIAODUAI_KEY = "aiy20m8c24h4care"` — the
  "aiy..." prefix *might* be a Chinese transliteration fragment but
  this is speculative.

**Why follow this thread**: payment domains are load-bearing in a
way that most other domains are not. A domain used for serving a
homepage can be registered by anyone to anything and hosted on any
CDN anonymously. A domain used for **accepting real payments** has
to be backed by a legal entity that can actually receive money from a
payment processor, which means:

- A real bank account at a real financial institution
- A real legal name registered with that institution
- Usually: a merchant agreement with a real payment processor (Stripe,
  Alipay, WeChat Pay, etc.) that also has "know your customer"
  requirements
- Usually: trademark / incorporation filings visible in a public
  registry

Any of those produces a public information chain that a determined
OSINT pass can walk back to a named entity. Once we have a named
entity, we can cross-reference it against the known brand chain in
`03-cloud-topology.md` — and if there&rsquo;s overlap, we may be able to
unmask the whole OEM supply chain for the Qianniao / Kalay / CS2 PPPP
camera family, not just this one brand.

**What that would be worth**: knowing the real operator of the OEM
stack would help the portability work in `docs/17-portability.md`
(which other camera brands share this backend?) and would give the
project&rsquo;s readers a clear understanding of who they&rsquo;re actually
giving their Wi-Fi credentials and video streams to when they run
this class of device.

---

## 2. What we already know (and don&rsquo;t)

**Known** (from Session 6):

- `aiseebling.com` appears at exactly one location: `URLConfig.pay` in
  the decrypted `/domainname/all` response, full value
  `https://payment.aiseebling.com`.
- The other decrypted domains fit into one of four brand clusters:
  `*.cloudbirds.cn`, `*.dayunlinks.cn`, `*.hapseemate.cn`, and
  `*.philipsiot.com`. See `docs/03-cloud-topology.md` for the full
  map.
- The Android app package is `com.dayunlinks.cloudbirds`, Java package
  root is `com.qianniao.*`. The OEM legal name is almost certainly
  **Qianniao** (千牛, Chinese for "thousand oxen") or a subsidiary /
  holding entity with that name.
- No other string literal "aiseebling" exists in the decompiled APK
  — confirmed with grep.

**Unknown** (the questions this investigation should answer):

1. **Who owns `aiseebling.com`?** Registrar, registration date,
   registrant organization (if not privacy-shielded), registrant
   country, name servers, historical WHOIS if current is private.
2. **What infrastructure does it use?** A records for `aiseebling.com`
   and `payment.aiseebling.com`, MX records, NS records, any TXT
   records (SPF/DKIM/DMARC often leak the email provider), HTTP
   response headers from the homepage.
3. **What is actually served at `payment.aiseebling.com`?** Is it a
   first-party payment page, an embedded Stripe/Alipay/WeChat Pay
   widget, a redirect to a third-party processor, or something else?
   Passive HTTP GET only — do **not** submit any form data.
4. **What other hostnames exist under `aiseebling.com`?** Certificate
   Transparency logs reveal every cert ever issued for
   `*.aiseebling.com`, which usually reveals internal subdomains
   (dev, staging, admin, etc.) that were never meant to be public.
5. **Does `aiseebling.com` connect back to any of the known brands?**
   Shared WHOIS registrant, shared IP hosting cluster, shared
   favicon, shared CDN, shared analytics tracker IDs, or any
   corporate-registry link between its operator and Dayunlinks /
   Cloudbirds / HapSee / Qianniao.
6. **Is there a corporate registration record?** In Chinese business
   registries (qichacha, tianyancha), or US/EU/WIPO trademark
   databases, or similar.
7. **Historical footprint**: Wayback Machine snapshots, when the
   domain first appeared, what was on it originally. Domains
   sometimes reveal their origin story through old pages.
8. **Is this domain actually in active use**? The app references it
   but we&rsquo;ve never seen the app actually reach it. Does
   `payment.aiseebling.com` respond at all? Return an HTTP 200? Have
   a TLS cert? Is it running on a CDN that returns a generic landing
   page?

---

## 3. Scope

### In scope

- **Passive OSINT**: `whois`, `dig`, crt.sh, archive.org Wayback
  Machine, search engines (Google, Bing, DuckDuckGo), GitHub code
  search, public trademark databases (USPTO, WIPO, CNIPA if
  accessible), public Chinese corporate registries (qichacha,
  tianyancha) — any of these via web fetch or native CLI.
- **Read-only HTTP GETs** against `aiseebling.com` and
  `payment.aiseebling.com`: homepage, `/robots.txt`, `/sitemap.xml`,
  `/.well-known/security.txt`, `/favicon.ico`. Capture HTTP response
  headers for server / CDN fingerprinting.
- **Cross-referencing** anything found against the existing project&rsquo;s
  known-domain map in `docs/03-cloud-topology.md` and the brand
  notes in `docs/16-portability.md`.
- **Writing new documentation**: a new file
  `docs/18-aiseebling-investigation.md`, plus minor cross-reference
  updates to `docs/03-cloud-topology.md`, `docs/12-session-log.md`,
  and `docs/README.md`.
- **Committing the result** to git with an appropriate message.

### Out of scope

- **Any active probing**: no port scans, no `nmap`, no directory
  enumeration, no path fuzzing, no vulnerability testing, no
  Metasploit, no dirbuster, no gobuster, no nuclei, no subfinder
  against live hosts.
- **Any form submission**: do not create accounts, do not enter
  email addresses, do not submit the registration form even with
  a throwaway email, do not solve captchas.
- **Any payment activity**: do not click "Pay Now," do not enter
  card numbers (even test cards), do not connect any payment
  instrument.
- **Any communication with humans**: no emails to registrants,
  no Slack/Twitter/LinkedIn DMs, no contact form submissions.
- **Modifying the cam project&rsquo;s live state**: do not touch the MITM
  proxies, do not SSH to the UDM router, do not start the emulator,
  do not read from `captures/` (that&rsquo;s gitignored and private to
  the main project).
- **Reading or modifying any files containing real personal data**:
  the Session 6 captures include a masked throwaway email and a
  real home WAN IP; those are not relevant to this investigation
  and should not be in your report.
- **Vulnerability disclosure**: if you find something that looks
  like a security issue (exposed backup file, leaked credentials,
  misconfigured bucket), document its existence in your report
  and MOVE ON. Do not exploit, probe further, or attempt to
  reach out to the vendor.

### Legal / ethical framing

This is **OSINT research on a commercial entity with legitimate
product-research motivation**: the project owner owns a camera
purchased from this OEM and has a reasonable interest in knowing
which legal entity the product connects to. It is **not** authorized
security testing, and nothing in this investigation can cross into
active behavior that would constitute unauthorized access or
probing under any jurisdiction.

The rule of thumb: **if you can imagine a curious consumer doing
this action from their home internet connection without any special
tooling, it&rsquo;s in scope**. If it requires exploit tooling, scanner
behavior, or credentials, it&rsquo;s out of scope.

---

## 4. Methodology — ordered investigation tiers

Start with Tier 1. Only escalate to a later tier if earlier tiers
didn&rsquo;t produce a conclusive answer to the corresponding question
in §2. Time-budget each tier.

### Tier 1 — Public registries and logs (target: 30 min)

| Step | Action | Captures |
|---|---|---|
| 1.1 | `whois aiseebling.com` from the shell; also try web WHOIS (`who.is`, `whoisfreaks.com`, `whoxy.com`) for an independent readback | registrar, creation date, registrant org/country, name servers, admin-email domain |
| 1.2 | Historical WHOIS via `securitytrails.com` (free tier) or `whoxy.com` history view — current records are often privacy-shielded but pre-2018 records may expose the original registrant | original registrant if private now |
| 1.3 | `dig aiseebling.com A`, `dig payment.aiseebling.com A`, `dig aiseebling.com MX`, `dig aiseebling.com NS`, `dig aiseebling.com TXT` | hosting IP, email provider, SPF/DKIM signatures |
| 1.4 | Reverse-WHOIS on each IP from step 1.3 — `whois <ip>` — to find the hosting provider&rsquo;s netblock owner | hosting provider, geo |
| 1.5 | Certificate Transparency logs: `https://crt.sh/?q=aiseebling.com` and `https://crt.sh/?q=%25.aiseebling.com` — list every cert ever issued, note unique subdomain names, CA used, issue dates | subdomains, CA |
| 1.6 | Wayback Machine: `https://web.archive.org/web/*/aiseebling.com` and `https://web.archive.org/web/*/payment.aiseebling.com` — oldest snapshots, any snapshots showing contact/About pages with company names | historical content, first-seen date |
| 1.7 | GitHub code search: `https://github.com/search?q=aiseebling&type=code` — any SDK, sample code, or library that mentions this domain | integration code |
| 1.8 | Google / Bing / DuckDuckGo for `"aiseebling.com"` (quoted) and `"aiseebling"` (unquoted). Also `site:aiseebling.com` for indexed content | brand mentions |

### Tier 2 — Passive web surface (target: 10 min)

| Step | Action | Captures |
|---|---|---|
| 2.1 | `curl -sIL https://aiseebling.com` and `curl -sIL https://payment.aiseebling.com` | HTTP headers, server banner, X-Powered-By, CDN fingerprints (CF-Ray, X-Amz-*, X-Served-By) |
| 2.2 | `curl -sL https://aiseebling.com/` — capture the HTML, look at `<title>`, `<meta name="description">`, `<meta name="author">`, any ICP license number in the footer (Chinese-hosted sites are legally required to display it), any copyright string with a year+entity | visible brand, legal entity, country |
| 2.3 | `curl -sL https://payment.aiseebling.com/` — same treatment | payment provider embed signature |
| 2.4 | `curl -sL https://aiseebling.com/robots.txt` and `/sitemap.xml` — directories disallowed here often name the framework / brand | site structure |
| 2.5 | `curl -sL https://aiseebling.com/.well-known/security.txt` — security contact if any | contact |
| 2.6 | Fetch `https://aiseebling.com/favicon.ico`, compute the mmh3 hash (e.g., `python3 -c "import mmh3, base64, requests; print(mmh3.hash(base64.encodebytes(requests.get('https://aiseebling.com/favicon.ico').content)))"` — if mmh3 isn&rsquo;t installed, just take the SHA-256 and note that; `mmh3` is what Shodan uses but SHA-256 is also fine for cross-referencing) | favicon fingerprint |
| 2.7 | **If mmh3 hash available**: search Shodan with `http.favicon.hash:<hash>` via the free web UI at `https://www.shodan.io/search?query=http.favicon.hash%3A<hash>` — identical favicons often mean "same operator" | other sites run by the same entity |

### Tier 3 — Chinese / international corporate registries (target: 20 min, if Tier 1–2 didn&rsquo;t identify the entity)

| Step | Action | Captures |
|---|---|---|
| 3.1 | Transliterate "aiseebling" into plausible Chinese pinyin — candidates include `爱西宾`, `艾西宾`, `爱熙宾`, `爱思宾`, `AI+西宾`, `AI+SeeBling`. Also consider it may be a genuinely made-up English brand name and not a transliteration at all. | candidate Chinese strings |
| 3.2 | Search `qichacha.com` (企查查) for each transliteration candidate AND for the literal `aiseebling` — note: free read access is limited, may require Chinese phone registration to view details, and is OUT OF SCOPE if it does. Use only the free public preview. | company hits |
| 3.3 | Search `tianyancha.com` (天眼查) for the same set — same no-registration constraint | company hits |
| 3.4 | USPTO TMSearch at `https://tmsearch.uspto.gov` for `aiseebling` — US trademark filings | US-registered brand |
| 3.5 | WIPO Global Brand Database at `https://www3.wipo.int/branddb/` for `aiseebling` — international trademark filings | international brand |
| 3.6 | CNIPA (Chinese trademark office) search at `https://sbj.cnipa.gov.cn/` — Chinese trademark filings. **May require captcha**; if so, document and skip. | Chinese trademark |

### Tier 4 — App-store metadata cross-reference (target: 10 min)

| Step | Action | Captures |
|---|---|---|
| 4.1 | Find "V360 Pro" on Google Play Store (`https://play.google.com/store/search?q=V360+Pro`) — note the listed developer name, developer email, developer physical address (all three are mandatory disclosures on Play Store) | developer identity |
| 4.2 | Find "V360 Pro" on Apple App Store (`https://apps.apple.com/`) — same disclosures | developer identity |
| 4.3 | Cross-reference the developer names / addresses from 4.1-4.2 against any entity found in Tier 1-3 | cross-reference |

### Tier 5 — Cross-reference pass (do throughout, not a distinct stage)

For every person, entity, address, phone, or ICP license number you
find at any tier, cross-reference it against:

- **Cloudbirds** / 云鸟
- **Dayunlinks** / 大云链 / 大云
- **Qianniao** / 千牛
- **HapSee** / 哈普
- **Signify** / Philips IoT
- The operator of `190.92.254.74` (the AWS-ELB endpoint behind
  `birds-public.philipsiot.com`)

Any match between aiseebling and one of the above collapses the
investigation to "aiseebling is a subsidiary / brand / division of
X." Report immediately even if the other tiers are incomplete.

---

## 5. Deliverables

### Primary: new docs file

Create **`docs/18-aiseebling-investigation.md`** with the following
sections (use the existing docs&rsquo; voice and formatting — check
`docs/00-overview.md` and `docs/03-cloud-topology.md` for tone):

1. **`# 18 · Aiseebling.com money-trail investigation`**
2. **Summary** — 3-5 sentence tl;dr of findings
3. **What we set out to investigate** — link back to Session 6
   finding and this spec file
4. **Methodology actually used** — which tiers, which tools, any
   deviations from the spec
5. **Findings** — organized by the eight questions in §2:
   - Who owns aiseebling.com?
   - What infrastructure?
   - What&rsquo;s at payment.aiseebling.com?
   - What other subdomains exist?
   - Any connection to known brands?
   - Corporate / trademark registration?
   - Historical footprint?
   - Active use / reachability?
6. **Evidence** — raw command output (WHOIS blocks, `dig` output,
   HTTP headers, crt.sh results) + source URLs so a future reader
   can reproduce every claim. No screenshots — plain text / fenced
   code blocks only (the static site builder is plain-md and
   screenshots are hard to diff).
7. **Cross-reference table** — brand matches found, with evidence
   path for each
8. **Open questions** — what Tier 1-5 couldn&rsquo;t answer and why
9. **Recommendations** — what this suggests for future cam-project
   work, specifically whether `14-next-steps.md` should gain a new
   Step
10. **Appendix A: OSINT safety log** — one list with every URL
    fetched and every CLI tool run during the investigation,
    formatted as `[HH:MM] GET <url>` or `[HH:MM] $ <command>`, for
    auditability

End the file with the standard `_Last updated: YYYY-MM-DD — Session N_`
footer where N is the session number you&rsquo;re running under (check
`12-session-log.md` for the current counter).

### Secondary: cross-reference updates

Minor edits to three existing docs:

- **`docs/03-cloud-topology.md`**: in the CBS control plane table,
  the `payment.aiseebling.com` row should get a trailing " — see
  [`18-aiseebling-investigation.md`](18-aiseebling-investigation.md)"
  pointer. Also update the `_Last updated_` footer.
- **`docs/12-session-log.md`**: append a new session entry dated the
  day you do the work, matching the existing entry template. Include
  the investigation&rsquo;s tl;dr and a pointer to the new doc.
- **`docs/README.md`**: add a row for `18-aiseebling-investigation.md`
  in the reading-order table at the bottom of the index.

### Build verification

Run `uv run build_docs.py` from the project root and confirm it
outputs "done: 21 pages → dist/" (was 20 before your new file). If
the builder errors, fix the markdown and re-run. Do not commit
until the build is green.

### Commit

Commit with message:

```
docs: aiseebling.com OSINT investigation — <one-line verdict>
```

where `<one-line verdict>` summarizes the headline finding (e.g.,
"identifies registrant as X" or "registrant privacy-shielded, brand
connection unconfirmed" — whichever is accurate).

Use a HEREDOC for the commit body per the existing project
convention (see `git log` for examples). End the commit body with:

```
Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

Do NOT push — leave the commit local for the project owner to
review and push themselves.

---

## 6. Success criteria

At least **one** of the following should be conclusively true when
the spec is considered done:

- [ ] The **legal name of the entity** behind aiseebling.com is
      identified with documentary evidence
- [ ] The **physical country / region of operations** is identified
      (even without a specific company name)
- [ ] A **confirmed link between aiseebling.com and one of the known
      brand clusters** (Cloudbirds, Dayunlinks, HapSee, Qianniao,
      Philips Signify) is established with evidence
- [ ] The **domain is confirmed to be a dormant / unused shell**
      (no active web content, no valid TLS cert, domain parked) —
      which is itself a useful finding and would explain why it&rsquo;s
      only referenced in one place in the app

Plus **all** of these hygiene criteria:

- [ ] `docs/18-aiseebling-investigation.md` exists and is well-formatted
- [ ] `uv run build_docs.py` is green with 21 pages
- [ ] Cross-references in `03-cloud-topology.md`, `12-session-log.md`,
      `README.md` are updated
- [ ] Appendix A safety log lists every URL fetched and every CLI
      tool invocation
- [ ] No files under `captures/`, `extracted/`, or `decompiled/` are
      modified (those belong to the main project)
- [ ] The commit message summarizes the verdict honestly, including
      "partial findings" or "inconclusive" if applicable

---

## 7. Stop conditions

Stop and write the partial-findings report if any of these happen:

- 🛑 **Time budget exhausted**: 90 minutes of elapsed research. A
  partial report with a clear "here&rsquo;s what we found, here&rsquo;s what we
  couldn&rsquo;t" is more valuable than an exhausted researcher grinding
  through paywalled databases at minute 120.
- 🛑 **All tiers yield nothing identifying**: WHOIS privacy-shielded,
  no CT logs, no web content, no trademark, no corporate registry
  hit, no cross-reference. The report should still be written —
  "deliberately anonymous" is itself a finding about vendor
  practices, and the reproducibility of the null result matters.
- 🛑 **Hard passive/active boundary**: you encounter a captcha, a
  login wall, an email verification, or a payment form. Do not
  cross the boundary. Document what you encountered and stop.
- 🛑 **Investigation becomes expensive**: paid databases (LexisNexis,
  Pitchbook, full SecurityTrails), manual Chinese-language research
  beyond public preview pages, or anything requiring a subscription.
  Note what would unlock the answer and stop.
- 🛑 **Finding suggests vulnerability**: if you find an exposed
  backup, leaked credentials, open S3 bucket, or similar — note its
  existence in the findings section and stop. Do not probe further,
  do not attempt access, do not contact the vendor. Vulnerability
  disclosure is out of scope.

---

## 8. Tools you can use

All of these are acceptable:

- Shell CLI tools: `whois`, `dig`, `host`, `curl`, `jq`, `openssl`
  (for fetching certs), `python3` (for hash computation)
- Web fetches via `curl` or `wget` — user-agent can be a generic
  browser string, no need to spoof anything weird
- Browsers to view `crt.sh`, `archive.org`, search engines, GitHub,
  and trademark databases (via WebFetch or WebSearch tool if
  available)
- Public WHOIS APIs (whoisfreaks, whoxy) — free-tier only

Not acceptable:

- Scanner tools (`nmap`, `masscan`, `zmap`, `nuclei`, `gobuster`,
  `ffuf`, `dirb`, `dirbuster`, `wfuzz`, `subfinder`, `amass`,
  `assetfinder`)
- Exploit frameworks (`metasploit`, `exploit-db` for this target)
- Browser automation against forms (`playwright`, `puppeteer` for
  form submission — reading public pages with playwright is fine,
  submitting anything is not)
- Any paid API that requires a subscription to function

---

## 9. Relationship to the main project

This investigation is a **sibling** of the main cam RE work, not a
component of it. The main project is at
`/Users/fdb/ReverseEngineering/cloudbirds-ip-cam` and tracks its own
blockers in `docs/14-next-steps.md`. This investigation&rsquo;s findings
may influence future steps in the main project — in particular, if
the aiseebling operator turns out to be a known quantity, the
`docs/17-portability.md` file should be updated with cross-brand
notes.

If the investigation reveals something directly actionable for the
cam project (e.g., "this is a subsidiary of X, which also operates
the update server at Y"), add a new step to `docs/14-next-steps.md`
referencing both the main project&rsquo;s Step A (firmware capture via
bind-real-cam) and the new finding.

---

## 10. Acceptance

Once the new doc is in place, the build is green, the commit is made,
and the cross-references are updated, the spec is complete. The
project owner will review the commit locally and either push it to
origin or request revisions.

If you need to ask clarifying questions before starting, pause and
note them — there is no real-time oracle for this spec, but a
thoughtful "here&rsquo;s what I&rsquo;m about to do, does this match your
intent?" checkpoint is always welcome.

Good hunting.

_Authored: 2026-04-15 — Session 6_
