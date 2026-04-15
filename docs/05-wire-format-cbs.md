# 05 · CBS control plane (HTTPS)

In parallel with its Kalay UDP traffic, the camera also makes HTTPS
calls to a separate control-plane service hosted at
`user.hapseemate.cn`. This is managed by `libCBSClient.so` — the
"Custom Backend Service" client built on top of Kalay.

## Transport

| Parameter | Value |
|---|---|
| Hostname | `user.hapseemate.cn` |
| Real IP | `190.92.254.71` |
| Frontend | AWS Elastic Load Balancer (visible in `Server: elb` header) |
| Port | TCP 443 |
| TLS version | TLS 1.2 |
| Cipher negotiated | `ECDHE-RSA-AES256-GCM-SHA384` |
| SNI | `user.hapseemate.cn` (always — used by our MITM to dispatch) |
| Cert validation | **NONE** — accepts self-signed `*.hapseemate.cn` certs |

## The cam accepts any cert for the right hostname

This is the core vulnerability that enables the entire MITM. Our
`fake_cbs_server.py` generates a self-signed cert with:

```
CN = *.hapseemate.cn
SAN:
  DNS:*.hapseemate.cn
  DNS:hapseemate.cn
  DNS:user.hapseemate.cn
  DNS:*.cloudbirds.cn
  DNS:*.hapsee.cn
```

The cam completes TLS 1.2 handshake with this cert and proceeds to
send its HTTPS request in cleartext over the encrypted tunnel — which
we then decrypt trivially because we hold the private key.

**No X.509 path validation** — we don&rsquo;t even sign the cert with a CA.
No certificate pinning — we don&rsquo;t need to use a specific cert issuer.
No public-key pinning — we don&rsquo;t need to use a specific key. The cam
just wants a valid-enough cert where the hostname matches the SNI.

## Observed endpoints

Only one so far: `/preadd/didBindUserId`.

### `GET /preadd/didBindUserId` — device-binding lookup

The camera asks the cloud "has a user account been bound to my DID
yet?" If yes, the response contains the user ID; if no, the response
is a plain success envelope.

#### Request

```http
GET /preadd/didBindUserId?relatInfo=eTgjfHOm%2B3jo%2BmB%2B2EJBJSvF5MeGVuqryBjI2slntTM%3D&did=Nb72w3ZMX2AtpU74BfdVuFVXbMDLsUyXWg9TMvVcCJM%3D&utcTime=1776203762&devType=1&netType=1&eleType=1 HTTP/1.1
Host: user.hapseemate.cn
Accept: */*
```

#### Query parameters

| Name | Type | Value | Meaning |
|---|---|---|---|
| `relatInfo` | base64url | 32-byte opaque blob | Related-info, high-entropy. Decodes to 32 bytes but contents are unreadable — probably ssid+pwd or a token hash, obfuscated |
| `did` | base64url | 32-byte opaque blob | The DID, obfuscated — NOT the plaintext `CFEOA-417739-RTFUU` |
| `utcTime` | decimal | `1776203762` | Unix timestamp when the request was built |
| `devType` | int | `1` | Device class: 1 = camera |
| `netType` | int | `1` | Network class: 1 = Wi-Fi |
| `eleType` | int | `1` | Element type: 1 = indoor (probably) |

**Both `relatInfo` and `did` are base64url-encoded opaque blobs.**
We can see the `%2B` (`+`), `%2F` (`/`), `%3D` (`=`) URL-encoding in
the captured request — classic base64 markers. Verified by manual
decode of the `relatInfo` value:

```
eTgjfHOm+3jo+mB+2EJBJSvF5MeGVuqryBjI2slntTM=
(44 chars of base64 with single `=` padding)
         ↓ base64 decode
79 38 23 7c 73 a6 fb 78 e8 fa 60 7e d8 42 41 25
2b c5 e4 c7 86 56 ea ab c8 18 c8 da c9 67 b5 33
(32 bytes of high-entropy binary)
```

The 32-byte blobs are almost certainly obfuscated — same obfuscation
scheme as the Kalay body that we also don&rsquo;t understand yet. Plaintext
content is **unknown**; contents are probably at least the DID plus
something identifying the original session (Wi-Fi SSID hash, time
salt, HMAC signature).

**`utcTime` is unobfuscated**, and it&rsquo;s why NTP synchronization
matters: a stale timestamp would get rejected by the server as a
replay-attack mitigation.

#### Response

```http
HTTP/1.1 200
Date: Tue, 14 Apr 2026 22:20:41 GMT
Content-Type: text/plain;charset=ISO-8859-1
Content-Length: 35
Connection: keep-alive
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Server: elb

{"mssage":"success","status":"200"}
```

#### The typo

**`"mssage"`, not `"message"`.** This is not a capture artifact — it
is verbatim what the real cloud sends, every time, across multiple
captures and cam boots _(observed)_.

We **partially** verified that the typo matters: a hand-rolled response
with `{"code":0,"msg":"success","data":null}` did NOT satisfy the cam
(it kept hot-retrying). After switching to the MITM and forwarding the
real cloud&rsquo;s actual `{"mssage":"success","status":"200"}`, the cam
immediately stopped retrying. So _something_ in the real response is
load-bearing.

**We did NOT explicitly test** `{"message":"success","status":"200"}`
(corrected spelling, otherwise identical). So strictly speaking we
don&rsquo;t know whether the typo itself is required, or whether it&rsquo;s the
`status:"200"` field, or something else in the exact byte sequence.
For safety, canned responses should reproduce the real cloud output
**verbatim** including `"mssage"`. Testing the corrected spelling is a
low-effort open question — see [`13-open-questions.md`](13-open-questions.md).

### What the cam does with the response

After receiving `{"mssage":"success","status":"200"}`, the cam stops
retrying `/preadd/didBindUserId` and transitions to a **steady-state
keepalive** phase. It does not make any further HTTPS requests for at
least several minutes.

This suggests:
- The cam cares about `status` more than `mssage`. `"200"` as a string
  is interpreted as "HTTP-like success".
- The absence of a `userId` field in `data` (or the absence of a `data`
  field altogether) is interpreted as "no user binding yet — I am an
  orphan device".
- "Orphan device" is a valid resting state that the cam is comfortable
  in forever. It continues keepaliving the supernode on 30s cadence
  but makes no further API calls.

## Why the Android app&rsquo;s `BaseRepo` is a red herring

When reverse-engineering, we initially tried to match the response
format to the Android app&rsquo;s `BaseRepo` Kotlin class, which has 23
fields including `message`, `msg`, `data`, `status`, `code`, `error`,
`details`, `ispush`, `alias`, `mid`, `ver`, `advType`, `slot`, … —
many of them ad-display configuration.

None of that is what the cam sees. The **cam&rsquo;s C parser** uses a
permissive JSON library (`kcJSON`, a fork of cJSON) that looks for
specific keys and ignores everything else. So the **wire format** is
the 35-byte envelope above, while the **Android app&rsquo;s deserialization
target** has 22 extra fields that don&rsquo;t appear on the wire at all.

**Two clients, two schemas, one server.** The cam&rsquo;s schema is much
smaller than the app&rsquo;s schema. Writing a canned response for the cam
that is "the intersection" won&rsquo;t satisfy either — you need the exact
cam-compatible form.

## Endpoints we expect but haven&rsquo;t seen

From symbol analysis of `libCBSClient.so` and the Android app&rsquo;s
`Api.java`, the cam probably has handlers for:

- `/preadd/checkDidByToken` — registration token verification
- `/preadd/didBindUserId` — **observed**, documented above
- `/drp/getP2pIP` or similar — could be where the cam gets its
  hardcoded supernode list refreshed (this might explain the
  hardcoded `123.56.74.245`)
- An OTA update endpoint — firmware checks

None of the above have been captured yet. Once we trigger them, add
a section here with the exact schemas.

_Last updated: 2026-04-15 — Session 6_

## CBSClient log strings (for reference)

Extracted from `strings libCBSClient.so`. These are format strings the
library logs to some internal log pipe. They confirm the CBS state
machine and hint at endpoint semantics we haven&rsquo;t yet exercised:

```
GET /index.html?key=%u&deviceId=%s&sid=%u&liveinterval=%d&livetimes=%d&version=%d&type=%s HTTP/1.1
http_create / http_destroy / http_get / http_post:%s
invalid json code=%p data=%p
invalid json p2pip=%p p2pport=%p stunip=%p stunport=%p ext1=%p
update hole waln=%s:%d lan=%s:%d sessionId=%u deviceId=%s
update media=%s:%d sessionId=%u deviceId=%s clientKey=%u
handshake recv success sessionId=%u deviceId=%s clientKey=%u rt=%d
handshake send success sessionId=%u deviceId=%s clientKey=%u
open module fail %d sessionId=%u deviceId=%s
open send success sessionId=%u deviceId=%s
recv open res session=%u deviceId=%s status=%d
live timeout sessionId=%u deviceId=%s clientKey=%u
recved close sessionId=%u deviceId=%s
send live fail sessionId=%u deviceId=%s clientKey=%u
connect to %s:%d rt %d sessionId=%u deviceId=%s clientKey=%u
wait for connect timeout sessionId=%u deviceId=%s clientKey=%u
hole_close / hole_deinit / hole_getCtx / hole_info / hole_init / hole_send / hole_start
```

Things to note:

- **`GET /index.html?key=...&deviceId=...&sid=...`** is a format string
  we have NOT seen the cam actually use on the wire. It might be a
  different code path triggered by specific conditions (OTA check, live
  streaming config fetch). Worth triggering later.
- **`update hole waln=...`** (note the typo `waln`) is what gets logged
  when the cam receives an `update hole` instruction telling it what
  its WAN/LAN addresses are. This would happen during a successful
  peer connection attempt.
- **`connect to %s:%d`** is where a connection URL is logged. We haven&rsquo;t
  triggered this log line because no peer has asked for the cam yet.
