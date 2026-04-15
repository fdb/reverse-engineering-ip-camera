# 10 · MITM Mac side

The "Mac side" of the interception pipeline is the pair of Python
proxies that terminate the cam&rsquo;s UDP Kalay and TCP/443 control-plane
traffic once the UDM has DNAT&rsquo;d it onto the laptop. This doc is the
standalone reference for bringing those proxies up, checking they&rsquo;re
healthy, and tearing them down again. It pairs with
[`09-router-setup.md`](09-router-setup.md), which covers the
router-side half (dnsmasq override, iptables DNAT and POSTROUTING,
persistence). Neither half works without the other: router-side
rewrites traffic, Mac-side speaks the protocol.

See [`08-attack-chain.md`](08-attack-chain.md) for the end-to-end
architecture diagram and the theory of why this particular split works.

## Prerequisites

- **Python 3.10+**. The project standardises on `uv` for script
  shebangs, but plain `python3` works for everything here.
- **No root required** on the Mac — UDP/32100 and TCP/8443 are both
  unprivileged ports. That&rsquo;s deliberate: the UDM rewrites
  `443 → 8443` precisely so nothing on the Mac needs `sudo`.
- **Working fake CA** in `/tmp/cam-listen/fake-cbs-certs/` with
  `server.crt` + `server.key`. On first run `mitm_cbs_proxy.py` will
  call out to the Mac&rsquo;s `openssl` CLI to generate a self-signed cert
  covering the CBS hostnames; subsequent runs reuse it. See
  [`11-tooling.md`](11-tooling.md) for the cert-gen helper.
- **Router side already applied** per
  [`09-router-setup.md`](09-router-setup.md) — dnsmasq sinkhole,
  PREROUTING DNAT, POSTROUTING MASQUERADE. Without those, the cam
  never reaches the Mac at all.
- **Cam already provisioned** onto the target Wi-Fi. If it isn&rsquo;t,
  see [`11-tooling.md`](11-tooling.md) for `wifiqr.py`.

## Starting the proxies

Two proxies run in parallel: `mitm_supernode_proxy.py` terminates the
UDP Kalay supernode traffic on `UDP/32100`, and `mitm_cbs_proxy.py`
terminates the TLS CBS control plane on `TCP/8443`. From the project
root:

```sh
mkdir -p /tmp/cam-listen
cd /Users/fdb/ReverseEngineering/cloudbirds-ip-cam

# UDP Kalay MITM
python3 mitm_supernode_proxy.py 2>&1 | tee /tmp/cam-listen/mitm_supernode.log &

# TCP TLS MITM
python3 mitm_cbs_proxy.py 2>&1 | tee /tmp/cam-listen/mitm_cbs.log &
```

Expected startup output, roughly:

```text
mitm_supernode_proxy.py
  [HH:MM:SS.mmm] MITM supernode proxy listening on UDP/32100  pid=XXXXX
  [HH:MM:SS.mmm] upstreams: [('8.134.120.63', 32100), ('47.89.232.167', 32100), ('123.56.74.245', 32100)]
  [HH:MM:SS.mmm] inject: write JSON to /tmp/cam-listen/inject.json, then `kill -USR1 XXXXX`

mitm_cbs_proxy.py
  [HH:MM:SS.mmm] MITM CBS TLS proxy listening on :8443
  [HH:MM:SS.mmm] upstream: user.hapseemate.cn → 190.92.254.71:443
```

As of Session 6, `mitm_cbs_proxy.py` supports **SNI-dispatched
multi-cloud upstream**: it inspects the ClientHello, picks the real
upstream per hostname, and resolves it through a **stub DNS resolver
pointed at `1.1.1.1:53`** rather than the Mac&rsquo;s system resolver —
because the system resolver goes through the UDM&rsquo;s dnsmasq, which is
now sinkholing those hostnames into our own listener. Unknown SNI
values are loudly rejected with a `REJECT unknown SNI` log line.
See the Session 6 design spec under `docs/superpowers/specs/` for the
full hostname table.

## Verification

Once the proxies are up, check they&rsquo;re actually listening on the
expected sockets:

```sh
lsof -iUDP:32100 -iTCP:8443 -n -P
```

You should see one `python3` process bound to `*:32100` (UDP) and
another bound to `*:8443` (TCP, LISTEN).

Tail the logs in two separate panes:

```sh
tail -f /tmp/cam-listen/mitm_supernode.log
tail -f /tmp/cam-listen/mitm_cbs.log
```

Power-cycle the cam. Within ~30 seconds of reboot you should see the
following traffic signatures — these are the "it&rsquo;s working" markers:

1. **UDP log** (`mitm_supernode.log`):
   - `new session: ('192.168.5.1', XXXX) → ('8.134.120.63', 32100)`
     — the UDM has rewritten the cam&rsquo;s source to the UDM&rsquo;s own LAN
     IP via MASQUERADE, so cam sessions arrive from `192.168.5.1:PORT`.
   - A burst of `HELLO`, `HELLO_ACK`, `DEV_LGN_CRC`, `DEV_LGN_ACK`
     frames going in both directions, decoded inline by
     `decode_kalay()`.
2. **TCP log** (`mitm_cbs.log`):
   - `ACCEPT new connection`
   - `SNI: user.hapseemate.cn` (or another CBS hostname)
   - `downstream TLS OK` — the cam accepted the fake cert.
   - `connected to 190.92.254.71:443 SNI=user.hapseemate.cn` —
     upstream TLS succeeded.
   - A cleartext `GET /preadd/didBindUserId?…` request and a
     `HTTP/1.1 200` response dumped to the log.

After the initial burst the cam settles into steady state and only
UDP keepalives continue, roughly every 30 seconds.

See [`04-wire-format-kalay.md`](04-wire-format-kalay.md) for the byte
layouts of each Kalay frame type and
[`05-wire-format-cbs.md`](05-wire-format-cbs.md) for the CBS HTTP
endpoints.

## Capture directory

Starting in Session 6, `mitm_cbs_proxy.py` also writes a structured
per-exchange dump to
`captures/ota/<ISO-timestamp>/<N>-request.json` and
`<N>-response.json`, one pair per completed TLS session, where
`<ISO-timestamp>` is the proxy start time (`YYYY-MM-DDTHH-MM-SS`).
Each JSON file records method, path, headers, body (base64-encoded
if non-printable), and timestamps. Firmware blobs, when the cam
downloads them, are dropped as `firmware.bin` in the same directory.
The `captures/ota/` tree is gitignored — these artifacts are not
meant to live in version control.

The human-readable `mitm_cbs.log` is still written in parallel and is
unchanged.

## Injecting packets

`mitm_supernode_proxy.py` accepts `SIGUSR1` to inject crafted Kalay
frames from its own `:32100` socket, so the injected packet inherits
the exact 4-tuple the cam already has conntrack state for. Writing
the packet JSON and signalling the proxy is handled by
`inject_p2p_req.py`; see [`11-tooling.md`](11-tooling.md) for
the full flag reference and examples rather than duplicating it here.

## Teardown

Kill both Mac-side proxies:

```sh
ps aux | grep -E 'mitm_supernode|mitm_cbs' | grep -v grep | awk '{print $2}' | xargs kill
```

The router-side DNAT / dnsmasq rules are torn down separately — see
[`09-router-setup.md`](09-router-setup.md) § "Teardown".

## Troubleshooting

For symptom → diagnosis → fix recipes covering pipeline failures
(cam not reaching the Mac, TLS handshake failures, stuck sessions,
DNS loops back into the sinkhole, etc.), see
[`16-debugging.md`](16-debugging.md).

_Last updated: 2026-04-15 — Session 6_
