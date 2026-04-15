# 14 · Glossary and references

Every acronym, brand name, symbol, and concept used throughout the
documentation. Reference material only — you don&rsquo;t need to read
this linearly.

## Brands and companies

| Term | Expansion |
|---|---|
| **Cloudbirds** | Consumer brand on the box. Parent company is Dayunlinks. |
| **Dayunlinks** | Chinese OEM, corporate parent of the Cloudbirds brand. Android app package: `com.dayunlinks.cloudbirds`. |
| **Qianniao** (千鸟) | The real OEM SDK namespace. All non-vendor-third-party Java code lives under `com.qianniao.*`. Dayunlinks is a skin on top. |
| **V360 Pro** | Generic Android app that supports Cloudbirds cameras and many others in the same OEM family. APK: `V360 Pro_6.5.0_APKPure.apk`. |
| **HapSee / HapSee Mate** | Alternative consumer app brands using the same backend. Origin of the `HAP-` Wi-Fi AP SSID prefix. |
| **Throughtek** | Taiwanese company that acquired or ran the CS2 Network PPPP library. Kalay is their rebrand. |
| **Kalay** | Throughtek&rsquo;s P2P SDK, successor to CS2 Network PPPP. The underlying protocol is compatible; they added some new message types and features. |
| **CS2 Network PPPP** | The legacy name of the P2P protocol family. Still the name of the library binary (`libPPCS_API.so`). |
| **Aliyun** | Alibaba Cloud. Hosts the three Kalay supernodes. |
| **hapseemate.cn** | CBS HTTPS backend, AWS ELB-fronted. |
| **cloudbirds.cn** | Dayunlinks&rsquo; brand domain, used for NTP wrappers and p2p supernode hosts. |

## Protocol / library terms

| Term | Meaning |
|---|---|
| **PPPP** | Peer-to-Peer Protocol Platform. The CS2 Network marketing name. |
| **PPCS** | "PPPP Client/Server". Library prefix in `libPPCS_API.so`. |
| **CBS** | **Our local shorthand** for the code in `libCBSClient.so`, not a vendor or Throughtek term. We guess it stands for "Custom Backend Service" based on the filename. The layer is a C session manager built on top of Kalay that handles the HTTPS control plane and NAT hole-punching bookkeeping. |
| **DID** | Device ID. Canonical format `AAAAA-NNNNNN-BBBBB` (5 letters, 6 digits, 5 letters). Uniquely identifies a single device in the vendor ecosystem. |
| **UID** | Same as DID. CS2/Kalay documentation uses "UID"; most OEMs call it "DID". |
| **sockaddr_in** | Standard C socket address struct, 16 bytes. Used verbatim in many Kalay message bodies. Layout on the wire: `family(2) + port(2) + ipv4(4) + pad(8)` all big-endian. |
| **Init key** | 80-character ASCII string passed to `PPCS_Initialize`. Vendor-specific. Controls which vendor&rsquo;s supernodes the library talks to and (probably) keys the obfuscation of some bodies. |
| **DRW** | "Data Read/Write". The Kalay data-channel framing used for video, audio, and IOTC commands. Message type `0xD0`. |
| **IOCTRL** | Kalay&rsquo;s command/response layer carried over DRW channels. Used for pan/tilt, motion detection config, user login, etc. |
| **Hole punching** | UDP NAT traversal technique: two peers behind different NATs simultaneously send to each other, opening their NAT mappings so replies work. The Kalay supernode mediates the initial endpoint exchange. |
| **Relay mode** | Fallback when hole punching fails. Kalay supernodes have "Rly*" functions (`RlyReq`, `RlyTo`, `RlyPkt`) that proxy the data channel through the supernode itself. Increases latency. |

## Wire format terms

| Term | Meaning |
|---|---|
| **Magic byte** | `0xF1`. Every Kalay packet begins with this byte. |
| **Message type** | Byte at offset 1 of the Kalay header. Determines how the rest of the packet is parsed. |
| **Body length** | Bytes at offset 2-3 of the Kalay header, big-endian unsigned 16-bit. |
| **Type nomenclature** | CS2 uses names like `HELLO`, `DEV_LGN`, `PUNCH_PKT`. We use the same names plus any Kalay-specific types we&rsquo;ve discovered (`REPORT_SESSION_RDY`, `SSDP2PReq`). |
| **`ntohAddr` / `htonAddr`** | Kalay-specific helpers that byte-swap a `sockaddr_in` for wire transmission. The "ntoh" and "hton" names are misleading — they always byte-swap regardless of host endianness. |
| **CRC** | Some message types (e.g., `DEV_LGN_CRC`) wrap the body in a CRC. We don&rsquo;t know the exact polynomial because we don&rsquo;t need to; replay is sufficient. |

## Our tooling and state

| Term | Meaning |
|---|---|
| **MITM proxy** | `mitm_supernode_proxy.py` + `mitm_cbs_proxy.py`. The pair of programs running on the Mac that intercept all cam cloud traffic. |
| **SIGUSR1 hook** | Mechanism by which `inject_p2p_req.py` (or any other caller) signals the UDP MITM proxy to send a crafted packet from its own `:32100` socket, with reverse-NAT conntrack making the packet appear to come from the cam&rsquo;s registered supernode. |
| **Injection file** | `/tmp/cam-listen/inject.json` — the JSON blob read by the SIGUSR1 hook. Contains a list of `{target, hex}` entries. |
| **Fake supernode** | `fake_supernode.py`, the original canned-responder before we pivoted to MITM. Superseded but kept in tree. |
| **Fake CBS** | `fake_cbs_server.py`, the original canned TLS server. Superseded. |
| **Fake client** | Term for the upcoming "speak app-side Kalay to the real supernode" approach. Doesn&rsquo;t exist yet as of 2026-04-15. See [`13-next-steps.md`](13-next-steps.md). |
| **WAITING state** | The cam&rsquo;s post-registration idle state. 30-second DEV_LGN keepalive, no other activity. The state we want to break out of. |
| **Airgap mode** | The target final deployment state where the cam never reaches any real cloud. All responses served from a local canned bank. |

## Network terms

| Term | Meaning |
|---|---|
| **DNAT** | Destination Network Address Translation. The iptables technique we use to rewrite the cam&rsquo;s cloud destination IPs to our Mac. |
| **MASQUERADE** | Source NAT for outbound connections. Used by the UDM to make the cam&rsquo;s traffic look like it&rsquo;s from the UDM itself when forwarding to us. |
| **conntrack** | Linux kernel connection tracker. Maintains bidirectional NAT state so that reply packets get the inverse rewrite applied. On UDP, entries time out after ~180 seconds of idle by default (`/proc/sys/net/netfilter/nf_conntrack_udp_timeout`). |
| **dispatcher** | A function that reads incoming packets and routes them to type-specific handlers. In this project, `thread_recv_Proto` is the main dispatcher on the cam side. |
| **tail call** | A function call that is the last operation in another function, so the compiler emits `b <target>` (branch) instead of `bl <target>` (branch-with-link). In ARM64 disassembly this looks like a plain jump at the function&rsquo;s end and means "the called function&rsquo;s return is also ours". Used by several Kalay helpers like `Read_P2PReq` tail-calling `ntohAddr`. |
| **thread_recv_Proto** | The cam&rsquo;s main receive loop for session-control Kalay messages. Located at `0x1ebe8` in our `libPPCS_API.so`. ~9000 instructions, dispatches to `Read_*` handlers per message type. |
| **thread_recv_DRW** | Receive loop for data-channel frames (`0xD0` family). Separate from `thread_recv_Proto`. |
| **thread_recv_LanSearch** | Receive loop dedicated to `0x30 LAN_SEARCH` on UDP/32108. This is why LAN_SEARCH replies work even when the rest of the cam&rsquo;s state machine is in weird states. |
| **thread_recv_FW_DCResponse** | Receive loop for "Firewall Destination Check" responses. Purpose unclear, part of the relay-server flow. |
| **UDM** | Ubiquiti Dream Router / Dream Machine. The router / firewall at `192.168.5.1` in our setup. |
| **dnsmasq** | DNS / DHCP server running on the UDM. We override cam cloud hostnames here. |
| **RFC1918** | The private IPv4 ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`. The cam&rsquo;s DNS rebinding filter rejects these as control-plane answers. |
| **TEST-NET** | RFC 5737 reserved ranges for documentation: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`. Not RFC1918, so they pass the cam&rsquo;s rebinding filter. Conventionally not routed on the public internet (nothing enforces this), so they&rsquo;re safe as a sink IP for a MITM redirect as long as you control routing. Safer than `9.9.9.9` because they don&rsquo;t collide with any real public service. |
| **SNI** | Server Name Indication. The plaintext hostname sent in the TLS ClientHello, used by multi-tenant servers to select the right cert. Our MITM reads this before wrapping the cam&rsquo;s socket. |

## File locations

| Path | What it is |
|---|---|
| `/Users/fdb/ReverseEngineering/cloudbirds-ip-cam/` | Project root |
| `docs/` | This directory |
| `extracted/` | APK unpacked (AndroidManifest, dex, native libs) |
| `decompiled/sources/` | jadx output — Java/Kotlin source tree |
| `ghidra_scripts/` | Ghidra headless scripts |
| `/tmp/cam-listen/` | Runtime state: MITM logs, injection file, certs |
| `/tmp/ghidra-cam/` | Ghidra project directory and decompile outputs |
| `~/.claude/projects/*/memory/` | Claude&rsquo;s cross-session memory files |

## External references

- **CS2 PPPP protocol documentation** — no official public spec
  exists. Best sources are reverse-engineering write-ups from other
  cheap-cam hackers, mostly on GitHub.
- **Kalay security advisories** — Throughtek had a major CVE in
  2021 (CVE-2021-28372) about peer endpoint enumeration via the
  supernode. Shows the supernode-side protocol was somewhat
  reversed publicly.
- **Unifi UDM iptables documentation** — Unifi&rsquo;s own docs are
  limited. The
  [unifi-utilities/unifios-utilities](https://github.com/unifi-utilities/unifios-utilities)
  GitHub org has boot-script tooling and iptables examples.
- **Android NDK ABI compatibility** — when trying to run the .so
  outside Android (Path B in next-steps), the Bionic libc
  differences from glibc matter. The NDK docs have an ABI list.
- **jadx** — Android APK decompiler,
  [GitHub](https://github.com/skylot/jadx). What we used to
  produce `decompiled/sources/`.
- **Ghidra** — NSA&rsquo;s open-source disassembler / decompiler,
  [ghidra-sre.org](https://ghidra-sre.org/). Installed via
  `brew install ghidra`. Headless mode is under
  `/opt/homebrew/Cellar/ghidra/*/libexec/support/analyzeHeadless`.

_Last updated: 2026-04-15 — Session 5_

## Common acronyms

| Acronym | Expansion |
|---|---|
| **SDK** | Software Development Kit |
| **NAT** | Network Address Translation |
| **DNS** | Domain Name System |
| **DHCP** | Dynamic Host Configuration Protocol |
| **NTP** | Network Time Protocol |
| **TLS** | Transport Layer Security |
| **SNI** | Server Name Indication |
| **SoC** | System on Chip |
| **OEM** | Original Equipment Manufacturer |
| **MITM** | Man In The Middle |
| **API** | Application Programming Interface |
| **RFC** | Request For Comments (IETF standards) |
| **JSON** | JavaScript Object Notation |
| **URL** | Uniform Resource Locator |
| **HTTP(S)** | HyperText Transfer Protocol (Secure) |
| **TCP** | Transmission Control Protocol |
| **UDP** | User Datagram Protocol |
| **OTA** | Over The Air (firmware update mechanism) |
| **CRC** | Cyclic Redundancy Check |
| **HMAC** | Hash-based Message Authentication Code |
| **XOR** | Exclusive-OR (boolean / bitwise operation) |
