# 01 · Hardware and OEM identity

## Physical device

The camera is one of the thousands of generic "Wi-Fi IP cams" sold on
AliExpress, Amazon and Chinese marketplaces for $10-30. The board
generation is almost certainly Hisilicon or similar low-end ARM SoC with
a fixed-focus CMOS sensor and a pan/tilt motor. We have not physically
disassembled it.

What we know for sure:

- **AP mode SSID**: starts with `HAP-` followed by ~17 characters
  (5-letter prefix + 6-digit serial + 5-letter suffix of the DID, minus
  the dashes).
- **Default admin password**: `"123"` — literal three-byte string. This
  is the PPPP/Kalay login password used in DEV_LGN, NOT a Wi-Fi
  password. The cam&rsquo;s AP is open.
- **Device name**: `IPCAMERA` (constant `ADD_AP_DEV_NAME` in the app).
- **Supported Wi-Fi**: 2.4 GHz only (we haven&rsquo;t verified 5 GHz support).
- **Imager**: the cam&rsquo;s camera can read QR codes held in front of it.
  This is how vendor provisioning transfers Wi-Fi credentials.
  **Confirmed working with our `wifiqr.py`** — the cam successfully
  decodes the `S<ssid>\n<pwd>\n` format from our ASCII-art QR when held
  ~15-25 cm in front of the lens.

## The DID and what it tells us

The device&rsquo;s unique identifier:

```
CFEOA-417739-RTFUU
```

This is the canonical CS2/Kalay UID format: `AAAAA-NNNNNN-BBBBB`.

| Segment | Length | Content | Meaning |
|---|---|---|---|
| Prefix | 5 letters | `CFEOA` | OEM vendor code (maps to an init key) |
| Serial | 6 decimal digits | `417739` | Per-device serial within the vendor |
| Suffix | 5 letters | `RTFUU` | Part of the same OEM identifier |

On the wire, the DID is encoded in a 20-byte struct in most messages:

```
offset  size  field
[0..8)   8     prefix, ASCII, NUL-padded to 8 bytes
[8..12)  4     serial as big-endian u32  (417739 = 0x00065fcb)
[12..20) 8     suffix, ASCII, NUL-padded to 8 bytes
```

Concretely, for `CFEOA-417739-RTFUU`:

```
43 46 45 4f 41 00 00 00   <- "CFEOA\0\0\0"
00 06 5f cb               <- serial BE = 417739
52 54 46 55 55 00 00 00   <- "RTFUU\0\0\0"
```

This is **byte-identical** to the body we see in LAN_SEARCH responses,
DEV_LGN messages, P2P_REQ payloads, and PUNCH_PKT bodies. The same
20-byte struct is reused everywhere — classic CS2 style.

## OEM identity

The brand stack looks like this, from most-visible to most-internal:

1. **Cloudbirds** — consumer brand seen on the box and the website.
2. **Dayunlinks** — corporate parent, Chinese company, listed as
   `com.dayunlinks.cloudbirds` in the Android app package name.
3. **Qianniao** (千鸟) — the real OEM SDK namespace. All the
   non-vendor-third-party Java code in the APK lives under
   `com.qianniao.*`. Dayunlinks is a skin on Qianniao.
4. **V360 Pro** / **HapSee** / **HapSee Mate** — multiple **consumer
   brand names** that all use the same underlying Qianniao stack and
   the same cloud backend. Your cam&rsquo;s AP SSID prefix `HAP-` is from
   "HapSee", not from "Access Point".
5. **Throughtek Kalay** (formerly CS2 Network PPPP) — the underlying
   P2P protocol library. Taiwanese, bought by or licensed from
   Throughtek. Ships in many non-Qianniao OEMs too.

Everything we learn about this cam is likely to apply, with minor
differences, to any other cam in the Qianniao or Kalay family —
including Yoosee, Sricam, V380 Pro, YI, EseeCloud, and dozens of
AliExpress no-name brands.

## Vendor init keys

Inside `decompiled/sources/ppcs/sdk/P2pSDK.java` we found three 80-character
string constants labeled `INIT_KEY`, `NEW_INIT_KEY`, and `NEW_INIT_2_KEY`.
They&rsquo;re fully quoted here because each is the vendor identifier the cam
uses to authenticate with its supernode cluster:

```java
public static final String INIT_KEY        = "EEGDFHBLKGJIGEJCECHIFFEKHKNAHBNAHAFJBECFADJELOLDDPAKCHOEGCLGJPLDACMCKODGOGMNBHCCJDMH";
public static final String NEW_INIT_KEY    = "EIHGFOBCKIIMGMJCEDHJFAEIGANHHENMHMFABMDDAKJJLHKDDHACDEPBGKLOIOLJAKNAKADOOJNJBMCLJGMC";
public static final String NEW_INIT_2_KEY  = "EEGDFHBBKAIEGEJJEPHFFIEAHDNJHKNAGNFLBDCEACJDLJKNDNANCCPKGIKGIJLIAKNAKDDLOJNJBLCKIC";
```

Notice the alphabet: every character is a letter A-P, which is 16
possible values per char, i.e. **each character encodes 4 bits**
(base-16 using letters instead of digits `0-9a-f`). 80 characters ×
4 bits = **320 bits = 40 bytes of key material**. That&rsquo;s a plausible
size for an AES-256 key (32 bytes) plus 8 bytes of vendor ID, or for
an HMAC-SHA256 key with some framing.

There&rsquo;s almost certainly a helper function in `libPPCS_API.so`
(probably `cs2p2p_PPPP_DecodeString`, despite its misleading name)
that converts the A-P alphabet back into raw bytes. We haven&rsquo;t
disassembled it yet — see `12-open-questions.md`.

These keys are passed to `PPCS_Initialize` as a byte array plus a NUL
terminator. Internally the library uses the decoded bytes as:

1. The identifier the supernode uses to decide which vendor&rsquo;s devices
   this client is authorized to see (_inferred_ from the pattern of
   different OEMs shipping different keys)
2. Probably the seed for the obfuscation applied to message bodies
   like `DEV_LGN_CRC` and `REPORT_SESSION_RDY` (_inferred_ from the
   symbol name `cs2p2p__P2P_Proprietary_Decrypt` being called from
   inside `thread_recv_Proto`)

Different OEMs get different keys. Same key = same vendor = same
supernode cluster.

## Native libraries in the APK

The APK ships ~40 `.so` files per ABI (`arm64-v8a` and `armeabi-v7a`).
The ones relevant to RE are:

| Library | Role |
|---|---|
| `libPPCS_API.so` | **Main Kalay P2P engine.** Exports `PPCS_Initialize`, `PPCS_Connect`, `PPCS_Listen`, `PPCS_Read`, `PPCS_Write`. Contains the wire format for every message type we care about. |
| `libCBSClient.so` | **Custom C session manager on top of Kalay.** Handles the HTTPS control plane, NAT hole-punching bookkeeping, session lifecycle. Has log strings like `update hole waln=%s:%d lan=%s:%d`. |
| `libHole.so` | Low-level NAT hole-punch helper used by libCBSClient. |
| `libnms.so` | "Network Management Service". Stripped — only header strings visible. Purpose unknown; possibly an on-device admin RPC. |
| `libiot.so` / `libsaas.so` | Aliyun IoT / SaaS cloud SDKs. Present in APK but we have not observed outbound traffic from them yet. |
| `libijkplayer.so` | ffmpeg-based video player used by the client app (not the cam firmware). |

Everything else in `extracted/lib/` is either framework (libc++, libyuv,
ffmpeg), Chinese ad SDKs (pangle, mbridge, tradplus, inmobi), or
measurement SDKs (apminsight, applovin). None of that is relevant to
the protocol.

_Last updated: 2026-04-15 — Session 5_

## What we have NOT done

- **Physical teardown**: we have not opened the camera. No photos, no
  probing the UART pads, no SPI flash dump.
- **Firmware extraction from the device**: we have the Android app&rsquo;s
  copy of the Kalay library but not the camera&rsquo;s own firmware.
  Potentially interesting because the library on the cam could be a
  different build than the one in the APK (cam is ARM32, Android is
  ARM64).
- **UART / serial console**: almost certainly exposed on the cam&rsquo;s PCB
  but we haven&rsquo;t poked at it.
- **OTA update interception**: haven&rsquo;t observed the cam doing a
  firmware update yet. When it does, we&rsquo;ll learn the update server and
  see whether firmware is signed.
