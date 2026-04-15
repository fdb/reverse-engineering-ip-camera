# 02 · Software architecture

This document describes the layered architecture of the software that
runs on the camera and the Android app that normally controls it. Even
though we are not trying to run the Android app, the APK is still the
primary RE artifact — the camera&rsquo;s firmware ships the same libraries
in the same roles.

> **Note**: "CBS" is our local shorthand for the code in
> `libCBSClient.so`. We don&rsquo;t know what Throughtek or the Qianniao OEM
> actually call it — the symbol prefix suggests "Custom Backend Service"
> but that&rsquo;s our guess. The only unambiguous name is the filename itself.

## Stack overview (camera side)

```
┌─────────────────────────────────────────────────────────┐
│ Camera firmware (ARM, unknown build)                    │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │ Application layer — motion detection, video,     │   │
│  │ pan/tilt motor, OTA updater                      │   │
│  └──────────────────────────────────────────────────┘   │
│                      ▲                                  │
│                      │                                  │
│  ┌───────────────────┴──────────────────────────────┐   │
│  │ libCBSClient.so — custom session manager         │   │
│  │ • http_get / http_post                           │   │
│  │ • kcJSON parser                                  │   │
│  │ • NAT hole state machine: hole_init/start/send   │   │
│  │ • Logs:  update hole waln=<wan>:<port>            │   │
│  │          lan=<lan>:<port> sessionId deviceId     │   │
│  │ • Calls PPCS_* for the transport layer           │   │
│  └───────────────────┬──────────────────────────────┘   │
│                      │                                  │
│                      ▼                                  │
│  ┌──────────────────────────────────────────────────┐   │
│  │ libPPCS_API.so — Throughtek Kalay core           │   │
│  │ • UDP protocol engine                            │   │
│  │ • Hand-written packet encoders / decoders        │   │
│  │ • Vendor init key auth                           │   │
│  │ • Body obfuscation for some message types        │   │
│  │ • Four receive threads:                          │   │
│  │     recv_Proto, recv_DRW,                        │   │
│  │     recv_LanSearch, recv_FW_DCResponse           │   │
│  └───────────────────┬──────────────────────────────┘   │
│                      │                                  │
│                      ▼                                  │
│  ┌──────────────────────────────────────────────────┐   │
│  │ Kernel: UDP sockets, Wi-Fi stack                 │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Stack overview (Android app side)

```
┌────────────────────────────────────────────────────────────┐
│ V360 Pro Android app 6.5.0                                 │
│                                                            │
│ UI / ViewModels                                            │
│ com.qianniao.*        ←──── OEM SDK logic                 │
│ com.dayunlinks.*      ←──── brand-specific skin            │
│                                                            │
│ ppcs.sdk.P2pSDK       ←──── Kotlin wrapper over JNI        │
│ com.p2p.pppp_api.*    ←──── generated JNI bindings         │
│                                                            │
│ libPPCS_API.so        ←──── same SOURCE as on the cam,     │
│ libCBSClient.so            different build flavor likely   │
│                                                            │
│ tons of ad SDKs       ←──── pangle / mbridge /             │
│ (irrelevant to us)          applovin / fyber / tradplus    │
└────────────────────────────────────────────────────────────┘
```

The key observation: **the same native libraries run on both sides of
the protocol**. This is how PPPP / Kalay has worked since 2005 —
symmetric C code, with a "mode" parameter (`PPCS_Initialize` takes a
vendor key; `PPCS_Connect` for clients, `PPCS_Listen` for devices).
Because both sides ship the same binary, reverse-engineering the app
also gives us the cam&rsquo;s wire format for free.

## Relationship between the layers

- **libPPCS_API.so** owns the UDP socket. It assembles packets, XORs
  bodies where needed, calls `sendto`. Receive side is a set of background
  threads (`thread_recv_Proto`, `thread_recv_DRW`, `thread_recv_LanSearch`)
  that read from the socket and dispatch by message type.
- **libCBSClient.so** sits on top, handling the higher-level concept of
  "a session with the cloud" — registration, keepalive, hole-punching
  state, and crucially the HTTPS control plane calls.
- **The application layer** (firmware on the cam, Kotlin on the Android
  app) only sees CBSClient&rsquo;s API. It never speaks raw Kalay packets
  directly.

## How the Android app calls into the native libs

The Kotlin wrapper `ppcs/sdk/P2pSDK.kt` decompiles to something like:

```kotlin
class P2pSDK {
    fun connect(device: Device): Int {
        // …
        device.session = PPCS_APIs.PPCS_Connect(
            device.did,
            device.connectMode,  // 0=P2P, 1=LAN-only, 2=relay
            0                    // flags
        )
        // …
    }
}
```

Where `PPCS_APIs` is the JNI binding class, and `PPCS_Connect` resolves
to `Java_com_p2p_pppp_1api_PPCS_1APIs_PPCS_1Connect` in the native lib.
That&rsquo;s the moment the client thread starts its Kalay handshake with the
supernode.

On the camera side, the equivalent entry point is `PPCS_Listen` — the
cam starts listening for incoming sessions instead of initiating them.
Same library, different mode.

## Static config the app pulls in

Some things that surprised us:

- The app bundles **nine dex files** (`classes.dex` through `classes9.dex`),
  totalling ~65 MB of bytecode. Most of that is ad SDK noise.
- The Java package `com.qianniao.base.http.Api` defines **every cloud
  endpoint the app will ever call** as Retrofit interfaces. There are
  ~50 endpoint constants, rooted at `birds-user.hapseemate.cn`,
  `wechat.hapseemate.cn`, and `public.dayunlinks.cn`. Most of them are
  app-side (user management, device sharing, subscription status) and
  don&rsquo;t apply to the camera&rsquo;s own phone-home traffic.
- The app&rsquo;s `BaseRepo` class (the generic JSON envelope for all Retrofit
  responses) has **23 fields** including ad-display config
  (`advType`, `isNative`, `coldStartInr`, `ldgWaitOt`, `switchNum`…).
  These fields exist because the vendor ad stack injects monetization
  config into every API response the app consumes. The **camera&rsquo;s** C
  parser does not care about these fields at all — proof that the wire
  format and the client-side deserialization target can be different.

## What runs on the cam itself

We don&rsquo;t have the cam firmware, but we can infer:

- A Linux userspace (probably minimal Busybox)
- `libPPCS_API.so` and `libCBSClient.so` linked into a single process
- An MJPEG or H.264 encoder pipe from the sensor
- A DHCP client, NTP client, TLS client (OpenSSL or BoringSSL)
- A thread pool for the recv loops
- A config store in flash for the hardcoded supernode IP, DID, and
  device-specific state

Total footprint is probably <10 MB binary. Confirmed only by the fact
that the cam boots quickly (under 30 seconds) and comes back up reliably
from a cold boot.

_Last updated: 2026-04-15 — Session 5_

## What is explicitly NOT in the stack

- **No ONVIF** — verified by probe.
- **No RTSP** — TCP 554 is closed.
- **No MJPEG-over-HTTP** — no HTTP server at all.
- **No mDNS / Bonjour / Zeroconf advertisement** — verified.
- **No SSDP / UPnP** — verified.
- **No Aliyun IoT traffic observed** — despite `libiot.so` being in the
  APK, we have never seen the cam contact any `iot.aliyuncs.com` host.
  It may be a dead code path or only used in specific modes.
