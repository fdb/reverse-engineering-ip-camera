# `cs2p2p_PPPP_Proto_Send_PunchTo` — disassembly notes

Target: `extracted/lib/arm64-v8a/libPPCS_API.so` (Throughtek Kalay / CS2 PPPP client).
Tool: `llvm-objdump -d` (no full Ghidra run needed — the function is ~40 instructions).

## Heads-up: `Write_PunchTo` does not exist

The function we went in looking for — `cs2p2p_PPPP_Proto_Write_PunchTo` — **is not
in this binary**. `nm -D` enumerates every `Punch`-related symbol:

```
d8e8 T Proto_Send_PunchTo(const char*, int, sockaddr_in*, sockaddr_in*)
e818 T Proto_Write_PunchPkt(st_cs2p2p_PunchPkt*, char*, uint, st_cs2p2p_PunchPkt*)
e868 T Proto_Read_PunchPkt  (...)
e8bc T Proto_Send_PunchPkt  (...)
1045c T Proto_Send_SmartPunchTo(...)               // 5 extra args over PunchTo
142c0 T RlyRdyPlus_Send_PunchGo                    // relay-plus variants:
14398 T RlyRdyPlus_Send_PunchTo                    //   these DO have
14470 T RlyRdyPlus_Send_PunchPkt                   //   separate Write_*
1454c T RlyRdyPlus_Send_PunchAck                   //   because the
14068 T RlyRdyPlus_Write_PunchGo                   //   RlyRdyPlus header
140f4 T RlyRdyPlus_Write_PunchTo                   //   is longer / more
14180 T RlyRdyPlus_Write_PunchPkt                  //   fields.
14220 T RlyRdyPlus_Write_PunchAck
```

So `Send_PunchTo` is fully self-contained — it inlines `Write_Header`, `htonAddr`,
`SendMessage`. A `Write_PunchTo` was never emitted because for the plain (non-relay)
variant it would just be two lines.

## Signature

```c
void cs2p2p_PPPP_Proto_Send_PunchTo(
    const char *sock_ctx,         // x0 — opaque CS2 socket handle
    int         sock_idx,         // w1 — slot index
    sockaddr_in *dst,             // x2 — who we are sending the packet TO
    sockaddr_in *target);         // x3 — the endpoint we are asking `dst`
                                  //      to punch over to
```

Mangled name `_Z30cs2p2p_PPPP_Proto_Send_PunchToPKciP11sockaddr_inS2_`; `S2_` is the
Itanium back-ref meaning "same type as previous sockaddr_in*".

## Disassembly (`@ 0xd8e8`)

```
stp   x29, x30, [sp, #-0x150]!          ; frame = 0x150 bytes
mov   x29, sp
stp   x19, x20, [sp, #0x10]
adrp  x20, 0x40000
add   x19, x29, #0x48                   ; x19 = &buf   (stack, 256 bytes)
stp   x21, x22, [sp, #0x20]
str   x2,  [x29, #0x30]                 ; spill arg3 = dst
mov   x22, x0                           ; x22 = sock_ctx
ldr   x20, [x20, #0xf48]                ; __stack_chk_guard
mov   w21, w1                           ; w21 = sock_idx
mov   x2,  #0x100                       ; 256
mov   w1,  #0                           ;
mov   x0,  x19                          ;
str   x3,  [x29, #0x38]                 ; spill arg4 = target
ldr   x5,  [x20]                        ; canary
str   x5,  [x29, #0x148]
bl    memset                            ; memset(buf, 0, 256)

mov   w2,  #0x10                        ; len = 16  (payload size)
mov   x0,  x19                          ; &buf
mov   w1,  #0x40                        ; type = 0x40  (PUNCH_TO)
bl    cs2p2p_PPPP_Proto_Write_Header    ; writes buf[0..4] = F1 40 00 10

ldr   x3,  [x29, #0x38]                 ; target
add   x1,  x19, #0x4                    ; &buf[4]
mov   x0,  x3
bl    cs2p2p_htonAddr                   ; serialize target into buf+4 (16 B)

ldr   x4,  [x29, #0x30]                 ; dst
mov   x1,  x19                          ; &buf
mov   w2,  #0x14                        ; 20 bytes total
mov   x0,  x22                          ; sock_ctx
mov   w3,  w21                          ; sock_idx
bl    cs2p2p_SendMessage                ; SendMessage(ctx, buf, 20, idx, dst)

; canary check, epilogue, ret
```

That is the entire function. The 256-byte stack buffer is comically large for a
20-byte packet — almost certainly a copy-pasted template from `Send_PunchPkt` or
`Send_RlyReq` which carry much bigger bodies. The canary + `memset` overhead is
>50% of the function's instructions.

## Helpers used

### `cs2p2p_PPPP_Proto_Write_Header(buf, type, len)` (`@ 0xcba8`)
```
rev16 w2, w2            ; len   → big-endian
mov   w3, #-0xf         ; 0xF1  (trick: sign-extended 1-byte store)
strh  w2, [x0, #0x2]    ; buf[2..4] = len_be
strb  w3, [x0]          ; buf[0]    = 0xF1
strb  w1, [x0, #0x1]    ; buf[1]    = type
ret
```
Header = 4 bytes `F1 <type:u8> <len:u16 BE>`. Confirms the existing notes.

### `cs2p2p_htonAddr(const sockaddr_in *src, sockaddr_in *dst)` (`@ 0xcb50`)
```
stp   xzr, xzr, [x1]    ; dst[0..16] = 0
ldrh  w3, [x0]          ; family (LE in mem)
ldrh  w2, [x0, #0x2]    ; port
ldr   w0, [x0, #0x4]    ; addr
rev16 w3, w3
rev16 w2, w2
strh  w3, [x1]          ; dst[0..2] = byte-swapped family
rev   w0, w0
strh  w2, [x1, #0x2]    ; dst[2..4] = byte-swapped port
str   w0, [x1, #0x4]    ; dst[4..8] = byte-swapped addr
ret
```

It zeros a 16-byte slot (via `stp xzr, xzr`) and writes 8 useful bytes. The
trailing 8 bytes (where `sin_zero` lives on the input side) are left at zero.
Every field goes through an explicit byte reversal regardless of whether
`sockaddr_in` already stores it in network order, so the wire layout is:

```
offset  size  field
0       2     sin_family, byte-swapped from host repr
2       2     sin_port,   byte-swapped from network repr
4       4     sin_addr,   byte-swapped from network repr
8       8     zero
```

Practical consequence: on a LE host (which every Kalay client including the
cam's ARM firmware is), the output bytes come out as
`00 02 <port-BE> <addr-BE> 00 00 00 00 00 00 00 00` — i.e. **port and addr are
big-endian on the wire**, `AF_INET` prints as `00 02`. That matches the
HELLO_ACK body shape already verified in `camera_phonehome*.pcap`, so the
"byte-swap twice" path happens to round-trip to naive-BE for the fields
that matter.

## Wire format of a `PUNCH_TO` packet

```
offset  size  value
0       1     0xF1               Kalay magic
1       1     0x40               msg type = PUNCH_TO
2       2     0x0010             payload length, BE
4       2     0x0002             AF_INET, BE
6       2     port               target port,  BE
8       4     ipv4               target ipv4,  BE
12      8     0x00 * 8           zero padding
------  ----
total = 20 bytes on wire.
```

This is byte-identical in shape to HELLO_ACK (`F1 01 00 10` + sockaddr) — only
the type byte differs. So for building one in Python we can lift the same
helper already used by `fake_supernode.py`.

## Caller semantics — who is `dst`, who is `target`?

The function is **symmetric**: it's just "write a sockaddr into a Kalay
envelope and send it somewhere." The meaning is purely a caller convention:

- In a **client → supernode** flow, `dst` is the supernode and `target` is
  the peer the client wants the device to punch out to.
- In a **supernode → device** flow (what we want to inject), `dst` is the
  device (the cam) and `target` is the endpoint the cam should open NAT to
  — i.e. our listener socket.

There is no signing, no session token, no nonce in the 16-byte body. The
"auth" is purely the UDP 4-tuple: the cam only accepts `0x40` from the
address it currently thinks is its supernode. We already satisfy that in
`mitm_supernode_proxy.py` — SIGUSR1 injection emits from the Mac's
`:32100` socket and conntrack rewrites the source to `9.9.9.9:32100`, which
matches the cam's per-session state.

## Why the earlier 20-byte injection attempts got silently dropped

Memory note said:
> First attempts (20 B body = single sockaddr_in) all got silent drop.

The size was right, but the body was probably shaped as
`family=2 port=BE addr=BE 00*8` on the wire while the cam's `htonAddr`-style
unpacker expects the fields byte-swapped **again**. On a LE cam that round-
trips to the same bytes for port/addr, so shape is not the problem. More
likely causes:

1. **Wrong message type.** `0x40` PUNCH_TO is not necessarily what triggers
   the cam to hole-punch outward. On the device side the flow is usually:
   - supernode relays a **P2P_REQ (`0x20`)** message from a peer
   - device responds by sending `PunchPkt (`0x41`)` UDP packets to the
     peer endpoint carried in P2P_REQ
   The PUNCH_TO message is primarily a *client→relay* instruction; it may
   be ignored entirely by the device-role code path.
2. **4-tuple mismatch.** If the injection was sent while the cam's session
   state had rolled over to a different supernode port, conntrack would
   have rewritten the source but the cam's state machine would not
   recognise it.
3. **Missing preceding `P2P_RDY`.** The cam might gate `PunchPkt` on having
   already seen a `P2P_RDY` for the session id.

## Next step (based on this disasm)

Because `Send_PunchTo` is symmetric we now know exactly how to build a
PUNCH_TO frame — but the real injection primitive we want is probably
**P2P_REQ (0x20)**, whose serializer is `cs2p2p_PPPP_Proto_Read_P2PReq`
at `0xd70c` (receive side) / likely an un-enumerated `Send_P2PReq`. A
follow-up disasm of `Read_P2PReq` will tell us the exact body layout the
cam is parsing, which is the contract our injected packet must satisfy.

For symmetry/completeness, also worth disassembling:
- `Proto_Read_PunchPkt @ 0xe868` — confirms whether `0x41` contains a
  session id or nonce the cam checks.
- `Proto_Send_SmartPunchTo @ 0x1045c` — takes 4 extra scalar args
  (`t h c` = u16, u8, i8), so it embeds extra fields in the body; might
  reveal the "session / try count / flags" fields the plain variant omits.
- `Proto_Read_P2PReq @ 0xd70c` — **the likely real injection target**.

All three are small leaf functions; another round of `llvm-objdump
--disassemble-symbols=` will finish the map without needing to boot Ghidra.
