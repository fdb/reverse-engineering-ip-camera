#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "qrcode[pil]>=7.4",
# ]
# ///
"""
wifiqr.py — generate the V360 Pro / Cloudbirds Wi-Fi provisioning QR code
locally, without phoning the vendor cloud.

Payload format (extracted from WifiScanQrcodeFragment.createQrCode() in the
decompiled APK, line 257):

    S<ssid>\n<pwd>\n

That is: literal ASCII 'S', then the SSID, then LF, then the password, then
LF. Nothing else. No JSON, no checksum, no token — the camera's imager just
reads that string straight out of the QR.

Usage
-----
    ./wifiqr.py "MyWifi" "s3cret"             # prompts for pwd if omitted
    ./wifiqr.py -s MyWifi --stdin-pwd         # read pwd from stdin (no echo)
    ./wifiqr.py MyWifi s3cret -o cam.png      # also save PNG to disk
    ./wifiqr.py MyWifi s3cret --no-ascii -o q.png
    ./wifiqr.py MyWifi s3cret --raw           # just print the payload string

On first run `uv` will fetch the qrcode library into a cache automatically.
Hold the terminal window ~20 cm from the camera lens; the default ASCII art
is dense enough for cheap fixed-focus imagers to decode.
"""
from __future__ import annotations

import argparse
import getpass
import sys

import qrcode
from qrcode.constants import ERROR_CORRECT_M


def build_payload(ssid: str, pwd: str) -> str:
    # Byte-for-byte match with the Kotlin source: `"S" + ssid + "\n" + pwd + "\n"`.
    # The Kotlin used StringsKt.trimIndent which strips leading whitespace; we
    # skip that because argparse already hands us the raw strings.
    return f"S{ssid}\n{pwd}\n"


def render_ascii(payload: str, *, invert: bool = False, border: int = 2) -> str:
    # ERROR_CORRECT_M matches the app's default and keeps the symbol compact.
    qr = qrcode.QRCode(error_correction=ERROR_CORRECT_M, border=border)
    qr.add_data(payload)
    qr.make(fit=True)

    # Render using Unicode half-block glyphs so each QR module is a square
    # pixel. We do this ourselves instead of calling qr.print_ascii(tty=True)
    # because the library insists its output stream must itself be a tty,
    # which breaks when rendering into a StringIO buffer.
    #
    # Idea: pack two matrix rows into one terminal row.
    #   top dark  + bot dark   → '█'  (full block)
    #   top dark  + bot light  → '▀'  (upper half)
    #   top light + bot dark   → '▄'  (lower half)
    #   top light + bot light  → ' '  (space)
    # 'dark' = a printed module in the QR. For terminal readability we invert
    # by default: dark module → space on white-fg terminal won't work, so we
    # treat dark=space and light=block. --invert flips it.
    matrix = qr.get_matrix()  # list[list[bool]]; True = dark (printed) module
    h = len(matrix)
    w = len(matrix[0]) if h else 0

    # Pad to even height so pairs always line up.
    if h % 2 == 1:
        matrix.append([False] * w)
        h += 1

    dark_is_block = invert  # default: dark modules render as space (light bg)
    GLYPHS = {
        (True,  True):  "█" if dark_is_block else " ",
        (True,  False): "▀" if dark_is_block else "▄",
        (False, True):  "▄" if dark_is_block else "▀",
        (False, False): " " if dark_is_block else "█",
    }

    lines = []
    for y in range(0, h, 2):
        top = matrix[y]
        bot = matrix[y + 1]
        lines.append("".join(GLYPHS[(top[x], bot[x])] for x in range(w)))

    return "\n".join(lines) + "\n"


def save_png(payload: str, path: str, *, box_size: int = 10, border: int = 2) -> None:
    qr = qrcode.QRCode(error_correction=ERROR_CORRECT_M, box_size=box_size, border=border)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(path)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="wifiqr.py",
        description="Generate a V360 Pro / Cloudbirds Wi-Fi provisioning QR locally.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Payload is S<ssid>\\n<pwd>\\n — see module docstring for details.",
    )
    p.add_argument("ssid", nargs="?", help="Wi-Fi SSID (positional or via -s)")
    p.add_argument("pwd", nargs="?", help="Wi-Fi password (positional; omit to be prompted)")
    p.add_argument("-s", "--ssid", dest="ssid_flag", help="Wi-Fi SSID (alternative to positional)")
    p.add_argument("-p", "--pwd", dest="pwd_flag", help="Wi-Fi password (alternative to positional)")
    p.add_argument("--stdin-pwd", action="store_true", help="Read password from stdin (one line, no echo)")
    p.add_argument("-o", "--out", help="Also save a PNG to this path")
    p.add_argument("--no-ascii", action="store_true", help="Don't print the QR to the terminal")
    p.add_argument("--invert", action="store_true", help="Invert ASCII colors (try this if the cam misreads)")
    p.add_argument("--border", type=int, default=2, help="Quiet-zone border in modules (default 2)")
    p.add_argument("--box-size", type=int, default=10, help="PNG pixels per module (default 10)")
    p.add_argument("--raw", action="store_true", help="Print the raw payload string instead of a QR")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    ssid = args.ssid_flag or args.ssid
    if not ssid:
        print("error: SSID is required", file=sys.stderr)
        return 2

    if args.stdin_pwd:
        pwd = sys.stdin.readline().rstrip("\n")
    else:
        pwd = args.pwd_flag or args.pwd
        if pwd is None:
            # Prompt without echoing — nicer than having the password stuck in
            # shell history.
            pwd = getpass.getpass(f"Password for {ssid!r}: ")

    payload = build_payload(ssid, pwd)

    if args.raw:
        sys.stdout.write(payload)
        return 0

    if not args.no_ascii:
        sys.stdout.write(render_ascii(payload, invert=args.invert, border=args.border))
        sys.stdout.write("\n")

    if args.out:
        save_png(payload, args.out, box_size=args.box_size, border=args.border)
        print(f"saved PNG → {args.out}", file=sys.stderr)

    # Print the payload at the end for verification, but mask the password so
    # it doesn't land in terminal scrollback.
    masked = "*" * len(pwd) if pwd else ""
    print(f"payload: S{ssid}\\n{masked}\\n", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
