#!/usr/bin/env bash
# open-talktalk client patcher
# patches GarenaMessenger.exe to force the pre-login gate to always pass, so the
# client proceeds past pre-login regardless of what the server replies.
#
# usage:  ./patch.sh GarenaMessenger.exe
# output: GarenaMessenger.patched.exe  (original is never modified)
#
# what it patches:
#   PreLogin_Gatekeeper @ ghidra 0x009f6210 (file offset 0x5f5610)
#   original: 55 8B EC   (push ebp; mov ebp,esp; ...)
#   patched : B0 01 C3   (mov al,1; ret)  -> always returns "success"

set -euo pipefail

SRC="${1:-GarenaMessenger.exe}"
OUT="${SRC%.exe}.patched.exe"

OFFSET=$((0x5f5610))
ORIG="558bec"
PATCH="b001c3"

hexat() { # file offset count -> hex string
  dd if="$1" bs=1 skip="$2" count="$3" 2>/dev/null | od -An -tx1 | tr -d ' \n'
}

if [[ ! -f "$SRC" ]]; then
  echo "error: '$SRC' not found"
  echo "usage: ./patch.sh GarenaMessenger.exe"
  exit 1
fi

GOT=$(hexat "$SRC" $OFFSET 3)
if [[ "$GOT" != "$ORIG" ]]; then
  echo "error: bytes at offset $OFFSET are '$GOT', expected '$ORIG'"
  echo "this exe may be a different version. aborting so we don't corrupt it."
  exit 1
fi

cp "$SRC" "$OUT"
printf '\xb0\x01\xc3' | dd of="$OUT" bs=1 seek=$OFFSET count=3 conv=notrunc 2>/dev/null

NEW=$(hexat "$OUT" $OFFSET 3)
if [[ "$NEW" == "$PATCH" ]]; then
  echo "patched OK -> $OUT"
  echo "  gatekeeper @ 0x9f6210 now always returns success"
  echo ""
  echo "next: run the patched exe, point live.imconnect.garenanow.com at your"
  echo "server via the hosts file, run your proxy on :9100, and log in."
else
  echo "error: verification failed (got '$NEW'). aborting."
  exit 1
fi