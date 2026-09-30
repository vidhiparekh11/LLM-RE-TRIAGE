#!/usr/bin/env bash
# Builds a stripped, benign demo binary (needs gcc + python3). Usage: examples/build_demo.sh [out]
set -euo pipefail
OUT=${1:-demo_target}; HERE=$(cd "$(dirname "$0")" && pwd); KEY=${DEMO_XOR_KEY:-0x5a}
PLAIN='http://c2.example.invalid/gate.php'
TMP=$(mktemp -d)
python3 - "$HERE/demo.c.in" "$TMP/demo.c" "$PLAIN" "$KEY" <<'PY'
import sys
src, dst, plain, key = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4], 0)
enc = [b ^ key for b in plain.encode()] + [0]
t = open(src).read().replace("@ENC_BYTES@", ", ".join(f"0x{b:02x}" for b in enc)).replace("@KEY@", hex(key))
open(dst, "w").write(t)
PY
gcc -O0 -fno-stack-protector -fcf-protection=none -o "$OUT" "$TMP/demo.c"
strip "$OUT"
echo "built $OUT (stripped, benign; plaintext indicator: $PLAIN, key $KEY)"
