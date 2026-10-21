#!/usr/bin/env bash
# Optional: run the test binaries under qemu-user with a CPU model
# that has AES-NI and PCLMULQDQ but no AVX, AVX2, AVX-512, FMA or
# BMI. Unlike GODEBUG, this makes any VEX/EVEX-encoded instruction
# fault with SIGILL, so a passing run shows that none is executed.
#
# Requires qemu-x86_64 (e.g. the qemu-user package).
#
# Usage: scripts/noavx-qemu.sh [go test flags...]
set -euo pipefail

cpu='Skylake-Client,-hle,-rtm,-avx,-avx2,-fma,-f16c,-avx512f,-bmi1,-bmi2,-xsavec'
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for pkg in . ./internal/polyval; do
	bin="$tmp/$(basename "$(cd "$root/$pkg" && pwd)").test"
	(cd "$root" && go test -c -o "$bin" "$pkg")
	echo "== $pkg"
	(cd "$root/$pkg" && qemu-x86_64 -cpu "$cpu" "$bin" -test.short "$@")
done
