#!/usr/bin/env bash
# Run a command as if on a dual-core x86-64 CPU with AES-NI,
# PCLMULQDQ and SSE4.1/4.2 but without AVX, AVX2, AVX-512, FMA or
# BMI.
#
# GODEBUG hides those features from both the Go runtime
# (internal/cpu, which drives crypto/aes, crypto/cipher, memmove,
# ...) and golang.org/x/sys/cpu. GOMAXPROCS=2 and taskset restrict
# the process to two logical CPUs.
#
# GODEBUG only changes feature detection; it cannot stop an AVX
# instruction from executing. scripts/noavx-qemu.sh is an optional,
# stronger check.
#
# Usage: scripts/noavx.sh go test -run '^$' -bench . ./...
set -euo pipefail

export GODEBUG="cpu.avx=off,cpu.avx2=off,cpu.avx512f=off,cpu.fma=off,cpu.bmi1=off,cpu.bmi2=off${GODEBUG:+,$GODEBUG}"
export GOMAXPROCS=2

if command -v taskset >/dev/null 2>&1; then
	exec taskset -c 0,1 "$@"
fi
exec "$@"
