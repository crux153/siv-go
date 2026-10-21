# siv-go

AES-GCM-SIV ([RFC 8452]) for Go, tuned for x86-64 CPUs that have
AES-NI and PCLMULQDQ but no AVX.

This is a fork of [ericlagergren/siv] with
[ericlagergren/polyval] vendored as `internal/polyval`.

[RFC 8452]: https://datatracker.ietf.org/doc/html/rfc8452
[ericlagergren/siv]: https://github.com/ericlagergren/siv
[ericlagergren/polyval]: https://github.com/ericlagergren/polyval

## CPU requirements (fail-closed)

`NewGCM` only returns an AEAD when the constant-time assembly
implementation can be used:

| GOARCH | Required instructions |
|--------|-----------------------|
| amd64  | AES-NI and PCLMULQDQ (SSE2 baseline; no AVX needed) |
| arm64  | AES and PMULL |

On any other CPU, architecture, compiler (gccgo) or with the
`purego` build tag, `NewGCM` returns `ErrUnsupportedCPU` instead
of falling back to `crypto/aes`, whose portable code is not
guaranteed to run in constant time. The portable implementation
is kept only as a reference for tests.

## amd64 implementation

All amd64 assembly uses legacy SSE encodings only (SSE2, AES-NI,
PCLMULQDQ); nothing requires AVX.

- AES-CTR encrypts eight counter blocks per iteration (then four,
  then one), following the structure of [secure-io/siv-go].
- Open decrypts and hashes in a single pass: each iteration runs
  AES-CTR on eight blocks while POLYVAL absorbs the eight plaintext
  blocks of the previous iteration.
- POLYVAL on long inputs precomputes the Karatsuba terms of the key
  powers once per call; the key powers themselves are computed on
  first use with a dependency depth of three.
- The key-generating key is expanded once per AEAD, and the
  per-nonce keys are derived with the CTR code.

[secure-io/siv-go]: https://github.com/secure-io/siv-go

## Testing

```bash
go test ./...                     # native CPU
scripts/noavx.sh go test ./...    # AVX/AVX2/AVX-512/FMA/BMI hidden, 2 CPUs
scripts/noavx-qemu.sh             # optional: qemu-user CPU model without AVX
go test -tags purego ./...        # portable reference code
```

The tests cover the RFC 8452 vectors (including the counter wrap
vectors), Project Wycheproof `aes_gcm_siv_test.json`, random
comparisons with Google Tink, byte-for-byte comparisons with
upstream ericlagergren/siv for every length up to 40 blocks and
random lengths up to 128 KiB, counter wrap-around in every CTR
path, and fail-closed behaviour with `GODEBUG=cpu.aes=off` and
`GODEBUG=cpu.pclmulqdq=off`.

## License

The AES-GCM-SIV code is derived from ericlagergren/siv and is
distributed under the BSD 3-Clause License (see `LICENSE`).
`internal/polyval` is derived from ericlagergren/polyval and is
distributed under the BSD 2-Clause License (see
`internal/polyval/LICENSE`).
