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

## License

The AES-GCM-SIV code is derived from ericlagergren/siv and is
distributed under the BSD 3-Clause License (see `LICENSE`).
`internal/polyval` is derived from ericlagergren/polyval and is
distributed under the BSD 2-Clause License (see
`internal/polyval/LICENSE`).
