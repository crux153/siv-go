# siv-go

AES-GCM-SIV ([RFC 8452]) for Go, tuned for x86-64 CPUs that have
AES-NI and PCLMULQDQ but no AVX.

This is a fork of [ericlagergren/siv] with
[ericlagergren/polyval] vendored as `internal/polyval`.

[RFC 8452]: https://datatracker.ietf.org/doc/html/rfc8452
[ericlagergren/siv]: https://github.com/ericlagergren/siv
[ericlagergren/polyval]: https://github.com/ericlagergren/polyval

## License

The AES-GCM-SIV code is derived from ericlagergren/siv and is
distributed under the BSD 3-Clause License (see `LICENSE`).
`internal/polyval` is derived from ericlagergren/polyval and is
distributed under the BSD 2-Clause License (see
`internal/polyval/LICENSE`).
