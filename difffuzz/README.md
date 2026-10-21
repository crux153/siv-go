# difffuzz

Differential fuzzing of `github.com/crux153/siv-go` against upstream
`github.com/ericlagergren/siv` (per-block CTR, independent of this
fork's kernels), BoringSSL (an independent C and assembly
implementation, which must seal exactly like upstream). It is a
separate module so that the root module does not depend on the
references.

BoringSSL is linked with cgo under `-tags difffuzz_boringssl` from a
static `libcrypto.a` that `boringssl.sh` builds into `.cache/` inside
the `golang:1.26` image (no cmake needed). Without the tag the
BoringSSL comparison is left out.

- `FuzzAEAD`: `NewGCM` Seal/Open against the references.
- `FuzzSegment`: `SegmentCipher` Seal/Open and `SegmentSealer` tilings.
- `FuzzSealerOps`: random `SegmentSealer` call sequences, including
  segments abandoned before `Finish`.
- `TestWrapHunt` (`WRAPHUNT=<duration>`): searches for inputs whose
  32-bit CTR counter wraps inside the message and checks every path.

`run.sh <end-epoch>` runs all four in Docker (`golang:1.26`) until the
given time; `status.sh` prints a summary. Failures are written to
`failures/` and Go fuzz crashers to `testdata/fuzz/`.
