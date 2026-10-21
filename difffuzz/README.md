# difffuzz

Differential fuzzing of `github.com/crux153/siv-go` against BoringSSL's
AES-GCM-SIV, an independent C and assembly implementation. Upstream
`github.com/ericlagergren/siv`, which this fork derives from, only
breaks ties: a failure message says whether upstream agrees with
BoringSSL, and `TestReferencesAgree` checks that the two match. It
is a separate module so that the root module does not depend on the
references.

BoringSSL is linked with cgo under `-tags difffuzz_boringssl` from a
static `libcrypto.a` that `boringssl.sh` builds into `.cache/` inside
the `golang:1.26` image (no cmake needed). Without the tag, upstream
is the reference.

- `FuzzAEAD`: `NewGCM` Seal/Open against the reference.
- `FuzzSegment`: `SegmentCipher` Seal/Open and `SegmentSealer` tilings.
- `FuzzSealerOps`: random `SegmentSealer` call sequences, including
  segments abandoned before `Finish`.
- `TestWrapHunt` (`WRAPHUNT=<duration>`): searches for inputs whose
  32-bit CTR counter wraps inside the message and checks every path.

`run.sh <end-epoch>` runs all four in Docker (`golang:1.26`) until the
given time; `status.sh` prints a summary. Failures are written to
`failures/` and Go fuzz crashers to `testdata/fuzz/`.
