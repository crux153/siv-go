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

## Results

### 2026-10-22, 7 hours

Run against commits 1f98ef8 to dd5fbd4 (library code unchanged
between them), with no failures:

| Target          | Executions | Corpus |
|-----------------|-----------:|-------:|
| `FuzzAEAD`      |     6.65e9 |     86 |
| `FuzzSegment`   |     1.58e9 |     97 |
| `FuzzSealerOps` |     2.44e9 |    173 |

`TestWrapHunt` checked 27.0M inputs whose CTR counter wraps inside the
message (21.5M of them also on the segment paths), with no failures
and no mispredicted tags. The wraps were spread evenly over the eight
block positions within an 8-block group.
