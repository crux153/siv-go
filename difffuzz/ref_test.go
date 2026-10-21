// Package difffuzz differentially fuzzes github.com/crux153/siv-go
// against BoringSSL's AES-GCM-SIV (C and assembly; built by
// boringssl.sh and linked with -tags difffuzz_boringssl), which shares
// no code with the fork.
//
// Upstream github.com/ericlagergren/siv, which the fork derives from,
// is not compared on every execution: it is the reference only when
// BoringSSL is not linked in, and otherwise tells, on a failure,
// whether BoringSSL or the fork is wrong. TestReferencesAgree checks
// that the two agree.
//
// It lives in its own module so the fork itself is not modified.
package difffuzz

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	siv "github.com/crux153/siv-go"
	eric "github.com/ericlagergren/siv"
)

const aadSegment = siv.SegmentAADSize // 57

// refSealTo seals into *want, which is reused when large enough,
// with the reference: BoringSSL when it is linked in, upstream
// otherwise.
func refSealTo(want *[]byte, key, nonce, pt, aad []byte) []byte {
	if haveBoring {
		return boringSeal(grow(want, len(pt)+siv.TagSize), key, nonce, pt, aad)
	}
	return upstreamSeal(grow(want, len(pt)+siv.TagSize)[:0], key, nonce, pt, aad)
}

// refSeal is refSealTo with a fresh buffer.
func refSeal(key, nonce, pt, aad []byte) []byte {
	var want []byte
	return refSealTo(&want, key, nonce, pt, aad)
}

// upstreamSeal appends upstream's ciphertext||tag to dst.
func upstreamSeal(dst, key, nonce, pt, aad []byte) []byte {
	a, err := eric.NewGCM(key)
	if err != nil {
		panic(err)
	}
	return a.Seal(dst, nonce, pt, aad)
}

// triage annotates a failed check against BoringSSL with whether
// upstream agrees with BoringSSL, which tells a fork bug from a
// reference bug.
func triage(err error, key, nonce, pt, aad []byte) error {
	if err == nil || !haveBoring {
		return err
	}
	if bytes.Equal(upstreamSeal(nil, key, nonce, pt, aad), refSeal(key, nonce, pt, aad)) {
		return fmt.Errorf("%w [upstream agrees with BoringSSL]", err)
	}
	return fmt.Errorf("%w [upstream DISAGREES with BoringSSL: check the references]", err)
}

// scratch holds buffers that are reused across executions, so that
// inputs of up to a few MiB do not churn the heap and the GC on
// every call.
type scratch struct {
	pt, want, alt, got, buf, pre, back, ct, bad, out []byte
}

var scratchPool = sync.Pool{New: func() any { return new(scratch) }}

func getScratch() *scratch   { return scratchPool.Get().(*scratch) }
func putScratch(sc *scratch) { scratchPool.Put(sc) }

// grow returns (*p)[:n], reallocating only if *p is too small. The
// contents are not cleared.
func grow(p *[]byte, n int) []byte {
	if cap(*p) < n {
		*p = make([]byte, n)
	}
	return (*p)[:n]
}

func mustFork(key []byte) cipher.AEAD {
	a, err := siv.NewGCM(key)
	if err != nil {
		panic(err)
	}
	return a
}

// fit returns b resized to n bytes: truncated, or extended
// deterministically from its own content.
func fit(b []byte, n int) []byte {
	return fitTo(make([]byte, n), b)
}

// fitTo is fit into out, which it returns.
func fitTo(out, b []byte) []byte {
	n := copy(out, b)
	if n < len(out) {
		var seed [32]byte
		copy(seed[:], b)
		seed[31] ^= byte(len(b))
		streamFill(out[n:], &seed)
	}
	return out
}

// streamFill fills out with AES-CTR keystream from seed, which is
// several times faster than ChaCha8 for the MiB-sized plaintexts.
func streamFill(out []byte, seed *[32]byte) {
	blk, err := aes.NewCipher(seed[:16])
	if err != nil {
		panic(err)
	}
	clear(out)
	cipher.NewCTR(blk, seed[16:]).XORKeyStream(out, out)
}

func fillRand(r *rand.Rand, b []byte) {
	for len(b) >= 8 {
		binary.LittleEndian.PutUint64(b, r.Uint64())
		b = b[8:]
	}
	for i := range b {
		b[i] = byte(r.Uint32())
	}
}

// segSizeFor returns the smallest valid segment size >= n.
func segSizeFor(n int) int {
	s := siv.MinSegmentSize
	for s < n {
		s <<= 1
	}
	return s
}

// record writes a failing case to failures/ so it survives the log.
var recordMu sync.Mutex

func record(kind string, fields map[string][]byte, msg string) string {
	recordMu.Lock()
	defer recordMu.Unlock()
	dir := os.Getenv("DIFFFUZZ_FAILDIR")
	if dir == "" {
		dir = "failures"
	}
	_ = os.MkdirAll(dir, 0o755)
	name := filepath.Join(dir, fmt.Sprintf("%s-%d.txt", kind, time.Now().UnixNano()))
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s\n", msg)
	for k, v := range fields {
		fmt.Fprintf(&b, "%s=%x\n", k, v)
	}
	_ = os.WriteFile(name, b.Bytes(), 0o644)
	return name
}

// TestReferencesAgree checks BoringSSL against upstream on every
// length up to 1 KiB and some larger ones.
func TestReferencesAgree(t *testing.T) {
	if !haveBoring {
		t.Skip("built without -tags difffuzz_boringssl")
	}
	var want, up []byte
	for _, keyLen := range []int{16, 32} {
		for n := 0; n <= 1<<20; {
			key := fit([]byte{byte(n), byte(n >> 8)}, keyLen)
			nonce := fit(key, siv.NonceSize)
			aad := fit(nonce, n%97)
			pt := fit(aad, n)
			w := refSealTo(&want, key, nonce, pt, aad)
			up = upstreamSeal(up[:0], key, nonce, pt, aad)
			if !bytes.Equal(w, up) {
				t.Fatalf("BoringSSL differs from upstream (key %d, len %d, aad %d)", keyLen, n, len(aad))
			}
			if n < 1024 {
				n++
			} else {
				n = n*3/2 + 1
			}
		}
	}
}
