// Package difffuzz differentially fuzzes github.com/crux153/siv-go
// against independent AES-GCM-SIV implementations:
//
//   - github.com/ericlagergren/siv (upstream; per-block CTR, so its CTR
//     shares no code with the fork's pipelined kernels)
//   - github.com/tink-crypto/tink-go/v2 (pure-Go POLYVAL and CTR; decrypt
//     side only, because its Encrypt picks a random nonce)
//
// It lives in its own module so the fork itself is not modified.
package difffuzz

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"time"

	siv "github.com/crux153/siv-go"
	eric "github.com/ericlagergren/siv"
	tink "github.com/tink-crypto/tink-go/v2/aead/subtle"
)

const aadSegment = siv.SegmentAADSize // 57

// refSeal is the upstream reference.
func refSeal(key, nonce, pt, aad []byte) []byte {
	a, err := eric.NewGCM(key)
	if err != nil {
		panic(err)
	}
	return a.Seal(nil, nonce, pt, aad)
}

// tinkOpen decrypts with Tink (nonce is prepended in Tink's format).
func tinkOpen(key, nonce, ct, aad []byte) ([]byte, error) {
	t, err := tink.NewAESGCMSIV(key)
	if err != nil {
		return nil, err
	}
	return t.Decrypt(append(bytes.Clone(nonce), ct...), aad)
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
	out := make([]byte, n)
	copy(out, b)
	if len(b) < n {
		var seed [32]byte
		copy(seed[:], b)
		seed[31] ^= byte(len(b))
		fillRand(rand.New(rand.NewChaCha8(seed)), out[len(b):])
	}
	return out
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
