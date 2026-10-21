//go:build !race

package siv

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// TestSegmentConcurrentMutation seals while another goroutine
// keeps modifying the plaintext, which is a data race in the
// caller. Every output that Seal or Finish accepts must open
// successfully; the others must be rejected with
// ErrPlaintextMismatch (and, for Seal, zeroed).
//
// The race is deliberate, so the test is excluded from -race
// builds.
func TestSegmentConcurrentMutation(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("needs two CPUs")
	}
	const n = MinSegmentSize
	c := newSegmentCipher(t, randbuf(32), n)
	pt := randbuf(n)
	nonce := randbuf(NonceSize)
	aad := randbuf(SegmentAADSize)

	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			pt[(i*4099)%n]++
		}
	}()

	iters := 300
	if testing.Short() {
		iters = 50
	}
	var accepted, rejected int
	s := c.NewSealer()
	out := make([]byte, n+TagSize)
	for i := 0; i < iters; i++ {
		var ct []byte
		var err error
		if i%2 == 0 {
			ct, err = c.Seal(out[:0], nonce, pt, aad)
			if errors.Is(err, ErrPlaintextMismatch) {
				for j, b := range out {
					if b != 0 {
						t.Fatalf("out[%d] = %#x after a rejected Seal", j, b)
					}
				}
			}
		} else {
			if err := s.Reset(nonce, aad); err != nil {
				t.Fatal(err)
			}
			if err := s.Absorb(pt); err != nil {
				t.Fatal(err)
			}
			if err := s.KeyStream(out[:n], pt); err != nil {
				t.Fatal(err)
			}
			var tag [TagSize]byte
			tag, err = s.Finish()
			copy(out[n:], tag[:])
			ct = out
		}
		switch {
		case err == nil:
			accepted++
			if _, err := c.Open(nil, nonce, ct, aad); err != nil {
				t.Fatalf("iteration %d: accepted output does not open: %v", i, err)
			}
		case errors.Is(err, ErrPlaintextMismatch):
			rejected++
		default:
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("accepted %d, rejected %d", accepted, rejected)
}
