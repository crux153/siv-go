//go:build amd64 && gc && !purego

package polyval

import (
	"testing"

	"golang.org/x/exp/rand"
)

func disableAsm(t *testing.T) {
	old := haveAsm
	t.Cleanup(func() {
		haveAsm = old
	})
	haveAsm = false
}

func runTests(t *testing.T, fn func(t *testing.T)) {
	if haveAsm {
		t.Run("assembly", fn)
	}
	t.Run("generic", func(t *testing.T) {
		disableAsm(t)
		fn(t)
	})
}

// TestWide compares polymulWideAsm with polymulBlocksAsm for
// every input length around wideMinBytes and a few long ones.
func TestWide(t *testing.T) {
	if !haveAsm {
		t.Skip("CPU lacks PCLMULQDQ")
	}
	key := make([]byte, 16)
	data := make([]byte, 64*1024+16*7)
	for i := 0; i < 200; i++ {
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		var p Polyval
		if err := p.Init(key); err != nil {
			continue
		}
		p.initPow()
		start := p.y
		start.lo ^= uint64(i)

		var lengths []int
		for n := 16; n <= 2*wideMinBytes+16*8; n += 16 {
			lengths = append(lengths, n)
		}
		lengths = append(lengths, len(data))
		for _, n := range lengths {
			want := start
			polymulBlocksAsm(&want, &p.pow, &data[0], n/16)
			got := start
			polymulBlocks(&got, &p.pow, data[:n])
			if got != want {
				t.Fatalf("n=%d: expected %v, got %v", n, want, got)
			}
		}
	}
}
