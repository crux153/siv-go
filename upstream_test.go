package siv

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"testing"

	rand "github.com/ericlagergren/saferand"
	upstream "github.com/ericlagergren/siv"
)

// TestUpstream checks that Seal and Open produce exactly the same
// output as github.com/ericlagergren/siv, the code this package
// was forked from.
//
// Every plaintext length up to 40 blocks is covered, which
// exercises every combination of the 8-way, 4-way and single
// block CTR paths plus a partial final block, followed by a set
// of larger random lengths.
func TestUpstream(t *testing.T) {
	runTests(t, func(t *testing.T) {
		for _, keySize := range []int{16, 32} {
			t.Run(fmt.Sprintf("%d", keySize*8), func(t *testing.T) {
				testUpstream(t, keySize)
			})
		}
	})
}

func testUpstream(t *testing.T, keySize int) {
	var lengths []int
	for n := 0; n <= 40*blockSize; n++ {
		lengths = append(lengths, n)
	}
	for i := 0; i < 64; i++ {
		lengths = append(lengths, rand.Intn(1<<17))
	}
	aadLengths := []int{0, 1, 15, 16, 17, 127, 128, 129, 1000}

	for i, n := range lengths {
		key := randbuf(keySize)
		nonce := randbuf(NonceSize)
		plaintext := randbuf(n)
		aad := randbuf(aadLengths[i%len(aadLengths)])

		want, err := upstream.NewGCM(key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := NewGCM(key)
		if err != nil {
			t.Fatal(err)
		}
		compareAEADs(t, want, got, nonce, plaintext, aad)
	}
}

func compareAEADs(t *testing.T, want, got cipher.AEAD, nonce, plaintext, aad []byte) {
	t.Helper()

	wantCt := want.Seal(nil, nonce, plaintext, aad)
	gotCt := got.Seal(nil, nonce, plaintext, aad)
	if !bytes.Equal(wantCt, gotCt) {
		for i := range wantCt {
			if wantCt[i] != gotCt[i] {
				t.Fatalf("len(pt)=%d len(aad)=%d: first mismatch at byte %d (block %d)",
					len(plaintext), len(aad), i, i/blockSize)
			}
		}
	}

	// In-place Seal must match too.
	inPlace := append(make([]byte, 0, len(plaintext)+TagSize), plaintext...)
	inPlace = got.Seal(inPlace[:0], nonce, inPlace, aad)
	if !bytes.Equal(wantCt, inPlace) {
		t.Fatalf("len(pt)=%d: in-place Seal mismatch", len(plaintext))
	}

	wantPt, wantErr := want.Open(nil, nonce, wantCt, aad)
	gotPt, gotErr := got.Open(nil, nonce, wantCt, aad)
	if wantErr != nil || gotErr != nil {
		t.Fatalf("len(pt)=%d: Open failed: upstream=%v got=%v",
			len(plaintext), wantErr, gotErr)
	}
	if !bytes.Equal(wantPt, gotPt) || !bytes.Equal(gotPt, plaintext) {
		t.Fatalf("len(pt)=%d: Open mismatch", len(plaintext))
	}

	// Flip one bit anywhere in the ciphertext or tag: both
	// implementations must reject it.
	bad := append([]byte(nil), wantCt...)
	bit := rand.Intn(len(bad) * 8)
	bad[bit/8] ^= 1 << (bit % 8)
	if _, err := want.Open(nil, nonce, bad, aad); err == nil {
		t.Fatalf("len(pt)=%d: upstream accepted a forgery", len(plaintext))
	}
	if _, err := got.Open(nil, nonce, bad, aad); err == nil {
		t.Fatalf("len(pt)=%d: accepted a forgery", len(plaintext))
	}
}
