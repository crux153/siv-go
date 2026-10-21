package siv

import (
	"crypto/aes"
	"errors"
	"testing"
)

// TestFailClosed tests that NewGCM refuses to fall back to the
// portable implementation when the assembly implementation is
// unavailable.
func TestFailClosed(t *testing.T) {
	oldAsm, oldGeneric := haveAsm, allowGeneric
	haveAsm, allowGeneric = false, false
	t.Cleanup(func() {
		haveAsm, allowGeneric = oldAsm, oldGeneric
	})

	for _, n := range []int{16, 32} {
		aead, err := NewGCM(make([]byte, n))
		if !errors.Is(err, ErrUnsupportedCPU) {
			t.Fatalf("%d: expected %v, got %v", n, ErrUnsupportedCPU, err)
		}
		if aead != nil {
			t.Fatalf("%d: expected nil AEAD", n)
		}
	}

	// Invalid key sizes are still reported as such.
	_, err := NewGCM(make([]byte, 24))
	var kse aes.KeySizeError
	if !errors.As(err, &kse) {
		t.Fatalf("unexpected error: %v", err)
	}
}
