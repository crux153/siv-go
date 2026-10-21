//go:build amd64 && gc && !purego

package siv

import (
	"bytes"
	"testing"
)

// TestSegmentSealerClear checks that Finish drops the sealer's
// key material, whether or not the check succeeds.
func TestSegmentSealerClear(t *testing.T) {
	c := newSegmentCipher(t, randbuf(32), MinSegmentSize)
	s := c.NewSealer()
	pt := randbuf(2 * SegmentQuantum)
	if err := s.Reset(randbuf(NonceSize), randbuf(SegmentAADSize)); err != nil {
		t.Fatal(err)
	}
	if err := s.Absorb(pt); err != nil {
		t.Fatal(err)
	}
	if err := s.KeyStream(pt[:SegmentQuantum], pt[:SegmentQuantum]); err != nil {
		t.Fatal(err)
	}
	if err := s.KeyStream(pt[SegmentQuantum:], pt[SegmentQuantum:]); err != nil {
		t.Fatal(err)
	}
	if s.enc == (keySchedule{}) {
		t.Fatal("sealer cleared before Finish")
	}
	if _, err := s.Finish(); err != nil {
		t.Fatal(err)
	}
	pv, err := s.pv.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if s.enc != (keySchedule{}) || s.tag != [TagSize]byte{} || s.ctr != [TagSize]byte{} ||
		s.nonce != [NonceSize]byte{} || s.aadAcc != [16]byte{} || s.ptAcc != [16]byte{} ||
		s.phase != phaseIdle || !bytes.Equal(pv, make([]byte, len(pv))) {
		t.Fatal("sealer still holds key material after Finish")
	}
}
