package difffuzz

import (
	"bytes"
	"testing"

	siv "github.com/crux153/siv-go"
)

// TestResetWithoutFinish is the reproduction of a bug in siv-go
// d4521a2: SegmentSealer.Reset re-keyed the sealer's POLYVAL state
// with Polyval.Init, which kept the accumulator, so a Reset that
// followed Reset/Absorb/KeyStream without an intervening Finish sealed
// the next segment from a polluted accumulator. The tag and
// ciphertext differed from RFC 8452, Finish still succeeded (both
// passes were polluted alike), and Open rejected the output.
func TestResetWithoutFinish(t *testing.T) {
	key := fit([]byte("k"), 32)
	nonce := fit([]byte("n"), siv.NonceSize)
	aad := fit([]byte("a"), aadSegment)
	pt := fit([]byte("p"), 4096)
	want := refSeal(key, nonce, pt, aad)
	c, err := siv.NewSegmentCipher(key, siv.MinSegmentSize)
	if err != nil {
		t.Skip(err)
	}
	for name, prep := range map[string]func(*siv.SegmentSealer){
		"Reset twice":          func(s *siv.SegmentSealer) { s.Reset(nonce, aad) },
		"abandon after Absorb": func(s *siv.SegmentSealer) { s.Reset(nonce, aad); s.Absorb(pt[:256]) },
		"abandon mid KeyStream": func(s *siv.SegmentSealer) {
			s.Reset(nonce, aad)
			s.Absorb(pt)
			s.KeyStream(make([]byte, 256), pt[:256])
		},
	} {
		s := c.NewSealer()
		prep(s)
		out := make([]byte, len(pt))
		tag, err := runSealer(c, out, nonce, aad, pt, pt, []int{len(pt)}, []int{len(pt)}, s)
		if err != nil || !bytes.Equal(append(out, tag[:]...), want) {
			t.Errorf("%s: output differs from RFC 8452 (err %v)", name, err)
		}
	}
}
