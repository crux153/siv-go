package difffuzz

import (
	"bytes"
	"errors"
	"fmt"

	siv "github.com/crux153/siv-go"
)

// checkAEAD compares the fork's general cipher.AEAD with the
// references on one input: Seal (fresh, appended, exactly aliased),
// Open (fresh, aliased), Tink decryption (sampled), and rejection of a
// tampered byte at flipPos.
func checkAEAD(key, nonce, pt, aad []byte, flipPos int, flipBit uint) error {
	sc := getScratch()
	defer putScratch(sc)
	n := len(pt)
	want, err := refSealTo(&sc.want, &sc.alt, key, nonce, pt, aad)
	if err != nil {
		return err
	}
	f := mustFork(key)

	if got := f.Seal(grow(&sc.got, n+siv.TagSize)[:0], nonce, pt, aad); !bytes.Equal(got, want) {
		return fmt.Errorf("NewGCM Seal differs from upstream (len %d, aad %d)", n, len(aad))
	}
	prefix := []byte{0xde, 0xad, 0xbe}
	pre := grow(&sc.pre, len(prefix)+n+siv.TagSize)
	copy(pre, prefix)
	if got := f.Seal(pre[:len(prefix)], nonce, pt, aad); !bytes.Equal(got[:3], prefix) || !bytes.Equal(got[3:], want) {
		return fmt.Errorf("NewGCM Seal with dst prefix differs (len %d)", n)
	}
	buf := grow(&sc.buf, n+siv.TagSize)[:n]
	copy(buf, pt)
	if got := f.Seal(buf[:0], nonce, buf, aad); !bytes.Equal(got, want) {
		return fmt.Errorf("NewGCM in-place Seal differs (len %d)", n)
	}

	back, err := f.Open(grow(&sc.back, n)[:0], nonce, want, aad)
	if err != nil || !bytes.Equal(back, pt) {
		return fmt.Errorf("NewGCM Open of upstream ciphertext failed (len %d): %v", n, err)
	}
	ct := grow(&sc.ct, len(want))
	copy(ct, want)
	back, err = f.Open(ct[:0], nonce, ct, aad)
	if err != nil || !bytes.Equal(back, pt) {
		return fmt.Errorf("NewGCM in-place Open failed (len %d): %v", n, err)
	}
	// Tink's pure-Go POLYVAL is slow; check it on every small input
	// and on one in 16 large ones.
	if n <= 4096 || flipPos%16 == 0 {
		back, err = tinkOpen(key, nonce, want, aad)
		if err != nil || !bytes.Equal(back, pt) {
			return fmt.Errorf("Tink cannot open the shared ciphertext (len %d): %v", n, err)
		}
	}

	bad := grow(&sc.bad, len(want))
	copy(bad, want)
	bad[flipPos%len(bad)] ^= 1 << (flipBit % 8)
	if out, err := f.Open(sc.back[:0], nonce, bad, aad); err == nil || out != nil {
		return fmt.Errorf("NewGCM Open accepted a tampered byte %d (len %d)", flipPos%len(bad), n)
	}
	return nil
}

// checkSegment compares SegmentCipher and SegmentSealer with the
// references. tilesA and tilesK are the Absorb and KeyStream tilings
// (in bytes, each a multiple of SegmentQuantum, summing to len(pt)).
// If misPos >= 0, a second sealer run changes one plaintext byte at
// misPos between Absorb and KeyStream and must fail Finish.
func checkSegment(key, nonce, pt, aad []byte, segSize int, tilesA, tilesK []int, misPos int, flipPos int) error {
	sc := getScratch()
	defer putScratch(sc)
	n := len(pt)
	want, err := refSealTo(&sc.want, &sc.alt, key, nonce, pt, aad)
	if err != nil {
		return err
	}
	c, err := siv.NewSegmentCipher(key, segSize)
	if err != nil {
		return err
	}
	got, err := c.Seal(grow(&sc.got, n+siv.TagSize)[:0], nonce, pt, aad)
	if err != nil || !bytes.Equal(got, want) {
		return fmt.Errorf("SegmentCipher Seal differs (len %d, seg %d): %v", n, segSize, err)
	}
	buf := grow(&sc.buf, n+siv.TagSize)[:n]
	copy(buf, pt)
	if got, err := c.Seal(buf[:0], nonce, buf, aad); err != nil || !bytes.Equal(got, want) {
		return fmt.Errorf("SegmentCipher in-place Seal differs (len %d): %v", n, err)
	}
	back, err := c.Open(grow(&sc.back, n)[:0], nonce, want, aad)
	if err != nil || !bytes.Equal(back, pt) {
		return fmt.Errorf("SegmentCipher Open failed (len %d): %v", n, err)
	}
	ct := grow(&sc.ct, len(want))
	copy(ct, want)
	if back, err := c.Open(ct[:0], nonce, ct, aad); err != nil || !bytes.Equal(back, pt) {
		return fmt.Errorf("SegmentCipher in-place Open failed (len %d): %v", n, err)
	}
	bad := grow(&sc.bad, len(want))
	copy(bad, want)
	bad[flipPos%len(bad)] ^= 1
	if out, err := c.Open(sc.back[:0], nonce, bad, aad); err == nil || out != nil {
		return fmt.Errorf("SegmentCipher Open accepted a tampered byte %d (len %d)", flipPos%len(bad), n)
	}

	out := grow(&sc.out, n+siv.TagSize)[:n]
	tag, err := runSealer(c, out, nonce, aad, pt, pt, tilesA, tilesK)
	if err != nil {
		return fmt.Errorf("SegmentSealer failed (len %d, tiles %v / %v): %v", n, tilesA, tilesK, err)
	}
	if !bytes.Equal(out, want[:n]) || !bytes.Equal(tag[:], want[n:]) {
		return fmt.Errorf("SegmentSealer output differs (len %d, tiles %v / %v)", n, tilesA, tilesK)
	}

	if misPos >= 0 {
		alt := grow(&sc.alt, n)
		copy(alt, pt)
		alt[misPos%len(alt)] ^= 0x01
		_, err := runSealer(c, out, nonce, aad, pt, alt, tilesA, tilesK)
		if !errors.Is(err, siv.ErrPlaintextMismatch) {
			return fmt.Errorf("SegmentSealer did not detect a changed byte %d (len %d): %v", misPos%len(alt), n, err)
		}
	}
	return nil
}

// runSealer seals with a SegmentSealer (a new one, or reuse[0]),
// absorbing absorb and key-streaming stream into out, which must be
// len(stream) bytes.
func runSealer(c *siv.SegmentCipher, out, nonce, aad, absorb, stream []byte, tilesA, tilesK []int, reuse ...*siv.SegmentSealer) ([siv.TagSize]byte, error) {
	var zero [siv.TagSize]byte
	var s *siv.SegmentSealer
	if len(reuse) > 0 {
		s = reuse[0]
	} else {
		s = c.NewSealer()
	}
	if err := s.Reset(nonce, aad); err != nil {
		return zero, err
	}
	off := 0
	for _, t := range tilesA {
		if err := s.Absorb(absorb[off : off+t]); err != nil {
			return zero, fmt.Errorf("Absorb at %d: %w", off, err)
		}
		off += t
	}
	off = 0
	for _, t := range tilesK {
		if err := s.KeyStream(out[off:off+t], stream[off:off+t]); err != nil {
			return zero, fmt.Errorf("KeyStream at %d: %w", off, err)
		}
		off += t
	}
	return s.Finish()
}

// tiling splits n bytes (a multiple of SegmentQuantum) into tiles
// whose sizes come from src; it falls back to one tile when src runs
// out. Every tile is a non-zero multiple of SegmentQuantum.
func tiling(n int, src []byte) []int {
	const q = siv.SegmentQuantum
	var out []int
	left := n
	for i := 0; left > 0; i++ {
		if i >= len(src) {
			out = append(out, left)
			break
		}
		// Bias towards small and odd tile counts as well as large ones.
		var t int
		switch src[i] >> 6 {
		case 0:
			t = q
		case 1:
			t = (int(src[i]&0x3f) + 1) * q
		default:
			t = (int(src[i]&0x3f) + 1) * q * 16
		}
		t = min(t, left)
		out = append(out, t)
		left -= t
	}
	return out
}
