//go:build amd64 && gc && !purego

package siv

import (
	"github.com/crux153/siv-go/internal/polyval"
	"github.com/ericlagergren/subtle"
)

// SegmentCipher is AES-GCM-SIV restricted to a fixed input
// shape:
//
//   - the nonce is NonceSize bytes,
//   - the additional data is exactly SegmentAADSize bytes,
//   - the plaintext is a non-zero multiple of SegmentQuantum
//     bytes and at most the segment size.
//
// Inputs of any other shape are rejected with ErrSegmentShape.
// Within that shape its output is identical to NewGCM.
//
// SegmentCipher is only available with the amd64 assembly
// implementation; elsewhere NewSegmentCipher returns
// ErrUnsupportedCPU.
//
// A SegmentCipher is safe for concurrent use.
type SegmentCipher struct {
	kgk         keySchedule
	keyLen      int
	segmentSize int
}

// SegmentSize returns the maximum plaintext length.
func (c *SegmentCipher) SegmentSize() int {
	return c.segmentSize
}

func (c *SegmentCipher) checkShape(nonce, additionalData []byte, n int) error {
	if len(nonce) != NonceSize ||
		len(additionalData) != SegmentAADSize ||
		!c.checkLength(n) {
		return ErrSegmentShape
	}
	return nil
}

func (c *SegmentCipher) checkLength(n int) bool {
	return n >= SegmentQuantum && n <= c.segmentSize && n%SegmentQuantum == 0
}

// sealerPhase is the state of a SegmentSealer.
type sealerPhase int

const (
	phaseIdle sealerPhase = iota
	phaseAbsorb
	phaseKeyStream
	phaseFinish
)

// SegmentSealer encrypts one segment in two passes so that the
// caller can process the plaintext in tiles:
//
//  1. Reset with the nonce and additional data, then Absorb
//     every plaintext tile in order.
//  2. KeyStream encrypts the same plaintext, tile by tile and in
//     the same order (the tiling may differ from step 1).
//  3. Finish checks that the plaintext passed to KeyStream is the
//     plaintext passed to Absorb and returns the authentication
//     tag, the last TagSize bytes of the sealed segment.
//
// KeyStream hashes the plaintext it encrypts, reading each byte
// once, and Finish compares that hash with the one computed by
// Absorb in constant time. If they differ (the caller passed
// different data, or the buffer changed between the two passes),
// Finish returns ErrPlaintextMismatch and no tag. The output of
// KeyStream must not be used before Finish succeeds and must be
// discarded if it fails: it is not a valid encryption and reusing
// its key stream would leak the XOR of the two plaintexts.
//
// Tiles must be non-zero multiples of SegmentQuantum bytes and
// the total must be a valid segment length. The result,
// ciphertext || tag, is identical to SegmentCipher.Seal.
//
// A SegmentSealer is not safe for concurrent use. It can be
// reused for further segments by calling Reset, which also
// abandons a segment in progress. Per-segment key material is
// dropped by Finish.
type SegmentSealer struct {
	c     *SegmentCipher
	phase sealerPhase
	enc   keySchedule
	pv    polyval.Polyval
	nonce [NonceSize]byte
	// aadAcc and ptAcc are the POLYVAL states after the
	// additional data and after the absorbed plaintext.
	aadAcc   [16]byte
	ptAcc    [16]byte
	tag      [TagSize]byte
	ctr      [TagSize]byte
	absorbed int
	streamed int
}

// NewSealer returns a SegmentSealer for c. Reset must be called
// before use.
func (c *SegmentCipher) NewSealer() *SegmentSealer {
	return &SegmentSealer{c: c}
}

// NewSegmentCipher creates a SegmentCipher.
//
// The key must be 16 or 32 bytes. segmentSize is the maximum
// plaintext length and must be a power of two between
// MinSegmentSize and MaxSegmentSize. NewSegmentCipher returns
// ErrUnsupportedCPU if the CPU lacks AES-NI or PCLMULQDQ.
func NewSegmentCipher(key []byte, segmentSize int) (*SegmentCipher, error) {
	if _, err := NewGCM(key); err != nil {
		return nil, err
	}
	if err := checkSegmentSize(segmentSize); err != nil {
		return nil, err
	}
	if !haveAsm {
		// NewGCM only succeeds without assembly in tests.
		return nil, ErrUnsupportedCPU
	}
	c := &SegmentCipher{keyLen: len(key), segmentSize: segmentSize}
	c.kgk.init(key)
	return c, nil
}

// Seal encrypts and authenticates plaintext, authenticates
// additionalData and appends ciphertext || tag to dst.
//
// It returns ErrSegmentShape if the inputs do not have the shape
// described by SegmentCipher. dst may alias plaintext exactly,
// but must not otherwise overlap it.
//
// Seal reads the plaintext twice, once to authenticate it and
// once to encrypt it, and checks that both passes saw the same
// data. If the plaintext changed in between, the output is
// zeroed and ErrPlaintextMismatch is returned.
func (c *SegmentCipher) Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if err := c.checkShape(nonce, additionalData, len(plaintext)); err != nil {
		return nil, err
	}
	ret, out := subtle.SliceForAppend(dst, len(plaintext)+TagSize)
	if subtle.InexactOverlap(out, plaintext) {
		return nil, ErrSegmentShape
	}

	var s SegmentSealer
	s.c = c
	s.reset(nonce, additionalData)
	s.absorb(plaintext)
	s.startKeyStream()
	s.keyStream(out[:len(plaintext)], plaintext)
	tag, ok := s.finish()
	if !ok {
		wipe(out)
		return nil, ErrPlaintextMismatch
	}
	*(*[TagSize]byte)(out[len(plaintext):]) = tag
	return ret, nil
}

// Open authenticates additionalData and ciphertext, which
// must be ciphertext || tag, and if successful appends the
// plaintext to dst.
//
// It returns ErrSegmentShape if the inputs do not have the shape
// described by SegmentCipher. Decryption and authentication run
// in a single pass; if the tag does not verify, the decrypted
// data written to dst is zeroed and an error is returned. dst
// may alias ciphertext exactly, but must not otherwise overlap
// it.
func (c *SegmentCipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, ErrSegmentShape
	}
	n := len(ciphertext) - TagSize
	if err := c.checkShape(nonce, additionalData, n); err != nil {
		return nil, err
	}
	tag := ciphertext[n:]
	ciphertext = ciphertext[:n]

	ret, out := subtle.SliceForAppend(dst, n)
	if subtle.InexactOverlap(out, ciphertext) {
		return nil, ErrSegmentShape
	}

	var encKey [40]byte
	var authKey [24]byte
	deriveKeysAsm(&authKey, &encKey, &c.kgk, nonce)

	var enc keySchedule
	enc.init(encKey[:c.keyLen])

	var pv polyval.Polyval
	initPolyval(&pv, authKey[:16])
	absorbAAD(&pv, additionalData)

	var block [TagSize]byte
	copy(block[:], tag)
	block[15] |= 0x80
	acc, pow := pv.Raw()
	openFusedAsm(enc.nr, &enc.enc[0], &block, &out[0], &ciphertext[0], n/blockSize, acc, pow)

	var wantTag [TagSize]byte
	finishTag(&pv, &wantTag, &enc, nonce, SegmentAADSize, n)
	wipeMessageKeys(&authKey, &encKey, &enc, &pv)
	if subtle.ConstantTimeCompare(tag, wantTag[:]) != 1 {
		wipe(out)
		return nil, errOpen
	}
	return ret, nil
}

// absorbAAD absorbs the SegmentAADSize-byte additional data as
// four zero-padded blocks with a single Update call.
func absorbAAD(p *polyval.Polyval, additionalData []byte) {
	var buf [4 * blockSize]byte
	copy(buf[:], additionalData[:SegmentAADSize])
	p.Update(buf[:])
}

// Reset starts a new segment with the given nonce and
// additional data, discarding any previous state.
//
// It returns ErrSegmentShape if the nonce is not NonceSize bytes
// or the additional data is not SegmentAADSize bytes.
func (s *SegmentSealer) Reset(nonce, additionalData []byte) error {
	if s.c == nil {
		return ErrSealerState
	}
	if len(nonce) != NonceSize || len(additionalData) != SegmentAADSize {
		s.clear()
		return ErrSegmentShape
	}
	s.reset(nonce, additionalData)
	return nil
}

func (s *SegmentSealer) reset(nonce, additionalData []byte) {
	var encKey [40]byte
	var authKey [24]byte
	deriveKeysAsm(&authKey, &encKey, &s.c.kgk, nonce)
	s.enc.init(encKey[:s.c.keyLen])
	initPolyval(&s.pv, authKey[:16])
	wipe(authKey[:])
	wipe(encKey[:])
	absorbAAD(&s.pv, additionalData)
	acc, _ := s.pv.Raw()
	s.aadAcc = *acc
	copy(s.nonce[:], nonce)
	s.absorbed = 0
	s.streamed = 0
	s.phase = phaseAbsorb
}

// Absorb authenticates the next plaintext tile.
//
// The tile must be a non-zero multiple of SegmentQuantum bytes
// and the total absorbed must not exceed the segment size.
func (s *SegmentSealer) Absorb(tile []byte) error {
	if s.phase != phaseAbsorb {
		return ErrSealerState
	}
	if len(tile) == 0 || len(tile)%SegmentQuantum != 0 ||
		len(tile) > s.c.segmentSize-s.absorbed {
		return ErrSegmentShape
	}
	s.absorb(tile)
	return nil
}

func (s *SegmentSealer) absorb(tile []byte) {
	s.pv.Update(tile)
	s.absorbed += len(tile)
}

// startKeyStream ends the absorb phase: it records the POLYVAL
// state of the absorbed plaintext, computes the tag and rewinds
// POLYVAL to the state after the additional data so that
// KeyStream can hash the plaintext again.
func (s *SegmentSealer) startKeyStream() {
	acc, _ := s.pv.Raw()
	s.ptAcc = *acc
	finishTag(&s.pv, &s.tag, &s.enc, s.nonce[:], SegmentAADSize, s.absorbed)
	*acc = s.aadAcc
	s.ctr = s.tag
	s.ctr[15] |= 0x80
	s.phase = phaseKeyStream
}

// KeyStream encrypts the next tile of the plaintext, src, into
// dst. The first call ends the absorb phase.
//
// The tile must be a non-zero multiple of SegmentQuantum bytes,
// len(dst) must be at least len(src), and dst may alias src
// exactly but must not otherwise overlap it. It returns
// ErrSegmentShape if the absorbed plaintext is not a valid
// segment length or the tiles would exceed it.
//
// The output must not be used until Finish succeeds.
func (s *SegmentSealer) KeyStream(dst, src []byte) error {
	if s.phase == phaseAbsorb {
		if !s.c.checkLength(s.absorbed) {
			return ErrSegmentShape
		}
		s.startKeyStream()
	}
	if s.phase != phaseKeyStream {
		return ErrSealerState
	}
	if len(src) == 0 || len(src)%SegmentQuantum != 0 ||
		len(src) > s.absorbed-s.streamed || len(dst) < len(src) {
		return ErrSegmentShape
	}
	if subtle.InexactOverlap(dst[:len(src)], src) {
		return ErrSegmentShape
	}
	s.keyStream(dst, src)
	return nil
}

func (s *SegmentSealer) keyStream(dst, src []byte) {
	acc, pow := s.pv.Raw()
	sealFusedAsm(s.enc.nr, &s.enc.enc[0], &s.ctr, &dst[0], &src[0], len(src)/blockSize, acc, pow)
	s.streamed += len(src)
	if s.streamed == s.absorbed {
		s.phase = phaseFinish
	}
}

// Finish checks that the plaintext encrypted by KeyStream is the
// plaintext authenticated by Absorb and, if so, returns the
// authentication tag. It must be called after the whole segment
// has been passed to KeyStream.
//
// If the plaintexts differ it returns ErrPlaintextMismatch; the
// caller must then discard everything KeyStream wrote for this
// segment. In both cases the sealer drops its key material and
// must be Reset before it is used again.
func (s *SegmentSealer) Finish() ([TagSize]byte, error) {
	if s.phase != phaseFinish {
		return [TagSize]byte{}, ErrSealerState
	}
	tag, ok := s.finish()
	if !ok {
		return [TagSize]byte{}, ErrPlaintextMismatch
	}
	return tag, nil
}

// finish compares the two POLYVAL states in constant time and
// clears the sealer. The tag must only be used if ok is true.
func (s *SegmentSealer) finish() (tag [TagSize]byte, ok bool) {
	acc, _ := s.pv.Raw()
	ok = subtle.ConstantTimeCompare(acc[:], s.ptAcc[:]) == 1
	tag = s.tag
	s.clear()
	return tag, ok
}

// clear drops all per-segment key material. It is not inlined
// so that the stores cannot be removed as dead when s is a local
// variable.
//
//go:noinline
func (s *SegmentSealer) clear() {
	c := s.c
	*s = SegmentSealer{c: c}
}
