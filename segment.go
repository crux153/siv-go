package siv

import (
	"errors"

	"github.com/crux153/siv-go/internal/polyval"
)

const (
	// SegmentAADSize is the only additional data length
	// accepted by SegmentCipher.
	SegmentAADSize = 57
	// SegmentQuantum is the granularity of SegmentCipher
	// plaintexts and of SegmentSealer tiles.
	SegmentQuantum = 256
	// MinSegmentSize and MaxSegmentSize bound the segment size
	// passed to NewSegmentCipher.
	MinSegmentSize = 1 << 16
	MaxSegmentSize = 1 << 20
)

var (
	// ErrSegmentShape is returned when an input to
	// SegmentCipher or SegmentSealer does not have the
	// required shape.
	ErrSegmentShape = errors.New("siv: input does not have the shape required by SegmentCipher")
	// ErrSealerState is returned when SegmentSealer methods
	// are called out of order.
	ErrSealerState = errors.New("siv: SegmentSealer used out of order")
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

func checkSegmentSize(segmentSize int) error {
	if segmentSize < MinSegmentSize || segmentSize > MaxSegmentSize ||
		segmentSize&(segmentSize-1) != 0 {
		return errors.New("siv: segment size must be a power of two between MinSegmentSize and MaxSegmentSize")
	}
	return nil
}

// sealerPhase is the state of a SegmentSealer.
type sealerPhase int

const (
	phaseIdle sealerPhase = iota
	phaseAbsorb
	phaseKeyStream
)

// SegmentSealer encrypts one segment in two phases so that the
// caller can process the plaintext in tiles:
//
//  1. Reset with the nonce and additional data, then Absorb
//     every plaintext tile in order.
//  2. Tag returns the authentication tag. Then KeyStream
//     encrypts the same tiles, in the same order.
//
// Tiles must be non-zero multiples of SegmentQuantum bytes and
// the total must be a valid segment length. The tiles passed
// to KeyStream must be byte-for-byte the plaintext passed to
// Absorb: encrypting different data under the same tag reuses
// the key stream and breaks confidentiality.
//
// The result, ciphertext || tag, is identical to
// SegmentCipher.Seal. A SegmentSealer is not safe for
// concurrent use; it can be reused for further segments by
// calling Reset.
type SegmentSealer struct {
	c        *SegmentCipher
	phase    sealerPhase
	enc      keySchedule
	pv       polyval.Polyval
	nonce    [NonceSize]byte
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
