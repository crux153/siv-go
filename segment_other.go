//go:build !amd64 || !gc || purego

package siv

// SegmentCipher is AES-GCM-SIV restricted to a fixed input
// shape. It needs the amd64 assembly implementation and is not
// available in this build.
type SegmentCipher struct {
	segmentSize int
}

// SegmentSize returns the maximum plaintext length.
func (c *SegmentCipher) SegmentSize() int {
	return c.segmentSize
}

// SegmentSealer encrypts one segment in two phases. It is not
// available in this build.
type SegmentSealer struct{}

// NewSealer returns a SegmentSealer for c.
func (c *SegmentCipher) NewSealer() *SegmentSealer {
	return &SegmentSealer{}
}

// NewSegmentCipher always returns ErrUnsupportedCPU without the
// amd64 assembly implementation.
func NewSegmentCipher(key []byte, segmentSize int) (*SegmentCipher, error) {
	if _, err := NewGCM(key); err != nil {
		return nil, err
	}
	if err := checkSegmentSize(segmentSize); err != nil {
		return nil, err
	}
	return nil, ErrUnsupportedCPU
}

// Seal is unavailable without the amd64 assembly implementation.
func (c *SegmentCipher) Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, error) {
	return nil, ErrUnsupportedCPU
}

// Open is unavailable without the amd64 assembly implementation.
func (c *SegmentCipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return nil, ErrUnsupportedCPU
}

// Reset is unavailable without the amd64 assembly implementation.
func (s *SegmentSealer) Reset(nonce, additionalData []byte) error {
	return ErrUnsupportedCPU
}

// Absorb is unavailable without the amd64 assembly
// implementation.
func (s *SegmentSealer) Absorb(tile []byte) error {
	return ErrUnsupportedCPU
}

// Finish is unavailable without the amd64 assembly
// implementation.
func (s *SegmentSealer) Finish() ([TagSize]byte, error) {
	return [TagSize]byte{}, ErrUnsupportedCPU
}

// KeyStream is unavailable without the amd64 assembly
// implementation.
func (s *SegmentSealer) KeyStream(dst, src []byte) error {
	return ErrUnsupportedCPU
}
