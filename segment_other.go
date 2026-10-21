//go:build !amd64 || !gc || purego

package siv

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

// Tag is unavailable without the amd64 assembly implementation.
func (s *SegmentSealer) Tag() ([TagSize]byte, error) {
	return [TagSize]byte{}, ErrUnsupportedCPU
}

// KeyStream is unavailable without the amd64 assembly
// implementation.
func (s *SegmentSealer) KeyStream(dst, src []byte) error {
	return ErrUnsupportedCPU
}
