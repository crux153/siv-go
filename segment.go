package siv

import (
	"errors"
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

func checkSegmentSize(segmentSize int) error {
	if segmentSize < MinSegmentSize || segmentSize > MaxSegmentSize ||
		segmentSize&(segmentSize-1) != 0 {
		return errors.New("siv: segment size must be a power of two between MinSegmentSize and MaxSegmentSize")
	}
	return nil
}
