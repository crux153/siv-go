//go:build amd64 && gc && !purego

package siv

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"testing"
)

// TestCTRWrap compares the assembly AES-CTR against the generic
// implementation with the 32-bit counter close to 2^32 - 1, so
// that the counter wraps inside the 8-way, 4-way and single
// block paths as well as on the trailing partial block.
func TestCTRWrap(t *testing.T) {
	if !haveAsm {
		t.Skip("CPU lacks AES-NI or PCLMULQDQ")
	}
	for _, keySize := range []int{16, 32} {
		key := randbuf(keySize)
		b, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		nr := 6 + keySize/4
		var enc [maxEncSize]uint32
		expandKeyAsm(nr, &key[0], &enc[0])

		for start := uint32(0); start <= 16; start++ {
			for n := 0; n <= 24*blockSize; n++ {
				var tag [TagSize]byte
				copy(tag[:], randbuf(TagSize))
				binary.LittleEndian.PutUint32(tag[0:4], 0xffffffff-start)

				src := randbuf(n)
				want := make([]byte, n)
				aesctrGeneric(b, tag[:], want, src)

				block := tag
				block[15] |= 0x80
				got := make([]byte, n)
				aesctr(nr, &enc[0], &block, got, src)
				if !bytes.Equal(want, got) {
					t.Fatalf("keySize=%d start=%#x n=%d: mismatch", keySize, 0xffffffff-start, n)
				}

				// The final counter must have wrapped modulo 2^32
				// and the other 96 bits must be unchanged.
				wantCtr := 0xffffffff - start + uint32(n/blockSize)
				if gotCtr := binary.LittleEndian.Uint32(block[0:4]); gotCtr != wantCtr {
					t.Fatalf("keySize=%d start=%#x n=%d: counter %#x, want %#x",
						keySize, 0xffffffff-start, n, gotCtr, wantCtr)
				}
				tag[15] |= 0x80
				if !bytes.Equal(block[4:], tag[4:]) {
					t.Fatalf("keySize=%d n=%d: upper 96 bits changed", keySize, n)
				}

				// In place.
				aesctr(nr, &enc[0], &tag, src, src)
				if !bytes.Equal(want, src) {
					t.Fatalf("keySize=%d start=%#x n=%d: in-place mismatch", keySize, 0xffffffff-start, n)
				}
			}
		}
	}
}
