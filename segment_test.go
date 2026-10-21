package siv

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	rand "github.com/ericlagergren/saferand"
	upstream "github.com/ericlagergren/siv"
)

func newSegmentCipher(t testing.TB, key []byte, segmentSize int) *SegmentCipher {
	t.Helper()
	c, err := NewSegmentCipher(key, segmentSize)
	if errors.Is(err, ErrUnsupportedCPU) {
		t.Skip("segment API needs the amd64 assembly implementation")
	}
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// segmentLengths returns every valid plaintext length up to
// 64 KiB, some random larger ones and the maximum.
func segmentLengths(segmentSize int) []int {
	var lengths []int
	for n := SegmentQuantum; n <= segmentSize && n <= 1<<16; n += SegmentQuantum {
		lengths = append(lengths, n)
	}
	if segmentSize > 1<<16 {
		for i := 0; i < 16; i++ {
			lengths = append(lengths, (1+rand.Intn(segmentSize/SegmentQuantum))*SegmentQuantum)
		}
		lengths = append(lengths, segmentSize)
	}
	return lengths
}

// TestSegmentMatchesGCM checks that SegmentCipher produces the
// same output as NewGCM and as upstream ericlagergren/siv for
// every valid plaintext length up to 64 KiB plus larger ones.
func TestSegmentMatchesGCM(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		for _, segmentSize := range []int{MinSegmentSize, MaxSegmentSize} {
			t.Run(fmt.Sprintf("%d/%d", keySize*8, segmentSize), func(t *testing.T) {
				key := randbuf(keySize)
				c := newSegmentCipher(t, key, segmentSize)
				if c.SegmentSize() != segmentSize {
					t.Fatalf("SegmentSize() = %d", c.SegmentSize())
				}
				ref, err := NewGCM(key)
				if err != nil {
					t.Fatal(err)
				}
				up, err := upstream.NewGCM(key)
				if err != nil {
					t.Fatal(err)
				}
				for _, n := range segmentLengths(segmentSize) {
					testSegmentLength(t, c, ref, up, n)
				}
			})
		}
	}
}

type aeadSealer interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
}

func testSegmentLength(t *testing.T, c *SegmentCipher, ref, up aeadSealer, n int) {
	t.Helper()

	nonce := randbuf(NonceSize)
	aad := randbuf(SegmentAADSize)
	plaintext := randbuf(n)

	want := ref.Seal(nil, nonce, plaintext, aad)
	if n <= 1<<16 || n%(1<<16) == 0 {
		if up := up.Seal(nil, nonce, plaintext, aad); !bytes.Equal(up, want) {
			t.Fatalf("n=%d: NewGCM differs from upstream", n)
		}
	}

	got, err := c.Seal(nil, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("n=%d: Seal: %v", n, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("n=%d: Seal mismatch", n)
	}

	// In-place Seal.
	buf := append(make([]byte, 0, n+TagSize), plaintext...)
	if got, err = c.Seal(buf[:0], nonce, buf, aad); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("n=%d: in-place Seal mismatch (%v)", n, err)
	}

	pt, err := c.Open(nil, nonce, want, aad)
	if err != nil {
		t.Fatalf("n=%d: Open: %v", n, err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("n=%d: Open mismatch", n)
	}

	// In-place Open.
	ct := append([]byte(nil), want...)
	if pt, err = c.Open(ct[:0], nonce, ct, aad); err != nil || !bytes.Equal(pt, plaintext) {
		t.Fatalf("n=%d: in-place Open mismatch (%v)", n, err)
	}
}

// TestSegmentSealerTiles checks that random tilings of Absorb
// and KeyStream produce the same output as Seal.
func TestSegmentSealerTiles(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		c := newSegmentCipher(t, randbuf(keySize), MaxSegmentSize)
		s := c.NewSealer()
		for i := 0; i < 64; i++ {
			n := (1 + rand.Intn(MaxSegmentSize/SegmentQuantum)) * SegmentQuantum
			if i%4 == 0 {
				n = MaxSegmentSize
			}
			nonce := randbuf(NonceSize)
			aad := randbuf(SegmentAADSize)
			plaintext := randbuf(n)
			want, err := c.Seal(nil, nonce, plaintext, aad)
			if err != nil {
				t.Fatal(err)
			}

			if err := s.Reset(nonce, aad); err != nil {
				t.Fatal(err)
			}
			for _, tile := range randomTiles(plaintext) {
				if err := s.Absorb(tile); err != nil {
					t.Fatal(err)
				}
			}
			tag, err := s.Tag()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(tag[:], want[n:]) {
				t.Fatalf("n=%d: tag mismatch", n)
			}

			// Encrypt in place with a different tiling.
			got := append([]byte(nil), plaintext...)
			for _, tile := range randomTiles(got) {
				if err := s.KeyStream(tile, tile); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(got, want[:n]) {
				t.Fatalf("n=%d: ciphertext mismatch", n)
			}
			if err := s.Absorb(plaintext[:SegmentQuantum]); !errors.Is(err, ErrSealerState) {
				t.Fatalf("sealer still usable after the last tile: %v", err)
			}
		}
	}
}

// randomTiles splits p into tiles of random multiples of
// SegmentQuantum, mostly between 64 KiB and 128 KiB.
func randomTiles(p []byte) [][]byte {
	var tiles [][]byte
	for len(p) > 0 {
		var n int
		switch rand.Intn(3) {
		case 0:
			n = SegmentQuantum * (1 + rand.Intn(8))
		default:
			n = (1<<16 + rand.Intn(1<<16+1)) &^ (SegmentQuantum - 1)
		}
		if n > len(p) {
			n = len(p)
		}
		tiles = append(tiles, p[:n])
		p = p[n:]
	}
	return tiles
}

// TestSegmentShape checks that inputs of the wrong shape are
// rejected.
func TestSegmentShape(t *testing.T) {
	key := randbuf(16)
	for _, size := range []int{0, 1 << 15, 1<<16 - 1, 3 << 16, 1<<20 + 1, 1 << 21} {
		if _, err := NewSegmentCipher(key, size); err == nil {
			t.Fatalf("segment size %d accepted", size)
		}
	}
	if _, err := NewSegmentCipher(randbuf(24), MinSegmentSize); err == nil {
		t.Fatal("24-byte key accepted")
	}

	const segmentSize = 1 << 17
	c := newSegmentCipher(t, key, segmentSize)
	nonce := randbuf(NonceSize)
	aad := randbuf(SegmentAADSize)
	pt := randbuf(segmentSize + 2*SegmentQuantum)
	good, err := c.Seal(nil, nonce, pt[:SegmentQuantum], aad)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		nonce, aad []byte
		n          int
	}
	for _, a := range []args{
		{nonce[:NonceSize-1], aad, SegmentQuantum},
		{append(nonce, 0), aad, SegmentQuantum},
		{nonce, aad[:SegmentAADSize-1], SegmentQuantum},
		{nonce, append(aad, 0), SegmentQuantum},
		{nonce, nil, SegmentQuantum},
		{nonce, aad, 0},
		{nonce, aad, 16},
		{nonce, aad, SegmentQuantum - 1},
		{nonce, aad, SegmentQuantum + 1},
		{nonce, aad, SegmentQuantum + 16},
		{nonce, aad, segmentSize + SegmentQuantum},
	} {
		if _, err := c.Seal(nil, a.nonce, pt[:a.n], a.aad); !errors.Is(err, ErrSegmentShape) {
			t.Fatalf("Seal(len(nonce)=%d, len(aad)=%d, n=%d): %v",
				len(a.nonce), len(a.aad), a.n, err)
		}
		ct := make([]byte, a.n+TagSize)
		if _, err := c.Open(nil, a.nonce, ct, a.aad); !errors.Is(err, ErrSegmentShape) {
			t.Fatalf("Open(len(nonce)=%d, len(aad)=%d, n=%d): %v",
				len(a.nonce), len(a.aad), a.n, err)
		}
	}
	if _, err := c.Open(nil, nonce, good[:TagSize-1], aad); !errors.Is(err, ErrSegmentShape) {
		t.Fatalf("short ciphertext: %v", err)
	}

	// Inexact overlap.
	buf := make([]byte, 2*SegmentQuantum+TagSize)
	if _, err := c.Seal(buf[1:1], nonce, buf[:SegmentQuantum], aad); !errors.Is(err, ErrSegmentShape) {
		t.Fatalf("overlapping Seal: %v", err)
	}
	copy(buf, good)
	if _, err := c.Open(buf[1:1], nonce, buf[:len(good)], aad); !errors.Is(err, ErrSegmentShape) {
		t.Fatalf("overlapping Open: %v", err)
	}
}

// TestSegmentSealerState checks that SegmentSealer enforces the
// order of its phases and the tile shape.
func TestSegmentSealerState(t *testing.T) {
	c := newSegmentCipher(t, randbuf(32), MinSegmentSize)
	nonce := randbuf(NonceSize)
	aad := randbuf(SegmentAADSize)
	pt := randbuf(MinSegmentSize + SegmentQuantum)
	buf := make([]byte, len(pt))

	var zero SegmentSealer
	if err := zero.Reset(nonce, aad); !errors.Is(err, ErrSealerState) {
		t.Fatalf("zero sealer: %v", err)
	}

	s := c.NewSealer()
	if err := s.Absorb(pt[:SegmentQuantum]); !errors.Is(err, ErrSealerState) {
		t.Fatalf("Absorb before Reset: %v", err)
	}
	if _, err := s.Tag(); !errors.Is(err, ErrSealerState) {
		t.Fatalf("Tag before Reset: %v", err)
	}
	if err := s.KeyStream(buf[:SegmentQuantum], pt[:SegmentQuantum]); !errors.Is(err, ErrSealerState) {
		t.Fatalf("KeyStream before Reset: %v", err)
	}
	if err := s.Reset(nonce[:8], aad); !errors.Is(err, ErrSegmentShape) {
		t.Fatalf("Reset with short nonce: %v", err)
	}
	if err := s.Reset(nonce, aad[:8]); !errors.Is(err, ErrSegmentShape) {
		t.Fatalf("Reset with short AAD: %v", err)
	}
	if err := s.Absorb(pt[:SegmentQuantum]); !errors.Is(err, ErrSealerState) {
		t.Fatalf("Absorb after failed Reset: %v", err)
	}

	if err := s.Reset(nonce, aad); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tag(); !errors.Is(err, ErrSegmentShape) {
		t.Fatalf("Tag with nothing absorbed: %v", err)
	}
	if err := s.KeyStream(buf[:SegmentQuantum], pt[:SegmentQuantum]); !errors.Is(err, ErrSealerState) {
		t.Fatalf("KeyStream before Tag: %v", err)
	}
	for _, n := range []int{0, 16, SegmentQuantum - 1, SegmentQuantum + 16} {
		if err := s.Absorb(pt[:n]); !errors.Is(err, ErrSegmentShape) {
			t.Fatalf("Absorb(%d bytes): %v", n, err)
		}
	}
	if err := s.Absorb(pt[:MinSegmentSize-SegmentQuantum]); err != nil {
		t.Fatal(err)
	}
	if err := s.Absorb(pt[:2*SegmentQuantum]); !errors.Is(err, ErrSegmentShape) {
		t.Fatalf("Absorb past the segment size: %v", err)
	}
	if err := s.Absorb(pt[MinSegmentSize-SegmentQuantum : MinSegmentSize]); err != nil {
		t.Fatal(err)
	}
	tag, err := s.Tag()
	if err != nil {
		t.Fatal(err)
	}
	if tag2, err := s.Tag(); err != nil || tag2 != tag {
		t.Fatalf("second Tag: %x, %v", tag2, err)
	}
	if err := s.Absorb(pt[:SegmentQuantum]); !errors.Is(err, ErrSealerState) {
		t.Fatalf("Absorb after Tag: %v", err)
	}
	if err := s.KeyStream(buf[:SegmentQuantum-1], pt[:SegmentQuantum]); !errors.Is(err, ErrSegmentShape) {
		t.Fatalf("short dst: %v", err)
	}
	if err := s.KeyStream(pt[1:SegmentQuantum+1], pt[:SegmentQuantum]); !errors.Is(err, ErrSegmentShape) {
		t.Fatalf("overlapping KeyStream: %v", err)
	}
	if err := s.KeyStream(buf, pt); !errors.Is(err, ErrSegmentShape) {
		t.Fatalf("KeyStream past the absorbed length: %v", err)
	}
	if err := s.KeyStream(buf[:MinSegmentSize], pt[:MinSegmentSize]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Tag(); !errors.Is(err, ErrSealerState) {
		t.Fatalf("Tag after the last tile: %v", err)
	}

	want, err := c.Seal(nil, nonce, pt[:MinSegmentSize], aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:MinSegmentSize], want[:MinSegmentSize]) || !bytes.Equal(tag[:], want[MinSegmentSize:]) {
		t.Fatal("sealer output differs from Seal")
	}
}

// TestSegmentOpenForgery checks that Open rejects modified
// inputs and zeroes the plaintext it wrote.
func TestSegmentOpenForgery(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		c := newSegmentCipher(t, randbuf(keySize), MinSegmentSize)
		for i := 0; i < 200; i++ {
			n := (1 + rand.Intn(MinSegmentSize/SegmentQuantum)) * SegmentQuantum
			nonce := randbuf(NonceSize)
			aad := randbuf(SegmentAADSize)
			ct, err := c.Seal(nil, nonce, randbuf(n), aad)
			if err != nil {
				t.Fatal(err)
			}

			badNonce := append([]byte(nil), nonce...)
			badAAD := append([]byte(nil), aad...)
			badCt := append([]byte(nil), ct...)
			switch i % 3 {
			case 0:
				bit := rand.Intn(len(badCt) * 8)
				badCt[bit/8] ^= 1 << (bit % 8)
			case 1:
				badAAD[rand.Intn(len(badAAD))] ^= 1
			case 2:
				badNonce[rand.Intn(len(badNonce))] ^= 1
			}

			dst := make([]byte, 7, 7+n)
			for j := range dst {
				dst[j] = 0xaa
			}
			out, err := c.Open(dst, badNonce, badCt, badAAD)
			if !errors.Is(err, errOpen) || out != nil {
				t.Fatalf("forgery accepted: %v", err)
			}
			dst = dst[:7+n]
			for j, b := range dst {
				if j < 7 && b != 0xaa || j >= 7 && b != 0 {
					t.Fatalf("dst[%d] = %#x after failed Open", j, b)
				}
			}

			// In place: the ciphertext buffer is zeroed.
			if _, err := c.Open(badCt[:0], badNonce, badCt, badAAD); !errors.Is(err, errOpen) {
				t.Fatalf("in-place forgery accepted: %v", err)
			}
			for j, b := range badCt[:n] {
				if b != 0 {
					t.Fatalf("badCt[%d] = %#x after failed in-place Open", j, b)
				}
			}
		}
	}
}

func BenchmarkSegment(b *testing.B) {
	for _, keySize := range []int{16, 32} {
		for _, n := range []int{1 << 16, 1 << 20} {
			name := fmt.Sprintf("%d/%dK", keySize*8, n>>10)
			b.Run("Seal/"+name, func(b *testing.B) {
				benchmarkSegmentSeal(b, keySize, n)
			})
			b.Run("Open/"+name, func(b *testing.B) {
				benchmarkSegmentOpen(b, keySize, n)
			})
			b.Run("Sealer64K/"+name, func(b *testing.B) {
				benchmarkSegmentSealer(b, keySize, n, 1<<16)
			})
		}
	}
}

func benchmarkSegmentSeal(b *testing.B, keySize, n int) {
	c := newSegmentCipher(b, make([]byte, keySize), n)
	nonce := make([]byte, NonceSize)
	aad := make([]byte, SegmentAADSize)
	pt := make([]byte, n)
	out := make([]byte, 0, n+TagSize)
	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Seal(out, nonce, pt, aad); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkSegmentOpen(b *testing.B, keySize, n int) {
	c := newSegmentCipher(b, make([]byte, keySize), n)
	nonce := make([]byte, NonceSize)
	aad := make([]byte, SegmentAADSize)
	ct, err := c.Seal(nil, nonce, make([]byte, n), aad)
	if err != nil {
		b.Fatal(err)
	}
	out := make([]byte, 0, n)
	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Open(out, nonce, ct, aad); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkSegmentSealer(b *testing.B, keySize, n, tile int) {
	c := newSegmentCipher(b, make([]byte, keySize), n)
	s := c.NewSealer()
	nonce := make([]byte, NonceSize)
	aad := make([]byte, SegmentAADSize)
	pt := make([]byte, n)
	out := make([]byte, n)
	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.Reset(nonce, aad); err != nil {
			b.Fatal(err)
		}
		for off := 0; off < n; off += tile {
			if err := s.Absorb(pt[off : off+tile]); err != nil {
				b.Fatal(err)
			}
		}
		if _, err := s.Tag(); err != nil {
			b.Fatal(err)
		}
		for off := 0; off < n; off += tile {
			if err := s.KeyStream(out[off:off+tile], pt[off:off+tile]); err != nil {
				b.Fatal(err)
			}
		}
	}
}
