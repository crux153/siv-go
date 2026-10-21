package difffuzz

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	siv "github.com/crux153/siv-go"
)

// FuzzAEAD: the fork's general AEAD against the reference on
// arbitrary lengths. ext stretches the plaintext up to 3 MiB so the
// 8/4/1-block loops and multi-megabyte inputs are reached.
func FuzzAEAD(f *testing.F) {
	f.Add(uint8(0), []byte("k"), []byte("n"), []byte(""), []byte(""), uint32(0))
	f.Add(uint8(2), []byte("key"), []byte("nonce"), []byte("aad"), []byte("pt"), uint32(1<<20))
	f.Add(uint8(3), []byte("key16"), []byte("nonce"), make([]byte, 57), make([]byte, 131), uint32(4096+7))
	f.Fuzz(func(t *testing.T, flags uint8, key, nonce, aad, pt []byte, ext uint32) {
		keyLen := 32
		if flags&1 != 0 {
			keyLen = 16
		}
		key = fit(key, keyLen)
		nonce = fit(nonce, siv.NonceSize)
		if len(aad) > 4096 {
			aad = aad[:4096]
		}
		if flags&2 != 0 {
			sc := getScratch()
			defer putScratch(sc)
			pt = fitTo(grow(&sc.pt, int(ext%(3<<20))), pt)
		}
		if err := checkAEAD(key, nonce, pt, aad, int(ext>>3), uint(flags>>5)); err != nil {
			t.Fatal(err)
		}
	})
}

// FuzzSegment: SegmentCipher and SegmentSealer (with independent
// Absorb/KeyStream tilings) against the reference, mismatch detection and
// shape rejection.
func FuzzSegment(f *testing.F) {
	f.Add(uint8(0), []byte("k"), []byte("n"), []byte("a"), []byte("p"), uint32(0), []byte{}, uint32(0))
	f.Add(uint8(4|16), []byte("key"), []byte("nonce"), []byte("aad"), []byte("pt"), uint32(4095), []byte{0x41, 0x82, 0x03, 0xc4}, uint32(77))
	f.Fuzz(func(t *testing.T, flags uint8, key, nonce, aad, pt []byte, nq uint32, tiles []byte, mis uint32) {
		segSize := siv.MinSegmentSize << (int(flags) % 5) // 64 KiB .. 1 MiB
		keyLen := 32
		if flags&8 != 0 {
			keyLen = 16
		}
		n := (int(nq)%(segSize/siv.SegmentQuantum) + 1) * siv.SegmentQuantum
		key = fit(key, keyLen)
		nonce = fit(nonce, siv.NonceSize)
		aad = fit(aad, aadSegment)
		sc := getScratch()
		defer putScratch(sc)
		pt = fitTo(grow(&sc.pt, n), pt)
		half := len(tiles) / 2
		tilesA, tilesK := tiling(n, tiles[:half]), tiling(n, tiles[half:])
		misPos := -1
		if flags&16 != 0 {
			misPos = int(mis)
		}
		if err := checkSegment(key, nonce, pt, aad, segSize, tilesA, tilesK, misPos, int(mis>>2)); err != nil {
			t.Fatal(err)
		}
		if flags&32 != 0 {
			c, _ := siv.NewSegmentCipher(key, segSize)
			for _, m := range []int{n + 1, n - 1, n + 16, segSize + siv.SegmentQuantum} {
				if m <= 0 {
					continue
				}
				if _, err := c.Seal(nil, nonce, fit(pt, m), aad); !errors.Is(err, siv.ErrSegmentShape) {
					t.Fatalf("length %d not rejected: %v", m, err)
				}
			}
			if _, err := c.Seal(nil, nonce, pt, aad[:len(aad)-1]); !errors.Is(err, siv.ErrSegmentShape) {
				t.Fatalf("56-byte AAD not rejected: %v", err)
			}
		}
	})
}

// FuzzSealerOps drives a SegmentSealer with arbitrary call sequences.
// Safety properties only (the exact error for each misuse is not
// modelled):
//   - no panic;
//   - Finish never yields a tag unless every plaintext byte passed to
//     KeyStream equals the absorbed byte and both cover a valid length,
//     and then ciphertext||tag equals the reference's Seal;
//   - Finish never reports a mismatch for identical plaintext;
//   - Absorb never succeeds after KeyStream started; nothing succeeds
//     before Reset or after Finish.
func FuzzSealerOps(f *testing.F) {
	f.Add([]byte("key"), []byte("nonce"), []byte("pt"), []byte{0, 0, 1, 3, 2, 3, 3, 0})
	f.Add([]byte("key"), []byte("nonce"), []byte("pt"), []byte{0, 0, 1, 7, 1, 2, 2, 0x81, 2, 9, 3, 0})
	f.Fuzz(func(t *testing.T, key, nonce, ptSeed, ops []byte) {
		const segSize = siv.MinSegmentSize
		const q = siv.SegmentQuantum
		key = fit(key, 32)
		nonce = fit(nonce, siv.NonceSize)
		sc := getScratch()
		defer putScratch(sc)
		pt := fitTo(grow(&sc.pt, segSize), ptSeed)
		aad := fit(append([]byte("aad"), nonce...), aadSegment)
		c, err := siv.NewSegmentCipher(key, segSize)
		if err != nil {
			t.Fatal(err)
		}
		s := c.NewSealer()

		var (
			active    bool // between a successful Reset and Finish
			streaming bool // a KeyStream succeeded in this session
			absorbed  []byte
			sPlain    []byte
			sCipher   []byte
		)
		for i := 0; i+1 < len(ops) && i < 400; i += 2 {
			op, arg := ops[i]%6, ops[i+1]
			k := (int(arg&0x0f) + 1) * q
			switch op {
			case 0: // Reset
				if err := s.Reset(nonce, aad); err != nil {
					t.Fatalf("valid Reset failed: %v", err)
				}
				active, streaming = true, false
				absorbed, sPlain, sCipher = absorbed[:0], sPlain[:0], sCipher[:0]
			case 1: // Absorb the next k plaintext bytes
				lo := len(absorbed)
				hi := min(lo+k, len(pt))
				if hi == lo {
					hi = lo + q // overflow on purpose
				}
				tile := fitTo(grow(&sc.buf, hi-lo), pt[lo:min(hi, len(pt))])
				err := s.Absorb(tile)
				if err == nil {
					if !active {
						t.Fatal("Absorb succeeded without an active session")
					}
					if streaming {
						t.Fatal("Absorb succeeded after KeyStream started")
					}
					absorbed = append(absorbed, tile...)
				}
			case 2: // KeyStream the next k bytes, optionally altered
				lo := len(sPlain)
				src := grow(&sc.buf, k)
				clear(src[copy(src, absorbed[min(lo, len(absorbed)):]):])
				if arg&0x80 != 0 {
					src[int(arg>>4)&7%len(src)] ^= 0x40
				}
				dst := grow(&sc.got, k)
				if err := s.KeyStream(dst, src); err == nil {
					if !active {
						t.Fatal("KeyStream succeeded without an active session")
					}
					streaming = true
					sPlain = append(sPlain, src...)
					sCipher = append(sCipher, dst...)
				}
			case 3: // Finish
				tag, err := s.Finish()
				same := bytes.Equal(sPlain, absorbed)
				switch {
				case err == nil:
					if !active {
						t.Fatal("Finish succeeded without an active session")
					}
					if !same {
						t.Fatal("Finish released a tag for plaintext that differs from the absorbed plaintext")
					}
					want := refSealTo(&sc.want, key, nonce, absorbed, aad)
					if !bytes.Equal(sCipher, want[:len(absorbed)]) || !bytes.Equal(tag[:], want[len(absorbed):]) {
						t.Fatal(triage(fmt.Errorf("sealer output differs from the reference (len %d)", len(absorbed)), key, nonce, absorbed, aad))
					}
					active = false
				case errors.Is(err, siv.ErrPlaintextMismatch):
					if same {
						t.Fatal("Finish reported a mismatch for identical plaintext")
					}
					active = false
				}
			case 4: // Absorb with an invalid size
				if err := s.Absorb(grow(&sc.buf, k+1+int(arg>>4))); err == nil {
					t.Fatal("Absorb accepted a size that is not a multiple of SegmentQuantum")
				}
			case 5: // KeyStream into a short dst
				if err := s.KeyStream(grow(&sc.got, k-1), grow(&sc.buf, k)); err == nil {
					t.Fatal("KeyStream accepted a short dst")
				}
			}
		}
	})
}
