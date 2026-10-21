//go:build amd64 && gc && !purego

package siv

import (
	"bytes"
	"testing"

	"github.com/crux153/siv-go/internal/polyval"
)

// TestOpenFused compares openFusedAsm with separate AES-CTR and
// POLYVAL passes, including a counter that wraps and in-place
// operation.
func TestOpenFused(t *testing.T) {
	if !haveAsm {
		t.Skip("CPU lacks AES-NI or PCLMULQDQ")
	}
	for _, keySize := range []int{16, 32} {
		var ks keySchedule
		ks.init(randbuf(keySize))
		for groups := 1; groups <= 40; groups++ {
			for _, wrap := range []bool{false, true} {
				n := groups * 8 * blockSize
				src := randbuf(n)
				hkey := randbuf(16)
				hkey[0] |= 1 // non-zero
				prefix := randbuf(4 * blockSize)

				var ctr0 [TagSize]byte
				copy(ctr0[:], randbuf(TagSize))
				ctr0[15] |= 0x80
				if wrap {
					ctr0[0], ctr0[1], ctr0[2], ctr0[3] = 0xfd, 0xff, 0xff, 0xff
				}

				// Reference: separate passes.
				want := make([]byte, n)
				wantCtr := ctr0
				aesctr(ks.nr, &ks.enc[0], &wantCtr, want, src)
				var wantPV polyval.Polyval
				if err := wantPV.Init(hkey); err != nil {
					t.Fatal(err)
				}
				wantPV.Update(prefix)
				wantPV.Update(want)

				for _, inPlace := range []bool{false, true} {
					var got []byte
					if inPlace {
						got = append([]byte(nil), src...)
					} else {
						got = make([]byte, n)
					}
					in := src
					if inPlace {
						in = got
					}
					var gotPV polyval.Polyval
					if err := gotPV.Init(hkey); err != nil {
						t.Fatal(err)
					}
					gotPV.Update(prefix)
					gotCtr := ctr0
					acc, pow := gotPV.Raw()
					openFusedAsm(ks.nr, &ks.enc[0], &gotCtr, &got[0], &in[0], n/blockSize, acc, pow)

					if !bytes.Equal(want, got) {
						t.Fatalf("keySize=%d groups=%d wrap=%v inPlace=%v: plaintext mismatch",
							keySize, groups, wrap, inPlace)
					}
					if gotCtr != wantCtr {
						t.Fatalf("keySize=%d groups=%d: counter %x, want %x", keySize, groups, gotCtr, wantCtr)
					}
					if w, g := wantPV.Sum(nil), gotPV.Sum(nil); !bytes.Equal(w, g) {
						t.Fatalf("keySize=%d groups=%d wrap=%v inPlace=%v: POLYVAL %x, want %x",
							keySize, groups, wrap, inPlace, g, w)
					}
				}
			}
		}
	}
}
