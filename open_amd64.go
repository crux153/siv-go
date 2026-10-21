//go:build amd64 && gc && !purego

package siv

// openFusedAsm decrypts nblocks blocks from src into dst with
// AES-CTR starting at *ctr and absorbs the resulting plaintext
// into the POLYVAL accumulator *acc using the powers
// pow = h^8 || h^7 || ... || h^1.
//
// nblocks must be a positive multiple of 8 and nr must be 10 or
// 14. dst and src must either be equal or not overlap.
//
//go:noescape
func openFusedAsm(nr int, xk *uint32, ctr *[TagSize]byte, dst, src *byte, nblocks int, acc *[16]byte, pow *[128]byte)

// sealFusedAsm encrypts nblocks blocks from src into dst with
// AES-CTR starting at *ctr and absorbs the plaintext into the
// POLYVAL accumulator *acc using the powers
// pow = h^8 || h^7 || ... || h^1. Each plaintext block is read
// once and used for both.
//
// nblocks must be a positive multiple of 8 and nr must be 10 or
// 14. dst and src must either be equal or not overlap.
//
//go:noescape
func sealFusedAsm(nr int, xk *uint32, ctr *[TagSize]byte, dst, src *byte, nblocks int, acc *[16]byte, pow *[128]byte)
