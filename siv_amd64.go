//go:build amd64 && gc && !purego

package siv

import (
	"encoding/binary"

	"github.com/crux153/siv-go/internal/polyval"
	"github.com/ericlagergren/subtle"
	"golang.org/x/sys/cpu"
)

// haveAsm reports whether the CPU supports the AES-NI and
// PCLMULQDQ instructions used by the assembly implementation.
var haveAsm = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ

const (
	// maxEncSize is the maximum number of uint32s used in the
	// AES round key expansion.
	maxEncSize = 32 + 28
)

// keySchedule is an expanded AES key.
type keySchedule struct {
	nr  int
	enc [maxEncSize]uint32
}

// init expands key, which must be 16 or 32 bytes.
//
// It does nothing if the CPU lacks AES-NI, in which case only
// the generic code (which tests can enable) is used.
func (k *keySchedule) init(key []byte) {
	if !haveAsm {
		return
	}
	k.nr = 6 + len(key)/4
	expandKeyAsm(k.nr, &key[0], &k.enc[0])
}

// wipe zeroes the round keys. It is not inlined so that the
// stores cannot be removed as dead.
//
//go:noinline
func (k *keySchedule) wipe() {
	*k = keySchedule{}
}

// wipeMessageKeys zeroes the per-message key material derived
// by Seal and Open.
func wipeMessageKeys(authKey *[24]byte, encKey *[40]byte, enc *keySchedule, p *polyval.Polyval) {
	wipe(authKey[:])
	wipe(encKey[:])
	enc.wipe()
	p.Wipe()
}

func (a *aead) seal(out, nonce, plaintext, additionalData []byte) {
	if !haveAsm {
		a.sealGeneric(out, nonce, plaintext, additionalData)
		return
	}

	var encKey [40]byte
	var authKey [24]byte
	deriveKeysAsm(&authKey, &encKey, &a.kgk, nonce)

	var enc keySchedule
	enc.init(encKey[:len(a.key)])

	var p polyval.Polyval
	initPolyval(&p, authKey[:16])
	absorbPadded(&p, additionalData)
	absorbPadded(&p, plaintext)

	tag := (*[TagSize]byte)(out[len(out)-TagSize:])
	finishTag(&p, tag, &enc, nonce, len(additionalData), len(plaintext))

	if len(plaintext) > 0 {
		block := *tag
		block[15] |= 0x80
		aesctr(enc.nr, &enc.enc[0], &block, out, plaintext)
	}
	wipeMessageKeys(&authKey, &encKey, &enc, &p)
}

func (a *aead) open(out, nonce, ciphertext, tag, additionalData []byte) bool {
	if !haveAsm {
		return a.openGeneric(out, nonce, ciphertext, tag, additionalData)
	}

	var encKey [40]byte
	var authKey [24]byte
	deriveKeysAsm(&authKey, &encKey, &a.kgk, nonce)

	var enc keySchedule
	enc.init(encKey[:len(a.key)])

	var p polyval.Polyval
	initPolyval(&p, authKey[:16])
	absorbPadded(&p, additionalData)

	if len(ciphertext) > 0 {
		var block [TagSize]byte
		copy(block[:], tag)
		block[15] |= 0x80
		openBlocks(&p, &enc, &block, out, ciphertext)
	}

	var wantTag [TagSize]byte
	finishTag(&p, &wantTag, &enc, nonce, len(additionalData), len(ciphertext))
	wipeMessageKeys(&authKey, &encKey, &enc, &p)
	return subtle.ConstantTimeCompare(tag, wantTag[:]) == 1
}

// openBlocks decrypts src into dst with AES-CTR starting at
// block and absorbs the zero-padded plaintext into p.
//
// Whole groups of eight blocks go through openFusedAsm, which
// decrypts and hashes in a single pass; the rest is decrypted
// and then hashed.
func openBlocks(p *polyval.Polyval, enc *keySchedule, block *[TagSize]byte, dst, src []byte) {
	if n := (len(src) / blockSize) &^ 7; n > 0 {
		_ = dst[n*blockSize-1] // bounds check
		acc, pow := p.Raw()
		openFusedAsm(enc.nr, &enc.enc[0], block, &dst[0], &src[0], n, acc, pow)
		dst = dst[n*blockSize:]
		src = src[n*blockSize:]
	}
	if len(src) > 0 {
		aesctr(enc.nr, &enc.enc[0], block, dst, src)
		absorbPadded(p, dst[:len(src)])
	}
}

// deriveKeys derives the authentication and encryption keys
// from keyGenKey and nonce and writes them to authKey and
// encKey.
func deriveKeys(authKey *[24]byte, encKey *[40]byte, keyGenKey, nonce []byte) {
	if !haveAsm {
		deriveKeysGeneric(authKey, encKey, keyGenKey, nonce)
		return
	}
	var kgk keySchedule
	kgk.init(keyGenKey)
	deriveKeysAsm(authKey, encKey, &kgk, nonce)
	kgk.wipe()
}

// deriveKeysAsm is deriveKeys with an already expanded
// key-generating key.
//
// RFC 8452 derives the keys from
//
//	AES(key_generating_key, little_endian_uint32(i) ++ nonce)[:8]
//
// for i = 0..3 (AES-128) or i = 0..5 (AES-256). Those inputs
// are consecutive AES-GCM-SIV counter blocks starting at
// 0 ++ nonce, so the blocks are produced in parallel by running
// the CTR code over zeros. The counter cannot wrap.
func deriveKeysAsm(authKey *[24]byte, encKey *[40]byte, kgk *keySchedule, nonce []byte) {
	var ctr [TagSize]byte
	copy(ctr[4:], nonce)

	var ks [6 * blockSize]byte
	n := 4
	if kgk.nr == 14 {
		n = 6
	}
	ctrBlocksAsm(kgk.nr, &kgk.enc[0], &ctr, &ks[0], &ks[0], n)

	// message_authentication_key = blocks 0 and 1.
	copy(authKey[0:8], ks[0*blockSize:])
	copy(authKey[8:16], ks[1*blockSize:])

	// message_encryption_key = blocks 2 and 3, plus 4 and 5
	// for AES-256.
	copy(encKey[0:8], ks[2*blockSize:])
	copy(encKey[8:16], ks[3*blockSize:])
	if n == 6 {
		copy(encKey[16:24], ks[4*blockSize:])
		copy(encKey[24:32], ks[5*blockSize:])
	}
	wipe(ks[:])
}

// initPolyval initialises p with the message authentication
// key.
func initPolyval(p *polyval.Polyval, authKey []byte) {
	if err := p.Init(authKey); err != nil {
		panic(err)
	}
}

// absorbPadded writes data to p, zero padding the final partial
// block.
func absorbPadded(p *polyval.Polyval, data []byte) {
	if n := len(data) &^ (blockSize - 1); n > 0 {
		p.Update(data[:n])
		data = data[n:]
	}
	if len(data) > 0 {
		var block [blockSize]byte
		copy(block[:], data)
		p.Update(block[:])
	}
}

// absorbLengths writes the length block to p.
func absorbLengths(p *polyval.Polyval, adLen, ptLen int) {
	var length [blockSize]byte
	binary.LittleEndian.PutUint64(length[0:8], uint64(adLen)*8)
	binary.LittleEndian.PutUint64(length[8:16], uint64(ptLen)*8)
	p.Update(length[:])
}

// maskTag writes the POLYVAL result XORed with the nonce and
// with the most significant bit cleared to tag.
func maskTag(p *polyval.Polyval, tag *[TagSize]byte, nonce []byte) {
	p.Sum(tag[:0])
	for i := range nonce {
		tag[i] ^= nonce[i]
	}
	tag[15] &= 0x7f
}

// finishTag absorbs the length block and writes the final
// authentication tag to tag.
func finishTag(p *polyval.Polyval, tag *[TagSize]byte, enc *keySchedule, nonce []byte, adLen, ptLen int) {
	absorbLengths(p, adLen, ptLen)
	maskTag(p, tag, nonce)
	encryptBlockAsm(enc.nr, &enc.enc[0], &tag[0], &tag[0])
}

// aesctr XORs src with the AES-CTR keystream starting at block
// and writes the result to dst.
//
// Full blocks are processed by ctrBlocksAsm, which encrypts
// eight (or four) counter blocks in parallel to keep the AES
// pipeline busy. The trailing partial block, if any, uses a
// single block encryption.
func aesctr(nr int, enc *uint32, block *[TagSize]byte, dst, src []byte) {
	if len(src) == 0 {
		return
	}
	// Bounds check: the assembly writes len(src) bytes to dst.
	_ = dst[len(src)-1]

	if n := len(src) / blockSize; n > 0 {
		ctrBlocksAsm(nr, enc, block, &dst[0], &src[0], n)
		dst = dst[n*blockSize:]
		src = src[n*blockSize:]
	}

	if len(src) > 0 {
		var ks [blockSize]byte
		encryptBlockAsm(nr, enc, &ks[0], &block[0])
		xor(dst, src, ks[:], len(src))
	}
}

// ctrBlocksAsm XORs nblocks full blocks of AES-CTR keystream,
// starting at *ctr, into src and writes the result to dst. On
// return *ctr holds the next unused counter block.
//
// nr must be 10 or 14. dst and src must either be equal or not
// overlap.
//
//go:noescape
func ctrBlocksAsm(nr int, xk *uint32, ctr *[TagSize]byte, dst, src *byte, nblocks int)
