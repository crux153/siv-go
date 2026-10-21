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

func (a *aead) seal(out, nonce, plaintext, additionalData []byte) {
	if !haveAsm {
		a.sealGeneric(out, nonce, plaintext, additionalData)
		return
	}

	var encKey [40]byte
	var authKey [24]byte
	deriveKeysAsm(&authKey, &encKey, &a.kgk, nonce)

	nr := 6 + len(a.key)/4
	var enc [maxEncSize]uint32
	expandKeyAsm(nr, &encKey[0], &enc[0])

	tag := (*[TagSize]byte)(out[len(out)-TagSize:])
	sum(tag, authKey[:16], nonce, plaintext, additionalData)
	encryptBlockAsm(nr, &enc[0], &tag[0], &tag[0])

	if len(plaintext) > 0 {
		block := *tag
		block[15] |= 0x80
		aesctr(nr, &enc[0], &block, out, plaintext)
	}
}

func (a *aead) open(out, nonce, ciphertext, tag, additionalData []byte) bool {
	if !haveAsm {
		return a.openGeneric(out, nonce, ciphertext, tag, additionalData)
	}

	var encKey [40]byte
	var authKey [24]byte
	deriveKeysAsm(&authKey, &encKey, &a.kgk, nonce)

	nr := 6 + len(a.key)/4
	var enc [maxEncSize]uint32
	expandKeyAsm(nr, &encKey[0], &enc[0])

	if len(ciphertext) > 0 {
		var block [TagSize]byte
		copy(block[:], tag)
		block[15] |= 0x80
		aesctr(nr, &enc[0], &block, out, ciphertext)
	}

	var wantTag [TagSize]byte
	sum(&wantTag, authKey[:16], nonce, out, additionalData)
	encryptBlockAsm(nr, &enc[0], &wantTag[0], &wantTag[0])

	return subtle.ConstantTimeCompare(tag, wantTag[:]) == 1
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
}

func sum(tag *[TagSize]byte, authKey, nonce, plaintext, additionalData []byte) {
	length := make([]byte, 16)
	binary.LittleEndian.PutUint64(length[0:8], uint64(len(additionalData))*8)
	binary.LittleEndian.PutUint64(length[8:16], uint64(len(plaintext))*8)

	var p polyval.Polyval
	if err := p.Init(authKey); err != nil {
		panic(err)
	}

	// Additional data
	if len(additionalData) >= 16 {
		n := len(additionalData) &^ (16 - 1)
		p.Update(additionalData[:n])
		additionalData = additionalData[n:]
	}
	if len(additionalData) > 0 {
		dst := make([]byte, 16)
		copy(dst, additionalData)
		p.Update(dst)
	}

	// Plaintext
	if len(plaintext) >= 16 {
		n := len(plaintext) &^ (16 - 1)
		p.Update(plaintext[:n])
		plaintext = plaintext[n:]
	}
	if len(plaintext) > 0 {
		dst := make([]byte, 16)
		copy(dst, plaintext)
		p.Update(dst)
	}

	// Length
	p.Update(length)

	p.Sum(tag[:0])
	for i := range nonce {
		tag[i] ^= nonce[i]
	}
	tag[15] &= 0x7f
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
