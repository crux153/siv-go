//go:build amd64 && gc && !purego

#include "textflag.h"
#include "fused_amd64.h"

// Single-pass AES-CTR encryption that also absorbs the plaintext
// into POLYVAL, used to check that the plaintext encrypted by
// SegmentSealer.KeyStream is the plaintext that was authenticated.
//
// Each plaintext block is loaded from src once. The loaded value
// is XORed with the key stream and also copied to a private
// buffer in this function's frame, which the next iteration
// hashes between its AES rounds (as openFusedAsm does with the
// plaintext it wrote to dst). A plaintext buffer modified
// concurrently therefore cannot produce a ciphertext block that
// differs from the hashed block. Only SSE2, AES-NI and PCLMULQDQ
// are used. See fused_amd64.h for the register use and the
// POLYVAL method.

// PTOFF is the offset of the plaintext copy in the aligned
// scratch area, after the powers and the reduction constant.
#define PTOFF 144

// XORSAVE encrypts the plaintext block at off(SI) with the key
// stream block in x, stores the ciphertext at off(DI) and the
// plaintext at PTOFF+off(R9).
#define XORSAVE(x, off) \
	MOVOU off(SI), X8; \
	MOVO  X8, (PTOFF+off)(R9); \
	PXOR  X8, x; \
	MOVOU x, off(DI)

#define XORSAVE8 \
	XORSAVE(X0, 0); \
	XORSAVE(X1, 16); \
	XORSAVE(X2, 32); \
	XORSAVE(X3, 48); \
	XORSAVE(X4, 64); \
	XORSAVE(X5, 80); \
	XORSAVE(X6, 96); \
	XORSAVE(X7, 112)

// HASH0 and HASH hash the saved plaintext block at
// PTOFF+off(R9) with the power at off(R9).
#define HASH0 \
	MOVO (PTOFF)(R9), X12; \
	HASHX0

#define HASH(off) \
	MOVO (PTOFF+off)(R9), X12; \
	HASHX(off)

// func sealFusedAsm(nr int, xk *uint32, ctr *[16]byte, dst, src *byte, nblocks int, acc *[16]byte, pow *[128]byte)
//
// sealFusedAsm encrypts nblocks blocks from src into dst with
// AES-CTR starting at *ctr and absorbs the plaintext into the
// POLYVAL accumulator *acc using the powers
// pow = h^8 || h^7 || ... || h^1.
//
// nblocks must be a positive multiple of 8 and nr must be 10 or
// 14. dst and src must either be equal or not overlap. On return
// *ctr and *acc hold the updated counter and accumulator.
//
// Requires: AES, PCLMULQDQ, SSE2
TEXT ·sealFusedAsm(SB), NOSPLIT, $288-64
	MOVQ nr+0(FP), CX
	MOVQ xk+8(FP), AX
	MOVQ ctr+16(FP), BX
	MOVQ dst+24(FP), DI
	MOVQ src+32(FP), SI
	MOVQ nblocks+40(FP), DX
	MOVQ acc+48(FP), R10
	MOVQ pow+56(FP), R11

	// Aligned scratch for h^8..h^1, the reduction constant and
	// the plaintext copy (15 + 144 + 128 <= 288 bytes).
	LEAQ 15(SP), R9
	ANDQ $-16, R9
	SETUP_SCRATCH

	// R8 points at round key nr-10; see ctr_amd64.s.
	MOVQ CX, R8
	SHLQ $4, R8
	LEAQ -160(AX)(R8*1), R8

	MOVOU (BX), X14
	MOVOU fusedOne<>(SB), X15
	MOVOU (R10), X9

	// First group: encrypt only.
	COUNTERS8
	CMPQ CX, $10
	JE   firstRounds
	ROUND8(AESENC, 16, AX)
	ROUND8(AESENC, 32, AX)
	ROUND8(AESENC, 48, AX)
	ROUND8(AESENC, 64, AX)

firstRounds:
	ROUND8(AESENC, 16, R8)
	ROUND8(AESENC, 32, R8)
	ROUND8(AESENC, 48, R8)
	ROUND8(AESENC, 64, R8)
	ROUND8(AESENC, 80, R8)
	ROUND8(AESENC, 96, R8)
	ROUND8(AESENC, 112, R8)
	ROUND8(AESENC, 128, R8)
	ROUND8(AESENC, 144, R8)
	ROUND8(AESENCLAST, 160, R8)
	XORSAVE8

	ADDQ $128, SI
	ADDQ $128, DI
	SUBQ $8, DX
	JZ   lastHash

	// Steady state: encrypt this group while hashing the saved
	// plaintext of the previous one.
loop:
	COUNTERS8
	CMPQ CX, $10
	JE   loopRounds
	ROUND8(AESENC, 16, AX)
	ROUND8(AESENC, 32, AX)
	ROUND8(AESENC, 48, AX)
	ROUND8(AESENC, 64, AX)

loopRounds:
	ROUND8(AESENC, 16, R8)
	HASH0
	ROUND8(AESENC, 32, R8)
	HASH(16)
	ROUND8(AESENC, 48, R8)
	HASH(32)
	ROUND8(AESENC, 64, R8)
	HASH(48)
	ROUND8(AESENC, 80, R8)
	HASH(64)
	ROUND8(AESENC, 96, R8)
	HASH(80)
	ROUND8(AESENC, 112, R8)
	HASH(96)
	ROUND8(AESENC, 128, R8)
	HASH(112)
	ROUND8(AESENC, 144, R8)
	REDUCE
	ROUND8(AESENCLAST, 160, R8)
	XORSAVE8

	ADDQ $128, SI
	ADDQ $128, DI
	SUBQ $8, DX
	JNZ  loop

	// Hash the final group.
lastHash:
	HASH0
	HASH(16)
	HASH(32)
	HASH(48)
	HASH(64)
	HASH(80)
	HASH(96)
	HASH(112)
	REDUCE

	MOVOU X9, (R10)
	MOVOU X14, (BX)

	// Do not leave the hash key powers or plaintext on the stack.
	CLEAR_SCRATCH
	MOVO X12, (PTOFF+0)(R9)
	MOVO X12, (PTOFF+16)(R9)
	MOVO X12, (PTOFF+32)(R9)
	MOVO X12, (PTOFF+48)(R9)
	MOVO X12, (PTOFF+64)(R9)
	MOVO X12, (PTOFF+80)(R9)
	MOVO X12, (PTOFF+96)(R9)
	MOVO X12, (PTOFF+112)(R9)
	RET
