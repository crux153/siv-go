//go:build amd64 && gc && !purego

#include "textflag.h"
#include "fused_amd64.h"

// Single-pass AES-GCM-SIV decryption: AES-CTR and POLYVAL over
// the same data, interleaved so that the AES unit and the
// carry-less multiplier work at the same time.
//
// Each iteration decrypts eight blocks while hashing the eight
// plaintext blocks written by the previous iteration (read back
// from dst, where they are still in L1). Only SSE2, AES-NI and
// PCLMULQDQ are used. See fused_amd64.h for the register use
// and the POLYVAL method.

// HASH0 and HASH load the data block at doff(DI), the plaintext
// written by the previous iteration.
#define HASH0(doff) \
	MOVOU doff(DI), X12; \
	HASHX0

#define HASH(doff, poff) \
	MOVOU doff(DI), X12; \
	HASHX(poff)

// func openFusedAsm(nr int, xk *uint32, ctr *[16]byte, dst, src *byte, nblocks int, acc *[16]byte, pow *[128]byte)
//
// openFusedAsm decrypts nblocks blocks from src into dst with
// AES-CTR starting at *ctr and absorbs the resulting plaintext
// into the POLYVAL accumulator *acc using the powers
// pow = h^8 || h^7 || ... || h^1.
//
// nblocks must be a positive multiple of 8 and nr must be 10 or
// 14. dst and src must either be equal or not overlap. On return
// *ctr and *acc hold the updated counter and accumulator.
//
// Requires: AES, PCLMULQDQ, SSE2
TEXT ·openFusedAsm(SB), NOSPLIT, $160-64
	MOVQ nr+0(FP), CX
	MOVQ xk+8(FP), AX
	MOVQ ctr+16(FP), BX
	MOVQ dst+24(FP), DI
	MOVQ src+32(FP), SI
	MOVQ nblocks+40(FP), DX
	MOVQ acc+48(FP), R10
	MOVQ pow+56(FP), R11

	// Aligned scratch for h^8..h^1 and the reduction constant.
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

	// First group: decrypt only.
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
	XOR8

	ADDQ $128, SI
	ADDQ $128, DI
	SUBQ $8, DX
	JZ   lastHash

	// Steady state: decrypt this group while hashing the
	// previous one, which ends just before DI.
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
	HASH0(-128)
	ROUND8(AESENC, 32, R8)
	HASH(-112, 16)
	ROUND8(AESENC, 48, R8)
	HASH(-96, 32)
	ROUND8(AESENC, 64, R8)
	HASH(-80, 48)
	ROUND8(AESENC, 80, R8)
	HASH(-64, 64)
	ROUND8(AESENC, 96, R8)
	HASH(-48, 80)
	ROUND8(AESENC, 112, R8)
	HASH(-32, 96)
	ROUND8(AESENC, 128, R8)
	HASH(-16, 112)
	ROUND8(AESENC, 144, R8)
	REDUCE
	ROUND8(AESENCLAST, 160, R8)
	XOR8

	ADDQ $128, SI
	ADDQ $128, DI
	SUBQ $8, DX
	JNZ  loop

	// Hash the final group.
lastHash:
	HASH0(-128)
	HASH(-112, 16)
	HASH(-96, 32)
	HASH(-80, 48)
	HASH(-64, 64)
	HASH(-48, 80)
	HASH(-32, 96)
	HASH(-16, 112)
	REDUCE

	MOVOU X9, (R10)
	MOVOU X14, (BX)

	// Do not leave the hash key powers on the stack.
	CLEAR_SCRATCH
	RET
