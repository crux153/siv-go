//go:build amd64 && gc && !purego

#include "textflag.h"

// Single-pass AES-GCM-SIV decryption: AES-CTR and POLYVAL over
// the same data, interleaved so that the AES unit and the
// carry-less multiplier work at the same time.
//
// Each iteration decrypts eight blocks while hashing the eight
// plaintext blocks written by the previous iteration (read back
// from dst, where they are still in L1). Only SSE2, AES-NI and
// PCLMULQDQ are used.
//
// POLYVAL uses schoolbook multiplication (four PCLMULQDQ per
// block, no shuffles) with aggregated reduction over eight
// blocks: block i of a group is multiplied by h^(8-i) and the
// accumulator is added to block 0, as in internal/polyval.
//
// Register use:
//
//	X0-X7   AES states
//	X8      round key / scratch
//	X9      POLYVAL low product, and the accumulator between groups
//	X10     POLYVAL high product
//	X11     POLYVAL middle product
//	X12     POLYVAL data block
//	X13     POLYVAL scratch
//	X14     counter block
//	X15     counter increment {1, 0, 0, 0}
//
// R9 points at a 16-byte aligned copy of the powers h^8..h^1
// followed by the reduction constant, so that PCLMULQDQ can use
// them as memory operands (legacy SSE requires alignment).

DATA openOne<>+0(SB)/8, $0x0000000000000001
DATA openOne<>+8(SB)/8, $0x0000000000000000
GLOBL openOne<>(SB), RODATA|NOPTR, $16

DATA openPolyMask<>+0(SB)/8, $0xc200000000000000
DATA openPolyMask<>+8(SB)/8, $0xc200000000000000
GLOBL openPolyMask<>(SB), RODATA|NOPTR, $16

#define ROUND8(op, off, base) \
	MOVOU off(base), X8; \
	op    X8, X0; \
	op    X8, X1; \
	op    X8, X2; \
	op    X8, X3; \
	op    X8, X4; \
	op    X8, X5; \
	op    X8, X6; \
	op    X8, X7

// NEXT loads the counter block into x, XORs it with the first
// round key (in X8) and increments the counter.
#define NEXT(x) \
	MOVO  X14, x; \
	PADDD X15, X14; \
	PXOR  X8, x

// COUNTERS8 prepares eight counter blocks for the first round.
#define COUNTERS8 \
	MOVOU (AX), X8; \
	NEXT(X0); \
	NEXT(X1); \
	NEXT(X2); \
	NEXT(X3); \
	NEXT(X4); \
	NEXT(X5); \
	NEXT(X6); \
	NEXT(X7)

// XORBLOCK XORs the ciphertext block at off(SI) into x and stores
// the plaintext at off(DI).
#define XORBLOCK(x, off) \
	MOVOU off(SI), X8; \
	PXOR  X8, x; \
	MOVOU x, off(DI)

#define XOR8 \
	XORBLOCK(X0, 0); \
	XORBLOCK(X1, 16); \
	XORBLOCK(X2, 32); \
	XORBLOCK(X3, 48); \
	XORBLOCK(X4, 64); \
	XORBLOCK(X5, 80); \
	XORBLOCK(X6, 96); \
	XORBLOCK(X7, 112)

// HASH0 starts a group: it adds the accumulator (X9) to the
// first data block at doff(DI) and multiplies by h^8, which
// initialises the low, high and middle products.
#define HASH0(doff) \
	MOVOU     doff(DI), X12; \
	PXOR      X9, X12; \
	MOVO      X12, X9; \
	PCLMULQDQ $0x00, 0(R9), X9; \
	MOVO      X12, X10; \
	PCLMULQDQ $0x11, 0(R9), X10; \
	MOVO      X12, X11; \
	PCLMULQDQ $0x01, 0(R9), X11; \
	PCLMULQDQ $0x10, 0(R9), X12; \
	PXOR      X12, X11

// HASH multiplies the data block at doff(DI) by the power at
// poff(R9) and adds the result to the products.
#define HASH(doff, poff) \
	MOVOU     doff(DI), X12; \
	MOVO      X12, X13; \
	PCLMULQDQ $0x00, poff(R9), X13; \
	PXOR      X13, X9; \
	MOVO      X12, X13; \
	PCLMULQDQ $0x11, poff(R9), X13; \
	PXOR      X13, X10; \
	MOVO      X12, X13; \
	PCLMULQDQ $0x01, poff(R9), X13; \
	PXOR      X13, X11; \
	PCLMULQDQ $0x10, poff(R9), X12; \
	PXOR      X12, X11

// REDUCE folds the middle product into the 256-bit result and
// performs the Montgomery reduction used by internal/polyval,
// leaving the new accumulator in X9.
#define REDUCE \
	MOVO      X11, X12; \
	PSLLDQ    $8, X12; \
	PXOR      X12, X9; \
	PSRLDQ    $8, X11; \
	PXOR      X11, X10; \
	MOVO      128(R9), X13; \
	PCLMULQDQ $0x00, X9, X13; \
	PSHUFD    $0x4e, X13, X13; \
	PXOR      X9, X13; \
	PXOR      X13, X10; \
	PCLMULQDQ $0x11, 128(R9), X13; \
	PXOR      X10, X13; \
	MOVO      X13, X9

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
	MOVOU 0(R11), X12
	MOVO  X12, 0(R9)
	MOVOU 16(R11), X12
	MOVO  X12, 16(R9)
	MOVOU 32(R11), X12
	MOVO  X12, 32(R9)
	MOVOU 48(R11), X12
	MOVO  X12, 48(R9)
	MOVOU 64(R11), X12
	MOVO  X12, 64(R9)
	MOVOU 80(R11), X12
	MOVO  X12, 80(R9)
	MOVOU 96(R11), X12
	MOVO  X12, 96(R9)
	MOVOU 112(R11), X12
	MOVO  X12, 112(R9)
	MOVOU openPolyMask<>(SB), X12
	MOVO  X12, 128(R9)

	// R8 points at round key nr-10; see ctr_amd64.s.
	MOVQ CX, R8
	SHLQ $4, R8
	LEAQ -160(AX)(R8*1), R8

	MOVOU (BX), X14
	MOVOU openOne<>(SB), X15
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
	PXOR X12, X12
	MOVO X12, 0(R9)
	MOVO X12, 16(R9)
	MOVO X12, 32(R9)
	MOVO X12, 48(R9)
	MOVO X12, 64(R9)
	MOVO X12, 80(R9)
	MOVO X12, 96(R9)
	MOVO X12, 112(R9)
	RET
