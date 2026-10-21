//go:build amd64 && gc && !purego

#include "textflag.h"

// AES-CTR keystream generation for AES-GCM-SIV.
//
// The 8-way and 4-way structure follows the AES-CTR code in
// github.com/secure-io/siv-go. It only uses SSE2 and AES-NI
// (no VEX encoding), so it runs on CPUs without AVX. Memory
// operands are always loaded with MOVOU first because
// legacy-SSE PXOR/AESENC require 16-byte aligned memory operands.
//
// AES-GCM-SIV increments only the first 32 bits of the counter
// block, as a little-endian integer modulo 2^32 (RFC 8452,
// section 4). PADDD with {1, 0, 0, 0} does exactly that.

DATA ctrOne<>+0(SB)/8, $0x0000000000000001
DATA ctrOne<>+8(SB)/8, $0x0000000000000000
GLOBL ctrOne<>(SB), RODATA|NOPTR, $16

// ROUND8 applies one AES round with the round key at off(base)
// to X0-X7. X8 is clobbered.
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

// ROUND4 applies one AES round with the round key at off(base)
// to X0-X3. X8 is clobbered.
#define ROUND4(op, off, base) \
	MOVOU off(base), X8; \
	op    X8, X0; \
	op    X8, X1; \
	op    X8, X2; \
	op    X8, X3

// ROUND1 applies one AES round with the round key at off(base)
// to X0. X8 is clobbered.
#define ROUND1(op, off, base) \
	MOVOU off(base), X8; \
	op    X8, X0

// NEXT loads the current counter block into x, XORs it with the
// first round key (in X11) and increments the counter in X10.
#define NEXT(x) \
	MOVOU X10, x; \
	PADDD X9, X10; \
	PXOR  X11, x

// XORBLOCK XORs the 16 bytes at off(SI) into x and stores the
// result at off(DI). X8 is clobbered.
#define XORBLOCK(x, off) \
	MOVOU off(SI), X8; \
	PXOR  X8, x; \
	MOVOU x, off(DI)

// func ctrBlocksAsm(nr int, xk *uint32, ctr *[16]byte, dst, src *byte, nblocks int)
//
// ctrBlocksAsm XORs nblocks full blocks of AES-CTR keystream
// into src and writes the result to dst. On return *ctr holds
// the next unused counter block.
//
// nr must be 10 (AES-128) or 14 (AES-256). dst and src must
// either be equal or not overlap.
//
// Requires: AES, SSE2
TEXT ·ctrBlocksAsm(SB), NOSPLIT, $0-48
	MOVQ nr+0(FP), CX
	MOVQ xk+8(FP), AX
	MOVQ ctr+16(FP), BX
	MOVQ dst+24(FP), DI
	MOVQ src+32(FP), SI
	MOVQ nblocks+40(FP), DX

	// R8 points at round key nr-10 so that the last ten rounds
	// share the same offsets for both key sizes. AES-256 runs
	// four extra rounds (keys 1-4) from AX first.
	MOVQ CX, R8
	SHLQ $4, R8
	LEAQ -160(AX)(R8*1), R8

	MOVOU (BX), X10
	MOVOU ctrOne<>(SB), X9
	MOVOU (AX), X11

	CMPQ DX, $8
	JB   tail4

loop8:
	NEXT(X0)
	NEXT(X1)
	NEXT(X2)
	NEXT(X3)
	NEXT(X4)
	NEXT(X5)
	NEXT(X6)
	NEXT(X7)

	CMPQ CX, $10
	JE   loop8Rounds
	ROUND8(AESENC, 16, AX)
	ROUND8(AESENC, 32, AX)
	ROUND8(AESENC, 48, AX)
	ROUND8(AESENC, 64, AX)

loop8Rounds:
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

	XORBLOCK(X0, 0)
	XORBLOCK(X1, 16)
	XORBLOCK(X2, 32)
	XORBLOCK(X3, 48)
	XORBLOCK(X4, 64)
	XORBLOCK(X5, 80)
	XORBLOCK(X6, 96)
	XORBLOCK(X7, 112)

	ADDQ $128, SI
	ADDQ $128, DI
	SUBQ $8, DX
	CMPQ DX, $8
	JAE  loop8

tail4:
	CMPQ DX, $4
	JB   tail1

	NEXT(X0)
	NEXT(X1)
	NEXT(X2)
	NEXT(X3)

	CMPQ CX, $10
	JE   tail4Rounds
	ROUND4(AESENC, 16, AX)
	ROUND4(AESENC, 32, AX)
	ROUND4(AESENC, 48, AX)
	ROUND4(AESENC, 64, AX)

tail4Rounds:
	ROUND4(AESENC, 16, R8)
	ROUND4(AESENC, 32, R8)
	ROUND4(AESENC, 48, R8)
	ROUND4(AESENC, 64, R8)
	ROUND4(AESENC, 80, R8)
	ROUND4(AESENC, 96, R8)
	ROUND4(AESENC, 112, R8)
	ROUND4(AESENC, 128, R8)
	ROUND4(AESENC, 144, R8)
	ROUND4(AESENCLAST, 160, R8)

	XORBLOCK(X0, 0)
	XORBLOCK(X1, 16)
	XORBLOCK(X2, 32)
	XORBLOCK(X3, 48)

	ADDQ $64, SI
	ADDQ $64, DI
	SUBQ $4, DX

tail1:
	TESTQ DX, DX
	JZ    done

loop1:
	NEXT(X0)

	CMPQ CX, $10
	JE   loop1Rounds
	ROUND1(AESENC, 16, AX)
	ROUND1(AESENC, 32, AX)
	ROUND1(AESENC, 48, AX)
	ROUND1(AESENC, 64, AX)

loop1Rounds:
	ROUND1(AESENC, 16, R8)
	ROUND1(AESENC, 32, R8)
	ROUND1(AESENC, 48, R8)
	ROUND1(AESENC, 64, R8)
	ROUND1(AESENC, 80, R8)
	ROUND1(AESENC, 96, R8)
	ROUND1(AESENC, 112, R8)
	ROUND1(AESENC, 128, R8)
	ROUND1(AESENC, 144, R8)
	ROUND1(AESENCLAST, 160, R8)

	XORBLOCK(X0, 0)

	ADDQ $16, SI
	ADDQ $16, DI
	DECQ DX
	JNZ  loop1

done:
	MOVOU X10, (BX)
	RET
