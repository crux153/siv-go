//go:build gc && !purego

#include "textflag.h"

// Eight-block POLYVAL loop with precomputed Karatsuba terms.
//
// polymulBlocksAsm recomputes the Karatsuba term hi^lo of each
// key power for every block, which costs an extra shuffle per
// block on the port that also runs PCLMULQDQ on Skylake-class
// cores. This loop computes those terms once per call. Each
// block then costs three PCLMULQDQ and one PSHUFD.
//
// The powers h^8..h^1, their Karatsuba terms (packed two per
// 16 bytes) and the reduction constant are kept in a 16-byte
// aligned area on the stack so that PCLMULQDQ can take them as
// memory operands (legacy SSE requires aligned memory operands).
// Only SSE2 and PCLMULQDQ are used.
//
// The aggregated reduction is the same as in polymulBlocksAsm:
// block i of a group is multiplied by h^(8-i) and the running
// accumulator is added to block 0. Block 0 is processed last, and
// with schoolbook multiplication, so that blocks 7..1 do not wait
// for the previous reduction and the dependency chain through the
// accumulator stays short.
//
// Register use: X0 accumulator, X1 low product, X2 high
// product, X3 middle product, X4 and X5 scratch.

DATA wideMask<>+0(SB)/8, $0xc200000000000000
DATA wideMask<>+8(SB)/8, $0xc200000000000000
GLOBL wideMask<>(SB), RODATA|NOPTR, $16

// Offsets in the aligned area.
#define KOFF 128
#define MASKOFF 192

// KARATSUBA2 stores the Karatsuba terms of the powers at off and
// off+16 in the low and high halves of KOFF+off/2.
#define KARATSUBA2(off) \
	MOVO       off(R9), X4; \
	PSHUFD     $0x4e, X4, X5; \
	PXOR       X5, X4; \
	MOVO       (off+16)(R9), X3; \
	PSHUFD     $0x4e, X3, X5; \
	PXOR       X5, X3; \
	PUNPCKLQDQ X3, X4; \
	MOVO       X4, (KOFF+off/2)(R9)

// FIRST multiplies the block in X4 by the power at poff and
// initialises X1, X2 and X3 with the products.
#define FIRST(poff, kimm) \
	PSHUFD    $0x4e, X4, X3; \
	PXOR      X4, X3; \
	PCLMULQDQ kimm, (KOFF+poff/32*16)(R9), X3; \
	MOVO      X4, X1; \
	PCLMULQDQ $0x00, poff(R9), X1; \
	MOVO      X4, X2; \
	PCLMULQDQ $0x11, poff(R9), X2

// NEXT multiplies the block in X4 by the power at poff and adds
// the products to X1, X2 and X3.
#define NEXT(poff, kimm) \
	PSHUFD    $0x4e, X4, X5; \
	PXOR      X4, X5; \
	PCLMULQDQ kimm, (KOFF+poff/32*16)(R9), X5; \
	PXOR      X5, X3; \
	MOVO      X4, X5; \
	PCLMULQDQ $0x00, poff(R9), X5; \
	PXOR      X5, X1; \
	PCLMULQDQ $0x11, poff(R9), X4; \
	PXOR      X4, X2

// LAST turns the Karatsuba sum in X3 into the middle product of
// blocks 7..1, then multiplies the block in X4 (which includes
// the accumulator) by h^8 with schoolbook multiplication and adds
// its products. This keeps the path from the accumulator to the
// next reduction short.
#define LAST \
	PXOR      X1, X3; \
	PXOR      X2, X3; \
	MOVO      X4, X5; \
	PCLMULQDQ $0x01, 0(R9), X5; \
	PXOR      X5, X3; \
	MOVO      X4, X5; \
	PCLMULQDQ $0x10, 0(R9), X5; \
	PXOR      X5, X3; \
	MOVO      X4, X5; \
	PCLMULQDQ $0x00, 0(R9), X5; \
	PXOR      X5, X1; \
	PCLMULQDQ $0x11, 0(R9), X4; \
	PXOR      X4, X2

// REDUCE folds the middle product into the 256-bit result and
// reduces it, leaving the accumulator in X0.
#define REDUCE \
	MOVO      X3, X4; \
	PSLLDQ    $8, X4; \
	PXOR      X4, X1; \
	PSRLDQ    $8, X3; \
	PXOR      X3, X2; \
	MOVO      MASKOFF(R9), X0; \
	PCLMULQDQ $0x00, X1, X0; \
	PSHUFD    $0x4e, X0, X0; \
	PXOR      X1, X0; \
	PXOR      X0, X2; \
	PCLMULQDQ $0x11, MASKOFF(R9), X0; \
	PXOR      X2, X0

// func polymulWideAsm(acc *fieldElement, pow *[8]fieldElement, input *byte, ngroups int)
//
// polymulWideAsm absorbs ngroups groups of eight blocks into
// acc. ngroups must be positive.
//
// Requires: PCLMULQDQ, SSE2
TEXT ·polymulWideAsm(SB), NOSPLIT, $224-32
	MOVQ acc+0(FP), AX
	MOVQ pow+8(FP), CX
	MOVQ input+16(FP), SI
	MOVQ ngroups+24(FP), DX

	LEAQ  15(SP), R9
	ANDQ  $-16, R9
	MOVOU 0(CX), X3
	MOVO  X3, 0(R9)
	MOVOU 16(CX), X3
	MOVO  X3, 16(R9)
	MOVOU 32(CX), X3
	MOVO  X3, 32(R9)
	MOVOU 48(CX), X3
	MOVO  X3, 48(R9)
	MOVOU 64(CX), X3
	MOVO  X3, 64(R9)
	MOVOU 80(CX), X3
	MOVO  X3, 80(R9)
	MOVOU 96(CX), X3
	MOVO  X3, 96(R9)
	MOVOU 112(CX), X3
	MOVO  X3, 112(R9)
	MOVOU wideMask<>(SB), X3
	MOVO  X3, MASKOFF(R9)
	KARATSUBA2(0)
	KARATSUBA2(32)
	KARATSUBA2(64)
	KARATSUBA2(96)

	MOVOU (AX), X0

loop:
	MOVOU 112(SI), X4
	FIRST(112, $0x10)
	MOVOU 96(SI), X4
	NEXT(96, $0x00)
	MOVOU 80(SI), X4
	NEXT(80, $0x10)
	MOVOU 64(SI), X4
	NEXT(64, $0x00)
	MOVOU 48(SI), X4
	NEXT(48, $0x10)
	MOVOU 32(SI), X4
	NEXT(32, $0x00)
	MOVOU 16(SI), X4
	NEXT(16, $0x10)
	MOVOU 0(SI), X4
	PXOR  X0, X4
	LAST
	REDUCE
	ADDQ  $128, SI
	DECQ  DX
	JNZ   loop

	MOVOU X0, (AX)

	// Do not leave the key powers on the stack.
	PXOR X4, X4
	MOVO X4, 0(R9)
	MOVO X4, 16(R9)
	MOVO X4, 32(R9)
	MOVO X4, 48(R9)
	MOVO X4, 64(R9)
	MOVO X4, 80(R9)
	MOVO X4, 96(R9)
	MOVO X4, 112(R9)
	MOVO X4, 128(R9)
	MOVO X4, 144(R9)
	MOVO X4, 160(R9)
	MOVO X4, 176(R9)
	RET
