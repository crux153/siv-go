// Shared macros for the fused AES-CTR + POLYVAL kernels in
// open_amd64.s and seal_amd64.s.
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
// them as memory operands (legacy SSE requires alignment). The
// including function needs a frame of at least 160 bytes.
//
// POLYVAL uses schoolbook multiplication (four PCLMULQDQ per
// block, no shuffles) with aggregated reduction over eight
// blocks: block i of a group is multiplied by h^(8-i) and the
// accumulator is added to block 0, as in internal/polyval.

DATA fusedOne<>+0(SB)/8, $0x0000000000000001
DATA fusedOne<>+8(SB)/8, $0x0000000000000000
GLOBL fusedOne<>(SB), RODATA|NOPTR, $16

DATA fusedPolyMask<>+0(SB)/8, $0xc200000000000000
DATA fusedPolyMask<>+8(SB)/8, $0xc200000000000000
GLOBL fusedPolyMask<>(SB), RODATA|NOPTR, $16

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

// HASHX0 starts a group with the data block in X12: it adds the
// accumulator (X9), multiplies by h^8 and initialises the low
// (X9), high (X10) and middle (X11) products. X12 is clobbered.
#define HASHX0 \
	PXOR      X9, X12; \
	MOVO      X12, X9; \
	PCLMULQDQ $0x00, 0(R9), X9; \
	MOVO      X12, X10; \
	PCLMULQDQ $0x11, 0(R9), X10; \
	MOVO      X12, X11; \
	PCLMULQDQ $0x01, 0(R9), X11; \
	PCLMULQDQ $0x10, 0(R9), X12; \
	PXOR      X12, X11

// HASHX multiplies the data block in X12 by the power at
// poff(R9) and adds the result to the products. X12 and X13
// are clobbered.
#define HASHX(poff) \
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

// SETUP_SCRATCH copies h^8..h^1 from (R11) and the reduction
// constant to the 16-byte aligned scratch area at R9, which the
// caller points into its frame. X12 is clobbered.
#define SETUP_SCRATCH \
	MOVOU 0(R11), X12; \
	MOVO  X12, 0(R9); \
	MOVOU 16(R11), X12; \
	MOVO  X12, 16(R9); \
	MOVOU 32(R11), X12; \
	MOVO  X12, 32(R9); \
	MOVOU 48(R11), X12; \
	MOVO  X12, 48(R9); \
	MOVOU 64(R11), X12; \
	MOVO  X12, 64(R9); \
	MOVOU 80(R11), X12; \
	MOVO  X12, 80(R9); \
	MOVOU 96(R11), X12; \
	MOVO  X12, 96(R9); \
	MOVOU 112(R11), X12; \
	MOVO  X12, 112(R9); \
	MOVOU fusedPolyMask<>(SB), X12; \
	MOVO  X12, 128(R9)

// CLEAR_SCRATCH zeroes the copy of the key powers. X12 is
// clobbered.
#define CLEAR_SCRATCH \
	PXOR X12, X12; \
	MOVO X12, 0(R9); \
	MOVO X12, 16(R9); \
	MOVO X12, 32(R9); \
	MOVO X12, 48(R9); \
	MOVO X12, 64(R9); \
	MOVO X12, 80(R9); \
	MOVO X12, 96(R9); \
	MOVO X12, 112(R9)
