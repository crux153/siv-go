//go:build gc && !purego

package polyval

import (
	"unsafe"

	"golang.org/x/sys/cpu"
)

var haveAsm = cpu.X86.HasPCLMULQDQ

func polymul(acc, key *fieldElement) {
	if haveAsm {
		polymulAsm(acc, key)
	} else {
		polymulGeneric(acc, key)
	}
}

func polymulBlocks(acc *fieldElement, pow *[8]fieldElement, blocks []byte) {
	if len(blocks) == 0 {
		return
	}
	if haveAsm {
		polymulBlocksAsm(acc, pow, &blocks[0], len(blocks)/16)
	} else {
		polymulBlocksGeneric(acc, pow, blocks)
	}
}

func ctmul(x, y uint64) (z1, z0 uint64) {
	return ctmulGeneric(x, y)
}

// Raw returns the running accumulator and the table of powers
// h^8, h^7, ..., h^1 as little-endian 128-bit values, computing
// the powers first if needed.
//
// It lets assembly outside this package interleave POLYVAL with
// other work. The caller must use the same aggregated reduction
// as polymulBlocksAsm.
func (p *Polyval) Raw() (acc *[16]byte, pow *[128]byte) {
	if !p.havePow {
		p.initPow()
	}
	return (*[16]byte)(unsafe.Pointer(&p.y)), (*[128]byte)(unsafe.Pointer(&p.pow))
}
