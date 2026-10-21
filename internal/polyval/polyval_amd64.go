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
	if !haveAsm {
		polymulBlocksGeneric(acc, pow, blocks)
		return
	}
	// polymulWideAsm is faster per group of eight blocks but
	// has a fixed setup cost, so short inputs use
	// polymulBlocksAsm alone. Otherwise the leading blocks that
	// do not fill a group are processed one at a time first.
	if len(blocks) < wideMinBytes {
		polymulBlocksAsm(acc, pow, &blocks[0], len(blocks)/16)
		return
	}
	if r := (len(blocks) / 16) % 8; r > 0 {
		polymulBlocksAsm(acc, pow, &blocks[0], r)
		blocks = blocks[16*r:]
	}
	polymulWideAsm(acc, pow, &blocks[0], len(blocks)/(16*8))
}

// wideMinBytes is the input length from which polymulWideAsm is
// used.
const wideMinBytes = 8 * 16 * 8

// polymulWideAsm absorbs ngroups groups of eight blocks into
// acc. ngroups must be positive.
//
//go:noescape
func polymulWideAsm(acc *fieldElement, pow *[8]fieldElement, input *byte, ngroups int)

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
