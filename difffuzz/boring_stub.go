//go:build !difffuzz_boringssl

package difffuzz

// haveBoring reports whether BoringSSL is linked in as a second
// sealing reference. Build with -tags difffuzz_boringssl (after
// boringssl.sh) to enable it.
const haveBoring = false

func boringSeal(dst, key, nonce, pt, aad []byte) []byte {
	panic("difffuzz: built without the difffuzz_boringssl tag")
}
