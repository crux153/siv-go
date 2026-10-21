//go:build difffuzz_boringssl

package difffuzz

/*
#cgo CFLAGS: -I${SRCDIR}/.cache/boringssl/src/include
#cgo LDFLAGS: ${SRCDIR}/.cache/boringssl/libcrypto.a -lstdc++ -lpthread
#include <openssl/aead.h>

static int boring_seal(const uint8_t *key, size_t key_len,
		uint8_t *out, size_t max_out,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *in, size_t in_len,
		const uint8_t *ad, size_t ad_len) {
	const EVP_AEAD *aead = key_len == 16 ? EVP_aead_aes_128_gcm_siv()
	                                     : EVP_aead_aes_256_gcm_siv();
	EVP_AEAD_CTX ctx;
	if (!EVP_AEAD_CTX_init(&ctx, aead, key, key_len,
	                       EVP_AEAD_DEFAULT_TAG_LENGTH, NULL)) {
		return 0;
	}
	size_t out_len = 0;
	int ok = EVP_AEAD_CTX_seal(&ctx, out, &out_len, max_out, nonce,
	                           nonce_len, in, in_len, ad, ad_len);
	EVP_AEAD_CTX_cleanup(&ctx);
	return ok && out_len == in_len + 16;
}
*/
import "C"

import "unsafe"

// haveBoring reports whether BoringSSL is linked in as a second
// sealing reference.
const haveBoring = true

// boringSeal seals pt with BoringSSL's AES-GCM-SIV into dst, which
// must have room for len(pt)+16 bytes, and returns
// dst[:len(pt)+16].
func boringSeal(dst, key, nonce, pt, aad []byte) []byte {
	out := dst[:len(pt)+16]
	if C.boring_seal(cptr(key), C.size_t(len(key)), cptr(out), C.size_t(len(out)),
		cptr(nonce), C.size_t(len(nonce)), cptr(pt), C.size_t(len(pt)),
		cptr(aad), C.size_t(len(aad))) != 1 {
		panic("BoringSSL seal failed")
	}
	return out
}

func cptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}
