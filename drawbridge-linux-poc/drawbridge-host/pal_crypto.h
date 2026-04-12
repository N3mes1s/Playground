/*
 * pal_crypto.h - Component C18: Crypto streams (OpenSSL-backed).
 *
 * ELF source references (analysis/sqlservr_FULL.c):
 *   ProtectDataStream.cpp  ~ lines 139600-139750 (OpenSSL error paths)
 *   CryptCommonStream.cpp  ~ shared EVP helpers invoked by the above
 *
 * Surface:
 *   - C++ RAII wrappers for EVP_CIPHER_CTX / EVP_MD_CTX that the
 *     Drawbridge "protect data" stream path depends on.
 *   - extern "C" DK_* hooks the NTUM uses for encrypted-stream I/O.
 *
 * All entries in this translation unit are no-ops sufficient for the
 * hello_world boot path -- they must only *compile* so that Wave-2
 * (M12) can close. As real ProtectDataStream traffic materialises,
 * flesh out pal_crypto_stream_encrypt/decrypt using the EVP helpers
 * already set up here.
 */

#ifndef PAL_CRYPTO_H
#define PAL_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialise the crypto subsystem: seeds OpenSSL, installs error
 * strings, and registers a global algorithm table. Idempotent.
 * Returns 0 on success, negative on failure.
 */
int  pal_crypto_init(void);

/*
 * Optional teardown for symmetry; OpenSSL >= 1.1 does not require it,
 * but we keep the entry so that DK_* shutdown paths can call through.
 */
void pal_crypto_shutdown(void);

/*
 * One-shot AES-256-CBC encrypt/decrypt used by ProtectDataStream.
 * Buffers must be sized to hold padding (in_len + 16). Returns the
 * number of bytes written on success, negative pal_result status
 * on failure.
 */
int32_t pal_crypto_aes256_cbc_encrypt(const uint8_t *key,
                                      const uint8_t *iv,
                                      const uint8_t *in,  size_t in_len,
                                      uint8_t       *out, size_t out_cap);

int32_t pal_crypto_aes256_cbc_decrypt(const uint8_t *key,
                                      const uint8_t *iv,
                                      const uint8_t *in,  size_t in_len,
                                      uint8_t       *out, size_t out_cap);

/*
 * SHA-256 hash used by CryptCommonStream.
 * out must point to at least 32 bytes.
 */
int32_t pal_crypto_sha256(const uint8_t *in, size_t in_len, uint8_t out[32]);

/*
 * DK_* entry hooks. These mirror the NTUM's expectation that a
 * crypto stream can be opened like any other pal_stream_handle and
 * that it routes through the same pread/pwrite dispatch. For the
 * hello_world boot path they intentionally fail-loud via
 * PAL_UNIMPLEMENTED; real wiring lands after Wave-2 is complete.
 */
int32_t DK_CryptStreamCreate(void *host, void *params, void **out_handle);
int32_t DK_CryptStreamDestroy(void *handle);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PAL_CRYPTO_H */
