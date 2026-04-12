/*
 * pal_crypto.cpp - Component C18: Crypto streams (OpenSSL).
 *
 * Translates the OpenSSL surface used by ProtectDataStream.cpp and
 * CryptCommonStream.cpp (see analysis/sqlservr_FULL.c around lines
 * 139600-139750 for the ProtectDataStream error sites that reference
 * AES_set_encrypt_key / EVP_* and "OpenSSL, %s" diagnostics).
 *
 * This unit:
 *   - provides RAII wrappers around EVP_CIPHER_CTX / EVP_MD_CTX,
 *   - exposes thin C helpers that do the one-shot AES-256-CBC and
 *     SHA-256 operations the NTUM's stream path relies on,
 *   - registers DK_CryptStream* entries that are no-op compatible
 *     with the hello_world boot path.
 *
 * The goal for M12 is COMPILE + LINK, not functional crypto traffic
 * -- Drawbridge's hello_world does not exercise any protected
 * stream. Real traffic wires in during the Wave-3 data-path pass.
 */

#include "pal_crypto.h"

#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* -----------------------------------------------------------------
 * RAII helpers (C++ class scope).
 * ----------------------------------------------------------------- */
namespace pal_crypto {

class CipherCtx {
public:
    CipherCtx() : ctx_(EVP_CIPHER_CTX_new()) {}
    ~CipherCtx() { if (ctx_) EVP_CIPHER_CTX_free(ctx_); }

    CipherCtx(const CipherCtx &) = delete;
    CipherCtx &operator=(const CipherCtx &) = delete;

    EVP_CIPHER_CTX *get() const { return ctx_; }
    explicit operator bool() const { return ctx_ != nullptr; }

private:
    EVP_CIPHER_CTX *ctx_;
};

class DigestCtx {
public:
    DigestCtx() : ctx_(EVP_MD_CTX_new()) {}
    ~DigestCtx() { if (ctx_) EVP_MD_CTX_free(ctx_); }

    DigestCtx(const DigestCtx &) = delete;
    DigestCtx &operator=(const DigestCtx &) = delete;

    EVP_MD_CTX *get() const { return ctx_; }
    explicit operator bool() const { return ctx_ != nullptr; }

private:
    EVP_MD_CTX *ctx_;
};

static std::atomic<int> g_init_state{0};   /* 0 = never, 1 = done */

static void log_openssl_error(const char *who)
{
    char buf[256];
    unsigned long e = ERR_get_error();
    if (e == 0) {
        std::fprintf(stderr, "[pal_crypto] %s: (no OpenSSL error)\n",
                     who ? who : "?");
        return;
    }
    ERR_error_string_n(e, buf, sizeof(buf));
    std::fprintf(stderr, "[pal_crypto] %s: OpenSSL, %s\n",
                 who ? who : "?", buf);
}

} /* namespace pal_crypto */

/* -----------------------------------------------------------------
 * C API (extern "C"): touches DK_* and pal_* entry points.
 * ----------------------------------------------------------------- */
extern "C" {

int pal_crypto_init(void)
{
    int expected = 0;
    if (!pal_crypto::g_init_state.compare_exchange_strong(expected, 1)) {
        return 0;   /* already initialised */
    }

    /* OpenSSL 1.1+ auto-initialises; we just seed the PRNG. */
    unsigned char seed[32];
    /* RAND_poll() is a no-op under OpenSSL 3.x's internal provider,
     * but keeps older builds happy. */
    if (RAND_poll() != 1) {
        pal_crypto::log_openssl_error("RAND_poll");
        /* fall through -- RAND_bytes will still succeed on Linux */
    }
    if (RAND_bytes(seed, sizeof(seed)) != 1) {
        pal_crypto::log_openssl_error("RAND_bytes");
        pal_crypto::g_init_state.store(0);
        return -1;
    }
    return 0;
}

void pal_crypto_shutdown(void)
{
    /* OpenSSL 1.1+ cleans up atexit; nothing required here. */
    pal_crypto::g_init_state.store(0);
}

int32_t pal_crypto_aes256_cbc_encrypt(const uint8_t *key,
                                      const uint8_t *iv,
                                      const uint8_t *in,  size_t in_len,
                                      uint8_t       *out, size_t out_cap)
{
    if (!key || !iv || !in || !out) return -1;
    if (out_cap < in_len + 16)      return -1;

    pal_crypto::CipherCtx ctx;
    if (!ctx) { pal_crypto::log_openssl_error("EVP_CIPHER_CTX_new"); return -1; }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                           key, iv) != 1) {
        pal_crypto::log_openssl_error("EVP_EncryptInit_ex");
        return -1;
    }

    int out_len_1 = 0;
    if (EVP_EncryptUpdate(ctx.get(), out, &out_len_1, in,
                          static_cast<int>(in_len)) != 1) {
        pal_crypto::log_openssl_error("EVP_EncryptUpdate");
        return -1;
    }
    int out_len_2 = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), out + out_len_1, &out_len_2) != 1) {
        pal_crypto::log_openssl_error("EVP_EncryptFinal_ex");
        return -1;
    }
    return static_cast<int32_t>(out_len_1 + out_len_2);
}

int32_t pal_crypto_aes256_cbc_decrypt(const uint8_t *key,
                                      const uint8_t *iv,
                                      const uint8_t *in,  size_t in_len,
                                      uint8_t       *out, size_t out_cap)
{
    if (!key || !iv || !in || !out) return -1;
    if (out_cap < in_len)           return -1;

    pal_crypto::CipherCtx ctx;
    if (!ctx) { pal_crypto::log_openssl_error("EVP_CIPHER_CTX_new"); return -1; }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                           key, iv) != 1) {
        pal_crypto::log_openssl_error("EVP_DecryptInit_ex");
        return -1;
    }
    int out_len_1 = 0;
    if (EVP_DecryptUpdate(ctx.get(), out, &out_len_1, in,
                          static_cast<int>(in_len)) != 1) {
        pal_crypto::log_openssl_error("EVP_DecryptUpdate");
        return -1;
    }
    int out_len_2 = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), out + out_len_1, &out_len_2) != 1) {
        pal_crypto::log_openssl_error("EVP_DecryptFinal_ex");
        return -1;
    }
    return static_cast<int32_t>(out_len_1 + out_len_2);
}

int32_t pal_crypto_sha256(const uint8_t *in, size_t in_len, uint8_t out[32])
{
    if (!in || !out) return -1;

    pal_crypto::DigestCtx md;
    if (!md) { pal_crypto::log_openssl_error("EVP_MD_CTX_new"); return -1; }

    if (EVP_DigestInit_ex(md.get(), EVP_sha256(), nullptr) != 1) {
        pal_crypto::log_openssl_error("EVP_DigestInit_ex");
        return -1;
    }
    if (EVP_DigestUpdate(md.get(), in, in_len) != 1) {
        pal_crypto::log_openssl_error("EVP_DigestUpdate");
        return -1;
    }
    unsigned int len = 32;
    if (EVP_DigestFinal_ex(md.get(), out, &len) != 1) {
        pal_crypto::log_openssl_error("EVP_DigestFinal_ex");
        return -1;
    }
    return static_cast<int32_t>(len);
}

/*
 * DK_CryptStream* - not exercised by hello_world. These return a
 * sentinel failure so that any accidental caller is caught early
 * without aborting the boot sequence (which is the stricter behavior
 * that pal_stubs.cpp uses for truly unmapped entries).
 */
int32_t DK_CryptStreamCreate(void * /*host*/, void * /*params*/,
                             void **out_handle)
{
    if (out_handle) *out_handle = nullptr;
    std::fprintf(stderr,
                 "[pal_crypto] DK_CryptStreamCreate: crypto stream not "
                 "wired (hello_world path does not exercise this)\n");
    return -1;
}

int32_t DK_CryptStreamDestroy(void * /*handle*/)
{
    return 0;
}

} /* extern "C" */
