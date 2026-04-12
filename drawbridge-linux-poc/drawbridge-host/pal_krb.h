/*
 * pal_krb.h - Component C19: Kerberos (KerberosStream.cpp).
 *
 * ELF source references (analysis/sqlservr_FULL.c):
 *   KrbCredentialCacheManager.cpp
 *     - semaphore init    ~ line 116438
 *     - StoreCred paths   ~ lines 116661, 116816, 116885, 117081
 *   KerberosStream.cpp OAuth ticket flow (same section).
 *
 * The NTUM only exercises the Kerberos stream for cross-realm auth.
 * hello_world does not reach that path, so this translation unit is
 * only required to COMPILE (Wave-2 / M12 exit criterion).
 *
 * If the build host lacks the MIT krb5 development headers, the
 * implementation degrades to stubs that return "not available" for
 * every credential-cache operation. See the __has_include guard in
 * pal_krb.cpp.
 */

#ifndef PAL_KRB_H
#define PAL_KRB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tri-state return code:
 *   0  = success
 *  -1  = kerberos runtime error (code propagated to stderr)
 *  -2  = krb5 not available on this build host (header-only build)
 */

int  pal_krb_init(void);
void pal_krb_shutdown(void);

/*
 * KrbCredentialCacheManager surface. Only the signatures Wave-3 uses
 * are exposed here; the implementation is either a real MIT-krb5
 * path or a "not available" stub.
 */
int  pal_krb_cache_default(char *out, size_t cap);
int  pal_krb_cache_store_oauth_ticket(const char *principal,
                                      const uint8_t *ticket, size_t ticket_len);
int  pal_krb_cache_remove(const char *principal);

/* DK_* entry hooks for the Kerberos stream plumbing. Fail-loud for
 * hello_world. */
int32_t DK_KerberosStreamCreate(void *host, void *params, void **out_handle);
int32_t DK_KerberosStreamDestroy(void *handle);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PAL_KRB_H */
