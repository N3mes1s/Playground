/*
 * pal_krb.cpp - Component C19: Kerberos / KerberosStream.
 *
 * Translation target: KerberosStream.cpp / KrbCredentialCacheManager
 * in the decompiled sqlservr (analysis/sqlservr_FULL.c around lines
 * 116400-117100). For Wave-2 (M12) we only need to COMPILE+LINK and
 * expose the pal_krb_* / DK_Kerberos* surface; real credential flows
 * land in Wave-3 once hello_world is green.
 *
 * Degradation path: if the build host has no MIT krb5 development
 * headers (<krb5.h>), we compile the "not available" stub path. The
 * stub mirrors the pal_stubs.cpp PAL_UNIMPLEMENTED convention but
 * returns -2 rather than abort()ing, since Kerberos absence is a
 * supported configuration (per the plan).
 *
 * Idiomatic C++ wrapper: KrbCredentialCacheManager owns its context
 * via RAII; a mutex guards cache mutation, matching the ELF
 * decompile's "Failed to initialize semaphore for
 * KrbCredentialCacheManager" diagnostic.
 */

#include "pal_krb.h"

#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

/* --------------------------------------------------------------
 * Header availability guard.
 *
 * __has_include is a standard C++17 feature (and a GCC extension
 * before that). We use it to pick between the real libkrb5 path
 * and the "not available" stub path at compile time.
 * -------------------------------------------------------------- */
#if defined(__has_include)
#  if __has_include(<krb5.h>)
#    define PAL_KRB_HAVE_KRB5 1
#    include <krb5.h>
#  elif __has_include(<krb5/krb5.h>)
#    define PAL_KRB_HAVE_KRB5 1
#    include <krb5/krb5.h>
#  else
#    define PAL_KRB_HAVE_KRB5 0
#  endif
#else
#  define PAL_KRB_HAVE_KRB5 0
#endif

/* pal_stubs.cpp provides PAL_UNIMPLEMENTED via a function that
 * abort()s. For the degradation path we want a *soft* not-available
 * return rather than abort, so we declare a local equivalent that
 * only logs. */
static void pal_krb_log_unavailable(const char *who)
{
    std::fprintf(stderr,
                 "[pal_krb] %s: MIT krb5 not available on this build host; "
                 "returning PAL_KRB_NOT_AVAILABLE\n",
                 who ? who : "?");
}

/* ==============================================================
 * Real MIT-krb5 path (PAL_KRB_HAVE_KRB5 == 1)
 * ============================================================== */
#if PAL_KRB_HAVE_KRB5

namespace pal_krb {

class CredentialCacheManager {
public:
    CredentialCacheManager() : ctx_(nullptr), initialised_(false) {}

    ~CredentialCacheManager()
    {
        if (ctx_) {
            krb5_free_context(ctx_);
            ctx_ = nullptr;
        }
    }

    CredentialCacheManager(const CredentialCacheManager &) = delete;
    CredentialCacheManager &operator=(const CredentialCacheManager &) = delete;

    int init()
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (initialised_) return 0;
        krb5_error_code kerr = krb5_init_context(&ctx_);
        if (kerr != 0) {
            std::fprintf(stderr,
                         "[pal_krb] krb5_init_context failed: %d\n",
                         static_cast<int>(kerr));
            return -1;
        }
        initialised_ = true;
        return 0;
    }

    int default_name(char *out, size_t cap)
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!initialised_) return -1;
        krb5_ccache cc = nullptr;
        krb5_error_code kerr = krb5_cc_default(ctx_, &cc);
        if (kerr != 0) return -1;
        const char *name = krb5_cc_get_name(ctx_, cc);
        int rc = 0;
        if (!name || std::strlen(name) + 1 > cap) {
            rc = -1;
        } else {
            std::strncpy(out, name, cap - 1);
            out[cap - 1] = '\0';
        }
        krb5_cc_close(ctx_, cc);
        return rc;
    }

    /*
     * The real OAuth-ticket store path lands in Wave-3. For M12 we
     * just validate context state so the link is clean.
     */
    int store_oauth_ticket(const char * /*principal*/,
                           const uint8_t * /*ticket*/,
                           size_t /*ticket_len*/)
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!initialised_) return -1;
        std::fprintf(stderr,
                     "[pal_krb] store_oauth_ticket: Wave-3 stub (M12 link-only)\n");
        return 0;
    }

    int remove_principal(const char * /*principal*/)
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!initialised_) return -1;
        return 0;
    }

private:
    krb5_context ctx_;
    bool         initialised_;
    std::mutex   mu_;
};

static CredentialCacheManager g_mgr;

} /* namespace pal_krb */

extern "C" {

int  pal_krb_init(void)     { return pal_krb::g_mgr.init(); }
void pal_krb_shutdown(void) { /* destructor runs at exit */ }

int pal_krb_cache_default(char *out, size_t cap)
{
    if (!out || cap == 0) return -1;
    return pal_krb::g_mgr.default_name(out, cap);
}

int pal_krb_cache_store_oauth_ticket(const char *principal,
                                     const uint8_t *ticket, size_t ticket_len)
{
    if (!principal || !ticket) return -1;
    return pal_krb::g_mgr.store_oauth_ticket(principal, ticket, ticket_len);
}

int pal_krb_cache_remove(const char *principal)
{
    if (!principal) return -1;
    return pal_krb::g_mgr.remove_principal(principal);
}

} /* extern "C" */

/* ==============================================================
 * Degradation path (no <krb5.h> on the build host).
 * ============================================================== */
#else /* !PAL_KRB_HAVE_KRB5 */

extern "C" {

int  pal_krb_init(void)
{
    pal_krb_log_unavailable("pal_krb_init");
    return -2;
}

void pal_krb_shutdown(void) { /* nothing to tear down */ }

int  pal_krb_cache_default(char * /*out*/, size_t /*cap*/)
{
    pal_krb_log_unavailable("pal_krb_cache_default");
    return -2;
}

int  pal_krb_cache_store_oauth_ticket(const char * /*principal*/,
                                      const uint8_t * /*ticket*/,
                                      size_t /*ticket_len*/)
{
    pal_krb_log_unavailable("pal_krb_cache_store_oauth_ticket");
    return -2;
}

int  pal_krb_cache_remove(const char * /*principal*/)
{
    pal_krb_log_unavailable("pal_krb_cache_remove");
    return -2;
}

} /* extern "C" */

#endif /* PAL_KRB_HAVE_KRB5 */

/* ==============================================================
 * DK_* entry hooks (always present regardless of krb5 availability).
 * ============================================================== */
extern "C" {

int32_t DK_KerberosStreamCreate(void * /*host*/, void * /*params*/,
                                void **out_handle)
{
    if (out_handle) *out_handle = nullptr;
    std::fprintf(stderr,
                 "[pal_krb] DK_KerberosStreamCreate: not wired "
                 "(hello_world does not exercise Kerberos)\n");
    return -1;
}

int32_t DK_KerberosStreamDestroy(void * /*handle*/)
{
    return 0;
}

} /* extern "C" */
