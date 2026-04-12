/* ============================================================
 * pal_ldap_odbc.h  -  Component C20 (Milestone M12)
 *
 * LDAP / ODBC stream wrapper skeletons for the Drawbridge host.
 *
 * Mirrors the LDAP/ODBC surface observed in the decompiled
 * sqlservr ELF (analysis/sqlservr_FULL.c):
 *
 *   - LdapConnection.cpp   (see references ~line 105272..108563)
 *     LDAP bind / query / keytab code paths.
 *   - ODBC surface          (no direct string refs in ELF dump,
 *     scaffolded here so M12 hello_world closes cleanly).
 *
 * Rationale: real libldap / unixODBC linkage is out-of-scope
 * for the M12 hello_world milestone.  When PAL_LDAP_ODBC_REAL
 * is not defined (the default), every call logs a single line
 * and returns a "not available" status.  This matches the
 * CLAUDE.md "fail fast and log it clearly" rule while still
 * giving the rest of the host a stable C++ API to link against.
 *
 * Idiomatic C++ surface internally; extern "C" shims are
 * provided at the bottom for any pal_* / DK_* cross-language
 * callers.
 * ============================================================ */

#ifndef PAL_LDAP_ODBC_H
#define PAL_LDAP_ODBC_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace pal {

/* Status codes returned by the stream wrappers.  Deliberately
 * small; the NTUM's HRESULT-style error objects are produced
 * one level up (see FUN_0028e0d0 pattern in CLAUDE.md). */
enum class StreamStatus : int32_t {
    Ok             = 0,
    NotAvailable   = -1,   /* stub build, or lib missing at runtime */
    NotConnected   = -2,
    InvalidArg     = -3,
    IoError        = -4,
    AuthFailed     = -5,
};

/* ------------------------------------------------------------
 * PalLdapStream
 *
 * Thin wrapper around ldap_init / ldap_sasl_bind_s / ldap_search_ext_s.
 * In stub mode every method logs once and returns NotAvailable.
 * ------------------------------------------------------------ */
class PalLdapStream {
public:
    PalLdapStream();
    ~PalLdapStream();

    /* Non-copyable; optionally movable. */
    PalLdapStream(const PalLdapStream&)            = delete;
    PalLdapStream& operator=(const PalLdapStream&) = delete;

    /* uri e.g. "ldaps://dc.example.com:636" */
    StreamStatus Connect(const std::string& uri);

    /* SASL / simple bind.  empty mech => simple bind. */
    StreamStatus Bind(const std::string& bind_dn,
                      const std::string& credential,
                      const std::string& mech = std::string());

    /* Single-level search; results are discarded in stub mode. */
    StreamStatus Search(const std::string& base_dn,
                        const std::string& filter,
                        int                scope);

    StreamStatus Disconnect();

    bool IsConnected() const noexcept { return connected_; }

private:
    void* handle_     = nullptr;  /* opaque LDAP* when real */
    bool  connected_  = false;
    std::string uri_;
};

/* ------------------------------------------------------------
 * PalOdbcStream
 *
 * Thin wrapper around SQLAllocHandle / SQLDriverConnect /
 * SQLExecDirect.  Stubbed identically to PalLdapStream.
 * ------------------------------------------------------------ */
class PalOdbcStream {
public:
    PalOdbcStream();
    ~PalOdbcStream();

    PalOdbcStream(const PalOdbcStream&)            = delete;
    PalOdbcStream& operator=(const PalOdbcStream&) = delete;

    /* connection string in unixODBC form */
    StreamStatus Connect(const std::string& conn_str);
    StreamStatus Execute(const std::string& sql);
    StreamStatus Disconnect();

    bool IsConnected() const noexcept { return connected_; }

private:
    void* env_  = nullptr;
    void* dbc_  = nullptr;
    void* stmt_ = nullptr;
    bool  connected_ = false;
};

} /* namespace pal */

/* ------------------------------------------------------------
 * extern "C" cross-language shims.  DK_* / pal_* symbols must
 * be callable from the decompiled-C side of the host.
 * ------------------------------------------------------------ */
#ifdef __cplusplus
extern "C" {
#endif

/* Lifecycle used by pal_boot.cpp. */
void pal_ldap_odbc_init(void);
void pal_ldap_odbc_shutdown(void);

/* Opaque-handle C shims.  Return NULL on failure. */
void*   pal_ldap_open(const char* uri);
int32_t pal_ldap_bind(void* h, const char* dn, const char* cred);
int32_t pal_ldap_search(void* h, const char* base, const char* filter);
void    pal_ldap_close(void* h);

void*   pal_odbc_open(const char* conn_str);
int32_t pal_odbc_exec(void* h, const char* sql);
void    pal_odbc_close(void* h);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PAL_LDAP_ODBC_H */
