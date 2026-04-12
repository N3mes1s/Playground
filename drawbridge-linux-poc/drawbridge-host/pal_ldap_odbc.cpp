/* ============================================================
 * pal_ldap_odbc.cpp  -  Component C20 (Milestone M12)
 *
 * Default stub implementation.  When / if libldap and unixODBC
 * become available in the build environment, build with
 * -DPAL_LDAP_ODBC_REAL and link -lldap -lodbc; the current file
 * is structured so the real bodies can drop straight in.
 * ============================================================ */

#include "pal_ldap_odbc.h"

#include <cstdio>
#include <cstring>

/* Single, consistent log prefix so grep-through-logs works. */
#define PAL_LO_LOG(tag, fmt, ...) \
    std::fprintf(stderr, "[PAL-%s] " fmt "\n", tag, ##__VA_ARGS__)

namespace pal {

/* ---------------- PalLdapStream ---------------- */

PalLdapStream::PalLdapStream() = default;

PalLdapStream::~PalLdapStream() {
    if (connected_) {
        (void)Disconnect();
    }
}

StreamStatus PalLdapStream::Connect(const std::string& uri) {
    uri_ = uri;
#ifdef PAL_LDAP_ODBC_REAL
    /* real path: ldap_initialize(&ld, uri.c_str()); ... */
    PAL_LO_LOG("LDAP", "Connect(%s) - real path not yet wired", uri.c_str());
    return StreamStatus::NotAvailable;
#else
    PAL_LO_LOG("LDAP", "Connect(%s) - stub build, returning NotAvailable",
               uri.c_str());
    return StreamStatus::NotAvailable;
#endif
}

StreamStatus PalLdapStream::Bind(const std::string& bind_dn,
                                 const std::string& /*credential*/,
                                 const std::string& mech) {
    PAL_LO_LOG("LDAP", "Bind(dn=%s, mech=%s) - stub, returning NotAvailable",
               bind_dn.c_str(),
               mech.empty() ? "<simple>" : mech.c_str());
    return StreamStatus::NotAvailable;
}

StreamStatus PalLdapStream::Search(const std::string& base_dn,
                                   const std::string& filter,
                                   int                scope) {
    PAL_LO_LOG("LDAP", "Search(base=%s, filter=%s, scope=%d) - stub",
               base_dn.c_str(), filter.c_str(), scope);
    return StreamStatus::NotAvailable;
}

StreamStatus PalLdapStream::Disconnect() {
    if (!connected_ && handle_ == nullptr) {
        return StreamStatus::Ok;
    }
    PAL_LO_LOG("LDAP", "Disconnect()");
    handle_    = nullptr;
    connected_ = false;
    return StreamStatus::Ok;
}

/* ---------------- PalOdbcStream ---------------- */

PalOdbcStream::PalOdbcStream() = default;

PalOdbcStream::~PalOdbcStream() {
    if (connected_) {
        (void)Disconnect();
    }
}

StreamStatus PalOdbcStream::Connect(const std::string& conn_str) {
#ifdef PAL_LDAP_ODBC_REAL
    PAL_LO_LOG("ODBC", "Connect(%s) - real path not yet wired",
               conn_str.c_str());
    return StreamStatus::NotAvailable;
#else
    PAL_LO_LOG("ODBC", "Connect(%s) - stub build, returning NotAvailable",
               conn_str.c_str());
    return StreamStatus::NotAvailable;
#endif
}

StreamStatus PalOdbcStream::Execute(const std::string& sql) {
    PAL_LO_LOG("ODBC", "Execute(%.64s%s) - stub",
               sql.c_str(), sql.size() > 64 ? "..." : "");
    return StreamStatus::NotAvailable;
}

StreamStatus PalOdbcStream::Disconnect() {
    if (!connected_ && dbc_ == nullptr) {
        return StreamStatus::Ok;
    }
    PAL_LO_LOG("ODBC", "Disconnect()");
    stmt_      = nullptr;
    dbc_       = nullptr;
    env_       = nullptr;
    connected_ = false;
    return StreamStatus::Ok;
}

} /* namespace pal */

/* ------------------------------------------------------------
 * extern "C" shims.  Deliberately thin - they just construct a
 * heap object for the opaque handle and route through the C++
 * API.  All stub-mode errors are logged by the C++ layer.
 * ------------------------------------------------------------ */
extern "C" {

void pal_ldap_odbc_init(void) {
    PAL_LO_LOG("LDAP-ODBC", "init (stub build)");
}

void pal_ldap_odbc_shutdown(void) {
    PAL_LO_LOG("LDAP-ODBC", "shutdown");
}

void* pal_ldap_open(const char* uri) {
    if (uri == nullptr) {
        PAL_LO_LOG("LDAP", "pal_ldap_open(NULL)");
        return nullptr;
    }
    auto* s = new pal::PalLdapStream();
    if (s->Connect(uri) != pal::StreamStatus::Ok) {
        /* Stub build always hits this path.  Keep the object so
         * the caller can at least observe IsConnected()==false. */
    }
    return static_cast<void*>(s);
}

int32_t pal_ldap_bind(void* h, const char* dn, const char* cred) {
    if (h == nullptr) return static_cast<int32_t>(pal::StreamStatus::InvalidArg);
    auto* s = static_cast<pal::PalLdapStream*>(h);
    return static_cast<int32_t>(
        s->Bind(dn ? dn : "", cred ? cred : ""));
}

int32_t pal_ldap_search(void* h, const char* base, const char* filter) {
    if (h == nullptr) return static_cast<int32_t>(pal::StreamStatus::InvalidArg);
    auto* s = static_cast<pal::PalLdapStream*>(h);
    return static_cast<int32_t>(
        s->Search(base ? base : "", filter ? filter : "", 0));
}

void pal_ldap_close(void* h) {
    if (h == nullptr) return;
    auto* s = static_cast<pal::PalLdapStream*>(h);
    (void)s->Disconnect();
    delete s;
}

void* pal_odbc_open(const char* conn_str) {
    if (conn_str == nullptr) {
        PAL_LO_LOG("ODBC", "pal_odbc_open(NULL)");
        return nullptr;
    }
    auto* s = new pal::PalOdbcStream();
    (void)s->Connect(conn_str);
    return static_cast<void*>(s);
}

int32_t pal_odbc_exec(void* h, const char* sql) {
    if (h == nullptr) return static_cast<int32_t>(pal::StreamStatus::InvalidArg);
    auto* s = static_cast<pal::PalOdbcStream*>(h);
    return static_cast<int32_t>(s->Execute(sql ? sql : ""));
}

void pal_odbc_close(void* h) {
    if (h == nullptr) return;
    auto* s = static_cast<pal::PalOdbcStream*>(h);
    (void)s->Disconnect();
    delete s;
}

} /* extern "C" */
