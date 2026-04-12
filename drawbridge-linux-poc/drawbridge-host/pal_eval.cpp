/* ============================================================
 * pal_eval.cpp  -  Component C21 (Milestone M13)
 *
 * Thin-but-real implementation of the evaluation-period and
 * host-parity residue functions.  Stubbed where the decompiled
 * behavior requires MSSQL-specific on-disk artefacts that the
 * hello_world milestone does not produce.
 * ============================================================ */

#include "pal_eval.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#define PAL_EVAL_LOG(fmt, ...) \
    std::fprintf(stderr, "[PAL-EVAL] " fmt "\n", ##__VA_ARGS__)

namespace {

/* Canonical paths / env names pulled directly from the ELF
 * decompilation.  Centralising them here means the rest of the
 * PAL can reference them via pal_eval_*_path() accessors. */
constexpr const char kSecretsDir[]    = "/var/opt/mssql/secrets/";
constexpr const char kLocaltimePath[] = "/etc/localtime";
constexpr const char kTzdataEnv[]     = "TZDATA";

/* The translation unit's single EvalPeriod - wrapped in a
 * Meyer's-singleton accessor so init ordering is deterministic. */
pal::EvalPeriod& instance() {
    static pal::EvalPeriod s;
    return s;
}

std::once_flag& init_once() {
    static std::once_flag f;
    return f;
}

/* Resolve the active timezone.
 *   1.  $TZDATA wins (matches the ELF's env check)
 *   2.  /etc/localtime symlink target
 *   3.  empty string => "UTC" assumed upstream
 */
std::string ResolveTimezone() {
    if (const char* tzd = std::getenv(kTzdataEnv)) {
        PAL_EVAL_LOG("timezone from $TZDATA: %s", tzd);
        return std::string(tzd);
    }

    struct stat st {};
    if (lstat(kLocaltimePath, &st) == 0 && S_ISLNK(st.st_mode)) {
        char buf[512];
        ssize_t n = readlink(kLocaltimePath, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            /* Strip the common "/usr/share/zoneinfo/" prefix. */
            const char* prefix = "/usr/share/zoneinfo/";
            const char* p = std::strstr(buf, prefix);
            const char* tz = p ? p + std::strlen(prefix) : buf;
            PAL_EVAL_LOG("timezone from %s: %s", kLocaltimePath, tz);
            return std::string(tz);
        }
    }

    PAL_EVAL_LOG("timezone unresolved - defaulting to UTC");
    return std::string("UTC");
}

/* Stamp the install epoch.  Prefer the mtime of the secrets
 * directory when present (that's what the ELF does via
 * FUN_00353660 at line 96398); otherwise fall back to now(). */
std::chrono::system_clock::time_point ResolveInstallEpoch() {
    struct stat st {};
    if (stat(kSecretsDir, &st) == 0) {
        PAL_EVAL_LOG("install-epoch from %s mtime=%ld",
                     kSecretsDir, (long)st.st_mtime);
        return std::chrono::system_clock::from_time_t(st.st_mtime);
    }
    PAL_EVAL_LOG("install-epoch: %s not present, using now()", kSecretsDir);
    return std::chrono::system_clock::now();
}

} /* anonymous namespace */

namespace pal {

/* ---- EvalPeriod ---------------------------------------- */

void EvalPeriod::Init() {
    if (initialized_) return;
    tz_         = ResolveTimezone();
    sec_        = kSecretsDir;
    install_tp_ = ResolveInstallEpoch();
    eval_days_  = kDefaultDays;
    initialized_ = true;
    PAL_EVAL_LOG("initialized: tz=%s eval_days=%d", tz_.c_str(), eval_days_);
}

int EvalPeriod::DaysRemaining() const {
    if (!initialized_) return 0;
    const auto now      = std::chrono::system_clock::now();
    const auto elapsed  = std::chrono::duration_cast<std::chrono::hours>(
                              now - install_tp_).count() / 24;
    const long remain   = static_cast<long>(eval_days_) - elapsed;
    if (remain < 0)                     return 0;
    if (remain > INT32_MAX)             return INT32_MAX;
    return static_cast<int>(remain);
}

bool EvalPeriod::Expired() const {
    return initialized_ && DaysRemaining() == 0;
}

/* Mirrors FUN_00204bb0 timeout-watchdog semantics:
 * returns true while the eval window is still valid. */
bool EvalPeriod::WatchdogTick() {
    if (!initialized_) return true;   /* be permissive pre-init */
    const bool alive = !Expired();
    if (!alive) {
        PAL_EVAL_LOG("watchdog: evaluation period expired");
    }
    return alive;
}

} /* namespace pal */

/* ------------------------------------------------------------
 * extern "C" ABI
 * ------------------------------------------------------------ */
extern "C" {

void pal_eval_init(void) {
    std::call_once(init_once(), [] {
        instance().Init();
    });
}

int32_t pal_eval_check(void) {
    pal_eval_init();
    return instance().WatchdogTick() ? 0 : 1;
}

int32_t pal_eval_expired(void) {
    pal_eval_init();
    return instance().Expired() ? 1 : 0;
}

int32_t pal_eval_days_remaining(void) {
    pal_eval_init();
    return static_cast<int32_t>(instance().DaysRemaining());
}

const char* pal_eval_secrets_dir(void)    { return kSecretsDir;    }
const char* pal_eval_localtime_path(void) { return kLocaltimePath; }
const char* pal_eval_tzdata_env(void)     { return std::getenv(kTzdataEnv); }

} /* extern "C" */
