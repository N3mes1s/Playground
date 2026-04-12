/* ============================================================
 * pal_eval.h  -  Component C21 (Milestone M13)
 *
 * Evaluation-period / watchdog / host-parity residue.
 *
 * Reimplements the cluster of helpers seen in the decompiled
 * sqlservr ELF (analysis/sqlservr_FULL.c):
 *
 *   - FUN_00204bb0 : logger-thread timeout / watchdog
 *   - FUN_0029a120 : evaluation-period gate
 *   - FUN_001ae6e0 : evaluation-days calculation
 *   - timezone map + config-file path resolvers
 *       * "/etc/localtime"          (~line 85503,85545)
 *       * "/var/opt/mssql/secrets/" (~line 96398 FUN_00353660)
 *       * TZDATA override
 *
 * Public C ABI (extern "C"):
 *   pal_eval_init(), pal_eval_check(), pal_eval_expired()
 * ============================================================ */

#ifndef PAL_EVAL_H
#define PAL_EVAL_H

#include <cstdint>

#ifdef __cplusplus
#include <chrono>
#include <string>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* The three public symbols the rest of the host links against. */

/* Initialize evaluation-period state.  Reads TZDATA env var,
 * resolves /etc/localtime, and stamps the install-epoch from
 * /var/opt/mssql/secrets/ (when present) or from the current
 * wallclock (stub fallback).  Safe to call multiple times;
 * only the first call has effect. */
void pal_eval_init(void);

/* Periodic watchdog tick - called from the logger thread.
 * Returns 0 while the evaluation period is valid, non-zero
 * when the caller should begin shutdown.  Mirrors the
 * timeout path in FUN_00204bb0. */
int32_t pal_eval_check(void);

/* One-shot query: 1 => evaluation expired, 0 => still valid.
 * Mirrors FUN_0029a120. */
int32_t pal_eval_expired(void);

/* Days remaining (clamped to [0, INT32_MAX]). Mirrors
 * FUN_001ae6e0. Returns 0 if pal_eval_init() has not run. */
int32_t pal_eval_days_remaining(void);

/* Path resolvers - exposed so other PAL components can share
 * the canonical locations without duplicating string literals. */
const char* pal_eval_secrets_dir(void);   /* "/var/opt/mssql/secrets/" */
const char* pal_eval_localtime_path(void);/* "/etc/localtime"          */
const char* pal_eval_tzdata_env(void);    /* value of $TZDATA or NULL  */

#ifdef __cplusplus
} /* extern "C" */
#endif

/* ------------------------------------------------------------
 * C++-only internal surface.  Kept in the header so the unit
 * tests (when they exist) can exercise the state machine
 * directly.  Not part of the stable ABI.
 * ------------------------------------------------------------ */
#ifdef __cplusplus
namespace pal {

class EvalPeriod {
public:
    /* Total length of the evaluation window.  Matches the
     * decompiled constant (180 days for the standard eval). */
    static constexpr int kDefaultDays = 180;

    EvalPeriod() = default;

    void Init();
    bool Expired() const;
    int  DaysRemaining() const;
    bool WatchdogTick();   /* returns true while valid */

    const std::string& Timezone()    const { return tz_;    }
    const std::string& SecretsDir()  const { return sec_;   }

private:
    bool                                           initialized_ = false;
    std::chrono::system_clock::time_point          install_tp_{};
    int                                            eval_days_    = kDefaultDays;
    std::string                                    tz_;
    std::string                                    sec_;
};

} /* namespace pal */
#endif /* __cplusplus */

#endif /* PAL_EVAL_H */
