/*
 * test_22_keyctl.c — Linux keyring subsystem attack surface tests
 *
 * The kernel keyring (keyctl syscall) has been a recurring LPE vector:
 *  - CVE-2016-0728: use-after-free via refcount overflow in keyring
 *  - CVE-2017-6951: keyring NULL deref DoS
 *  - CVE-2022-0185: filesystem context heap overflow (legacy_parse_param)
 *
 * keyctl creates kernel objects that can be used for:
 *  - Cross-cache slab attacks (key_type_user objects)
 *  - Reference count manipulation
 *  - Information leaks via /proc/keys
 *
 * Tests:
 *  1. keyctl() syscall availability
 *  2. KEYCTL_JOIN_SESSION_KEYRING
 *  3. add_key() — create user keys
 *  4. KEYCTL_READ — read key data
 *  5. KEYCTL_SETPERM — modify key permissions
 *  6. KEYCTL_SEARCH — search keyrings
 *  7. /proc/keys readable
 *  8. request_key() availability
 */
#include "test_harness.h"

#ifndef __NR_keyctl
#define __NR_keyctl 250
#endif
#ifndef __NR_add_key
#define __NR_add_key 248
#endif
#ifndef __NR_request_key
#define __NR_request_key 249
#endif

/* keyctl commands */
#define KEYCTL_GET_KEYRING_ID       0
#define KEYCTL_JOIN_SESSION_KEYRING 1
#define KEYCTL_READ                11
#define KEYCTL_SETPERM              5
#define KEYCTL_SEARCH               10
#define KEYCTL_REVOKE                3
#define KEYCTL_DESCRIBE              6

/* Special keyring IDs */
#define KEY_SPEC_SESSION_KEYRING   -3
#define KEY_SPEC_PROCESS_KEYRING   -2
#define KEY_SPEC_THREAD_KEYRING    -1

static long keyctl_call(int cmd, unsigned long arg2, unsigned long arg3,
                        unsigned long arg4, unsigned long arg5) {
    return syscall(__NR_keyctl, cmd, arg2, arg3, arg4, arg5);
}

/* Test 1: keyctl() syscall availability */
static int try_keyctl(void) {
    g_got_sigsys = 0;
    long ret = keyctl_call(KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 0, 0, 0);
    if (g_got_sigsys) return -2;
    if (ret < 0 && errno == ENOSYS) return -1;
    if (ret >= 0) return 1; /* Keyring accessible */
    return 0;
}

/* Test 2: KEYCTL_JOIN_SESSION_KEYRING */
static int try_join_session(void) {
    g_got_sigsys = 0;
    long ret = keyctl_call(KEYCTL_JOIN_SESSION_KEYRING, (unsigned long)"test_session", 0, 0, 0);
    if (g_got_sigsys) return -2;
    if (ret >= 0) return 1; /* Joined session keyring */
    return 0;
}

/* Test 3: add_key — create user keys (cross-cache spray primitive) */
static int try_add_key(void) {
    g_got_sigsys = 0;
    long ret = syscall(__NR_add_key, "user", "test_key",
                       "test_data", 9, KEY_SPEC_PROCESS_KEYRING);
    if (g_got_sigsys) return -2;
    if (ret >= 0) return 1; /* Key created! */
    if (errno == ENOSYS) return -1;
    return 0;
}

/* Test 4: KEYCTL_READ — read key data */
static int try_keyctl_read(void) {
    g_got_sigsys = 0;
    /* First create a key */
    long key_id = syscall(__NR_add_key, "user", "read_test",
                          "secret", 6, KEY_SPEC_PROCESS_KEYRING);
    if (g_got_sigsys || key_id < 0) return 0;

    char buf[256];
    long ret = keyctl_call(KEYCTL_READ, key_id, (unsigned long)buf, sizeof(buf), 0);
    if (ret > 0) return 1; /* Can read key data */
    return 0;
}

/* Test 5: KEYCTL_SETPERM — modify key permissions */
static int try_keyctl_setperm(void) {
    g_got_sigsys = 0;
    long key_id = syscall(__NR_add_key, "user", "perm_test",
                          "data", 4, KEY_SPEC_PROCESS_KEYRING);
    if (g_got_sigsys || key_id < 0) return 0;

    /* Try to set world-readable permissions */
    long ret = keyctl_call(KEYCTL_SETPERM, key_id, 0x3f3f3f3f, 0, 0);
    return (ret == 0) ? 1 : 0;
}

/* Test 6: KEYCTL_SEARCH — search keyrings */
static int try_keyctl_search(void) {
    g_got_sigsys = 0;
    long ret = keyctl_call(KEYCTL_SEARCH, KEY_SPEC_SESSION_KEYRING,
                           (unsigned long)"user", (unsigned long)"test_key", 0);
    if (g_got_sigsys) return -2;
    if (ret >= 0) return 1; /* Search works */
    if (errno == ENOKEY || errno == EINVAL) return 1; /* Syscall reachable */
    return 0;
}

/* Test 7: /proc/keys readable */
static int try_proc_keys(void) {
    char buf[4096];
    ssize_t n = read_file("/proc/keys", buf, sizeof(buf));
    if (n > 0) return 1;
    return 0;
}

/* Test 8: request_key() availability */
static int try_request_key(void) {
    g_got_sigsys = 0;
    long ret = syscall(__NR_request_key, "user", "nonexistent", NULL,
                       KEY_SPEC_SESSION_KEYRING);
    if (g_got_sigsys) return -2;
    if (ret >= 0) return 1;
    /* ENOKEY means syscall is reachable but key doesn't exist */
    if (errno == ENOKEY) return 1;
    if (errno == ENOSYS) return -1;
    return 0;
}

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("KEYRING SUBSYSTEM (CVE-2016-0728, cross-cache spray)");

    int keyctl = try_keyctl();
    TEST("keyctl() syscall blocked",
         keyctl <= 0,
         keyctl == 1  ? "ACCESSIBLE — keyring attack surface exposed!" :
         keyctl == -2 ? "SIGSYS (seccomp)" :
         keyctl == -1 ? "ENOSYS" : "blocked");

    int join = try_join_session();
    TEST("KEYCTL_JOIN_SESSION blocked",
         join <= 0,
         join == 1  ? "JOINED — session keyring manipulation!" :
         join == -2 ? "SIGSYS" : "blocked");

    int add = try_add_key();
    TEST("add_key() blocked",
         add <= 0,
         add == 1  ? "KEY CREATED — kernel object spray possible!" :
         add == -2 ? "SIGSYS" :
         add == -1 ? "ENOSYS" : "blocked");

    int read_key = try_keyctl_read();
    TEST("KEYCTL_READ blocked",
         read_key <= 0,
         read_key == 1 ? "READ — can read key data!" : "blocked");

    int setperm = try_keyctl_setperm();
    TEST("KEYCTL_SETPERM blocked",
         setperm <= 0,
         setperm == 1 ? "SETPERM — can modify key permissions!" : "blocked");

    int search = try_keyctl_search();
    TEST("KEYCTL_SEARCH blocked",
         search <= 0,
         search == 1  ? "SEARCH — keyring enumeration!" :
         search == -2 ? "SIGSYS" : "blocked");

    int proc_keys = try_proc_keys();
    TEST("/proc/keys not readable",
         proc_keys == 0,
         proc_keys ? "readable — key info leak!" : "blocked");

    int req_key = try_request_key();
    TEST("request_key() blocked",
         req_key <= 0,
         req_key == 1  ? "REACHABLE — key request attack surface!" :
         req_key == -2 ? "SIGSYS" :
         req_key == -1 ? "ENOSYS" : "blocked");

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
