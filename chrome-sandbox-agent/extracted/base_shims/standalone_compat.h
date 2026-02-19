// standalone_compat.h - Force-included in every TU to provide compatibility macros.
// This replaces various Chromium build system defines that the sandbox code expects.

#ifndef STANDALONE_COMPAT_H_
#define STANDALONE_COMPAT_H_

// MSAN (Memory Sanitizer) macros - no-ops in standalone build.
#ifndef MSAN_UNPOISON
#define MSAN_UNPOISON(ptr, size)
#endif

#ifndef MSAN_CHECK_MEM_IS_INITIALIZED
#define MSAN_CHECK_MEM_IS_INITIALIZED(ptr, size)
#endif

// ASAN macros
#ifndef ASAN_UNPOISON_MEMORY_REGION
#define ASAN_UNPOISON_MEMORY_REGION(ptr, size)
#endif

// Thread-safety annotations (no-ops)
#ifndef GUARDED_BY
#define GUARDED_BY(x)
#endif

#ifndef EXCLUSIVE_LOCKS_REQUIRED
#define EXCLUSIVE_LOCKS_REQUIRED(...)
#endif

// PTHREAD_STACK_MIN_CONST for older kernels
#ifndef PTHREAD_STACK_MIN_CONST
#define PTHREAD_STACK_MIN_CONST PTHREAD_STACK_MIN
#endif

#endif  // STANDALONE_COMPAT_H_
