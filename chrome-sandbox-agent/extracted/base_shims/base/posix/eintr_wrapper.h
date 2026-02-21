// Copyright 2012 The Chromium Authors
// Standalone shim: base/posix/eintr_wrapper.h
// HANDLE_EINTR: retries syscalls interrupted by signals.

#ifndef BASE_POSIX_EINTR_WRAPPER_H_
#define BASE_POSIX_EINTR_WRAPPER_H_

#include <cerrno>

// HANDLE_EINTR: retries expression x while it returns -1 with errno==EINTR.
// This is critical for POSIX signal safety.
#define HANDLE_EINTR(x)                                         \
  ({                                                            \
    decltype(x) eintr_wrapper_result;                           \
    do {                                                        \
      eintr_wrapper_result = (x);                               \
    } while (eintr_wrapper_result == -1 && errno == EINTR);     \
    eintr_wrapper_result;                                       \
  })

// IGNORE_EINTR: like HANDLE_EINTR but returns 0 on EINTR instead of -1.
#define IGNORE_EINTR(x)                                         \
  ({                                                            \
    decltype(x) eintr_wrapper_result;                           \
    do {                                                        \
      eintr_wrapper_result = (x);                               \
      if (eintr_wrapper_result == -1 && errno == EINTR) {       \
        eintr_wrapper_result = 0;                               \
      }                                                         \
    } while (0);                                                \
    eintr_wrapper_result;                                       \
  })

#endif  // BASE_POSIX_EINTR_WRAPPER_H_
