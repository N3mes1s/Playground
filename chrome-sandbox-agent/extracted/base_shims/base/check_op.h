// Copyright 2020 The Chromium Authors
// Standalone shim: base/check_op.h
// Provides CHECK_EQ/NE/LE/LT/GE/GT and DCHECK variants.

#ifndef BASE_CHECK_OP_H_
#define BASE_CHECK_OP_H_

#include "base/check.h"

// Comparison CHECK macros - these support << streaming.
// E.g.: CHECK_EQ(a, b) << "values differ";

#define CHECK_OP(name, op, val1, val2)                          \
  ((val1) op (val2)) ? (void)0                                  \
                     : ::logging::VoidifyStream() &             \
                           ::logging::CheckError(               \
                               __FILE__, __LINE__,              \
                               #val1 " " #op " " #val2)        \
                               .stream()

#define CHECK_EQ(val1, val2, ...) CHECK_OP(_EQ, ==, val1, val2)
#define CHECK_NE(val1, val2, ...) CHECK_OP(_NE, !=, val1, val2)
#define CHECK_LE(val1, val2, ...) CHECK_OP(_LE, <=, val1, val2)
#define CHECK_LT(val1, val2, ...) CHECK_OP(_LT, <, val1, val2)
#define CHECK_GE(val1, val2, ...) CHECK_OP(_GE, >=, val1, val2)
#define CHECK_GT(val1, val2, ...) CHECK_OP(_GT, >, val1, val2)

#define DCHECK_EQ(val1, val2) CHECK_EQ(val1, val2)
#define DCHECK_NE(val1, val2) CHECK_NE(val1, val2)
#define DCHECK_LE(val1, val2) CHECK_LE(val1, val2)
#define DCHECK_LT(val1, val2) CHECK_LT(val1, val2)
#define DCHECK_GE(val1, val2) CHECK_GE(val1, val2)
#define DCHECK_GT(val1, val2) CHECK_GT(val1, val2)

#define DUMP_WILL_BE_CHECK_EQ(val1, val2) CHECK_EQ(val1, val2)
#define DUMP_WILL_BE_CHECK_NE(val1, val2) CHECK_NE(val1, val2)
#define DUMP_WILL_BE_CHECK_LE(val1, val2) CHECK_LE(val1, val2)
#define DUMP_WILL_BE_CHECK_LT(val1, val2) CHECK_LT(val1, val2)
#define DUMP_WILL_BE_CHECK_GE(val1, val2) CHECK_GE(val1, val2)
#define DUMP_WILL_BE_CHECK_GT(val1, val2) CHECK_GT(val1, val2)

#endif  // BASE_CHECK_OP_H_
