// Copyright 2020 The Chromium Authors
// Standalone shim: base/notreached.h

#ifndef BASE_NOTREACHED_H_
#define BASE_NOTREACHED_H_

#include "base/check.h"
#include "base/logging.h"

// NOTREACHED() marks code paths that should never be executed.
// Supports << streaming: NOTREACHED() << "unexpected value";
#define NOTREACHED(...)                                         \
  ::logging::VoidifyStream() &                                  \
      ::logging::NotReachedError(__FILE__, __LINE__).stream()

#define DUMP_WILL_BE_NOTREACHED() NOTREACHED()

#endif  // BASE_NOTREACHED_H_
