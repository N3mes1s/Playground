// Copyright 2021 The Chromium Authors
// Standalone shim: base/memory/page_size.h

#ifndef BASE_MEMORY_PAGE_SIZE_H_
#define BASE_MEMORY_PAGE_SIZE_H_

#include <unistd.h>

namespace base {

inline size_t GetPageSize() {
  static const size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  return page_size;
}

}  // namespace base

#endif  // BASE_MEMORY_PAGE_SIZE_H_
