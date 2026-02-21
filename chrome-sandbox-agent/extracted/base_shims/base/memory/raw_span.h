// Standalone shim: base/memory/raw_span.h
#ifndef BASE_MEMORY_RAW_SPAN_H_
#define BASE_MEMORY_RAW_SPAN_H_

#include "base/containers/span.h"
#include "base/memory/raw_ptr.h"

namespace base {

template <typename T, RawPtrTraits Traits = RawPtrTraits::kEmpty>
using raw_span = span<T>;

}  // namespace base

#endif  // BASE_MEMORY_RAW_SPAN_H_
