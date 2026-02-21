// Copyright 2022 The Chromium Authors
// Standalone shim: base/memory/raw_ptr_exclusion.h

#ifndef BASE_MEMORY_RAW_PTR_EXCLUSION_H_
#define BASE_MEMORY_RAW_PTR_EXCLUSION_H_

// In Chromium, this annotates fields that should be excluded from raw_ptr
// rewriting. In our standalone build, it's a no-op.
#define RAW_PTR_EXCLUSION

#endif  // BASE_MEMORY_RAW_PTR_EXCLUSION_H_
