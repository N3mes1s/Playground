// Standalone shim: base/features.h
#ifndef BASE_FEATURES_H_
#define BASE_FEATURES_H_

// Feature stubs - sandbox code checks these at runtime.
// In standalone build, all features are disabled.

namespace base::features {

// Stub: these are normally extern Feature objects.
// The sandbox code checks IsEnabled(feature) -- we always return false.

}  // namespace base::features

#endif  // BASE_FEATURES_H_
