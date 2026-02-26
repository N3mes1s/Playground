// Standalone shim: base/feature_list.h
#ifndef BASE_FEATURE_LIST_H_
#define BASE_FEATURE_LIST_H_

#include <string>

namespace base {

enum FeatureState {
  FEATURE_DISABLED_BY_DEFAULT,
  FEATURE_ENABLED_BY_DEFAULT,
};

struct Feature {
  const char* name;
  FeatureState default_state;
};

class FeatureList {
 public:
  static bool IsEnabled(const Feature& feature) {
    return feature.default_state == FEATURE_ENABLED_BY_DEFAULT;
  }
};

// BASE_FEATURE macro for declaring features
#define BASE_FEATURE(feature_name, name_str, default_state_val) \
  constexpr ::base::Feature feature_name { name_str, default_state_val }

// Declare features used by sandbox code
BASE_FEATURE(kPartitionAllocEnable, "PartitionAlloc",
             FEATURE_DISABLED_BY_DEFAULT);

}  // namespace base

#endif  // BASE_FEATURE_LIST_H_
