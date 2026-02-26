// Standalone shim: base/types/pass_key.h
#ifndef BASE_TYPES_PASS_KEY_H_
#define BASE_TYPES_PASS_KEY_H_

namespace base {

// PassKey pattern: restricts who can call a method.
template <typename Tag>
class PassKey {
 private:
  friend Tag;
  PassKey() = default;
};

}  // namespace base

#endif  // BASE_TYPES_PASS_KEY_H_
