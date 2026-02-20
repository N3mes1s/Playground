// Standalone shim: base/environment.h
#ifndef BASE_ENVIRONMENT_H_
#define BASE_ENVIRONMENT_H_

#include <cstdlib>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace base {

// NativeEnvironmentString: on POSIX, just std::string.
using NativeEnvironmentString = std::string;

// EnvironmentMap: used by LaunchOptions etc.
using EnvironmentMap = std::map<std::string, std::string>;

class Environment {
 public:
  virtual ~Environment() = default;

  // New API: returns optional<string>
  virtual std::optional<std::string> GetVar(const char* name) {
    const char* val = getenv(name);
    if (!val) return std::nullopt;
    return std::string(val);
  }

  std::optional<std::string> GetVar(const std::string& name) {
    return GetVar(name.c_str());
  }
  std::optional<std::string> GetVar(std::string_view name) {
    return GetVar(std::string(name).c_str());
  }

  virtual bool SetVar(const char* name, const std::string& value) {
    return setenv(name, value.c_str(), 1) == 0;
  }
  bool SetVar(const std::string& name, const std::string& value) {
    return SetVar(name.c_str(), value);
  }

  virtual bool UnSetVar(const char* name) {
    return unsetenv(name) == 0;
  }
  bool UnSetVar(const std::string& name) {
    return UnSetVar(name.c_str());
  }

  virtual bool HasVar(const char* name) {
    return getenv(name) != nullptr;
  }
  bool HasVar(const std::string& name) {
    return HasVar(name.c_str());
  }

  static std::unique_ptr<Environment> Create();

 private:
  class EnvironmentImpl;
};

class Environment::EnvironmentImpl : public Environment {};

inline std::unique_ptr<Environment> Environment::Create() {
  return std::make_unique<EnvironmentImpl>();
}

}  // namespace base

#endif  // BASE_ENVIRONMENT_H_
