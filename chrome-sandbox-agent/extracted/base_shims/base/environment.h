// Standalone shim: base/environment.h
#ifndef BASE_ENVIRONMENT_H_
#define BASE_ENVIRONMENT_H_

#include <cstdlib>
#include <memory>
#include <string>

namespace base {

class Environment {
 public:
  virtual ~Environment() = default;
  virtual bool GetVar(const char* name, std::string* result) = 0;
  virtual bool SetVar(const char* name, const std::string& value) = 0;
  virtual bool UnSetVar(const char* name) = 0;
  virtual bool HasVar(const char* name) {
    std::string unused;
    return GetVar(name, &unused);
  }

  static std::unique_ptr<Environment> Create() {
    return std::make_unique<EnvironmentImpl>();
  }

 private:
  class EnvironmentImpl : public Environment {
   public:
    bool GetVar(const char* name, std::string* result) override {
      const char* val = getenv(name);
      if (!val) return false;
      if (result) *result = val;
      return true;
    }
    bool SetVar(const char* name, const std::string& value) override {
      return setenv(name, value.c_str(), 1) == 0;
    }
    bool UnSetVar(const char* name) override {
      return unsetenv(name) == 0;
    }
  };
};

}  // namespace base

#endif  // BASE_ENVIRONMENT_H_
