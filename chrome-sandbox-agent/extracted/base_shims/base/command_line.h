// Standalone shim: base/command_line.h
#ifndef BASE_COMMAND_LINE_H_
#define BASE_COMMAND_LINE_H_

#include <map>
#include <string>
#include <vector>

#include "base/files/file_path.h"

namespace base {

class CommandLine {
 public:
  using StringVector = std::vector<std::string>;
  using SwitchMap = std::map<std::string, std::string>;

  CommandLine(int argc, const char* const* argv) {
    if (argc > 0) program_ = FilePath(argv[0]);
    for (int i = 1; i < argc; ++i) {
      std::string arg(argv[i]);
      if (arg.substr(0, 2) == "--") {
        auto eq = arg.find('=');
        if (eq != std::string::npos) {
          switches_[arg.substr(2, eq - 2)] = arg.substr(eq + 1);
        } else {
          switches_[arg.substr(2)] = "";
        }
      } else {
        args_.push_back(arg);
      }
    }
  }

  explicit CommandLine(const FilePath& program) : program_(program) {}
  CommandLine(const StringVector& argv) {
    if (!argv.empty()) program_ = FilePath(argv[0]);
    for (size_t i = 1; i < argv.size(); ++i) args_.push_back(argv[i]);
  }

  static CommandLine* ForCurrentProcess() {
    static CommandLine instance(FilePath(""));
    return &instance;
  }

  static void Init(int argc, const char* const* argv) {
    auto* cmd = ForCurrentProcess();
    *cmd = CommandLine(argc, argv);
  }

  FilePath GetProgram() const { return program_; }
  void SetProgram(const FilePath& program) { program_ = program; }
  bool HasSwitch(const std::string& name) const {
    return switches_.count(name) > 0;
  }
  std::string GetSwitchValueASCII(const std::string& name) const {
    auto it = switches_.find(name);
    return it != switches_.end() ? it->second : "";
  }
  void AppendSwitch(const std::string& name) { switches_[name] = ""; }
  void AppendSwitchASCII(const std::string& name, const std::string& value) {
    switches_[name] = value;
  }
  void AppendSwitchPath(const std::string& name, const FilePath& path) {
    switches_[name] = path.value();
  }

  StringVector argv() const {
    StringVector result;
    result.push_back(program_.value());
    for (auto& [k, v] : switches_) {
      if (v.empty())
        result.push_back("--" + k);
      else
        result.push_back("--" + k + "=" + v);
    }
    for (auto& a : args_) result.push_back(a);
    return result;
  }

  const StringVector& GetArgs() const { return args_; }
  void AppendArg(const std::string& arg) { args_.push_back(arg); }

  // PrependWrapper: prepend a wrapper command (e.g., setuid sandbox binary)
  void PrependWrapper(const std::string& wrapper) {
    // Insert wrapper as first element, shift existing argv[0] to args
    StringVector old_argv = argv();
    program_ = FilePath(wrapper);
    args_.clear();
    switches_.clear();
    for (size_t i = 0; i < old_argv.size(); ++i) {
      args_.push_back(old_argv[i]);
    }
  }

 private:
  FilePath program_;
  SwitchMap switches_;
  StringVector args_;
};

}  // namespace base

#endif  // BASE_COMMAND_LINE_H_
