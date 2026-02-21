// Stub: base/system/sys_info.h
#ifndef BASE_SYSTEM_SYS_INFO_H_
#define BASE_SYSTEM_SYS_INFO_H_

#include <cstdio>
#include <cstring>
#include <string>
#include <sys/utsname.h>
#include <unistd.h>

namespace base {

class SysInfo {
 public:
  static int NumberOfProcessors() {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? static_cast<int>(n) : 1;
  }

  static std::string OperatingSystemName() {
    struct utsname info;
    if (uname(&info) < 0) return "Linux";
    return info.sysname;
  }

  static std::string OperatingSystemVersion() {
    struct utsname info;
    if (uname(&info) < 0) return "0.0.0";
    return info.release;
  }

  static void OperatingSystemVersionNumbers(int* major, int* minor, int* bugfix) {
    struct utsname info;
    *major = *minor = *bugfix = 0;
    if (uname(&info) == 0) {
      sscanf(info.release, "%d.%d.%d", major, minor, bugfix);
    }
  }

  static std::string KernelVersion() {
    struct utsname info;
    if (uname(&info) < 0) return "";
    return info.release;
  }
};

}  // namespace base

#endif  // BASE_SYSTEM_SYS_INFO_H_
