// Stub: base/system/sys_info.h
#ifndef BASE_SYSTEM_SYS_INFO_H_
#define BASE_SYSTEM_SYS_INFO_H_

#include <unistd.h>

namespace base {

class SysInfo {
 public:
  static int NumberOfProcessors() {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? static_cast<int>(n) : 1;
  }
};

}  // namespace base

#endif  // BASE_SYSTEM_SYS_INFO_H_
