#include <stdio.h>
#include <fcntl.h>
#include "sandbox/linux/syscall_broker/broker_file_permission.h"
#include "sandbox/linux/syscall_broker/broker_permission_list.h"

using sandbox::syscall_broker::BrokerFilePermission;
using sandbox::syscall_broker::BrokerPermissionList;

int main() {
  std::vector<BrokerFilePermission> perms;
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/lib/"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/lib64/"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/usr/lib/"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/etc/"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/bin/"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/usr/bin/"));
  perms.push_back(BrokerFilePermission::ReadOnlyRecursive("/proc/"));
  perms.push_back(BrokerFilePermission::ReadWrite("/dev/null"));
  perms.push_back(BrokerFilePermission::ReadWriteCreateRecursive("/tmp/"));

  printf("perms count: %zu\n", perms.size());

  BrokerPermissionList broker(EACCES, std::move(perms));

  // Test access checks
  auto test_access = [&](const char* path, int mode) {
    auto ret = broker.GetFileNameIfAllowedToAccess(path, mode);
    printf("  Access %-40s mode=%d => %s\n", path, mode,
           ret ? "ALLOWED" : "DENIED");
  };

  // Test open checks
  auto test_open = [&](const char* path, int flags) {
    auto ret = broker.GetFileNameIfAllowedToOpen(path, flags);
    printf("  Open   %-40s flags=0x%x => %s\n", path, flags,
           ret.first ? "ALLOWED" : "DENIED");
  };

  printf("\n=== Access checks ===\n");
  test_access("/etc/ld.so.preload", R_OK);
  test_access("/bin/sh", R_OK);
  test_access("/lib/x86_64-linux-gnu/libc.so.6", R_OK);

  printf("\n=== Open checks ===\n");
  test_open("/etc/ld.so.cache", O_RDONLY);
  test_open("/etc/ld.so.cache", O_RDONLY | O_CLOEXEC);
  test_open("/bin/sh", O_RDONLY);
  test_open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY);
  test_open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY | O_CLOEXEC);
  test_open("/tmp/test.txt", O_RDWR | O_CREAT);

  printf("\n=== Stat checks ===\n");
  auto test_stat = [&](const char* path) {
    auto ret = broker.GetFileNameIfAllowedToStat(path);
    printf("  Stat   %-40s => %s\n", path,
           ret ? "ALLOWED" : "DENIED");
  };
  test_stat("/etc/ld.so.cache");
  test_stat("/bin/sh");

  return 0;
}
