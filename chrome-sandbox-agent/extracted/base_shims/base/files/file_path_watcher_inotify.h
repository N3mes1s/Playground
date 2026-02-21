// Standalone shim: base/files/file_path_watcher_inotify.h
// Provides GetMaxNumberOfInotifyWatches which also prewarms the
// InotifyReader singleton (creating the inotify fd before sandbox entry).

#ifndef BASE_FILES_FILE_PATH_WATCHER_INOTIFY_H_
#define BASE_FILES_FILE_PATH_WATCHER_INOTIFY_H_

#include <cstddef>
#include <cstdio>
#include <cstdlib>

#include "base/files/file_path_watcher.h"

namespace base {

// Returns the maximum number of inotify watches from
// /proc/sys/fs/inotify/max_user_watches.
// Side effect: prewarms the InotifyReader singleton so the inotify fd
// is created before the seccomp sandbox is applied.
inline size_t GetMaxNumberOfInotifyWatches() {
  // Prewarm: ensure the singleton inotify fd is created now.
  (void)InotifyReader::Instance();

  // Read the actual kernel limit.
  FILE* f = fopen("/proc/sys/fs/inotify/max_user_watches", "r");
  if (f) {
    size_t val = 0;
    if (fscanf(f, "%zu", &val) == 1) {
      fclose(f);
      return val;
    }
    fclose(f);
  }
  return 65536;  // Default fallback
}

}  // namespace base

#endif  // BASE_FILES_FILE_PATH_WATCHER_INOTIFY_H_
