// Standalone shim: base/files/file_path_watcher.h
// Chrome-compatible FilePathWatcher using singleton inotify reader.
// The inotify fd is created eagerly via GetMaxNumberOfInotifyWatches()
// (must happen before sandbox entry). Events are polled by RunLoop::Run(),
// matching Chrome's architecture where the IO message loop handles inotify.

#ifndef BASE_FILES_FILE_PATH_WATCHER_H_
#define BASE_FILES_FILE_PATH_WATCHER_H_

#include <functional>
#include <map>
#include <mutex>
#include <sys/inotify.h>
#include <unistd.h>

#include "base/files/file_path.h"

namespace base {

// Singleton inotify reader, analogous to Chrome's InotifyReader.
// Creates the inotify fd once. Events are polled externally (by RunLoop).
class InotifyReader {
 public:
  struct WatchEntry {
    FilePath path;
    std::function<void(const FilePath&, bool)> callback;
  };

  static InotifyReader& Instance() {
    static InotifyReader instance;
    return instance;
  }

  bool Valid() const { return inotify_fd_ >= 0; }
  int inotify_fd() const { return inotify_fd_; }

  int AddWatch(const FilePath& path, uint32_t mask,
               std::function<void(const FilePath&, bool)> callback) {
    if (inotify_fd_ < 0) return -1;
    int wd = inotify_add_watch(inotify_fd_, path.value().c_str(), mask);
    if (wd >= 0) {
      std::lock_guard<std::mutex> lock(mu_);
      watches_[wd] = {path, std::move(callback)};
    }
    return wd;
  }

  void RemoveWatch(int wd) {
    if (inotify_fd_ >= 0 && wd >= 0) {
      inotify_rm_watch(inotify_fd_, wd);
      std::lock_guard<std::mutex> lock(mu_);
      watches_.erase(wd);
    }
  }

  // Poll for inotify events and dispatch callbacks. Non-blocking.
  // Returns true if any events were processed.
  bool PollAndDispatch() {
    if (inotify_fd_ < 0) return false;

    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    ssize_t len = read(inotify_fd_, buf, sizeof(buf));
    if (len <= 0) return false;

    for (char* ptr = buf; ptr < buf + len; ) {
      auto* event = reinterpret_cast<struct inotify_event*>(ptr);
      {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = watches_.find(event->wd);
        if (it != watches_.end() && it->second.callback) {
          it->second.callback(it->second.path, false);
        }
      }
      ptr += sizeof(struct inotify_event) + event->len;
    }
    return true;
  }

 private:
  InotifyReader() {
    inotify_fd_ = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  }

  ~InotifyReader() {
    if (inotify_fd_ >= 0) close(inotify_fd_);
  }

  int inotify_fd_ = -1;
  std::mutex mu_;
  std::map<int, WatchEntry> watches_;
};

class FilePathWatcher {
 public:
  enum class Type {
    kNonRecursive,
    kRecursive,
  };

  using Callback = std::function<void(const FilePath&, bool)>;

  FilePathWatcher() = default;
  ~FilePathWatcher() { Cancel(); }

  FilePathWatcher(const FilePathWatcher&) = delete;
  FilePathWatcher& operator=(const FilePathWatcher&) = delete;

  bool Watch(const FilePath& path, Type type, const Callback& callback) {
    auto& reader = InotifyReader::Instance();
    if (!reader.Valid()) return false;

    uint32_t mask = IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVE |
                    IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF |
                    IN_MOVE_SELF;
    wd_ = reader.AddWatch(path, mask, callback);
    return wd_ >= 0;
  }

  bool Watch(const FilePath& path, bool recursive, const Callback& callback) {
    return Watch(path, recursive ? Type::kRecursive : Type::kNonRecursive,
                 callback);
  }

  void Cancel() {
    if (wd_ >= 0) {
      InotifyReader::Instance().RemoveWatch(wd_);
      wd_ = -1;
    }
  }

 private:
  int wd_ = -1;
};

}  // namespace base

#endif  // BASE_FILES_FILE_PATH_WATCHER_H_
