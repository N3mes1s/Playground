// Copyright 2011 The Chromium Authors
// Standalone shim: base/posix/unix_domain_socket.h
// Provides sendmsg/recvmsg with SCM_RIGHTS fd passing.

#ifndef BASE_POSIX_UNIX_DOMAIN_SOCKET_H_
#define BASE_POSIX_UNIX_DOMAIN_SOCKET_H_

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <vector>

#include "base/containers/span.h"
#include "base/files/scoped_file.h"
#include "base/process/process_handle.h"

namespace base {

inline bool CreateSocketPair(ScopedFD* one, ScopedFD* two) {
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) != 0)
    return false;
  one->reset(fds[0]);
  two->reset(fds[1]);
  return true;
}

class UnixDomainSocket {
 public:
  static const size_t kMaxFileDescriptors = 16;

  static bool EnableReceiveProcessId(int fd) {
    int optval = 1;
    return setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == 0;
  }

  static bool SendMsg(int fd, base::span<const uint8_t> msg,
                      const std::vector<int>& fds) {
    struct msghdr msgh = {};
    struct iovec iov;
    iov.iov_base = const_cast<uint8_t*>(msg.data());
    iov.iov_len = msg.size();
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    char control_buf[CMSG_SPACE(sizeof(int) * kMaxFileDescriptors)] = {};
    if (!fds.empty()) {
      size_t control_len = CMSG_SPACE(sizeof(int) * fds.size());
      msgh.msg_control = control_buf;
      msgh.msg_controllen = control_len;
      struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msgh);
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fds.size());
      memcpy(CMSG_DATA(cmsg), fds.data(), sizeof(int) * fds.size());
    }

    return sendmsg(fd, &msgh, MSG_NOSIGNAL) >= 0;
  }

  static ssize_t RecvMsg(int fd, base::span<uint8_t> msg,
                         std::vector<ScopedFD>* fds) {
    struct msghdr msgh = {};
    struct iovec iov;
    iov.iov_base = msg.data();
    iov.iov_len = msg.size();
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    char control_buf[CMSG_SPACE(sizeof(int) * kMaxFileDescriptors)] = {};
    msgh.msg_control = control_buf;
    msgh.msg_controllen = sizeof(control_buf);

    ssize_t result = recvmsg(fd, &msgh, 0);
    if (result < 0) return result;

    if (fds) {
      fds->clear();
      for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msgh); cmsg;
           cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
          size_t payload_len = cmsg->cmsg_len - CMSG_LEN(0);
          size_t num_fds = payload_len / sizeof(int);
          const int* fd_array = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
          for (size_t i = 0; i < num_fds; ++i)
            fds->emplace_back(fd_array[i]);
        }
      }
    }

    return result;
  }

  static ssize_t RecvMsgWithPid(int fd, base::span<uint8_t> msg,
                                std::vector<ScopedFD>* fds,
                                ProcessId* pid) {
    struct msghdr msgh = {};
    struct iovec iov;
    iov.iov_base = msg.data();
    iov.iov_len = msg.size();
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    // Allocate control buffer for both SCM_RIGHTS and SCM_CREDENTIALS.
    const size_t kControlBufSize =
        CMSG_SPACE(sizeof(int) * kMaxFileDescriptors) +
        CMSG_SPACE(sizeof(struct ucred));
    char control_buf[kControlBufSize] = {};
    msgh.msg_control = control_buf;
    msgh.msg_controllen = sizeof(control_buf);

    ssize_t result = recvmsg(fd, &msgh, 0);
    if (result < 0) return result;

    if (fds) fds->clear();
    if (pid) *pid = -1;

    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msgh); cmsg;
         cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
      if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
        if (fds) {
          size_t payload_len = cmsg->cmsg_len - CMSG_LEN(0);
          size_t num_fds = payload_len / sizeof(int);
          const int* fd_array = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
          for (size_t i = 0; i < num_fds; ++i)
            fds->emplace_back(fd_array[i]);
        }
      }
      if (cmsg->cmsg_level == SOL_SOCKET &&
          cmsg->cmsg_type == SCM_CREDENTIALS) {
        if (pid) {
          struct ucred* cred =
              reinterpret_cast<struct ucred*>(CMSG_DATA(cmsg));
          *pid = cred->pid;
        }
      }
    }

    return result;
  }
};

}  // namespace base

#endif  // BASE_POSIX_UNIX_DOMAIN_SOCKET_H_
