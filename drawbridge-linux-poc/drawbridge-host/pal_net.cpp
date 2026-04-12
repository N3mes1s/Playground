/*
 * pal_net.cpp - Component C17: Socket / Network I/O (M11).
 *
 * Translates SocketStream.cpp + SocketIoCompletionPort.cpp out of
 * analysis/sqlservr_FULL.c (search for "SocketStream", "socket(",
 * "epoll"). The ELF host hands off socket I/O to a SocketStream
 * subclass of Stream; the PE side reaches the same code through the
 * SocketStream Stream subclass created from a "socket:" URI. Either
 * way the primitives below are what the NTUM eventually calls.
 *
 * Decompile cross-reference (line numbers in analysis/sqlservr_FULL.c):
 *   FUN_0025aa60 @ 127673  SocketStream::SocketStream (uring path)
 *   FUN_0025ab40 @ 127805  SocketStream dtor ("socket deleted")
 *   FUN_0025acc0 @ 127840  SocketStream::CreateSocket (socket())
 *   FUN_0025b090 @ 127970  SocketStream::Close        (close())
 *   FUN_0025bXXX            SocketStream::Send/Recv   (writev/readv)
 *   FUN_001f1c50 @  52045  IoCompletionPort::Create   (io_setup)
 *   s_network_he_socket_epoll_configur_001438dd       epoll config
 *
 * This TU owns the strong definitions for the DK_Socket* entry points
 * declared in pal_net.h. They are marked extern "C" + __attribute__
 * ((ms_abi)) so the NTUM can call them with Windows x64 calling
 * convention through the ABI dispatcher.
 */

#include "pal_net.h"
#include "pal_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <atomic>
#include <mutex>
#include <new>

/* =====================================================================
 * 1. WinSock-shaped struct layout checks.
 *
 * The NTUM passes sockaddr_in / sockaddr_in6 buffers built by the PE's
 * winsock2.h. Those have the same byte layout as the Linux headers
 * (sin_family, sin_port, sin_addr, zero-padding) so we can accept the
 * pointer directly without byte-swapping the struct. static_assert the
 * layout so a future libc/glibc ABI drift fails the build loudly.
 * ===================================================================== */

static_assert(sizeof(sockaddr_in)  == 16,
              "sockaddr_in must be 16 bytes to match WinSock SOCKADDR_IN");
static_assert(sizeof(sockaddr_in6) == 28,
              "sockaddr_in6 must be 28 bytes to match WinSock SOCKADDR_IN6");
static_assert(offsetof(sockaddr_in, sin_family) == 0,
              "sockaddr_in.sin_family must be at offset 0");
static_assert(offsetof(sockaddr_in, sin_port)   == 2,
              "sockaddr_in.sin_port must be at offset 2");
static_assert(offsetof(sockaddr_in, sin_addr)   == 4,
              "sockaddr_in.sin_addr must be at offset 4");
static_assert(offsetof(sockaddr_in6, sin6_family) == 0,
              "sockaddr_in6.sin6_family must be at offset 0");
static_assert(offsetof(sockaddr_in6, sin6_port)   == 2,
              "sockaddr_in6.sin6_port must be at offset 2");

/* =====================================================================
 * 2. PalSocket RAII wrapper.
 *
 * SocketStream holds m_fd (offset 0xc0 in the ELF, see FUN_0025acc0).
 * We keep that per-fd state plus enough metadata to route completion
 * events back into epoll. Destruction closes the fd; construction
 * takes ownership of an already-opened fd.
 * ===================================================================== */

namespace {

struct PalSocket {
    int  fd        = -1;
    int  family    = 0;
    int  type      = 0;
    int  protocol  = 0;
    void *user_key = nullptr;

    PalSocket() = default;
    PalSocket(int f, int fam, int t, int p)
        : fd(f), family(fam), type(t), protocol(p) {}

    /* Non-copyable, movable. */
    PalSocket(const PalSocket &) = delete;
    PalSocket &operator=(const PalSocket &) = delete;
    PalSocket(PalSocket &&other) noexcept { swap(other); }
    PalSocket &operator=(PalSocket &&other) noexcept {
        swap(other);
        return *this;
    }

    ~PalSocket() { reset(); }

    void swap(PalSocket &o) noexcept {
        std::swap(fd, o.fd);
        std::swap(family, o.family);
        std::swap(type, o.type);
        std::swap(protocol, o.protocol);
        std::swap(user_key, o.user_key);
    }

    int release() noexcept {
        int r = fd;
        fd = -1;
        return r;
    }

    void reset() noexcept {
        if (fd >= 0) {
            /* Retry close() on EINTR, mirroring the
             * "Socket close failed with errno other than EINTR"
             * panic in SocketStream.cpp:0x169. */
            int rc;
            do { rc = ::close(fd); } while (rc == -1 && errno == EINTR);
            fd = -1;
        }
    }

    bool valid() const noexcept { return fd >= 0; }
};

/* =====================================================================
 * 3. Handle pool.
 *
 * DK_HANDLE values for sockets live in a private numbering space so
 * they never collide with the file-stream pool (PAL_STREAM_POOL_BASE).
 * ===================================================================== */

constexpr uint64_t PAL_NET_POOL_BASE = 0x10000ULL; /* 65536 */
constexpr uint64_t PAL_NET_POOL_MAX  = 4096;

struct NetPool {
    std::mutex mu;
    PalSocket  slots[PAL_NET_POOL_MAX];
    bool       used [PAL_NET_POOL_MAX] = {false};

    DK_HANDLE insert(PalSocket &&s) {
        std::lock_guard<std::mutex> g(mu);
        for (uint64_t i = 0; i < PAL_NET_POOL_MAX; ++i) {
            if (!used[i]) {
                slots[i] = std::move(s);
                used[i]  = true;
                return DK_HANDLE(PAL_NET_POOL_BASE + i);
            }
        }
        return DK_NULL_HANDLE;
    }

    PalSocket *lookup(DK_HANDLE h) {
        if (h < PAL_NET_POOL_BASE) return nullptr;
        uint64_t i = h - PAL_NET_POOL_BASE;
        if (i >= PAL_NET_POOL_MAX) return nullptr;
        /* Intentionally unlocked: callers hold a handle they just got
         * from us, and the slot outlives the handle. A concurrent
         * DK_SocketClose on the same handle is a caller bug. */
        if (!used[i]) return nullptr;
        return &slots[i];
    }

    void erase(DK_HANDLE h) {
        if (h < PAL_NET_POOL_BASE) return;
        uint64_t i = h - PAL_NET_POOL_BASE;
        if (i >= PAL_NET_POOL_MAX) return;
        std::lock_guard<std::mutex> g(mu);
        if (used[i]) {
            slots[i].reset();
            used[i] = false;
        }
    }
};

NetPool &net_pool() {
    static NetPool p;
    return p;
}

/* =====================================================================
 * 4. Epoll-backed completion port.
 *
 * SocketIoCompletionPort.cpp keeps an epoll fd + a vector of pending
 * epoll_events. We wrap that in CompletionPort and hand out
 * DK_HANDLEs in a second numbering space so they can't be confused
 * with PalSocket handles.
 * ===================================================================== */

constexpr uint64_t PAL_NET_CP_BASE = 0x20000ULL;
constexpr uint64_t PAL_NET_CP_MAX  = 64;

struct CompletionPort {
    int epfd = -1;
    bool in_use = false;

    ~CompletionPort() { reset(); }

    bool create() {
        epfd = ::epoll_create1(EPOLL_CLOEXEC);
        return epfd >= 0;
    }

    void reset() {
        if (epfd >= 0) {
            ::close(epfd);
            epfd = -1;
        }
        in_use = false;
    }
};

struct CpPool {
    std::mutex mu;
    CompletionPort ports[PAL_NET_CP_MAX];

    DK_HANDLE create() {
        std::lock_guard<std::mutex> g(mu);
        for (uint64_t i = 0; i < PAL_NET_CP_MAX; ++i) {
            if (!ports[i].in_use) {
                if (!ports[i].create()) return DK_NULL_HANDLE;
                ports[i].in_use = true;
                return DK_HANDLE(PAL_NET_CP_BASE + i);
            }
        }
        return DK_NULL_HANDLE;
    }

    CompletionPort *lookup(DK_HANDLE h) {
        if (h < PAL_NET_CP_BASE) return nullptr;
        uint64_t i = h - PAL_NET_CP_BASE;
        if (i >= PAL_NET_CP_MAX) return nullptr;
        if (!ports[i].in_use) return nullptr;
        return &ports[i];
    }

    void erase(DK_HANDLE h) {
        if (h < PAL_NET_CP_BASE) return;
        uint64_t i = h - PAL_NET_CP_BASE;
        if (i >= PAL_NET_CP_MAX) return;
        std::lock_guard<std::mutex> g(mu);
        ports[i].reset();
    }
};

CpPool &cp_pool() {
    static CpPool p;
    return p;
}

/* =====================================================================
 * 5. errno → NTSTATUS translation.
 *
 * SocketStream.cpp uses the same generic pal_result helper the stream
 * layer does (FUN_0028e0f0), plus a handful of specific sites that
 * hand out 0x103 (STATUS_PENDING), 0xc0000017 (NO_MEMORY),
 * 0xc000000d (INVALID_PARAMETER), 0xc000020d (CONNECTION_RESET) and
 * 0xc00000a3 (DEVICE_NOT_READY).
 * ===================================================================== */

uint64_t errno_to_dk(int e) {
    switch (e) {
        case 0:           return DK_STATUS_SUCCESS;
        case EINVAL:      return DK_STATUS_INVALID_PARAM;
        case ENOMEM:      return DK_STATUS_NO_MEMORY;
        case EAGAIN:      return 0x00000103ULL;              /* STATUS_PENDING */
        case ECONNRESET:  return 0xC000020DULL;              /* CONN_RESET */
        case EPIPE:       return 0xC000020CULL;              /* CONN_DISC */
        case ENOTCONN:    return 0xC000023CULL;
        case ECONNREFUSED:return 0xC0000236ULL;
        case ETIMEDOUT:   return 0xC00000B5ULL;
        case EADDRINUSE:  return 0xC0000048ULL;
        case EACCES:      return 0xC0000022ULL;
        default:          return 0xC0000001ULL;              /* STATUS_UNSUCCESSFUL */
    }
}

std::atomic<int> g_net_init{0};

} /* anonymous namespace */

/* =====================================================================
 * 6. Public C API (ms_abi).
 * ===================================================================== */

extern "C" {

void pal_net_init(void) {
    int expected = 0;
    if (!g_net_init.compare_exchange_strong(expected, 1)) return;

    /* SIGPIPE must not kill the host if the peer disappears mid-send.
     * SocketStream relies on the EPIPE errno instead. */
    struct sigaction sa{};
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGPIPE, &sa, nullptr);

    /* Touch both pools so their static constructors run on this
     * thread, not a racy first-use thread inside the NTUM. */
    (void)net_pool();
    (void)cp_pool();

    fprintf(stderr, "[pal_net] initialized (epoll+SIGPIPE suppressed)\n");
}

DK_API uint64_t DK_SocketCreate(uint64_t family, uint64_t type,
                                uint64_t protocol, DK_HANDLE *out_handle)
{
    pal_net_init();
    if (!out_handle) return DK_STATUS_INVALID_PARAM;
    *out_handle = DK_NULL_HANDLE;

    int fd = ::socket(int(family), int(type) | SOCK_CLOEXEC, int(protocol));
    if (fd < 0) {
        /* Matches SocketStream.cpp:0x11d fall-back: if AF_INET6 isn't
         * available, try AF_INET. The ELF only does this when the
         * caller asked for AF_INET6 (family==10). */
        if (family == AF_INET6 && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)) {
            fd = ::socket(AF_INET, int(type) | SOCK_CLOEXEC, int(protocol));
        }
        if (fd < 0) return errno_to_dk(errno);
    }

    PalSocket s(fd, int(family), int(type), int(protocol));
    DK_HANDLE h = net_pool().insert(std::move(s));
    if (h == DK_NULL_HANDLE) {
        /* s's dtor closes the fd for us. */
        return DK_STATUS_NO_MEMORY;
    }
    *out_handle = h;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SocketConnect(DK_HANDLE socket,
                                 const void *addr, uint64_t addr_len)
{
    PalSocket *s = net_pool().lookup(socket);
    if (!s || !addr || addr_len == 0) return DK_STATUS_INVALID_PARAM;
    int rc;
    do {
        rc = ::connect(s->fd, (const sockaddr *)addr, (socklen_t)addr_len);
    } while (rc == -1 && errno == EINTR);
    if (rc == 0) return DK_STATUS_SUCCESS;
    return errno_to_dk(errno);
}

DK_API uint64_t DK_SocketSend(DK_HANDLE socket, const void *buffer,
                              uint64_t length, uint64_t flags,
                              uint64_t *bytes_sent)
{
    PalSocket *s = net_pool().lookup(socket);
    if (!s || (!buffer && length)) return DK_STATUS_INVALID_PARAM;
    ssize_t n;
    do {
        n = ::send(s->fd, buffer, (size_t)length,
                   int(flags) | MSG_NOSIGNAL);
    } while (n == -1 && errno == EINTR);
    if (n < 0) {
        if (bytes_sent) *bytes_sent = 0;
        return errno_to_dk(errno);
    }
    if (bytes_sent) *bytes_sent = (uint64_t)n;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SocketRecv(DK_HANDLE socket, void *buffer,
                              uint64_t length, uint64_t flags,
                              uint64_t *bytes_received)
{
    PalSocket *s = net_pool().lookup(socket);
    if (!s || (!buffer && length)) return DK_STATUS_INVALID_PARAM;
    ssize_t n;
    do {
        n = ::recv(s->fd, buffer, (size_t)length, int(flags));
    } while (n == -1 && errno == EINTR);
    if (n < 0) {
        if (bytes_received) *bytes_received = 0;
        return errno_to_dk(errno);
    }
    if (bytes_received) *bytes_received = (uint64_t)n;
    /* n == 0 on a stream socket means the peer closed cleanly; that
     * is STATUS_END_OF_FILE per SocketStream.cpp:0x323 "Detected
     * close after read". */
    if (n == 0 && length != 0) return 0xC0000011ULL;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SocketClose(DK_HANDLE socket) {
    if (!net_pool().lookup(socket)) return DK_STATUS_INVALID_PARAM;
    net_pool().erase(socket);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SocketBind(DK_HANDLE socket,
                              const void *addr, uint64_t addr_len)
{
    PalSocket *s = net_pool().lookup(socket);
    if (!s || !addr) return DK_STATUS_INVALID_PARAM;
    if (::bind(s->fd, (const sockaddr *)addr, (socklen_t)addr_len) != 0)
        return errno_to_dk(errno);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SocketListen(DK_HANDLE socket, uint64_t backlog) {
    PalSocket *s = net_pool().lookup(socket);
    if (!s) return DK_STATUS_INVALID_PARAM;
    if (::listen(s->fd, int(backlog)) != 0) return errno_to_dk(errno);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SocketAccept(DK_HANDLE socket, void *addr,
                                uint64_t *addr_len, DK_HANDLE *out)
{
    PalSocket *s = net_pool().lookup(socket);
    if (!s || !out) return DK_STATUS_INVALID_PARAM;
    *out = DK_NULL_HANDLE;

    socklen_t slen = 0;
    socklen_t *pslen = nullptr;
    if (addr && addr_len) {
        slen = (socklen_t)*addr_len;
        pslen = &slen;
    }
    int nfd;
    do {
        nfd = ::accept4(s->fd, (sockaddr *)addr, pslen, SOCK_CLOEXEC);
    } while (nfd == -1 && errno == EINTR);
    if (nfd < 0) return errno_to_dk(errno);

    if (addr_len) *addr_len = slen;

    PalSocket ns(nfd, s->family, s->type, s->protocol);
    DK_HANDLE h = net_pool().insert(std::move(ns));
    if (h == DK_NULL_HANDLE) return DK_STATUS_NO_MEMORY;
    *out = h;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SocketShutdown(DK_HANDLE socket, uint64_t how) {
    PalSocket *s = net_pool().lookup(socket);
    if (!s) return DK_STATUS_INVALID_PARAM;
    if (::shutdown(s->fd, int(how)) != 0) return errno_to_dk(errno);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SocketGetSockOpt(DK_HANDLE socket, uint64_t level,
                                    uint64_t name, void *val,
                                    uint64_t *len)
{
    PalSocket *s = net_pool().lookup(socket);
    if (!s || !val || !len) return DK_STATUS_INVALID_PARAM;
    socklen_t slen = (socklen_t)*len;
    if (::getsockopt(s->fd, int(level), int(name), val, &slen) != 0)
        return errno_to_dk(errno);
    *len = slen;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SocketSetSockOpt(DK_HANDLE socket, uint64_t level,
                                    uint64_t name, const void *val,
                                    uint64_t len)
{
    PalSocket *s = net_pool().lookup(socket);
    if (!s || (!val && len)) return DK_STATUS_INVALID_PARAM;
    if (::setsockopt(s->fd, int(level), int(name), val, (socklen_t)len) != 0)
        return errno_to_dk(errno);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SocketCompletionCreate(DK_HANDLE *out) {
    pal_net_init();
    if (!out) return DK_STATUS_INVALID_PARAM;
    DK_HANDLE h = cp_pool().create();
    if (h == DK_NULL_HANDLE) return errno_to_dk(errno ? errno : ENOMEM);
    *out = h;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SocketCompletionAssociate(DK_HANDLE cp, DK_HANDLE sock,
                                             uint64_t events,
                                             void *user_key)
{
    CompletionPort *p = cp_pool().lookup(cp);
    PalSocket      *s = net_pool().lookup(sock);
    if (!p || !s) return DK_STATUS_INVALID_PARAM;
    s->user_key = user_key;

    epoll_event ev{};
    ev.events = (uint32_t)(events ? events
                                  : (EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET));
    ev.data.u64 = (uint64_t)sock; /* caller maps back via handle */
    if (::epoll_ctl(p->epfd, EPOLL_CTL_ADD, s->fd, &ev) != 0)
        return errno_to_dk(errno);
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SocketCompletionWait(DK_HANDLE cp, uint64_t timeout_ms,
                                        void *events_out,
                                        uint64_t events_cap,
                                        uint64_t *events_ret)
{
    CompletionPort *p = cp_pool().lookup(cp);
    if (!p || !events_out || events_cap == 0) return DK_STATUS_INVALID_PARAM;
    int n;
    do {
        n = ::epoll_wait(p->epfd, (epoll_event *)events_out,
                         (int)events_cap,
                         timeout_ms == UINT64_MAX ? -1 : (int)timeout_ms);
    } while (n == -1 && errno == EINTR);
    if (n < 0) {
        if (events_ret) *events_ret = 0;
        return errno_to_dk(errno);
    }
    if (events_ret) *events_ret = (uint64_t)n;
    return DK_STATUS_SUCCESS;
}

DK_API uint64_t DK_SocketCompletionClose(DK_HANDLE cp) {
    if (!cp_pool().lookup(cp)) return DK_STATUS_INVALID_PARAM;
    cp_pool().erase(cp);
    return DK_STATUS_SUCCESS;
}

} /* extern "C" */
