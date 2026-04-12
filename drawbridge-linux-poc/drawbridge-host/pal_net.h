/*
 * pal_net.h - Component C17: Socket / Network I/O (M11).
 *
 * Public interface for the DK socket/network subsystem. Translated
 * from SocketStream.cpp and SocketIoCompletionPort.cpp in the
 * decompiled ELF host (analysis/sqlservr_FULL.c, around line 127680
 * and the 0x143000 network/he/socket/epoll configure region).
 *
 * The NTUM itself resolves sockets through the SocketStream path
 * (DK_StreamOpen with a "socket:" URI), but we also expose explicit
 * DK_Socket* entry points for callers that want a thin, POSIX-style
 * wrapper. epoll is used to back the socket completion port exactly
 * like SocketIoCompletionPort.cpp does on the ELF side.
 */

#ifndef PAL_NET_H
#define PAL_NET_H

#include "drawbridge_types.h"

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- DK socket entry points (ms_abi) ---------- */

/* Create a socket. `family` is an AF_* value, `type` a SOCK_* value,
 * `protocol` an IPPROTO_* value. On success writes a DK_HANDLE into
 * *out_handle that routes back to the owning PalSocket wrapper. */
DK_API uint64_t DK_SocketCreate(uint64_t family, uint64_t type,
                                uint64_t protocol, DK_HANDLE *out_handle);

/* Connect an AF_INET/AF_INET6 socket to a sockaddr buffer (caller
 * provides the raw bytes + length, just like connect(2)). */
DK_API uint64_t DK_SocketConnect(DK_HANDLE socket,
                                 const void *addr, uint64_t addr_len);

/* Send/Recv translate to send(2)/recv(2). `bytes_xfer` is optional. */
DK_API uint64_t DK_SocketSend(DK_HANDLE socket, const void *buffer,
                              uint64_t length, uint64_t flags,
                              uint64_t *bytes_sent);
DK_API uint64_t DK_SocketRecv(DK_HANDLE socket, void *buffer,
                              uint64_t length, uint64_t flags,
                              uint64_t *bytes_received);

/* Close a socket handle previously returned by DK_SocketCreate. */
DK_API uint64_t DK_SocketClose(DK_HANDLE socket);

/* Additional wrappers that the decompile touches (bind/listen/accept/
 * shutdown/getsockopt/setsockopt). Exposed as strong overrides for
 * the socket function IDs that would otherwise hit DK_GenericStub. */
DK_API uint64_t DK_SocketBind(DK_HANDLE socket,
                              const void *addr, uint64_t addr_len);
DK_API uint64_t DK_SocketListen(DK_HANDLE socket, uint64_t backlog);
DK_API uint64_t DK_SocketAccept(DK_HANDLE socket, void *addr,
                                uint64_t *addr_len, DK_HANDLE *out);
DK_API uint64_t DK_SocketShutdown(DK_HANDLE socket, uint64_t how);
DK_API uint64_t DK_SocketGetSockOpt(DK_HANDLE socket, uint64_t level,
                                    uint64_t name, void *val,
                                    uint64_t *len);
DK_API uint64_t DK_SocketSetSockOpt(DK_HANDLE socket, uint64_t level,
                                    uint64_t name, const void *val,
                                    uint64_t len);

/* Epoll-backed socket completion port. Mirrors
 * SocketIoCompletionPort.cpp. One of these is created per I/O thread
 * by the NTUM; DK_SocketCompletionAssociate pushes the socket's fd
 * into the epoll set, DK_SocketCompletionWait blocks until something
 * happens. */
DK_API uint64_t DK_SocketCompletionCreate(DK_HANDLE *out);
DK_API uint64_t DK_SocketCompletionAssociate(DK_HANDLE cp, DK_HANDLE sock,
                                             uint64_t events,
                                             void *user_key);
DK_API uint64_t DK_SocketCompletionWait(DK_HANDLE cp, uint64_t timeout_ms,
                                        void *events_out,
                                        uint64_t events_cap,
                                        uint64_t *events_ret);
DK_API uint64_t DK_SocketCompletionClose(DK_HANDLE cp);

/* One-time startup: creates the process-wide epoll fd, installs the
 * SIGPIPE handler (sockets must not crash the host on a broken peer)
 * and primes the handle pool. Safe to call more than once. */
void pal_net_init(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PAL_NET_H */
