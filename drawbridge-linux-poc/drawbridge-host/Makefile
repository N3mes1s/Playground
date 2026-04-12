CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -no-pie
LDFLAGS = -lpthread -ldl -no-pie -Wl,--allow-multiple-definition

# Component C7: real KEVENT / dispatcher-object sync (pal_sync.c) MUST come
# before dk_pal.c so that with --allow-multiple-definition the pal_sync.c
# strong symbols (DK_NotificationEventCreate, DK_SynchronizationEventCreate,
# DK_EventSet, DK_EventClear, DK_EventPeek, DK_ObjectsWaitAny) win over the
# stub versions still defined in dk_pal.c.
SRCS  = pal_sync.c
# M1 — Agent A: kernel substrate (C12 pool, C13 TEB, C8 object lifecycle).
# These must precede dk_pal.c so that, with --allow-multiple-definition,
# our DK_ObjectClose / DK_ObjectReference strong symbols win over the
# legacy ones in dk_pal.c.
SRCS += pal_kobj.c pal_teb.c pal_object.c
# Agent F (C3/C4) landed pal_vm.c (split of VM from dk_pal.c).
# Precede dk_pal.c so its DK_VirtualMemory* strong symbols win.
SRCS += pal_vm.c
# Original host files
SRCS += main.c ntum_bootstrap.c dk_pal.c ntum_signals.c
# New per-subsystem translations of the ELF host (M1 scaffolding)
SRCS += pal_boot.c pal_thread.c pal_abi.c pal_io.c pe_init_replicas.c
SRCS += pal_stubs.c
# Weak override / corrected pool allocator (zero-init + LIST_ENTRY self-refs)
SRCS += pool_allocator_real.c

ASM_SRCS = trampoline.S cfg_passthrough.S
HDRS = ntum_bootstrap.h pal_internal.h pal_sync.h drawbridge_types.h

all: drawbridge-host

drawbridge-host: $(SRCS) $(ASM_SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(ASM_SRCS) $(LDFLAGS)
	@echo "[BUILD] drawbridge-host ready"

clean:
	rm -f drawbridge-host
