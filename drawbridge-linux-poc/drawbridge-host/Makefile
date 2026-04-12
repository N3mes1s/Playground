CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -no-pie
LDFLAGS = -lpthread -ldl -no-pie

# Original host files
SRCS  = main.c ntum_bootstrap.c dk_pal.c ntum_signals.c
# New per-subsystem translations of the ELF host (M1 scaffolding)
SRCS += pal_boot.c pal_thread.c pal_abi.c pal_io.c pe_init_replicas.c

ASM_SRCS = trampoline.S cfg_passthrough.S
HDRS = ntum_bootstrap.h pal_internal.h drawbridge_types.h

all: drawbridge-host

drawbridge-host: $(SRCS) $(ASM_SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(ASM_SRCS) $(LDFLAGS)
	@echo "[BUILD] drawbridge-host ready"

clean:
	rm -f drawbridge-host
