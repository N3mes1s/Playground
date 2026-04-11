CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -no-pie
LDFLAGS = -lpthread -ldl -no-pie

SRCS = main.c ntum_bootstrap.c dk_pal.c ntum_signals.c

all: drawbridge-host

drawbridge-host: $(SRCS) trampoline.S cfg_passthrough.S ntum_bootstrap.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) trampoline.S cfg_passthrough.S $(LDFLAGS)
	@echo "[BUILD] drawbridge-host ready"

clean:
	rm -f drawbridge-host
