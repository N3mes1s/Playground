CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = -lpthread -ldl

SRCS = main.c ntum_bootstrap.c dk_pal.c

all: drawbridge-host

drawbridge-host: $(SRCS) trampoline.S ntum_bootstrap.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) trampoline.S $(LDFLAGS)
	@echo "[BUILD] drawbridge-host ready"

clean:
	rm -f drawbridge-host
