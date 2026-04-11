CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = -lpthread -ldl

SRCS = main.c ntum_bootstrap.c

all: drawbridge-host

drawbridge-host: $(SRCS) ntum_bootstrap.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)
	@echo "[BUILD] drawbridge-host ready"

clean:
	rm -f drawbridge-host
