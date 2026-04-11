CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = -lpthread -ldl

all: drawbridge-host

drawbridge-host: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[BUILD] drawbridge-host ready"

clean:
	rm -f drawbridge-host
