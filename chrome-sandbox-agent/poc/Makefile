CC = cc
CFLAGS = -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE
LDFLAGS = -static-pie

POCS = poc_io_uring_invisible \
       poc_xattrat_exploit \
       poc_covert_channel

.PHONY: all clean

all: $(POCS)

$(POCS): %: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(POCS)
