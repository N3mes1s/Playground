CC = gcc
MINGW64 = x86_64-w64-mingw32-gcc
MINGW32 = i686-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = -lpthread

HOST_SRCS = pal-host/host.c pal-host/pe_loader.c pal-host/pal_linux.c pal-host/win32_stubs.c pal-host/dll_registry.c
HOST_64 = drawbridge-run
HOST_32 = drawbridge-run32

.PHONY: all clean test test32

all: $(HOST_64) $(HOST_32) test/hello_minimal.exe test/hello32.exe

# Build 64-bit PAL host (for PE32+ executables)
$(HOST_64): $(HOST_SRCS) pal-host/pe_loader.h include/ntum_pal.h
	$(CC) $(CFLAGS) -o $@ $(HOST_SRCS) $(LDFLAGS)
	@echo "[BUILD] 64-bit PAL host: $@"

# Build 32-bit PAL host (for PE32 executables - most malware)
$(HOST_32): $(HOST_SRCS) pal-host/pe_loader.h include/ntum_pal.h
	$(CC) -m32 $(CFLAGS) -DHOST_32BIT -o $@ $(HOST_SRCS) $(LDFLAGS)
	@echo "[BUILD] 32-bit PAL host: $@"

# 64-bit test PE
test/hello_minimal.exe: test/hello_minimal.c
	@mkdir -p test
	$(MINGW64) -o $@ $< -nostdlib -lkernel32 -e _start
	@echo "[BUILD] 64-bit test PE: $@"

# 32-bit test PE
test/hello32.exe: test/hello32.c
	@mkdir -p test
	$(MINGW32) -o $@ $< -nostdlib -lkernel32 -e _start
	@echo "[BUILD] 32-bit test PE: $@"

# Run tests
test: $(HOST_64) test/hello_minimal.exe
	./$(HOST_64) test/hello_minimal.exe

test32: $(HOST_32) test/hello32.exe
	./$(HOST_32) test/hello32.exe

# Run malware
run-malware: $(HOST_32)
	@if [ -z "$(PE)" ]; then \
		echo "Usage: make run-malware PE=<path-to-malware.exe>"; \
		echo "Example: make run-malware PE=../malware-analysis/samples/jeefo_virus.exe"; \
	else \
		./$(HOST_32) $(PE); \
	fi

clean:
	rm -f $(HOST_64) $(HOST_32) test/*.exe
