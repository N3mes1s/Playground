CC = gcc
MINGW64 = x86_64-w64-mingw32-gcc
MINGW32 = i686-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -O2 -g -Wno-unused-parameter
LDFLAGS = -lpthread

HOST_SRCS = pal-host/host.c pal-host/pe_loader.c pal-host/pal_linux.c pal-host/win32_stubs.c pal-host/dll_registry.c
HOST_64 = drawbridge-run
HOST_32 = drawbridge-run32

.PHONY: all clean test test32

all: $(HOST_64) test/hello_minimal.exe

# Build 64-bit PAL host (for PE32+ executables)
$(HOST_64): $(HOST_SRCS) pal-host/pe_loader.h include/ntum_pal.h
	$(CC) $(CFLAGS) -o $@ $(HOST_SRCS) $(LDFLAGS)
	@echo "[BUILD] 64-bit PAL host: $@"

# Build 32-bit PAL host (for PE32 executables)
$(HOST_32): $(HOST_SRCS) pal-host/pe_loader.h include/ntum_pal.h
	$(CC) -m32 $(CFLAGS) -DHOST_32BIT -o $@ $(HOST_SRCS) $(LDFLAGS)
	@echo "[BUILD] 32-bit PAL host: $@"

# 64-bit test PE
test/hello_minimal.exe: test/hello_minimal.c
	@mkdir -p test
	$(MINGW64) -o $@ $< -nostdlib -lkernel32 -e _start
	@echo "[BUILD] 64-bit test PE: $@"

# 32-bit test PE (requires i686-w64-mingw32-gcc)
test/hello32.exe: test/hello32.c
	@mkdir -p test
	$(MINGW32) -o $@ $< -nostdlib -lkernel32 -e _start
	@echo "[BUILD] 32-bit test PE: $@"

# Full drawbridge test app (uses CRT, more Win32 APIs)
test/full_test.exe: ../test-apps/full_test.c
	@mkdir -p test
	$(MINGW64) -o $@ $< -ladvapi32 -lws2_32 -mconsole
	@echo "[BUILD] 64-bit full test PE: $@"

# Hello drawbridge test (uses CRT, basic Win32 APIs)
test/hello_drawbridge.exe: ../test-apps/hello_drawbridge.c
	@mkdir -p test
	$(MINGW64) -o $@ $< -ladvapi32 -mconsole
	@echo "[BUILD] 64-bit hello drawbridge PE: $@"

# Run tests
test: $(HOST_64) test/hello_minimal.exe
	./$(HOST_64) test/hello_minimal.exe

test-full: $(HOST_64) test/hello_drawbridge.exe
	./$(HOST_64) test/hello_drawbridge.exe

test32: $(HOST_32) test/hello32.exe
	./$(HOST_32) test/hello32.exe

clean:
	rm -f $(HOST_64) $(HOST_32) test/*.exe
