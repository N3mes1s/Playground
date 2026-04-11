CC = gcc
MINGW = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = -lpthread

HOST_SRCS = pal-host/host.c pal-host/pe_loader.c pal-host/pal_linux.c pal-host/win32_stubs.c
HOST_BIN = drawbridge-run

TEST_SRCS = test/hello_win.c
TEST_BIN = test/hello_win.exe

.PHONY: all clean test

all: $(HOST_BIN) $(TEST_BIN)

# Build the PAL host (Linux ELF)
$(HOST_BIN): $(HOST_SRCS) pal-host/pe_loader.h include/ntum_pal.h
	$(CC) $(CFLAGS) -o $@ $(HOST_SRCS) $(LDFLAGS)
	@echo "[BUILD] PAL host ready: $@"

# Cross-compile test Windows program (PE64)
$(TEST_BIN): $(TEST_SRCS)
	@mkdir -p test
	$(MINGW) -o $@ $< -nostdlib -lkernel32 -e mainCRTStartup
	@echo "[BUILD] Test PE ready: $@"

# Build a minimal test that uses our stubs directly
test/hello_minimal.exe: test/hello_minimal.c
	@mkdir -p test
	$(MINGW) -o $@ $< -nostdlib -e _start
	@echo "[BUILD] Minimal test PE ready: $@"

# Run test
test: $(HOST_BIN) $(TEST_BIN)
	./$(HOST_BIN) $(TEST_BIN)

# Run against a malware sample
run-malware: $(HOST_BIN)
	@echo "Usage: ./$(HOST_BIN) <path-to-malware.exe>"
	@echo "Example: ./$(HOST_BIN) ../malware-analysis/samples/jeefo_virus.exe"

clean:
	rm -f $(HOST_BIN) $(TEST_BIN) test/hello_minimal.exe
