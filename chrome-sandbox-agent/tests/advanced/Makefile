# Makefile for advanced sandbox bypass tests
#
# Each test is a standalone C binary compiled statically.
# Run inside sandbox: sandbox-run ./test_XX_name
# Run all:            make run-all

CC      ?= gcc
CFLAGS  := -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE -fpie
LDFLAGS := -static-pie -pthread

TESTS := test_01_fd_smuggling \
         test_02_dirty_pipe \
         test_03_abstract_socket \
         test_04_proc_self_mem \
         test_05_mmap_shared \
         test_06_scm_rights \
         test_07_futex_covert \
         test_08_ld_preload \
         test_09_renameat2_toctou \
         test_10_compound_attack \
         test_11_io_uring \
         test_12_msg_oob \
         test_13_userfaultfd \
         test_14_cross_cache \
         test_15_cgroup_escape \
         test_16_netfilter \
         test_17_vsock \
         test_18_procfs_race \
         test_19_ebpf \
         test_20_landlock

.PHONY: all clean run-all

all: $(TESTS)

$(TESTS): %: %.c test_harness.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TESTS)

run-all: all
	@total_pass=0; total_fail=0; total_tests=0; \
	echo ""; \
	echo "\033[1m╔══════════════════════════════════════════════════╗\033[0m"; \
	echo "\033[1m║   ADVANCED SANDBOX BYPASS TEST SUITE             ║\033[0m"; \
	echo "\033[1m║   20 attack categories, ~160 individual tests    ║\033[0m"; \
	echo "\033[1m╚══════════════════════════════════════════════════╝\033[0m"; \
	for t in $(TESTS); do \
		echo ""; \
		echo "\033[1m▶ Running $$t ...\033[0m"; \
		./$$t; \
		if [ $$? -ne 0 ]; then \
			total_fail=$$((total_fail + 1)); \
		else \
			total_pass=$$((total_pass + 1)); \
		fi; \
		total_tests=$$((total_tests + 1)); \
	done; \
	echo ""; \
	echo "\033[1m══════════════════════════════════════════════════\033[0m"; \
	echo "\033[1mSUITE SUMMARY: $$total_pass/$$total_tests categories passed\033[0m"; \
	if [ $$total_fail -gt 0 ]; then \
		echo "\033[91m$$total_fail categories had failures\033[0m"; \
	else \
		echo "\033[92mALL CATEGORIES HELD — sandbox is solid\033[0m"; \
	fi; \
	echo "\033[1m══════════════════════════════════════════════════\033[0m"
