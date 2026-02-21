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
         test_20_landlock \
         test_21_memfd_secret \
         test_22_keyctl \
         test_23_watch_queue \
         test_24_splice_tee \
         test_25_tty_pushback \
         test_26_process_vm \
         test_27_handle_ops \
         test_28_credential_spoof \
         test_29_fanotify_inotify \
         test_30_misc_kernel \
         test_31_signalfd_sigsys \
         test_32_mprotect_timing \
         test_33_posix_timer \
         test_34_prctl_audit \
         test_35_resource_limits \
         test_36_broker_ipc \
         test_37_socket_options \
         test_38_fuse_access \
         test_39_nested_namespace \
         test_40_syscall_enum \
         test_41_open_flags \
         test_42_timerfd_signalfd_abuse \
         test_43_kcmp_proc_leak \
         test_44_memfd_exec \
         test_45_pipe_buffer_exploit \
         test_46_seccomp_notify \
         test_47_rlimit_escape \
         test_48_network_raw \
         test_49_covert_channels \
         test_50_pidfd_getfd \
         test_51_new_mount_api \
         test_52_mseal_bypass \
         test_53_dirty_pagetable \
         test_54_listmount_statmount \
         test_55_process_madvise \
         test_56_shadow_stack \
         test_57_userns_capability \
         test_58_io_uring_advanced \
         test_59_clone3_flags \
         test_60_cachestat_lsm \
         test_61_close_range_epoll2 \
         test_62_speculative_sidechan \
         test_63_landlock_v4 \
         test_64_device_ioctl \
         test_65_sysctl_sysfs \
         test_66_kcfi_cfi_bypass \
         test_67_nftables_netlink

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
	echo "\033[1m║   67 attack categories, ~536 individual tests    ║\033[0m"; \
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
