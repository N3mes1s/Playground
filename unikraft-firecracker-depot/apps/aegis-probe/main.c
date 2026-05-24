/*
 * aegis-probe — a tiny native Unikraft unikernel.
 *
 * Compiled and linked into the unikernel binary at build time by
 * `kraft build` (see Kraftfile + Makefile.uk in this dir). No rootfs,
 * no Linux ELF loader, no syscall translation — this C source lives
 * in the same address space as Unikraft's libc and platform layer.
 *
 * On boot it prints a banner, emits a JSON status line between
 * markers so the host serial parser can pick it up, then returns
 * from main(). Unikraft's libukboot catches the return and halts
 * the unikernel cleanly (Firecracker exit_code=0).
 */

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	printf("\n=== aegis-probe (native Unikraft unikernel) ===\n");

	printf("DETONATE_JSON_BEGIN\n");
	printf("{\"verdict\":\"OK\","
	       "\"app\":\"aegis-probe\","
	       "\"runtime\":\"native\","
	       "\"argc\":%d,"
	       "\"argv0\":\"%s\","
	       "\"linkage\":\"compiled-into-unikernel\"}\n",
	       argc, (argc > 0 && argv[0]) ? argv[0] : "");
	printf("DETONATE_JSON_END\n");

	return 0;
}
