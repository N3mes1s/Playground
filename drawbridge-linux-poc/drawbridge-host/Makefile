CXX = g++
CXXFLAGS = -Wall -Wextra -O2 -g -no-pie -fno-exceptions -fno-rtti \
           -fpermissive -std=gnu++17
LDFLAGS  = -lpthread -ldl -no-pie -Wl,--allow-multiple-definition

# C18 crypto streams (ProtectDataStream / CryptCommonStream) link
# against OpenSSL libcrypto + libssl.
LDFLAGS += -lssl -lcrypto

# C19 Kerberos (KerberosStream / KrbCredentialCacheManager) links
# against MIT krb5. Use `-l:libfoo.so.N` so we do not require the
# `-dev` symlink package; this matches the runtime SONAMEs present
# whenever the krb5 runtime is installed. Build hosts lacking the
# runtime can override:  make KRB5_LIBS=
KRB5_LIBS ?= -l:libkrb5.so.3 -l:libgssapi_krb5.so.2
LDFLAGS  += $(KRB5_LIBS)

SRCS  = pal_sync.cpp
SRCS += pal_kobj.cpp pal_teb.cpp pal_object.cpp
SRCS += pal_vm.cpp
SRCS += pe_loader.cpp pal_sys.cpp
# pal_stream.cpp and pal_console.cpp MUST precede dk_pal.cpp so that
# their strong DK_StreamWrite / DK_StreamOpen / DK_ConsoleCreate
# definitions win under -Wl,--allow-multiple-definition (first-seen).
SRCS += pal_stream.cpp pal_console.cpp
# pal_cpu.cpp MUST precede dk_pal.cpp: its strong DK_ThreadSetAffinity
# and DK_SystemInfoQuery overrides win under
# -Wl,--allow-multiple-definition (first-seen rule).
SRCS += pal_cpu.cpp
# pal_net.cpp (Component C17 / M11) owns the DK_Socket* strong symbols
# and must precede dk_pal.cpp for the same first-seen link rule.
SRCS += pal_net.cpp
SRCS += main.cpp ntum_bootstrap.cpp dk_pal.cpp ntum_signals.cpp
SRCS += pal_boot.cpp pal_thread.cpp pal_abi.cpp pal_io.cpp pe_init_replicas.cpp
SRCS += pal_stubs.cpp
SRCS += pal_except.cpp
SRCS += pool_allocator_real.cpp
# C18 (M12) Crypto streams - OpenSSL EVP wrappers.
SRCS += pal_crypto.cpp
# C19 (M12) Kerberos - KrbCredentialCacheManager + OAuth ticket flow.
SRCS += pal_krb.cpp
# C20 (M12) LDAP/ODBC stream wrappers - stubbed; no extra libs required.
SRCS += pal_ldap_odbc.cpp
# C21 (M13) Evaluation-period + host-parity residue (watchdog, tz, eval).
SRCS += pal_eval.cpp

ASM_SRCS = trampoline.S cfg_passthrough.S
HDRS = ntum_bootstrap.h pal_internal.h pal_sync.h drawbridge_types.h \
       pe_loader.h pal_boot.h pal_sys.h pal_cpu.h pal_net.h \
       pal_crypto.h pal_krb.h \
       pal_ldap_odbc.h pal_eval.h

all: drawbridge-host

drawbridge-host: $(SRCS) $(ASM_SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) $(ASM_SRCS) $(LDFLAGS)
	@echo "[BUILD] drawbridge-host ready"

clean:
	rm -f drawbridge-host
