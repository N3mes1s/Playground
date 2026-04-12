CXX = g++
CXXFLAGS = -Wall -Wextra -O2 -g -no-pie -fno-exceptions -fno-rtti \
           -fpermissive -std=gnu++17
LDFLAGS  = -lpthread -ldl -no-pie -Wl,--allow-multiple-definition

SRCS  = pal_sync.cpp
SRCS += pal_kobj.cpp pal_teb.cpp pal_object.cpp
SRCS += pal_vm.cpp
SRCS += pe_loader.cpp pal_sys.cpp
SRCS += main.cpp ntum_bootstrap.cpp dk_pal.cpp ntum_signals.cpp
SRCS += pal_boot.cpp pal_thread.cpp pal_abi.cpp pal_io.cpp pe_init_replicas.cpp
SRCS += pal_stubs.cpp
SRCS += pool_allocator_real.cpp

ASM_SRCS = trampoline.S cfg_passthrough.S
HDRS = ntum_bootstrap.h pal_internal.h pal_sync.h drawbridge_types.h \
       pe_loader.h pal_boot.h pal_sys.h

all: drawbridge-host

drawbridge-host: $(SRCS) $(ASM_SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) $(ASM_SRCS) $(LDFLAGS)
	@echo "[BUILD] drawbridge-host ready"

clean:
	rm -f drawbridge-host
