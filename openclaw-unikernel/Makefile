# OpenClaw Unikernel — Build System
#
# Targets:
#   make build    — Release build
#   make debug    — Debug build
#   make iso      — Build GRUB2 bootable ISO
#   make run      — Build and run in QEMU (tries -kernel, falls back to ISO)
#   make run-iso  — Build ISO and run in QEMU via CDROM
#   make clean    — Remove build artifacts
#   make size     — Report binary size
#   make clippy   — Run linter
#   make fmt      — Format code

TARGET    := x86_64-unknown-none
BINARY    := target/$(TARGET)/release/openclaw-unikernel
ISO       := openclaw.iso
BUILD_STD := -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem
QEMU      := qemu-system-x86_64
QEMU_ARGS := -m 1G -serial stdio -display none -no-reboot \
             -cpu qemu64 -smp 1 \
             -netdev user,id=net0,hostfwd=tcp::3000-:3000 \
             -device virtio-net-pci,netdev=net0 \
             -device isa-debug-exit,iobase=0xf4,iosize=0x04

.PHONY: build debug iso run run-iso run-kvm run-debug clean size clippy fmt test

build:
	cargo build --release --target $(TARGET) $(BUILD_STD)
	@echo "Binary: $(BINARY)"
	@ls -lh $(BINARY)

debug:
	cargo build --target $(TARGET) $(BUILD_STD)

iso: build
	cp $(BINARY) iso/boot/openclaw-unikernel
	grub-mkrescue -o $(ISO) iso/ 2>/dev/null
	@echo "ISO: $(ISO)"
	@ls -lh $(ISO)

run: build
	$(QEMU) -kernel $(BINARY) $(QEMU_ARGS)

run-iso: iso
	$(QEMU) -cdrom $(ISO) $(QEMU_ARGS)

run-kvm: build
	$(QEMU) -enable-kvm -kernel $(BINARY) $(QEMU_ARGS) -cpu host -smp 2

run-debug: debug
	$(QEMU) -kernel target/$(TARGET)/debug/openclaw-unikernel \
		-m 128M -serial stdio -display none -no-reboot -s -S

clean:
	cargo clean
	rm -f $(ISO)
	rm -f iso/boot/openclaw-unikernel

size: build
	@echo "=== Binary Size ==="
	@ls -lh $(BINARY)
	@echo ""
	@size $(BINARY) 2>/dev/null || true

clippy:
	cargo clippy --target $(TARGET) $(BUILD_STD) -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check
