# Makefile for xdp-tun-decap
# XDP tunnel decapsulation program for GRE and IPIP
# Target: Linux kernel 5.17+ with CO-RE support

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
CC ?= gcc

# Directories
SRC_DIR := src
BPF_DIR := $(SRC_DIR)/bpf
INCLUDE_DIR := $(SRC_DIR)/include
TEST_DIR := $(SRC_DIR)/test
BUILD_DIR := build

# Output files
VMLINUX_H := $(BPF_DIR)/vmlinux.h
BPF_OBJ := $(BUILD_DIR)/tun_decap.bpf.o
BPF_SKEL := $(BUILD_DIR)/tun_decap.skel.h
TEST_BIN := $(BUILD_DIR)/test_decap

# Detect architecture
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Check for libxdp headers
XDP_HEADERS_FOUND := $(shell test -f /usr/include/xdp/xdp_helpers.h && echo yes || echo no)
ifeq ($(XDP_HEADERS_FOUND),yes)
    XDP_DEFINES := -DHAVE_XDP_HELPERS
    XDP_INCLUDES := -I/usr/include/xdp
else
    XDP_DEFINES :=
    XDP_INCLUDES :=
endif

# BPF compilation flags
# -O2: Required for BPF (verifier needs optimized code)
# -g: Generate BTF debug info for CO-RE
# -mcpu=v3: Enable atomics and ALU32 (kernel 5.1+)
# -target bpf: BPF target (64-bit pointers)
BPF_CFLAGS := -O2 -g -Wall -Wextra \
              -target bpf \
              -mcpu=v3 \
              -D__TARGET_ARCH_$(ARCH) \
              $(XDP_DEFINES) \
              -I$(BPF_DIR) \
              -I$(INCLUDE_DIR) \
              $(XDP_INCLUDES)

# Userspace compilation flags
USER_CFLAGS := -O2 -g -Wall -Wextra \
               -I$(INCLUDE_DIR) \
               -I$(BUILD_DIR)

USER_LDFLAGS := -lbpf -lelf -lz

# Default target
.PHONY: all
all: $(BUILD_DIR) vmlinux bpf skel

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Generate vmlinux.h from running kernel's BTF
# This provides all kernel type definitions for CO-RE
.PHONY: vmlinux
vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@echo "Generating vmlinux.h from kernel BTF..."
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "Error: Kernel BTF not available. Ensure CONFIG_DEBUG_INFO_BTF=y"; \
		exit 1; \
	fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "Generated $@"

# Compile BPF program
.PHONY: bpf
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_DIR)/tun_decap.bpf.c $(BPF_DIR)/gre.h $(BPF_DIR)/parsing.h $(INCLUDE_DIR)/tun_decap.h $(VMLINUX_H) | $(BUILD_DIR)
	@echo "Compiling BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "Generated $@"

# Generate BPF skeleton header for userspace
.PHONY: skel
skel: $(BPF_SKEL)

$(BPF_SKEL): $(BPF_OBJ)
	@echo "Generating BPF skeleton..."
	$(BPFTOOL) gen skeleton $< > $@
	@echo "Generated $@"

# Build test binary
.PHONY: test-build
test-build: $(TEST_BIN)

$(TEST_BIN): $(TEST_DIR)/test_decap.c $(TEST_DIR)/test_packets.h $(BPF_SKEL) | $(BUILD_DIR)
	@echo "Building test binary..."
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)
	@echo "Generated $@"

# Run tests (requires root for BPF operations)
.PHONY: test
test: $(TEST_BIN)
	@echo "Running tests..."
	@if [ $$(id -u) -ne 0 ]; then \
		echo "Tests require root privileges. Running with sudo..."; \
		sudo $(TEST_BIN); \
	else \
		$(TEST_BIN); \
	fi

# Verify BPF program loads successfully
.PHONY: verify
verify: $(BPF_OBJ)
	@echo "Verifying BPF program..."
	$(BPFTOOL) prog load $< /sys/fs/bpf/tun_decap_test type xdp && \
		$(BPFTOOL) prog show pinned /sys/fs/bpf/tun_decap_test && \
		rm -f /sys/fs/bpf/tun_decap_test
	@echo "Verification successful"

# Show BPF program disassembly
.PHONY: dump
dump: $(BPF_OBJ)
	@echo "=== BPF Program Sections ==="
	@llvm-objdump -h $<
	@echo ""
	@echo "=== XDP Section Disassembly ==="
	@llvm-objdump -d -S $<

# Check BTF info
.PHONY: btf
btf: $(BPF_OBJ)
	@echo "=== BTF Info ==="
	$(BPFTOOL) btf dump file $<

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(VMLINUX_H)

# Full rebuild
.PHONY: rebuild
rebuild: clean all

# Help
.PHONY: help
help:
	@echo "XDP Tunnel Decapsulation Program Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build everything (default)"
	@echo "  vmlinux    - Generate vmlinux.h from kernel BTF"
	@echo "  bpf        - Compile BPF program"
	@echo "  skel       - Generate BPF skeleton header"
	@echo "  test-build - Build test binary"
	@echo "  test       - Build and run tests (requires root)"
	@echo "  verify     - Verify BPF program loads successfully"
	@echo "  dump       - Show BPF program disassembly"
	@echo "  btf        - Show BTF type information"
	@echo "  clean      - Remove build artifacts"
	@echo "  rebuild    - Clean and rebuild"
	@echo "  help       - Show this help"
	@echo ""
	@echo "Requirements:"
	@echo "  - Linux kernel 5.17+ with CONFIG_DEBUG_INFO_BTF=y"
	@echo "  - clang, llvm, bpftool, libbpf-dev"
