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

# Helper test binaries (run in userspace, no root required)
TEST_PARSING_BIN := $(BUILD_DIR)/test_parsing_helpers
TEST_GRE_BIN := $(BUILD_DIR)/test_gre_helpers
TEST_IPV6_BIN := $(BUILD_DIR)/test_ipv6_helpers
HELPER_TEST_BINS := $(TEST_PARSING_BIN) $(TEST_GRE_BIN) $(TEST_IPV6_BIN)

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

# Default target - just build the skeleton (which depends on everything else)
.PHONY: all
all: $(BPF_SKEL)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

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
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "Generated $@"

# Generate BPF skeleton header for userspace
.PHONY: skel
skel: $(BPF_SKEL)

$(BPF_SKEL): $(BPF_OBJ) | $(BUILD_DIR)
	@echo "Generating BPF skeleton..."
	@$(BPFTOOL) gen skeleton $< > $@
	@echo "Generated $@"

# Build test binary
.PHONY: test-build
test-build: $(TEST_BIN)

$(TEST_BIN): $(TEST_DIR)/test_decap.c $(TEST_DIR)/test_packets.h $(BPF_SKEL) | $(BUILD_DIR)
	@echo "Building test binary..."
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)
	@echo "Generated $@"

# Build helper test binaries (userspace only, no BPF dependencies)
# These tests don't require root permissions or BPF loading
.PHONY: test-helpers-build
test-helpers-build: $(HELPER_TEST_BINS)

$(TEST_PARSING_BIN): $(TEST_DIR)/test_parsing_helpers.c $(INCLUDE_DIR)/tun_decap.h | $(BUILD_DIR)
	@echo "Building parsing helpers test..."
	$(CC) $(USER_CFLAGS) $< -o $@
	@echo "Generated $@"

$(TEST_GRE_BIN): $(TEST_DIR)/test_gre_helpers.c $(INCLUDE_DIR)/tun_decap.h | $(BUILD_DIR)
	@echo "Building GRE helpers test..."
	$(CC) $(USER_CFLAGS) $< -o $@
	@echo "Generated $@"

$(TEST_IPV6_BIN): $(TEST_DIR)/test_ipv6_helpers.c $(INCLUDE_DIR)/tun_decap.h | $(BUILD_DIR)
	@echo "Building IPv6 helpers test..."
	$(CC) $(USER_CFLAGS) $< -o $@
	@echo "Generated $@"

# Run helper tests (userspace only, NO root required)
# These tests validate pure C helper functions without BPF loading
.PHONY: test-helpers
test-helpers: $(HELPER_TEST_BINS)
	@echo "=== Running Helper Tests (no root required) ==="
	@echo ""
	@$(TEST_PARSING_BIN)
	@$(TEST_GRE_BIN)
	@$(TEST_IPV6_BIN)
	@echo ""
	@echo "=== All helper tests completed ==="

# Run BPF unit tests (requires root for BPF operations)
# Note: Unit tests use BPF_PROG_TEST_RUN which requires CAP_BPF and CAP_SYS_ADMIN
# For comprehensive testing, also run integration tests: cd tests && ./run-tests.sh
.PHONY: test-bpf
test-bpf: $(TEST_BIN)
	@echo "Running BPF unit tests..."
	@echo "Note: These tests require loading BPF programs (CAP_BPF, CAP_SYS_ADMIN)"
	@echo "For comprehensive testing, run: cd tests && ./run-tests.sh"
	@echo ""
	@if [ $$(id -u) -ne 0 ]; then \
		echo "Tests require root privileges. Running with sudo..."; \
		sudo $(TEST_BIN); \
	else \
		$(TEST_BIN); \
	fi

# Run all unit tests (helpers + BPF)
.PHONY: test
test: test-helpers test-bpf
	@echo ""
	@echo "=== All unit tests completed ==="

# Run integration tests (comprehensive Docker-based testing)
# These tests use Docker containers with proper BPF capabilities
# and test real packet decapsulation with tcpdump verification
.PHONY: integration-test
integration-test: all
	@echo "Running integration tests with Docker containers..."
	@echo "This will test actual packet decapsulation on a network interface"
	@cd tests && ./run-tests.sh

# Run all tests (helper tests + BPF tests + integration tests)
.PHONY: test-all
test-all: test integration-test
	@echo ""
	@echo "=== All tests completed (helpers + BPF + integration) ==="

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

# Source files to format/lint (exclude generated files and build directory)
SOURCE_FILES := $(shell find $(SRC_DIR) -name '*.c' -o -name '*.h' | grep -v vmlinux.h | grep -v tun_decap.skel.h | grep -v build)

# Format code with clang-format
.PHONY: format
format:
	@echo "Formatting code with clang-format..."
	@clang-format -i $(SOURCE_FILES)
	@echo "Formatting complete"

# Check formatting without modifying files
.PHONY: format-check
format-check:
	@echo "Checking code formatting..."
	@clang-format --dry-run --Werror $(SOURCE_FILES) || \
		(echo "Error: Code formatting issues found. Run 'make format' to fix."; exit 1)
	@echo "Format check passed"

# Run clang-tidy linter
.PHONY: lint
lint: $(VMLINUX_H)
	@echo "Running clang-tidy linter..."
	@for file in $(filter %.c,$(SOURCE_FILES)); do \
		echo "Linting $$file..."; \
		if echo "$$file" | grep -q "$(BPF_DIR)"; then \
			clang-tidy $$file -- $(BPF_CFLAGS) || exit 1; \
		else \
			clang-tidy $$file -- $(USER_CFLAGS) || exit 1; \
		fi; \
	done
	@echo "Linting complete"

# Run clang-tidy with automatic fixes
.PHONY: lint-fix
lint-fix: $(VMLINUX_H)
	@echo "Running clang-tidy with auto-fix..."
	@for file in $(filter %.c,$(SOURCE_FILES)); do \
		echo "Linting and fixing $$file..."; \
		if echo "$$file" | grep -q "$(BPF_DIR)"; then \
			clang-tidy --fix $$file -- $(BPF_CFLAGS) || exit 1; \
		else \
			clang-tidy --fix $$file -- $(USER_CFLAGS) || exit 1; \
		fi; \
	done
	@echo "Linting and fixes complete"

# Run both format and lint checks (for CI)
.PHONY: check
check: format-check lint
	@echo "All checks passed"

# Help
.PHONY: help
help:
	@echo "XDP Tunnel Decapsulation Program Build System"
	@echo ""
	@echo "Build Targets:"
	@echo "  all               - Build everything (default)"
	@echo "  vmlinux           - Generate vmlinux.h from kernel BTF"
	@echo "  bpf               - Compile BPF program"
	@echo "  skel              - Generate BPF skeleton header"
	@echo "  test-build        - Build BPF test binary"
	@echo "  test-helpers-build- Build helper test binaries (no BPF)"
	@echo ""
	@echo "Test Targets:"
	@echo "  test-helpers      - Run helper tests (NO root required)"
	@echo "  test-bpf          - Run BPF tests (requires root)"
	@echo "  test              - Run all unit tests (helpers + BPF)"
	@echo "  integration-test  - Run Docker-based integration tests"
	@echo "  test-all          - Run all tests (unit + integration)"
	@echo ""
	@echo "Development Targets:"
	@echo "  verify            - Verify BPF program loads successfully"
	@echo "  dump              - Show BPF program disassembly"
	@echo "  btf               - Show BTF type information"
	@echo "  format            - Auto-format code with clang-format"
	@echo "  format-check      - Check code formatting without modifying"
	@echo "  lint              - Run clang-tidy linter"
	@echo "  lint-fix          - Run clang-tidy with automatic fixes"
	@echo "  check             - Run format-check and lint (for CI)"
	@echo "  clean             - Remove build artifacts"
	@echo "  rebuild           - Clean and rebuild"
	@echo "  help              - Show this help"
	@echo ""
	@echo "Requirements:"
	@echo "  - Linux kernel 5.17+ with CONFIG_DEBUG_INFO_BTF=y"
	@echo "  - clang, llvm, bpftool, libbpf-dev"
	@echo "  - clang-format, clang-tidy (for linting and formatting)"
