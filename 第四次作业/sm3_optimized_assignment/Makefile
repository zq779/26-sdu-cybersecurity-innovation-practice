CC ?= gcc
AR ?= ar
OBJDUMP ?= objdump
ARCH ?= $(shell uname -m)
BUILD ?= build

CPPFLAGS := -Iinclude -Isrc
COMMON_CFLAGS ?= -std=c11 -O3 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
                 -fno-strict-aliasing
LDFLAGS ?=

COMMON_SRC := src/sm3_scalar.c src/sm3_dispatch.c
COMMON_OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(COMMON_SRC))

ifeq ($(ARCH),x86_64)
ARCH_SRC := src/sm3_avx2.c src/sm3_avx512.c
ARCH_OBJ := $(BUILD)/sm3_avx2.o $(BUILD)/sm3_avx512.o
ARCH_NAME := x86_64
else ifeq ($(ARCH),amd64)
ARCH_SRC := src/sm3_avx2.c src/sm3_avx512.c
ARCH_OBJ := $(BUILD)/sm3_avx2.o $(BUILD)/sm3_avx512.o
ARCH_NAME := x86_64
else ifeq ($(ARCH),aarch64)
ARCH_SRC := src/sm3_neon.c
ARCH_OBJ := $(BUILD)/sm3_neon.o
ARCH_NAME := arm64
else
ARCH_SRC :=
ARCH_OBJ :=
ARCH_NAME := scalar
endif

LIB_OBJ := $(COMMON_OBJ) $(ARCH_OBJ)

.PHONY: all native test bench verify-openssl sanitize asm-check clean info x86 arm64 report

all: $(BUILD)/libsm3opt.a $(BUILD)/sm3_test $(BUILD)/sm3_bench $(BUILD)/sm3_cli

native: all

info:
	@echo "ARCH=$(ARCH) ARCH_NAME=$(ARCH_NAME) CC=$(CC)"
	@$(CC) --version | head -n 1

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/sm3_scalar.o: src/sm3_scalar.c include/sm3.h src/sm3_internal.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(COMMON_CFLAGS) -c $< -o $@

$(BUILD)/sm3_dispatch.o: src/sm3_dispatch.c include/sm3.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(COMMON_CFLAGS) -c $< -o $@

$(BUILD)/sm3_avx2.o: src/sm3_avx2.c include/sm3.h src/sm3_internal.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(COMMON_CFLAGS) -mavx2 -c $< -o $@

$(BUILD)/sm3_avx512.o: src/sm3_avx512.c include/sm3.h src/sm3_internal.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(COMMON_CFLAGS) -mavx512f -c $< -o $@

$(BUILD)/sm3_neon.o: src/sm3_neon.c include/sm3.h src/sm3_internal.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(COMMON_CFLAGS) -march=armv8-a+simd -c $< -o $@

$(BUILD)/libsm3opt.a: $(LIB_OBJ)
	$(AR) rcs $@ $^

$(BUILD)/test_sm3.o: tests/test_sm3.c include/sm3.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(COMMON_CFLAGS) -c $< -o $@

$(BUILD)/bench_sm3.o: bench/bench_sm3.c include/sm3.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(COMMON_CFLAGS) -c $< -o $@

$(BUILD)/sm3_cli.o: tools/sm3_cli.c include/sm3.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(COMMON_CFLAGS) -c $< -o $@

$(BUILD)/sm3_test: $(BUILD)/test_sm3.o $(BUILD)/libsm3opt.a
	$(CC) $^ -o $@ $(LDFLAGS)

$(BUILD)/sm3_bench: $(BUILD)/bench_sm3.o $(BUILD)/libsm3opt.a
	$(CC) $^ -o $@ $(LDFLAGS)

$(BUILD)/sm3_cli: $(BUILD)/sm3_cli.o $(BUILD)/libsm3opt.a
	$(CC) $^ -o $@ $(LDFLAGS)

test: $(BUILD)/sm3_test
	./$(BUILD)/sm3_test

bench: $(BUILD)/sm3_bench
	./$(BUILD)/sm3_bench 4096 256

verify-openssl: $(BUILD)/sm3_cli
	./scripts/verify_openssl.py

sanitize:
	$(MAKE) clean
	$(MAKE) COMMON_CFLAGS='-std=c11 -O1 -g -Wall -Wextra -Wpedantic -Wshadow -fno-omit-frame-pointer -fsanitize=address,undefined' LDFLAGS='-fsanitize=address,undefined' test

asm-check: all
ifeq ($(ARCH_NAME),x86_64)
	$(OBJDUMP) -d -Mintel $(BUILD)/sm3_avx2.o > $(BUILD)/sm3_avx2.asm
	$(OBJDUMP) -d -Mintel $(BUILD)/sm3_avx512.o > $(BUILD)/sm3_avx512.asm
	@echo 'AVX2 evidence:'
	@grep -Ei 'ymm|vpaddd|vpxor|vpslld|vpsrld' $(BUILD)/sm3_avx2.asm | head -n 16 || true
	@echo 'AVX-512 evidence:'
	@grep -Ei 'zmm|vpternlogd|vpaddd|vpxord|k[0-7]' $(BUILD)/sm3_avx512.asm | head -n 16 || true
else ifeq ($(ARCH_NAME),arm64)
	$(OBJDUMP) -d $(BUILD)/sm3_neon.o > $(BUILD)/sm3_neon.asm
	@grep -Ei 'v[0-9]+\\.4s|eor|add|ushl|orr|bsl' $(BUILD)/sm3_neon.asm | head -n 24 || true
else
	@echo 'No SIMD backend for ARCH=$(ARCH)'
endif

x86:
	$(MAKE) clean
	$(MAKE) ARCH=x86_64 all

AARCH64_CC ?= aarch64-linux-gnu-gcc
AARCH64_AR ?= aarch64-linux-gnu-ar
AARCH64_OBJDUMP ?= aarch64-linux-gnu-objdump
arm64:
	$(MAKE) clean
	$(MAKE) ARCH=aarch64 CC=$(AARCH64_CC) AR=$(AARCH64_AR) OBJDUMP=$(AARCH64_OBJDUMP) all

report:
	python /home/oai/skills/pdfs/scripts/latex_to_pdf.py report/report.tex -o report/SM3软件实现与优化实验报告.pdf --engine xelatex

clean:
	rm -rf $(BUILD)
