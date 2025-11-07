# wf-eval/ebpf/Makefile
# Build: BPF object + user-space loader (libbpf)

BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf

# Arch mapping for __TARGET_ARCH_*
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  BPF_CFLAGS += -D__TARGET_ARCH_x86
else ifeq ($(UNAME_M),aarch64)
  BPF_CFLAGS += -D__TARGET_ARCH_arm64
else ifeq ($(UNAME_M),arm64)
  BPF_CFLAGS += -D__TARGET_ARCH_arm64
endif

# User-space
CC ?= gcc
UCFLAGS := -O2 -g -Wall
ULIBS := -lbpf -lelf -lz

# --- 修正这里 ---
# 'all' 必须包含 *所有* 你想默认编译的文件
all: packet_dropper.bpf.o dummy_generator.bpf.o loader

packet_dropper.bpf.o: packet_dropper.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# (这条规则是正确的，保持不变)
dummy_generator.bpf.o: dummy_generator.bpf.c parse_helpers.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

loader: loader.c
	$(CC) $(UCFLAGS) $< -o $@ $(ULIBS)

clean:
    # (这里你写了两行，我帮你合并成一行)
	rm -f packet_dropper.bpf.o dummy_generator.bpf.o loader
