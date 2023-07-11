# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../
BUILD_DIR=$(ROOT_DIR)build
SYSBOOST=$(BUILD_DIR)/src/sysboost
RELOCATION_DIR=/usr/lib/relocation

TEMPLATE_FILE=$(BUILD_DIR)/src/static_template/sysboost_static_template
TEMPLATE_FILE_PUB_PATH=$(RELOCATION_DIR)/sysboost_static_template.relocation

BASH=/usr/bin/bash
BASH_R=$(RELOCATION_DIR)$(BASH).relocation

LIBC=/usr/lib64/libc.so.6
LIBC_R=$(RELOCATION_DIR)$(LIBC).relocation

VERSION_ID=$(shell cat /etc/os-release | grep VERSION_ID)
ifeq ($(VERSION_ID), VERSION_ID="22.03")
LIBTINFO=/usr/lib64/libtinfo.so.6
LIBTINFO_R=$(RELOCATION_DIR)$(LIBTINFO).3.relocation
else
LIBTINFO=/usr/lib64/libtinfo.so.7
LIBTINFO_R=$(RELOCATION_DIR)$(LIBTINFO).relocation
endif

ARCH=$(shell uname -m)
ifeq ($(ARCH), aarch64)
	LIBLD=/lib/ld-linux-aarch64.so.1
else
	LIBLD=/lib64/ld-linux-x86-64.so.2
endif

MODE?=--static-nold
#MODE=--static-nolibc

.PHONY: all

all: bash

ifeq ($(MODE), --static-nold)
# --static-nold
bash:
	clear
	make -C $(ROOT_DIR)
	@echo ===rto===
	$(SYSBOOST) $(MODE) $(BASH) $(LIBTINFO) $(LIBC)
	readelf -W -a $(BASH).rto > bash.rto.elf
	objdump -d $(BASH).rto > bash.rto.asm
	@echo ===run===
	$(BASH).rto -c "echo 1"

rto:
	gdb --args $(SYSBOOST) $(MODE) $(BASH) $(LIBTINFO) $(LIBC)

else

# static-nolibc
bash:
	clear
	readelf -W -a $(TEMPLATE_FILE) > sysboost_static_template.elf
	objdump -d $(TEMPLATE_FILE) > sysboost_static_template.asm
	make -C $(ROOT_DIR)
	xz $(TEMPLATE_FILE)
	mv -f $(TEMPLATE_FILE).xz $(TEMPLATE_FILE_PUB_PATH)
	@echo ===rto===
	$(SYSBOOST) $(MODE) $(BASH) $(LIBTINFO)
	readelf -W -a $(BASH).rto > bash.rto.elf
	objdump -d $(BASH).rto > bash.rto.asm
	@echo ===run===
	$(BASH).rto -c "echo 1"

rto:
	gdb --args $(SYSBOOST) $(MODE) $(BASH) $(LIBTINFO)

endif

run:
	gdb --args $(BASH).rto -c "echo 1"

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space
	readelf -W -a $(BASH_R) > bash.elf
	objdump -d $(BASH_R) > bash.asm
	readelf -W -a $(LIBC_R) > libc.so.elf
	objdump -d $(LIBC_R) > libc.so.asm
	readelf -W -a $(LIBTINFO_R) > libtinfo.so.elf
	objdump -d $(LIBTINFO_R) > libtinfo.so.asm
	readelf -W -a $(LIBLD) > ld.so.elf
	objdump -d $(LIBLD) > ld.so.asm
