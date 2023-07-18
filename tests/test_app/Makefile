# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../
BUILD_DIR=$(ROOT_DIR)build/
SYSBOOST=$(BUILD_DIR)src/sysboost
TEST_APP=$(BUILD_DIR)tests/test_app/test_app
LIB1=$(BUILD_DIR)tests/test_app/libutil1.so
LIB2=$(BUILD_DIR)tests/test_app/libutil2.so

LIBHOOK=$(BUILD_DIR)src/libhook/libhook.so
LIBHOOK_R=/usr/lib/relocation/libhook.so.relocation

LIBC=/usr/lib64/libc.so.6
LIBC_R=/usr/lib/relocation$(LIBC).relocation

MODE?=--static-nold
#MODE=--static-nolibc

.PHONY: all

all: test-s

prepare:
	make -C $(ROOT_DIR)
	readelf -W -a $(TEST_APP) > test_app.elf
	objdump -d $(TEST_APP) > test_app.asm
	readelf -W -a $(LIB1) > libutil1.so.elf
	objdump -d $(LIB1) > libutil1.so.asm
	cp $(LIB1) .

# share mode, --hook
hook: prepare
	readelf -W -a $(LIBHOOK) > libhook.so.elf
	objdump -d $(LIBHOOK) > libhook.so.asm
	clear
	xz $(LIBHOOK)
	mv -f $(LIBHOOK).xz $(LIBHOOK_R)
	@echo ===rto1===
	$(SYSBOOST) --hook $(TEST_APP) $(LIB1) $(LIB2)
	readelf -W -a $(TEST_APP).rto > test_app.rto.elf
	objdump -d $(TEST_APP).rto > test_app.rto.asm
	@echo ===run_ori===
	$(TEST_APP) -dlsym
	@echo ===run1===
	$(TEST_APP).rto -dlsym

rto1:
	gdb --args $(SYSBOOST) --hook $(TEST_APP) $(LIB1) $(LIB2)

run1:
	gdb --args ./test_app.rto -dlsym

# static mode
test-s: prepare
	clear
	@echo ===rto===
	$(SYSBOOST) $(MODE) $(TEST_APP) $(LIB1) $(LIB2) $(LIBC)
	readelf -W -a $(TEST_APP).rto > test_app.rto.elf
	objdump -d $(TEST_APP).rto > test_app.rto.asm
	@echo ===old===
	$(TEST_APP)
	@echo ===run===
	$(TEST_APP).rto

rto:
	gdb --args $(SYSBOOST) $(MODE) $(TEST_APP) $(LIB1) $(LIB2) $(LIBC)

run:
	gdb --args $(TEST_APP).rto

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space
	readelf -W -a $(LIBC) > libc.so.elf
	objdump -d $(LIBC) > libc.so.asm

clean:
	$(RM) *.o *.ro *.old *.so *.asm *.elf *.rto *.out test_app
