# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../
BUILD_DIR=$(ROOT_DIR)build/
SYSBOOST=$(BUILD_DIR)src/sysboost
KO_DIR=$(ROOT_DIR)src/sysboost_loader

.PHONY: all

all: test_ko

link:
	cp -f /usr/bin/bash bash_test_link
	$(SYSBOOST) --set bash_test_link
	readelf -W -a bash_test_link > bash_test_link.link.elf

test_ko: link
	make -C $(KO_DIR) install
	@echo ===test link===
	cp -f /usr/bin/bash bash_test_link.rto
	./bash_test_link -c "echo 1"
	@echo ===test rto===
	$(SYSBOOST) --set-rto bash_test_link.rto
	readelf -W -a bash_test_link.rto > bash_test_link.rto.elf
	./bash_test_link -c "echo 1"

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space

clean:
	$(RM) *.o *.ro *.old *.so *.asm *.elf *.rto *.out bash_test_link
