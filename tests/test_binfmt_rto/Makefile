# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../
BUILD_DIR=$(ROOT_DIR)build/
SYSBOOST=$(BUILD_DIR)src/sysboost
KO_DIR=$(ROOT_DIR)src/binfmt_rto

.PHONY: all

all: test_ko

link:
	cp /usr/bin/ls ls_test_link
	$(SYSBOOST) --set ls_test_link
	readelf -W -a ls_test_link > ls_test_link.link.elf

test_ko: link
	make -C $(KO_DIR) install
	cp /usr/bin/ls ls_test_link.rto
	./ls_test_link

env:
	echo 0 > /proc/sys/kernel/randomize_va_space
	cat /proc/sys/kernel/randomize_va_space

clean:
	$(RM) *.o *.ro *.old *.so *.asm *.elf *.rto *.out ls_test_link
