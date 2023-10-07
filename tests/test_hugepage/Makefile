# SPDX-License-Identifier: MulanPSL-2.0

.PHONY: all

all: app

app:
	gcc -c test_hugepage.c -o test_hugepage.o
	# 编译过程找不到_start, 运行过程会coredump, 不影响测试
	ld -dynamic-linker /lib64/ld-linux-x86-64.so.2 -lc -T hugepage.x86_64.lds -zcommon-page-size=2097152 -zmax-page-size=2097152 -o test_hugepage test_hugepage.o

test: app
	./test_hugepage

clean:
	$(RM) *.o *.ro *.old *.so *.asm *.elf *.rto *.out test_hugepage
