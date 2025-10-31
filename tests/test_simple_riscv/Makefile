# SPDX-License-Identifier: MulanPSL-2.0
ROOT_DIR=../../
BUILD_DIR=$(ROOT_DIR)build/
ELFMERGE=$(BUILD_DIR)src/elfmerge/elfmerge
TEST_APP=./main.out
LIBX=./libx.so

CC := gcc
CFLAGS := -fPIC
LDFLAGS := -Wl,-rpath=.,--emit-relocs,-pie,-z,now
SO_LDFLAGS := -shared -Wl,--emit-relocs,-z,now

all: main.out

main.out: main.o libx.so
	$(CC) $(LDFLAGS) -o $@ $< -L. -lx

libx.so: libx.o
	$(CC) $(SO_LDFLAGS) -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f main.out *.o *.so $(TEST_APP).tmp.rto

test: main.out
	@echo ===rto===
	$(ELFMERGE) --output $(TEST_APP).tmp.rto --share $(TEST_APP) $(LIBX)
	@echo ===run===
	$(TEST_APP).tmp.rto
	@echo ===done===