.PHONY: all clean test

SYSBOOSTD=./target/debug/sysboostd
SYSBOOST=../build/sysboost/sysboost
SYSBOOSTD_INSTALL_PATH=/usr/bin/sysboostd
SYSBOOST_INSTALL_PATH=/usr/bin/sysboost

all: sysboostd sysboost

sysboostd:
	clear
	cargo build

release:
	rm -rf build
	meson build

debug:
	rm -rf build
	meson build --buildtype=debug
	make -C sysboost

sysboost:
	ninja -C build -v

clean:
	ninja -C build clean
	make -C sysboost clean
	cargo clean

format:
	meson --internal clangformat ./ ./build
	cargo fmt

static_template_debug:
	readelf -W -a ./build/sysboost/src/static_template/static_template > static_template.elf
	objdump -d ./build/sysboost/src/static_template/static_template > static_template.asm

test: sysboostd
	clear
	cp -f $(SYSBOOSTD) $(SYSBOOSTD_INSTALL_PATH)
	cp -f $(SYSBOOST) $(SYSBOOST_INSTALL_PATH)
	cargo test

test-debug:
	cargo test -- --nocapture

bash-test: static_template_debug
	clear
	./build/sysboost/sysboost -static ./build/sysboost/src/static_template/sysboost_static_template bash/bash bash/libtinfo.so
	readelf -W -a bash.rto > bash.rto.elf
	objdump -d bash.rto > bash.rto.asm

bash-gdb:
	gdb --args ./build/sysboost/sysboost -static ./build/sysboost/src/static_template/static_template bash/bash bash/libtinfo.so