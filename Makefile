.PHONY: all clean test

SYSBOOSTD=./target/debug/sysboostd
SYSBOOST=../build/sysboost/sysboost
SYSBOOSTD_INSTALL_PATH=/usr/bin/sysboostd
SYSBOOST_INSTALL_PATH=/usr/bin/sysboost

all: sysboostd sysboost binfmt_rto

sysboostd:
	clear
	cargo build

sysboost:
	ninja -C build -v

binfmt_rto:
	make -C src/binfmt_rto

release:
	rm -rf build
	meson build

debug:
	rm -rf build
	meson build --buildtype=debug

clean:
	ninja -C build clean
	cargo clean

format:
	meson --internal clangformat ./ ./build
	cargo fmt

test: sysboostd
	clear
	cp -f $(SYSBOOSTD) $(SYSBOOSTD_INSTALL_PATH)
	cp -f $(SYSBOOST) $(SYSBOOST_INSTALL_PATH)
	cargo test

test-debug:
	cargo test -- --nocapture
