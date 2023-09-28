.PHONY: all clean test

ROOT_DIR=.
SYSBOOSTD=$(ROOT_DIR)/target/debug/sysboostd
BUILD_DIR=$(ROOT_DIR)/build
SYSBOOST=$(BUILD_DIR)/src/sysboost
SYSBOOSTD_INSTALL_PATH=/usr/bin/sysboostd
SYSBOOST_INSTALL_PATH=/usr/bin/sysboost

all: sysboostd sysboost binfmt_rto

sysboostd:
	clear
	cargo build

sysboost:
	ninja -C build -v

binfmt_rto:
	make -C src/binfmt_rto || true

release:
	rm -rf Cargo.lock
	rm -rf build
	meson build

debug:
	rm -rf Cargo.lock
	rm -rf build
	meson build --buildtype=debug

clean:
	rm -rf Cargo.lock
	ninja -C build clean
	cargo clean

format:
	meson --internal clangformat ./ ./build
	cargo fmt

install:
	cp -f $(SYSBOOSTD) $(SYSBOOSTD_INSTALL_PATH)
	cp -f $(SYSBOOST) $(SYSBOOST_INSTALL_PATH)

test: sysboostd install
	clear
	./tests/test_sysboostd.py

unittest:
	cargo test -- --nocapture
