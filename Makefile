.PHONY: all clean test

BUILD_DIR=build
ELFMERGE=$(BUILD_DIR)/src/elfmerge/elfmerge
ELFMERGE_INSTALL_PATH=/usr/bin/elfmerge

all: sysboostd elfmerge sysboost_loader

sysboostd:
	cd src/sysboostd && cargo build

elfmerge:
	meson build --buildtype=debug
	ninja -C build -v

sysboost_loader:
	cd src/sysboost_loader && make -j8

release:
	rm -rf Cargo.lock
	rm -rf build
	meson build

debug:
	rm -rf Cargo.lock
	rm -rf build
	meson build --buildtype=debug

clean:
	rm -rf build
	rm -rf src/sysboostd/Cargo.lock
	cd src/sysboostd && cargo clean
	cd src/sysboost_loader && make clean

format:
	meson --internal clangformat ./ ./build
	cargo fmt

install:
	cp -f src/sysboostd/target/debug/sysboostd /usr/bin/
	cp -f $(ELFMERGE) $(ELFMERGE_INSTALL_PATH)
	mkdir -p /lib/modules/sysboost/
	cp -f src/sysboost_loader/sysboost_loader.ko /lib/modules/sysboost/
	cp -f src/sysboost.service/sysboostd_exec_stop.sh /etc/systemd/system/
	cp -f src/sysboost.service/sysboost.service /usr/lib/systemd/system/
	mkdir -p /etc/sysboost.d
	mkdir -p /usr/lib/relocation
	xz -k $(BUILD_DIR)/src/static_template/sysboost_static_template
	mv -f $(BUILD_DIR)/src/static_template/sysboost_static_template.xz /usr/lib/relocation/

test: sysboostd install
	clear
	./tests/test_sysboostd.py

unittest:
	cargo test -- --nocapture
