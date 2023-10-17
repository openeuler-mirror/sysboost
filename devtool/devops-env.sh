#!/bin/bash
set -x

# compat openEuler 22.03 LTS
# update pkg >= kernel-5.10.0-60.99.0.123.oe2203

# build dependencies
sudo yum install -y gcc make meson cargo xz-devel kernel kernel-devel ncurses-devel

# rpm-build dependencies
sudo yum install -y rpm-build native-turbo-devel rust-packaging
