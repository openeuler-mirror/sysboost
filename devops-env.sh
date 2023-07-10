#!/bin/bash
set -x

# compat openEuler 22.03 LTS
# update pkg >= kernel-5.10.0-60.99.0.123.oe2203

# install tools
sudo yum install -y gcc make meson cargo xz-devel kernel kernel-devel ncurses-devel
