# SPDX-License-Identifier: GPL-2.0

sources = files('dlsym_hook.c')

cflags += ['-v']
ldflags += ['-ldl', '-Wl,--whole-archive', '/usr/lib64/libsi_sys.a', '-Wl,--no-whole-archive']
includes = []

deps = []

libhook = shared_library('hook', sources,
    install: true,
    c_args: cflags,
    link_args: ldflags,
    dependencies: deps,
    include_directories: includes)
