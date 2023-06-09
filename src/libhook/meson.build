# SPDX-License-Identifier: GPL-2.0

sources = files('dlsym_hook.c')

cflags += ['-v']
ldflags += ['-ldl']
includes = []

deps = []

libhook = shared_library('hook', sources,
    install: true,
    c_args: cflags,
    link_args: ldflags,
    link_with: link_libs,
    dependencies: deps,
    include_directories: includes)
