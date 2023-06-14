# SPDX-License-Identifier: MulanPSL-2.0
sources = files('test_ifunc.c')

cflags += ['-fpic', '-pie', '-pthread', '-ldl', '-static-pie', '-Wl,-z,relro,-z,now']

executable('test_ifunc', sources,
        c_args: cflags,
        link_args: ldflags + cflags,
        build_rpath : './',
        dependencies: ext_deps,
        include_directories: includes)