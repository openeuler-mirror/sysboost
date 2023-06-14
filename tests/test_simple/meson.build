# SPDX-License-Identifier: MulanPSL-2.0
sources = files('simple_app.c')

cflags += ['-fpic', '-pie', '-pthread', '-ldl']

executable('simple_app', sources,
        c_args: cflags,
        link_args: ldflags,
        build_rpath : './',
        dependencies: ext_deps,
        include_directories: includes)