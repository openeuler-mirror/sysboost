# SPDX-License-Identifier: GPL-2.0

if arch_subdir == 'x86'
    cpu_arch = 'x86_64'
elif arch_subdir == 'arm'
    cpu_arch = 'aarch64'
endif

tools = [
        'static_template',
        'libhook'
]

default_cflags = machine_args + ['-Wno-pointer-arith', '-Wno-pedantic']
default_ldflags = lk_args

ext_deps = []
deps = static_link_libraries

if get_option('buildtype').contains('debug')
	default_cflags += [ '-pedantic', '-DPEDANTIC', '-Og', '-g', '-rdynamic' ]
	default_ldflags += ['-rdynamic']
else
	default_cflags += [ '-UPEDANTIC', '-O2' ]
endif

if cc.has_argument('-Wno-format-truncation')
	default_cflags += '-Wno-format-truncation'
endif

foreach tool:tools
	name = tool
	sources = []
	includes = []
	cflags = default_cflags
	ldflags = default_ldflags

	subdir(name)
endforeach

default_ldflags += ['-Wl,--whole-archive', '/usr/lib64/libsi_sys.a']
default_ldflags += ['-Wl,--whole-archive', '/usr/lib64/libsi_array.a']
default_ldflags += ['-Wl,--whole-archive', '/usr/lib64/liblzma.a', '-Wl,--no-whole-archive']

core_sources = files([
                'main.c',
                'elf_link_elf.c',
                'elf_read_elf.c',
                'elf_read_elf_xz.c',
                'elf_hugepage.c',
                'elf_link_common.c',
                'elf_relocation.c',
                'elf_relocation_' + cpu_arch + '.c',
                'elf_check_elf.c',
                'elf_write_elf.c',
                ])

cflags += ['-fpic', '-pie']

executable('sysboost', core_sources,
        install: true,
        c_args: default_cflags,
        link_args: default_ldflags,
        dependencies: deps,
        include_directories: includes)