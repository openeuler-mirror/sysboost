# SPDX-License-Identifier: GPL-2.0

core_sources = files(
        [
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
		'elf_instruction.c',
        ]
)

cflags += ['-fpic', '-pie']

executable(
        'elfmerge', core_sources,
        install: true,
        install_dir: '/usr/bin',
        c_args: default_cflags,
        link_args: default_ldflags,
        dependencies: deps,
        include_directories: includes
)