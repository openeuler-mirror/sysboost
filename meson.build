# SPDX-License-Identifier: MulanPSL-2.0

project('SYSBOOST', 'C',
        version: run_command(find_program('cat', 'more'), files('VERSION'), check: true).stdout().strip(),
        license: 'MulanPSL',
        default_options: [
            'buildtype=release',
            'default_library=static',
            'warning_level=2',
        ],
        meson_version: '>= 0.49.2'
)

# set up some global vars for compiler, platform, configuration, etc.
static_link_libraries = []
cc = meson.get_compiler('c')
si_source_root = meson.current_source_dir()
si_build_root = meson.current_build_dir()
si_static_libraries = []
abi_version_file = files('ABI_VERSION')

if host_machine.cpu_family().startswith('x86')
    arch_subdir = 'x86'
elif host_machine.cpu_family().startswith('arm') or host_machine.cpu_family().startswith('aarch')
    arch_subdir = 'arm'
elif host_machine.cpu_family().startswith('riscv')
    arch_subdir = 'riscv'
endif

machine_args = ['-Wall', '-Werror', '-Wextra', '-Wformat', '-D_GNU_SOURCE',
                '-fno-jump-tables', '-Wl,-z,relro,-z,now', '-Bsymbolic', '-zcommon-page-size=2097152', '-zmax-page-size=2097152']
lk_args = []

# build sysboost
subdir('src')

# build tests
subdir('tests')