# SPDX-License-Identifier: GPL-2.0

sources = files('static_template.c')

temp_cflags = ['-O2', '-Wall', '-Wextra', '-Wformat', '-D_GNU_SOURCE', '-fno-jump-tables', '-Wl,-z,relro,-z,now', '-fpic',
            '-Bsymbolic', '-zcommon-page-size=2097152', '-zmax-page-size=2097152', '-static-pie',
            '-Wno-nonnull', '-Wno-unused-variable', '-Wno-stringop-truncation', '-Wno-unused-result',
            '-D_FORTIFY_SOURCE=2']

libc_ver=run_command('rpm', '-qi', 'glibc', check: true).stdout().strip()
# openEuler 2309
if libc_ver.contains('2.38')
        temp_cflags += ['-DGLIBC236']
endif

executable('sysboost_static_template', sources,
        install: true,
        c_args: temp_cflags,
        link_args: temp_cflags + ['-Wl,--emit-relocs', '-ldl'])
