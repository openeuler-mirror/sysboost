# SPDX-License-Identifier: MulanPSL-2.0

if arch_subdir == 'x86'
    cpu_arch = 'x86_64'
elif arch_subdir == 'arm'
    cpu_arch = 'aarch64'
endif

default_cflags = machine_args + ['-Wno-pointer-arith', '-Wno-pedantic']
default_ldflags = lk_args

ext_deps = []
deps = static_link_libraries

# Added -rdynamic option to trace stack information
if get_option('buildtype').contains('debug')
	# debug compile need with debuginfo
	default_cflags += [ '-pedantic', '-DPEDANTIC', '-Og', '-g', '-rdynamic' ]
	default_cflags += [ '-DDEBUG' ]
	default_ldflags += [ '-Og', '-g', '-rdynamic']
else
	default_cflags += [ '-UPEDANTIC', '-O2' ]
endif

if cc.has_argument('-Wno-format-truncation')
	default_cflags += '-Wno-format-truncation'
endif

tools = [
        'static_template',
        'libhook',
        'elfmerge',
]

default_ldflags += ['-Wl,--whole-archive', '/usr/lib64/libsi_sys.a']
default_ldflags += ['-Wl,--whole-archive', '/usr/lib64/libsi_array.a']
default_ldflags += ['-Wl,--whole-archive', '/usr/lib64/liblzma.a', '-Wl,--no-whole-archive']

foreach tool:tools
	name = tool
	sources = []
	includes = []
	cflags = default_cflags
	ldflags = default_ldflags

	subdir(name)
endforeach

