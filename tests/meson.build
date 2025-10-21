# SPDX-License-Identifier: MulanPSL-2.0

if arch_subdir != 'riscv'
	tests = ['test_app', 'test_simple', 'test_ifunc']
else
	tests = []
endif

foreach test:tests
	name = test
	sources = []
	includes = []
	cflags = []
	ldflags = ['-Wl,--emit-relocs', '-Wl,-z,relro,-z,now', '-pie']

	subdir(name)
endforeach
