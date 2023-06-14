# SPDX-License-Identifier: MulanPSL-2.0

tests = ['test_app', 'test_simple', 'test_ifunc']

foreach test:tests
	name = test
	sources = []
	includes = []
	cflags = []
	ldflags = ['-Wl,--emit-relocs', '-Wl,-z,relro,-z,now']

	subdir(name)
endforeach