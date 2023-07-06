/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <stdio.h>

int run_b(int a, int b)
{
	printf("call local ELF func %d\n", 123);

	return a + b;
}
