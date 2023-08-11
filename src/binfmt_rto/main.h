// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include <linux/module.h>
#include <linux/kprobes.h>

extern bool use_rto;
extern int debug;

typedef unsigned long (*kallsyms_lookup_name_kprobe_t)(const char *name);
extern kallsyms_lookup_name_kprobe_t klookupf;
static inline int do_init_symbols(unsigned long *func_base, char *func[], unsigned int num)
{
	unsigned int i;
	unsigned long *input_func_base = func_base;

	for (i = 0; i < num; i++) {
		*input_func_base = klookupf(func[i]);
		if (!*input_func_base) {
			pr_warn("get %s failed\n", func[i]);
			return -EEXIST;
		}
		input_func_base++;
	}

	return 0;
}
