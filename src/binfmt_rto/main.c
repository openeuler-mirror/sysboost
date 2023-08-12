// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include "main.h"
#include "loader_device.h"
#include "binfmt_rto.h"

bool use_rto = false;
module_param(use_rto, bool, 0600);
MODULE_PARM_DESC(use_rto, "use rto featue");

/* debug mode only process rto format */
int debug = 0;
module_param(debug, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "debug mode");

kallsyms_lookup_name_kprobe_t klookupf;

static int init_kallsyms_lookup_name(void)
{
	int ret;
	struct kprobe kallsyms_kprobe_var =  {
		.symbol_name = "kallsyms_lookup_name",
	};

	ret = register_kprobe(&kallsyms_kprobe_var);
	if (ret) {
		pr_err("register_kprobes returned %d\n", ret);
		return ret;
	}

	klookupf = (kallsyms_lookup_name_kprobe_t)kallsyms_kprobe_var.addr;
	unregister_kprobe(&kallsyms_kprobe_var);
	if (!klookupf) {
		pr_err("no kallsyms_lookup_name in kernel!\n");
		return -EFAULT;
	}

	return 0;
}

static int __init sysboost_loader_init(void)
{
	int ret = 0;

	ret = init_kallsyms_lookup_name();
	if (ret)
		goto error_rto;

// TODO: x86 check_vma_flags found fail
#ifdef CONFIG_ARM64
	ret = rto_populate_init();
	if (ret)
		goto error_rto;
#endif

	ret = init_rto_binfmt();
	if (ret)
		goto error_rto;

	ret = loader_device_init();
	if (ret)
		goto error_device;
	
	return 0;

error_device:
	exit_rto_binfmt();
error_rto:
	return ret;
}

static void __exit sysboost_loader_exit(void)
{
	loader_device_exit();
	exit_rto_binfmt();
}

module_init(sysboost_loader_init);
module_exit(sysboost_loader_exit);
MODULE_LICENSE("GPL");
