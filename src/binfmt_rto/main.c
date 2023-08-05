// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include "main.h"
#include "loader_device.h"

bool use_rto = false;
module_param(use_rto, bool, 0600);
MODULE_PARM_DESC(use_rto, "use rto featue");

/* debug mode only process rto format */
int debug = 0;
module_param(debug, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "debug mode");

int init_rto_binfmt(void);
void exit_rto_binfmt(void);

static int __init sysboost_loader_init(void)
{
	int ret = 0;

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
