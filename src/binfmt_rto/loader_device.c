// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include <linux/miscdevice.h>
#include <linux/slab.h>
#include "main.h"

static long loader_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int len = cmd;
	int ret;
	char *data = kmalloc(len, GFP_KERNEL);
	ret = copy_from_user(data, (char *)arg, len);
	if (ret)
		return ret;


	pr_info("lyt get ioctl, cmd: %d, arg: 0x%lx, data: %s\n", cmd, arg, data);

	return 0;
}

static const struct file_operations loader_fops = {
	.owner	= THIS_MODULE,
	.unlocked_ioctl = loader_ioctl,
	.compat_ioctl	= loader_ioctl,
};

static struct miscdevice loader_miscdev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "sysboost_loader",
	.fops	= &loader_fops,
};

int __init loader_device_init(void)
{
	int err = misc_register(&loader_miscdev);
	if (err != 0) {
		pr_err("sysboost_loader: init failed!\n");
		goto out;
	}

	pr_info("sysboost_loader: init success.\n");

out:
	return err;
}

void __exit loader_device_exit(void)
{
	misc_deregister(&loader_miscdev);
	pr_info("sysboost_loader: exit!\n");
}
