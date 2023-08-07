// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <asm/pgtable.h>
#include "main.h"
#include "loader_device.h"

struct loaded_seg {
	struct list_head	list;
	struct list_head	hpages;
};

struct loaded_rto {
	struct list_head	list;
	struct inode 		*inode;
	struct list_head	segs;
	atomic_t		use_count;
};

static LIST_HEAD(loaded_rtos);
static DEFINE_RWLOCK(rtos_rwlock);

static struct loaded_seg *loaded_seg_alloc(struct inode *inode)
{
	struct loaded_seg *result = kmalloc(sizeof(struct loaded_seg), GFP_KERNEL);
	if (!result)
		return result;

	INIT_LIST_HEAD(&result->list);
	INIT_LIST_HEAD(&result->hpages);

	return result;
}

static void loaded_seg_free(struct loaded_seg *loaded_seg)
{
	struct page *pos, *tmp;

	list_for_each_entry_safe(pos, tmp, &loaded_seg->hpages, lru) {
		list_del(&pos->lru);
		__free_pages(pos, HUGETLB_PAGE_ORDER);
	}
	kfree(loaded_seg);
}

static int load_seg(struct file *file, struct loaded_rto *loaded_rto,
		    unsigned long offset, unsigned long size)
{
	int ret;
	struct loaded_seg *loaded_seg;
	struct page *page;
	loff_t pos = offset, end = offset + size;
	ssize_t bytes;
	struct inode *inode = file->f_inode;

	loaded_seg = loaded_seg_alloc(inode);
	if (!loaded_seg)
		return -ENOMEM;
	
	for (;;) {
		page = alloc_pages(GFP_KERNEL | __GFP_ZERO, HUGETLB_PAGE_ORDER);
		if (!page) {
			ret = -ENOMEM;
			goto error;
		}

		bytes = kernel_read(file, page_to_virt(page), HPAGE_SIZE, &pos);
		if (bytes < 0) {
			__free_pages(page, HUGETLB_PAGE_ORDER);
			ret = bytes;
			goto error;
		} else if (bytes == 0) {
			__free_pages(page, HUGETLB_PAGE_ORDER);
			break;
		}

		list_add(&page->lru, &loaded_seg->hpages);
		pr_info("load_seg: load 1\n");
		if (pos >= end)
			break;
	}

	list_add(&loaded_seg->list, &loaded_rto->segs);
	return 0;
error:
pr_info("load_seg error: %d\n", ret);
	loaded_seg_free(loaded_seg);
	return ret;
}

static struct loaded_rto *loaded_rto_alloc(struct inode *inode)
{
	struct loaded_rto *result = kmalloc(sizeof(struct loaded_rto), GFP_KERNEL);
	if (!result)
		return result;

	INIT_LIST_HEAD(&result->list);
	INIT_LIST_HEAD(&result->segs);
	result->inode = inode;
	atomic_set(&result->use_count, 1);

	return result;
}

static void loaded_rto_free(struct loaded_rto *loaded_rto)
{
	struct loaded_seg *pos, *tmp;

	list_for_each_entry_safe(pos, tmp, &loaded_rto->segs, list) {
		list_del(&pos->list);
		loaded_seg_free(pos);
	}
	kfree(loaded_rto);
}

static void loaded_rto_put(struct loaded_rto *loaded_rto)
{
	if (atomic_dec_and_test(&loaded_rto->use_count))
		loaded_rto_free(loaded_rto);
}

static int do_load_rto(struct file *file)
{
	int ret;
	struct loaded_rto *loaded_rto;
	struct inode *inode = file->f_inode;

	loaded_rto = loaded_rto_alloc(inode);
	if (!loaded_rto)
		return -ENOMEM;

	ret = load_seg(file, loaded_rto, 0, 2*HPAGE_SIZE);
	if (ret)
		goto error;

	return 0;
error:
	loaded_rto_free(loaded_rto);
	return ret;
}

static int load_rto(struct file *file)
{
	struct inode *inode;

	inode = file->f_inode;

	do_load_rto(file);

	return 0;
}

struct loaded_rto *find_loaded_rto(struct inode *inode)
{
	struct loaded_rto *pos, *result = NULL;
	read_lock(&rtos_rwlock);
	list_for_each_entry(pos, &loaded_rtos, list)
		if (pos->inode == inode) {
			result = pos;
			break;
		}
	read_unlock(&rtos_rwlock);

	return result;
}

static void unload_rto(struct inode *inode)
{
	struct loaded_rto *loaded_rto;

	loaded_rto = find_loaded_rto(inode);
	if (!loaded_rto) {
		pr_err("inode sysboost flag is set, but cannot find loaded_rto!\n");
		return;
	}
	
	write_lock(&rtos_rwlock);
	list_del(&loaded_rto->list);
	write_unlock(&rtos_rwlock);

	loaded_rto_put(loaded_rto);
}

static int do_loader_ioctl(char *rto_path)
{
	struct file *file;
	struct inode *inode;
	struct loaded_rto *loaded_rto;

	file = filp_open(rto_path, O_LARGEFILE | O_RDONLY | __FMODE_EXEC, 0);
	if (IS_ERR(file)) {
		return PTR_ERR(file);
	}
	inode = file->f_inode;

	spin_lock(&inode->i_lock);
	if (IS_SYSBOOST_RTO(inode)) {
		iput(inode);
		inode->i_flags &= ~S_SYSBOOST_RTO;
	} else {
		ihold(inode);
		inode->i_flags |= S_SYSBOOST_RTO;
	}
	pr_info("lyt inode: 0x%pK, i_flags: 0x%x, i_count: %d\n",
		inode, inode->i_flags, atomic_read(&inode->i_count));
	spin_unlock(&inode->i_lock);


	loaded_rto = find_loaded_rto(inode);
	if (loaded_rto) {
		pr_info("lyt find original rto, release it.\n");
		unload_rto(inode);
	} else {
		load_rto(file);
	}

	filp_close(file, NULL);

	return 0;
}

static long loader_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int len = cmd;
	int ret = 0;
	char *data = kmalloc(len + 1, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = copy_from_user(data, (char *)arg, len);
	if (ret)
		goto out;
	data[len] = '\0';

	pr_info("lyt get ioctl, cmd: %d, arg: 0x%lx, data: %s\n", cmd, arg, data);

	ret = do_loader_ioctl(data);

out:
	kfree(data);
	return ret;
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
