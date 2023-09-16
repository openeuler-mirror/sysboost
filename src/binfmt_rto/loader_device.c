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
#include "binfmt_rto.h"

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
	int i;

	loaded_seg = loaded_seg_alloc(inode);
	if (!loaded_seg)
		return -ENOMEM;
	
	for (; pos < end; ) {
		page = alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_COMP, HUGETLB_PAGE_ORDER);
		if (!page) {
			ret = -ENOMEM;
			goto error;
		}
		for (i = 0; i < 100000; i++) {
			get_page(page);
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

		if (loaded_rto->segs.next != &loaded_rto->segs) {
				// && loaded_seg->hpages.next != &loaded_seg->hpages) {
			SetPageNeedCopy(page);
			// pr_info("load_seg: SetPageNeedCopy for page: %pK\n", page);
		} else {
			get_page(page);
		}
		// if (loaded_rto->segs.next == &loaded_rto->segs || 
		// 		loaded_seg->hpages.next == &loaded_seg->hpages) {
			list_add_tail(&page->lru, &loaded_seg->hpages);
			pr_info("load_seg: load 1 hpage: 0x%pK\n",
				page);
		// }
	}

	list_add_tail(&loaded_seg->list, &loaded_rto->segs);
	return 0;
error:
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

// static void loaded_rto_put(struct loaded_rto *loaded_rto)
// {
// 	if (atomic_dec_and_test(&loaded_rto->use_count))
// 		loaded_rto_free(loaded_rto);
// }

static int preload_rto(struct file *file)
{
	int ret, i;
	struct loaded_rto *loaded_rto;
	struct inode *inode = file->f_inode;
	unsigned long size, offset;
	struct elfhdr *elf_ex;
	struct elf_phdr *elf_ppnt, *elf_phdata;
	struct file *rto_file;

	rto_file = try_get_rto_file(file);
	if (IS_ERR(rto_file)) {
		return -ENOENT;
	}

	loaded_rto = loaded_rto_alloc(inode);
	if (!loaded_rto) {
		ret = -ENOMEM;
		goto error_alloc;
	}

	elf_ex = load_bprm_buf(rto_file);
	if (IS_ERR(elf_ex)) {
		ret = PTR_ERR(elf_ex);
		goto error_bprm_buf;
	}
	elf_phdata = load_elf_phdrs(elf_ex, rto_file);
	if (!elf_phdata) {
		ret = -EIO;
		goto error_phdrs;
	}

	for(i = 0, elf_ppnt = elf_phdata; i < elf_ex->e_phnum; i++, elf_ppnt++) {
		if (elf_ppnt->p_type != PT_LOAD)
			continue;

		size = elf_ppnt->p_filesz + ELF_HPAGEOFFSET(elf_ppnt->p_vaddr);
		offset = elf_ppnt->p_offset - ELF_HPAGEOFFSET(elf_ppnt->p_vaddr);
		size = ELF_HPAGEALIGN(size);
		// pr_info("load_seg, offset: 0x%lx, size: 0x%lx\n", offset, size);
		ret = load_seg(rto_file, loaded_rto, offset, size);
		if (ret)
			goto error_seg;
	}

	list_add(&loaded_rto->list, &loaded_rtos);

	kfree(elf_phdata);
	kfree(elf_ex);
	fput(rto_file);
	return 0;

error_seg:
	kfree(elf_phdata);
error_phdrs:
	kfree(elf_ex);
error_bprm_buf:
	loaded_rto_free(loaded_rto);
error_alloc:
	fput(rto_file);
	return ret;
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

// static void unload_rto(struct inode *inode)
// {
// 	struct loaded_rto *loaded_rto;

// 	loaded_rto = find_loaded_rto(inode);
// 	if (!loaded_rto) {
// 		pr_err("inode sysboost flag is set, but cannot find loaded_rto!\n");
// 		return;
// 	}
	
// 	write_lock(&rtos_rwlock);
// 	list_del(&loaded_rto->list);
// 	write_unlock(&rtos_rwlock);

// 	loaded_rto_put(loaded_rto);
// }

static int load_rto(struct file *file, unsigned int flags)
{
	struct inode *inode = file->f_inode;
	struct loaded_rto *loaded_rto;
	int ret = 0;

	spin_lock(&inode->i_lock);
	if (!IS_SYSBOOST_RTO_SYMBOLIC_LINK(inode)) {
		ihold(inode);
		inode->i_flags |= S_SYSBOOST_RTO_SYMBOLIC_LINK;
	}
	// pr_info("lyt inode: 0x%pK, i_flags: 0x%x, i_count: %d\n",
		// inode, inode->i_flags, atomic_read(&inode->i_count));
	spin_unlock(&inode->i_lock);

	if (flags & RTO_LOAD_FLAG_PRELOAD) {
		loaded_rto = find_loaded_rto(inode);
		if (!loaded_rto)
			ret = preload_rto(file);
	}

	return ret;
}

static int unload_rto(struct file *file, unsigned int flags)
{
	struct inode *inode = file->f_inode;

	spin_lock(&inode->i_lock);
	if (IS_SYSBOOST_RTO_SYMBOLIC_LINK(inode)) {
		iput(inode);
		inode->i_flags &= ~S_SYSBOOST_RTO_SYMBOLIC_LINK;
	}
	// pr_info("lyt inode: 0x%pK, i_flags: 0x%x, i_count: %d\n",
		// inode, inode->i_flags, atomic_read(&inode->i_count));
	spin_unlock(&inode->i_lock);

	return 0;
}

static long loader_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned int flags = _IOC_NR(cmd);
	int ret = 0;
	struct fd fd;
	// struct file *rto_file;

	fd = fdget(arg);
	if (!fd.file) {
		ret = -ENOENT;
		goto out;
	}

	if (flags & RTO_LOAD_FLAG_LOAD) {
		ret = load_rto(fd.file, flags);
	} else {
		ret = unload_rto(fd.file, flags);
	}

out:
	fdput(fd);
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

	// pr_info("sysboost_loader: init success.\n");

out:
	return err;
}

void __exit loader_device_exit(void)
{
	misc_deregister(&loader_miscdev);
	// pr_info("sysboost_loader: exit!\n");
}
