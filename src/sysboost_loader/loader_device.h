// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

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

static inline void SetPageNeedCopy(struct page *page)
{
	SetPageOwnerPriv1(page);
}

static inline void ClearPageNeedCopy(struct page *page)
{
	ClearPageOwnerPriv1(page);
}

static inline int TestPageNeedCopy(struct page *page)
{
	return PageOwnerPriv1(page);
}

struct loaded_rto *find_loaded_rto(struct inode *inode);
int __init loader_device_init(void);
void loader_device_exit(void);
struct file *try_get_rto_file(struct file *file);
void *load_bprm_buf(struct file *file);

#define S_SYSBOOST_RTO_SYMBOLIC_LINK		(1 << 31) /* has rto cache */
#define IS_SYSBOOST_RTO_SYMBOLIC_LINK(inode)	((inode)->i_flags & S_SYSBOOST_RTO_SYMBOLIC_LINK)

#define RTO_LOAD_FLAG_LOAD		0x1
#define RTO_LOAD_FLAG_PRELOAD		0x2
#define RTO_LOAD_FLAG_MAX		0x100
