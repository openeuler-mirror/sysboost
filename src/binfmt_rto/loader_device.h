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

struct loaded_rto *find_loaded_rto(struct inode *inode);
int __init loader_device_init(void);
void __exit loader_device_exit(void);

#define S_SYSBOOST_RTO_SYMBOLIC_LINK		(1 << 31) /* has rto cache */
#define IS_SYSBOOST_RTO_SYMBOLIC_LINK(inode)	((inode)->i_flags & S_SYSBOOST_RTO_SYMBOLIC_LINK)

#define RTO_LOAD_FLAG_LOAD		0x1
#define RTO_LOAD_FLAG_PRELOAD		0x2
#define RTO_LOAD_FLAG_MAX		0x100
