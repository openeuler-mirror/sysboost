// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

int __init loader_device_init(void);
void __exit loader_device_exit(void);

#define S_SYSBOOST_RTO		(1 << 31) /* has rto cache */
#define IS_SYSBOOST_RTO(inode)	((inode)->i_flags & S_SYSBOOST_RTO)