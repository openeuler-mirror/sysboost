// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#ifndef NETLINK_KERNEL_H
#define NETLINK_KERNEL_H 

#define PATH_MAX        4096
struct crash_info {
        int     len;
        char    path[PATH_MAX];
};

int send_to_user(struct crash_info *msg);
int __init nl_trans_init(void);
void __exit nl_trans_exit(void);


#endif