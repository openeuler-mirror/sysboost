// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/net_namespace.h>

#include "netlink_kernel.h"

/* Multicast group, consistent in both kernel prog and user prog. */
#define GRP_NUMBER 21

static struct sock *nl_sk = NULL;

int send_to_user(struct crash_info *msg)
{
        struct sk_buff *skb;
        struct nlmsghdr *nlh;
        int msg_size = sizeof(struct crash_info);
        int res;
        skb = nlmsg_new(NLMSG_ALIGN(msg_size), GFP_KERNEL);
        if (!skb) {
                pr_err("netlink_kernel: allocate sk_buff fail.\n");
                return -ENOMEM;
        }
        nlh = nlmsg_put(skb, 0, 1, NLMSG_DONE, msg_size, 0);
        if (!nlh) {
               pr_err("netlink_kernel: put nlmsg fail.\n"); 
               nlmsg_free(skb);
               return -EMSGSIZE;    
        }
        memcpy(nlmsg_data(nlh), msg, msg_size);
        NETLINK_CB(skb).dst_group = GRP_NUMBER;
        res = netlink_broadcast(nl_sk, skb, 0, GRP_NUMBER, GFP_KERNEL);
        if (res < 0)
                pr_info("nlmsg_multicast() error: %d\n", res);
        return res;
}

int __init nl_trans_init(void)
{
        nl_sk = netlink_kernel_create(&init_net, NETLINK_USERSOCK, NULL);
        if (!nl_sk) {
                pr_err("netlink_kernel_create failed\n");
                return -ENOMEM;
        }
        return 0;	
}

void __exit nl_trans_exit(void)
{
        netlink_kernel_release(nl_sk);  
}