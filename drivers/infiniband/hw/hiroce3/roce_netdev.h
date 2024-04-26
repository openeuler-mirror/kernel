/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_NETDEV_H
#define ROCE_NETDEV_H

#include <net/ipv6.h>
#include <net/bonding.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/inetdevice.h>
#include <linux/if_vlan.h>

#include <rdma/ib_user_verbs.h>
#include <rdma/ib_addr.h>

#include "roce.h"
#include "roce_compat.h"
#include "roce_mix.h"
#include "roce_cmd.h"

#ifdef ROCE_BONDING_EN
#include "hinic3_srv_nic.h"
#endif
/* the 31 bit is vlan eable bit */
#define ROCE_GID_SET_VLAN_32BIT_VLAID(vlan_id) ((vlan_id) | (((u32)1) << 31))
#define ROCE_MAC_ADDR_LEN 6

/* ipv4 header len. unit:4B */
#define IPV4_HDR_LEN 5

#define ROCE_DEFAULT_GID_SUBNET_PREFIX 0xFE80000000000000ULL

#define ROCE_GID_MAP_TBL_IDX_GET(tunnel, tag, new_gid_type) \
	((u8)(((tunnel) << 4) | ((tag) << 2) | (new_gid_type)))

#define ROCE_GID_MAP_TBL_IDX2 2

#define ROCE_NETWORK_GID_TYPE_MAX 4

enum roce3_gid_tunnel_type {
	ROCE_GID_TUNNEL_INVALID = 0,
	ROCE_GID_TUNNEL_VALID
};

enum roce3_gid_vlan_type {
	ROCE_GID_VLAN_INVALID = 0,
	ROCE_GID_VLAN_VALID
};

struct roce3_vlan_dev_list {
	u8 mac[6];
	u32 vlan_id;
	u32 ref_cnt;
	struct net_device *net_dev;
	struct list_head list;
};

#endif /* ROCE_NETDEV_H */
