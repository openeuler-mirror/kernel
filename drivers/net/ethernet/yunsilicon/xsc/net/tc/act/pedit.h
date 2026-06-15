/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __PEDIT_H__
#define __PEDIT_H__
#include <net/tc_act/tc_pedit.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/udp.h>
#include "../../xsc_eth.h"

struct pedit_headers {
	struct ethhdr   eth;
	struct vlan_hdr vlan;
	struct iphdr    ip4;
	struct ipv6hdr  ip6;
	struct tcphdr   tcp;
	struct udphdr   udp;
};

struct pedit_headers_action {
	struct pedit_headers vals;
	struct pedit_headers masks;
	u32 pedits;
};

int xsc_tc_act_pedit_parse_action(struct xsc_adapter *adapter,
				  const struct flow_action_entry *act, int namespace,
				  struct pedit_headers_action *hdrs,
				  struct netlink_ext_ack *extack);

#endif /* __PEDIT_H__ */
