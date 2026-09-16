/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_NEIGH_H_
#define _NSE_NEIGH_H_

#include "nse_type.h"

enum nse_neigh_update_t {
	NSE_NEIGH_NONE = 0,
	NSE_NEIGH_MAC = 1, /*neigh from connected to connected, but mac is changed*/
	NSE_NEIGH_DOWN = 2, /*neigh from connected to disconnected*/
	NSE_NEIGH_UP = 3, /*neigh from disconnected to connected*/
	NSE_NEIGH_MAX = 4,
};

struct nse_neigh {
	union {
		__be32	v4;
		struct in6_addr v6;
	} dst_ip;
	int family;
};

struct nse_neigh_entry {
	struct nse_neigh m_neigh;
	struct net_device *neigh_dev;
	struct list_head list_entry; /*attach to neigh table*/
	struct list_head encap_list; /*list head for encap entries that use this same neigh*/
	struct mutex encap_list_lock;
	refcount_t ref_cnt;
};

struct neigh_update_work {
	struct work_struct work;
	struct neighbour *n;
	struct nse_neigh_entry *neigh_entry;
	struct nse_hw *hw;
};

int
nse_encap_entry_attach_neigh(struct nse_hw *hw,
		 struct nse_sw_encap_entry *encap_entry,
		 struct nse_neigh *m_neigh, struct net_device *neigh_dev);

int
nse_encap_entry_detach_neigh(struct nse_hw *hw,
		 struct nse_sw_encap_entry *encap_entry);

int
nse_neigh_init(struct nse_hw *hw, struct nse_switchdev_info *switchdev);

void
nse_neigh_cleanup(struct nse_hw *hw, struct nse_switchdev_info *switchdev);

void
nse_neigh_dump_neigh_entry(struct nse_pf *pf);

#endif /* _NSE_NEIGH_H_ */

