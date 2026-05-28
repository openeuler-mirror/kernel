/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2025 - 2025, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */
#ifndef XSC_MC_HASH_H
#define XSC_MC_HASH_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/rhashtable.h>

extern bool mc_filter;

struct xsc_mc_node {
	struct rcu_head      rcu;        /* must be first，for call_rcu */
	struct rhash_head    node;
	u8                   addr[ETH_ALEN];
	atomic_t             refcnt;
};

struct xsc_mc_trace {
	u8          mac[ETH_ALEN];
	atomic_t    cnt;
	u8          enabled;
};

struct xsc_mc_hash {
	struct rhashtable     ht;
	struct dentry         *debug_dir;
	struct dentry         *debug_dump;

	struct xsc_mc_trace   trace;
	struct dentry         *debug_trace;
};

struct xsc_mc_seq_node {
	u16			bucket;
	const u8		*addr;
};

struct xsc_adapter;

int xsc_mc_hash_init(struct xsc_mc_hash *table);
int xsc_mc_hash_add(struct xsc_mc_hash *table, const u8 *addr);
int xsc_mc_hash_del(struct xsc_mc_hash *table, const u8 *addr);
void xsc_mc_hash_destroy(struct xsc_mc_hash *table);
u8 xsc_mc_hash_lookup(struct xsc_mc_hash *table, const u8 *addr);
int xsc_mc_filter_setup(struct xsc_adapter *adapter);
void xsc_mc_filter_cleanup(struct xsc_adapter *adapter);

#endif

