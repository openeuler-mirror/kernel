/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __FS_CHAINS_H__
#define __FS_CHAINS_H__

#include <linux/bits.h>
#include <linux/err.h>
#include "common/fs_core.h"

struct xsc_fs_chains;

enum xsc_chains_flags {
	XSC_CHAINS_AND_PRIOS_SUPPORTED = BIT(0),
	XSC_CHAINS_IGNORE_FLOW_LEVEL_SUPPORTED = BIT(1),
	XSC_CHAINS_FT_TUNNEL_SUPPORTED = BIT(2),
};

struct xsc_chains_attr {
	enum xsc_flow_namespace_type ns;
	int fs_base_prio;
	int fs_base_level;
	u32 flags;
	u32 max_grp_num;
	struct xsc_flow_table *default_ft;
};

bool xsc_chains_prios_supported(struct xsc_fs_chains *chains);
bool xsc_chains_ignore_flow_level_supported(struct xsc_fs_chains *chains);
bool xsc_chains_backwards_supported(struct xsc_fs_chains *chains);
u32 xsc_chains_get_prio_range(struct xsc_fs_chains *chains);
u32 xsc_chains_get_chain_range(struct xsc_fs_chains *chains);
u32 xsc_chains_get_nf_ft_chain(struct xsc_fs_chains *chains);

struct xsc_flow_table *xsc_chains_get_table(struct xsc_fs_chains *chains,
					    u32 chain, u32 prio, u32 level);
void xsc_chains_put_table(struct xsc_fs_chains *chains,
			  u32 chain, u32 prio, u32 level);

struct xsc_flow_table *xsc_chains_get_tc_end_ft(struct xsc_fs_chains *chains);

struct xsc_flow_table *xsc_chains_create_global_table(struct xsc_fs_chains *chains);
void xsc_chains_destroy_global_table(struct xsc_fs_chains *chains, struct xsc_flow_table *ft);
int xsc_chains_get_chain_mapping(struct xsc_fs_chains *chains, u32 chain, u32 *chain_mapping);
int xsc_chains_put_chain_mapping(struct xsc_fs_chains *chains, u32 chain_mapping);

struct xsc_fs_chains *xsc_chains_create(struct xsc_core_device *dev, struct xsc_chains_attr *attr);
void xsc_chains_destroy(struct xsc_fs_chains *chains);

void xsc_chains_set_end_ft(struct xsc_fs_chains *chains, struct xsc_flow_table *ft);
void xsc_chains_print_info(struct xsc_fs_chains *chains);
void xsc_set_flow_attr_vport(struct xsc_eswitch *esw, u32 *flow_group_in, u16 vport);
#endif /* __FS_CHAINS_H__ */
