/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __xsc_EN_MOD_HDR_H__
#define __xsc_EN_MOD_HDR_H__

#include <linux/hashtable.h>
#include "common/xsc_core.h"
#include "common/fs_core.h"

#define XSC_FDB_MAX_MODIFY_HEADER_ACTIONS    256
#define XSC_NIC_RX_MAX_MODIFY_HEADER_ACTIONS 128

#define XSC_MH_ACT_SZ XSC_ST_SZ_BYTES(set_action_in)

struct mod_hdr_key {
	int num_actions;
	void *actions;
};

struct xsc_mod_hdr_handle {
	/* a node of a hash table which keeps all the mod_hdr entries */
	struct hlist_node mod_hdr_hlist;

	struct mod_hdr_key key;

	struct xsc_modify_hdr *modify_hdr;

	refcount_t refcnt;
	struct completion res_ready;
	int compl_result;
};

struct xsc_tc_mod_hdr_acts {
	int num_actions;
	int max_actions;
	bool is_static;
	void *actions;
};

#define DECLARE_MOD_HDR_ACTS_ACTIONS(name, len) \
	u8 name[len][XSC_MH_ACT_SZ] = {}

#define DECLARE_MOD_HDR_ACTS(name, acts_arr) \
	struct xsc_tc_mod_hdr_acts name = { \
		.max_actions = ARRAY_SIZE(acts_arr), \
		.is_static = true, \
		.actions = acts_arr, \
	}

char *xsc_mod_hdr_alloc(struct xsc_core_device *xdev, int namespace,
			struct xsc_tc_mod_hdr_acts *mod_hdr_acts);
void xsc_mod_hdr_dealloc(struct xsc_tc_mod_hdr_acts *mod_hdr_acts);
char *xsc_mod_hdr_get_item(struct xsc_tc_mod_hdr_acts *mod_hdr_acts, int pos);

struct xsc_mod_hdr_handle *
xsc_mod_hdr_attach(struct xsc_core_device *xdev,
		   struct mod_hdr_tbl *tbl,
		   enum xsc_flow_namespace_type namespace,
		   struct xsc_tc_mod_hdr_acts *mod_hdr_acts);
void xsc_mod_hdr_detach(struct xsc_core_device *xdev,
			struct mod_hdr_tbl *tbl,
			struct xsc_mod_hdr_handle *mh);
struct xsc_modify_hdr *xsc_mod_hdr_get(struct xsc_mod_hdr_handle *mh);

void xsc_mod_hdr_tbl_init(struct mod_hdr_tbl *tbl);
void xsc_mod_hdr_tbl_destroy(struct mod_hdr_tbl *tbl);

char *xsc_get_mod_action_item(struct mod_hdr_key *action_key, int pos);

static inline int xsc_mod_hdr_max_actions(struct xsc_core_device *xdev, int namespace)
{
	if (namespace == XSC_FLOW_NAMESPACE_FDB) /* FDB offloading */
		return XSC_FDB_MAX_MODIFY_HEADER_ACTIONS;
	else /* namespace is XSC_FLOW_NAMESPACE_KERNEL - NIC offloading */
		return XSC_NIC_RX_MAX_MODIFY_HEADER_ACTIONS;
}

#endif /* __xsc_EN_MOD_HDR_H__ */
