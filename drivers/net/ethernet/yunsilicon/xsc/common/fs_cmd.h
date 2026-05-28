/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef _XSC_FS_CMD_
#define _XSC_FS_CMD_

#include "common/fs_core.h"

enum {
	XSC_FLOW_CONTEXT_ACTION_ALLOW     = 0x1,
	XSC_FLOW_CONTEXT_ACTION_DROP      = 0x2,
	XSC_FLOW_CONTEXT_ACTION_FWD_DEST  = 0x4,
	XSC_FLOW_CONTEXT_ACTION_COUNT     = 0x8,
	XSC_FLOW_CONTEXT_ACTION_PACKET_REFORMAT = 0x10,
	XSC_FLOW_CONTEXT_ACTION_DECAP     = 0x20,
	XSC_FLOW_CONTEXT_ACTION_MOD_HDR   = 0x40,
	XSC_FLOW_CONTEXT_ACTION_VLAN_POP  = 0x80,
	XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH = 0x100,
	XSC_FLOW_CONTEXT_ACTION_VLAN_POP_2  = 0x400,
	XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH_2 = 0x800,
	XSC_FLOW_CONTEXT_ACTION_EXECUTE_ASO = 0x1000,
};

enum {
	XSC_FLOW_CONTEXT_FLOW_SOURCE_ANY_VPORT         = 0x0,
	XSC_FLOW_CONTEXT_FLOW_SOURCE_UPLINK            = 0x1,
	XSC_FLOW_CONTEXT_FLOW_SOURCE_LOCAL_VPORT       = 0x2,
};

enum xsc_ifc_flow_destination_type {
	XSC_IFC_FLOW_DESTINATION_TYPE_VPORT        = 0x0,
	XSC_IFC_FLOW_DESTINATION_TYPE_FLOW_TABLE   = 0x1,
	XSC_IFC_FLOW_DESTINATION_TYPE_TIR          = 0x2,
	XSC_IFC_FLOW_DESTINATION_TYPE_FLOW_SAMPLER = 0x6,
	XSC_IFC_FLOW_DESTINATION_TYPE_UPLINK       = 0x8,
	XSC_IFC_FLOW_DESTINATION_TYPE_TABLE_TYPE   = 0xA,
};

struct xsc_flow_cmds {
	int (*create_flow_table)(struct xsc_core_device *dev,
				 struct xsc_flow_table *ft,
				 struct xsc_flow_table_attr *ft_attr,
				 struct xsc_flow_table *next_ft);
	int (*destroy_flow_table)(struct xsc_core_device *dev,
				  struct xsc_flow_table *ft);

	int (*modify_flow_table)(struct xsc_core_device *dev,
				 struct xsc_flow_table *ft,
				 struct xsc_flow_table *next_ft);

	int (*create_flow_group)(struct xsc_core_device *dev,
				 struct xsc_flow_table *ft,
				 u32 *in,
				 struct xsc_flow_group *fg);

	int (*destroy_flow_group)(struct xsc_core_device *dev,
				  struct xsc_flow_table *ft,
				  struct xsc_flow_group *fg);

	int (*create_fte)(struct xsc_core_device *dev,
			  struct xsc_flow_table *ft,
			  struct xsc_flow_group *fg,
			  struct fs_fte *fte);

	int (*update_fte)(struct xsc_core_device *dev,
			  struct xsc_flow_table *ft,
			  struct xsc_flow_group *fg,
			  int modify_mask,
			  struct fs_fte *fte);

	int (*delete_fte)(struct xsc_core_device *dev,
			  struct xsc_flow_table *ft,
			  struct fs_fte *fte);

	int (*update_root_ft)(struct xsc_core_device *dev,
			      struct xsc_flow_table *ft,
			      u32 underlay_qpn,
			      bool disconnect);

	int (*packet_reformat_alloc)(struct xsc_core_device *dev,
				     struct xsc_pkt_reformat_params *params,
				     enum xsc_flow_namespace_type namespace,
				     struct xsc_pkt_reformat *pkt_reformat);

	void (*packet_reformat_dealloc)(struct xsc_core_device *dev,
					struct xsc_pkt_reformat *pkt_reformat);

	int (*modify_header_alloc)(struct xsc_core_device *dev,
				   u8 namespace, u8 num_actions,
				   void *modify_actions,
				   struct xsc_modify_hdr *modify_hdr);

	void (*modify_header_dealloc)(struct xsc_core_device *dev,
				      struct xsc_modify_hdr *modify_hdr);

	int (*set_peer)(struct xsc_flow_root_namespace *ns,
			struct xsc_flow_root_namespace *peer_ns,
			u16 peer_vhca_id);

	int (*create_ns)(struct xsc_flow_root_namespace *ns);
	int (*destroy_ns)(struct xsc_flow_root_namespace *ns);

	u32 (*get_capabilities)(struct xsc_core_device *dev,
				enum fs_flow_table_type ft_type);
};

#ifdef CONFIG_XSC_OFFLOAD_COUNTER
int xsc_flow_fc_alloc(struct xsc_core_device *dev, u32 *id);
int xsc_flow_fc_bulk_alloc(struct xsc_core_device *dev,
			   enum xsc_fc_bulk_alloc_bitmask alloc_bitmask,
			   u32 *id);
int xsc_flow_fc_free(struct xsc_core_device *dev, u32 id, u32 bulk_len);
int xsc_flow_fc_query(struct xsc_core_device *dev, u32 id,
		      u64 *packets, u64 *bytes, bool clear);

int xsc_flow_fc_get_bulk_query_out_len(int bulk_len);
int xsc_flow_fc_bulk_query(struct xsc_core_device *dev, u32 base_id, u32 bulk_len,
			   u32 *out);
#endif
int xsc_flow_create_fte(struct xsc_core_device *dev, struct xsc_flow_table *ft,
			struct xsc_flow_group *group, struct fs_fte *fte);
int xsc_flow_create_group(struct xsc_core_device *dev, struct xsc_flow_table *ft,
			  u32 *in, struct xsc_flow_group *fg);

static inline u32 xsc_fs_action_get_pkt_reformat_id(struct xsc_pkt_reformat *pkt_reformat)
{
	return 0;
}

const struct xsc_flow_cmds *xsc_fs_cmd_get_default(enum fs_flow_table_type type);
const struct xsc_flow_cmds *xsc_fs_cmd_get_fw_cmds(void);

#endif
