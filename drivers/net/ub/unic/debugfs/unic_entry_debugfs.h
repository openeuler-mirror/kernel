/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_ENTRY_DEBUGFS_H__
#define __UNIC_ENTRY_DEBUGFS_H__

#include <linux/in6.h>
#include <ub/ubase/ubase_comm_debugfs.h>

#include "unic_guid.h"

#define UNIC_BITMAP_LEN		8
#define UNIC_DBG_MAC_NUM	16
#define UNIC_DBG_MNG_NUM	8
#define UNIC_DBG_VLAN_NUM	250
#define UNIC_QUERY_MAC_LEN	(sizeof(struct unic_dbg_mac_head) + \
				 sizeof(struct unic_dbg_mac_entry) * UNIC_DBG_MAC_NUM)
#define UNIC_QUERY_MNG_LEN	(sizeof(struct unic_dbg_mng_head) + \
				 sizeof(struct unic_dbg_mng_entry) * UNIC_DBG_MNG_NUM)
#define UNIC_QUERY_VLAN_LEN	(sizeof(struct unic_dbg_vlan_head) + \
				 sizeof(struct unic_dbg_vlan_entry) * UNIC_DBG_VLAN_NUM)

struct unic_dbg_mac_entry {
	u8 mac_addr[ETH_ALEN];
	__le32 eport;
};

struct unic_dbg_mac_head {
	__le32 mac_idx;
	u8 cur_mac_cnt;
	u8 rsv[3];
	struct unic_dbg_mac_entry mac_entry[];
};

struct unic_dbg_mng_entry {
	u8 mac_mask;
	u8 ether_type_mask;
	u8 vlan_mask;
	u8 resv0;

	u8 mac[ETH_ALEN];
	u8 resv1[2];

	__le16 ether_type;
	__le16 vlan;

	u8 port_bitmap;
	u8 drop;
	__le16 jfrn;

	u8 resv2[4];
};

struct unic_dbg_mng_head {
	__le16 idx;
	u8 entry_num;
	u8 resv;
	struct unic_dbg_mng_entry entries[];
};

struct unic_dbg_vlan_entry {
	__le16 ue_id;
	__le16 vlan_id;
};

struct unic_dbg_vlan_head {
	__le16 idx;
	__le16 vlan_cnt;
	struct unic_dbg_vlan_entry vlan_entry[];
};

struct unic_dbg_vlan_node {
	struct list_head node;
	u16 ue_id;
	u16 vlan_id;
};

struct unic_dbg_comm_addr_node {
	struct list_head	node;
	u16			ue_id;
	u32			ue_bitmap[UNIC_BITMAP_LEN];
	u32			port_bitmap;
	union {
		u8		guid[UBL_ALEN];
		struct {
			struct	in6_addr ip_addr;
			u32	extend_info;
		};
		struct {
			u8 mac_addr[ETH_ALEN];
			u32	eport;
		};
	};
};

struct unic_dbg_mng_node {
	struct list_head	node;
	u8			mac_mask;
	u8			ether_type_mask;
	u8			vlan_mask;
	u8			mac[ETH_ALEN];
	u16			ether_type;
	u16			vlan;
	u8			port_bitmap;
	u8			drop;
	u16			jfrn;
};

int unic_dbg_dump_ip_tbl_spec(struct seq_file *s, void *data);
int unic_dbg_dump_mac_tbl_spec(struct seq_file *s, void *data);
int unic_dbg_dump_mc_mac_tbl_list(struct seq_file *s, void *data);
int unic_dbg_dump_uc_mac_tbl_list(struct seq_file *s, void *data);
int unic_dbg_dump_ip_tbl_list(struct seq_file *s, void *data);
int unic_dbg_dump_bond_ip_tbl_list(struct seq_file *s, void *data);
int unic_dbg_dump_vlan_tbl_list_hw(struct seq_file *s, void *data);
int unic_dbg_dump_mac_tbl_list_hw(struct seq_file *s, void *data);
int unic_dbg_dump_mng_tbl_list_hw(struct seq_file *s, void *data);

#endif /* __UNIC_ENTRY_DEBUGFS_H__ */
