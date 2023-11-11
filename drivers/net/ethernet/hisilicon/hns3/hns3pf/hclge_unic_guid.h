/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2023 Hisilicon Limited.

#ifndef __HCLGE_UNIC_GUID_H
#define __HCLGE_UNIC_GUID_H

#include <linux/types.h>

#include "hclge_mbx.h"

struct hclge_dev;

struct hclge_unic_mc_guid_cfg_cmd {
	__le16 index;
	u8 vld_lookup_flag;
	u8 rsvd;
	u8 mguid[UBL_ALEN];
	__le16 ad_data;
	__le16 hit_info;
};

#define HCLGE_UNIC_BIT_NUM_PER_BD 128

#define HCLGE_UNIC_ENTRY_VLD_B 0
#define HCLGE_UNIC_LOOKUP_EN_B 1

#define HCLGE_UNIC_GUID_HIT BIT(15)

void hclge_unic_sync_mguid_table(struct hclge_dev *hdev);
void hclge_unic_uninit_mguid_table(struct hclge_dev *hdev);
int hclge_unic_set_vf_mc_guid(struct hclge_vport *vport,
			      struct hclge_mbx_vf_to_pf_cmd *mbx_req);
void hclge_unic_restore_mc_guid_table(struct hclge_vport *vport);
void hclge_unic_reset_mc_guid_space(struct hclge_dev *hdev);
void hclge_unic_del_vport_all_mc_guid_table(struct hclge_vport *vport,
					    bool is_del_list);
int hclge_unic_update_guid_list(struct hclge_vport *vport,
				enum HCLGE_COMM_ADDR_NODE_STATE state,
				const unsigned char *addr);
void hclge_unic_set_func_guid(struct hnae3_handle *handle, u8 *guid);
int hclge_unic_get_func_guid(struct hnae3_handle *handle, u8 *guid);
void hclge_unic_rm_func_guid(struct hclge_dev *hdev);

#endif
