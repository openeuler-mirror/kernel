// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2024-2024 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include "hclge_comm_unic_addr.h"
#include "hclge_debugfs.h"
#include "hclge_unic_debugfs.h"

int hclge_dbg_dump_ip_spec(struct hclge_dev *hdev, char *buf, int len)
{
	struct unic_ip_table_info *iptbl_info = &hdev->iptbl_info;
	u8 func_num = pci_num_vf(hdev->pdev) + 1;
	struct hclge_vport *vport;
	int pos = 0;
	u8 i;

	pos += scnprintf(buf, len, "num_alloc_vport       : %u\n",
			 hdev->num_alloc_vport);
	pos += scnprintf(buf + pos, len - pos, "max_ip_table_size     : %u\n",
			 iptbl_info->max_iptbl_size);
	pos += scnprintf(buf + pos, len - pos, "priv_ip_table_size    : %u\n",
			 iptbl_info->priv_iptbl_size);

	mutex_lock(&hdev->vport_lock);
	pos += scnprintf(buf + pos, len - pos, "share_ip_table_size   : %u\n",
			 iptbl_info->share_iptbl_size);
	for (i = 0; i < func_num; i++) {
		vport = &hdev->vport[i];
		pos += scnprintf(buf + pos, len - pos,
				 "vport(%u) used_ip_table_num : %u\n",
				 i, vport->used_iptbl_num);
	}
	mutex_unlock(&hdev->vport_lock);

	return 0;
}

int hclge_dbg_dump_guid_spec(struct hclge_dev *hdev, char *buf, int len)
{
	u16 mc_guid_tbl_size;

	mc_guid_tbl_size = hclge_unic_real_mguid_tbl_size(hdev);
	scnprintf(buf, len, "function guid tbl size: %u\nmc guid tbl size: %u\n",
		  HCLGE_VPORT_NUM, mc_guid_tbl_size);

	return 0;
}

#define HCLGE_UNIC_DBG_DATA_STR_LEN	50
#define HCLGE_UNIC_IPV6_LEN		16

static const struct hclge_dbg_item ip_list_items[] = {
	{ "FUNC_ID", 2 },
	{ "IP_ADDR", 34 },
	{ "STATE", 2 },
};

static const char * const hclge_unic_entry_state_str[] = {
	"TO_ADD", "TO_DEL", "ACTIVE"
};

int hclge_dbg_dump_ip_list(struct hclge_dev *hdev, char *buf, int len)
{
	char data_str[ARRAY_SIZE(ip_list_items)][HCLGE_UNIC_DBG_DATA_STR_LEN];
	char content[HCLGE_DBG_INFO_LEN], str_id[HCLGE_DBG_ID_LEN];
	struct hclge_comm_unic_addr_node *ip_node, *tmp;
	char *result[ARRAY_SIZE(ip_list_items)];
	struct hclge_vport *vport;
	struct list_head *list;
	u16 used_iptbl_num = 0;
	u32 func_id;
	int pos = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(ip_list_items); i++)
		result[i] = &data_str[i][0];

	for (i = 0; i < hdev->num_alloc_vport; i++)
		used_iptbl_num += hdev->vport[i].used_iptbl_num;

	pos += scnprintf(buf + pos, len - pos, "used ip number: %u\n",
			 used_iptbl_num);

	hclge_dbg_fill_content(content, sizeof(content), ip_list_items,
			       NULL, ARRAY_SIZE(ip_list_items));
	pos += scnprintf(buf + pos, len - pos, "%s", content);

	for (func_id = 0; func_id < hdev->num_alloc_vport; func_id++) {
		vport = &hdev->vport[func_id];
		list = &vport->ip_list;
		spin_lock_bh(&vport->ip_list_lock);
		list_for_each_entry_safe(ip_node, tmp, list, node) {
			i = 0;
			result[i++] = hclge_dbg_get_func_id_str(str_id,
								func_id);
			sprintf(result[i++], "%pI6c", &ip_node->ip_addr.s6_addr);
			sprintf(result[i++], "%5s",
				hclge_unic_entry_state_str[ip_node->state]);
			hclge_dbg_fill_content(content, sizeof(content),
					       ip_list_items,
					       (const char **)result,
					       ARRAY_SIZE(ip_list_items));

			if (len - pos < strlen(content)) {
				spin_unlock_bh(&vport->ip_list_lock);
				dev_warn(&hdev->pdev->dev,
					 "Warning: IP list debugfs buffer overflow.\n");
				return 0;
			}

			pos += scnprintf(buf + pos, len - pos, "%s", content);
		}
		spin_unlock_bh(&vport->ip_list_lock);
	}
	return 0;
}

int hclge_dbg_dump_guid_list(struct hclge_dev *hdev, char *buf, int len)
{
#define HCLGE_UNIC_GUID_DUMP_SIZE 68

	char format_guid_addr[HCLGE_COMM_FORMAT_GUID_ADDR_LEN];
	struct hclge_comm_unic_addr_node *guid_node, *tmp;
	char str_id[HCLGE_DBG_ID_LEN];
	struct hclge_vport *vport;
	struct list_head *list;
	u16 func_id;
	int pos = 0;
	u16 i;

	pos += scnprintf(buf + pos, len - pos, "used mc guid number: %u\n",
			 hdev->used_mc_guid_num);
	pos += scnprintf(buf + pos, len - pos, "mc guid table bitmap: ");
	for (i = 0; i < BITS_TO_LONGS(HCLGE_UNIC_MC_GUID_NUM); i++)
		pos += scnprintf(buf + pos, len - pos, "%lx ",
				 hdev->mc_guid_tbl_bmap[i]);
	pos += scnprintf(buf + pos, len - pos, "\nMC GUID LIST:\n");
	pos += scnprintf(buf + pos, len - pos, "No. FUNC_ID %-48s STATE\n", "MC_GUID");
	for (func_id = 0, i = 0; func_id < hdev->num_alloc_vport; func_id++) {
		vport = &hdev->vport[func_id];
		list = &vport->mc_guid_list;
		spin_lock_bh(&vport->mguid_list_lock);
		list_for_each_entry_safe(guid_node, tmp, list, node) {
			if (len - pos < HCLGE_UNIC_GUID_DUMP_SIZE) {
				spin_unlock_bh(&vport->mguid_list_lock);
				dev_warn(&hdev->pdev->dev,
					 "Warning: GUID list debugfs buffer overflow.\n");
				return 0;
			}

			hclge_comm_format_guid_addr(format_guid_addr,
						    guid_node->mguid);
			pos += scnprintf(buf + pos, len - pos,
					 "%-3d %-7s %-48s %s\n", i++,
					 hclge_dbg_get_func_id_str(str_id, func_id),
					 format_guid_addr,
					 hclge_unic_entry_state_str[guid_node->state]);
		}
		spin_unlock_bh(&vport->mguid_list_lock);
	}
	return 0;
}

int hclge_dbg_dump_fastpath_info(struct hclge_dev *hdev, char *buf, int len)
{
	struct hclge_config_fastpath_cmd *fp_info;
	struct hclge_desc desc;
	int pos = 0;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_COMM_CFG_FASTPATH, true);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump fastpath_info, ret = %d\n", ret);
		return ret;
	}

	fp_info = (struct hclge_config_fastpath_cmd *)desc.data;

	pos += scnprintf(buf + pos, len - pos, "fastpath_en: %u\n",
			 fp_info->fastpath_en);
	pos += scnprintf(buf + pos, len - pos, "ssu_cfg_status: 0x%x\n",
			 le32_to_cpu(fp_info->ssu_cfg_status));
	pos += scnprintf(buf + pos, len - pos, "igu_cfg_status: 0x%x\n",
			 le32_to_cpu(fp_info->igu_cfg_status));
	pos += scnprintf(buf + pos, len - pos, "ppp_cfg_status: 0x%x\n",
			 le32_to_cpu(fp_info->ppp_cfg_status));

	return 0;
}
