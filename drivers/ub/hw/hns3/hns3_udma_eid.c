// SPDX-License-Identifier: GPL-2.0
/* Huawei HNS3_UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include <linux/inetdevice.h>
#include "hns3_udma_cmd.h"
#include "hns3_udma_eid.h"

static int config_gmv_table(struct hns3_udma_dev *udma_dev, struct hns3_udma_eid *hns3_udma_eid,
			    uint32_t eid_index)
{
	enum hns3_udma_sgid_type sgid_type = hns3_udma_eid->type;
	struct hns3_udma_cmq_desc desc[HNS3_UDMA_CMQ_DESC_SIZE];
	struct hns3_udma_cfg_gmv_tb_a *tb_a;
	struct hns3_udma_cfg_gmv_tb_b *tb_b;
	uint16_t guid_shift = 0;
	uint16_t smac_l;

	tb_a = (struct hns3_udma_cfg_gmv_tb_a *)desc[0].data;
	tb_b = (struct hns3_udma_cfg_gmv_tb_b *)desc[1].data;

	hns3_udma_cmq_setup_basic_desc(&desc[0], HNS3_UDMA_OPC_CFG_GMV_TBL, false);
	desc[0].flag |= cpu_to_le16(HNS3_UDMA_CMD_FLAG_NEXT);
	hns3_udma_cmq_setup_basic_desc(&desc[1], HNS3_UDMA_OPC_CFG_GMV_TBL, false);

	if (udma_dev->uboe.netdevs[0]->addr_len > UBOE_MAC_LEN)
		guid_shift = HNS3_UDMA_SMAC_OFFSET;

	smac_l =
		*(uint16_t *)&udma_dev->uboe.netdevs[0]->dev_addr[SMAC_L_SHIFT + guid_shift];
	hns3_udma_set_field(tb_a->vf_type_vlan_smac, CFG_GMV_TB_VF_SMAC_L_M,
		       CFG_GMV_TB_VF_SMAC_L_S, smac_l);

	tb_a->vf_smac_h =
		*(uint32_t *)&udma_dev->uboe.netdevs[0]->dev_addr[SMAC_H_SHIFT + guid_shift];

	hns3_udma_set_field(tb_a->vf_type_vlan_smac, CFG_GMV_TB_VF_SGID_TYPE_M,
		       CFG_GMV_TB_VF_SGID_TYPE_S, sgid_type);

	memcpy(tb_a, &hns3_udma_eid->eid, sizeof(hns3_udma_eid->eid));

	hns3_udma_set_bit(tb_a->vf_type_vlan_smac, CFG_GMV_TB_VF_PATTERN_S, 0);
	tb_b->table_idx_rsv = eid_index;
	tb_b->vf_id = 0;

	return hns3_udma_cmq_send(udma_dev, desc, CFG_GMV_TBL_CMD_NUM);
}

static inline int clear_gmv_table(struct hns3_udma_dev *udma_dev, uint32_t eid_index)
{
	struct hns3_udma_eid eid = {};

	return config_gmv_table(udma_dev, &eid, eid_index);
}

static int add_eid_entry(struct hns3_udma_dev *udma_dev, union ubcore_eid eid,
			 uint32_t eid_index)
{
	struct hns3_udma_eid *hns3_udma_eid;
	int local_ret;
	int ret;

	hns3_udma_eid = kcalloc(1, sizeof(*hns3_udma_eid), GFP_KERNEL);
	if (!hns3_udma_eid)
		return -ENOMEM;

	memcpy(&hns3_udma_eid->eid, &eid, sizeof(eid));
	hns3_udma_eid->type = get_sgid_type_from_eid(eid);

	ret = config_gmv_table(udma_dev, hns3_udma_eid, eid_index);
	if (ret) {
		dev_err(udma_dev->dev, "Set EID to GMV table failed, ret = %d.\n",
			ret);
		goto err_config;
	}

	ret = xa_err(xa_store(&udma_dev->eid_table, eid_index, hns3_udma_eid, GFP_KERNEL));
	if (ret) {
		dev_err(udma_dev->dev, "Failed to store eid, ret = %d.\n", ret);
		goto err_store;
	}

	return ret;
err_store:
	local_ret = clear_gmv_table(udma_dev, eid_index);
	if (local_ret)
		dev_err(udma_dev->dev, "Failed to clear eid from GMV table, ret = %d.\n",
			local_ret);
err_config:
	kfree(hns3_udma_eid);
	return ret;
}

static int del_eid_entry(struct hns3_udma_dev *udma_dev, uint32_t eid_index)
{
	struct hns3_udma_eid *udma_eid;

	udma_eid = (struct hns3_udma_eid *)xa_load(&udma_dev->eid_table, eid_index);
	if (IS_ERR_OR_NULL(udma_eid)) {
		dev_err(udma_dev->dev, "Failed to find eid, index = %u.\n",
			eid_index);
		return -EINVAL;
	}

	xa_erase(&udma_dev->eid_table, eid_index);
	kfree(udma_eid);

	return clear_gmv_table(udma_dev, eid_index);
}

static int hns3_udma_check_ueid_cfg(struct hns3_udma_dev *dev, uint16_t fe_idx,
				    uint32_t eid_index)
{
	if (fe_idx != dev->func_id) {
		dev_err(dev->dev, "Check FE ID failed.\n");
		return -EINVAL;
	}

	if (eid_index >= dev->caps.max_eid_cnt) {
		dev_err(dev->dev, "Invalid EID index(%u), max value is %u.\n",
			eid_index, dev->caps.max_eid_cnt);
		return -EINVAL;
	}

	return 0;
}

int hns3_udma_add_ueid(struct ubcore_device *dev, uint16_t fe_idx, struct ubcore_ueid_cfg *cfg)
{
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(dev);
	uint32_t eid_index = cfg->eid_index;
	union ubcore_eid eid = cfg->eid;
	int ret;

	ret = hns3_udma_check_ueid_cfg(udma_dev, fe_idx, eid_index);
	if (ret)
		return ret;

	return add_eid_entry(udma_dev, eid, eid_index);
}

int hns3_udma_delete_ueid(struct ubcore_device *dev, uint16_t fe_idx,
			  struct ubcore_ueid_cfg *cfg)
{
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(dev);
	uint32_t eid_index = cfg->eid_index;
	int ret;

	ret = hns3_udma_check_ueid_cfg(udma_dev, fe_idx, eid_index);
	if (ret)
		return ret;

	return del_eid_entry(udma_dev, eid_index);
}

int hns3_udma_find_eid_idx(struct hns3_udma_dev *dev, union ubcore_eid eid)
{
	struct hns3_udma_eid *udma_eid = NULL;
	int eid_index = -EINVAL;
	unsigned long index = 0;

	xa_lock(&dev->eid_table);
	xa_for_each(&dev->eid_table, index, udma_eid) {
		if (!memcmp(&udma_eid->eid, &eid, sizeof(eid))) {
			eid_index = index;
			break;
		}
	}
	xa_unlock(&dev->eid_table);

	return eid_index;
}
