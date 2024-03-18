// SPDX-License-Identifier: GPL-2.0+
/* Hisilicon UNIC Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
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

#include <linux/etherdevice.h>
#include <linux/random.h>

#include "ubl.h"
#include "hclge_cmd.h"
#include "hclge_main.h"
#include "hclge_mbx.h"
#include "hclge_comm_unic_addr.h"
#include "hnae3.h"
#include "hclge_unic_guid.h"

static bool hclge_unic_need_sync_guid_table(struct hclge_vport *vport)
{
	struct hclge_dev *hdev = vport->back;

	if (test_bit(vport->vport_id, hdev->vport_config_block))
		return false;

	if (test_and_clear_bit(HCLGE_VPORT_STATE_GUID_TBL_CHANGE, &vport->state))
		return true;

	return false;
}

int hclge_unic_update_guid_list(struct hclge_vport *vport,
				enum HCLGE_COMM_ADDR_NODE_STATE state,
				const unsigned char *addr)
{
	char format_guid_addr[HCLGE_COMM_FORMAT_GUID_ADDR_LEN];
	struct hclge_dev *hdev = vport->back;
	int ret;

	ret = hclge_comm_unic_update_addr_list(&vport->mc_guid_list,
					       &vport->mguid_list_lock,
					       state, addr);
	if (ret == -ENOENT) {
		hclge_comm_format_guid_addr(format_guid_addr, addr);
		dev_err(&hdev->pdev->dev,
			"failed to delete guid %s from mc guid list\n",
			format_guid_addr);
	}

	if (!ret)
		set_bit(HCLGE_VPORT_STATE_GUID_TBL_CHANGE, &vport->state);

	return ret;
}

static int hclge_unic_lookup_mc_guid(struct hclge_vport *vport,
				     struct hclge_unic_mc_guid_cfg_cmd *req,
				     struct hclge_desc *desc)
{
	struct hclge_unic_mc_guid_cfg_cmd *resp;
	struct hclge_dev *hdev = vport->back;
	u16 resp_code;
	u16 retval;
	int ret;

	resp = (struct hclge_unic_mc_guid_cfg_cmd *)desc[0].data;
	hnae3_set_bit(req->vld_lookup_flag, HCLGE_UNIC_LOOKUP_EN_B, 1);
	hclge_cmd_setup_basic_desc(&desc[0], HCLGE_OPC_CFG_MC_GUID_CMD, true);
	desc[0].flag |= cpu_to_le16(HCLGE_COMM_CMD_FLAG_NEXT);
	memcpy(desc[0].data, req, sizeof(struct hclge_unic_mc_guid_cfg_cmd));
	hclge_cmd_setup_basic_desc(&desc[1], HCLGE_OPC_CFG_MC_GUID_CMD, true);
	desc[1].flag |= cpu_to_le16(HCLGE_COMM_CMD_FLAG_NEXT);
	hclge_cmd_setup_basic_desc(&desc[2], HCLGE_OPC_CFG_MC_GUID_CMD, true);
	ret = hclge_cmd_send(&hdev->hw, desc, 3);
	if (ret) {
		dev_err(&hdev->pdev->dev, "lookup mc guid failed for cmd_send, ret = %d\n",
			ret);
		return ret;
	}
	resp_code = resp->hit_info;
	retval = le16_to_cpu(desc[0].retval);
	if (retval) {
		dev_err(&hdev->pdev->dev, "cmdq execute failed for lookup mc guid, status = %u.\n",
			retval);
		return -EIO;
	} else if (!(resp_code & HCLGE_UNIC_GUID_HIT)) {
		dev_dbg(&hdev->pdev->dev, "lookup mc guid failed for miss.\n");
		return -ENOENT;
	}

	return ret;
}

static int hclge_unic_fill_add_desc(struct hclge_vport *vport,
				    struct hclge_unic_mc_guid_cfg_cmd *req,
				    struct hclge_desc *desc,
				    bool is_new_guid)
{
	struct hclge_unic_mc_guid_cfg_cmd *rsp;
	struct hclge_dev *hdev = vport->back;
	u16 mc_guid_tbl_size;

	mc_guid_tbl_size = min(HCLGE_UNIC_MC_GUID_NUM,
			       hdev->ae_dev->dev_specs.guid_tbl_space -
			       HCLGE_VPORT_NUM);
	if (is_new_guid) {
		req->index = find_first_zero_bit(hdev->mc_guid_tbl_bmap,
						 HCLGE_UNIC_MC_GUID_NUM);
		if (req->index >= mc_guid_tbl_size)
			return -ENOSPC;
	} else {
		rsp = (struct hclge_unic_mc_guid_cfg_cmd *)desc[0].data;
		req->index = rsp->index;
	}

	if (vport->vport_id >= HCLGE_VPORT_NUM)
		return -EIO;
	req->ad_data = req->index;
	if (vport->vport_id >= HCLGE_UNIC_BIT_NUM_PER_BD &&
	    test_and_set_bit(vport->vport_id - HCLGE_UNIC_BIT_NUM_PER_BD,
			     (unsigned long *)&desc[1].data[2]))
		return -EEXIST;
	else if (test_and_set_bit(vport->vport_id,
				  (unsigned long *)&desc[2].data[2]))
		return -EEXIST;

	return 0;
}

static int hclge_unic_add_mc_guid_cmd(struct hclge_vport *vport,
				      struct hclge_unic_mc_guid_cfg_cmd *req,
				      struct hclge_desc *desc)
{
	struct hclge_dev *hdev = vport->back;
	u16 retval;
	int ret;

	req->vld_lookup_flag = BIT(HCLGE_UNIC_ENTRY_VLD_B);
	hclge_comm_cmd_reuse_desc(&desc[0], false);
	desc[0].flag |= cpu_to_le16(HCLGE_COMM_CMD_FLAG_NEXT);
	hclge_comm_cmd_reuse_desc(&desc[1], false);
	desc[1].flag |= cpu_to_le16(HCLGE_COMM_CMD_FLAG_NEXT);
	hclge_comm_cmd_reuse_desc(&desc[2], false);
	desc[2].flag &= cpu_to_le16(~HCLGE_COMM_CMD_FLAG_NEXT);
	memcpy(desc[0].data, req, sizeof(struct hclge_unic_mc_guid_cfg_cmd));
	ret = hclge_cmd_send(&hdev->hw, desc, 3);
	if (ret) {
		dev_err(&hdev->pdev->dev, "add mc guid failed, ret = %d\n", ret);
		return ret;
	}
	retval = le16_to_cpu(desc[0].retval);
	if (retval) {
		dev_err(&hdev->pdev->dev, "cmdq execute failed for add mc guid, status = %u.\n",
			retval);
		return -EIO;
	}

	return 0;
}

int hclge_unic_add_mc_guid_common(struct hclge_vport *vport,
				  const unsigned char *mguid)
{
	struct hclge_unic_mc_guid_cfg_cmd req = {0};
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc[3];
	bool is_new_guid = false;
	int ret;

	memcpy(req.mguid, mguid, UBL_ALEN);
	ret = hclge_unic_lookup_mc_guid(vport, &req, desc);
	if (ret) {
		if (hdev->used_mc_guid_num >=
		    hdev->ae_dev->dev_specs.guid_tbl_space - HCLGE_VPORT_NUM)
			goto err_no_space;
		is_new_guid = true;
		memset(desc[0].data, 0, sizeof(desc[0].data));
		memset(desc[1].data, 0, sizeof(desc[0].data));
		memset(desc[2].data, 0, sizeof(desc[0].data));
	}

	ret = hclge_unic_fill_add_desc(vport, &req, desc, is_new_guid);
	if (ret == -EEXIST)
		return 0;
	if (ret == -ENOSPC)
		goto err_no_space;
	if (ret)
		return ret;
	ret = hclge_unic_add_mc_guid_cmd(vport, &req, desc);
	if (!ret && is_new_guid) {
		set_bit(req.index, hdev->mc_guid_tbl_bmap);
		hdev->used_mc_guid_num++;
	}

	return 0;
err_no_space:
	/* if already overflow, not to print each time */
	if (!(vport->overflow_promisc_flags & HNAE3_OVERFLOW_MGP)) {
		vport->overflow_promisc_flags |= HNAE3_OVERFLOW_MGP;
		dev_err(&hdev->pdev->dev, "mc guid table is full\n");
	}

	return -ENOSPC;
}

static bool hclge_unic_is_all_function_deleted(struct hclge_desc *desc)
{
#define HCLGE_UNIC_DWORD_OF_MGUID 4
	int i;

	for (i = 0; i < HCLGE_UNIC_DWORD_OF_MGUID; i++) {
		if (desc[1].data[2 + i] || desc[2].data[2 + i])
			return false;
	}

	return true;
}

static int hclge_unic_fill_del_desc(struct hclge_vport *vport,
				    struct hclge_unic_mc_guid_cfg_cmd *req,
				    struct hclge_desc *desc)
{
	struct hclge_unic_mc_guid_cfg_cmd *rsp;

	if (vport->vport_id >= HCLGE_VPORT_NUM)
		return -EIO;
	rsp = (struct hclge_unic_mc_guid_cfg_cmd *)desc[0].data;
	req->index = rsp->index;
	req->ad_data = rsp->index;
	if (vport->vport_id >= HCLGE_UNIC_BIT_NUM_PER_BD)
		clear_bit(vport->vport_id - HCLGE_UNIC_BIT_NUM_PER_BD,
			  (unsigned long *)&desc[1].data[2]);
	else
		clear_bit(vport->vport_id, (unsigned long *)&desc[2].data[2]);

	return 0;
}

static int hclge_unic_del_mc_guid_cmd(struct hclge_vport *vport,
				      struct hclge_unic_mc_guid_cfg_cmd *req,
				      struct hclge_desc *desc)
{
	struct hclge_dev *hdev = vport->back;
	u16 retval;
	int ret;

	req->vld_lookup_flag = 0;
	hclge_comm_cmd_reuse_desc(&desc[0], false);
	desc[0].flag |= cpu_to_le16(HCLGE_COMM_CMD_FLAG_NEXT);
	hclge_comm_cmd_reuse_desc(&desc[1], false);
	desc[1].flag |= cpu_to_le16(HCLGE_COMM_CMD_FLAG_NEXT);
	hclge_comm_cmd_reuse_desc(&desc[2], false);
	desc[2].flag &= cpu_to_le16(~HCLGE_COMM_CMD_FLAG_NEXT);
	memcpy(desc[0].data, req, sizeof(struct hclge_unic_mc_guid_cfg_cmd));
	ret = hclge_cmd_send(&hdev->hw, desc, 3);
	if (ret) {
		dev_err(&hdev->pdev->dev, "del mc guid failed, ret = %d\n", ret);
		return ret;
	}
	retval = le16_to_cpu(desc[0].retval);
	if (retval) {
		dev_err(&hdev->pdev->dev, "cmdq execute failed for add mc guid, status = %u.\n",
			retval);
		return -EIO;
	}

	return 0;
}

int hclge_unic_del_mc_guid_common(struct hclge_vport *vport,
				  const unsigned char *mguid)
{
	struct hclge_unic_mc_guid_cfg_cmd req = {0};
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc[3];
	int ret;

	memcpy(req.mguid, mguid, UBL_ALEN);
	ret = hclge_unic_lookup_mc_guid(vport, &req, desc);
	if (!ret) {
		ret = hclge_unic_fill_del_desc(vport, &req, desc);
		if (ret)
			return ret;
		if (hclge_unic_is_all_function_deleted(desc)) {
			ret = hclge_unic_del_mc_guid_cmd(vport, &req, desc);
			if (!ret) {
				clear_bit(req.index, hdev->mc_guid_tbl_bmap);
				hdev->used_mc_guid_num--;
			}
		} else {
			return hclge_unic_add_mc_guid_cmd(vport, &req, desc);
		}
	} else if (ret == -ENOENT) {
		ret = 0;
	}

	return ret;
}

static void hclge_unic_sync_vport_mguid_list(struct hnae3_handle *h,
					     struct list_head *list)
{
	struct hclge_vport *vport = container_of(h, struct hclge_vport, nic);
	struct hclge_comm_unic_addr_node *guid_node, *tmp;
	int ret;

	list_for_each_entry_safe(guid_node, tmp, list, node) {
		ret = hclge_unic_add_mc_guid_common(vport, guid_node->mguid);
		if (!ret) {
			guid_node->state = HCLGE_COMM_UNIC_ADDR_ACTIVE;
		} else {
			set_bit(HCLGE_VPORT_STATE_GUID_TBL_CHANGE,
				&vport->state);

			/* Mc guid can be reusable, even though there is no
			 * space to add new mc guid, we should check whether
			 * other mc guid are existing in hardware for reuse.
			 */
			if (ret != -ENOSPC)
				break;
		}
	}
}

static void hclge_unic_unsync_vport_mguid_list(struct hnae3_handle *h,
					       struct list_head *list)
{
	struct hclge_vport *vport = container_of(h, struct hclge_vport, nic);
	struct hclge_comm_unic_addr_node *guid_node, *tmp;
	int ret;

	list_for_each_entry_safe(guid_node, tmp, list, node) {
		ret = hclge_unic_del_mc_guid_common(vport, guid_node->mguid);
		if (!ret || ret == -ENOENT) {
			list_del(&guid_node->node);
			kfree(guid_node);
		} else {
			set_bit(HCLGE_VPORT_STATE_GUID_TBL_CHANGE,
				&vport->state);
			break;
		}
	}
}

static void hclge_unic_sync_vport_guid_table(struct hclge_vport *vport)
{
	void (*unsync)(struct hnae3_handle *h, struct list_head *list);
	void (*sync)(struct hnae3_handle *h, struct list_head *list);
	bool all_added;

	sync = hclge_unic_sync_vport_mguid_list;
	unsync = hclge_unic_unsync_vport_mguid_list;
	all_added = hclge_comm_unic_sync_addr_table(&vport->nic,
						    &vport->mc_guid_list,
						    &vport->mguid_list_lock,
						    sync, unsync);
	if (all_added)
		vport->overflow_promisc_flags &= ~HNAE3_OVERFLOW_MGP;
	else
		vport->overflow_promisc_flags |= HNAE3_OVERFLOW_MGP;
}

void hclge_unic_sync_mguid_table(struct hclge_dev *hdev)
{
	int i;

	for (i = 0; i < hdev->num_alloc_vport; i++) {
		struct hclge_vport *vport = &hdev->vport[i];

		if (!hclge_unic_need_sync_guid_table(vport))
			continue;
		hclge_unic_sync_vport_guid_table(vport);
	}
}

/* remove all guid when uninitailize */
static void hclge_unic_uninit_vport_guid_list(struct hclge_vport *vport)
{
	struct hclge_comm_unic_addr_node *guid_node, *tmp;
	struct hclge_dev *hdev = vport->back;
	struct list_head tmp_del_list, *list;

	INIT_LIST_HEAD(&tmp_del_list);

	list = &vport->mc_guid_list;

	spin_lock_bh(&vport->mguid_list_lock);

	list_for_each_entry_safe(guid_node, tmp, list, node) {
		switch (guid_node->state) {
		case HCLGE_COMM_UNIC_ADDR_TO_DEL:
		case HCLGE_COMM_UNIC_ADDR_ACTIVE:
			list_move_tail(&guid_node->node, &tmp_del_list);
			break;
		case HCLGE_COMM_UNIC_ADDR_TO_ADD:
			list_del(&guid_node->node);
			kfree(guid_node);
			break;
		}
	}

	spin_unlock_bh(&vport->mguid_list_lock);

	hclge_unic_unsync_vport_mguid_list(&vport->nic, &tmp_del_list);

	if (!list_empty(&tmp_del_list))
		dev_warn(&hdev->pdev->dev,
			 "uninit mguid list for vport %u not completely.\n",
			 vport->vport_id);

	list_for_each_entry_safe(guid_node, tmp, &tmp_del_list, node) {
		list_del(&guid_node->node);
		kfree(guid_node);
	}
}

void hclge_unic_uninit_mguid_table(struct hclge_dev *hdev)
{
	struct hclge_vport *vport;
	int i;

	for (i = 0; i < hdev->num_alloc_vport; i++) {
		vport = &hdev->vport[i];
		hclge_unic_uninit_vport_guid_list(vport);
	}
	bitmap_zero(hdev->mc_guid_tbl_bmap, HCLGE_UNIC_MC_GUID_NUM);
}

int hclge_unic_set_vf_mc_guid(struct hclge_vport *vport,
			      struct hclge_mbx_vf_to_pf_cmd *mbx_req)
{
	__le16 proto = *(__le16 *)(mbx_req->msg.data);
	struct hclge_dev *hdev = vport->back;
	__le16 *mguid_proto = NULL;
	u8 mguid[UBL_ALEN];
	int ret = 0;

	memset(mguid, 0xff, UBL_ALEN);
	mguid_proto = (__le16 *)&mguid[HCLGE_COMM_MGUID_PREFIX_LEN];
	*mguid_proto = proto;

	if (mbx_req->msg.subcode == HCLGE_MBX_MC_GUID_MC_ADD) {
		ret = hclge_unic_update_guid_list(vport,
						  HCLGE_COMM_UNIC_ADDR_TO_ADD,
						  (const u8 *)mguid);
	} else if (mbx_req->msg.subcode == HCLGE_MBX_MC_GUID_MC_DELETE) {
		ret = hclge_unic_update_guid_list(vport,
						  HCLGE_COMM_UNIC_ADDR_TO_DEL,
						  (const u8 *)mguid);
	} else {
		dev_err(&hdev->pdev->dev,
			"failed to set mc guid, unknown subcode %u\n",
			mbx_req->msg.subcode);
		return -EIO;
	}

	return ret;
}

/* For global reset and imp reset, hardware will clear the guid table,
 * so we change the guid state from ACTIVE to TO_ADD, then they
 * can be restored in the service task after reset complete. Furtherly,
 * the guid with state TO_DEL or DEL_FAIL are unnecessary to
 * be restored after reset, so just remove these guid nodes from guid_list.
 */
void hclge_unic_restore_mc_guid_table(struct hclge_vport *vport)
{
	struct hclge_comm_unic_addr_node *guid_node, *tmp;
	struct list_head *list = &vport->mc_guid_list;

	spin_lock_bh(&vport->mguid_list_lock);

	list_for_each_entry_safe(guid_node, tmp, list, node) {
		if (guid_node->state == HCLGE_COMM_UNIC_ADDR_ACTIVE) {
			guid_node->state = HCLGE_COMM_UNIC_ADDR_TO_ADD;
		} else if (guid_node->state == HCLGE_COMM_UNIC_ADDR_TO_DEL) {
			list_del(&guid_node->node);
			kfree(guid_node);
		}
	}
	set_bit(HCLGE_VPORT_STATE_GUID_TBL_CHANGE, &vport->state);

	spin_unlock_bh(&vport->mguid_list_lock);
}

static void hclge_unic_build_del_list(struct list_head *list,
				      bool is_del_list,
				      struct list_head *tmp_del_list)
{
	struct hclge_comm_unic_addr_node *guid_node, *tmp;

	list_for_each_entry_safe(guid_node, tmp, list, node) {
		switch (guid_node->state) {
		case HCLGE_COMM_UNIC_ADDR_TO_DEL:
		case HCLGE_COMM_UNIC_ADDR_ACTIVE:
			list_move_tail(&guid_node->node, tmp_del_list);
			break;
		case HCLGE_COMM_UNIC_ADDR_TO_ADD:
			if (is_del_list) {
				list_del(&guid_node->node);
				kfree(guid_node);
			}
			break;
		}
	}
}

static void hclge_unic_unsync_del_list(struct hclge_vport *vport,
				       int (*unsync)(struct hclge_vport *vport,
						     const unsigned char *mguid),
				       bool is_del_list,
				       struct list_head *tmp_del_list)
{
	struct hclge_comm_unic_addr_node *guid_node, *tmp;
	int ret;

	list_for_each_entry_safe(guid_node, tmp, tmp_del_list, node) {
		ret = unsync(vport, guid_node->mguid);
		if (!ret || ret == -ENOENT) {
			/* clear all mac addr from hardware, but remain these
			 * mac addr in the mac list, and restore them after
			 * vf reset finished.
			 */
			if (!is_del_list &&
			    guid_node->state == HCLGE_COMM_UNIC_ADDR_ACTIVE) {
				guid_node->state = HCLGE_COMM_UNIC_ADDR_TO_ADD;
			} else {
				list_del(&guid_node->node);
				kfree(guid_node);
			}
		} else if (is_del_list) {
			guid_node->state = HCLGE_COMM_UNIC_ADDR_TO_DEL;
		}
	}
}

void hclge_unic_del_vport_all_mc_guid_table(struct hclge_vport *vport,
					    bool is_del_list)
{
	struct hclge_dev *hdev = vport->back;
	struct list_head tmp_del_list, *list;

	list = &vport->mc_guid_list;
	INIT_LIST_HEAD(&tmp_del_list);

	if (!is_del_list)
		set_bit(vport->vport_id, hdev->vport_config_block);

	spin_lock_bh(&vport->mguid_list_lock);

	hclge_unic_build_del_list(list, is_del_list, &tmp_del_list);

	spin_unlock_bh(&vport->mguid_list_lock);

	hclge_unic_unsync_del_list(vport, hclge_unic_del_mc_guid_common,
				   is_del_list, &tmp_del_list);

	spin_lock_bh(&vport->mguid_list_lock);

	hclge_comm_unic_sync_from_addr_del_list(&tmp_del_list, list);

	spin_unlock_bh(&vport->mguid_list_lock);
}

void hclge_unic_reset_mc_guid_space(struct hclge_dev *hdev)
{
	hdev->used_mc_guid_num = 0;
	bitmap_zero(hdev->mc_guid_tbl_bmap, HCLGE_UNIC_MC_GUID_NUM);
}

void hclge_unic_set_func_guid(struct hnae3_handle *handle, u8 *guid)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;

	hdev->hw.func_guid = guid;
}

int hclge_unic_get_func_guid(struct hnae3_handle *handle, u8 *guid)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;

	return hclge_comm_unic_get_func_guid(&hdev->hw.hw, guid);
}

void hclge_unic_rm_func_guid(struct hclge_dev *hdev)
{
	hclge_comm_unic_rm_func_guid(&hdev->hw.hw, &hdev->hw.func_guid);
}
