// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2023-2023 Hisilicon Limited.
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
#include <linux/inet.h>
#include <linux/in6.h>
#include <net/ipv6.h>

#include "ubl.h"
#include "hclge_cmd.h"
#include "hclge_main.h"
#include "hclge_comm_cmd.h"
#include "hclge_err.h"
#include "hclge_mbx.h"
#include "hclge_comm_unic_addr.h"
#include "hclge_unic_guid.h"
#include "hclge_unic_ip.h"

static int hclge_unic_get_ip_tbl_cmd_status(struct hclge_vport *vport,
					    u16 cmdq_resp, u8 resp_code,
					    enum hclge_ip_tbl_opcode op)
{
	struct hclge_dev *hdev = vport->back;

	if (cmdq_resp) {
		dev_err(&hdev->pdev->dev,
			"cmdq execute failed for get_ip_tbl_cmd_status, status=%u.\n",
			cmdq_resp);
		return -EIO;
	}

	if (op == HCLGE_IP_TBL_ADD) {
		if (!resp_code || resp_code == HCLGE_UNIC_IP_TBL_MISS)
			return 0;
		else if (resp_code == HCLGE_ADD_IP_TBL_OVERFLOW)
			return -ENOSPC;

		dev_err(&hdev->pdev->dev,
			"add ip addr failed for undefined, code=%u.\n",
			resp_code);
		return -EIO;
	} else if (op == HCLGE_IP_TBL_REMOVE) {
		if (!resp_code) {
			return 0;
		} else if (resp_code == HCLGE_UNIC_IP_TBL_MISS) {
			dev_dbg(&hdev->pdev->dev,
				"remove ip addr failed for miss.\n");
			return -ENOENT;
		}

		dev_err(&hdev->pdev->dev,
			"remove ip addr failed for undefined, code=%u.\n",
			resp_code);
		return -EIO;
	} else if (op == HCLGE_IP_TBL_LKUP) {
		if (!resp_code) {
			return 0;
		} else if (resp_code == HCLGE_UNIC_IP_TBL_MISS) {
			dev_dbg(&hdev->pdev->dev,
				"lookup ip addr failed for miss.\n");
			return -ENOENT;
		}

		dev_err(&hdev->pdev->dev,
			"lookup ip addr failed for undefined, code=%u.\n",
			resp_code);
		return -EIO;
	}

	dev_err(&hdev->pdev->dev,
		"unknown opcode for get_ip_tbl_cmd_status, opcode=%d.\n", op);

	return -EINVAL;
}

static int hclge_unic_remove_ip_tbl(struct hclge_vport *vport,
				    struct hclge_ip_tbl_entry_cmd *req)
{
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	u8 resp_code;
	u16 retval;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_DEL_IP_TBL, false);

	memcpy(desc.data, req, sizeof(struct hclge_ip_tbl_entry_cmd));

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"del ip addr failed for cmd_send, ret =%d.\n",
			ret);
		return ret;
	}
	resp_code = (le32_to_cpu(desc.data[0])) & 0xff;
	retval = le16_to_cpu(desc.retval);

	return hclge_unic_get_ip_tbl_cmd_status(vport, retval, resp_code,
						HCLGE_IP_TBL_REMOVE);
}

static int hclge_unic_lookup_ip_tbl(struct hclge_vport *vport,
				    struct hclge_ip_tbl_entry_cmd *req,
				    struct hclge_desc *desc)
{
	struct hclge_dev *hdev = vport->back;
	u8 resp_code;
	u16 retval;
	int ret;

	hclge_cmd_setup_basic_desc(&desc[0], HCLGE_OPC_ADD_IP_TBL, true);

	memcpy(desc[0].data, req, sizeof(struct hclge_ip_tbl_entry_cmd));

	ret = hclge_cmd_send(&hdev->hw, desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"lookup ip addr failed for cmd_send, ret =%d.\n",
			ret);
		return ret;
	}
	resp_code = (le32_to_cpu(desc[0].data[0])) & 0xff;
	retval = le16_to_cpu(desc[0].retval);

	return hclge_unic_get_ip_tbl_cmd_status(vport, retval, resp_code,
						HCLGE_IP_TBL_LKUP);
}

static int hclge_unic_add_ip_tbl(struct hclge_vport *vport,
				 struct hclge_ip_tbl_entry_cmd *req)
{
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	u8 resp_code;
	u16 retval;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_ADD_IP_TBL, false);

	memcpy(desc.data, req, sizeof(struct hclge_ip_tbl_entry_cmd));
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"add ip addr failed for cmd_send, ret =%d.\n",
			ret);
		return ret;
	}

	resp_code = (le32_to_cpu(desc.data[0])) & 0xff;
	retval = le16_to_cpu(desc.retval);

	return hclge_unic_get_ip_tbl_cmd_status(vport, retval, resp_code,
						HCLGE_IP_TBL_ADD);
}

int hclge_unic_init_iptbl_info(struct hclge_dev *hdev)
{
	struct unic_ip_table_info *iptbl_info = &hdev->iptbl_info;

	iptbl_info->priv_iptbl_size = iptbl_info->max_iptbl_size /
			(hdev->num_alloc_vport + 1);
	iptbl_info->share_iptbl_size = iptbl_info->priv_iptbl_size +
			iptbl_info->max_iptbl_size % (hdev->num_alloc_vport + 1);

	memset(&iptbl_info->ipaddr_to_assemble, 0,
	       sizeof(struct sockaddr_in6));
	iptbl_info->upper_ip_addr_state = HCLGE_UNIC_IP_ADDR_NOTSET;

	return 0;
}

void hclge_unic_reset_iptbl_space(struct hclge_dev *hdev)
{
	struct unic_ip_table_info *iptbl_info = &hdev->iptbl_info;
	struct hclge_vport *vport;
	int i;

	for (i = 0; i < hdev->num_alloc_vport; i++) {
		vport = &hdev->vport[i];
		vport->used_iptbl_num = 0;
	}

	mutex_lock(&hdev->vport_lock);
	iptbl_info->share_iptbl_size = iptbl_info->priv_iptbl_size +
			iptbl_info->max_iptbl_size % (hdev->num_alloc_vport + 1);
	mutex_unlock(&hdev->vport_lock);
}

static bool hclge_unic_is_iptbl_space_full(struct hclge_vport *vport,
					   bool need_lock)
{
	struct hclge_dev *hdev = vport->back;
	struct unic_ip_table_info *iptbl_info = &hdev->iptbl_info;
	bool is_full;

	if (need_lock)
		mutex_lock(&hdev->vport_lock);

	is_full = (vport->used_iptbl_num >= iptbl_info->priv_iptbl_size &&
		   iptbl_info->share_iptbl_size == 0);

	if (need_lock)
		mutex_unlock(&hdev->vport_lock);

	return is_full;
}

static void hclge_unic_update_iptbl_space(struct hclge_vport *vport,
					  bool is_free)
{
	struct hclge_dev *hdev = vport->back;
	struct unic_ip_table_info *iptbl_info = &hdev->iptbl_info;

	if (is_free) {
		if (vport->used_iptbl_num > iptbl_info->priv_iptbl_size)
			iptbl_info->share_iptbl_size++;

		if (vport->used_iptbl_num > 0)
			vport->used_iptbl_num--;
	} else {
		if (vport->used_iptbl_num >= iptbl_info->priv_iptbl_size &&
		    iptbl_info->share_iptbl_size > 0)
			iptbl_info->share_iptbl_size--;
		vport->used_iptbl_num++;
	}
}

int hclge_unic_update_ip_list(struct hclge_vport *vport,
			      enum HCLGE_COMM_ADDR_NODE_STATE state,
			      const struct sockaddr *addr)
{
	struct hclge_dev *hdev = vport->back;
	struct in6_addr ip_addr;
	int ret;

	hclge_comm_unic_convert_ip_addr(addr, &ip_addr);

	ret = hclge_comm_unic_update_addr_list(&vport->ip_list,
					       &vport->ip_list_lock,
					       state,
					       (const unsigned char *)&ip_addr);
	if (ret == -ENOENT)
		dev_err(&hdev->pdev->dev,
			"failed to delete ip %pI6c from ip list\n",
			ip_addr.s6_addr);

	if (!ret)
		set_bit(HCLGE_VPORT_STATE_IP_TBL_CHANGE, &vport->state);

	return ret;
}

static int hclge_unic_add_ip_addr_common(struct hclge_vport *vport,
					 struct in6_addr *addr)
{
	struct hclge_dev *hdev = vport->back;
	struct hclge_ip_tbl_entry_cmd req;
	struct hclge_desc desc;
	u16 dip_ad = 0;
	int ret;

	memset(&req, 0, sizeof(req));

	hnae3_set_field(dip_ad, HCLGE_IP_PORT_VFID_M,
			HCLGE_IP_PORT_VFID_S, vport->vport_id);

	req.dip_ad = cpu_to_le16(dip_ad);
	memcpy(req.ipaddr, addr->s6_addr, sizeof(req.ipaddr));

	/* Lookup the ip address in the ip address table, and add
	 * it if the entry is inexistent. Repeated unicast entry
	 * is not allowed in the ip address table.
	 */
	ret = hclge_unic_lookup_ip_tbl(vport, &req, &desc);
	if (ret == -ENOENT) {
		mutex_lock(&hdev->vport_lock);
		if (!hclge_unic_is_iptbl_space_full(vport, false)) {
			ret = hclge_unic_add_ip_tbl(vport, &req);
			if (!ret)
				hclge_unic_update_iptbl_space(vport, false);
			mutex_unlock(&hdev->vport_lock);
			return ret;
		}
		mutex_unlock(&hdev->vport_lock);

		if (!(vport->overflow_promisc_flags & HNAE3_OVERFLOW_MPE))
			dev_err(&hdev->pdev->dev,  "IP table full(%u)\n",
				hdev->iptbl_info.priv_iptbl_size);

		return -ENOSPC;
	}

	/* check if we just hit the duplicate */
	if (!ret)
		return -EEXIST;

	return ret;
}

static int hclge_unic_rm_ip_addr_common(struct hclge_vport *vport,
					struct in6_addr *addr)
{
	struct hclge_dev *hdev = vport->back;
	struct hclge_ip_tbl_entry_cmd req;
	int ret;

	memset(&req, 0, sizeof(req));
	memcpy(req.ipaddr, addr->s6_addr, sizeof(req.ipaddr));
	ret = hclge_unic_remove_ip_tbl(vport, &req);
	if (!ret || ret == -ENOENT) {
		mutex_lock(&hdev->vport_lock);
		hclge_unic_update_iptbl_space(vport, true);
		mutex_unlock(&hdev->vport_lock);
		return 0;
	}

	return ret;
}

static void hclge_unic_sync_vport_ip_list(struct hnae3_handle *h,
					  struct list_head *list)
{
	struct hclge_vport *vport = container_of(h, struct hclge_vport, nic);
	struct hclge_comm_unic_addr_node *ip_node, *tmp;
	int ret;

	list_for_each_entry_safe(ip_node, tmp, list, node) {
		ret = hclge_unic_add_ip_addr_common(vport, &ip_node->ip_addr);
		if (!ret) {
			ip_node->state = HCLGE_COMM_UNIC_ADDR_ACTIVE;
		} else {
			set_bit(HCLGE_VPORT_STATE_IP_TBL_CHANGE,
				&vport->state);

			if (ret != -EEXIST)
				break;
		}
	}
}

static void hclge_unic_unsync_vport_ip_list(struct hnae3_handle *h,
					    struct list_head *list)
{
	struct hclge_vport *vport = container_of(h, struct hclge_vport, nic);
	struct hclge_comm_unic_addr_node *ip_node, *tmp;
	int ret;

	list_for_each_entry_safe(ip_node, tmp, list, node) {
		ret = hclge_unic_rm_ip_addr_common(vport, &ip_node->ip_addr);
		if (!ret || ret == -ENOENT) {
			list_del(&ip_node->node);
			kfree(ip_node);
		} else {
			set_bit(HCLGE_VPORT_STATE_IP_TBL_CHANGE,
				&vport->state);
			break;
		}
	}
}

static void hclge_unic_sync_vport_ip_table(struct hclge_vport *vport)
{
	void (*unsync)(struct hnae3_handle *h, struct list_head *list);
	void (*sync)(struct hnae3_handle *h, struct list_head *list);
	bool all_added;

	sync = hclge_unic_sync_vport_ip_list;
	unsync = hclge_unic_unsync_vport_ip_list;
	all_added = hclge_comm_unic_sync_addr_table(&vport->nic,
						    &vport->ip_list,
						    &vport->ip_list_lock,
						    sync, unsync);
	if (all_added)
		vport->overflow_promisc_flags &= ~HNAE3_OVERFLOW_MPE;
	else
		vport->overflow_promisc_flags |= HNAE3_OVERFLOW_MPE;
}

static bool hclge_unic_need_sync_ip_table(struct hclge_vport *vport)
{
	struct hclge_dev *hdev = vport->back;

	if (test_bit(vport->vport_id, hdev->vport_config_block))
		return false;

	if (test_and_clear_bit(HCLGE_VPORT_STATE_IP_TBL_CHANGE, &vport->state))
		return true;

	return false;
}

void hclge_unic_sync_ip_table(struct hclge_dev *hdev)
{
	int i;

	for (i = 0; i < hdev->num_alloc_vport; i++) {
		struct hclge_vport *vport = &hdev->vport[i];

		if (!hclge_unic_need_sync_ip_table(vport))
			continue;

		hclge_unic_sync_vport_ip_table(vport);
	}
}

/* For global reset and imp reset, hardware will clear the ip table,
 * so we change the ip state from ACTIVE to TO_ADD, then they
 * can be restored in the service task after reset completed. Furtherly,
 * the ip address with state TO_DEL are unnecessary to be restored
 * after reset, so just remove these ip nodes from ip_list.
 */
void hclge_unic_restore_ip_table(struct hclge_vport *vport)
{
	struct hclge_comm_unic_addr_node *ip_node, *tmp;
	struct list_head *list = &vport->ip_list;

	spin_lock_bh(&vport->ip_list_lock);

	list_for_each_entry_safe(ip_node, tmp, list, node) {
		if (ip_node->state == HCLGE_COMM_UNIC_ADDR_ACTIVE) {
			ip_node->state = HCLGE_COMM_UNIC_ADDR_TO_ADD;
		} else if (ip_node->state == HCLGE_COMM_UNIC_ADDR_TO_DEL) {
			list_del(&ip_node->node);
			kfree(ip_node);
		}
	}
	set_bit(HCLGE_VPORT_STATE_IP_TBL_CHANGE, &vport->state);

	spin_unlock_bh(&vport->ip_list_lock);
}

static void hclge_unic_build_ip_del_list(struct list_head *list,
					 bool is_del_list,
					 struct list_head *tmp_del_list)
{
	struct hclge_comm_unic_addr_node *ip_cfg, *tmp;

	list_for_each_entry_safe(ip_cfg, tmp, list, node) {
		switch (ip_cfg->state) {
		case HCLGE_COMM_UNIC_ADDR_TO_DEL:
		case HCLGE_COMM_UNIC_ADDR_ACTIVE:
			list_move_tail(&ip_cfg->node, tmp_del_list);
			break;
		case HCLGE_COMM_UNIC_ADDR_TO_ADD:
			if (is_del_list) {
				list_del(&ip_cfg->node);
				kfree(ip_cfg);
			}
			break;
		}
	}
}

static void hclge_unic_unsync_ip_del_list(struct hclge_vport *vport,
					  int (*unsync)(struct hclge_vport *vport,
							struct in6_addr *addr),
					  bool is_del_list,
					  struct list_head *tmp_del_list)
{
	struct hclge_comm_unic_addr_node *ip_cfg, *tmp;
	int ret;

	list_for_each_entry_safe(ip_cfg, tmp, tmp_del_list, node) {
		ret = unsync(vport, &ip_cfg->ip_addr);
		if (!ret || ret == -ENOENT) {
			/* clear all ip addr from hardware, but remain these
			 * ip addr in the ip list, and restore them after
			 * vf reset finished.
			 */
			if (!is_del_list &&
			    ip_cfg->state == HCLGE_COMM_UNIC_ADDR_ACTIVE) {
				ip_cfg->state = HCLGE_COMM_UNIC_ADDR_TO_ADD;
			} else {
				list_del(&ip_cfg->node);
				kfree(ip_cfg);
			}
		} else if (is_del_list) {
			ip_cfg->state = HCLGE_COMM_UNIC_ADDR_TO_DEL;
		}
	}
}

void hclge_unic_rm_vport_all_ip_table(struct hclge_vport *vport,
				      bool is_del_list)
{
	int (*unsync)(struct hclge_vport *vport, struct in6_addr *addr);
	struct hclge_dev *hdev = vport->back;
	struct list_head tmp_del_list, *list;

	list = &vport->ip_list;
	unsync = hclge_unic_rm_ip_addr_common;
	INIT_LIST_HEAD(&tmp_del_list);

	if (!is_del_list)
		set_bit(vport->vport_id, hdev->vport_config_block);

	spin_lock_bh(&vport->ip_list_lock);
	hclge_unic_build_ip_del_list(list, is_del_list, &tmp_del_list);
	spin_unlock_bh(&vport->ip_list_lock);

	hclge_unic_unsync_ip_del_list(vport, unsync, is_del_list,
				      &tmp_del_list);

	spin_lock_bh(&vport->ip_list_lock);
	hclge_comm_unic_sync_from_addr_del_list(&tmp_del_list, list);
	spin_unlock_bh(&vport->ip_list_lock);
}

/* remove all ip address when uninitailize */
static void hclge_unic_uninit_vport_ip_list(struct hclge_vport *vport)
{
	struct hclge_comm_unic_addr_node *ip_node, *tmp;
	struct hclge_dev *hdev = vport->back;
	struct list_head tmp_del_list, *list;

	INIT_LIST_HEAD(&tmp_del_list);

	list = &vport->ip_list;

	spin_lock_bh(&vport->ip_list_lock);

	list_for_each_entry_safe(ip_node, tmp, list, node) {
		switch (ip_node->state) {
		case HCLGE_COMM_UNIC_ADDR_TO_DEL:
		case HCLGE_COMM_UNIC_ADDR_ACTIVE:
			list_move_tail(&ip_node->node, &tmp_del_list);
			break;
		case HCLGE_COMM_UNIC_ADDR_TO_ADD:
			list_del(&ip_node->node);
			kfree(ip_node);
			break;
		}
	}

	spin_unlock_bh(&vport->ip_list_lock);

	hclge_unic_unsync_vport_ip_list(&vport->nic, &tmp_del_list);

	if (!list_empty(&tmp_del_list))
		dev_warn(&hdev->pdev->dev,
			 "uninit ip list for vport %u not completely.\n",
			 vport->vport_id);

	list_for_each_entry_safe(ip_node, tmp, &tmp_del_list, node) {
		list_del(&ip_node->node);
		kfree(ip_node);
	}
}

void hclge_unic_uninit_ip_table(struct hclge_dev *hdev)
{
	struct hclge_vport *vport;
	int i;

	for (i = 0; i < hdev->num_alloc_vport; i++) {
		vport = &hdev->vport[i];
		hclge_unic_uninit_vport_ip_list(vport);
	}
}

static int hclge_unic_iptbl_parse_subcode(u8 msg_subcode,
					  struct hclge_vport *vport,
					  struct sockaddr *ip_addr)
{
	struct hclge_dev *hdev = vport->back;

	switch (msg_subcode) {
	case HCLGE_UNIC_MBX_IP_TABLE_ADD:
		return hclge_unic_update_ip_list(vport,
						 HCLGE_COMM_UNIC_ADDR_TO_ADD,
						 (const struct sockaddr *)ip_addr);
	case HCLGE_UNIC_MBX_IP_TABLE_REMOVE:
		return hclge_unic_update_ip_list(vport,
						 HCLGE_COMM_UNIC_ADDR_TO_DEL,
						 (const struct sockaddr *)ip_addr);
	default:
		dev_err(&hdev->pdev->dev,
			"failed to set ip addr, unknown subcode %u\n",
			msg_subcode);
		return -EIO;
	}
}

int hclge_unic_set_vf_ip_addr(struct hclge_vport *vport,
			      struct hclge_mbx_vf_to_pf_cmd *mbx_req)
{
	struct hclge_dev *hdev = vport->back;
	struct unic_ip_table_info *iptbl_info = &hdev->iptbl_info;
	struct sockaddr_in6 *ip_addr = &iptbl_info->ipaddr_to_assemble;
	char *lower_ip_addr = &ip_addr->sin6_addr.s6_addr[HCLGE_COMM_UNIC_IPV6_UPPER_LEN];
	char *msg_ip_addr = &mbx_req->msg.data[HCLGE_COMM_UNIC_MSG_IPADDR_POS];
	int ret;

	if (iptbl_info->upper_ip_addr_state == HCLGE_UNIC_IP_ADDR_NOTSET &&
	    mbx_req->msg.data[0] == HCLGE_COMM_UNIC_IPV6_UPPER_LEN) {
		memcpy(&ip_addr->sin6_addr.s6_addr, msg_ip_addr,
		       sizeof(u8) * HCLGE_COMM_UNIC_IPV6_UPPER_LEN);
		iptbl_info->upper_ip_addr_state = mbx_req->msg.subcode;

		return 0;
	} else if (mbx_req->msg.subcode == iptbl_info->upper_ip_addr_state &&
		   mbx_req->msg.data[0] == HCLGE_COMM_UNIC_IPV6_LOWER_LEN) {
		memcpy(lower_ip_addr, msg_ip_addr,
		       sizeof(u8) * HCLGE_COMM_UNIC_IPV6_LOWER_LEN);

		ip_addr->sin6_family = AF_INET6;
		ret = hclge_unic_iptbl_parse_subcode(mbx_req->msg.subcode,
						     vport,
						     (struct sockaddr *)ip_addr);
	} else {
		dev_err(&hdev->pdev->dev,
			"failed to configure ip table, unknown subcode %u or different ip addr\n",
			mbx_req->msg.subcode);
		ret = -EIO;
	}
	memset(ip_addr, 0, sizeof(struct sockaddr_in6));
	iptbl_info->upper_ip_addr_state = HCLGE_UNIC_IP_ADDR_NOTSET;

	return ret;
}
