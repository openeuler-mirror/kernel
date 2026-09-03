// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025-2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <net/page_pool/types.h>
#include <linux/debugfs.h>

#include "unic_bond.h"
#include "unic_comm_addr.h"
#include "unic_dev.h"
#include "unic_debugfs.h"
#include "unic_entry_debugfs.h"

static const char * const unic_entry_state_str[] = {
	"TO_ADD", "TO_DEL", "ACTIVE"
};

static int unic_dbg_check_dev_state(struct unic_dev *unic_dev)
{
	if (__unic_resetting(unic_dev))
		return -EBUSY;

	return 0;
}

int unic_dbg_dump_ip_tbl_spec(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	u32 total_ip_tbl_size, total_ue_num;
	struct ubase_caps *ubase_caps;

	ubase_caps = ubase_get_dev_caps(unic_dev->comdev.adev);
	total_ue_num = ubase_caps->total_ue_num;
	total_ip_tbl_size = unic_dev->caps.total_ip_tbl_size;

	seq_printf(s, "total_ue_num\t: %u\n", total_ue_num);
	seq_printf(s, "total_ip_tbl_size\t: %u\n", total_ip_tbl_size);

	return 0;
}

static int unic_common_query_addr_list(struct unic_dev *unic_dev, u32 total_size,
				       u32 size, struct list_head *list,
				       int (*query_list)(struct unic_dev *, u32 *,
							 struct list_head *,
							 bool *complete))
{
#define UNIC_LOOP_COUNT(total_size, size) ((total_size) / (size) + 1)

	u32 idx = 0, cnt = 0;
	bool complete;
	int ret = 0;

	while (cnt < UNIC_LOOP_COUNT(total_size, size)) {
		complete = false;
		ret = query_list(unic_dev, &idx, list, &complete);
		if (ret) {
			unic_err(unic_dev,
				 "failed to query addr list, ret = %d.\n", ret);
			break;
		}

		if (complete)
			break;
		cnt++;
	}

	return ret == -EPERM ? -EOPNOTSUPP : ret;
}

static int unic_dbg_dump_mac_tbl_list(struct seq_file *s, void *data,
				      bool is_unicast)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct unic_vport *vport = &unic_dev->vport;
	struct unic_comm_addr_node *mac_node, *tmp;
	struct list_head *list;
	int i = 0;

	if (!unic_dev_cfg_mac_supported(unic_dev))
		return -EOPNOTSUPP;

	seq_printf(s, "%s mac_list:\n", is_unicast ? "unicast" : "multicast");
	seq_printf(s, "No.     %-28sSTATE\n", "MAC_ADDR");

	list = is_unicast ?
	       &vport->addr_tbl.uc_mac_list : &vport->addr_tbl.mc_mac_list;

	spin_lock_bh(&vport->addr_tbl.mac_list_lock);
	list_for_each_entry_safe(mac_node, tmp, list, node) {
		seq_printf(s, "%-8d", i++);
		seq_printf(s, "%-28pM", mac_node->mac_addr);
		seq_printf(s, "%s\n", unic_entry_state_str[mac_node->state]);
	}

	spin_unlock_bh(&vport->addr_tbl.mac_list_lock);
	return 0;
}

int unic_dbg_dump_uc_mac_tbl_list(struct seq_file *s, void *data)
{
	return unic_dbg_dump_mac_tbl_list(s, data, true);
}

int unic_dbg_dump_mc_mac_tbl_list(struct seq_file *s, void *data)
{
	return unic_dbg_dump_mac_tbl_list(s, data, false);
}

int unic_dbg_dump_mac_tbl_spec(struct seq_file *s, void *data)
{
	u32 mac_tbl_size, priv_uc_mac_tbl_size, priv_mc_mac_tbl_size;
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);

	if (!unic_dev_cfg_mac_supported(unic_dev))
		return -EOPNOTSUPP;

	priv_mc_mac_tbl_size = unic_dev->caps.mc_mac_tbl_size;
	priv_uc_mac_tbl_size = unic_dev->caps.uc_mac_tbl_size;
	mac_tbl_size = priv_mc_mac_tbl_size + priv_uc_mac_tbl_size;

	seq_printf(s, "mac_tbl_size\t: %u\n", mac_tbl_size);
	seq_printf(s, "priv_uc_mac_tbl_size\t: %u\n", priv_uc_mac_tbl_size);
	seq_printf(s, "priv_mc_mac_tbl_size\t: %u\n", priv_mc_mac_tbl_size);

	return 0;
}

int unic_dbg_dump_ip_tbl_list(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct unic_comm_addr_node *ip_node;
	struct unic_addr_tbl *ip_tbl;
	struct list_head *list;
	u16 i = 0;

	seq_printf(s, "No  %-43sSTATE    IP_MASK\n", "IP_ADDR");

	ip_tbl = &unic_dev->vport.addr_tbl;
	list = &ip_tbl->ip_list;
	spin_lock_bh(&ip_tbl->ip_list_lock);
	list_for_each_entry(ip_node, list, node) {
		seq_printf(s, "%-4u", i++);
		seq_printf(s, "%-43pI6c", &ip_node->ip_addr.s6_addr);
		seq_printf(s, "%-9s", unic_entry_state_str[ip_node->state]);
		seq_printf(s, "%-3u", ip_node->node_mask);
		seq_puts(s, "\n");
	}
	spin_unlock_bh(&ip_tbl->ip_list_lock);

	return 0;
}

int unic_dbg_dump_bond_ip_tbl_list(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct unic_comm_addr_node *ip_node;
	struct unic_addr_tbl *ip_tbl;
	struct list_head *list;
	u16 i = 0;

	if (!unic_bond_ip_sync_supported(unic_dev))
		return -EOPNOTSUPP;

	seq_printf(s, "No  %-43sSTATE    IP_MASK\n", "IP_ADDR");

	ip_tbl = &unic_dev->vport.addr_tbl;
	list = &ip_tbl->bond_ip_list;
	spin_lock_bh(&ip_tbl->bond_ip_list_lock);
	list_for_each_entry(ip_node, list, node) {
		seq_printf(s, "%-4u", i++);
		seq_printf(s, "%-43pI6c", &ip_node->ip_addr.s6_addr);
		seq_printf(s, "%-9s", unic_entry_state_str[ip_node->state]);
		seq_printf(s, "%-3u\n", ip_node->node_mask);
	}
	spin_unlock_bh(&ip_tbl->bond_ip_list_lock);

	return 0;
}

static int unic_query_mac_list_hw(struct unic_dev *unic_dev, u32 *mac_idx,
				  struct list_head *list, bool *complete)
{
	struct unic_dbg_comm_addr_node *mac_node;
	struct unic_dbg_mac_entry *mac_entry;
	struct unic_dbg_mac_head req = {0};
	struct unic_dbg_mac_head *head;
	struct ubase_cmd_buf in, out;
	int ret;
	u8 i;

	head = kzalloc(UNIC_QUERY_MAC_LEN, GFP_ATOMIC);
	if (!head)
		return -ENOMEM;

	mac_entry = head->mac_entry;
	req.mac_idx = cpu_to_le32(*mac_idx);

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_MAC_TBL, true, sizeof(req),
			     &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_MAC_TBL, true,
			     UNIC_QUERY_MAC_LEN, head);
	ret = ubase_cmd_send_inout(unic_dev->comdev.adev, &in, &out);
	if (ret) {
		unic_err(unic_dev,
			 "failed to query mac hw tbl, ret = %d.\n", ret);
		goto err_out;
	}

	if (head->cur_mac_cnt > UNIC_DBG_MAC_NUM) {
		ret = -EINVAL;
		unic_err(unic_dev,
			 "invalid cur_mac_cnt = %u out of range [0, %d].\n",
			 head->cur_mac_cnt, UNIC_DBG_MAC_NUM);
		goto err_out;
	}

	for (i = 0; i < head->cur_mac_cnt; i++) {
		mac_node = kzalloc(sizeof(*mac_node), GFP_ATOMIC);
		if (!mac_node) {
			ret = -ENOMEM;
			goto err_out;
		}

		memcpy(&mac_node->mac_addr, &mac_entry[i].mac_addr,
		       sizeof(mac_node->mac_addr));
		mac_node->eport = le32_to_cpu(mac_entry[i].eport);
		list_add_tail(&mac_node->node, list);
	}

	*complete = head->cur_mac_cnt < UNIC_DBG_MAC_NUM;

	*mac_idx = le32_to_cpu(head->mac_idx);

err_out:
	kfree(head);

	return ret;
}

int unic_dbg_dump_mac_tbl_list_hw(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct unic_dbg_comm_addr_node *mac_node, *next_node;
	struct unic_caps *caps = &unic_dev->caps;
	struct list_head list;
	int ret, cnt = 0;
	u32 size;

	ret = unic_dbg_check_dev_state(unic_dev);
	if (ret)
		return ret;

	if (!unic_dev_cfg_mac_supported(unic_dev))
		return -EOPNOTSUPP;

	size = caps->uc_mac_tbl_size + caps->mc_mac_tbl_size;

	INIT_LIST_HEAD(&list);
	ret = unic_common_query_addr_list(unic_dev, size,
					  UNIC_DBG_MAC_NUM, &list,
					  unic_query_mac_list_hw);
	if (ret)
		goto release_list;

	seq_printf(s, "No     %-28sEXTEND_INFO\n", "MAC_ADDR");

	list_for_each_entry(mac_node, &list, node) {
		seq_printf(s, "%-7d", cnt++);
		seq_printf(s, "%-28pM", &mac_node->mac_addr);
		seq_printf(s, "0x%08x\n", mac_node->eport);
	}

release_list:
	list_for_each_entry_safe(mac_node, next_node, &list, node) {
		list_del(&mac_node->node);
		kfree(mac_node);
	}

	return ret;
}

static int unic_query_mng_list_hw(struct unic_dev *unic_dev, u32 *mng_idx,
				  struct list_head *list, bool *complete)
{
	struct unic_dbg_mng_entry *mng_entry;
	struct unic_dbg_mng_node *mng_node;
	struct unic_dbg_mng_head req = {0};
	struct unic_dbg_mng_head *head;
	struct ubase_cmd_buf in, out;
	int ret;
	u8 i;

	head = kzalloc(UNIC_QUERY_MNG_LEN, GFP_KERNEL);
	if (!head)
		return -ENOMEM;

	mng_entry = head->entries;
	req.idx = cpu_to_le16((u16)*mng_idx);

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_MNG_TBL, true, sizeof(req),
			     &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_MNG_TBL, true,
			     UNIC_QUERY_MNG_LEN, head);
	ret = ubase_cmd_send_inout(unic_dev->comdev.adev, &in, &out);
	if (ret) {
		unic_err(unic_dev,
			 "failed to query mng hw tbl, ret = %d.\n", ret);
		goto err_out;
	}

	if (head->entry_num > UNIC_DBG_MNG_NUM) {
		ret = -EINVAL;
		unic_err(unic_dev,
			 "invalid entry_num = %u out of range is [0, %d].\n",
			 head->entry_num, UNIC_DBG_MNG_NUM);
		goto err_out;
	}

	for (i = 0; i < head->entry_num; i++) {
		mng_node = kzalloc(sizeof(*mng_node), GFP_KERNEL);
		if (!mng_node) {
			ret = -ENOMEM;
			goto err_out;
		}
		memcpy(&mng_node->mac, &mng_entry[i].mac,
		       sizeof(mng_node->mac));
		mng_node->mac_mask = mng_entry[i].mac_mask;
		mng_node->vlan = le16_to_cpu(mng_entry[i].vlan);
		mng_node->vlan_mask = mng_entry[i].vlan_mask;
		mng_node->ether_type = le16_to_cpu(mng_entry[i].ether_type);
		mng_node->ether_type_mask = mng_entry[i].ether_type_mask;
		mng_node->port_bitmap = mng_entry[i].port_bitmap;
		mng_node->drop = mng_entry[i].drop;
		mng_node->jfrn = le16_to_cpu(mng_entry[i].jfrn);
		list_add_tail(&mng_node->node, list);
	}

	*complete = head->entry_num < UNIC_DBG_MNG_NUM;

	*mng_idx = le32_to_cpu(head->idx);

err_out:
	kfree(head);

	return ret;
}

int unic_dbg_dump_mng_tbl_list_hw(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct unic_dbg_mng_node *mng_node, *next_node;
	struct unic_caps *caps = &unic_dev->caps;
	u32 size = caps->mng_tbl_size;
	struct list_head list;
	int ret, cnt = 0;

	ret = unic_dbg_check_dev_state(unic_dev);
	if (ret)
		return ret;

	if (!unic_dev_cfg_mac_supported(unic_dev))
		return -EOPNOTSUPP;

	INIT_LIST_HEAD(&list);
	ret = unic_common_query_addr_list(unic_dev, size,
					  UNIC_DBG_MNG_NUM, &list,
					  unic_query_mng_list_hw);
	if (ret)
		goto release_list;

	seq_printf(s, "No %-18smac_mask vlan vlan_mask ether_type ether_type_mask port_bitmap drop jfrn\n",
		   "mac");
	list_for_each_entry(mng_node, &list, node) {
		seq_printf(s, "%-3d", cnt++);
		seq_printf(s, "%-18pM", mng_node->mac);
		seq_printf(s, "%-9u", mng_node->mac_mask);
		seq_printf(s, "%-5u", mng_node->vlan);
		seq_printf(s, "%-10u", mng_node->vlan_mask);
		seq_printf(s, "%-11u", mng_node->ether_type);
		seq_printf(s, "%-16u", mng_node->ether_type_mask);
		seq_printf(s, "0x%-10x", mng_node->port_bitmap);
		seq_printf(s, "%-5u", mng_node->drop);
		seq_printf(s, "%u\n", mng_node->jfrn);
	}

release_list:
	list_for_each_entry_safe(mng_node, next_node, &list, node) {
		list_del(&mng_node->node);
		kfree(mng_node);
	}

	return ret;
}

static int unic_query_vlan_list_hw(struct unic_dev *unic_dev, u32 *idx,
				   struct list_head *list, bool *complete)
{
	struct unic_dbg_vlan_entry *vlan_entry;
	struct unic_dbg_vlan_node *vlan_node;
	struct unic_dbg_vlan_head req = {0};
	struct unic_dbg_vlan_head *resp;
	struct ubase_cmd_buf in, out;
	u16 vlan_cnt, i;
	int ret;

	resp = kzalloc(UNIC_QUERY_VLAN_LEN, GFP_ATOMIC);
	if (!resp)
		return -ENOMEM;

	vlan_entry = resp->vlan_entry;
	req.idx = cpu_to_le16((u16)*idx);

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_VLAN_TBL, true,
			     sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_VLAN_TBL, true,
			     UNIC_QUERY_VLAN_LEN, resp);
	ret = ubase_cmd_send_inout(unic_dev->comdev.adev, &in, &out);
	if (ret && ret != -EPERM) {
		unic_err(unic_dev, "failed to query vlan hw tbl, ret = %d.\n",
			 ret);
		goto err_out;
	}

	vlan_cnt = le16_to_cpu(resp->vlan_cnt);
	if (vlan_cnt > UNIC_DBG_VLAN_NUM) {
		ret = -EINVAL;
		unic_err(unic_dev,
			 "invalid vlan_cnt = %u out of range [0, %d].\n",
			 vlan_cnt, UNIC_DBG_VLAN_NUM);
		goto err_out;
	}

	for (i = 0; i < vlan_cnt; i++) {
		vlan_node = kzalloc(sizeof(*vlan_node), GFP_ATOMIC);
		if (!vlan_node) {
			ret = -ENOMEM;
			goto err_out;
		}
		vlan_node->ue_id = le16_to_cpu(vlan_entry[i].ue_id);
		vlan_node->vlan_id = le16_to_cpu(vlan_entry[i].vlan_id);
		list_add_tail(&vlan_node->node, list);
	}

	*idx = le16_to_cpu(resp->idx);

err_out:
	kfree(resp);

	return ret;
}

int unic_dbg_dump_vlan_tbl_list_hw(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct unic_dbg_vlan_node *vlan_node, *tmp_node;
	struct list_head list;
	int ret, cnt = 0;
	u32 size;

	ret = unic_dbg_check_dev_state(unic_dev);
	if (ret)
		return ret;

	INIT_LIST_HEAD(&list);
	size = unic_dev->caps.vlan_tbl_size;
	ret = unic_common_query_addr_list(unic_dev, size, UNIC_DBG_VLAN_NUM,
					  &list, unic_query_vlan_list_hw);
	if (ret)
		goto release_list;

	seq_puts(s, "No     UE_ID    VLAN_ID\n");

	list_for_each_entry(vlan_node, &list, node) {
		seq_printf(s, "%-7d", cnt++);
		seq_printf(s, "%-9u", vlan_node->ue_id);
		seq_printf(s, "%-12u\n", vlan_node->vlan_id);
	}

release_list:
	list_for_each_entry_safe(vlan_node, tmp_node, &list, node) {
		list_del(&vlan_node->node);
		kfree(vlan_node);
	}

	return ret;
}
