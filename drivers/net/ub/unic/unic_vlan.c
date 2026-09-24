// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025-2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#define dev_fmt(fmt) "unic: (pid %d) " fmt, current->pid

#include "unic_hw.h"
#include "unic_vlan.h"

static int unic_init_vlan_filter(struct unic_dev *unic_dev)
{
	struct unic_vlan_tbl *vlan_tbl = &unic_dev->vport.vlan_tbl;

	vlan_tbl->cur_vlan_fltr_en = false;

	return unic_set_vlan_filter_hw(unic_dev, false);
}

int unic_init_vlan_config(struct unic_dev *unic_dev)
{
	int ret;

	if (unic_dev_ubl_supported(unic_dev) ||
	    !unic_dev_cfg_vlan_filter_supported(unic_dev))
		return 0;

	ret = unic_init_vlan_filter(unic_dev);
	if (ret)
		return ret;

	return unic_set_vlan_table(unic_dev, htons(ETH_P_8021Q), 0, true);
}

void unic_uninit_vlan_config(struct unic_dev *unic_dev)
{
	struct unic_vlan_tbl *vlan_tbl = &unic_dev->vport.vlan_tbl;
	struct unic_vlan_cfg *vlan, *tmp;
	struct list_head tmp_del_list;

	if (unic_dev_ubl_supported(unic_dev) ||
	    !unic_dev_cfg_vlan_filter_supported(unic_dev))
		return;

	mutex_lock(&vlan_tbl->vlan_cmd_mutex);

	INIT_LIST_HEAD(&tmp_del_list);
	spin_lock_bh(&vlan_tbl->vlan_lock);

	list_for_each_entry_safe(vlan, tmp, &vlan_tbl->vlan_list, node)
		list_move_tail(&vlan->node, &tmp_del_list);

	spin_unlock_bh(&vlan_tbl->vlan_lock);

	list_for_each_entry_safe(vlan, tmp, &tmp_del_list, node) {
		unic_set_port_vlan_hw(unic_dev, vlan->vlan_id, false);
		list_del(&vlan->node);
		kfree(vlan);
	}

	mutex_unlock(&vlan_tbl->vlan_cmd_mutex);
}

static bool unic_need_update_port_vlan(struct unic_dev *unic_dev, u16 vlan_id,
				       bool is_add)
{
	struct unic_vlan_tbl *vlan_tbl = &unic_dev->vport.vlan_tbl;
	struct unic_vlan_cfg *vlan;
	bool exist = false;

	if (!is_add && !vlan_id)
		return false;

	spin_lock_bh(&vlan_tbl->vlan_lock);

	list_for_each_entry(vlan, &vlan_tbl->vlan_list, node) {
		if (vlan->vlan_id == vlan_id) {
			exist = true;
			break;
		}
	}

	spin_unlock_bh(&vlan_tbl->vlan_lock);

	if (is_add && exist) {
		/* vlan 0 may be added twice when 8021q module is enabled */
		if (vlan_id)
			dev_warn(unic_dev->comdev.adev->dev.parent,
				 "failed to add port vlan(%hu), which is already in hw.\n",
				 vlan_id);
		return false;
	}

	if (!is_add && !exist) {
		dev_warn(unic_dev->comdev.adev->dev.parent,
			 "failed to delete port vlan(%hu), which is not in hw.\n",
			 vlan_id);
		return false;
	}

	return true;
}

static int unic_set_port_vlan(struct unic_dev *unic_dev, u16 vlan_id,
			      bool is_add)
{
	if (!unic_need_update_port_vlan(unic_dev, vlan_id, is_add))
		return 0;

	return unic_set_port_vlan_hw(unic_dev, vlan_id, is_add);
}

static void unic_add_vlan_table(struct unic_dev *unic_dev,
				struct unic_vlan_cfg *vlan)
{
	struct unic_vlan_tbl *vlan_tbl = &unic_dev->vport.vlan_tbl;
	struct unic_vlan_cfg *entry;

	spin_lock_bh(&vlan_tbl->vlan_lock);

	list_for_each_entry(entry, &vlan_tbl->vlan_list, node) {
		if (entry->vlan_id == vlan->vlan_id) {
			kfree(vlan);
			goto out;
		}
	}

	list_add_tail(&vlan->node, &vlan_tbl->vlan_list);

out:
	spin_unlock_bh(&vlan_tbl->vlan_lock);
}

static void unic_rm_vlan_table(struct unic_dev *unic_dev, u16 vlan_id)
{
	struct unic_vlan_tbl *vlan_tbl = &unic_dev->vport.vlan_tbl;
	struct unic_vlan_cfg *vlan, *tmp;

	spin_lock_bh(&vlan_tbl->vlan_lock);

	list_for_each_entry_safe(vlan, tmp, &vlan_tbl->vlan_list, node) {
		if (vlan->vlan_id == vlan_id) {
			list_del(&vlan->node);
			kfree(vlan);
			break;
		}
	}

	spin_unlock_bh(&vlan_tbl->vlan_lock);
}

int unic_set_vlan_table(struct unic_dev *unic_dev, __be16 proto, u16 vlan_id,
			bool is_add)
{
	struct unic_vlan_tbl *vlan_tbl = &unic_dev->vport.vlan_tbl;
	struct unic_vlan_cfg *vlan;
	int ret;

	if (vlan_id >= VLAN_N_VID)
		return -EINVAL;

	if (proto != htons(ETH_P_8021Q))
		return -EPROTONOSUPPORT;

	mutex_lock(&vlan_tbl->vlan_cmd_mutex);

	spin_lock_bh(&vlan_tbl->vlan_lock);

	if (is_add && test_bit(vlan_id, vlan_tbl->vlan_del_fail_bmap)) {
		clear_bit(vlan_id, vlan_tbl->vlan_del_fail_bmap);
	} else if (test_bit(UNIC_STATE_RESETTING, &unic_dev->state) &&
		   !is_add) {
		set_bit(vlan_id, vlan_tbl->vlan_del_fail_bmap);
		spin_unlock_bh(&vlan_tbl->vlan_lock);
		ret = -EBUSY;
		goto unlock;
	}

	spin_unlock_bh(&vlan_tbl->vlan_lock);

	if (is_add) {
		vlan = kzalloc(sizeof(*vlan), GFP_KERNEL);
		if (!vlan) {
			ret = -ENOMEM;
			goto unlock;
		}

		vlan->vlan_id = vlan_id;
	}

	ret = unic_set_port_vlan(unic_dev, vlan_id, is_add);
	if (!ret) {
		if (is_add)
			unic_add_vlan_table(unic_dev, vlan);
		else if (!is_add && vlan_id != 0)
			unic_rm_vlan_table(unic_dev, vlan_id);
		set_bit(UNIC_VPORT_STATE_VLAN_FILTER_CHANGE,
			&unic_dev->vport.state);
	} else if (!is_add) {
		/* when remove hw vlan filter failed, record the vlan id,
		 * and try to remove it from hw later, to be consistent
		 * with stack.
		 */
		spin_lock_bh(&vlan_tbl->vlan_lock);
		set_bit(vlan_id, vlan_tbl->vlan_del_fail_bmap);
		spin_unlock_bh(&vlan_tbl->vlan_lock);
	} else {
		kfree(vlan);
	}

unlock:
	mutex_unlock(&vlan_tbl->vlan_cmd_mutex);

	return ret;
}

static bool unic_need_enable_vlan_filter(struct unic_dev *unic_dev, bool enable)
{
	struct unic_vlan_tbl *vlan_tbl = &unic_dev->vport.vlan_tbl;
	struct unic_vlan_cfg *vlan;

	if ((unic_dev->netdev_flags & UNIC_USER_UPE) || !enable)
		return false;

	spin_lock_bh(&vlan_tbl->vlan_lock);
	list_for_each_entry(vlan, &vlan_tbl->vlan_list, node) {
		if (vlan->vlan_id != 0) {
			spin_unlock_bh(&vlan_tbl->vlan_lock);
			return true;
		}
	}

	spin_unlock_bh(&vlan_tbl->vlan_lock);

	return false;
}

int unic_set_vlan_filter(struct unic_dev *unic_dev, bool enable)
{
	struct unic_vlan_tbl *vlan_tbl = &unic_dev->vport.vlan_tbl;
	bool need_en;
	int ret = 0;

	need_en = unic_need_enable_vlan_filter(unic_dev, enable);
	if (need_en == vlan_tbl->cur_vlan_fltr_en)
		return ret;

	ret = unic_set_vlan_filter_hw(unic_dev, need_en);
	if (ret)
		return ret;

	vlan_tbl->cur_vlan_fltr_en = need_en;

	return ret;
}

static void unic_sync_vlan_filter_state(struct unic_dev *unic_dev)
{
	struct unic_vport *vport = &unic_dev->vport;
	int ret;

	if (!test_and_clear_bit(UNIC_VPORT_STATE_VLAN_FILTER_CHANGE,
				&vport->state))
		return;

	ret = unic_set_vlan_filter(unic_dev, true);
	if (ret) {
		unic_err(unic_dev,
			 "failed to sync vlan filter state, ret = %d.\n", ret);
		set_bit(UNIC_VPORT_STATE_VLAN_FILTER_CHANGE, &vport->state);
	}
}

static u16 unic_find_del_fail_vlan(struct unic_dev *unic_dev)
{
	struct unic_vlan_tbl *vlan_tbl = &unic_dev->vport.vlan_tbl;
	u16 vlan_id;

	spin_lock_bh(&vlan_tbl->vlan_lock);
	vlan_id = find_first_bit(vlan_tbl->vlan_del_fail_bmap, VLAN_N_VID);
	spin_unlock_bh(&vlan_tbl->vlan_lock);

	return vlan_id;
}

static void unic_rm_del_fail_vlan(struct unic_dev *unic_dev, u16 vlan_id)
{
	struct unic_vlan_tbl *vlan_tbl = &unic_dev->vport.vlan_tbl;
	bool pending;

	spin_lock_bh(&vlan_tbl->vlan_lock);
	pending = test_and_clear_bit(vlan_id, vlan_tbl->vlan_del_fail_bmap);
	spin_unlock_bh(&vlan_tbl->vlan_lock);

	/* the vlan was re-added by user while the delete was in flight,
	 * keep it in the table.
	 */
	if (!pending)
		return;

	unic_rm_vlan_table(unic_dev, vlan_id);
}

void unic_sync_vlan_filter(struct unic_dev *unic_dev)
{
#define UNIC_MAX_SYNC_COUNT	60

	struct unic_vlan_tbl *vlan_tbl = &unic_dev->vport.vlan_tbl;
	int ret, sync_cnt = 0;
	u16 vlan_id;

	if (unic_dev_ubl_supported(unic_dev) ||
	    !unic_dev_cfg_vlan_filter_supported(unic_dev))
		return;

	mutex_lock(&vlan_tbl->vlan_cmd_mutex);

	vlan_id = unic_find_del_fail_vlan(unic_dev);
	while (vlan_id != VLAN_N_VID) {
		ret = unic_set_port_vlan(unic_dev, vlan_id, false);
		if (ret)
			break;

		unic_rm_del_fail_vlan(unic_dev, vlan_id);
		set_bit(UNIC_VPORT_STATE_VLAN_FILTER_CHANGE,
			&unic_dev->vport.state);

		if (++sync_cnt >= UNIC_MAX_SYNC_COUNT)
			break;

		vlan_id = unic_find_del_fail_vlan(unic_dev);
	}

	unic_sync_vlan_filter_state(unic_dev);

	mutex_unlock(&vlan_tbl->vlan_cmd_mutex);
}
