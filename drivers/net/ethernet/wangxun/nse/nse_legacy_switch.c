// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_common.h"
#include "nse_lib.h"
#include "nse_legacy_switch.h"

static enum nse_status
nse_aq_cfg_legacy_sw_fltr(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_SET_LEGACY_FILTER &&
	    opc != NSE_AQ_OPC_GET_LEGACY_FILTER)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (opc != NSE_AQ_OPC_SET_LEGACY_FILTER &&
	    hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

static enum nse_status
nse_legacy_sw_sync_mac_table(struct nse_legacy_switch *sw)
{
	struct nse_hw *hw = sw->hw;
	enum nse_status status = NSE_SUCCESS;
	struct nse_aqc_legacy_fltrs *buf = NULL;
	struct nse_aqc_legacy_fltr_elem *elem;
	u16 i, buf_size;

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf) {
		status = NSE_ERR_NO_MEMORY;
		goto nse_legacy_sw_sync_mac_table_fail;
	}

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->fltr_type = cpu_to_le16(NSE_AQC_LEGACY_MAC_FLTR);

	for (i = 0; i < sw->num_mac_entries; i++) {
		if (sw->mac_table[i].state & NSE_FLTR_STATE_MODIFIED) {
			u32 mac_fltr_reg0 = 0;
			u32 mac_fltr_reg1 = 0;
			u8 *addr = sw->mac_table[i].addr;
			u16 addr_hi16;

			sw->mac_table[i].state &= ~(NSE_FLTR_STATE_MODIFIED);
			elem->index = cpu_to_le16(i);
			addr_hi16 = ((u32)addr[1] | ((u32)addr[0] << 8));
			if (sw->mac_table[i].state & NSE_FLTR_STATE_IN_USE) {
				mac_fltr_reg1 |= NSE_LEGACY_MAC_FLTR_EN;
				mac_fltr_reg1 |= (sw->mac_table[i].vsi_list <<
								NSE_LEGACY_MAC_FLTR_VSI_LIST_S) &
								NSE_LEGACY_MAC_FLTR_VSI_LIST_M;
				mac_fltr_reg1 |= (addr_hi16 <<
						  NSE_LEGACY_MAC_FLTR_ADDR_HIGH_16_S) &
								NSE_LEGACY_MAC_FLTR_ADDR_HIGH_16_M;
				mac_fltr_reg0 = ((u32)addr[5] |	 ((u32)addr[4] << 8) |
					  ((u32)addr[3] << 16) | ((u32)addr[2] << 24));
			} else { /* remove */
				mac_fltr_reg1 &= ~NSE_LEGACY_MAC_FLTR_EN;
			}

			elem->content0 = cpu_to_le32(mac_fltr_reg0);
			elem->content1 = cpu_to_le32(mac_fltr_reg1);

			dev_info(nse_hw_to_dev(hw),
				"Real to config hw mac filter, idx = %d, reg0 = 0x%x, reg1 = 0x%x\n",
				i, mac_fltr_reg0, mac_fltr_reg1);
			status = nse_aq_cfg_legacy_sw_fltr(hw, buf, buf_size,
						 NSE_AQ_OPC_SET_LEGACY_FILTER, NULL);
			if (status) {
				dev_err(nse_hw_to_dev(hw),
					"Failed to set mac filter, err = %d\n",
					status);
				goto nse_legacy_sw_sync_mac_table_fail;
			}
		}
	}

	devm_kfree(nse_hw_to_dev(hw), buf);
	return NSE_SUCCESS;

nse_legacy_sw_sync_mac_table_fail:
	if (buf)
		devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

enum nse_status
nse_legacy_sw_add_mac(struct nse_hw *hw, const u8 *addr, u16 vsi_handle)
{
	struct nse_legacy_switch *sw = NULL;
	enum nse_status status = NSE_ERR_MAX_LIMIT;

	u16 hw_vsi_id;
	int i;

	if (!hw)
		return NSE_ERR_BAD_PTR;

	sw = hw->legacy_switch;
	if (!sw) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] legacy switch info is NULL\n",
			__func__, __LINE__);
		status = NSE_ERR_BAD_PTR;
		goto exit;
	}

	if (is_zero_ether_addr(addr)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] mac address is zero\n",
			__func__, __LINE__);
		status = NSE_ERR_PARAM;
		goto exit;
	}

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] invalid vsi handle\n",
			__func__, __LINE__);
		status = NSE_ERR_PARAM;
		goto exit;
	}

	hw_vsi_id =	nse_get_hw_vsi_num(hw, vsi_handle);

	mutex_lock(&sw->mac_tbl_lock);

	/*if find exsited, update vsi list*/
	for (i = 0; i < sw->num_mac_entries; i++) {
		if (sw->mac_table[i].state & NSE_FLTR_STATE_IN_USE) {
			if (ether_addr_equal(addr, sw->mac_table[i].addr)) {
				if (!(sw->mac_table[i].vsi_list & (1ULL << hw_vsi_id))) {
					sw->mac_table[i].state |= NSE_FLTR_STATE_MODIFIED;
					sw->mac_table[i].vsi_list |= (1ULL << hw_vsi_id);

					dev_info(nse_hw_to_dev(hw),
						"Start to update mac fltr into legacy switch:\n");
					dev_info(nse_hw_to_dev(hw),
						"\t mac addr: %pM, mac entry idx: %d, vsi_list: 0x%x, new vsi: %d\n",
						addr, i, sw->mac_table[i].vsi_list, hw_vsi_id);

					status = nse_legacy_sw_sync_mac_table(sw);
				} else
					status = NSE_ERR_ALREADY_EXISTS;

				goto unlock_exit;
			}
		}
	}

	/*not exsited, get a new one*/
	for (i = 0; i < sw->num_mac_entries; i++) {
		if (sw->mac_table[i].state & NSE_FLTR_STATE_IN_USE)
			continue;
		sw->mac_table[i].state |= NSE_FLTR_STATE_MODIFIED |
					       NSE_FLTR_STATE_IN_USE;
		memcpy(sw->mac_table[i].addr, addr, ETH_ALEN);
		sw->mac_table[i].vsi_list |= (1ULL << hw_vsi_id);

		dev_info(nse_hw_to_dev(hw),
			"Start to add a new mac fltr into legacy switch:\n");
		dev_info(nse_hw_to_dev(hw),
			"\t mac addr: %pM, mac entry idx: %d, vsi_list: 0x%x, new vsi: %d\n",
			addr, i, sw->mac_table[i].vsi_list, hw_vsi_id);

		status = nse_legacy_sw_sync_mac_table(sw);
		goto unlock_exit;
	}
unlock_exit:
	mutex_unlock(&sw->mac_tbl_lock);
exit:
	return status;
}

static enum nse_status
nse_legacy_sw_replay_mac(struct nse_hw *hw, const u8 *addr, u16 vsi_handle)
{
	struct nse_legacy_switch *sw = NULL;
	enum nse_status status = NSE_ERR_MAX_LIMIT;

	u16 hw_vsi_id;
	int i;

	if (!hw)
		return NSE_ERR_BAD_PTR;

	sw = hw->legacy_switch;
	if (!sw) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] legacy switch info is NULL\n",
			__func__, __LINE__);
		status = NSE_ERR_BAD_PTR;
		goto exit;
	}

	if (is_zero_ether_addr(addr)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] mac address is zero\n",
			__func__, __LINE__);
		status = NSE_ERR_PARAM;
		goto exit;
	}

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] invalid vsi handle\n",
			__func__, __LINE__);
		status = NSE_ERR_PARAM;
		goto exit;
	}

	hw_vsi_id =	nse_get_hw_vsi_num(hw, vsi_handle);

	mutex_lock(&sw->mac_tbl_lock);

	/*if find exsited, replay vsi list*/
	for (i = 0; i < sw->num_mac_entries; i++) {
		if (sw->mac_table[i].state & NSE_FLTR_STATE_IN_USE) {
			if (ether_addr_equal(addr, sw->mac_table[i].addr)) {
				sw->mac_table[i].state |= NSE_FLTR_STATE_MODIFIED;
				sw->mac_table[i].vsi_list |= (1ULL << hw_vsi_id);
				dev_info(nse_hw_to_dev(hw),
					"Start to replay mac fltr into legacy switch:\n");
				dev_info(nse_hw_to_dev(hw),
					"\t mac addr: %pM, mac entry idx: %d, vsi_list: 0x%x, new vsi: %d\n",
					addr, i, sw->mac_table[i].vsi_list, hw_vsi_id);
				status = nse_legacy_sw_sync_mac_table(sw);
				goto unlock_exit;
			}
		}
	}

	/*not exsited, get a new one*/
	for (i = 0; i < sw->num_mac_entries; i++) {
		if (sw->mac_table[i].state & NSE_FLTR_STATE_IN_USE)
			continue;
		sw->mac_table[i].state |= NSE_FLTR_STATE_MODIFIED |
					       NSE_FLTR_STATE_IN_USE;
		memcpy(sw->mac_table[i].addr, addr, ETH_ALEN);
		sw->mac_table[i].vsi_list |= (1ULL << hw_vsi_id);

		dev_info(nse_hw_to_dev(hw),
			"Start to replay a new mac fltr into legacy switch:\n");
		dev_info(nse_hw_to_dev(hw),
			"\t mac addr: %pM, mac entry idx: %d, vsi_list: 0x%x, new vsi: %d\n",
			addr, i, sw->mac_table[i].vsi_list, hw_vsi_id);

		status = nse_legacy_sw_sync_mac_table(sw);
		goto unlock_exit;
	}
unlock_exit:
	mutex_unlock(&sw->mac_tbl_lock);
exit:
	return status;
}

enum nse_status
nse_legacy_sw_remove_mac(struct nse_hw *hw, const u8 *addr, u16 vsi_handle)
{
	struct nse_legacy_switch *sw = NULL;
	enum nse_status status = NSE_SUCCESS;

	u16 hw_vsi_id;
	int i;

	if (!hw)
		return NSE_ERR_BAD_PTR;

	sw = hw->legacy_switch;
	if (!sw) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] legacy switch info is NULL\n",
			__func__, __LINE__);
		status = NSE_ERR_BAD_PTR;
		goto exit;
	}

	if (is_zero_ether_addr(addr)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] mac address is zero\n",
			__func__, __LINE__);
		status = NSE_ERR_PARAM;
		goto exit;
	}

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] invalid vsi handle\n",
			__func__, __LINE__);
		status = NSE_ERR_PARAM;
		goto exit;
	}

	hw_vsi_id =	nse_get_hw_vsi_num(hw, vsi_handle);

	mutex_lock(&sw->mac_tbl_lock);

	for (i = 0; i < sw->num_mac_entries; i++) {
		if (!ether_addr_equal(addr, sw->mac_table[i].addr))
			continue;

		if (!(sw->mac_table[i].vsi_list & (1ULL << hw_vsi_id)))
			continue;

		/*found with mac address and hw vsi id, should sync it*/
		sw->mac_table[i].state |= NSE_FLTR_STATE_MODIFIED;
		if (sw->mac_table[i].vsi_list == (1ULL << hw_vsi_id)) {
			/*if mac addr is only belong to current vsi, free it*/
			sw->mac_table[i].state &= ~NSE_FLTR_STATE_IN_USE;
			memset(sw->mac_table[i].addr, 0, ETH_ALEN);
			sw->mac_table[i].vsi_list = 0;
		} else
			sw->mac_table[i].vsi_list &= ~(1ULL << hw_vsi_id);

		dev_info(nse_hw_to_dev(hw),
			"Start to remove mac fltr from legacy switch:\n");
		dev_info(nse_hw_to_dev(hw),
			"\t mac addr: %pM, mac entry idx: %d, vsi_list: 0x%x, removed vsi: %d\n",
			addr, i, sw->mac_table[i].vsi_list, hw_vsi_id);

		status = nse_legacy_sw_sync_mac_table(sw);
		goto exit_unlock;
	}

	/*not found*/
	status = NSE_ERR_DOES_NOT_EXIST;

exit_unlock:
	mutex_unlock(&sw->mac_tbl_lock);
exit:
	return status;
}

static enum nse_status
nse_legacy_sw_get_mac_list_by_vsi(struct nse_legacy_switch *sw,
				u16 hw_vsi_id, struct list_head *list_head)
{
	struct nse_legacy_sw_fltr_list_entry *tmp, *list_itr;
	struct nse_hw *hw = sw->hw;
	enum nse_status status = NSE_SUCCESS;

	int i;

	for (i = 0; i < sw->num_mac_entries; i++) {
		if (!(sw->mac_table[i].state & NSE_FLTR_STATE_IN_USE))
			continue;

		if (sw->mac_table[i].vsi_list & (1ULL << hw_vsi_id)) {
			list_itr = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*list_itr), GFP_KERNEL);
			if (!list_itr) {
				status = NSE_ERR_NO_MEMORY;
				goto err;
			}
			memcpy(list_itr->fltr_info.mac_addr, sw->mac_table[i].addr, ETH_ALEN);
			list_add_tail(&list_itr->list_entry, list_head);
		}
	}

	return NSE_SUCCESS;
err:
	list_for_each_entry_safe(list_itr, tmp, list_head, list_entry) {
		list_del(&list_itr->list_entry);
		devm_kfree(nse_hw_to_dev(hw), list_itr);
	}
	return status;
}

static enum nse_status
nse_legacy_sw_replay_rm_vsi_mac_fltr(struct nse_hw *hw,
				u16 vsi_handle, bool is_replay)
{
	struct nse_legacy_switch *sw = NULL;
	struct list_head temp_list;
	struct nse_legacy_sw_fltr_list_entry *tmp, *list_itr;
	enum nse_status status = NSE_SUCCESS;
	u16 hw_vsi_id;

	if (!hw)
		return NSE_ERR_BAD_PTR;

	sw = hw->legacy_switch;
	if (!sw) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] legacy switch info is NULL\n",
			__func__, __LINE__);
		return NSE_ERR_BAD_PTR;
	}

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] invalid vsi handle\n",
			__func__, __LINE__);
		return NSE_ERR_PARAM;
	}

	INIT_LIST_HEAD(&temp_list);
	hw_vsi_id =	nse_get_hw_vsi_num(hw, vsi_handle);
	mutex_lock(&sw->mac_tbl_lock);
	status = nse_legacy_sw_get_mac_list_by_vsi(sw, hw_vsi_id, &temp_list);
	mutex_unlock(&sw->mac_tbl_lock);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to get mac list by vsi(%d)\n",
			__func__, __LINE__, hw_vsi_id);
		return status;
	}

	list_for_each_entry_safe(list_itr, tmp, &temp_list, list_entry) {
		if (is_replay) {
			status = nse_legacy_sw_replay_mac(hw,
						list_itr->fltr_info.mac_addr, vsi_handle);
			if (status) {
				dev_err(nse_hw_to_dev(hw),
					"[%s, %d] Failed to replay mac addr(%pM) by vsi(%d)\n",
					__func__, __LINE__,
						list_itr->fltr_info.mac_addr, hw_vsi_id);
				goto err;
			}
		} else {
			status = nse_legacy_sw_remove_mac(hw,
						list_itr->fltr_info.mac_addr, vsi_handle);
			if (status && status != NSE_ERR_DOES_NOT_EXIST) {
				dev_err(nse_hw_to_dev(hw),
					"[%s, %d] Failed to remove mac addr(%pM) by vsi(%d)\n",
					__func__, __LINE__,
						list_itr->fltr_info.mac_addr, hw_vsi_id);
			}
		}
	}
err:
	/* memory of temp list need be freed always */
	list_for_each_entry_safe(list_itr, tmp, &temp_list, list_entry) {
		list_del(&list_itr->list_entry);
		devm_kfree(nse_hw_to_dev(hw), list_itr);
	}

	return status;
}

static enum nse_status
nse_legacy_sw_sync_vlan_table(struct nse_legacy_switch *sw)
{
	struct nse_hw *hw = sw->hw;
	enum nse_status status = NSE_SUCCESS;
	struct nse_aqc_legacy_fltrs *buf = NULL;
	struct nse_aqc_legacy_fltr_elem *elem;
	u16 i, buf_size;

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf) {
		status = NSE_ERR_NO_MEMORY;
		goto nse_legacy_sw_sync_vlan_table_fail;
	}

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->fltr_type = cpu_to_le16(NSE_AQC_LEGACY_VLAN_FLTR);

	for (i = 0; i < sw->num_vlan_entries; i++) {
		if (sw->vlan_table[i].state & NSE_FLTR_STATE_MODIFIED) {
			u32 vlan_fltr_reg = 0;

			sw->vlan_table[i].state &= ~(NSE_FLTR_STATE_MODIFIED);
			elem->index = cpu_to_le16(i);
			if (sw->vlan_table[i].state & NSE_FLTR_STATE_IN_USE) {
				vlan_fltr_reg |= NSE_LEGACY_VLAN_FLTR_EN;
				vlan_fltr_reg |= (sw->vlan_table[i].vsi_list <<
								NSE_LEGACY_VLAN_FLTR_VSI_LIST_S) &
								NSE_LEGACY_VLAN_FLTR_VSI_LIST_M;
				vlan_fltr_reg |= (sw->vlan_table[i].vid <<
								NSE_LEGACY_VLAN_FLTR_VID_S) &
								NSE_LEGACY_VLAN_FLTR_VID_M;
			} else { /* remove */
				vlan_fltr_reg &= ~NSE_LEGACY_VLAN_FLTR_EN;
			}

			elem->content0 = cpu_to_le32(vlan_fltr_reg);

			dev_info(nse_hw_to_dev(hw),
				"Real to config hw vlan filter, idx = %d, reg = 0x%x\n",
				i, vlan_fltr_reg);
			status = nse_aq_cfg_legacy_sw_fltr(hw, buf, buf_size,
						 NSE_AQ_OPC_SET_LEGACY_FILTER, NULL);
			if (status) {
				dev_err(nse_hw_to_dev(hw),
					"Failed to set vlan filter, err = %d\n",
					status);
				goto nse_legacy_sw_sync_vlan_table_fail;
			}
		}
	}

	devm_kfree(nse_hw_to_dev(hw), buf);
	return NSE_SUCCESS;

nse_legacy_sw_sync_vlan_table_fail:
	if (buf)
		devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

enum nse_status
nse_legacy_sw_add_vlan(struct nse_hw *hw, u16 vid, u16 vsi_handle)
{
	struct nse_legacy_switch *sw = NULL;
	enum nse_status status = NSE_ERR_MAX_LIMIT;

	u16 hw_vsi_id;
	int i;

	if (!hw)
		return NSE_ERR_BAD_PTR;

	sw = hw->legacy_switch;
	if (!sw) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] legacy switch info is NULL\n",
			__func__, __LINE__);
		status = NSE_ERR_BAD_PTR;
		goto exit;
	}

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] invalid vsi handle\n",
			__func__, __LINE__);
		status = NSE_ERR_PARAM;
		goto exit;
	}

	hw_vsi_id =	nse_get_hw_vsi_num(hw, vsi_handle);

	mutex_lock(&sw->vlan_tbl_lock);

	/*if find exsited, update vsi list*/
	for (i = 0; i < sw->num_vlan_entries; i++) {
		if (sw->vlan_table[i].state & NSE_FLTR_STATE_IN_USE) {
			if (vid == sw->vlan_table[i].vid) {
				if (!(sw->vlan_table[i].vsi_list & (1ULL << hw_vsi_id))) {
					sw->vlan_table[i].state |= NSE_FLTR_STATE_MODIFIED;
					sw->vlan_table[i].vsi_list |= (1ULL << hw_vsi_id);

					dev_info(nse_hw_to_dev(hw),
						"Start to update vlan fltr into legacy switch:\n");
					dev_info(nse_hw_to_dev(hw),
						"\t vlan id: %d, vlan entry idx: %d, vsi_list: 0x%x, new vsi: %d\n",
						vid, i, sw->vlan_table[i].vsi_list, hw_vsi_id);

					status = nse_legacy_sw_sync_vlan_table(sw);
				} else
					status = NSE_ERR_ALREADY_EXISTS;

				goto exit_unlock;
			}
		}
	}

	/*not exsited, get a new one*/
	for (i = 0; i < sw->num_vlan_entries; i++) {
		if (sw->vlan_table[i].state & NSE_FLTR_STATE_IN_USE)
			continue;
		sw->vlan_table[i].state |= NSE_FLTR_STATE_MODIFIED |
					       NSE_FLTR_STATE_IN_USE;

		sw->vlan_table[i].vid = vid;
		sw->vlan_table[i].vsi_list |= (1ULL << hw_vsi_id);

		dev_info(nse_hw_to_dev(hw),
			"Start to add a new vlan fltr into legacy switch:\n");
		dev_info(nse_hw_to_dev(hw),
			"\t vlan id: %d, vlan entry idx: %d, vsi_list: 0x%x, new vsi: %d\n",
			vid, i, sw->vlan_table[i].vsi_list, hw_vsi_id);

		status = nse_legacy_sw_sync_vlan_table(sw);
		goto exit_unlock;
	}

exit_unlock:
	mutex_unlock(&sw->vlan_tbl_lock);
exit:
	return status;
}

static enum nse_status
nse_legacy_sw_replay_vlan(struct nse_hw *hw, u16 vid, u16 vsi_handle)
{
	struct nse_legacy_switch *sw = NULL;
	enum nse_status status = NSE_ERR_MAX_LIMIT;

	u16 hw_vsi_id;
	int i;

	if (!hw)
		return NSE_ERR_BAD_PTR;

	sw = hw->legacy_switch;
	if (!sw) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] legacy switch info is NULL\n",
			__func__, __LINE__);
		status = NSE_ERR_BAD_PTR;
		goto exit;
	}

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] invalid vsi handle\n",
			__func__, __LINE__);
		status = NSE_ERR_PARAM;
		goto exit;
	}

	hw_vsi_id =	nse_get_hw_vsi_num(hw, vsi_handle);

	mutex_lock(&sw->vlan_tbl_lock);

	/*if find exsited, update vsi list*/
	for (i = 0; i < sw->num_vlan_entries; i++) {
		if (sw->vlan_table[i].state & NSE_FLTR_STATE_IN_USE) {
			if (vid == sw->vlan_table[i].vid) {
				sw->vlan_table[i].state |= NSE_FLTR_STATE_MODIFIED;
				sw->vlan_table[i].vsi_list |= (1ULL << hw_vsi_id);

				dev_info(nse_hw_to_dev(hw),
					"Start to replay vlan fltr into legacy switch:\n");
				dev_info(nse_hw_to_dev(hw),
					"\t vlan id: %d, vlan entry idx: %d, vsi_list: 0x%x, new vsi: %d\n",
					vid, i, sw->vlan_table[i].vsi_list, hw_vsi_id);

				status = nse_legacy_sw_sync_vlan_table(sw);
				goto exit_unlock;
			}
		}
	}

	/*not exsited, get a new one*/
	for (i = 0; i < sw->num_vlan_entries; i++) {
		if (sw->vlan_table[i].state & NSE_FLTR_STATE_IN_USE)
			continue;
		sw->vlan_table[i].state |= NSE_FLTR_STATE_MODIFIED |
					       NSE_FLTR_STATE_IN_USE;

		sw->vlan_table[i].vid = vid;
		sw->vlan_table[i].vsi_list |= (1ULL << hw_vsi_id);

		dev_info(nse_hw_to_dev(hw),
			"Start to replay a new vlan fltr into legacy switch:\n");
		dev_info(nse_hw_to_dev(hw),
			"\t vlan id: %d, vlan entry idx: %d, vsi_list: 0x%x, new vsi: %d\n",
			vid, i, sw->vlan_table[i].vsi_list, hw_vsi_id);

		status = nse_legacy_sw_sync_vlan_table(sw);
		goto exit_unlock;
	}

exit_unlock:
	mutex_unlock(&sw->vlan_tbl_lock);
exit:
	return status;
}

enum nse_status
nse_legacy_sw_remove_vlan(struct nse_hw *hw, u16 vid, u16 vsi_handle)
{
	struct nse_legacy_switch *sw = NULL;
	enum nse_status status = NSE_SUCCESS;

	u16 hw_vsi_id;
	int i;

	if (!hw)
		return NSE_ERR_BAD_PTR;

	sw = hw->legacy_switch;
	if (!sw) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] legacy switch info is NULL\n",
			__func__, __LINE__);
		status = NSE_ERR_BAD_PTR;
		goto exit;
	}

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] invalid vsi handle\n",
			__func__, __LINE__);
		status = NSE_ERR_PARAM;
		goto exit;
	}

	hw_vsi_id =	nse_get_hw_vsi_num(hw, vsi_handle);

	mutex_lock(&sw->vlan_tbl_lock);

	for (i = 0; i < sw->num_vlan_entries; i++) {
		if (vid != sw->vlan_table[i].vid)
			continue;

		if (!(sw->vlan_table[i].vsi_list & (1ULL << hw_vsi_id)))
			continue;

		/*found with vlan id and hw vsi id, should sync it*/
		sw->vlan_table[i].state |= NSE_FLTR_STATE_MODIFIED;
		if (sw->vlan_table[i].vsi_list == (1ULL << hw_vsi_id)) {
			/*if vid is only belong to current vsi, free it*/
			sw->vlan_table[i].state &= ~NSE_FLTR_STATE_IN_USE;
			sw->vlan_table[i].vid = 0;
			sw->vlan_table[i].vsi_list = 0;
		} else
			sw->vlan_table[i].vsi_list &= ~(1ULL << hw_vsi_id);

		dev_info(nse_hw_to_dev(hw),
			"Start to remove vlan fltr from legacy switch:\n");
		dev_info(nse_hw_to_dev(hw),
			"\t vlan id: %d, vlan entry idx: %d, vsi_list: 0x%x, removed vsi: %d\n",
			vid, i, sw->vlan_table[i].vsi_list, hw_vsi_id);

		status = nse_legacy_sw_sync_vlan_table(sw);
		goto exit_unlock;
	}

	/*not found*/
	status = NSE_ERR_DOES_NOT_EXIST;

exit_unlock:
	mutex_unlock(&sw->vlan_tbl_lock);
exit:
	return status;
}

static enum nse_status
nse_legacy_sw_get_vlan_list_by_vsi(struct nse_legacy_switch *sw,
				u16 hw_vsi_id, struct list_head *list_head)
{
	struct nse_legacy_sw_fltr_list_entry *tmp, *list_itr;
	struct nse_hw *hw = sw->hw;
	enum nse_status status = NSE_SUCCESS;

	int i;

	for (i = 0; i < sw->num_vlan_entries; i++) {
		if (!(sw->vlan_table[i].state & NSE_FLTR_STATE_IN_USE))
			continue;

		if (sw->vlan_table[i].vsi_list & (1ULL << hw_vsi_id)) {
			list_itr = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*list_itr), GFP_KERNEL);
			if (!list_itr) {
				status = NSE_ERR_NO_MEMORY;
				goto err;
			}
			list_itr->fltr_info.vlan_id = sw->vlan_table[i].vid;
			list_add_tail(&list_itr->list_entry, list_head);
		}
	}

	return NSE_SUCCESS;
err:
	list_for_each_entry_safe(list_itr, tmp, list_head, list_entry) {
		list_del(&list_itr->list_entry);
		devm_kfree(nse_hw_to_dev(hw), list_itr);
	}
	return status;
}

static enum nse_status
nse_legacy_sw_replay_rm_vsi_vlan_fltr(struct nse_hw *hw,
				u16 vsi_handle, bool is_replay)
{
	struct nse_legacy_switch *sw = NULL;
	struct list_head temp_list;
	struct nse_legacy_sw_fltr_list_entry *tmp, *list_itr;
	enum nse_status status = NSE_SUCCESS;
	u16 hw_vsi_id;

	if (!hw)
		return NSE_ERR_BAD_PTR;

	sw = hw->legacy_switch;
	if (!sw) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] legacy switch info is NULL\n",
			__func__, __LINE__);
		return NSE_ERR_BAD_PTR;
	}

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] invalid vsi handle\n",
			__func__, __LINE__);
		return NSE_ERR_PARAM;
	}

	INIT_LIST_HEAD(&temp_list);
	hw_vsi_id =	nse_get_hw_vsi_num(hw, vsi_handle);
	mutex_lock(&sw->vlan_tbl_lock);
	status = nse_legacy_sw_get_vlan_list_by_vsi(sw, hw_vsi_id, &temp_list);
	mutex_unlock(&sw->vlan_tbl_lock);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to get vlan list by vsi(%d)\n",
			__func__, __LINE__, hw_vsi_id);
		return status;
	}

	list_for_each_entry_safe(list_itr, tmp, &temp_list, list_entry) {
		if (is_replay) {
			status = nse_legacy_sw_replay_vlan(hw,
						list_itr->fltr_info.vlan_id, vsi_handle);
			if (status) {
				dev_err(nse_hw_to_dev(hw),
					"[%s, %d] Failed to replay vlan(id=%d) by vsi(%d)\n",
					__func__, __LINE__,
						list_itr->fltr_info.vlan_id, hw_vsi_id);
				goto err;
			}
		} else {
			status = nse_legacy_sw_remove_vlan(hw,
						list_itr->fltr_info.vlan_id, vsi_handle);
			if (status && status != NSE_ERR_DOES_NOT_EXIST) {
				dev_err(nse_hw_to_dev(hw),
					"[%s, %d] Failed to remove vlan(id=%d) by vsi(%d)\n",
					__func__, __LINE__,
						list_itr->fltr_info.vlan_id, hw_vsi_id);
			}
		}
	}
err:
	/* memory of temp list need be freed always */
	list_for_each_entry_safe(list_itr, tmp, &temp_list, list_entry) {
		list_del(&list_itr->list_entry);
		devm_kfree(nse_hw_to_dev(hw), list_itr);
	}
	return status;
}

static enum nse_status
nse_legacy_sw_sync_ethtype_table(struct nse_legacy_switch *sw)
{
	struct nse_hw *hw = sw->hw;
	enum nse_status status = NSE_SUCCESS;
	struct nse_aqc_legacy_fltrs *buf = NULL;
	struct nse_aqc_legacy_fltr_elem *elem;
	u16 i, buf_size;

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf) {
		status = NSE_ERR_NO_MEMORY;
		goto nse_legacy_sw_sync_ethtype_table_fail;
	}

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->fltr_type = cpu_to_le16(NSE_AQC_LEGACY_ETHTYPE_FLTR);

	for (i = 0; i < sw->num_ethtype_entries; i++) {
		if (sw->ethtype_table[i].state & NSE_FLTR_STATE_MODIFIED) {
			u32 ethtype_reg0 = 0;
			u32 ethtype_reg1 = 0;

			sw->ethtype_table[i].state &= ~(NSE_FLTR_STATE_MODIFIED);
			elem->index = cpu_to_le16(i);
			if (sw->ethtype_table[i].state & NSE_FLTR_STATE_IN_USE) {
				ethtype_reg0 |= NSE_LEGACY_ETHTYPE_FLTR_EN;
				ethtype_reg0 |= (sw->ethtype_table[i].ethtype <<
								NSE_LEGACY_ETHTYPE_FLTR_ETYPE_S) &
								NSE_LEGACY_ETHTYPE_FLTR_ETYPE_M;
				ethtype_reg1 |= (sw->ethtype_table[i].vsi_list <<
						 NSE_LEGACY_ETHTYPE_FLTR_VSI_LIST_S) &
								NSE_LEGACY_ETHTYPE_FLTR_VSI_LIST_M;
			} else { /* remove */
				ethtype_reg0 &= ~NSE_LEGACY_ETHTYPE_FLTR_EN;
			}

			elem->content0 = cpu_to_le32(ethtype_reg0);
			elem->content1 = cpu_to_le32(ethtype_reg1);

			dev_info(nse_hw_to_dev(hw),
				"Real to config hw ethtype filter, idx = %d, reg0 = 0x%x, reg1 = 0x%x\n",
				i, ethtype_reg0, ethtype_reg1);
			status = nse_aq_cfg_legacy_sw_fltr(hw, buf, buf_size,
						 NSE_AQ_OPC_SET_LEGACY_FILTER, NULL);
			if (status) {
				dev_err(nse_hw_to_dev(hw),
					"Failed to set ethtype filter, err = %d\n",
					status);
				goto nse_legacy_sw_sync_ethtype_table_fail;
			}
		}
	}

	devm_kfree(nse_hw_to_dev(hw), buf);
	return NSE_SUCCESS;

nse_legacy_sw_sync_ethtype_table_fail:
	if (buf)
		devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

enum nse_status
nse_legacy_sw_add_ethtype(struct nse_hw *hw, u16 ethtype, u16 vsi_handle)
{
	struct nse_legacy_switch *sw = NULL;
	enum nse_status status = NSE_ERR_MAX_LIMIT;

	u16 hw_vsi_id;
	int i;

	if (!hw)
		return NSE_ERR_BAD_PTR;

	sw = hw->legacy_switch;
	if (!sw) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] legacy switch info is NULL\n",
			__func__, __LINE__);
		status = NSE_ERR_BAD_PTR;
		goto exit;
	}

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] invalid vsi handle\n",
			__func__, __LINE__);
		status = NSE_ERR_PARAM;
		goto exit;
	}

	hw_vsi_id =	nse_get_hw_vsi_num(hw, vsi_handle);

	mutex_lock(&sw->ethtype_tbl_lock);

	/*if find exsited, update vsi list*/
	for (i = 0; i < sw->num_ethtype_entries; i++) {
		if (sw->ethtype_table[i].state & NSE_FLTR_STATE_IN_USE) {
			if (ethtype == sw->ethtype_table[i].ethtype) {
				if (!(sw->ethtype_table[i].vsi_list & (1ULL << hw_vsi_id))) {
					sw->ethtype_table[i].state |= NSE_FLTR_STATE_MODIFIED;
					sw->ethtype_table[i].vsi_list |= (1ULL << hw_vsi_id);

					dev_info(nse_hw_to_dev(hw),
						"Start to update ethtype fltr into legacy switch:\n");
					dev_info(nse_hw_to_dev(hw),
						"\t ethtype: 0x%x, ethtype entry idx: %d, vsi_list: 0x%x, new vsi: %d\n",
						ethtype, i, sw->ethtype_table[i].vsi_list,
							hw_vsi_id);

					status = nse_legacy_sw_sync_ethtype_table(sw);
				} else
					status = NSE_ERR_ALREADY_EXISTS;

				goto exit_unlock;
			}
		}
	}

	/*not exsited, get a new one*/
	for (i = 0; i < sw->num_ethtype_entries; i++) {
		if (sw->ethtype_table[i].state & NSE_FLTR_STATE_IN_USE)
			continue;
		sw->ethtype_table[i].state |= NSE_FLTR_STATE_MODIFIED |
					       NSE_FLTR_STATE_IN_USE;

		sw->ethtype_table[i].ethtype = ethtype;
		sw->ethtype_table[i].vsi_list |= (1ULL << hw_vsi_id);

		dev_info(nse_hw_to_dev(hw),
			"Start to add a new ethtype fltr into legacy switch:\n");
		dev_info(nse_hw_to_dev(hw),
			"\t ethtype: 0x%x, ethtype entry idx: %d, vsi_list: 0x%x, new vsi: %d\n",
			ethtype, i, sw->ethtype_table[i].vsi_list, hw_vsi_id);

		status = nse_legacy_sw_sync_ethtype_table(sw);
		goto exit_unlock;
	}

exit_unlock:
	mutex_unlock(&sw->ethtype_tbl_lock);
exit:
	return status;
}

enum nse_status
nse_legacy_sw_replay_ethtype(struct nse_hw *hw, u16 ethtype, u16 vsi_handle)
{
	struct nse_legacy_switch *sw = NULL;
	enum nse_status status = NSE_ERR_MAX_LIMIT;

	u16 hw_vsi_id;
	int i;

	if (!hw)
		return NSE_ERR_BAD_PTR;

	sw = hw->legacy_switch;
	if (!sw) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] legacy switch info is NULL\n",
			__func__, __LINE__);
		status = NSE_ERR_BAD_PTR;
		goto exit;
	}

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] invalid vsi handle\n",
			__func__, __LINE__);
		status = NSE_ERR_PARAM;
		goto exit;
	}

	hw_vsi_id =	nse_get_hw_vsi_num(hw, vsi_handle);

	mutex_lock(&sw->ethtype_tbl_lock);

	/*if find exsited, update vsi list*/
	for (i = 0; i < sw->num_ethtype_entries; i++) {
		if (sw->ethtype_table[i].state & NSE_FLTR_STATE_IN_USE) {
			if (ethtype == sw->ethtype_table[i].ethtype) {
				sw->ethtype_table[i].state |= NSE_FLTR_STATE_MODIFIED;
				sw->ethtype_table[i].vsi_list |= (1ULL << hw_vsi_id);

				dev_info(nse_hw_to_dev(hw),
					"Start to replay ethtype fltr into legacy switch:\n");
				dev_info(nse_hw_to_dev(hw),
					"\t ethtype: 0x%x, ethtype entry idx: %d, vsi_list: 0x%x, new vsi: %d\n",
					ethtype, i, sw->ethtype_table[i].vsi_list, hw_vsi_id);

				status = nse_legacy_sw_sync_ethtype_table(sw);
				goto exit_unlock;
			}
		}
	}

	/*not exsited, get a new one*/
	for (i = 0; i < sw->num_ethtype_entries; i++) {
		if (sw->ethtype_table[i].state & NSE_FLTR_STATE_IN_USE)
			continue;
		sw->ethtype_table[i].state |= NSE_FLTR_STATE_MODIFIED |
					       NSE_FLTR_STATE_IN_USE;

		sw->ethtype_table[i].ethtype = ethtype;
		sw->ethtype_table[i].vsi_list |= (1ULL << hw_vsi_id);

		dev_info(nse_hw_to_dev(hw),
			"Start to replay a new ethtype fltr into legacy switch:\n");
		dev_info(nse_hw_to_dev(hw),
			"\t ethtype: 0x%x, ethtype entry idx: %d, vsi_list: 0x%x, new vsi: %d\n",
			ethtype, i, sw->ethtype_table[i].vsi_list, hw_vsi_id);

		status = nse_legacy_sw_sync_ethtype_table(sw);
		goto exit_unlock;
	}

exit_unlock:
	mutex_unlock(&sw->ethtype_tbl_lock);
exit:
	return status;
}

enum nse_status
nse_legacy_sw_remove_ethtype(struct nse_hw *hw, u16 ethtype, u16 vsi_handle)
{
	struct nse_legacy_switch *sw = NULL;
	enum nse_status status = NSE_SUCCESS;

	u16 hw_vsi_id;
	int i;

	if (!hw)
		return NSE_ERR_BAD_PTR;

	sw = hw->legacy_switch;
	if (!sw) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] legacy switch info is NULL\n",
			__func__, __LINE__);
		status = NSE_ERR_BAD_PTR;
		goto exit;
	}

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] invalid vsi handle\n",
			__func__, __LINE__);
		status = NSE_ERR_PARAM;
		goto exit;
	}

	hw_vsi_id =	nse_get_hw_vsi_num(hw, vsi_handle);

	mutex_lock(&sw->ethtype_tbl_lock);

	for (i = 0; i < sw->num_ethtype_entries; i++) {
		if (ethtype != sw->ethtype_table[i].ethtype)
			continue;

		if (!(sw->ethtype_table[i].vsi_list & (1ULL << hw_vsi_id)))
			continue;

		/*found with ethtype and hw vsi id, should sync it*/
		sw->ethtype_table[i].state |= NSE_FLTR_STATE_MODIFIED;
		if (sw->ethtype_table[i].vsi_list == (1ULL << hw_vsi_id)) {
			/*if ethtype is only belong to current vsi, free it*/
			sw->ethtype_table[i].state &= ~NSE_FLTR_STATE_IN_USE;
			sw->ethtype_table[i].ethtype = 0;
			sw->ethtype_table[i].vsi_list = 0;
		} else
			sw->ethtype_table[i].vsi_list &= ~(1ULL << hw_vsi_id);

		dev_info(nse_hw_to_dev(hw),
			"Start to remove ethtype fltr from legacy switch:\n");
		dev_info(nse_hw_to_dev(hw),
			"\t ethtype: 0x%x, ethtype entry idx: %d, vsi_list: 0x%x, removed vsi: %d\n",
			ethtype, i, sw->ethtype_table[i].vsi_list, hw_vsi_id);

		status = nse_legacy_sw_sync_ethtype_table(sw);
		goto exit_unlock;
	}

	/*not found*/
	status = NSE_ERR_DOES_NOT_EXIST;

exit_unlock:
	mutex_unlock(&sw->ethtype_tbl_lock);
exit:
	return status;
}

static enum nse_status
nse_legacy_sw_get_ethtype_list_by_vsi(struct nse_legacy_switch *sw,
				u16 hw_vsi_id, struct list_head *list_head)
{
	struct nse_legacy_sw_fltr_list_entry *tmp, *list_itr;
	struct nse_hw *hw = sw->hw;
	enum nse_status status = NSE_SUCCESS;

	int i;

	for (i = 0; i < sw->num_ethtype_entries; i++) {
		if (!(sw->ethtype_table[i].state & NSE_FLTR_STATE_IN_USE))
			continue;

		if (sw->ethtype_table[i].vsi_list & (1ULL << hw_vsi_id)) {
			list_itr = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*list_itr), GFP_KERNEL);
			if (!list_itr) {
				status = NSE_ERR_NO_MEMORY;
				goto err;
			}
			list_itr->fltr_info.ethtype = sw->ethtype_table[i].ethtype;
			list_add_tail(&list_itr->list_entry, list_head);
		}
	}

	return NSE_SUCCESS;
err:
	list_for_each_entry_safe(list_itr, tmp, list_head, list_entry) {
		list_del(&list_itr->list_entry);
		devm_kfree(nse_hw_to_dev(hw), list_itr);
	}
	return status;
}

static enum nse_status
nse_legacy_sw_replay_rm_vsi_ethtype_fltr(struct nse_hw *hw,
				u16 vsi_handle, bool is_replay)
{
	struct nse_legacy_switch *sw = NULL;
	struct list_head temp_list;
	struct nse_legacy_sw_fltr_list_entry *tmp, *list_itr;
	enum nse_status status = NSE_SUCCESS;
	u16 hw_vsi_id;

	if (!hw)
		return NSE_ERR_BAD_PTR;

	sw = hw->legacy_switch;
	if (!sw) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] legacy switch info is NULL\n",
			__func__, __LINE__);
		return NSE_ERR_BAD_PTR;
	}

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] invalid vsi handle\n",
			__func__, __LINE__);
		return NSE_ERR_PARAM;
	}

	INIT_LIST_HEAD(&temp_list);
	hw_vsi_id =	nse_get_hw_vsi_num(hw, vsi_handle);
	mutex_lock(&sw->ethtype_tbl_lock);
	status = nse_legacy_sw_get_ethtype_list_by_vsi(sw, hw_vsi_id, &temp_list);
	mutex_unlock(&sw->ethtype_tbl_lock);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to get ethtype list by vsi(%d)\n",
			__func__, __LINE__, hw_vsi_id);
		return status;
	}

	list_for_each_entry_safe(list_itr, tmp, &temp_list, list_entry) {
		if (is_replay) {
			status = nse_legacy_sw_replay_ethtype(hw,
						list_itr->fltr_info.ethtype, vsi_handle);
			if (status) {
				dev_err(nse_hw_to_dev(hw),
					"[%s, %d] Failed to replay ethtype(0x%x) by vsi(%d)\n",
					__func__, __LINE__,
						list_itr->fltr_info.ethtype, hw_vsi_id);
				goto err;
			}
		} else {
			status = nse_legacy_sw_remove_ethtype(hw,
						list_itr->fltr_info.ethtype, vsi_handle);
			if (status && status != NSE_ERR_DOES_NOT_EXIST) {
				dev_err(nse_hw_to_dev(hw),
					"[%s, %d] Failed to remove ethtype(0x%x) by vsi(%d)\n",
					__func__, __LINE__,
						list_itr->fltr_info.ethtype, hw_vsi_id);
			}
		}
	}

err:
	/* memory of temp list need be freed always */
	list_for_each_entry_safe(list_itr, tmp, &temp_list, list_entry) {
		list_del(&list_itr->list_entry);
		devm_kfree(nse_hw_to_dev(hw), list_itr);
	}

	return status;
}

void
nse_legacy_sw_remove_vsi_fltr(struct nse_hw *hw, u16 vsi_handle)
{
	nse_legacy_sw_replay_rm_vsi_mac_fltr(hw, vsi_handle, false);
	nse_legacy_sw_replay_rm_vsi_vlan_fltr(hw, vsi_handle, false);
	nse_legacy_sw_replay_rm_vsi_ethtype_fltr(hw, vsi_handle, false);
}

enum nse_status
nse_replay_vsi_all_fltr_legacy(struct nse_hw *hw, u16 vsi_handle)
{
	enum nse_status status = NSE_SUCCESS;

	status = nse_legacy_sw_replay_rm_vsi_mac_fltr(hw, vsi_handle, true);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to replay mac fltr by vsi(vsi_handle=%d)\n",
			__func__, __LINE__, vsi_handle);
		goto err;
	}
	status = nse_legacy_sw_replay_rm_vsi_vlan_fltr(hw, vsi_handle, true);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to replay vlan fltr by vsi(vsi_handle=%d)\n",
			__func__, __LINE__, vsi_handle);
		goto err;
	}
	status = nse_legacy_sw_replay_rm_vsi_ethtype_fltr(hw, vsi_handle, true);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to replay ethtype fltr by vsi(vsi_handle=%d)\n",
			__func__, __LINE__, vsi_handle);
		goto err;
	}
err:
	return status;
}

void nse_drain_sw_replay_list_legacy(struct nse_hw *hw)
{
	/*in hw legacy switch mode, we use a temporay replay list
	 * when do replay, which is different with flex switch.
	 * so that we needn't a global replay list, but keep code if need.
	 */
}

void nse_replace_sw_replay_list_legacy(struct nse_hw *hw)
{
	/*in hw legacy switch mode, we use a temporay replay list
	 * when do replay, which is different with flex switch.
	 * so that we needn't a global replay list, but keep code if need.
	 */
}
