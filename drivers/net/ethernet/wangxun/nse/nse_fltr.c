// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_lib.h"
#include "nse_fltr.h"

static enum nse_status
nse_fltr_remove_mac_legacy(struct nse_vsi *vsi, const u8 *mac,
				    enum nse_sw_fwd_act_type act_type);

static enum nse_status
nse_fltr_add_mac_legacy(struct nse_vsi *vsi, const u8 *mac,
				 enum nse_sw_fwd_act_type act_type);

/**
 * nse_fltr_free_list - free filter lists helper
 * @dev: pointer to the device struct
 * @h: pointer to the list head to be freed
 *
 * Helper function to free filter lists
 *
 */
void nse_fltr_free_list(struct device *dev, struct list_head *h)
{
	struct nse_fltr_list_entry *e, *tmp;

	list_for_each_entry_safe(e, tmp, h, list_entry) {
		list_del(&e->list_entry);
		devm_kfree(dev, e);
	}
}

/**
 * nse_fltr_add_entry_to_list - allocate and add filter entry to list
 * @dev: pointer to device needed by alloc function
 * @info: filter info struct that gets added to the passed in list
 * @list: pointer to the list which contains MAC filters entry
 */
static enum nse_status
nse_fltr_add_entry_to_list(struct device *dev, struct nse_fltr_info *info,
			   struct list_head *list)
{
	struct nse_fltr_list_entry *entry;

	entry = devm_kzalloc(dev, sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return NSE_ERR_NO_MEMORY;

	entry->fltr_info = *info;

	INIT_LIST_HEAD(&entry->list_entry);
	list_add_tail(&entry->list_entry, list);

	return NSE_SUCCESS;
}

enum nse_status nse_fltr_add_mac_list_legacy(struct nse_vsi *vsi,
			struct list_head *list)
{
	struct nse_fltr_list_entry *e, *tmp;
	enum nse_status status = NSE_SUCCESS;

	if (!list)
		return NSE_ERR_PARAM;

	list_for_each_entry_safe(e, tmp, list, list_entry) {
		status = nse_fltr_add_mac_legacy(vsi, e->fltr_info.l_data.mac.mac_addr,
						e->fltr_info.fltr_act);
		if (status && status != NSE_ERR_ALREADY_EXISTS)
			return status;
	}

	return NSE_SUCCESS;
}

/**
 * nse_fltr_add_mac_list - add list of MAC filters
 * @vsi: pointer to VSI struct
 * @list: list of filters
 */
enum nse_status nse_fltr_add_mac_list(struct nse_vsi *vsi,
			struct list_head *list)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_add_mac(hw, list);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		status = nse_fltr_add_mac_list_legacy(vsi, list);

	return status;
}

/**
 * nse_fltr_add_bmc_mac_list - add list of BMC MAC filters
 * @vsi: pointer to VSI struct
 * @list: list of filters
 */
enum nse_status nse_fltr_add_bmc_mac_list(struct nse_vsi *vsi,
			struct list_head *list)
{
	return nse_add_bmc_mac(&vsi->back->hw, list);
}

/**
 * nse_fltr_add_roce_mac_list - add list of roce MAC filters
 * @vsi: pointer to VSI struct
 * @list: list of filters
 */
enum nse_status nse_fltr_add_roce_mac_list(struct nse_vsi *vsi,
			struct list_head *list)
{
	return nse_add_roce_mac(&vsi->back->hw, list);
}

/**
 * nse_fltr_add_vlan_list - add list of VLAN filters
 * @vsi: pointer to VSI struct
 * @list: list of filters
 */
static enum nse_status nse_fltr_add_vlan_list(struct nse_vsi *vsi, struct list_head *list)
{
	return nse_add_vlan(&vsi->back->hw, list);
}

/**
 * nse_fltr_add_mac_vlan_list - add list of MAC VLAN filters
 * @vsi: pointer to VSI struct
 * @list: list of filters
 */
static enum nse_status
nse_fltr_add_mac_vlan_list(struct nse_vsi *vsi, struct list_head *list)
{
	return nse_add_mac_vlan(&vsi->back->hw, list);
}

/**
 * nse_fltr_add_eth_list - add list of ethertype filters
 * @vsi: pointer to VSI struct
 * @list: list of filters
 */
static enum nse_status nse_fltr_add_eth_list(struct nse_vsi *vsi, struct list_head *list)
{
	return nse_add_eth_mac(&vsi->back->hw, list);
}

enum nse_status nse_fltr_remove_mac_list_legacy(struct nse_vsi *vsi,
			struct list_head *list)
{
	struct nse_fltr_list_entry *e, *tmp;
	enum nse_status status = NSE_SUCCESS;

	if (!list)
		return NSE_ERR_PARAM;

	list_for_each_entry_safe(e, tmp, list, list_entry) {
		status = nse_fltr_remove_mac_legacy(vsi, e->fltr_info.l_data.mac.mac_addr,
							e->fltr_info.fltr_act);
		if (status && status != NSE_ERR_DOES_NOT_EXIST)
			return status;
	}

	return NSE_SUCCESS;
}

/**
 * nse_fltr_remove_mac_list - remove list of MAC filters
 * @vsi: pointer to VSI struct
 * @list: list of filters
 */
enum nse_status nse_fltr_remove_mac_list(struct nse_vsi *vsi,
			struct list_head *list)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_remove_mac(hw, list);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		status = nse_fltr_remove_mac_list_legacy(vsi, list);

	return status;
}

/**
 * nse_fltr_remove_bmc_mac_list - remove list of BMC MAC filters
 * @vsi: pointer to VSI struct
 * @list: list of filters
 */
enum nse_status nse_fltr_remove_bmc_mac_list(struct nse_vsi *vsi,
			struct list_head *list)
{
	return nse_remove_bmc_mac(&vsi->back->hw, list);
}

/**
 * nse_fltr_remove_roce_mac_list - remove list of roce MAC filters
 * @vsi: pointer to VSI struct
 * @list: list of filters
 */
enum nse_status nse_fltr_remove_roce_mac_list(struct nse_vsi *vsi,
			struct list_head *list)
{
	return nse_remove_roce_mac(&vsi->back->hw, list);
}

/**
 * nse_fltr_remove_vlan_list - remove list of VLAN filters
 * @vsi: pointer to VSI struct
 * @list: list of filters
 */
static enum nse_status
nse_fltr_remove_vlan_list(struct nse_vsi *vsi, struct list_head *list)
{
	return nse_remove_vlan(&vsi->back->hw, list);
}

/**
 * nse_fltr_remove_mac_vlan_list - remove list of MAC VLAN filters
 * @vsi: pointer to VSI struct
 * @list: list of filters
 */
static enum nse_status
nse_fltr_remove_mac_vlan_list(struct nse_vsi *vsi, struct list_head *list)
{
	return nse_remove_mac_vlan(&vsi->back->hw, list);
}

/**
 * nse_fltr_remove_eth_list - remove list of ethertype filters
 * @vsi: pointer to VSI struct
 * @list: list of filters
 */
static enum nse_status nse_fltr_remove_eth_list(struct nse_vsi *vsi, struct list_head *list)
{
	return nse_remove_eth_mac(&vsi->back->hw, list);
}

/**
 * nse_fltr_add_mac_to_list - add MAC filter info to exsisting list
 * @vsi: pointer to VSI struct
 * @list: list to add filter info to
 * @mac: MAC address to add
 * @act_type: filter act_type
 */
enum nse_status
nse_fltr_add_mac_to_list(struct nse_vsi *vsi, struct list_head *list,
			 const u8 *mac, enum nse_sw_fwd_act_type act_type)
{
	struct nse_fltr_info info = { 0 };

	info.sw_id = vsi->port_info->sw_id;
	info.lkup_type = NSE_SW_LKUP_MAC;
	info.fltr_act = act_type;
	info.vsi_handle = vsi->idx;
	ether_addr_copy(info.l_data.mac.mac_addr, mac);

	return nse_fltr_add_entry_to_list(nse_pf_to_dev(vsi->back), &info,
					  list);
}

/**
 * nse_fltr_add_bmc_mac_to_list - add BMC MAC filter info to exsisting list
 * @vsi: pointer to VSI struct
 * @list: list to add filter info to
 * @mac: MAC address to add
 * @act_type: filter act_type
 */
enum nse_status
nse_fltr_add_bmc_mac_to_list(struct nse_vsi *vsi, struct list_head *list,
			 const u8 *mac, enum nse_sw_fwd_act_type act_type)
{
	struct nse_fltr_info info = { 0 };

	info.sw_id = vsi->port_info->sw_id;
	info.lkup_type = NSE_SW_LKUP_BMC_MAC;
	info.fltr_act = act_type;
	info.vsi_handle = vsi->idx;
	ether_addr_copy(info.l_data.mac.mac_addr, mac);

	return nse_fltr_add_entry_to_list(nse_pf_to_dev(vsi->back), &info,
					  list);
}

/**
 * nse_fltr_add_roce_mac_to_list - add roce MAC filter info to exsisting list
 * @vsi: pointer to VSI struct
 * @list: list to add filter info to
 * @dst_vsi: pointer to destination VSI struct
 * @mac: MAC address to add
 * @act_type: filter act_type
 */
enum nse_status
nse_fltr_add_roce_mac_to_list(struct nse_vsi *vsi, struct list_head *list,
			 struct nse_vsi *dst_vsi, const u8 *mac, enum nse_sw_fwd_act_type act_type)
{
	struct nse_fltr_info info = { 0 };

	info.sw_id = vsi->port_info->sw_id;
	info.lkup_type = NSE_SW_LKUP_ROCE_MAC;
	info.fltr_act = act_type;
	info.vsi_handle = vsi->idx;
	info.fwd_id.hw_vsi_id = dst_vsi->vsi_abs_num;
	ether_addr_copy(info.l_data.mac.mac_addr, mac);

	return nse_fltr_add_entry_to_list(nse_pf_to_dev(vsi->back), &info,
					  list);
}

/**
 * nse_fltr_add_vlan_to_list - add VLAN filter info to exsisting list
 * @vsi: pointer to VSI struct
 * @list: list to add filter info to
 * @vlan: VLAN filter details
 */
static enum nse_status
nse_fltr_add_vlan_to_list(struct nse_vsi *vsi, struct list_head *list,
			  struct nse_vlan *vlan)
{
	struct nse_fltr_info info = { 0 };

	info.sw_id = vsi->port_info->sw_id;
	info.lkup_type = NSE_SW_LKUP_VLAN;
	info.fltr_act = vlan->fwd_act;
	info.vsi_handle = vsi->idx;
	info.l_data.vlan.vlan_id = vlan->vid;
	info.l_data.vlan.tpid = vlan->tpid;
	info.l_data.vlan.tpid_valid = true;

	return nse_fltr_add_entry_to_list(nse_pf_to_dev(vsi->back), &info,
					  list);
}

/**
 * nse_fltr_add_mac_vlan_to_list - add MAC VLAN filter info to
 * exsisting list
 * @vsi: pointer to VSI struct
 * @list: list to add filter info to
 * @mac: MAC addr to add
 * @vlan_id: VLAN ID to add
 * @act_type: filter act_type
 */
static enum nse_status
nse_fltr_add_mac_vlan_to_list(struct nse_vsi *vsi, struct list_head *list,
			      const u8 *mac, u16 vlan_id,
			      enum nse_sw_fwd_act_type act_type)
{
	struct nse_fltr_info info = { 0 };

	if (!is_valid_ether_addr(mac) ||
	    is_broadcast_ether_addr(mac) || !vlan_id)
		return -EINVAL;

	info.sw_id = vsi->port_info->sw_id;
	info.lkup_type = NSE_SW_LKUP_MAC_VLAN;
	info.fltr_act = act_type;
	info.vsi_handle = vsi->idx;
	info.l_data.mac_vlan.vlan_id = vlan_id;
	ether_addr_copy(info.l_data.mac_vlan.mac_addr, mac);

	return nse_fltr_add_entry_to_list(nse_pf_to_dev(vsi->back), &info,
					  list);
}

/**
 * nse_fltr_add_eth_to_list - add ethertype filter info to exsisting list
 * @vsi: pointer to VSI struct
 * @list: list to add filter info to
 * @ethertype: ethertype of packet that matches filter
 * @flag: filter direction, Tx or Rx
 * @act_type: filter act_type
 */
static enum nse_status
nse_fltr_add_eth_to_list(struct nse_vsi *vsi, struct list_head *list,
			 u16 ethertype, u16 flag,
			 enum nse_sw_fwd_act_type act_type)
{
	struct nse_fltr_info info = { 0 };

	info.sw_id = vsi->port_info->sw_id;
	info.lkup_type = NSE_SW_LKUP_ETHERTYPE;
	info.fltr_act = act_type;
	info.vsi_handle = vsi->idx;
	info.l_data.ethertype_mac.ethertype = ethertype;

	if (flag == NSE_FLTR_TX)
		info.dir = NSE_FILTER_DIR_TX;
	else
		info.dir = NSE_FILTER_DIR_RX;

	return nse_fltr_add_entry_to_list(nse_pf_to_dev(vsi->back), &info,
					  list);
}

/**
 * nse_fltr_prepare_mac - add or remove MAC rule
 * @vsi: pointer to VSI struct
 * @mac: MAC address to add
 * @act_type: act_type to be performed on filter match
 * @mac_action: pointer to add or remove MAC function
 */
static enum nse_status
nse_fltr_prepare_mac(struct nse_vsi *vsi, const u8 *mac,
			enum nse_sw_fwd_act_type act_type,
			enum nse_status (*mac_action)
			(struct nse_vsi *, struct list_head *))
{
	LIST_HEAD(tmp_list);
	enum nse_status result;

	if (nse_fltr_add_mac_to_list(vsi, &tmp_list, mac, act_type)) {
		nse_fltr_free_list(nse_pf_to_dev(vsi->back), &tmp_list);
		return NSE_ERR_NO_MEMORY;
	}

	result = mac_action(vsi, &tmp_list);
	nse_fltr_free_list(nse_pf_to_dev(vsi->back), &tmp_list);
	return result;
}

/**
 * nse_fltr_prepare_bmc_mac - add or remove BMC MAC rule
 * @vsi: pointer to VSI struct
 * @mac: MAC address to add
 * @act_type: act_type to be performed on filter match
 * @mac_action: pointer to add or remove MAC function
 */
static enum nse_status
nse_fltr_prepare_bmc_mac(struct nse_vsi *vsi, const u8 *mac,
			enum nse_sw_fwd_act_type act_type,
			enum nse_status (*mac_action)
			(struct nse_vsi *, struct list_head *))
{
	LIST_HEAD(tmp_list);
	enum nse_status result;

	if (nse_fltr_add_bmc_mac_to_list(vsi, &tmp_list, mac, act_type)) {
		nse_fltr_free_list(nse_pf_to_dev(vsi->back), &tmp_list);
		return NSE_ERR_NO_MEMORY;
	}

	result = mac_action(vsi, &tmp_list);
	nse_fltr_free_list(nse_pf_to_dev(vsi->back), &tmp_list);
	return result;
}

/**
 * nse_fltr_prepare_roce_mac - add or remove roce MAC rule
 * @vsi: pointer to VSI struct
 * @mac: MAC address to add
 * @dst_vsi: pointer to destination VSI struct
 * @act_type: act_type to be performed on filter match
 * @mac_action: pointer to add or remove MAC function
 */
static enum nse_status
nse_fltr_prepare_roce_mac(struct nse_vsi *vsi, const u8 *mac,
			struct nse_vsi *dst_vsi,
			enum nse_sw_fwd_act_type act_type,
			enum nse_status (*mac_action)
			(struct nse_vsi *, struct list_head *))
{
	LIST_HEAD(tmp_list);
	enum nse_status result;

	if (nse_fltr_add_roce_mac_to_list(vsi, &tmp_list, dst_vsi, mac, act_type)) {
		nse_fltr_free_list(nse_pf_to_dev(vsi->back), &tmp_list);
		return NSE_ERR_NO_MEMORY;
	}

	result = mac_action(vsi, &tmp_list);
	nse_fltr_free_list(nse_pf_to_dev(vsi->back), &tmp_list);
	return result;
}

/**
 * nse_fltr_prepare_mac_and_broadcast - add or remove MAC and broadcast filter
 * @vsi: pointer to VSI struct
 * @mac: MAC address to add
 * @act_type: act_type to be performed on filter match
 * @mac_action: pointer to add or remove MAC function
 */
static enum nse_status
nse_fltr_prepare_mac_and_broadcast(struct nse_vsi *vsi, const u8 *mac,
				   enum nse_sw_fwd_act_type act_type,
				   enum nse_status(*mac_action)
				   (struct nse_vsi *, struct list_head *))
{
	u8 broadcast[ETH_ALEN];
	LIST_HEAD(tmp_list);
	enum nse_status result;

	eth_broadcast_addr(broadcast);
	if (nse_fltr_add_mac_to_list(vsi, &tmp_list, mac, act_type) ||
	    nse_fltr_add_mac_to_list(vsi, &tmp_list, broadcast, act_type)) {
		nse_fltr_free_list(nse_pf_to_dev(vsi->back), &tmp_list);
		return NSE_ERR_NO_MEMORY;
	}

	result = mac_action(vsi, &tmp_list);
	nse_fltr_free_list(nse_pf_to_dev(vsi->back), &tmp_list);
	return result;
}

/**
 * nse_fltr_prepare_vlan - add or remove VLAN filter
 * @vsi: pointer to VSI struct
 * @vlan: VLAN filter details
 * @vlan_action: pointer to add or remove VLAN function
 */
static enum nse_status
nse_fltr_prepare_vlan(struct nse_vsi *vsi, struct nse_vlan *vlan,
		      enum nse_status (*vlan_action)
		      (struct nse_vsi *, struct list_head *))
{
	LIST_HEAD(tmp_list);
	enum nse_status result;

	if (nse_fltr_add_vlan_to_list(vsi, &tmp_list, vlan))
		return NSE_ERR_NO_MEMORY;

	result = vlan_action(vsi, &tmp_list);
	nse_fltr_free_list(nse_pf_to_dev(vsi->back), &tmp_list);
	return result;
}

/**
 * nse_fltr_prepare_mac_vlan - add or remove MAC VLAN filter
 * @vsi: pointer to VSI struct
 * @mac: MAC address to add
 * @vlan_id: VLAN ID to add
 * @act_type: act_type to be performed on filter match
 * @mac_vlan_action: pointer to add or remove MAC VLAN function
 */
static enum nse_status
nse_fltr_prepare_mac_vlan(struct nse_vsi *vsi, const u8 *mac, u16 vlan_id,
			  enum nse_sw_fwd_act_type act_type,
			  enum nse_status (mac_vlan_action)
			  (struct nse_vsi *, struct list_head *))
{
	LIST_HEAD(tmp_list);
	enum nse_status result;

	if (nse_fltr_add_mac_vlan_to_list(vsi, &tmp_list, mac, vlan_id,
					  act_type))
		return NSE_ERR_NO_MEMORY;

	result = mac_vlan_action(vsi, &tmp_list);
	nse_fltr_free_list(nse_pf_to_dev(vsi->back), &tmp_list);
	return result;
}

/**
 * nse_fltr_prepare_eth - add or remove ethertype filter
 * @vsi: pointer to VSI struct
 * @ethertype: ethertype of packet to be filtered
 * @flag: direction of packet, Tx or Rx
 * @act_type: act_type to be performed on filter match
 * @eth_action: pointer to add or remove ethertype function
 */
static enum nse_status
nse_fltr_prepare_eth(struct nse_vsi *vsi, u16 ethertype, u16 flag,
		     enum nse_sw_fwd_act_type act_type,
		     enum nse_status (*eth_action)
		     (struct nse_vsi *, struct list_head *))
{
	LIST_HEAD(tmp_list);
	enum nse_status result;

	if (nse_fltr_add_eth_to_list(vsi, &tmp_list, ethertype, flag, act_type))
		return NSE_ERR_NO_MEMORY;

	result = eth_action(vsi, &tmp_list);
	nse_fltr_free_list(nse_pf_to_dev(vsi->back), &tmp_list);
	return result;
}

static enum nse_status
nse_fltr_add_mac_legacy(struct nse_vsi *vsi, const u8 *mac,
				 enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;
	int err = 0;

	if (act_type != NSE_FWD_TO_VSI) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] only fwd_to_vsi action type is supported\n",
			__func__, __LINE__);
		return NSE_ERR_PARAM;
	}

	if (is_broadcast_ether_addr(mac)) {
		err = nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_set_rx_bam);
		if (err) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to set BAM, err = %d\n",
				__func__, __LINE__, err);
			status = NSE_ERR_DEVICE_NOT_SUPPORTED;
			goto err;
		}
	} else {
		if (is_zero_ether_addr(mac)) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] invalid mac zero address\n",
				__func__, __LINE__);
			return NSE_ERR_PARAM;
		}

		/*add to legacy mac table here.*/
		status = nse_legacy_sw_add_mac(hw, mac, vsi->idx);
		if (status && status != NSE_ERR_ALREADY_EXISTS) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to add mac filter, status = %d\n",
				__func__, __LINE__, status);
			goto err;
		} else if (status == NSE_ERR_ALREADY_EXISTS) {
			dev_warn(nse_hw_to_dev(hw),
				"[%s, %d] mac_addr(%pM) is already added to vsi(%d)\n",
				__func__, __LINE__, mac, vsi->vsi_abs_num);
		}
	}

	return NSE_SUCCESS;

err:
	return status;
}

static enum nse_status
nse_fltr_add_mac_flex(struct nse_vsi *vsi, const u8 *mac,
				 enum nse_sw_fwd_act_type act_type)
{
	return nse_fltr_prepare_mac(vsi, mac, act_type, nse_fltr_add_mac_list);
}

/**
 * nse_fltr_add_mac - add single MAC filter
 * @vsi: pointer to VSI struct
 * @mac: MAC to add
 * @act_type: act_type to be performed on filter match
 */
enum nse_status nse_fltr_add_mac(struct nse_vsi *vsi, const u8 *mac,
				 enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_fltr_add_mac_flex(vsi, mac, act_type);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		status = nse_fltr_add_mac_legacy(vsi, mac, act_type);

	return status;
}

/**
 * nse_fltr_add_bmc_mac - add single bmc MAC filter
 * @vsi: pointer to VSI struct
 * @mac: MAC to add
 * @act_type: act_type to be performed on filter match
 */
enum nse_status nse_fltr_add_bmc_mac(struct nse_vsi *vsi, const u8 *mac,
				 enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		return NSE_SUCCESS;

	return nse_fltr_prepare_bmc_mac(vsi, mac, act_type, nse_fltr_add_bmc_mac_list);
}

/**
 * nse_fltr_add_roce_mac - add single roce MAC filter
 * @vsi: pointer to VSI struct
 * @mac: MAC to add
 * @dst_vsi: pointer to destination VSI struct
 * @act_type: act_type to be performed on filter match
 */
enum nse_status nse_fltr_add_roce_mac(struct nse_vsi *vsi, const u8 *mac,
				 struct nse_vsi *dst_vsi, enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		return NSE_SUCCESS;

	return nse_fltr_prepare_roce_mac(vsi, mac, dst_vsi, act_type, nse_fltr_add_roce_mac_list);
}

/**
 * nse_fltr_add_mac_and_broadcast - add single MAC and broadcast
 * @vsi: pointer to VSI struct
 * @mac: MAC to add
 * @act_type: act_type to be performed on filter match
 */
enum nse_status
nse_fltr_add_mac_and_broadcast(struct nse_vsi *vsi, const u8 *mac,
			       enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_fltr_prepare_mac_and_broadcast(vsi, mac, act_type,
						  nse_fltr_add_mac_list);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY)) {
		u8 broadcast[ETH_ALEN];

		eth_broadcast_addr(broadcast);
		status = nse_fltr_add_mac_legacy(vsi, broadcast, act_type);
		if (status && status != NSE_ERR_ALREADY_EXISTS) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to add broadcast mac address, err = %d\n",
				__func__, __LINE__, status);
			goto err;
		}

		status = nse_fltr_add_mac_legacy(vsi, mac, act_type);
		if (status && status != NSE_ERR_ALREADY_EXISTS) {
			/*remove the successful broadcast mac above  */
			nse_fltr_remove_mac_legacy(vsi, broadcast, act_type);
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to add unicast mac address, err = %d\n",
				__func__, __LINE__, status);
			goto err;
		}
	}

err:
	return status;
}

/**
 * nse_fltr_add_vlan - add single VLAN filter
 * @vsi: pointer to VSI struct
 * @vlan: VLAN filter details
 */
static enum nse_status
nse_fltr_add_vlan_flex(struct nse_vsi *vsi, struct nse_vlan *vlan)
{
	return nse_fltr_prepare_vlan(vsi, vlan, nse_fltr_add_vlan_list);
}

static enum nse_status
nse_fltr_add_vlan_legacy(struct nse_vsi *vsi, struct nse_vlan *vlan)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;

	/*add to legacy vlan table here.*/
	status = nse_legacy_sw_add_vlan(hw, vlan->vid, vsi->idx);
	if (status && status != NSE_ERR_ALREADY_EXISTS) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to add vlan filter, status = %d\n",
			__func__, __LINE__, status);
		goto err;
	} else if (status == NSE_ERR_ALREADY_EXISTS) {
		dev_warn(nse_hw_to_dev(hw),
			"[%s, %d] vlan id(%d) is already added to vsi(%d)\n",
			__func__, __LINE__, vlan->vid, vsi->vsi_abs_num);
	}

	return NSE_SUCCESS;
err:
	return status;
}

enum nse_status nse_fltr_add_vlan(struct nse_vsi *vsi, struct nse_vlan *vlan)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_fltr_add_vlan_flex(vsi, vlan);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		status = nse_fltr_add_vlan_legacy(vsi, vlan);

	return status;
}

/**
 * nse_fltr_add_mac_vlan - add single MAC VLAN filter
 * @vsi: pointer to VSI struct
 * @mac: MAC address to add
 * @vlan_id: VLAN ID to add
 * @act_type: act_type to be performed on filter match
 */
enum nse_status
nse_fltr_add_mac_vlan(struct nse_vsi *vsi, const u8 *mac, u16 vlan_id,
		      enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		return NSE_SUCCESS;

	return nse_fltr_prepare_mac_vlan(vsi, mac, vlan_id, act_type,
					 nse_fltr_add_mac_vlan_list);
}

/**
 * nse_fltr_add_eth - add specyfic ethertype filter
 * @vsi: pointer to VSI struct
 * @ethertype: ethertype of filter
 * @flag: direction of packet to be filtered, Tx or Rx
 * @act_type: act_type to be performed on filter match
 */
static enum nse_status
nse_fltr_add_eth_flex(struct nse_vsi *vsi, u16 ethertype, u16 flag,
		 enum nse_sw_fwd_act_type act_type)
{
	return nse_fltr_prepare_eth(vsi, ethertype, flag, act_type,
				    nse_fltr_add_eth_list);
}

static enum nse_status
nse_fltr_add_eth_legacy(struct nse_vsi *vsi, u16 ethertype, u16 flag,
		 enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;

	/*there is no tsw in moonstone, we return success always here*/
	if (flag == NSE_FLTR_TX)
		return NSE_SUCCESS;

	if (act_type != NSE_FWD_TO_VSI) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] only fwd_to_vsi action type is supported\n",
			__func__, __LINE__);
		return NSE_ERR_PARAM;
	}

	/*add to legacy ethtype table here.*/
	status = nse_legacy_sw_add_ethtype(hw, ethertype, vsi->idx);
	if (status && status != NSE_ERR_ALREADY_EXISTS) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to add ethtype filter, status = %d\n",
			__func__, __LINE__, status);
		goto err;
	} else if (status == NSE_ERR_ALREADY_EXISTS) {
		dev_warn(nse_hw_to_dev(hw),
			"[%s, %d] ethtype(0x%x) is already added to vsi(%d)\n",
			__func__, __LINE__, ethertype, vsi->vsi_abs_num);
	}

	return NSE_SUCCESS;
err:
	return status;
}

enum nse_status
nse_fltr_add_eth(struct nse_vsi *vsi, u16 ethertype, u16 flag,
		 enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_fltr_add_eth_flex(vsi, ethertype, flag, act_type);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		status = nse_fltr_add_eth_legacy(vsi, ethertype, flag, act_type);

	return status;
}

static enum nse_status
nse_fltr_remove_mac_legacy(struct nse_vsi *vsi, const u8 *mac,
				    enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;
	int err = 0;

	if (is_zero_ether_addr(mac)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] invalid mac zero address\n",
			__func__, __LINE__);
		return NSE_ERR_PARAM;
	}

	if (act_type != NSE_FWD_TO_VSI) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] only fwd_to_vsi action type is supported\n",
			__func__, __LINE__);
		return NSE_ERR_PARAM;
	}

	if (is_broadcast_ether_addr(mac)) {
		err = nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_clear_rx_bam);
		if (err) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to clear BAM, err = %d\n",
				__func__, __LINE__, err);
			status = NSE_ERR_DEVICE_NOT_SUPPORTED;
			goto err;
		}
	} else {
		status = nse_legacy_sw_remove_mac(hw, mac, vsi->idx);
		if (status && status != NSE_ERR_DOES_NOT_EXIST) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to remove mac filter, err = %d\n",
				__func__, __LINE__, status);
			goto err;
		} else if (status == NSE_ERR_DOES_NOT_EXIST) {
			dev_warn(nse_hw_to_dev(hw),
				"[%s, %d] mac_addr(%pM) is not existed in vsi(%d)\n",
				__func__, __LINE__, mac, vsi->vsi_abs_num);
		}
	}

	return NSE_SUCCESS;

err:
	return status;
}

static enum nse_status
nse_fltr_remove_mac_flex(struct nse_vsi *vsi, const u8 *mac,
				    enum nse_sw_fwd_act_type act_type)
{
	return nse_fltr_prepare_mac(vsi, mac, act_type, nse_fltr_remove_mac_list);
}

/**
 * nse_fltr_remove_mac - remove MAC filter
 * @vsi: pointer to VSI struct
 * @mac: filter MAC to remove
 * @act_type: act_type to remove
 */
enum nse_status nse_fltr_remove_mac(struct nse_vsi *vsi, const u8 *mac,
				    enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_fltr_remove_mac_flex(vsi, mac, act_type);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		status = nse_fltr_remove_mac_legacy(vsi, mac, act_type);

	return status;
}

/**
 * nse_fltr_remove_bmc_mac - remove BMC MAC filter
 * @vsi: pointer to VSI struct
 * @mac: filter MAC to remove
 * @act_type: act_type to remove
 */
enum nse_status nse_fltr_remove_bmc_mac(struct nse_vsi *vsi, const u8 *mac,
				    enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		return NSE_SUCCESS;

	return nse_fltr_prepare_bmc_mac(vsi, mac, act_type, nse_fltr_remove_bmc_mac_list);
}

/**
 * nse_fltr_remove_roce_mac - remove single roce MAC filter
 * @vsi: pointer to VSI struct
 * @mac: filter MAC to remove
 * @act_type: act_type to remove
 */
enum nse_status nse_fltr_remove_roce_mac(struct nse_vsi *vsi, const u8 *mac,
				 struct nse_vsi *dst_vsi, enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		return NSE_SUCCESS;

	return nse_fltr_prepare_roce_mac(vsi, mac, dst_vsi, act_type,
					 nse_fltr_remove_roce_mac_list);
}

/**
 * nse_fltr_remove_vlan - remove VLAN filter
 * @vsi: pointer to VSI struct
 * @vlan: VLAN filter details
 */
static enum nse_status
nse_fltr_remove_vlan_flex(struct nse_vsi *vsi, struct nse_vlan *vlan)
{
	return nse_fltr_prepare_vlan(vsi, vlan, nse_fltr_remove_vlan_list);
}

static enum nse_status
nse_fltr_remove_vlan_legacy(struct nse_vsi *vsi, struct nse_vlan *vlan)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;

	status = nse_legacy_sw_remove_vlan(hw, vlan->vid, vsi->idx);
	if (status && status != NSE_ERR_DOES_NOT_EXIST) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to remove vlan filter, err = %d\n",
			__func__, __LINE__, status);
		goto err;
	} else if (status == NSE_ERR_DOES_NOT_EXIST) {
		dev_warn(nse_hw_to_dev(hw),
			"[%s, %d] vlan id(%d) is not existed in vsi(%d)\n",
			__func__, __LINE__, vlan->vid, vsi->vsi_abs_num);
	}

	return NSE_SUCCESS;
err:
	return status;
}

enum nse_status nse_fltr_remove_vlan(struct nse_vsi *vsi, struct nse_vlan *vlan)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_fltr_remove_vlan_flex(vsi, vlan);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		status = nse_fltr_remove_vlan_legacy(vsi, vlan);

	return status;
}

/**
 * nse_fltr_remove_mac_vlan - remove MAC VLAN filter
 * @vsi: pointer to VSI struct
 * @mac: MAC address to add
 * @vlan_id: filter MAC VLAN to remove
 * @act_type: act_type to remove
 */
enum nse_status
nse_fltr_remove_mac_vlan(struct nse_vsi *vsi, const u8 *mac, u16 vlan_id,
			 enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		return NSE_SUCCESS;

	return nse_fltr_prepare_mac_vlan(vsi, mac, vlan_id, act_type,
					 nse_fltr_remove_mac_vlan_list);
}

/**
 * nse_fltr_remove_eth - remove ethertype filter
 * @vsi: pointer to VSI struct
 * @ethertype: ethertype of filter
 * @flag: direction of filter
 * @act_type: act_type to remove
 */
static enum nse_status
nse_fltr_remove_eth_flex(struct nse_vsi *vsi, u16 ethertype, u16 flag,
		    enum nse_sw_fwd_act_type act_type)
{
	return nse_fltr_prepare_eth(vsi, ethertype, flag, act_type,
				    nse_fltr_remove_eth_list);
}

static enum nse_status
nse_fltr_remove_eth_legacy(struct nse_vsi *vsi, u16 ethertype, u16 flag,
		    enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;

	/*there is no tsw in moonstone, we return success always here*/
	if (flag == NSE_FLTR_TX)
		return NSE_SUCCESS;

	if (act_type != NSE_FWD_TO_VSI) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] only fwd_to_vsi action type is supported\n",
			__func__, __LINE__);
		return NSE_ERR_PARAM;
	}

	status = nse_legacy_sw_remove_ethtype(hw, ethertype, vsi->idx);
	if (status && status != NSE_ERR_DOES_NOT_EXIST) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to remove ethtype filter, err = %d\n",
			__func__, __LINE__, status);
		goto err;
	} else if (status == NSE_ERR_DOES_NOT_EXIST) {
		dev_warn(nse_hw_to_dev(hw),
			"[%s, %d] ethtype(0x%x) is not existed in vsi(%d)\n",
			__func__, __LINE__, ethertype, vsi->vsi_abs_num);
	}

	return NSE_SUCCESS;
err:
	return status;
}

enum nse_status
nse_fltr_remove_eth(struct nse_vsi *vsi, u16 ethertype, u16 flag,
		    enum nse_sw_fwd_act_type act_type)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status = NSE_SUCCESS;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_fltr_remove_eth_flex(vsi, ethertype, flag, act_type);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		status = nse_fltr_remove_eth_legacy(vsi, ethertype, flag, act_type);

	return status;
}

/**
 * nse_fltr_remove_all - remove all filters associated with VSI
 * @vsi: pointer to VSI struct
 */
static void
nse_fltr_remove_all_flex(struct nse_vsi *vsi)
{
	nse_remove_vsi_fltr(&vsi->back->hw, vsi->idx);
}

static void
nse_fltr_remove_all_legacy(struct nse_vsi *vsi)
{
	nse_legacy_sw_remove_vsi_fltr(&vsi->back->hw, vsi->idx);
}

void nse_fltr_remove_all(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;

	if (nse_bypass_switch)
		return;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		nse_fltr_remove_all_flex(vsi);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		nse_fltr_remove_all_legacy(vsi);
}

/**
 * nse_fltr_set_vsi_promisc - set given VSI to given promiscuous mode(s)
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to configure
 * @promisc_mask: mask of promiscuous config bits
 * @vid: VLAN ID to set VLAN promiscuous
 *
 * when vid is valid,
 *	this function is to set current one vlan entry to vlan promisc table.
 */
static enum nse_status
nse_fltr_set_vsi_promisc_flex(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
			 u16 vid)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	enum nse_status result;

	result = nse_set_vsi_promisc(hw, vsi_handle, promisc_mask, vid);
	if (result && result != NSE_ERR_ALREADY_EXISTS)
		dev_err(nse_pf_to_dev(pf),
			"Error setting promisc mode on VSI %i for VID %u (rc=%d)\n",
			nse_get_hw_vsi_num(hw, vsi_handle), vid, result);
	return result;
}

static enum nse_status
nse_fltr_set_vsi_promisc_legacy(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi = NULL;
	enum nse_status status = NSE_SUCCESS;
	int err = 0;

	nse_debug(hw, NSE_DBG_SW, "[%s] vsi_handle=%d, promisc_mask=%X\n",
					__func__, vsi_handle, promisc_mask);

	if (!nse_is_vsi_valid(hw, vsi_handle))
		return NSE_ERR_PARAM;

	vsi = pf->vsi[vsi_handle];
	if (!vsi)
		return NSE_ERR_BAD_PTR;

	/*Only rx ucast / rx mcast modes are supported, ignore unsupported flags*/
	if (promisc_mask & NSE_PROMISC_UCAST_RX) {
		err = nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_set_rx_upe);
		if (err) {
			dev_err(nse_hw_to_dev(hw),
				"Error setting ucast promisc mode on VSI %i (err=%d)\n",
				nse_get_hw_vsi_num(hw, vsi_handle), err);
			status = NSE_ERR_DEVICE_NOT_SUPPORTED;
			goto err;
		}
	}

	if (promisc_mask & NSE_PROMISC_MCAST_RX) {
		err = nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_set_rx_mpe);
		if (err) {
			dev_err(nse_hw_to_dev(hw),
				"Error setting mcast promisc mode on VSI %i (err=%d)\n",
				nse_get_hw_vsi_num(hw, vsi_handle), err);
			if (promisc_mask & NSE_PROMISC_UCAST_RX)
				nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_clear_rx_upe);

			status = NSE_ERR_DEVICE_NOT_SUPPORTED;
			goto err;
		}
	}
	return NSE_SUCCESS;

err:
	return status;
}

enum nse_status
nse_fltr_set_vsi_promisc(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
			 u16 vid)
{
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_SW, "[%s] vsi_handle=%d, promisc_mask=%X, vid=%d\n",
					__func__, vsi_handle, promisc_mask, vid);

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_fltr_set_vsi_promisc_flex(hw, vsi_handle, promisc_mask, vid);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		status = nse_fltr_set_vsi_promisc_legacy(hw, vsi_handle, promisc_mask);

	return status;
}

/**
 * nse_fltr_set_vlan_vsi_promisc
 * @hw: pointer to the hardware structure
 * @vsi: the VSI being configured
 * @promisc_mask: mask of promiscuous config bits
 *
 * Set VSI with all existed VLANs to given promiscuous mode(s)
 *
 * VlAN fltr is set before vlan promisc, so need sync existed VLANs
 *	to vlan promisc when this vsi is configured to vlan promisc.
 */
static enum nse_status
nse_fltr_set_vlan_vsi_promisc_flex(struct nse_hw *hw, struct nse_vsi *vsi, u8 promisc_mask)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	enum nse_status result;

	result = nse_set_vlan_vsi_promisc(hw, vsi->idx, promisc_mask, false);
	if (result && result != NSE_ERR_ALREADY_EXISTS)
		dev_err(nse_pf_to_dev(pf),
			"Error setting promisc mode on VSI %i (rc=%d\n",
			vsi->vsi_abs_num, result);
	return result;
}

enum nse_status
nse_fltr_set_vlan_vsi_promisc(struct nse_hw *hw, struct nse_vsi *vsi, u8 promisc_mask)
{
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_SW, "[%s] vsi->idx=%d, promisc_mask=%X\n",
					__func__, vsi->idx, promisc_mask);

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_fltr_set_vlan_vsi_promisc_flex(hw, vsi, promisc_mask);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		/* there is no difference between with and without vlan in hardware legacy switch,
		 * VPE flag is not used
		 */
		status = nse_fltr_set_vsi_promisc_legacy(hw, vsi->idx, promisc_mask);

	return status;
}

/**
 * nse_fltr_clear_vsi_promisc - clear specified promiscuous mode(s)
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to clear mode
 * @promisc_mask: mask of promiscuous config bits to clear
 * @vid: VLAN ID to clear VLAN promiscuous
 * @lport: logical port number to clear mode
 */
static enum nse_status
nse_fltr_clear_vsi_promisc_flex(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
			   u16 vid)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	enum nse_status result;

	result = nse_clear_vsi_promisc(hw, vsi_handle, promisc_mask, vid);
	if (result && result != NSE_ERR_ALREADY_EXISTS)
		dev_err(nse_pf_to_dev(pf),
			"Error clearing promisc mode on VSI %i for VID %u (rc=%d)\n",
			nse_get_hw_vsi_num(hw, vsi_handle), vid, result);
	return result;
}

static enum nse_status
nse_fltr_clear_vsi_promisc_legacy(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi = NULL;
	enum nse_status status = NSE_SUCCESS;
	int err = 0;

	nse_debug(hw, NSE_DBG_SW, "[%s] vsi_handle=%d, promisc_mask=%X\n",
					__func__, vsi_handle, promisc_mask);

	if (!nse_is_vsi_valid(hw, vsi_handle))
		return NSE_ERR_PARAM;

	vsi = pf->vsi[vsi_handle];
	if (!vsi)
		return NSE_ERR_BAD_PTR;

	/*Only rx ucast / rx mcast modes are supported, ignore unsupported flags*/
	if (promisc_mask & NSE_PROMISC_UCAST_RX) {
		err = nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_clear_rx_upe);
		if (err) {
			dev_err(nse_hw_to_dev(hw),
				"Error setting ucast promisc mode on VSI %i (err=%d)\n",
				nse_get_hw_vsi_num(hw, vsi_handle), err);
			status = NSE_ERR_DEVICE_NOT_SUPPORTED;
			goto err;
		}
	}

	if (promisc_mask & NSE_PROMISC_MCAST_RX) {
		err = nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_clear_rx_mpe);
		if (err) {
			dev_err(nse_hw_to_dev(hw),
				"Error setting mcast promisc mode on VSI %i (err=%d)\n",
				nse_get_hw_vsi_num(hw, vsi_handle), err);
			if (promisc_mask & NSE_PROMISC_UCAST_RX)
				nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_set_rx_upe);

			status = NSE_ERR_DEVICE_NOT_SUPPORTED;
			goto err;
		}
	}
	return NSE_SUCCESS;

err:
	return status;
}

enum nse_status
nse_fltr_clear_vsi_promisc(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
			   u16 vid)
{
	enum nse_status status = NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_fltr_clear_vsi_promisc_flex(hw, vsi_handle, promisc_mask, vid);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		status = nse_fltr_clear_vsi_promisc_legacy(hw, vsi_handle, promisc_mask);

	return status;
}

/**
 * nse_fltr_clear_vlan_vsi_promisc
 * @hw: pointer to the hardware structure
 * @vsi: the VSI being configured
 * @promisc_mask: mask of promiscuous config bits
 *
 * Clear VSI with all associated VLANs to given promiscuous mode(s)
 */
static enum nse_status
nse_fltr_clear_vlan_vsi_promisc_flex(struct nse_hw *hw, struct nse_vsi *vsi, u8 promisc_mask)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	enum nse_status result;

	result = nse_set_vlan_vsi_promisc(hw, vsi->idx, promisc_mask, true);
	if (result && result != NSE_ERR_ALREADY_EXISTS)
		dev_err(nse_pf_to_dev(pf),
			"Error setting promisc mode on VSI %i (rc=%d\n",
			vsi->vsi_abs_num, result);
	return result;
}

enum nse_status
nse_fltr_clear_vlan_vsi_promisc(struct nse_hw *hw, struct nse_vsi *vsi, u8 promisc_mask)
{
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_SW, "[%s] vsi->idx=%d, promisc_mask=%X\n",
					__func__, vsi->idx, promisc_mask);

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_fltr_clear_vlan_vsi_promisc_flex(hw, vsi, promisc_mask);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		/* there is no difference between with and without vlan in hardware legacy switch,
		 * VPE flag is not used
		 */
		status = nse_fltr_clear_vsi_promisc_legacy(hw, vsi->idx, promisc_mask);

	return status;
}

/**
 * nse_fltr_set_bmc_mac_event -
 *	 set bmc mac address to bmc, event from fw.
 * @hw: pointer to the hardware structure.
 * @event: event info from fw.
 */
void
nse_fltr_set_bmc_mac_event(struct nse_hw *hw,
			struct nse_rq_event_info *event)
{
	struct nse_aqc_bmc_mac_event *buf;
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vsi *vsi = nse_get_main_vsi(pf);
	enum nse_status status = NSE_SUCCESS;
	int i;
	u16 mac_cnt = 0;

	if (!event->msg_buf || !vsi)
		return;

	if (nse_bypass_switch)
		return;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		return;

	buf = (struct nse_aqc_bmc_mac_event *)event->msg_buf;
	mac_cnt = le16_to_cpu(buf->count);

	if (!mac_cnt || mac_cnt > NSE_AQC_BMC_MAC_MAX_CNT) {
		dev_err(nse_hw_to_dev(hw),
			"Receive err bmc mac event, mac count is %d\n",	mac_cnt);
		return;
	}

	dev_info(nse_hw_to_dev(hw),
		"Receive a bmc mac event, total mac num is %d\n", mac_cnt);

	for (i = 0; i < mac_cnt; i++) {
		struct nse_aqc_bmc_mac_elem *elem = &buf->elem[i];
		u16 opcode = 0;

		opcode = le16_to_cpu(elem->op);

		dev_info(nse_hw_to_dev(hw),
			"\t Mac entry[%d]'s opcode is %d, address is %pM\n",
				i, opcode, elem->mac);

		if (opcode) {
			status = nse_fltr_add_bmc_mac(vsi, elem->mac, NSE_FWD_BMC);
			if (status)
				dev_err(nse_hw_to_dev(hw),
					"Failed to add bmc mac(%pM), err = %d\n",
						elem->mac, status);
		} else {
			status = nse_fltr_remove_bmc_mac(vsi, elem->mac, NSE_FWD_BMC);
			if (status)
				dev_err(nse_hw_to_dev(hw),
					"Failed to remove bmc mac(%pM), err = %d\n",
						elem->mac, status);
		}
	}
}

