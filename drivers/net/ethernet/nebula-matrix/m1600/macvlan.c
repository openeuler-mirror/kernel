// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#include "hw.h"
#include "common.h"
#include "mailbox.h"
#include "macvlan.h"

static void nbl_macvlan_set_key(struct nbl_macvlan_key *key, u8 eth_port_id,
				u8 *mac_addr, u16 vlan_id,
				enum nbl_macvlan_direction direction)
{
	memset(key, 0, sizeof(*key));
	key->vlan_id = vlan_id;
	key->mac5 = mac_addr[5];
	key->mac4 = mac_addr[4];
	key->mac3_l = mac_addr[3];
	key->mac3_h = mac_addr[3] >> 4;
	key->mac2 = mac_addr[2];
	key->mac1 = mac_addr[1];
	key->mac0 = mac_addr[0];
	key->eth_port_id = eth_port_id;
	key->direction = direction;
}

static void nbl_macvlan_set_result(struct nbl_macvlan_result *result,
				   enum nbl_macvlan_dport_type dport_type,
				   u8 dport_id)
{
	memset(result, 0, sizeof(*result));
	result->dport = dport_type;
	result->dport_id = dport_id;
}

static void nbl_macvlan_set_table_index(struct nbl_macvlan_table_index *table_index,
					u16 index)
{
	memset(table_index, 0, sizeof(*table_index));
	table_index->index = index;
}

static void nbl_macvlan_set_control(struct nbl_macvlan_control *control,
				    enum nbl_macvlan_operation_type type)
{
	memset(control, 0, sizeof(*control));
	control->op_type = type;
	control->start = 1;
}

static int nbl_macvlan_table_add(struct nbl_hw *hw, struct nbl_macvlan_key *key,
				 struct nbl_macvlan_result *result,
				 struct nbl_macvlan_table_index *table_index,
				 struct nbl_macvlan_control *control)
{
	struct nbl_macvlan_status status;
	int i = NBL_MACVLAN_TRY_GET_STATUS_TIMES;
	enum nbl_macvlan_direction direction;
	enum nbl_macvlan_operation_type type;

	direction = key->direction;
	type = control->op_type;

	wr32_for_each(hw, NBL_MEMT_KEY_REG, (u32 *)key, sizeof(*key));
	wr32_for_each(hw, NBL_MEMT_TABLE_INDEX_REG, (u32 *)table_index, sizeof(*table_index));
	wr32_for_each(hw, NBL_MEMT_RESULT_REG, (u32 *)result, sizeof(*result));
	wr32_for_each(hw, NBL_MEMT_OPERATION_REG, (u32 *)control, sizeof(*control));

	while (i--) {
		rd32_for_each(hw, NBL_MEMT_STATUS_REG, (u32 *)&status, sizeof(status));
		if (direction == NBL_MACVLAN_UP_DIRECTION) {
			if (status.up_mac_op_done) {
				if (status.up_mac_op_type != type) {
					pr_err("Add to up macvlan table, but invalid op type is returned\n");
					return -EINVAL;
				}
				if (status.up_mac_op_success)
					return 0;
				pr_info("Add to up macvlan table, but failed\n");
				return -EEXIST;
			}
		} else {
			if (status.dn_mac_op_done) {
				if (status.dn_mac_op_type != type) {
					pr_err("Add to down macvlan table, but invalid op type is returned\n");
					return -EINVAL;
				}
				if (status.dn_mac_op_success)
					return 0;
				pr_info("Add to down macvlan table, but failed\n");
				return -EEXIST;
			}
		}

		udelay(2);
	}

	return -EAGAIN;
}

static int nbl_macvlan_table_delete(struct nbl_hw *hw, struct nbl_macvlan_key *key,
				    struct nbl_macvlan_control *control)
{
	struct nbl_macvlan_status status;
	int i = NBL_MACVLAN_TRY_GET_STATUS_TIMES;
	enum nbl_macvlan_direction direction;
	enum nbl_macvlan_operation_type type;

	direction = key->direction;
	type = control->op_type;

	wr32_for_each(hw, NBL_MEMT_KEY_REG, (u32 *)key, sizeof(*key));
	wr32_for_each(hw, NBL_MEMT_OPERATION_REG, (u32 *)control, sizeof(*control));

	while (i--) {
		rd32_for_each(hw, NBL_MEMT_STATUS_REG, (u32 *)&status, sizeof(status));
		if (direction == NBL_MACVLAN_UP_DIRECTION) {
			if (status.up_mac_op_done) {
				if (status.up_mac_op_type != type) {
					pr_err("Delete up macvlan table entry, but invalid op type is returned\n");
					return -EINVAL;
				}
				if (status.up_mac_op_success)
					return 0;
				pr_info("Delete up macvlan table entry, but failed\n");
				return -ENOENT;
			}
		} else {
			if (status.dn_mac_op_done) {
				if (status.dn_mac_op_type != type) {
					pr_err("Delete down macvlan table entry, but invalid op type is returned\n");
					return -EINVAL;
				}
				if (status.dn_mac_op_success)
					return 0;
				pr_info("Delete down macvlan table entry, but failed\n");
				return -ENOENT;
			}
		}

		udelay(2);
	}

	return -EAGAIN;
}

static int nbl_macvlan_up_add(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr, u16 vlan_id,
			      u8 vsi_id, int index)
{
	struct nbl_macvlan_key key;
	struct nbl_macvlan_result result;
	struct nbl_macvlan_table_index table_index;
	struct nbl_macvlan_control control;

	nbl_macvlan_set_key(&key, eth_port_id, mac_addr, vlan_id, NBL_MACVLAN_UP_DIRECTION);
	nbl_macvlan_set_result(&result, NBL_MACVLAN_DPORT_HOST, vsi_id);
	nbl_macvlan_set_table_index(&table_index, index);
	nbl_macvlan_set_control(&control, NBL_MACVLAN_OP_ADD);

	return nbl_macvlan_table_add(hw, &key, &result, &table_index, &control);
}

static int nbl_macvlan_up_delete(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr, u16 vlan_id)
{
	struct nbl_macvlan_key key;
	struct nbl_macvlan_control control;

	nbl_macvlan_set_key(&key, eth_port_id, mac_addr, vlan_id, NBL_MACVLAN_UP_DIRECTION);
	nbl_macvlan_set_control(&control, NBL_MACVLAN_OP_DELETE);

	return nbl_macvlan_table_delete(hw, &key, &control);
}

static int nbl_macvlan_down_add(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr, u16 vlan_id,
				u8 vsi_id, int index)
{
	struct nbl_macvlan_key key;
	struct nbl_macvlan_result result;
	struct nbl_macvlan_table_index table_index;
	struct nbl_macvlan_control control;

	nbl_macvlan_set_key(&key, eth_port_id, mac_addr, vlan_id, NBL_MACVLAN_DOWN_DIRECTION);
	nbl_macvlan_set_result(&result, NBL_MACVLAN_DPORT_HOST, vsi_id);
	nbl_macvlan_set_table_index(&table_index, index);
	nbl_macvlan_set_control(&control, NBL_MACVLAN_OP_ADD);

	return nbl_macvlan_table_add(hw, &key, &result, &table_index, &control);
}

static int nbl_macvlan_down_delete(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr, u16 vlan_id)
{
	struct nbl_macvlan_key key;
	struct nbl_macvlan_control control;

	nbl_macvlan_set_key(&key, eth_port_id, mac_addr, vlan_id, NBL_MACVLAN_DOWN_DIRECTION);
	nbl_macvlan_set_control(&control, NBL_MACVLAN_OP_DELETE);

	return nbl_macvlan_table_delete(hw, &key, &control);
}

int nbl_macvlan_add(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr, u16 vlan_id,
		    u8 vsi_id, int index)
{
	int err;
	int ret;

	err = nbl_macvlan_up_add(hw, eth_port_id, mac_addr, vlan_id, vsi_id, index);
	if (err)
		return err;

	err = nbl_macvlan_down_add(hw, eth_port_id, mac_addr, vlan_id, vsi_id, index);
	if (err) {
		ret = nbl_macvlan_up_delete(hw, eth_port_id, mac_addr, vlan_id);
		if (ret)
			pr_err("Failed to roll back macvlan table add operation with error %d\n",
			       ret);
		return err;
	}

	return 0;
}

int nbl_macvlan_delete(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr, u16 vlan_id)
{
	int err;

	err = nbl_macvlan_up_delete(hw, eth_port_id, mac_addr, vlan_id);
	if (err)
		return err;

	err = nbl_macvlan_down_delete(hw, eth_port_id, mac_addr, vlan_id);
	if (err) {
		pr_err("Failed to delete entry in macvlan down table though delete entry in macvlan up table success\n");
		return err;
	}

	return 0;
}

int nbl_af_configure_mac_addr(struct nbl_hw *hw, u16 func_id, u8 eth_port_id,
			      u8 *mac_addr, u8 vsi_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	int macvlan_entry_index;
	int i;
	int err;

	if (!func_res->num_macvlan_entries) {
		if (func_id >= NBL_MAX_PF_FUNC) {
			func_res->num_macvlan_entries = NBL_VF_MAX_MACVLAN_ENTRIES;
			func_res->macvlan_start_index = NBL_VF_MACVLAN_START_INDEX +
				(func_id - NBL_VF_BASE_FUNC_ID) * NBL_VF_MAX_MACVLAN_ENTRIES;
		} else {
			func_res->num_macvlan_entries = NBL_PF_MAX_MACVLAN_ENTRIES;
			func_res->macvlan_start_index = func_id * NBL_PF_MAX_MACVLAN_ENTRIES;
		}

		for (i = 0; i < NBL_PF_MAX_MACVLAN_ENTRIES; i++)
			func_res->vlan_ids[i] = -1;
	}

	for (i = 0; i < func_res->num_macvlan_entries; i++)
		if (func_res->vlan_ids[i] == -1)
			break;
	if (i == func_res->num_macvlan_entries) {
		pr_err("There is no available macvlan entry left for mailbox function id %u device\n",
		       func_id);
		return -EAGAIN;
	}
	macvlan_entry_index = func_res->macvlan_start_index + i;

	err = nbl_macvlan_add(hw, eth_port_id, mac_addr, NBL_DEFAULT_VLAN_ID, vsi_id,
			      macvlan_entry_index);
	if (err) {
		pr_err("Mailbox function id %u device failed to add macvlan entry at index %d with error %d\n",
		       func_id, macvlan_entry_index, err);
		return err;
	}

	memcpy(func_res->mac_addr, mac_addr, ETH_ALEN);
	func_res->eth_port_id = eth_port_id;
	func_res->vlan_ids[i] = 0;
	return 0;
}

int nbl_af_clear_mac_addr(struct nbl_hw *hw, u16 func_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	u8 eth_port_id;
	u8 *mac_addr;
	int offset;
	int i;
	int err;

	for (i = 0; i < func_res->num_macvlan_entries; i++)
		if (func_res->vlan_ids[i] == 0)
			break;
	if (i == func_res->num_macvlan_entries) {
		pr_err("MAC address may be cleared already\n");
		return -EINVAL;
	}
	offset = i;

	for (i = 0; i < func_res->num_macvlan_entries; i++)
		if (func_res->vlan_ids[i] != -1 && i != offset)
			pr_err("Macvlan entry with vlan id %hd has not been cleared\n",
			       func_res->vlan_ids[i]);

	eth_port_id = func_res->eth_port_id;
	mac_addr = func_res->mac_addr;
	err = nbl_macvlan_delete(hw, eth_port_id, mac_addr, NBL_DEFAULT_VLAN_ID);
	if (err) {
		pr_err("Clear mac address from hardware failed with error %d\n", err);
		return err;
	}

	func_res->vlan_ids[offset] = -1;
	return 0;
}

int nbl_af_change_mac_addr(struct nbl_hw *hw, u16 func_id, u8 *mac_addr, u8 vsi_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	int macvlan_entry_start;
	int macvlan_entry_index;
	u8 *old_mac_addr;
	u8 eth_port_id;
	s16 vlan_id;
	int i;
	int err;
	int ret;

	old_mac_addr = func_res->mac_addr;
	if (ether_addr_equal(old_mac_addr, mac_addr)) {
		pr_info("There is no need for AF to change mac address\n");
		return 0;
	}

	macvlan_entry_start = func_res->macvlan_start_index;
	eth_port_id = func_res->eth_port_id;
	for (i = 0; i < func_res->num_macvlan_entries; i++) {
		vlan_id = func_res->vlan_ids[i];
		if (vlan_id == -1)
			continue;

		macvlan_entry_index = macvlan_entry_start + i;

		err = nbl_macvlan_delete(hw, eth_port_id, old_mac_addr, vlan_id);
		if (err) {
			pr_err("Failed to delete macvlan entry with error %d when change mac address\n",
			       err);
			pr_alert("Please reset hardware\n");
			goto err_out;
		}

		err = nbl_macvlan_add(hw, eth_port_id, mac_addr, vlan_id,
				      vsi_id, macvlan_entry_index);
		if (err) {
			pr_err("Failed to add macvlan entry with error %d when change mac address\n",
			       err);
			goto add_macvlan_err;
		}
	}

	memcpy(func_res->mac_addr, mac_addr, ETH_ALEN);

	return 0;

add_macvlan_err:
	ret = nbl_macvlan_add(hw, eth_port_id, old_mac_addr, vlan_id, vsi_id, macvlan_entry_index);
	if (ret) {
		pr_err("Failed to add macvlan entry with error %d when change mac address roll back\n",
		       ret);
		pr_alert("Please reset hardware\n");
		goto err_out;
	}

	while (--i >= 0) {
		vlan_id = func_res->vlan_ids[i];
		if (vlan_id == -1)
			continue;

		macvlan_entry_index = macvlan_entry_start + i;

		ret = nbl_macvlan_delete(hw, eth_port_id, mac_addr, vlan_id);
		if (ret) {
			pr_err("Failed to delete macvlan entry with error %d when change mac address roll back\n",
			       ret);
			pr_alert("Please reset hardware\n");
			goto err_out;
		}

		ret = nbl_macvlan_add(hw, eth_port_id, old_mac_addr, vlan_id,
				      vsi_id, macvlan_entry_index);
		if (ret) {
			pr_err("Failed to add macvlan entry with error %d when change mac address roll back\n",
			       ret);
			pr_alert("Please reset hardware\n");
			goto err_out;
		}
	}

err_out:
	return err;
}

int nbl_configure_mac_addr(struct nbl_hw *hw, u8 *mac_addr)
{
	int err;
	u8 eth_port_id = hw->eth_port_id;
	u8 vsi_id = hw->vsi_id;

	if (is_af(hw))
		err = nbl_af_configure_mac_addr(hw, 0, eth_port_id, mac_addr, vsi_id);
	else
		err = nbl_mailbox_req_configure_mac_addr(hw, eth_port_id, mac_addr, vsi_id);

	return err;
}

int nbl_clear_mac_addr(struct nbl_hw *hw)
{
	int err;

	if (is_af(hw))
		err = nbl_af_clear_mac_addr(hw, 0);
	else
		err = nbl_mailbox_req_clear_mac_addr(hw);

	return err;
}

int nbl_change_mac_addr(struct nbl_hw *hw, u8 *mac_addr)
{
	u8 vsi_id;
	int err;

	vsi_id = hw->vsi_id;
	if (is_af(hw))
		err = nbl_af_change_mac_addr(hw, 0, mac_addr, vsi_id);
	else
		err = nbl_mailbox_req_change_mac_addr(hw, mac_addr, vsi_id);

	return err;
}

static int nbl_af_add_vlan_id(struct nbl_hw *hw, u16 func_id, u16 vlan_id, u8 vsi_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	int macvlan_entry_start;
	int macvlan_entry_index;
	u8 *mac_addr;
	u8 eth_port_id;
	int i;
	int err;

	for (i = 0; i < func_res->num_macvlan_entries; i++) {
		if ((s16)vlan_id == func_res->vlan_ids[i]) {
			pr_info("Vlan id %u is added already\n", vlan_id);
			return -EEXIST;
		}
	}

	for (i = 0; i < func_res->num_macvlan_entries; i++) {
		if (func_res->vlan_ids[i] == -1)
			break;
	}

	if (i == func_res->num_macvlan_entries) {
		pr_info("There is no macvlan entry left to add vlan id\n");
		return -ENOMEM;
	}

	macvlan_entry_start = func_res->macvlan_start_index;
	macvlan_entry_index = macvlan_entry_start + i;
	eth_port_id = func_res->eth_port_id;
	mac_addr = func_res->mac_addr;
	err = nbl_macvlan_add(hw, eth_port_id, mac_addr, vlan_id, vsi_id,
			      macvlan_entry_index);
	if (err) {
		pr_err("Failed to add vlan id %u into macvlan table\n", vlan_id);
		return err;
	}

	func_res->vlan_ids[i] = vlan_id;

	return 0;
}

static int nbl_af_delete_vlan_id(struct nbl_hw *hw, u16 func_id, u16 vlan_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	u8 *mac_addr;
	u8 eth_port_id;
	int i;
	int err;

	for (i = 0; i < func_res->num_macvlan_entries; i++) {
		if ((s16)vlan_id == func_res->vlan_ids[i])
			break;
	}
	if (i == func_res->num_macvlan_entries) {
		pr_info("There is no vlan id %u in macvlan table\n", vlan_id);
		return -ENOENT;
	}

	eth_port_id = func_res->eth_port_id;
	mac_addr = func_res->mac_addr;
	err = nbl_macvlan_delete(hw, eth_port_id, mac_addr, vlan_id);
	if (err) {
		pr_err("Failed to delete vlan id %u from macvlan table\n", vlan_id);
		pr_alert("Please reset hardware\n");
		return err;
	}

	func_res->vlan_ids[i] = -1;

	return 0;
}

int nbl_af_operate_vlan_id(struct nbl_hw *hw, u16 func_id, u16 vlan_id,
			   u8 vsi_id, bool add)
{
	if (add)
		return nbl_af_add_vlan_id(hw, func_id, vlan_id, vsi_id);

	return nbl_af_delete_vlan_id(hw, func_id, vlan_id);
}

int nbl_add_vlan_id(struct nbl_hw *hw, u16 vlan_id)
{
	u8 vsi_id;
	int err;

	vsi_id = hw->vsi_id;
	if (is_af(hw))
		err = nbl_af_operate_vlan_id(hw, 0, vlan_id, vsi_id, true);
	else
		err = nbl_mailbox_req_operate_vlan_id(hw, vlan_id, vsi_id, true);

	return err;
}

int nbl_delete_vlan_id(struct nbl_hw *hw, u16 vlan_id)
{
	u8 vsi_id;
	int err;

	vsi_id = hw->vsi_id;
	if (is_af(hw))
		err = nbl_af_operate_vlan_id(hw, 0, vlan_id, vsi_id, false);
	else
		err = nbl_mailbox_req_operate_vlan_id(hw, vlan_id, vsi_id, false);

	return err;
}
