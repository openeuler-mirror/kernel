// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/moduleparam.h>

#include "rdma_comp.h"
#include "roce_compat.h"
#include "roce_mpu_common.h"
#include "roce_cmd.h"
#ifdef ROCE_BONDING_EN
#include "roce_bond.h"
#endif

int roce3_cfg_func_tbl_er_fwd_id_compact(void *hwdev, u32 bond_tbl_val, u16 func_id)
{
	struct roce_bond_cfg_er_fwd_id_cmd cfg_er_fwd_id_comp_info;
	u16 out_size = (u16)sizeof(cfg_er_fwd_id_comp_info);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	memset(&cfg_er_fwd_id_comp_info, 0, sizeof(cfg_er_fwd_id_comp_info));
	cfg_er_fwd_id_comp_info.func_id = func_id;
	cfg_er_fwd_id_comp_info.bond_tbl_val = bond_tbl_val;
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_BOND_ER_FWD_ID_COMPACT,
		&cfg_er_fwd_id_comp_info, sizeof(cfg_er_fwd_id_comp_info),
		&cfg_er_fwd_id_comp_info, &out_size);
	if ((ret != 0) || (out_size == 0) || (cfg_er_fwd_id_comp_info.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to cfg func er_fwd_id(compact), err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, cfg_er_fwd_id_comp_info.head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int roce3_set_port_tbl_bond_state(void *hwdev, u8 bond_state, u16 func_id)
{
	struct roce_bond_cfg_state_cmd set_bond_state_info;
	u16 out_size = (u16)sizeof(set_bond_state_info);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	memset(&set_bond_state_info, 0, sizeof(set_bond_state_info));
	set_bond_state_info.func_id = func_id;
	set_bond_state_info.bond_en = bond_state;
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_BOND_SET_STATE, &set_bond_state_info,
		sizeof(set_bond_state_info), &set_bond_state_info, &out_size);
	if ((ret != 0) || (out_size == 0) || (set_bond_state_info.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to cfg bond state, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, set_bond_state_info.head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int roce3_add_mac_tbl_mac_entry(void *hwdev, u8 *mac_addr, u32 vlan_id, u16 er_fwd_id, u16 func_id)
{
	struct roce_cfg_mac_cmd add_mac_entry_info;
	u16 out_size = (u16)sizeof(add_mac_entry_info);
	int ret;

	if ((hwdev == NULL) || (mac_addr == NULL)) {
		pr_err("[ROCE, ERR] %s: Hwdev or mac_addr is null\n", __func__);
		return -EINVAL;
	}

	if ((vlan_id & ROCE_VLAN_ID_MASK) >= ROCE_VLAN_N_VID) {
		pr_err("[ROCE, ERR] %s: Invalid vlan_id(%d)\n", __func__, vlan_id);
		return -EINVAL;
	}

	memset(&add_mac_entry_info, 0, sizeof(add_mac_entry_info));
	add_mac_entry_info.vni_en = 0;
	add_mac_entry_info.func_id = func_id;
	add_mac_entry_info.vlan_id = vlan_id;
	add_mac_entry_info.er_fwd_id = er_fwd_id;
	memcpy(add_mac_entry_info.mac, mac_addr, ETH_ALEN);
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_ADD_MAC, &add_mac_entry_info,
		sizeof(add_mac_entry_info), &add_mac_entry_info, &out_size);
	if ((ret != 0) || (out_size == 0) || (add_mac_entry_info.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to add mac entry, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, add_mac_entry_info.head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int roce3_del_mac_tbl_mac_entry(void *hwdev, u8 *mac_addr, u32 vlan_id, u16 er_fwd_id, u16 func_id)
{
	struct roce_cfg_mac_cmd del_mac_tbl_info;
	u16 out_size = (u16)sizeof(del_mac_tbl_info);
	int ret;

	if ((hwdev == NULL) || (mac_addr == NULL)) {
		pr_err("[ROCE, ERR] %s: Hwdev or mac_addr is null\n", __func__);
		return -EINVAL;
	}

	if ((vlan_id & ROCE_VLAN_ID_MASK) >= ROCE_VLAN_N_VID) {
		pr_err("[ROCE, ERR] %s: Invalid vlan_id(%d)\n", __func__, vlan_id);
		return -EINVAL;
	}

	memset(&del_mac_tbl_info, 0, sizeof(del_mac_tbl_info));
	del_mac_tbl_info.vni_en = 0;
	del_mac_tbl_info.func_id = func_id;
	del_mac_tbl_info.vlan_id = vlan_id;
	del_mac_tbl_info.er_fwd_id = er_fwd_id;
	memcpy(del_mac_tbl_info.mac, mac_addr, ETH_ALEN);
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_DEL_MAC,
		&del_mac_tbl_info, sizeof(del_mac_tbl_info),
		&del_mac_tbl_info, &out_size);
	if ((ret != 0) || (out_size == 0) || (del_mac_tbl_info.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to del mac entry, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, del_mac_tbl_info.head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

void roce3_add_ipsu_tbl_mac_entry(void *hwdev, u8 *mac_addr, u32 vlan_id, u16 func_id, u8 er_id)
{
	struct roce_cfg_ipsu_mac_cmd ipsu_add_mac_entry_info;
	u16 out_size = (u16)sizeof(ipsu_add_mac_entry_info);
	int ret;

#ifdef ROCE_BONDING_EN
	if (!roce3_get_bond_ipsurx_en()) {
		pr_err("[ROCE, INFO] %s: No need to add ipsu tbl mac entry\n", __func__);
		return;
	}
#endif

	if ((hwdev == NULL) || (mac_addr == NULL)) {
		pr_err("[ROCE, ERR] %s: Hwdev or mac_addr is null\n", __func__);
		return;
	}

	if ((vlan_id & ROCE_VLAN_ID_MASK) >= ROCE_VLAN_N_VID)
		pr_err("[ROCE, ERR] %s: Invalid vlan_id(%d)\n", __func__, vlan_id);

	memset(&ipsu_add_mac_entry_info, 0, sizeof(ipsu_add_mac_entry_info));
	ipsu_add_mac_entry_info.func_id = func_id;
	ipsu_add_mac_entry_info.vlanid_vni = vlan_id & ROCE_VLAN_ID_MASK;
	ipsu_add_mac_entry_info.vni_en = 0;
	memcpy(ipsu_add_mac_entry_info.mac, mac_addr, ETH_ALEN);
	ipsu_add_mac_entry_info.er_id = er_id;
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_ADD_IPSU_MAC, &ipsu_add_mac_entry_info,
		sizeof(ipsu_add_mac_entry_info), &ipsu_add_mac_entry_info, &out_size);
	if ((ret != 0) || (out_size == 0) ||
		((ipsu_add_mac_entry_info.head.status != 0) &&
		(ipsu_add_mac_entry_info.head.status != ERR_EXIST))) {
		pr_err("[ROCE, ERR] %s: Failed to add mac entry to IPSU, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, ipsu_add_mac_entry_info.head.status, out_size);
		return;
	}

	if (ipsu_add_mac_entry_info.head.status == ERR_EXIST)
		pr_info("[ROCE, INFO] %s: This mac entry has been added to IPSU\n", __func__);
}

void roce3_del_ipsu_tbl_mac_entry(void *hwdev, u8 *mac_addr, u32 vlan_id, u16 func_id, u8 er_id)
{
	struct roce_cfg_ipsu_mac_cmd ipsu_del_mac_entry_info;
	u16 out_size = (u16)sizeof(ipsu_del_mac_entry_info);
	int ret;

	if ((hwdev == NULL) || (mac_addr == NULL)) {
		pr_err("[ROCE, ERR] %s: Hwdev or mac_addr is null\n", __func__);
		return;
	}

#ifdef ROCE_BONDING_EN
	if (!roce3_get_bond_ipsurx_en()) {
		pr_err("[ROCE, INFO] %s: No need to del ipsu tbl mac entry\n", __func__);
		return;
	}
#endif

	if ((vlan_id & ROCE_VLAN_ID_MASK) >= ROCE_VLAN_N_VID) {
		pr_err("[ROCE, ERR] %s: Invalid vlan_id(%d)\n", __func__, vlan_id);
		return;
	}

	memset(&ipsu_del_mac_entry_info, 0, sizeof(ipsu_del_mac_entry_info));
	ipsu_del_mac_entry_info.func_id = func_id;
	ipsu_del_mac_entry_info.vlanid_vni = vlan_id & ROCE_VLAN_ID_MASK;
	ipsu_del_mac_entry_info.vni_en = 0;
	memcpy(ipsu_del_mac_entry_info.mac, mac_addr, ETH_ALEN);
	ipsu_del_mac_entry_info.er_id = er_id;
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_DEL_IPSU_MAC, &ipsu_del_mac_entry_info,
		sizeof(ipsu_del_mac_entry_info), &ipsu_del_mac_entry_info, &out_size);
	if ((ret != 0) || (out_size == 0) ||
		((ipsu_del_mac_entry_info.head.status != 0) &&
		(ipsu_del_mac_entry_info.head.status != ERR_NOT_FOUND))) {
		pr_err("[ROCE, ERR] %s: Failed to del mac entry, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, ipsu_del_mac_entry_info.head.status, out_size);
		return;
	}

	if (ipsu_del_mac_entry_info.head.status == ERR_NOT_FOUND)
		pr_info("[ROCE, INFO] %s: This mac entry of ipsu has been deleted\n", __func__);
}

int roce3_do_cache_out(void *hwdev, u8 cl_id, u16 func_id)
{
	struct roce_dfx_cache_out_cmd cache_out_info;
	u16 out_size = (u16)sizeof(cache_out_info);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	memset(&cache_out_info, 0, sizeof(cache_out_info));
	cache_out_info.func_idx = func_id;
	cache_out_info.cache_index = cl_id;
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_DFX_CACHE_OUT,
		&cache_out_info, sizeof(cache_out_info), &cache_out_info, &out_size);
	if ((ret != 0) || (out_size == 0) || (cache_out_info.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to cache out, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, cache_out_info.head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int roce3_set_cfg_ccf_param(void *hwdev, u16 func_id, u32 *ccf_param)
{
	struct roce_cc_cfg_param_cmd cfg_ccf_param;
	u16 out_size = (u16)sizeof(cfg_ccf_param);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	memset(&cfg_ccf_param, 0, sizeof(cfg_ccf_param));
	cfg_ccf_param.func_id = func_id;
	cfg_ccf_param.param[0] = ccf_param[0]; // 0 is param array idx
	cfg_ccf_param.param[1] = ccf_param[1]; // 1 is param array idx
	cfg_ccf_param.param[2] = ccf_param[2]; // 2 is param array idx
	cfg_ccf_param.param[3] = ccf_param[3]; // 3 is param array idx
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_CC_CFG_CCF_PARAM,
		&cfg_ccf_param, sizeof(cfg_ccf_param), &cfg_ccf_param, &out_size);
	if ((ret != 0) || (out_size == 0) || (cfg_ccf_param.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to cfg ccf param, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, cfg_ccf_param.head.status, out_size);

		return -EINVAL;
	}

	return 0;
}

int roce3_set_cfg_dcqcn_param(void *hwdev, u16 func_id, u32 *dcqcn_param)
{
	struct roce_cc_cfg_param_cmd cfg_dcqcn_param;
	u16 out_size = (u16)sizeof(cfg_dcqcn_param);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	memset(&cfg_dcqcn_param, 0, sizeof(cfg_dcqcn_param));
	cfg_dcqcn_param.func_id = func_id;
	cfg_dcqcn_param.param[0] = dcqcn_param[0]; // 0 is param array idx
	cfg_dcqcn_param.param[1] = dcqcn_param[1]; // 1 is param array idx
	cfg_dcqcn_param.param[2] = dcqcn_param[2]; // 2 is param array idx
	cfg_dcqcn_param.param[3] = dcqcn_param[3]; // 3 is param array idx
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_CC_CFG_DCQCN_PARAM,
		&cfg_dcqcn_param, sizeof(cfg_dcqcn_param), &cfg_dcqcn_param, &out_size);
	if ((ret != 0) || (out_size == 0) || (cfg_dcqcn_param.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to cfg dcqcn param, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, cfg_dcqcn_param.head.status, out_size);

		return -EINVAL;
	}

	return 0;
}

int roce3_set_cfg_ipqcn_param(void *hwdev, u16 func_id, u32 *ipqcn_param)
{
	struct roce_cc_cfg_param_cmd cfg_ipqcn_param;
	u16 out_size = (u16)sizeof(cfg_ipqcn_param);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	memset(&cfg_ipqcn_param, 0, sizeof(cfg_ipqcn_param));
	cfg_ipqcn_param.func_id = func_id;
	cfg_ipqcn_param.param[0] = ipqcn_param[0]; // 0 is param array idx
	cfg_ipqcn_param.param[1] = ipqcn_param[1]; // 1 is param array idx
	cfg_ipqcn_param.param[2] = ipqcn_param[2]; // 2 is param array idx
	cfg_ipqcn_param.param[3] = ipqcn_param[3]; // 3 is param array idx
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_CC_CFG_IPQCN_PARAM,
		&cfg_ipqcn_param, sizeof(cfg_ipqcn_param), &cfg_ipqcn_param, &out_size);
	if ((ret != 0) || (out_size == 0) || (cfg_ipqcn_param.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to cfg ipqcn param, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, cfg_ipqcn_param.head.status, out_size);

		return -EINVAL;
	}

	return 0;
}

int roce3_set_cfg_ldcp_param(void *hwdev, u16 func_id, u32 *ldcp_param)
{
	struct roce_cc_cfg_param_cmd cfg_ldcp_param;
	u16 out_size = (u16)sizeof(cfg_ldcp_param);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	memset(&cfg_ldcp_param, 0, sizeof(cfg_ldcp_param));
	cfg_ldcp_param.func_id = func_id;
	cfg_ldcp_param.param[0] = ldcp_param[0]; // 0 is param array idx
	cfg_ldcp_param.param[1] = ldcp_param[1]; // 1 is param array idx
	cfg_ldcp_param.param[2] = ldcp_param[2]; // 2 is param array idx
	cfg_ldcp_param.param[3] = ldcp_param[3]; // 3 is param array idx
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_CC_CFG_LDCP_PARAM,
		&cfg_ldcp_param, sizeof(cfg_ldcp_param), &cfg_ldcp_param, &out_size);
	if ((ret != 0) || (out_size == 0) || (cfg_ldcp_param.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to cfg ldcp param, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, cfg_ldcp_param.head.status, out_size);

		return -EINVAL;
	}

	return 0;
}

int roce3_set_cap_cfg(void *hwdev, u16 index, u32 *cap_cfg)
{
	struct roce_dfx_cfg_cap_param_cmd set_cap_cfg;
	u16 out_size = (u16)sizeof(set_cap_cfg);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	memset(&set_cap_cfg, 0, sizeof(set_cap_cfg));
	set_cap_cfg.index = index;
	set_cap_cfg.param[0] = cap_cfg[0]; // 0 is param array idx
	set_cap_cfg.param[1] = cap_cfg[1]; // 1 is param array idx
	set_cap_cfg.param[2] = cap_cfg[2]; // 2 is param array idx
	set_cap_cfg.param[3] = cap_cfg[3]; // 3 is param array idx
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_DFX_SET_CAP_CFG,
		&set_cap_cfg, sizeof(set_cap_cfg), &set_cap_cfg, &out_size);
	if ((ret != 0) || (out_size == 0) || (set_cap_cfg.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to set cap cfg, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, set_cap_cfg.head.status, out_size);

		return -EINVAL;
	}

	return 0;
}

int roce3_get_cap_cfg(void *hwdev, u16 index, u32 *cap_cfg)
{
	struct roce_dfx_cfg_cap_param_cmd get_cap_cfg;
	u16 out_size = (u16)sizeof(get_cap_cfg);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	memset(&get_cap_cfg, 0, sizeof(get_cap_cfg));
	get_cap_cfg.index = index;
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_DFX_GET_CAP_CFG,
		&get_cap_cfg, sizeof(get_cap_cfg), &get_cap_cfg, &out_size);
	if ((ret != 0) || (out_size == 0) || (get_cap_cfg.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to get cap cfg, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, get_cap_cfg.head.status, out_size);

		return -EINVAL;
	}

	memcpy(cap_cfg, get_cap_cfg.param, sizeof(get_cap_cfg.param));

	return 0;
}

int roce3_clear_cap_counter(void *hwdev, u16 index, u32 *value)
{
	struct roce_dfx_cap_ctr_cmd clear_cap_counter;
	u16 out_size = (u16)sizeof(clear_cap_counter);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	memset(&clear_cap_counter, 0, sizeof(clear_cap_counter));
	clear_cap_counter.index = index;
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_DFX_CLEAR_CAP_CTR,
		&clear_cap_counter, sizeof(clear_cap_counter),
		&clear_cap_counter, &out_size);
	if ((ret != 0) || (out_size == 0) || (clear_cap_counter.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to clear cap counter, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, clear_cap_counter.head.status, out_size);

		return -EINVAL;
	}

	*value = clear_cap_counter.value;

	return 0;
}

int roce3_read_cap_counter(void *hwdev, u16 index, u32 *value)
{
	struct roce_dfx_cap_ctr_cmd read_cap_counter;
	u16 out_size = (u16)sizeof(read_cap_counter);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	memset(&read_cap_counter, 0, sizeof(read_cap_counter));
	read_cap_counter.index = index;
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_DFX_READ_CAP_CTR, &read_cap_counter,
		sizeof(read_cap_counter), &read_cap_counter, &out_size);
	if ((ret != 0) || (out_size == 0) || (read_cap_counter.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to read cap counter, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, read_cap_counter.head.status, out_size);

		return -EINVAL;
	}

	*value = read_cap_counter.value;

	return 0;
}

int roce3_set_func_tbl_func_state(struct roce3_device *rdev, u8 func_state)
{
	void *hwdev = rdev->hwdev;
	u16 func_id = rdev->glb_func_id;
	struct roce_set_func_state_cmd set_func_state_info;
	u16 out_size = (u16)sizeof(set_func_state_info);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return (-EINVAL);
	}

	memset(&set_func_state_info, 0, sizeof(set_func_state_info));
	set_func_state_info.func_id = func_id;
	set_func_state_info.func_en = func_state;
	set_func_state_info.tag = 0;
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_SET_FUNC_STATE,
		&set_func_state_info, sizeof(set_func_state_info),
		&set_func_state_info, &out_size);
	if ((ret != 0) || (out_size == 0) || (set_func_state_info.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to set func state(%d), err(%d), status(0x%x), out size(0x%x), func_id(%d)\n",
			__func__, func_state, ret, set_func_state_info.head.status,
			out_size, func_id);
		return (-EINVAL);
	}

	return 0;
}

int roce3_get_func_table(void *hwdev, u16 func_id, u32 *func_tbl_value)
{
	struct roce_get_func_table_cmd get_func_table;
	struct roce_get_func_table_rsp get_func_table_rsp;
	u16 out_size = (u16)sizeof(get_func_table_rsp);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return (-EINVAL);
	}

	memset(&get_func_table, 0, sizeof(get_func_table));
	memset(&get_func_table_rsp, 0, out_size);
	get_func_table.func_id = func_id;
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_GET_FUNC_TABLE,
		&get_func_table, sizeof(get_func_table),
		&get_func_table_rsp, &out_size);
	if ((ret != 0) || (out_size == 0) || (get_func_table_rsp.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to get func table, err(%d), status(0x%x), out size(0x%x), func_id(%d)\n",
			__func__, ret, get_func_table_rsp.head.status, out_size, func_id);
		return (-EINVAL);
	}

	*func_tbl_value = get_func_table_rsp.func_tbl_value;

	return 0;
}

int roce3_set_func_tbl_cpu_endian(void *hwdev, u8 cpu_endian, u16 func_id)
{
	struct roce_set_cpu_endian_cmd set_cpu_endian_info;
	u16 out_size = (u16)sizeof(set_cpu_endian_info);
	int ret;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	memset(&set_cpu_endian_info, 0, sizeof(set_cpu_endian_info));
	set_cpu_endian_info.func_id = func_id;
	set_cpu_endian_info.cpu_endian = cpu_endian;
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_SET_CPU_ENDIAN,
		&set_cpu_endian_info, sizeof(set_cpu_endian_info),
		&set_cpu_endian_info, &out_size);
	if ((ret != 0) || (out_size == 0) || (set_cpu_endian_info.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to set func state, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, set_cpu_endian_info.head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int roce3_init_cfg_info(struct roce3_device *rdev)
{
	struct roce_get_cfg_info_cmd get_cfg_info;
	struct roce_get_cfg_info_resp resp;
	u16 out_size = (u16)sizeof(resp);
	int ret = 0;

	if (rdev->hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return (-EINVAL);
	}

	memset(&get_cfg_info, 0, sizeof(get_cfg_info));
	memset(&resp, 0, sizeof(resp));

	get_cfg_info.func_id = rdev->glb_func_id;

	ret = roce3_msg_to_mgmt_sync(rdev->hwdev, ROCE_MPU_CMD_GET_CFG_INFO,
		&get_cfg_info, sizeof(get_cfg_info), &resp, &out_size);
	if ((ret != 0) || (out_size == 0) || (get_cfg_info.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to init cfg info, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, get_cfg_info.head.status, out_size);
		return (-EINVAL);
	}

	rdev->cfg_info.scence_id = resp.scence_id;
	rdev->cfg_info.lb_en = resp.lb_en;
	rdev->cfg_info.lb_mode = resp.lb_mode;
	rdev->cfg_info.srq_container_en = (resp.container_mode != ROCE_CHIP_SRQ_MODE_N);
	rdev->cfg_info.srq_container_mode = roce3_srq_mode_chip_adapt(resp.container_mode);
	rdev->cfg_info.xrc_srq_container_mode = ROCE_SRQ_MODE_3;
	rdev->cfg_info.warn_th = 0;

	rdev->cfg_info.fake_en = resp.fake_en;
	rdev->cfg_info.pf_start_bit = resp.pf_start_bit;
	rdev->cfg_info.pf_end_bit = resp.pf_end_bit;
	rdev->cfg_info.page_bit = resp.page_bit;

	rdev->cfg_info.port_num = resp.port_num;
	rdev->cfg_info.host_num = resp.host_num;
	rdev->cfg_info.master_func = (u8)(resp.port_num * resp.host_num);

	dev_info(rdev->hwdev_hdl, "[ROCE] %s: RoCE init,func_id(%d),lb_en(%d),lb_mode(%d),srq_mode(%d),aa_en(%d)\n",
		__func__, rdev->glb_func_id, rdev->cfg_info.lb_en, rdev->cfg_info.lb_mode,
		rdev->cfg_info.srq_container_mode, rdev->cfg_info.scence_id);
	return 0;
}

int roce3_get_group_id(u16 func_id, void *hwdev, struct roce_group_id *group_id)
{
	struct roce_cmd_get_group_id group_id_info;
	u16 out_size = (u16)sizeof(group_id_info);
	int ret;

	if (hwdev == NULL) {
		(void)pr_err("[ROCE] %s(%d): Hwdev is null\n", __func__, __LINE__);
		return -EINVAL;
	}

	/* 组命令并下发给uP */
	memset(&group_id_info, 0, sizeof(group_id_info));
	group_id_info.func_id = func_id;
	ret = roce3_msg_to_mgmt_sync(hwdev, ROCE_MPU_CMD_GET_GROUP_ID,
		&group_id_info, sizeof(group_id_info), &group_id_info, &out_size);
	if (!!ret || (!out_size) || !!group_id_info.status) {
		(void)pr_err(
			"[ROCE] %s(%d): Failed to get group id, ret(%d), status(%u), out size(0x%x)\n",
			__func__, __LINE__, ret, group_id_info.status, out_size);
		return -EINVAL;
	}

	group_id->group_rc_cos = group_id_info.group_rc_cos;
	group_id->group_ud_cos = group_id_info.group_ud_cos;
	group_id->group_xrc_cos = group_id_info.group_xrc_cos;

	return 0;
}

int roce3_del_func_res(struct roce3_device *rdev)
{
	struct roce_set_func_state_cmd del_func_res_info;
	u16 out_size = (u16)sizeof(del_func_res_info);
	int ret;

	if ((rdev == NULL) || (rdev->hwdev == NULL)) {
		pr_err("[ROCE, ERR] %s: rdev/Hwdev is null\n", __func__);
		return (-EINVAL);
	}

	memset(&del_func_res_info, 0, sizeof(del_func_res_info));
	del_func_res_info.func_id = rdev->glb_func_id;
	ret = roce3_msg_to_mgmt_sync(rdev->hwdev, ROCE_MPU_CMD_DEL_FUNC_RES,
		&del_func_res_info, sizeof(del_func_res_info),
		&del_func_res_info, &out_size);
	if ((ret != 0) || (out_size == 0) || (del_func_res_info.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to set func state, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, del_func_res_info.head.status, out_size);
		return (-EINVAL);
	}

	return 0;
}

int roce3_set_bw_ctrl_state(struct roce3_device *rdev, u8 cmd, struct roce3_bw_ctrl_inbuf *inbuf)
{
	int ret = 0;
	struct roce_cc_cfg_bw_ctrl_cmd set_bw_ctrl;
	u16 out_size = (u16)sizeof(set_bw_ctrl);

	if (rdev->hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return (-EINVAL);
	}

	memset(&set_bw_ctrl, 0, sizeof(set_bw_ctrl));

	set_bw_ctrl.func_id = rdev->glb_func_id;
	set_bw_ctrl.cmd = cmd;
	set_bw_ctrl.cir = inbuf->ctrl_param.cir;
	set_bw_ctrl.pir = inbuf->ctrl_param.pir;
	set_bw_ctrl.cnp = inbuf->ctrl_param.cnp;
	pr_info("[ROCE, DEBUG] %s: func_id:%u, cmd:%u, cir:%u, pir:%u, cnp:%u\n",
		__func__, rdev->glb_func_id, set_bw_ctrl.cmd, set_bw_ctrl.cir,
		set_bw_ctrl.pir, set_bw_ctrl.cnp);
	ret = roce3_msg_to_mgmt_sync(rdev->hwdev, ROCE_MPU_CMD_CC_SET_BW_CTRL,
		&set_bw_ctrl, sizeof(set_bw_ctrl), &set_bw_ctrl, &out_size);
	if ((ret != 0) || (out_size == 0) || (set_bw_ctrl.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to set set_bw_ctrl cmd, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, set_bw_ctrl.head.status, out_size);
		return (-EINVAL);
	}

	return 0;
}

int roce3_query_bw_ctrl_state(struct roce3_device *rdev, struct roce3_bw_ctrl_param *bw_ctrl_param)
{
	int ret = 0;
	struct roce_cc_cfg_bw_ctrl_cmd query_bw_ctrl;
	u16 out_size = (u16)sizeof(query_bw_ctrl);

	if (rdev->hwdev == NULL) {
		pr_err("[ROCE, ERR] %s: Hwdev is null\n", __func__);
		return (-EINVAL);
	}

	memset(&query_bw_ctrl, 0, sizeof(query_bw_ctrl));

	query_bw_ctrl.func_id = rdev->glb_func_id;
	ret = roce3_msg_to_mgmt_sync(rdev->hwdev, ROCE_MPU_CMD_CC_QUERY_BW_CTRL,
		&query_bw_ctrl, sizeof(query_bw_ctrl),
		&query_bw_ctrl, &out_size);
	if ((ret != 0) || (out_size == 0) || (query_bw_ctrl.head.status != 0)) {
		pr_err("[ROCE, ERR] %s: Failed to set query_bw_ctrl cmd, err(%d), status(0x%x), out size(0x%x)\n",
			__func__, ret, query_bw_ctrl.head.status, out_size);
		return (-EINVAL);
	}

	memcpy((void *)bw_ctrl_param,
		(void *)((u8 *)(&query_bw_ctrl) + ROCE_CMD_DEFAULT_SIZE),
		sizeof(struct roce3_bw_ctrl_param));

	pr_info("[ROCE, DEBUG] %s: query_bw_ctrl_state:func_id:%u, cir:%u, pir:%u, cnp:%u\n",
		__func__, rdev->glb_func_id, bw_ctrl_param->cir,
		bw_ctrl_param->pir, bw_ctrl_param->cnp);

	return 0;
}
