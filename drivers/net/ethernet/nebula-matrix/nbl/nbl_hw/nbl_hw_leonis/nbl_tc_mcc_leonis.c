// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright(c) 2021-2030 nbl, Inc.
 */
#include "nbl_tc_mcc_leonis.h"

static u16 nbl_tc_cfg_action_set_dport_mcc_eth(u8 eth, u8 port_type)
{
	union nbl_action_data set_dport = {.data = 0};

	set_dport.dport.down.upcall_flag = AUX_FWD_TYPE_NML_FWD;
	set_dport.dport.down.port_type = SET_DPORT_TYPE_ETH_LAG;
	set_dport.dport.down.next_stg_sel = NEXT_STG_SEL_EPRO;
	if (port_type == NBL_TC_PORT_TYPE_ETH) {
		set_dport.dport.down.eth_vld = 1;
		set_dport.dport.down.eth_id = eth;
	} else {
		set_dport.dport.down.lag_vld = 1;
		set_dport.dport.down.lag_id = eth;
	}

	return set_dport.data;
}

static u16 nbl_tc_cfg_action_set_dport_mcc_vsi(u16 vsi)
{
	union nbl_action_data set_dport = {.data = 0};

	set_dport.dport.up.upcall_flag = AUX_FWD_TYPE_NML_FWD;
	set_dport.dport.up.port_type = SET_DPORT_TYPE_VSI_HOST;
	set_dport.dport.up.port_id = vsi;
	set_dport.dport.up.next_stg_sel = NEXT_STG_SEL_EPRO;

	return set_dport.data;
}

void nbl_tc_mcc_init(struct nbl_tc_mcc_mgt *tc_mcc_mgt, struct nbl_common_info *common)
{
	tc_mcc_mgt->common = common;
	INIT_LIST_HEAD(&tc_mcc_mgt->mcc_list);
}

int nbl_tc_mcc_add_leaf_node(struct nbl_tc_mcc_mgt *tc_mcc_mgt, u16 dport_id, u8 port_type)
{
	struct nbl_tc_mcc_info *mcc_node;
	long idx;

	if (tc_mcc_mgt->mcc_offload_cnt >= NBL_TC_MCC_MAX_OFFLOAD_CNT)  {
		nbl_err(tc_mcc_mgt->common, NBL_DEBUG_FLOW, "tc mcc groups exceed max num\n");
		return -ENOBUFS;
	}

	idx = find_first_zero_bit(tc_mcc_mgt->mcc_pool, NBL_TC_MCC_TBL_DEPTH);
	/* idx won't exceed NBL_TC_MCC_TBL_DEPTH unless flow call error */
	if (idx >= NBL_TC_MCC_TBL_DEPTH) {
		nbl_err(tc_mcc_mgt->common, NBL_DEBUG_FLOW, "tc mcc no available idx\n");
		return -ENOBUFS;
	}
	mcc_node = kzalloc(sizeof(*mcc_node), GFP_KERNEL);
	if (!mcc_node)
		return -ENOMEM;

	mcc_node->port_type = port_type;
	mcc_node->dport_id = dport_id;
	mcc_node->mcc_id = (u16)idx;

	set_bit(idx, tc_mcc_mgt->mcc_pool);
	list_add(&mcc_node->node, &tc_mcc_mgt->mcc_list);
	nbl_debug(tc_mcc_mgt->common, NBL_DEBUG_FLOW, "tc mcc group %d add member port type %d id %d\n",
		  (int)idx, port_type, dport_id);

	return idx;
}

void nbl_tc_mcc_get_list(struct nbl_tc_mcc_mgt *tc_mcc_mgt, struct list_head *tc_mcc_list)
{
	list_replace_init(&tc_mcc_mgt->mcc_list, tc_mcc_list);
}

void nbl_tc_mcc_free_list(struct nbl_tc_mcc_mgt *tc_mcc_mgt)
{
	struct nbl_tc_mcc_info *mcc_node = NULL;
	struct nbl_tc_mcc_info *safe_node = NULL;

	list_for_each_entry_safe(mcc_node, safe_node, &tc_mcc_mgt->mcc_list, node) {
		list_del(&mcc_node->node);
		clear_bit(mcc_node->mcc_id, tc_mcc_mgt->mcc_pool);
		nbl_debug(tc_mcc_mgt->common, NBL_DEBUG_FLOW,
			  "tc mcc group %d free member port type %d id %d\n",
			  mcc_node->mcc_id, mcc_node->port_type, mcc_node->dport_id);
		kfree(mcc_node);
	}
}

void nbl_tc_mcc_add_hw_tbl(struct nbl_resource_mgt *res_mgt, struct nbl_tc_mcc_mgt *tc_mcc_mgt)
{
	struct nbl_tc_mcc_info *mcc_node = NULL;
	struct nbl_phy_ops *phy_ops;
	u16 prev_mcc_id, mcc_action;
	bool mcc_add_succ = false;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	list_for_each_entry(mcc_node, &tc_mcc_mgt->mcc_list, node) {
		if (mcc_node->port_type == NBL_TC_PORT_TYPE_VSI)
			mcc_action = nbl_tc_cfg_action_set_dport_mcc_vsi(mcc_node->dport_id);
		else
			mcc_action = nbl_tc_cfg_action_set_dport_mcc_eth((u8)mcc_node->dport_id,
									 mcc_node->port_type);

		if (nbl_list_is_first(&mcc_node->node, &tc_mcc_mgt->mcc_list))
			prev_mcc_id = NBL_MCC_ID_INVALID;
		else
			prev_mcc_id = list_prev_entry(mcc_node, node)->mcc_id;
		phy_ops->add_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mcc_node->mcc_id,
				 prev_mcc_id, NBL_MCC_ID_INVALID, mcc_action, 0, 0);
		mcc_add_succ = true;
	}
	if (mcc_add_succ)
		++tc_mcc_mgt->mcc_offload_cnt;
}

void nbl_tc_mcc_free_hw_tbl(struct nbl_resource_mgt *res_mgt, struct nbl_tc_mcc_mgt *tc_mcc_mgt,
			    struct list_head *tc_mcc_list)
{
	struct nbl_tc_mcc_info *mcc_node = NULL;
	struct nbl_tc_mcc_info *safe_node = NULL;
	struct nbl_phy_ops *phy_ops;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	list_for_each_entry_safe(mcc_node, safe_node, tc_mcc_list, node) {
		phy_ops->del_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mcc_node->mcc_id,
				 NBL_MCC_ID_INVALID, NBL_MCC_ID_INVALID, 0, 0);
		list_del(&mcc_node->node);
		clear_bit(mcc_node->mcc_id, tc_mcc_mgt->mcc_pool);
		nbl_debug(tc_mcc_mgt->common, NBL_DEBUG_FLOW,
			  "tc mcc group %d free member port type %d id %d\n",
			  mcc_node->mcc_id, mcc_node->port_type, mcc_node->dport_id);
		kfree(mcc_node);
	}
	--tc_mcc_mgt->mcc_offload_cnt;
}
