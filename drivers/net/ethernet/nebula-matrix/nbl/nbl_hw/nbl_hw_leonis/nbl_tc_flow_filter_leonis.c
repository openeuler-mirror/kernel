// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_tc_flow_filter_leonis.h"
#include "nbl_p4_actions.h"
#include "nbl_tc_tun_leonis.h"
#include "nbl_tc_flow_leonis.h"
#include "nbl_tc_pedit.h"

#define NBL_ACT_OFT 16
#define NBL_GET_ACT_INFO(data, idx) (*(u16 *)&(data) + ((idx) << NBL_ACT_OFT))

static const struct nbl_cmd_hdr g_cmd_hdr[] = {
	[NBL_FEM_KTAT_WRITE] = { NBL_BLOCK_PPE, NBL_MODULE_FEM,
				 NBL_TABLE_FEM_KTAT, NBL_CMD_OP_WRITE },
	[NBL_FEM_KTAT_READ] = { NBL_BLOCK_PPE, NBL_MODULE_FEM,
				NBL_TABLE_FEM_KTAT, NBL_CMD_OP_READ },
	[NBL_FEM_KTAT_SEARCH] = { NBL_BLOCK_PPE, NBL_MODULE_FEM,
				  NBL_TABLE_FEM_KTAT, NBL_CMD_OP_SEARCH },
	[NBL_FEM_HT_WRITE] = { NBL_BLOCK_PPE, NBL_MODULE_FEM, NBL_TABLE_FEM_HT,
			       NBL_CMD_OP_WRITE },
	[NBL_FEM_HT_READ] = { NBL_BLOCK_PPE, NBL_MODULE_FEM, NBL_TABLE_FEM_HT,
			      NBL_CMD_OP_READ },
};

static int nbl_set_tcam_process(struct nbl_common_info *common,
				struct nbl_flow_tcam_key_mng *tcam_pp_key_mng,
				struct nbl_flow_tcam_ad_mng *tcam_pp_ad_mng,
				struct nbl_tcam_item *tcam_item,
				struct nbl_flow_tcam_ad_item *ad_item,
				u16 *index, bool *is_new)
{
	int ret;

	if (!nbl_tcam_key_lookup(tcam_pp_key_mng, tcam_item, index)) {
		tcam_pp_key_mng[*index].ref_cnt++;
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow tcam:ref_cnt++ pp%d index=%d, ref_cnt=%d",
			  tcam_item->pp_type, *index,
			  tcam_pp_key_mng[*index].ref_cnt);
		if (tcam_item->key_mode == NBL_TC_KT_FULL_MODE) {
			tcam_pp_key_mng[*index + 1].ref_cnt++;
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "tc flow tcam:ref_cnt++ pp%d index=%d, ref_cnt=%d",
				  tcam_item->pp_type, *index + 1,
				  tcam_pp_key_mng[*index + 1].ref_cnt);
		}
	} else {
		ret = nbl_insert_tcam_key_ad(common, tcam_pp_key_mng, tcam_pp_ad_mng,
					     tcam_item, ad_item, index);
		*is_new = true;
		if (ret)
			return ret;
	}

	return 0;
}

static int nbl_flow_ht_assign_proc(struct nbl_resource_mgt *res_mgt,
				   struct nbl_mt_input *mt_input,
				   struct nbl_flow_pp_ht_mng *pp_ht0_mng,
				   struct nbl_flow_pp_ht_mng *pp_ht1_mng,
				   struct nbl_tc_ht_item *ht_item,
				   struct nbl_tcam_item *tcam_item)
{
	int ret = 0;
	u16 i = 0;
	u16 ht0_hash = 0;
	u16 ht1_hash = 0;
	struct nbl_flow_pp_ht_tbl *pp_ht0_node = NULL;
	struct nbl_flow_pp_ht_tbl *pp_ht1_node = NULL;
	u32 num = 0;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	ht0_hash = NBL_CRC16_CCITT(mt_input->key, NBL_KT_BYTE_LEN);
	ht1_hash = NBL_CRC16_IBM(mt_input->key, NBL_KT_BYTE_LEN);

	ht0_hash =
		nbl_hash_transfer(ht0_hash, mt_input->power, mt_input->depth);
	ht1_hash =
		nbl_hash_transfer(ht1_hash, mt_input->power, mt_input->depth);

	pp_ht0_node = pp_ht0_mng->hash_map[ht0_hash];
	pp_ht1_node = pp_ht1_mng->hash_map[ht1_hash];

	ht_item->ht0_hash = ht0_hash;
	ht_item->ht1_hash = ht1_hash;
	ht_item->tbl_id = mt_input->tbl_id;

	/* 2 flow has the same ht0 ht1,put it to tcam*/
	if (nbl_pp_ht0_ht1_search(pp_ht0_mng, ht0_hash, pp_ht1_mng, ht1_hash)) {
		if ((*tcam_item->pp_tcam_count < NBL_FEM_TCAM_MAX_NUM - num - 1) ||
		    (*tcam_item->pp_tcam_count == NBL_FEM_TCAM_MAX_NUM - num - 1 &&
		     tcam_item->key_mode == NBL_TC_KT_HALF_MODE)) {
			tcam_item->tcam_flag = true;
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "tc flow tcam:pp%d has the same ht0=%x,ht1=%x,put it to tcam.\n",
				  mt_input->pp_type, ht0_hash, ht1_hash);
		} else {
			nbl_err(common, NBL_DEBUG_FLOW,
				"tc flow tcam:pp%d has the same ht0=%x,ht1=%x,exceed max num.\n",
				mt_input->pp_type, ht0_hash, ht1_hash);
			ret = -ENOSPC;
		}
		return ret;
	}

	if (!pp_ht0_node && !pp_ht1_node) {
		ret = nbl_insert_pp_ht(res_mgt, pp_ht0_mng, ht0_hash, ht1_hash,
				       mt_input->tbl_id);
		ht_item->ht_entry = NBL_HASH0;
		ht_item->hash_bucket = 0;

	} else if (pp_ht0_node && !pp_ht1_node) {
		if (pp_ht0_node->ref_cnt >= NBL_HASH_CFT_AVL) {
			ret = nbl_insert_pp_ht(res_mgt, pp_ht1_mng, ht1_hash, ht0_hash,
					       mt_input->tbl_id);
			ht_item->ht_entry = NBL_HASH1;
			ht_item->hash_bucket = 0;
		} else {
			for (i = 0; i < NBL_HASH_CFT_MAX; i++) {
				if (pp_ht0_node->key[i].vid == 0) {
					pp_ht0_node->key[i].vid = 1;
					pp_ht0_node->key[i].ht_other_index =
						ht1_hash;
					pp_ht0_node->key[i].kt_index =
						mt_input->tbl_id;
					pp_ht0_node->ref_cnt++;
					ht_item->ht_entry = NBL_HASH0;
					ht_item->hash_bucket = i;
					break;
				}
			}
		}
	} else if (!pp_ht0_node && pp_ht1_node) {
		if (pp_ht1_node->ref_cnt >= NBL_HASH_CFT_AVL) {
			ret = nbl_insert_pp_ht(res_mgt, pp_ht0_mng, ht0_hash, ht1_hash,
					       mt_input->tbl_id);
			ht_item->ht_entry = NBL_HASH0;
			ht_item->hash_bucket = 0;
		} else {
			for (i = 0; i < NBL_HASH_CFT_MAX; i++) {
				if (pp_ht1_node->key[i].vid == 0) {
					pp_ht1_node->key[i].vid = 1;
					pp_ht1_node->key[i].ht_other_index =
						ht0_hash;
					pp_ht1_node->key[i].kt_index =
						mt_input->tbl_id;
					pp_ht1_node->ref_cnt++;
					ht_item->ht_entry = NBL_HASH1;
					ht_item->hash_bucket = i;
					break;
				}
			}
		}
	} else {
		if (pp_ht0_node->ref_cnt <= NBL_HASH_CFT_AVL ||
		    (pp_ht0_node->ref_cnt > NBL_HASH_CFT_AVL &&
		     pp_ht0_node->ref_cnt < NBL_HASH_CFT_MAX &&
		     pp_ht1_node->ref_cnt > NBL_HASH_CFT_AVL)) {
			for (i = 0; i < NBL_HASH_CFT_MAX; i++) {
				if (pp_ht0_node->key[i].vid == 0) {
					pp_ht0_node->key[i].vid = 1;
					pp_ht0_node->key[i].ht_other_index =
						ht1_hash;
					pp_ht0_node->key[i].kt_index =
						mt_input->tbl_id;
					pp_ht0_node->ref_cnt++;
					ht_item->ht_entry = NBL_HASH0;
					ht_item->hash_bucket = i;
					break;
				}
			}
		} else if ((pp_ht0_node->ref_cnt > NBL_HASH_CFT_AVL &&
			    pp_ht1_node->ref_cnt <= NBL_HASH_CFT_AVL) ||
			   (pp_ht0_node->ref_cnt == NBL_HASH_CFT_MAX &&
			    pp_ht1_node->ref_cnt > NBL_HASH_CFT_AVL &&
			    pp_ht1_node->ref_cnt < NBL_HASH_CFT_MAX)) {
			for (i = 0; i < NBL_HASH_CFT_MAX; i++) {
				if (pp_ht1_node->key[i].vid == 0) {
					pp_ht1_node->key[i].vid = 1;
					pp_ht1_node->key[i].ht_other_index =
						ht0_hash;
					pp_ht1_node->key[i].kt_index =
						mt_input->tbl_id;
					pp_ht1_node->ref_cnt++;
					ht_item->ht_entry = NBL_HASH1;
					ht_item->hash_bucket = i;
					break;
				}
			}
		} else {
			if ((*tcam_item->pp_tcam_count <
			     NBL_FEM_TCAM_MAX_NUM - num - 1) ||
			    (*tcam_item->pp_tcam_count ==
				     NBL_FEM_TCAM_MAX_NUM - num - 1 &&
			     tcam_item->key_mode == NBL_TC_KT_HALF_MODE)) {
				tcam_item->tcam_flag = true;
				nbl_debug(common, NBL_DEBUG_FLOW,
					  "tc flow tcam:pp%d ht0=%x,cnt=%d,ht1=%x,cnt=%d, put it to tcam.\n",
					  mt_input->pp_type, ht0_hash,
					  pp_ht0_node->ref_cnt, ht1_hash,
					  pp_ht1_node->ref_cnt);
			} else {
				nbl_err(common, NBL_DEBUG_FLOW,
					"tc flow tcam: pp%d ht0=%x,ht1=%x,exceed max tcam num.\n",
					mt_input->pp_type, ht0_hash, ht1_hash);
				ret = -ENOSPC;
			}
		}
	}

	return ret;
}

static inline u8 nbl_flow_act_num(struct nbl_mt_input *input,
				  u16 count)
{
	if (count <= input->kt_left_num)
		return NBL_FEM_AT_NO_ENTRY;
	else if (count <= input->kt_left_num + NBL_MAX_ACTION_NUM - 1)
		return NBL_FEM_AT_ONE_ENTRY;
	else if (count <= input->kt_left_num + 2 * (NBL_MAX_ACTION_NUM - 1))
		return NBL_FEM_AT_TWO_ENTRY;

	return NBL_FEM_AT_TWO_ENTRY;
}

static int
nbl_flow_port_id_action_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
			    struct nbl_edit_item *edit_item,
			    struct nbl_resource_mgt *res_mgt)
{
	union nbl_action_data set_dport = {.data = 0};
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(tc_flow_mgt->res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_txrx_bond_info *bond_info = &txrx_mgt->bond_info;
	u16 port_id = 0;
	u16 act_idx = *item;
	u16 cur_eth_proto = 0;
	u32 salve1_port_id = 0;
	u32 salve2_port_id = 0;

	if (!action || !buf)
		return -EINVAL;

	set_dport.dport.up.port_type = action->port_type;
	set_dport.dport.up.port_id = action->port_id;
	set_dport.dport.up.upcall_flag = AUX_FWD_TYPE_NML_FWD;
	set_dport.dport.up.next_stg_sel = action->next_stg_sel;

	memcpy(&port_id, &set_dport, 2);
	buf[act_idx] = port_id + (NBL_ACT_SET_DPORT << 16);

	if (!(action->flag & NBL_FLOW_ACTION_PUSH_OUTER_VLAN))
		goto ret_info;

	if (action->vlan.eth_proto == NBL_QINQ_TPID_VALUE)
		cur_eth_proto = NBL_QINQ_TPYE;
	else if (action->vlan.eth_proto == NBL_VLAN_TPID_VALUE)
		cur_eth_proto = NBL_VLAN_TPYE;
	else
		goto ret_info;

	if ((action->vlan.port_type == NBL_TC_PORT_TYPE_VSI ||
	     action->vlan.port_type == NBL_TC_PORT_TYPE_ETH) &&
	     cur_eth_proto != tc_flow_mgt->port_tpid_type[action->vlan.port_id]) {
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow port_id=%d,eth_proto=%d.\n",
			 action->vlan.port_id, cur_eth_proto);
		phy_ops->set_ped_tab_vsi_type(NBL_RES_MGT_TO_PHY_PRIV(tc_flow_mgt->res_mgt),
					      action->vlan.port_id, cur_eth_proto);
		tc_flow_mgt->port_tpid_type[action->vlan.port_id] = cur_eth_proto;
		goto ret_info;
	}

	salve1_port_id = bond_info->eth_id[0] + NBL_VLAN_TYPE_ETH_BASE;
	salve2_port_id = bond_info->eth_id[1] + NBL_VLAN_TYPE_ETH_BASE;

	if (action->vlan.port_type == NBL_TC_PORT_TYPE_BOND && bond_info->bond_enable &&
	    action->vlan.port_id == bond_info->lag_id &&
	    (cur_eth_proto != tc_flow_mgt->port_tpid_type[salve1_port_id] ||
	    cur_eth_proto != tc_flow_mgt->port_tpid_type[salve2_port_id])) {
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow lag_id = %d, port1_id=%d, eth_proto=%d, port2_id=%d, eth_proto=%d.\n",
			 bond_info->lag_id, salve1_port_id, cur_eth_proto,
			 salve2_port_id, cur_eth_proto);
		phy_ops->set_ped_tab_vsi_type(NBL_RES_MGT_TO_PHY_PRIV(tc_flow_mgt->res_mgt),
					      salve1_port_id, cur_eth_proto);
		tc_flow_mgt->port_tpid_type[salve1_port_id] = cur_eth_proto;
		phy_ops->set_ped_tab_vsi_type(NBL_RES_MGT_TO_PHY_PRIV(tc_flow_mgt->res_mgt),
					      salve2_port_id, cur_eth_proto);
		tc_flow_mgt->port_tpid_type[salve2_port_id] = cur_eth_proto;
	}

ret_info:
	return 0;
}

static int nbl_flow_drop_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
			     struct nbl_edit_item *edit_item,
			     struct nbl_resource_mgt *res_mgt)
{
	union nbl_action_data set_dport = {.data = 0};
	u16 port_id = 0;
	u16 act_idx = *item;

	if (!action || !buf)
		return -EINVAL;

	set_dport.dport.up.port_type = SET_DPORT_TYPE_SP_PORT;
	set_dport.dport.up.port_id = 0x3FF;
	set_dport.dport.up.upcall_flag = AUX_KEEP_FWD_TYPE;
	set_dport.dport.up.next_stg_sel = NEXT_STG_SEL_EPRO;

	memcpy(&port_id, &set_dport, 2);
	buf[act_idx] = port_id + (NBL_ACT_SET_DPORT << 16);

	return 0;
}

static int
nbl_flow_counter_action_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
			    struct nbl_edit_item *edit_item,
			    struct nbl_resource_mgt *res_mgt)
{
	u16 act_idx = *item;

	if (!action || !buf)
		return -EINVAL;

	buf[act_idx] =
		(action->counter_id & 0x1FFFF) + (NBL_ACT_SET_FLOW_STAT0 << 16);
	return 0;
}

static int
nbl_flow_mcc_action_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
			struct nbl_edit_item *edit_item,
			struct nbl_resource_mgt *res_mgt)
{
	u16 act_idx = *item;
	int i;
	int ret = 0;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	u16 mcc_port = 0;
	union nbl_action_data mcc_dport = {.data = 0};

	if (!action || !buf)
		return -EINVAL;

	for (i = 0; i < action->mcc_cnt; i++) {
		ret = nbl_tc_mcc_add_leaf_node(&tc_flow_mgt->tc_mcc_mgt,
					       action->port_mcc[i].dport_id,
					       action->port_mcc[i].port_type);
		if (ret < 0) {
			nbl_tc_mcc_free_list(&tc_flow_mgt->tc_mcc_mgt);
			return ret;
		}

		if (i == action->mcc_cnt - 1) {
			edit_item->mcc_idx = ret;
			edit_item->is_mir = true;
		}
	}

	buf[act_idx] = edit_item->mcc_idx + (NBL_ACT_SET_MCC << 16);
	++act_idx;

	mcc_dport.set_fwd_type.identify = NBL_SET_FWD_TYPE_IDENTIFY;
	mcc_dport.set_fwd_type.next_stg_vld = 1;
	mcc_dport.set_fwd_type.next_stg = NBL_NEXT_STG_MCC;
	memcpy(&mcc_port, &mcc_dport, 2);
	buf[act_idx] = mcc_port + (NBL_ACT_SET_AUX_FIELD << 16);
	*item = act_idx;

	nbl_tc_mcc_add_hw_tbl(tc_flow_mgt->res_mgt, &tc_flow_mgt->tc_mcc_mgt);

	nbl_tc_mcc_get_list(&tc_flow_mgt->tc_mcc_mgt, &edit_item->tc_mcc_list);

	return 0;
}

static int
nbl_flow_push_outer_vlan_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
			     struct nbl_edit_item *edit_item,
			     struct nbl_resource_mgt *res_mgt)
{
	u16 act_idx = *item;

	if (!action || !buf)
		return -EINVAL;

	buf[act_idx] = action->vlan.vlan_tag + (NBL_ACT_ADD_SVLAN << 16);
	return 0;
}

static int
nbl_flow_push_inner_vlan_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
			     struct nbl_edit_item *edit_item,
			     struct nbl_resource_mgt *res_mgt)
{
	u16 act_idx = *item;

	if (!action || !buf)
		return -EINVAL;

	buf[act_idx] = action->vlan.vlan_tag + (NBL_ACT_ADD_CVLAN << 16);
	return 0;
}

static int
nbl_flow_pop_outer_vlan_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
			    struct nbl_edit_item *edit_item,
			    struct nbl_resource_mgt *res_mgt)
{
	u16 act_idx = *item;

	if (!action || !buf)
		return -EINVAL;

	buf[act_idx] = NBL_ACT_DEL_SVLAN << 16;
	return 0;
}

static int
nbl_flow_pop_inner_vlan_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
			    struct nbl_edit_item *edit_item,
			    struct nbl_resource_mgt *res_mgt)
{
	u16 act_idx = *item;

	if (!action || !buf)
		return -EINVAL;

	buf[act_idx] = NBL_ACT_DEL_CVLAN << 16;
	return 0;
}

static int
nbl_flow_tunnel_encap_act_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
			      struct nbl_edit_item *edit_item,
			      struct nbl_resource_mgt *res_mgt)
{
	u16 vni_h;
	u16 vni_l;
	u16 act_idx = *item;

	if (!action || !buf)
		return -EINVAL;

	vni_l = (u16)(action->vni & 0x0000ffff);
	vni_h = (u16)(action->vni >> 16);
	buf[act_idx] = (action->encap_idx & 0x1FFFF) + (NBL_ACT_TNL_ENCAP << 16);
	act_idx++;
	buf[act_idx] = vni_h + (NBL_ACT_SET_VNI1 << 16);
	act_idx++;
	buf[act_idx] = vni_l + (NBL_ACT_SET_VNI0 << 16);
	*item = act_idx;

	return 0;
}

static int
nbl_flow_tunnel_decap_act_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
			      struct nbl_edit_item *edit_item,
			      struct nbl_resource_mgt *res_mgt)
{
	u16 act_idx = *item;

	if (!action || !buf)
		return -EINVAL;

	buf[act_idx] = NBL_ACT_TNL_DECAP << 16;

	return 0;
}

static u32 nbl_flow_set_pedit_act(struct nbl_resource_mgt *res_mgt,
				  struct nbl_tc_pedit_entry *in_e,
				  enum nbl_flow_ped_type pedit_type, u32 act_id)
{
	u32 act = 0;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(tc_flow_mgt->res_mgt);

	/* ref_node no need write ped cuz first node had done it */
	if (!NBL_TC_PEDIT_GET_NODE_VAL(in_e))
		phy_ops->write_ped_tbl(NBL_RES_MGT_TO_PHY_PRIV(tc_flow_mgt->res_mgt),
				       in_e->key, nbl_tc_pedit_get_hw_id(in_e), pedit_type);
	act = nbl_tc_pedit_get_hw_id(in_e) + (act_id << 16);

	return act;
}

static int nbl_flow_set_sip_act_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
				    struct nbl_edit_item *edit_item,
				    struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	const struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 act_idx = *item;
	void *out_e = NULL;
	struct nbl_tc_pedit_entry in_e;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	enum nbl_flow_ped_type pedit_type;

	memset(&in_e, 0, sizeof(in_e));
	/* ipv4 should write in the high 32-bits of ped_tbl */
	in_e.ip[1] = be32_to_cpu(action->tc_pedit_info.val.ip4.saddr);
	if (action->flag & NBL_FLOW_ACTION_EGRESS)
		pedit_type = NBL_FLOW_PED_DIP_TYPE;
	else
		pedit_type = NBL_FLOW_PED_UIP_TYPE;

	NBL_TC_PEDIT_DEC_NODE_RES_EDITS(action->tc_pedit_info.pedit_node, 1);
	ret = nbl_tc_pedit_add_node(&tc_flow_mgt->pedit_mgt, &in_e, &out_e, pedit_type);
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW, "nbl_set_sip error");
		return -ENOMEM;
	}

	nbl_debug(common, NBL_DEBUG_FLOW, "nbl_pedit_act(%d-%u):sip:%u, hw-idx:%u",
		  pedit_type, action->tc_pedit_info.pedit_node.pedits,
		  action->tc_pedit_info.val.ip4.saddr, nbl_tc_pedit_get_hw_id(&in_e));

	buf[act_idx] = nbl_flow_set_pedit_act(res_mgt, &in_e, pedit_type, NBL_ACT_REP_IPV4_SIP);
	NBL_TC_PEDIT_SET_NODE_RES_VAL(action->tc_pedit_info.pedit_node);
	NBL_TC_PEDIT_SET_NODE_RES_ENTRY(action->tc_pedit_info.pedit_node, pedit_type, out_e);
	return ret;
}

static int nbl_flow_set_dip_act_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
				    struct nbl_edit_item *edit_item,
				    struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	const struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 act_idx = *item;
	struct nbl_tc_pedit_entry in_e;
	void *out_e = NULL;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	enum nbl_flow_ped_type pedit_type;

	memset(&in_e, 0, sizeof(in_e));
	/* ipv4 should write in the high 32-bits of ped_tbl */
	in_e.ip[1] = be32_to_cpu(action->tc_pedit_info.val.ip4.daddr);
	if (action->flag & NBL_FLOW_ACTION_EGRESS)
		pedit_type = NBL_FLOW_PED_DIP_TYPE;
	else
		pedit_type = NBL_FLOW_PED_UIP_TYPE;

	NBL_TC_PEDIT_DEC_NODE_RES_EDITS(action->tc_pedit_info.pedit_node, 1);
	ret = nbl_tc_pedit_add_node(&tc_flow_mgt->pedit_mgt, &in_e, &out_e, pedit_type);
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW, "nbl_set_dip error");
		return -ENOMEM;
	}

	nbl_debug(common, NBL_DEBUG_FLOW, "nbl_pedit_act(%d-%u):dip:%u, hw-idx:%u",
		  pedit_type, action->tc_pedit_info.pedit_node.pedits,
		  action->tc_pedit_info.val.ip4.daddr, nbl_tc_pedit_get_hw_id(&in_e));
	buf[act_idx] = nbl_flow_set_pedit_act(res_mgt, &in_e, pedit_type, NBL_ACT_REP_IPV4_DIP);
	NBL_TC_PEDIT_SET_NODE_RES_VAL(action->tc_pedit_info.pedit_node);

	/* update pedit_type, for dst ip store in _D_TYPE */
	NBL_TC_PEDIT_SET_D_TYPE(pedit_type);
	NBL_TC_PEDIT_SET_NODE_RES_ENTRY(action->tc_pedit_info.pedit_node, pedit_type, out_e);
	return ret;
}

static int nbl_flow_set_sip6_act_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
				     struct nbl_edit_item *edit_item,
				     struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	const struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 act_idx = *item;
	struct nbl_tc_pedit_entry in_e;
	void *out_e = NULL;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	enum nbl_flow_ped_type pedit_type;
	int idx;
	char ip6[128];
	int oft = 0;
	u32 *cur_ip_s = (u32 *)&in_e.ip6;
	u32 *ip = &action->tc_pedit_info.val.ip6.saddr.in6_u.u6_addr32[3];

	memset(&in_e, 0, sizeof(in_e));
	for (idx = 0; idx < 4; ++idx) {
		*cur_ip_s = be32_to_cpu(*ip);
		oft += snprintf(&ip6[oft], 128, "-%x", *cur_ip_s);
		--ip;
		++cur_ip_s;
	}

	if (action->flag & NBL_FLOW_ACTION_EGRESS)
		pedit_type = NBL_FLOW_PED_DIP_TYPE;
	else
		pedit_type = NBL_FLOW_PED_UIP_TYPE;

	NBL_TC_PEDIT_DEC_NODE_RES_EDITS(action->tc_pedit_info.pedit_node, 4);
	NBL_TC_PEDIT_SET_NODE_H(&in_e);
	ret = nbl_tc_pedit_add_node(&tc_flow_mgt->pedit_mgt, &in_e, &out_e, pedit_type);
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW, "nbl_set_sip6 error");
		return -ENOMEM;
	}

	nbl_debug(common, NBL_DEBUG_FLOW, "nbl_pedit_act(%d-%u):sip6:%s, hw-idx:%u",
		  pedit_type, action->tc_pedit_info.pedit_node.pedits, ip6,
		  nbl_tc_pedit_get_hw_id(&in_e));
	buf[act_idx] = nbl_flow_set_pedit_act(res_mgt, &in_e,
					      NBL_TC_PEDIT_GET_IP6_PHY_TYPE(pedit_type),
					      NBL_ACT_REP_IPV6_SIP);

	NBL_TC_PEDIT_SET_NODE_RES_VAL(action->tc_pedit_info.pedit_node);
	NBL_TC_PEDIT_SET_NODE_RES_ENTRY(action->tc_pedit_info.pedit_node, pedit_type, out_e);
	return ret;
}

static int nbl_flow_set_dip6_act_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
				     struct nbl_edit_item *edit_item,
				     struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	const struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 act_idx = *item;
	struct nbl_tc_pedit_entry in_e;
	void *out_e = NULL;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	enum nbl_flow_ped_type pedit_type;
	int idx;
	char ip6[128];
	int oft = 0;
	u32 *cur_ip_s = (u32 *)&in_e.ip6;
	u32 *ip = &action->tc_pedit_info.val.ip6.daddr.in6_u.u6_addr32[3];

	memset(&in_e, 0, sizeof(in_e));
	for (idx = 0; idx < 4; ++idx) {
		*cur_ip_s = be32_to_cpu(*ip);
		oft += snprintf(&ip6[oft], 128 - oft, "-%x", *cur_ip_s);
		--ip;
		++cur_ip_s;
	}

	if (action->flag & NBL_FLOW_ACTION_EGRESS)
		pedit_type = NBL_FLOW_PED_DIP_TYPE;
	else
		pedit_type = NBL_FLOW_PED_UIP_TYPE;

	NBL_TC_PEDIT_DEC_NODE_RES_EDITS(action->tc_pedit_info.pedit_node, 4);
	NBL_TC_PEDIT_SET_NODE_H(&in_e);
	ret = nbl_tc_pedit_add_node(&tc_flow_mgt->pedit_mgt, &in_e, &out_e, pedit_type);
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW, "nbl_set_dip6 error");
		return -ENOMEM;
	}

	nbl_debug(common, NBL_DEBUG_FLOW, "nbl_pedit_act(%u-%d):dip6:%s, hw-idx:%u",
		  pedit_type, action->tc_pedit_info.pedit_node.pedits, ip6,
		  nbl_tc_pedit_get_hw_id(&in_e));
	buf[act_idx] = nbl_flow_set_pedit_act(res_mgt, &in_e,
					      NBL_TC_PEDIT_GET_IP6_PHY_TYPE(pedit_type),
					      NBL_ACT_REP_IPV6_DIP);

	NBL_TC_PEDIT_SET_NODE_RES_VAL(action->tc_pedit_info.pedit_node);
	/* update pedit_type, for dst ip store in _D_TYPE */
	NBL_TC_PEDIT_SET_D_TYPE(pedit_type);
	NBL_TC_PEDIT_SET_NODE_RES_ENTRY(action->tc_pedit_info.pedit_node, pedit_type, out_e);
	return ret;
}

static int nbl_flow_set_smac_act_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
				     struct nbl_edit_item *edit_item,
				     struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	const struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 act_idx = *item;
	struct nbl_tc_pedit_entry in_e;
	void *out_e = NULL;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	enum nbl_flow_ped_type pedit_type;
	int idx;
	char mac[128];
	int oft = 0;
	u8 *cur_mac_s = (u8 *)&in_e.mac;

	memset(&in_e, 0, sizeof(in_e));
	/* update mac offset, for low 16-bit must be 0 */
	NBL_TC_UPDATE_MAC_OFT(cur_mac_s);
	for (idx = 0; idx < ETH_ALEN; ++idx) {
		*cur_mac_s = action->tc_pedit_info.val.eth.h_source[ETH_ALEN - 1 - idx];
		oft += snprintf(&mac[oft], 128 - oft, "-%x", *cur_mac_s);
		++cur_mac_s;
	}

	if (action->flag & NBL_FLOW_ACTION_EGRESS)
		pedit_type = NBL_FLOW_PED_DMAC_TYPE;
	else
		pedit_type = NBL_FLOW_PED_UMAC_TYPE;

	NBL_TC_PEDIT_DEC_NODE_RES_EDITS(action->tc_pedit_info.pedit_node, 2);
	ret = nbl_tc_pedit_add_node(&tc_flow_mgt->pedit_mgt, &in_e, &out_e, pedit_type);
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW, "nbl_set_smac error");
		return -ENOMEM;
	}

	nbl_debug(common, NBL_DEBUG_FLOW, "nbl_pedit_act(%d-%u):smac:%s, hw-idx:%u",
		  pedit_type, action->tc_pedit_info.pedit_node.pedits, mac,
		  nbl_tc_pedit_get_hw_id(&in_e));
	buf[act_idx] = nbl_flow_set_pedit_act(res_mgt, &in_e, pedit_type, NBL_ACT_REP_SMAC);
	NBL_TC_PEDIT_SET_NODE_RES_VAL(action->tc_pedit_info.pedit_node);
	NBL_TC_PEDIT_SET_NODE_RES_ENTRY(action->tc_pedit_info.pedit_node, pedit_type, out_e);
	return ret;
}

static int nbl_flow_set_dmac_act_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
				     struct nbl_edit_item *edit_item,
				     struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	const struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 act_idx = *item;
	struct nbl_tc_pedit_entry in_e;
	void *out_e = NULL;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	enum nbl_flow_ped_type pedit_type;
	int idx;
	char mac[128];
	int oft = 0;
	u8 *cur_mac_s = in_e.mac;

	memset(&in_e, 0, sizeof(in_e));
	/* update mac offset, for low 16-bit must be 0 */
	NBL_TC_UPDATE_MAC_OFT(cur_mac_s);
	for (idx = 0; idx < ETH_ALEN; ++idx) {
		*cur_mac_s = action->tc_pedit_info.val.eth.h_dest[ETH_ALEN - 1 - idx];
		oft += snprintf(&mac[oft], 128 - oft, "-%x", *cur_mac_s);
		++cur_mac_s;
	}

	if (action->flag & NBL_FLOW_ACTION_EGRESS)
		pedit_type = NBL_FLOW_PED_DMAC_TYPE;
	else
		pedit_type = NBL_FLOW_PED_UMAC_TYPE;

	NBL_TC_PEDIT_DEC_NODE_RES_EDITS(action->tc_pedit_info.pedit_node, 2);
	ret = nbl_tc_pedit_add_node(&tc_flow_mgt->pedit_mgt, &in_e, &out_e, pedit_type);
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW, "nbl_set_dmac error");
		return -ENOMEM;
	}

	nbl_debug(common, NBL_DEBUG_FLOW, "nbl_pedit_act(%d-%u):dmac:%s, hw-idx:%u",
		  pedit_type, action->tc_pedit_info.pedit_node.pedits, mac,
		  nbl_tc_pedit_get_hw_id(&in_e));
	buf[act_idx] = nbl_flow_set_pedit_act(res_mgt, &in_e, pedit_type, NBL_ACT_REP_DMAC);
	NBL_TC_PEDIT_SET_NODE_RES_VAL(action->tc_pedit_info.pedit_node);

	/* update pedit_type, for dst mac store in _D_TYPE */
	NBL_TC_PEDIT_SET_D_TYPE(pedit_type);
	NBL_TC_PEDIT_SET_NODE_RES_ENTRY(action->tc_pedit_info.pedit_node, pedit_type, out_e);
	return ret;
}

static int nbl_flow_set_sp_act_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
				   struct nbl_edit_item *edit_item,
				   struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	const struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 port = 0;
	u16 act_idx = *item;
	bool is_udp = NBL_TC_PEDIT_GET_NODE_RES_PRO(action->tc_pedit_info.pedit_node);

	if (!is_udp)
		port = be16_to_cpu(action->tc_pedit_info.val.tcp.source);
	else
		port = be16_to_cpu(action->tc_pedit_info.val.udp.source);

	nbl_debug(common, NBL_DEBUG_FLOW, "nbl_pedit_act(%u):sp:%s-%u",
		  action->tc_pedit_info.pedit_node.pedits,
		  is_udp ? "udp" : "tcp", port);
	NBL_TC_PEDIT_DEC_NODE_RES_EDITS(action->tc_pedit_info.pedit_node, 1);

	buf[act_idx] = port + (NBL_ACT_REP_SPORT << 16);
	return ret;
}

static int nbl_flow_set_dp_act_2hw(struct nbl_rule_action *action, u32 *buf, u16 *item,
				   struct nbl_edit_item *edit_item,
				   struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	const struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 port = 0;
	u16 act_idx = *item;
	bool is_udp = NBL_TC_PEDIT_GET_NODE_RES_PRO(action->tc_pedit_info.pedit_node);

	if (!is_udp)
		port = be16_to_cpu(action->tc_pedit_info.val.tcp.dest);
	else
		port = be16_to_cpu(action->tc_pedit_info.val.udp.dest);

	nbl_debug(common, NBL_DEBUG_FLOW, "nbl_pedit_act(%u):dp:%s-%u",
		  action->tc_pedit_info.pedit_node.pedits,
		  is_udp ? "udp" : "tcp", port);
	NBL_TC_PEDIT_DEC_NODE_RES_EDITS(action->tc_pedit_info.pedit_node, 1);

	buf[act_idx] = port + (NBL_ACT_REP_DPORT << 16);
	return ret;
}

static struct nbl_flow_action_2hw acts_2hw[] = {
	{ NBL_FLOW_ACTION_PORT_ID, nbl_flow_port_id_action_2hw },
	{ NBL_FLOW_ACTION_DROP, nbl_flow_drop_2hw },
	{ NBL_FLOW_ACTION_COUNTER, nbl_flow_counter_action_2hw },
	{ NBL_FLOW_ACTION_MCC, nbl_flow_mcc_action_2hw },
	{ NBL_FLOW_ACTION_PUSH_OUTER_VLAN, nbl_flow_push_outer_vlan_2hw },
	{ NBL_FLOW_ACTION_PUSH_INNER_VLAN, nbl_flow_push_inner_vlan_2hw },
	{ NBL_FLOW_ACTION_POP_OUTER_VLAN, nbl_flow_pop_outer_vlan_2hw },
	{ NBL_FLOW_ACTION_POP_INNER_VLAN, nbl_flow_pop_inner_vlan_2hw },
	{ NBL_FLOW_ACTION_TUNNEL_ENCAP, nbl_flow_tunnel_encap_act_2hw },
	{ NBL_FLOW_ACTION_TUNNEL_DECAP, nbl_flow_tunnel_decap_act_2hw },
	{ NBL_FLOW_ACTION_SET_IPV4_SRC_IP, nbl_flow_set_sip_act_2hw },
	{ NBL_FLOW_ACTION_SET_IPV4_DST_IP, nbl_flow_set_dip_act_2hw },
	{ NBL_FLOW_ACTION_SET_IPV6_SRC_IP, nbl_flow_set_sip6_act_2hw },
	{ NBL_FLOW_ACTION_SET_IPV6_DST_IP, nbl_flow_set_dip6_act_2hw },
	{ NBL_FLOW_ACTION_SET_SRC_MAC, nbl_flow_set_smac_act_2hw },
	{ NBL_FLOW_ACTION_SET_DST_MAC, nbl_flow_set_dmac_act_2hw },
	{ NBL_FLOW_ACTION_SET_SRC_PORT, nbl_flow_set_sp_act_2hw },
	{ NBL_FLOW_ACTION_SET_DST_PORT, nbl_flow_set_dp_act_2hw },
};

static int nbl_flow_at_num_proc(struct nbl_resource_mgt *res_mgt,
				struct nbl_mt_input *mt_input,
				u16 action_cnt, u32 *buf,
				struct nbl_tc_at_item *at_item)
{
	u16 idx = 0;
	u16 act_idx = 0;
	u16 act1_idx = 0;
	u16 act2_idx = 0;
	u32 act_node_idx[2];
	u32 i;
	int ret = 0;
	struct nbl_flow_pp_at_key at_key[2];
	struct nbl_flow_at_tbl *node = NULL;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	memset(&at_key, 0, sizeof(at_key));

	if (mt_input->at_num == 0) {
		for (idx = 0; idx < action_cnt; idx++)
			at_item->act_buf[idx] = buf[idx];

		at_item->act_num = action_cnt;
	} else if (mt_input->at_num == 1) {
		while (idx < mt_input->kt_left_num - 1) {
			at_item->act_buf[idx + 1] = buf[idx];
			idx++;
		}
		at_item->act_num = mt_input->kt_left_num;

		while (idx < action_cnt) {
			at_item->act1_buf[act1_idx] = buf[idx];
			at_key[0].act[act1_idx] = buf[idx];
			idx++;
			act1_idx++;
		}

		at_item->act1_num = action_cnt - mt_input->kt_left_num + 1;
		act_node_idx[0] = nbl_pp_at_lookup(res_mgt, mt_input->pp_type, NBL_AT_TYPE_1,
						   &at_key[0], &node);
		if (act_node_idx[0] != U32_MAX) {
			node->ref_cnt++;
		} else {
			act_node_idx[0] = nbl_insert_pp_at(res_mgt, mt_input->pp_type,
							   NBL_AT_TYPE_1, &at_key[0], &node);
			if (act_node_idx[0] == U32_MAX) {
				nbl_err(common, NBL_DEBUG_FLOW,
					"tc flow nbl_insert_pp_at error.\n");
				return -1;
			}

			memcpy(&at_item->act_collect.act_key, &at_key[0],
			       sizeof(struct nbl_flow_pp_at_key));
		}

		at_item->act_collect.act_vld = 1;
		at_item->act_collect.act_hw_index = act_node_idx[0] +
							at_item->act_collect.act_offset;
		at_item->act_buf[0] = at_item->act_collect.act_hw_index +
				      (NBL_ACT_NEXT_AT_FULL0 << 16);
	} else if (mt_input->at_num == 2) {
		while (idx < mt_input->kt_left_num - 2) {
			at_item->act_buf[idx + 2] = buf[idx];
			idx++;
		}
		at_item->act_num = mt_input->kt_left_num;
		act_idx = idx;

		while (idx < NBL_AT_MAX_NUM + act_idx) {
			at_item->act1_buf[act1_idx] = buf[idx];
			at_key[0].act[act1_idx] = buf[idx];
			idx++;
			act1_idx++;
		}
		at_item->act1_num = NBL_AT_MAX_NUM;

		while (idx < action_cnt) {
			at_item->act2_buf[act2_idx] = buf[idx];
			at_key[1].act[act2_idx] = buf[idx];
			idx++;
			act2_idx++;
		}
		at_item->act2_num =
			action_cnt - mt_input->kt_left_num + 2 - NBL_AT_MAX_NUM;

		for (i = 0; i < 2; i++) {
			act_node_idx[i] = nbl_pp_at_lookup(res_mgt, mt_input->pp_type,
							   NBL_AT_TYPE_1 + i, &at_key[i], &node);
			if (act_node_idx[i] != U32_MAX) {
				node->ref_cnt++;
			} else {
				ret = nbl_insert_pp_at(res_mgt, mt_input->pp_type,
						       NBL_AT_TYPE_1 + i, &at_key[i], &node);
				if (act_node_idx[i] == U32_MAX) {
					nbl_err(common, NBL_DEBUG_FLOW,
						"tc flow nbl_insert_pp_at error.\n");
					return -1;
				}
				memcpy(&at_item->act_collect.act_key[i], &at_key[i],
				       sizeof(struct nbl_flow_pp_at_key));
			}
		}

		at_item->act_collect.act2_vld = 1;
		at_item->act_collect.act_vld = 1;
		at_item->act_collect.act2_hw_index =
			act_node_idx[0] +
			at_item->act_collect.act2_offset;
		at_item->act_collect.act_hw_index =
			act_node_idx[1] +
			at_item->act_collect.act_offset;
		at_item->act_buf[0] = at_item->act_collect.act2_hw_index +
				      (NBL_ACT_NEXT_AT_FULL0 << 16);
		at_item->act_buf[1] = at_item->act_collect.act_hw_index +
				      (NBL_ACT_NEXT_AT_FULL0 << 16);
	}

	return ret;
}

static int nbl_flow_insert_at(struct nbl_resource_mgt *res_mgt,
			      struct nbl_mt_input *mt_input,
			      struct nbl_rule_action *action,
			      struct nbl_tc_at_item *at_item,
			      struct nbl_edit_item *edit_item,
			      struct nbl_tcam_item *tcam_item)
{
	int ret = 0;
	u32 idx = 0;
	u16 item = 0;
	u32 list_num = ARRAY_SIZE(acts_2hw);
	u32 buf[NBL_MAX_ACTION_NUM] = { 0 };
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	for (idx = 0; idx < list_num; idx++) {
		if (action->flag & acts_2hw[idx].action_type) {
			if (!acts_2hw[idx].act_2hw)
				continue;

			ret = acts_2hw[idx].act_2hw(action, buf, &item,
						    edit_item, res_mgt);
			if (ret)
				return ret;
			item++;
		}
	}

	if (tcam_item->tcam_flag) {
		memcpy(tcam_item->tcam_action, buf, sizeof(tcam_item->tcam_action));
		return ret;
	}

	mt_input->at_num = nbl_flow_act_num(mt_input, item);
	mutex_lock(&tc_flow_mgt->flow_lock);

	ret = nbl_flow_at_num_proc(res_mgt, mt_input, item, buf, at_item);
	mutex_unlock(&tc_flow_mgt->flow_lock);

	return ret;
}

static void nbl_cmdq_show_ht_data(struct nbl_common_info *common,
				  union nbl_cmd_fem_ht_u *ht, bool read)
{
	u32 index = 0;

	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow HT bucket/entry/ht/em: %x-%04x-%x-%x\n",
		  ht->info.bucket_id, ht->info.entry_id, ht->info.ht_id, ht->info.em_id);
	if (read) {
		for (index = 0; index < 4; index++) {
			if (index == 0)
				nbl_debug(common, NBL_DEBUG_FLOW,
					  "tc flow HT four buckets kt_idx/hash/vld:%05x-%04x-%x\n",
					  ht->info.ht_data[index].info.kt_index,
					  ht->info.ht_data[index].info.hash,
					  ht->info.ht_data[index].info.vld);
			else
				nbl_debug(common, NBL_DEBUG_FLOW,
					  "tc flow HT four buckets kt_idx/hash/vld: %05x-%04x-%x",
					  ht->info.ht_data[index].info.kt_index,
					  ht->info.ht_data[index].info.hash,
					  ht->info.ht_data[index].info.vld);
		}

	} else {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow HT kt_idx/hash/vld: %05x-%04x-%x\n",
			  ht->info.ht_data[index].info.kt_index,
			  ht->info.ht_data[index].info.hash,
			  ht->info.ht_data[index].info.vld);
	}
}

int nbl_cmdq_flow_ht_clear_2hw(struct nbl_tc_ht_item *ht_item,
			       u8 pp_type, struct nbl_resource_mgt *res_mgt)
{
	union nbl_cmd_fem_ht_u ht;
	struct nbl_cmd_hdr hdr = g_cmd_hdr[NBL_FEM_HT_WRITE];
	struct nbl_cmd_content cmd = { 0 };
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	memset(&ht, 0, sizeof(ht));

	ht.info.ht_valid = 1;
	if (ht_item->ht_entry == NBL_HASH0) {
		ht.info.entry_id = ht_item->ht0_hash;
		ht.info.ht_id = NBL_ACC_HT0;
	} else if (ht_item->ht_entry == NBL_HASH1) {
		ht.info.entry_id = ht_item->ht1_hash;
		ht.info.ht_id = NBL_ACC_HT1;
	}

	ht.info.bucket_id = ht_item->hash_bucket;
	ht.info.em_id = pp_type;
	/* prepare the command and command header */
	cmd.in_va = &ht;
	cmd.in_length = NBL_CMDQ_FEM_W_REQ_LEN;
	nbl_cmdq_show_ht_data(common, &ht, false);
	return nbl_tc_call_inst_cmdq(common->tc_inst_id, (void *)&hdr, (void *)&cmd);
}

static int nbl_flow_del_ht_2hw(struct nbl_tc_ht_item *ht_item, u8 pp_type,
			       struct nbl_flow_pp_ht_mng *pp_ht0_mng,
			       struct nbl_flow_pp_ht_mng *pp_ht1_mng,
			       struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	struct nbl_flow_pp_ht_key pp_ht_key = { 0 };
	struct nbl_flow_pp_ht_tbl *node = NULL;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	if (ht_item->ht_entry == NBL_HT0_HASH) {
		pp_ht_key.vid = 1;
		pp_ht_key.ht_other_index = ht_item->ht1_hash;
		pp_ht_key.kt_index = ht_item->tbl_id;
		node = nbl_pp_ht_lookup(pp_ht0_mng, ht_item->ht0_hash,
					&pp_ht_key);

		if (node) {
			ret = nbl_cmdq_flow_ht_clear_2hw(ht_item, pp_type, res_mgt);
			if (ret) {
				nbl_err(common, NBL_DEBUG_FLOW,
					"tc flow failed to del cmdq ht 2hw,pp%d ht0_hash=%d,ht1_hash=%d,tbl_id=%d., ret %d\n",
					pp_type, ht_item->ht0_hash,
					ht_item->ht1_hash, ht_item->tbl_id, ret);
				return ret;
			}

			ret = nbl_delete_pp_ht(res_mgt, pp_ht0_mng, node,
					       ht_item->ht0_hash,
					       ht_item->ht1_hash,
					       ht_item->tbl_id);
			if (ret) {
				nbl_err(common, NBL_DEBUG_FLOW,
					"tc flow failed to del ht,pp%d ht0_hash=%d,ht1_hash=%d,tbl_id=%d, ret %d.\n",
					pp_type, ht_item->ht0_hash,
					ht_item->ht1_hash, ht_item->tbl_id, ret);
				return ret;
			}
		} else {
			nbl_err(common, NBL_DEBUG_FLOW,
				"tc flow node = null, pp%d ht0_hash=%d,ht1_hash=%d,tbl_id=%d.\n",
				pp_type, ht_item->ht0_hash, ht_item->ht1_hash,
				ht_item->tbl_id);
			return -EINVAL;
		}

	} else if (ht_item->ht_entry == NBL_HT1_HASH) {
		pp_ht_key.vid = 1;
		pp_ht_key.ht_other_index = ht_item->ht0_hash;
		pp_ht_key.kt_index = ht_item->tbl_id;
		node = nbl_pp_ht_lookup(pp_ht1_mng, ht_item->ht1_hash,
					&pp_ht_key);

		if (node) {
			ret = nbl_cmdq_flow_ht_clear_2hw(ht_item, pp_type, res_mgt);
			if (ret) {
				nbl_err(common, NBL_DEBUG_FLOW,
					"tc flow failed to del cmdq ht 2hw,pp%d ht0_hash=%d,ht1_hash=%d,tbl_id=%d, ret %d.\n",
					pp_type, ht_item->ht0_hash,
					ht_item->ht1_hash, ht_item->tbl_id, ret);
				return ret;
			}

			ret = nbl_delete_pp_ht(res_mgt, pp_ht1_mng, node,
					       ht_item->ht1_hash,
					       ht_item->ht0_hash,
					       ht_item->tbl_id);
			if (ret) {
				nbl_err(common, NBL_DEBUG_FLOW,
					"tc flow failed to del ht, pp%d ht1_hash=%d, ht0_hash=%d, tbl_id=%d, ret %d.\n",
					pp_type, ht_item->ht1_hash,
					ht_item->ht0_hash, ht_item->tbl_id, ret);
				return ret;
			}
		} else {
			nbl_err(common, NBL_DEBUG_FLOW,
				"tc flow node = null, pp%d ht1_hash=%d,ht0_hash=%d,tbl_id=%d.\n",
				pp_type, ht_item->ht1_hash, ht_item->ht0_hash,
				ht_item->tbl_id);
			return -EINVAL;
		}
	} else {
		nbl_err(common, NBL_DEBUG_FLOW,
			"tc flow ht_entry error, pp%d ht0_hash=%d,ht1_hash=%d,tbl_id=%d.\n",
			pp_type, ht_item->ht0_hash, ht_item->ht1_hash,
			ht_item->tbl_id);
	}

	return ret;
}

static int nbl_flow_del_at_2hw(struct nbl_resource_mgt *res_mgt,
			       struct nbl_act_collect *act_collect, u8 pp_type)
{
	int ret = 0;
	int idx;
	struct nbl_flow_at_tbl *at_node = NULL;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	void *at1_tbl = tc_flow_mgt->at_mng.at_tbl[pp_type][NBL_AT_TYPE_1];
	void *at2_tbl = tc_flow_mgt->at_mng.at_tbl[pp_type][NBL_AT_TYPE_2];
	struct nbl_index_key_extra extra_key;

	NBL_INDEX_EXTRA_KEY_INIT(&extra_key, 0, 0, true);
	if (act_collect->act_vld == 1) {
		idx = nbl_common_get_index_with_data(at1_tbl, act_collect->act_key[0].act,
						     &extra_key, NULL, 0, (void **)&at_node);
		if (idx != U32_MAX) {
			at_node->ref_cnt--;
			if (!at_node->ref_cnt) {
				nbl_common_free_index(at1_tbl, act_collect->act_key[0].act);
				nbl_debug(common, NBL_DEBUG_FLOW, "tc flow delete at node key:%d-%d-%d-%d-%d-%d-%d-%d.\n",
					  act_collect->act_key[0].act[0],
					  act_collect->act_key[0].act[1],
					  act_collect->act_key[0].act[2],
					  act_collect->act_key[0].act[3],
					  act_collect->act_key[0].act[4],
					  act_collect->act_key[0].act[5],
					  act_collect->act_key[0].act[6],
					  act_collect->act_key[0].act[7]);
			}
		}
	}

	if (act_collect->act2_vld == 1) {
		idx = nbl_common_get_index_with_data(at2_tbl, act_collect->act_key[1].act,
						     &extra_key, NULL, 0, (void **)&at_node);
		if (idx != U32_MAX) {
			at_node->ref_cnt--;
			if (!at_node->ref_cnt) {
				nbl_common_free_index(at2_tbl, act_collect->act_key[1].act);
				nbl_debug(common, NBL_DEBUG_FLOW, "tc flow delete at node key:%d-%d-%d-%d-%d-%d-%d-%d.\n",
					  act_collect->act_key[1].act[0],
					  act_collect->act_key[1].act[1],
					  act_collect->act_key[1].act[2],
					  act_collect->act_key[1].act[3],
					  act_collect->act_key[1].act[4],
					  act_collect->act_key[1].act[5],
					  act_collect->act_key[1].act[6],
					  act_collect->act_key[1].act[7]);
			}
		}
	}

	return ret;
}

static int nbl_tc_flow_send_tcam_2hw(struct nbl_resource_mgt *res_mgt,
				     struct nbl_flow_tcam_key_mng *tcam_pp_key_mng,
				     struct nbl_flow_tcam_ad_mng *tcam_pp_ad_mng,
				     struct nbl_tcam_item *tcam_item)
{
	int ret = 0;
	struct nbl_flow_tcam_ad_item ad_item;
	u16 index = 0;
	bool is_new = false;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(tc_flow_mgt->res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u8 mode;

	if (!tcam_pp_key_mng || !tcam_pp_ad_mng || !tcam_item)
		return -EINVAL;

	memset(&ad_item, 0, sizeof(ad_item));

	memcpy(ad_item.action, tcam_item->tcam_action, sizeof(ad_item.action));
	ret = nbl_set_tcam_process(common, tcam_pp_key_mng, tcam_pp_ad_mng,
				   tcam_item, &ad_item, &index, &is_new);
	if (ret)
		return ret;

	if (is_new) {
		tcam_item->tcam_index = index;
		if (tcam_item->key_mode == NBL_TC_KT_HALF_MODE) {
			mode = NBL_KT_HALF_MODE;
			*tcam_item->pp_tcam_count =
				*tcam_item->pp_tcam_count + 1;
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow tcam:count+1 pp%d count=%d",
				  tcam_item->pp_type, *tcam_item->pp_tcam_count);
		} else {
			mode = NBL_KT_FULL_MODE;
			*tcam_item->pp_tcam_count =
				*tcam_item->pp_tcam_count + 2;
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow tcam:count+2 pp%d count=%d",
				  tcam_item->pp_type, *tcam_item->pp_tcam_count);
		}

		ret = phy_ops->add_tcam(NBL_RES_MGT_TO_PHY_PRIV(tc_flow_mgt->res_mgt),
					tcam_item->tcam_index, tcam_item->kt_data.hash_key,
					tcam_item->tcam_action, mode, tcam_item->pp_type);
	}

	return ret;
}

static void nbl_cmdq_show_ktat_header(struct nbl_common_info *common,
				      union nbl_cmd_fem_ktat_u *ktat)
{
	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow show KT index: 0x%08x\n", ktat->info.kt_index);
	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow show KT valid: 0x%0x\n", ktat->info.kt_valid);
	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow show KT size: 0x%02x\n", ktat->info.kt_size);
	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow show AT index: 0x%08x\n", ktat->info.at_index);
	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow show AT valid: 0x%0x\n", ktat->info.at_valid);
	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow show AT size: 0x%02x\n", ktat->info.at_size);
}

static void nbl_cmdq_show_kt_data(struct nbl_common_info *common,
				  union nbl_cmd_fem_ktat_u *ktat, bool second)
{
	u32 i = 0;
	const unsigned char *p = (unsigned char *)&ktat->info.kt_data;

	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow showing KT data (320 bits):\n");

	for (i = 0; i < NBL_PPE_KT_FULL_SIZE; i += 16) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow [%d] %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			  i / 8, p[i], p[i + 1], p[i + 2], p[i + 3], p[i + 4],
			  p[i + 5], p[i + 6], p[i + 7], p[i + 8], p[i + 9],
			  p[i + 10], p[i + 11], p[i + 12], p[i + 13], p[i + 14],
			  p[i + 15]);
	}

	if (second) {
		const union nbl_fem_four_at_data_u *test =
			(const union nbl_fem_four_at_data_u *)(p + 20);
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow showing KT actions:\n");
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow [actions]: %02x %02x %02x %02x\n",
			  test->info.at1, test->info.at2, test->info.at3,
			  test->info.at4);
	} else {
		const union nbl_fem_four_at_data_u *test =
			(const union nbl_fem_four_at_data_u *)(p);
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow showing KT actions:\n");
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow [actions]: %02x %02x %02x %02x\n",
			  test->info.at1, test->info.at2, test->info.at3,
			  test->info.at4);
	}
}

static void __maybe_unused
nbl_cmdq_show_at_data(struct nbl_common_info *common,
		      union nbl_cmd_fem_ktat_u *ktat)
{
	/* AT 176 bit */
	const union nbl_fem_at_acc_data_u *at = (union nbl_fem_at_acc_data_u *)&ktat->info.at_data;

	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow showing AT data (176 bits):\n");
	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow check at data:0x%x-%x-%x-%x-%x-%x-%x-%x.\n",
		  at->info.at1, at->info.at2, at->info.at3, at->info.at4,
		  at->info.at5, at->info.at6, at->info.at7, at->info.at8);
}

static void __maybe_unused
nbl_cmdq_show_searched_at_data(struct nbl_common_info *common,
			       union nbl_cmd_fem_ktat_u *ktat)
{
	const union nbl_fem_all_at_data_u *at = (union nbl_fem_all_at_data_u *)&ktat->info.kt_data;

	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow showing all action data (352 bits):\n");
	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow check at data:0x%x-%x-%x-%x-%x-%x-%x-%x.\n",
		  at->info.at1, at->info.at2, at->info.at3, at->info.at4,
		  at->info.at5, at->info.at6, at->info.at7, at->info.at8);
	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow check act data:0x%x-%x-%x-%x-%x-%x-%x-%x.\n",
		  at->info.at9, at->info.at10, at->info.at11, at->info.at12,
		  at->info.at13, at->info.at14, at->info.at15, at->info.at16);
}

static void __maybe_unused
nbl_cmdq_search_flow_ktat(const struct nbl_tc_kt_item *kt_item,
			  struct nbl_resource_mgt *res_mgt)
{
	union nbl_cmd_fem_ktat_u ktat;
	struct nbl_cmd_hdr hdr = g_cmd_hdr[NBL_FEM_KTAT_SEARCH];
	struct nbl_cmd_content cmd = { 0 };
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	memset(&ktat, 0, sizeof(ktat));

	ktat.info.kt_valid = 1;
	ktat.info.kt_em = kt_item->pp_type;
	if (kt_item->key_type == NBL_KEY_TYPE_160)
		memcpy(&ktat.info.kt_data[5], &kt_item->kt_data.data,
		       sizeof(kt_item->kt_data.data) / 2);
	else
		memcpy(&ktat.info.kt_data, &kt_item->kt_data.data,
		       sizeof(kt_item->kt_data.data));

	cmd.in_va = &ktat;
	cmd.in_length = NBL_CMDQ_FEM_S_REQ_LEN;
	cmd.out_va = &ktat;
	nbl_cmdq_show_kt_data(common, &ktat, kt_item->key_type == NBL_KEY_TYPE_160);
	nbl_tc_call_inst_cmdq(common->tc_inst_id, (void *)&hdr, (void *)&cmd);
	/* the result AT will be stored in KT in ktat */
	nbl_cmdq_show_searched_at_data(common, &ktat);
}

/* search a non-existant KT */
static void __maybe_unused
nbl_cmdq_search_noflow_ktat(const struct nbl_tc_kt_item *kt_item,
			    struct nbl_resource_mgt *res_mgt)
{
	union nbl_cmd_fem_ktat_u ktat;
	struct nbl_cmd_hdr hdr = g_cmd_hdr[NBL_FEM_KTAT_SEARCH];
	struct nbl_cmd_content cmd = { 0 };
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	memset(&ktat, 0, sizeof(ktat));

	ktat.info.kt_valid = 1;
	ktat.info.kt_em = kt_item->pp_type;
	if (kt_item->key_type == NBL_KEY_TYPE_160)
		memcpy(&ktat.info.kt_data[5], &kt_item->kt_data.data,
		       sizeof(kt_item->kt_data.data) / 2);
	else
		memcpy(&ktat.info.kt_data, &kt_item->kt_data.data,
		       sizeof(kt_item->kt_data.data));

	/* KT data modification */
	ktat.info.kt_data[9] = 0;

	cmd.in_va = &ktat;
	cmd.in_length = NBL_CMDQ_FEM_S_REQ_LEN;
	cmd.out_va = &ktat;
	nbl_debug(common, NBL_DEBUG_FLOW,
		  "tc flow searching AT with non-existant KT data\n");
	nbl_cmdq_show_kt_data(common, &ktat, kt_item->key_type == NBL_KEY_TYPE_160);
	nbl_tc_call_inst_cmdq(common->tc_inst_id, (void *)&hdr, (void *)&cmd);

	/* the result AT will be stored in KT in ktat */
	nbl_cmdq_show_searched_at_data(common, &ktat);
}

/* use cmdq to read the KT & AT written to MT */
static int __maybe_unused nbl_cmdq_read_flow_ktat(struct nbl_tc_ht_item *ht_item,
						  struct nbl_tc_at_item *at_item,
						  struct nbl_resource_mgt *res_mgt)
{
	union nbl_cmd_fem_ktat_u ktat;
	union nbl_cmd_fem_ktat_u extra_ktat;
	struct nbl_cmd_hdr hdr = g_cmd_hdr[NBL_FEM_KTAT_READ];
	struct nbl_cmd_content cmd = { 0 };
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	/* not necessary to check KT info */
	if (!ht_item || !at_item)
		return -EINVAL;

	memset(&ktat, 0, sizeof(ktat));
	memset(&extra_ktat, 0, sizeof(extra_ktat));

	/* read KT */
	ktat.info.kt_valid = 1;
	ktat.info.kt_size = 1; /* can only read full table */
	ktat.info.kt_index = ht_item->tbl_id;
	if (at_item->act1_num) {
		ktat.info.at_valid = 1;
		ktat.info.at_size = 1; /* can only read full table */
		ktat.info.at_index = at_item->act_collect.act_hw_index;
	}

	cmd.in_va = &ktat;
	cmd.in_length = NBL_CMDQ_FEM_R_REQ_LEN;
	cmd.out_va = &ktat;
	nbl_debug(common, NBL_DEBUG_FLOW,
		  "tc flow sending read request of KT and AT table\n");

	nbl_tc_call_inst_cmdq(common->tc_inst_id, (void *)&hdr, (void *)&cmd);

	/* print out read data */
	nbl_cmdq_show_ktat_header(common, &ktat);
	nbl_cmdq_show_kt_data(common, &ktat, false);
	nbl_cmdq_show_at_data(common, &ktat);

	/* read AT */
	if (at_item->act2_num) {
		extra_ktat.info.at_index = at_item->act_collect.act2_hw_index;
		extra_ktat.info.at_valid = 1;
		extra_ktat.info.at_size = 1;
		cmd.in_va = &extra_ktat;
		cmd.in_length = NBL_CMDQ_FEM_R_REQ_LEN;
		cmd.out_va = &extra_ktat;
		cmd.out_length = 0;
		cmd.out_params = 0;
		cmd.in_params = 0;
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow sending read request of AT table\n");

		nbl_tc_call_inst_cmdq(common->tc_inst_id, (void *)&hdr, (void *)&cmd);

		/* print out AT data */
		nbl_cmdq_show_ktat_header(common, &extra_ktat);
		nbl_cmdq_show_at_data(common, &extra_ktat);
	}

	return 0;
}

static void __maybe_unused
nbl_cmdq_read_hw_ht_entry(struct nbl_tc_ht_item *ht_item,
			  u8 pp_type, struct nbl_resource_mgt *res_mgt)
{
	union nbl_cmd_fem_ht_u ht;
	struct nbl_cmd_hdr hdr = g_cmd_hdr[NBL_FEM_HT_READ];
	struct nbl_cmd_content cmd = { 0 };
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	ht.info.ht_valid = 1;
	ht.info.ht_data[0].info.vld = 1;
	if (ht_item->ht_entry == NBL_HASH0) {
		ht.info.ht_data[0].info.hash = ht_item->ht1_hash;
		ht.info.entry_id = ht_item->ht0_hash;
		ht.info.ht_id = NBL_ACC_HT0;
	} else if (ht_item->ht_entry == NBL_HASH1) {
		ht.info.ht_data[0].info.hash = ht_item->ht0_hash;
		ht.info.entry_id = ht_item->ht1_hash;
		ht.info.ht_id = NBL_ACC_HT1;
	}

	/* no need to fill in the bucket id */
	ht.info.ht_data[0].info.kt_index = ht_item->tbl_id;
	ht.info.em_id = pp_type;

	cmd.in_va = &ht;
	cmd.in_length = NBL_CMDQ_FEM_R_REQ_LEN;

	nbl_tc_call_inst_cmdq(common->tc_inst_id, (void *)&hdr, (void *)&cmd);

	/* show read result */
	nbl_cmdq_show_ht_data(common, &ht, true);
}

/* write HT table using CMDQ */
static void nbl_cmdq_send_flow_ht(struct nbl_tc_ht_item *ht_item, u8 pp_type,
				  struct nbl_resource_mgt *res_mgt)
{
	union nbl_cmd_fem_ht_u ht;
	struct nbl_cmd_hdr hdr = g_cmd_hdr[NBL_FEM_HT_WRITE];
	struct nbl_cmd_content cmd = { 0 };
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	memset(&ht, 0, sizeof(ht));

	ht.info.ht_valid = 1;
	ht.info.ht_data[0].info.vld = 1;

	if (ht_item->ht_entry == NBL_HASH0) {
		ht.info.ht_data[0].info.hash = ht_item->ht1_hash;
		ht.info.entry_id = ht_item->ht0_hash;
		ht.info.ht_id = NBL_ACC_HT0;
	} else if (ht_item->ht_entry == NBL_HASH1) {
		ht.info.ht_data[0].info.hash = ht_item->ht0_hash;
		ht.info.entry_id = ht_item->ht1_hash;
		ht.info.ht_id = NBL_ACC_HT1;
	}

	ht.info.bucket_id = ht_item->hash_bucket;
	ht.info.ht_data[0].info.kt_index = ht_item->tbl_id;
	ht.info.em_id = pp_type;

	/* sending the command */
	cmd.in_va = &ht;
	cmd.in_length = NBL_CMDQ_FEM_W_REQ_LEN;
	nbl_tc_call_inst_cmdq(common->tc_inst_id, (void *)&hdr, (void *)&cmd);
}

/* write KT and AT table, KT index is stored in ht_item */
__maybe_unused static int
nbl_cmdq_send_flow_ktat(struct nbl_tc_ht_item *ht_item,
			struct nbl_tc_kt_item *kt_item,
			struct nbl_tc_at_item *at_item,
			struct nbl_resource_mgt *res_mgt)
{
	union nbl_cmd_fem_ktat_u ktat;
	struct nbl_cmd_hdr hdr = g_cmd_hdr[NBL_FEM_KTAT_WRITE];
	struct nbl_cmd_content cmd = { 0 };
	union nbl_fem_at_acc_data_u at1;
	union nbl_fem_at_acc_data_u at2;
	struct nbl_cmd_content cmd_addition;
	union nbl_cmd_fem_ktat_u extra_ktat;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	if (!ht_item || !kt_item || !at_item)
		return -EINVAL;

	memset(&ktat, 0, sizeof(ktat));
	memset(&at1, 0, sizeof(at1));
	memset(&at2, 0, sizeof(at2));
	memset(&cmd_addition, 0, sizeof(cmd_addition));
	memset(&extra_ktat, 0, sizeof(extra_ktat));

	/* the first command, it should send KT, and possible the first AT */
	ktat.info.kt_valid = 1;
	ktat.info.kt_index = ht_item->tbl_id;
	ktat.info.kt_size = (kt_item->key_type == NBL_KEY_TYPE_160) ? 0 : 1;
	memcpy(&ktat.info.kt_data, &kt_item->kt_data.data, sizeof(kt_item->kt_data.data));

	if (at_item->act1_num) {
		at1.info.at1 = at_item->act1_buf[0];
		at1.info.at2 = at_item->act1_buf[1];
		at1.info.at3 = at_item->act1_buf[2];
		at1.info.at4 = at_item->act1_buf[3];
		at1.info.at5 = at_item->act1_buf[4];
		at1.info.at6 = at_item->act1_buf[5];
		at1.info.at7 = at_item->act1_buf[6];
		at1.info.at8 = at_item->act1_buf[7];

		ktat.info.at_valid = 1;
		ktat.info.at_index = at_item->act_collect.act_hw_index;
		/* all AT entry use the full width */
		ktat.info.at_size = 1;
		memcpy(&ktat.info.at_data, &at1.info, sizeof(at1));
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow kt index=0x%x,at_hw_index=0x%x,at data:0x%x-%x-%x-%x-%x-%x-%x-%x.",
			  ktat.info.kt_index, at_item->act_collect.act_hw_index,
			  at1.info.at1, at1.info.at2, at1.info.at3, at1.info.at4,
			  at1.info.at5, at1.info.at6, at1.info.at7, at1.info.at8);
	}

	/* fill in the command flags, block, module, table, etc */
	cmd.in_va = &ktat;
	cmd.in_length = NBL_CMDQ_FEM_W_REQ_LEN;

	nbl_tc_call_inst_cmdq(common->tc_inst_id, (void *)&hdr, (void *)&cmd);

	/* if AT2 is used, another command is also needed */
	if (at_item->act2_num) {
		at2.info.at1 = at_item->act2_buf[0];
		at2.info.at2 = at_item->act2_buf[1];
		at2.info.at3 = at_item->act2_buf[2];
		at2.info.at4 = at_item->act2_buf[3];
		at2.info.at5 = at_item->act2_buf[4];
		at2.info.at6 = at_item->act2_buf[5];
		at2.info.at7 = at_item->act2_buf[6];
		at2.info.at8 = at_item->act2_buf[7];

		extra_ktat.info.at_valid = 1;
		extra_ktat.info.at_index = at_item->act_collect.act2_hw_index;
		/* all AT entry use the full width */
		extra_ktat.info.at_size = 1;
		memcpy(&extra_ktat.info.at_data, &at2.info, sizeof(at2));

		cmd_addition.in_va = &extra_ktat;
		cmd_addition.in_length = NBL_CMDQ_FEM_W_REQ_LEN;

		nbl_tc_call_inst_cmdq(common->tc_inst_id, (void *)&hdr, (void *)&cmd);
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow kt index=0x%x, at2_hw_index=0x%x, at2 data:0x%x-%x-%x-%x-%x-%x-%x-%x.",
			  ktat.info.kt_index, at_item->act_collect.act2_hw_index,
			  at2.info.at1, at2.info.at2, at2.info.at3, at2.info.at4,
			  at2.info.at5, at2.info.at6, at2.info.at7, at2.info.at8);
	}

	/* write HT table using CMDQ */
	nbl_cmdq_send_flow_ht(ht_item, kt_item->pp_type, res_mgt);

	return 0;
}

static int nbl_flow_del_tcam_2hw(struct nbl_resource_mgt *res_mgt,
				 struct nbl_flow_tcam_key_mng *tcam_pp_key_mng,
				 struct nbl_flow_tcam_ad_mng *tcam_pp_ad_mng,
				 struct nbl_tcam_item *tcam_item)
{
	int ret = 0;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(tc_flow_mgt->res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u8 mode;

	if (!tcam_pp_key_mng || !tcam_pp_ad_mng || !tcam_item)
		return -EINVAL;

	ret = nbl_delete_tcam_key_ad(common, tcam_pp_key_mng, tcam_pp_ad_mng,
				     tcam_item->tcam_index, tcam_item->key_mode,
				     tcam_item->pp_type);
	if (ret == 0 && tcam_pp_key_mng[tcam_item->tcam_index].ref_cnt == 0) {
		if (tcam_item->key_mode == NBL_TC_KT_HALF_MODE) {
			mode = NBL_KT_HALF_MODE;
			*tcam_item->pp_tcam_count =
				*tcam_item->pp_tcam_count - 1;
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow tcam:count-1 pp%d count=%d\n",
				  tcam_item->pp_type, *tcam_item->pp_tcam_count);
		} else {
			mode = NBL_KT_FULL_MODE;
			*tcam_item->pp_tcam_count =
				*tcam_item->pp_tcam_count - 2;
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow tcam:count-2 pp%d count=%d\n",
				  tcam_item->pp_type, *tcam_item->pp_tcam_count);
		}

		phy_ops->del_tcam(NBL_RES_MGT_TO_PHY_PRIV(tc_flow_mgt->res_mgt),
				  tcam_item->tcam_index, mode, tcam_item->pp_type);
	}

	return ret;
}

static int nbl_tc_set_pp_related_value(struct nbl_select_input *select_input,
				       struct nbl_mt_input *mt_input,
				       struct nbl_tc_flow_mgt *tc_flow_mgt,
				       u8 profile_id)
{
	select_input->pp_type = profile_id / NBL_PP_PROFILE_NUM;

	switch (select_input->pp_type) {
	case NBL_PP_TYPE_1:
		select_input->pp_tcam_count = &tc_flow_mgt->count_mng.pp1_tcam_count;
		select_input->pp_ht0_mng = &tc_flow_mgt->pp1_ht0_mng;
		select_input->pp_ht1_mng = &tc_flow_mgt->pp1_ht1_mng;
		select_input->act_offset = NBL_PP1_AT_OFFSET;
		select_input->act2_offset = NBL_PP1_AT2_OFFSET;

		select_input->tcam_pp_key_mng = tc_flow_mgt->tcam_pp1_key_mng;
		select_input->tcam_pp_ad_mng = tc_flow_mgt->tcam_pp1_ad_mng;
		select_input->pp_kt_bmp = tc_flow_mgt->pp1_kt_bmp;
		select_input->pp_kt_num = NBL_PP1_KT_NUM;

		mt_input->depth = NBL_FEM_HT_PP1_DEPTH;
		select_input->kt_idx_offset = NBL_PP1_KT_OFFSET;
		mt_input->power = NBL_PP1_POWER;

		mt_input->pp_type = NBL_PP_TYPE_1;
		break;
	case NBL_PP_TYPE_2:
		select_input->pp_tcam_count = &tc_flow_mgt->count_mng.pp2_tcam_count;
		select_input->pp_ht0_mng = &tc_flow_mgt->pp2_ht0_mng;
		select_input->pp_ht1_mng = &tc_flow_mgt->pp2_ht1_mng;
		select_input->tcam_pp_key_mng = tc_flow_mgt->tcam_pp2_key_mng;
		select_input->tcam_pp_ad_mng = tc_flow_mgt->tcam_pp2_ad_mng;
		select_input->pp_kt_bmp = tc_flow_mgt->pp2_kt_bmp;
		select_input->pp_kt_num = NBL_PP2_KT_NUM;

		mt_input->depth = NBL_FEM_HT_PP2_DEPTH;
		select_input->act2_offset = NBL_PP2_AT2_OFFSET;
		mt_input->power = NBL_PP2_POWER;

		mt_input->pp_type = NBL_PP_TYPE_2;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void nbl_tc_assign_action_data(u32 *key, u32 offset,
				      u32 value)
{
	u32 index = offset / NBL_BITS_IN_U32;
	u32 remain = offset % NBL_BITS_IN_U32;
	u32 shifted = 0;

	if (NBL_BITS_IN_U32 - remain < NBL_AT_WIDTH) {
		/* if the value span across u32 boundary */
		shifted = NBL_BITS_IN_U32 - remain;
		key[index] += (value << remain);
		key[index + 1] += (value >> shifted);
	} else {
		key[index] += (value << remain);
	}
}

static void nbl_tc_assign_acts_for_kt(struct nbl_common_info *common,
				      struct nbl_tc_at_item *at_item, u32 *key,
				      struct nbl_mt_input *input)
{
	u8 i = 0;
	u32 offset = 0;

	if (input->kt_left_num > (NBL_FEM_KT_HALF_LEN / NBL_AT_WIDTH)) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow too many actions to insert for KT data\n");
		return;
	}

	for (i = 0; i < input->kt_left_num; i++) {
		nbl_tc_assign_action_data(key, offset, at_item->act_buf[i]);
		offset += NBL_AT_WIDTH;
	}
}

static inline void nbl_tc_assign_idx_act_for_kt(struct nbl_tc_kt_item *kt_item,
						struct nbl_flow_tab_filter *node)
{
	u32 act_value = node->assoc_tbl_id + (NBL_ACT_SET_TAB_INDEX << 16);

	nbl_tc_assign_action_data(kt_item->kt_data.data, 0, act_value);
}

static inline void
nbl_tc_assign_idx_act_for_tcam(struct nbl_tcam_item *tcam_item,
			       struct nbl_flow_tab_filter *node)
{
	u32 idx = 0;

	tcam_item->tcam_action[idx++] = NBL_GET_ACT_INFO(node->tbl_id,
							 NBL_ACT_SET_TAB_INDEX);
}

static inline void nbl_tc_assign_key_for_hash(struct nbl_mt_input *mt_input,
					      struct nbl_flow_tab_filter *node)
{
	u8 idx;
	u8 *ptr = (u8 *)node->key.key_value;

	for (idx = 0; idx < NBL_KT_BYTE_HALF_LEN; idx++) {
		mt_input->key[idx] = ptr[NBL_KT_BYTE_LEN - idx - 1];
		mt_input->key[NBL_KT_BYTE_LEN - idx - 1] = ptr[idx];
	}
}

static inline void nbl_tc_assign_kt_item(struct nbl_tc_kt_item *kt_item,
					 struct nbl_select_input *select_input,
					 struct nbl_flow_tab_filter *node,
					 bool full)
{
	u32 *ptr = node->key.key_value;
	u16 size = full ? NBL_FEM_KT_LEN : NBL_FEM_KT_HALF_LEN;
	u16 offset = full ? 0 : (NBL_FEM_KT_HALF_LEN / NBL_BITS_IN_U32);

	kt_item->key_type = full ? NBL_KEY_TYPE_320 : NBL_KEY_TYPE_160;
	kt_item->pp_type = select_input->pp_type;
	memcpy(kt_item->kt_data.data, ptr + offset, size / NBL_BITS_IN_U8);
}

static void
nbl_tc_kt_mt_set_value(struct nbl_tc_at_item *at_item,
		       struct nbl_mt_input *mt_input,
		       struct nbl_select_input *select_input,
		       struct nbl_rule_action *action,
		       struct nbl_profile_msg *profile_msg,
		       const struct nbl_flow_idx_info *idx_info)
{
	at_item->act_collect.act_offset = select_input->act_offset;
	at_item->act_collect.act2_offset = select_input->act2_offset;
	mt_input->kt_left_num = profile_msg->act_count;
	if (idx_info->key_flag & NBL_FLOW_KEY_DIPV4_FLAG) {
		action->flag |= NBL_FLOW_ACTION_IPV4;
	} else if (idx_info->key_flag &
			NBL_FLOW_KEY_DIPV6_FLAG) {
		action->flag |= NBL_FLOW_ACTION_IPV6;
	}

	if (idx_info->key_flag & NBL_FLOW_KEY_T_VNI_FLAG)
		action->flag |= NBL_FLOW_ACTION_TUNNEL_DECAP;
}

static void
nbl_tc_node_at_set_value(struct nbl_tc_at_item *at_item,
			 struct nbl_flow_tab_filter *node,
			 struct nbl_edit_item *edit_item,
			 struct nbl_rule_action *action)
{
	memcpy(&node->act_collect, &at_item->act_collect,
	       sizeof(at_item->act_collect));
	memcpy(&node->edit_item, edit_item, sizeof(struct nbl_edit_item));
	if (node->edit_item.is_mir)
		list_replace_init(&edit_item->tc_mcc_list, &node->edit_item.tc_mcc_list);
	if (action->flag & NBL_FLOW_ACTION_INGRESS)
		node->edit_item.direct = NBL_ACT_INGRESS;
}

static int nbl_flow_tab_add(struct nbl_flow_tab_filter *node,
			    struct nbl_rule_action *action,
			    struct nbl_resource_mgt *res_mgt,
			    const struct nbl_flow_idx_info *idx_info,
			    struct nbl_mt_input *mt_input,
			    struct nbl_select_input *select_input)
{
	int ret = 0;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_profile_msg *profile_msg =
		&tc_flow_mgt->profile_msg[idx_info->profile_id];
	struct nbl_tc_ht_item ht_item;
	struct nbl_tc_kt_item kt_item;
	struct nbl_tc_at_item *at_item = NULL;
	struct nbl_edit_item edit_item;
	struct nbl_tcam_item tcam_item;

	memset(&ht_item, 0, sizeof(ht_item));
	memset(&kt_item, 0, sizeof(kt_item));
	memset(&edit_item, 0, sizeof(edit_item));
	memset(&tcam_item, 0, sizeof(tcam_item));

	nbl_tc_assign_key_for_hash(mt_input, node);

	mutex_lock(&tc_flow_mgt->flow_lock);
	if (mt_input->key_full) {
		tcam_item.key_mode = NBL_TC_KT_FULL_MODE;
		ret = nbl_tc_flow_alloc_bmp_id(select_input->pp_kt_bmp,
					       select_input->pp_kt_num,
					       tcam_item.key_mode, &node->tbl_id);
		if (ret) {
			mutex_unlock(&tc_flow_mgt->flow_lock);
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "tc flow failed to alloc id for full table, ret %d.\n", ret);
			return -ENOSPC;
		}
	} else {
		tcam_item.key_mode = NBL_TC_KT_HALF_MODE;
		ret = nbl_tc_flow_alloc_bmp_id(select_input->pp_kt_bmp,
					       select_input->pp_kt_num,
					       tcam_item.key_mode, &node->tbl_id);
		if (ret) {
			mutex_unlock(&tc_flow_mgt->flow_lock);
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "tc flow failed to alloc id for half table, ret %d.\n", ret);
			return -ENOSPC;
		}
	}

	mt_input->tbl_id = node->tbl_id + select_input->kt_idx_offset;
	tcam_item.pp_tcam_count = select_input->pp_tcam_count;
	ret = nbl_flow_ht_assign_proc(res_mgt, mt_input,
				      select_input->pp_ht0_mng,
				      select_input->pp_ht1_mng, &ht_item,
				      &tcam_item);
	mutex_unlock(&tc_flow_mgt->flow_lock);

	if (ret)
		goto ret_bitmap_fail;

	if (tcam_item.tcam_flag) {
		node->tcam_flag = tcam_item.tcam_flag;
		if (mt_input->key_full)
			memcpy(tcam_item.kt_data.data, node->key.key_value,
			       sizeof(node->key.key_value));
		else
			memcpy(tcam_item.kt_data.data,
			       &node->key.key_value[NBL_TABLE_KEY_DATA_LEN / 2],
			       sizeof(node->key.key_value) / 2);
	}
	memcpy(&node->ht_item, &ht_item, sizeof(ht_item));
	node->pp_type = select_input->pp_type;

	/* copy pure key from node to kt */
	nbl_tc_assign_kt_item(&kt_item, select_input, node, (bool)mt_input->key_full);

	at_item = kzalloc(sizeof(*at_item), GFP_KERNEL);
	if (!at_item) {
		ret = -ENOMEM;
		goto ret_bitmap_fail;
	}

	if (idx_info->last_stage) {
		nbl_tc_kt_mt_set_value(at_item, mt_input, select_input,
				       action, profile_msg, idx_info);

		ret = nbl_flow_insert_at(res_mgt, mt_input, action,
					 at_item, &edit_item, &tcam_item);
		if (ret)
			goto ret_fail;
		nbl_tc_node_at_set_value(at_item, node, &edit_item, action);
		nbl_tc_assign_acts_for_kt(common, at_item, kt_item.kt_data.data,
					  mt_input);
	} else {
		if (!tcam_item.tcam_flag)
			nbl_tc_assign_idx_act_for_kt(&kt_item, node);
		else
			nbl_tc_assign_idx_act_for_tcam(&tcam_item, node);
	}

	if (tcam_item.tcam_flag) {
		mutex_lock(&tc_flow_mgt->flow_lock);
		tcam_item.pp_type = select_input->pp_type;
		tcam_item.sw_hash_id = node->sw_hash_id;
		tcam_item.profile_id = idx_info->profile_id;
		ret = nbl_tc_flow_send_tcam_2hw(res_mgt, select_input->tcam_pp_key_mng,
						select_input->tcam_pp_ad_mng, &tcam_item);
		node->tcam_index = tcam_item.tcam_index;
		mutex_unlock(&tc_flow_mgt->flow_lock);
		goto ret_fail;
	}

	/* write flow KT AT using CMDQ */
	ret = nbl_cmdq_send_flow_ktat(&ht_item, &kt_item, at_item, res_mgt);

ret_fail:
	kfree(at_item);
ret_bitmap_fail:
	if (ret) {
		mutex_lock(&tc_flow_mgt->flow_lock);
		if (mt_input->key_full)
			nbl_tc_flow_free_bmp_id(select_input->pp_kt_bmp,
						node->tbl_id, NBL_TC_KT_FULL_MODE);
		else
			nbl_tc_flow_free_bmp_id(select_input->pp_kt_bmp,
						node->tbl_id, NBL_TC_KT_HALF_MODE);
		mutex_unlock(&tc_flow_mgt->flow_lock);
	}

	return ret;
}

static int nbl_flow_tab_del(struct nbl_flow_tab_filter *node, struct nbl_resource_mgt *res_mgt,
			    struct nbl_mt_input *mt_input, struct nbl_select_input *select_input)
{
	int ret = 0;
	struct nbl_tcam_item tcam_item;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	memset(&tcam_item, 0, sizeof(tcam_item));

	mutex_lock(&tc_flow_mgt->flow_lock);
	if (node->tcam_flag) {
		if (mt_input->key_full)
			tcam_item.key_mode = NBL_TC_KT_FULL_MODE;
		else
			tcam_item.key_mode = NBL_TC_KT_HALF_MODE;
		tcam_item.pp_type = select_input->pp_type;
		tcam_item.tcam_index = node->tcam_index;
		tcam_item.pp_tcam_count = select_input->pp_tcam_count;
		ret = nbl_flow_del_tcam_2hw(res_mgt, select_input->tcam_pp_key_mng,
					    select_input->tcam_pp_ad_mng, &tcam_item);
		if (!ret)
			goto ret_tcam_success;
		else
			goto ret_fail;
	}

	if (mt_input->key_full) {
		nbl_tc_flow_free_bmp_id(select_input->pp_kt_bmp,
					node->tbl_id, NBL_TC_KT_FULL_MODE);
	} else {
		nbl_tc_flow_free_bmp_id(select_input->pp_kt_bmp,
					node->tbl_id, NBL_TC_KT_HALF_MODE);
	}

	ret = nbl_flow_del_ht_2hw(&node->ht_item, node->pp_type,
				  select_input->pp_ht0_mng,
				  select_input->pp_ht1_mng,
				  res_mgt);
	if (ret)
		goto ret_fail;

	ret = nbl_flow_del_at_2hw(res_mgt, &node->act_collect, select_input->pp_type);
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow failed to del at 2hw, ret %d\n", ret);
		goto ret_fail;
	}

ret_tcam_success:
	if (node->edit_item.is_mir)
		nbl_tc_mcc_free_hw_tbl(tc_flow_mgt->res_mgt, &tc_flow_mgt->tc_mcc_mgt,
				       &node->edit_item.tc_mcc_list);

ret_fail:
	mutex_unlock(&tc_flow_mgt->flow_lock);
	return ret;
}

/* note that the key in node should not be modified */
static int nbl_flow_tab_ht_at(struct nbl_flow_tab_filter *node,
			      struct nbl_rule_action *action, u8 opcode,
			      struct nbl_resource_mgt *res_mgt,
			      const struct nbl_flow_idx_info *idx_info)
{
	int ret = 0;
	struct nbl_mt_input mt_input = { 0 };
	struct nbl_select_input select_input = { 0 };
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_profile_msg *profile_msg =
		&tc_flow_mgt->profile_msg[idx_info->profile_id];
	const struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	if (!node || !idx_info)
		return -EINVAL;

	mt_input.key_full = profile_msg->key_full;
	ret = nbl_tc_set_pp_related_value(&select_input, &mt_input, tc_flow_mgt,
					  idx_info->profile_id);
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow set pp failed, profile_id %u.\n",
			profile_msg->key_full);
		return ret;
	}

	if (opcode == NBL_OPCODE_ADD)
		ret = nbl_flow_tab_add(node, action, res_mgt, idx_info, &mt_input, &select_input);
	else if (opcode == NBL_OPCODE_DELETE)
		ret = nbl_flow_tab_del(node, res_mgt, &mt_input, &select_input);

	return ret;
}

static int nbl_flow_tbl_op(void *ptr, struct nbl_rule_action *action,
			   struct nbl_resource_mgt *res_mgt,
			   const struct nbl_flow_idx_info *idx_info,
			   __maybe_unused void *query_rslt, u8 opcode)
{
	struct nbl_flow_tab_filter *flow_tab_node = NULL;
	int ret = 0;
	const struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	if (opcode == NBL_OPCODE_ADD && !action) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow add failed as action is NULL.\n");
		return -EINVAL;
	}

	flow_tab_node = (struct nbl_flow_tab_filter *)ptr;
	ret = nbl_flow_tab_ht_at(flow_tab_node, action, opcode, res_mgt, idx_info);

	return ret;
}

static int nbl_off_flow_op(void *ptr, struct nbl_rule_action *act,
			   struct nbl_resource_mgt *res_mgt,
			   struct nbl_flow_idx_info *idx_info, u8 opcode,
			   void *query_rslt)
{
	int ret = 0;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	if (!ptr) {
		nbl_err(common, NBL_DEBUG_FLOW,
			"tc flow offload op failed, flow node is NULL. op:%u\n", opcode);
		return -EINVAL;
	}

	ret = nbl_flow_tbl_op(ptr, act, res_mgt, idx_info, query_rslt, opcode);

	return ret;
}

/**
 * @brief: offload flow add
 *
 * @param[in] ptr: flow tab node info
 * @param[in] act: act to add
 * @param[in] idx_info: some indx info
 * @return int : 0-success other-fail
 */
static int nbl_off_flow_add(void *ptr, struct nbl_rule_action *act,
			    struct nbl_resource_mgt *res_mgt,
			    struct nbl_flow_idx_info *idx_info)
{
	return nbl_off_flow_op(ptr, act, res_mgt, idx_info, NBL_OPCODE_ADD, NULL);
}

/**
 * @brief: offload flow del
 *
 * @param[in] ptr: flow tab node info
 * @param[in] idx_info: some indx info
 * @return int : 0-success other-fail
 */
static int nbl_off_flow_del(void *ptr, struct nbl_resource_mgt *res_mgt,
			    struct nbl_flow_idx_info *idx_info)
{
	return nbl_off_flow_op(ptr, NULL, res_mgt, idx_info, NBL_OPCODE_DELETE, NULL);
}

/**
 * @brief: offload flow query
 *
 * @param[in] ptr: flow tab node info
 * @param[in] idx: flow-id
 * @param[in] type: distinguish which key template to query
 * @param[out] query_rslt: when query use this param
 * @brief: offload flow
 * @return int : 0-success other-fail
 */
static int nbl_off_flow_query(void *ptr, u32 idx, void *query_rslt)
{
	struct nbl_flow_idx_info idx_inf = { 0 };

	idx_inf.flow_idx = idx;
	return nbl_off_flow_op(ptr, NULL, NULL, &idx_inf, NBL_OPCODE_QUERY,
			       query_rslt);
}

const struct nbl_flow_offload_ops nbl_flow_offload_ops = {
	.add = nbl_off_flow_add,
	.del = nbl_off_flow_del,
	.query = nbl_off_flow_query,
};
