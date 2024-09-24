// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_flow_leonis.h"
#include "nbl_p4_actions.h"

static u32 nbl_flow_cfg_action_set_dport(u16 upcall_flag, u16 port_type, u16 vsi, u16 next_stg_sel)
{
	union nbl_action_data set_dport = {.data = 0};

	set_dport.dport.up.upcall_flag = upcall_flag;
	set_dport.dport.up.port_type = port_type;
	set_dport.dport.up.port_id = vsi;
	set_dport.dport.up.next_stg_sel = next_stg_sel;

	return set_dport.data + (NBL_ACT_SET_DPORT << 16);
}

static u16 nbl_flow_cfg_action_set_dport_mcc_eth(u8 eth)
{
	union nbl_action_data set_dport = {.data = 0};

	set_dport.dport.down.upcall_flag = AUX_FWD_TYPE_NML_FWD;
	set_dport.dport.down.port_type = SET_DPORT_TYPE_ETH_LAG;
	set_dport.dport.down.next_stg_sel = NEXT_STG_SEL_EPRO;
	set_dport.dport.down.lag_vld = 0;
	set_dport.dport.down.eth_vld = 1;
	set_dport.dport.down.eth_id = eth;

	return set_dport.data;
}

static u16 nbl_flow_cfg_action_set_dport_mcc_vsi(u16 vsi)
{
	union nbl_action_data set_dport = {.data = 0};

	set_dport.dport.up.upcall_flag = AUX_FWD_TYPE_NML_FWD;
	set_dport.dport.up.port_type = SET_DPORT_TYPE_VSI_HOST;
	set_dport.dport.up.port_id = vsi;
	set_dport.dport.up.next_stg_sel = NEXT_STG_SEL_EPRO;

	return set_dport.data;
}

static int nbl_flow_cfg_action_mcc(u16 mcc_id, u32 *action0, u32 *action1)
{
	union nbl_action_data mcc_idx_act = {.data = 0}, set_aux_act = {.data = 0};

	mcc_idx_act.mcc_idx.mcc_id = mcc_id;
	*action0 = (u32)mcc_idx_act.data + (NBL_ACT_SET_MCC << 16);

	set_aux_act.set_aux.sub_id = NBL_SET_AUX_SET_AUX;
	set_aux_act.set_aux.nstg_vld = 1;
	set_aux_act.set_aux.nstg_val = NBL_NEXT_STG_MCC;
	*action1 = (u32)set_aux_act.data + (NBL_ACT_SET_AUX_FIELD << 16);

	return 0;
}

static int nbl_flow_cfg_action_up_tnl(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	*action1 = 0;
	*action0 = nbl_flow_cfg_action_set_dport(AUX_FWD_TYPE_NML_FWD, SET_DPORT_TYPE_VSI_HOST,
						 param.vsi, NEXT_STG_SEL_EPRO);

	return 0;
}

static int nbl_flow_cfg_action_lldp_lacp_up(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	*action1 = 0;
	*action0 = nbl_flow_cfg_action_set_dport(AUX_FWD_TYPE_NML_FWD, SET_DPORT_TYPE_VSI_HOST,
						 param.vsi, NEXT_STG_SEL_EPRO);

	return 0;
}

static int nbl_flow_cfg_action_up(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	*action1 = 0;
	*action0 = nbl_flow_cfg_action_set_dport(AUX_FWD_TYPE_NML_FWD, SET_DPORT_TYPE_VSI_HOST,
						 param.vsi, NEXT_STG_SEL_NONE);

	return 0;
}

static int nbl_flow_cfg_action_down(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	*action1 = 0;
	*action0 = nbl_flow_cfg_action_set_dport(AUX_FWD_TYPE_NML_FWD, SET_DPORT_TYPE_VSI_HOST,
						 param.vsi, NEXT_STG_SEL_EPRO);

	return 0;
}

static int nbl_flow_cfg_action_l2_up(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	return nbl_flow_cfg_action_mcc(param.mcc_id, action0, action1);
}

static int nbl_flow_cfg_action_l2_down(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	return nbl_flow_cfg_action_mcc(param.mcc_id, action0, action1);
}

static int nbl_flow_cfg_action_l3_up(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	return nbl_flow_cfg_action_mcc(param.mcc_id, action0, action1);
}

static int nbl_flow_cfg_action_l3_down(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	return nbl_flow_cfg_action_mcc(param.mcc_id, action0, action1);
}

static int nbl_flow_cfg_up_tnl_key_value(union nbl_common_data_u *data,
					 struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_l2_phy_up_data_u *kt_data = (union nbl_l2_phy_up_data_u *)data;
	u64 dst_mac = 0;
	u8 sport;
	u8 reverse_mac[ETH_ALEN];

	nbl_convert_mac(param.mac, reverse_mac);

	memset(kt_data->hash_key, 0x0, sizeof(kt_data->hash_key));
	ether_addr_copy((u8 *)&dst_mac, reverse_mac);

	kt_data->info.dst_mac = dst_mac;
	kt_data->info.svlan_id = param.vid;
	kt_data->info.template = NBL_EM0_PT_PHY_UP_TUNNEL_UNICAST_L2;
	kt_data->info.padding = 0;

	sport = param.eth;
	kt_data->info.sport = sport + NBL_SPORT_ETH_OFFSET;

	return 0;
}

static int nbl_flow_cfg_lldp_lacp_up_key_value(union nbl_common_data_u *data,
					       struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_l2_phy_lldp_lacp_data_u *kt_data = (union nbl_l2_phy_lldp_lacp_data_u *)data;
	u8 sport;

	kt_data->info.template = NBL_EM0_PT_PHY_UP_LLDP_LACP;

	kt_data->info.ether_type = param.ether_type;

	sport = param.eth;
	kt_data->info.sport = sport + NBL_SPORT_ETH_OFFSET;

	return 0;
}

static int nbl_flow_cfg_up_key_value(union nbl_common_data_u *data,
				     struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_l2_phy_up_data_u *kt_data = (union nbl_l2_phy_up_data_u *)data;
	u64 dst_mac = 0;
	u8 sport;
	u8 reverse_mac[ETH_ALEN];

	nbl_convert_mac(param.mac, reverse_mac);

	memset(kt_data->hash_key, 0x0, sizeof(kt_data->hash_key));
	ether_addr_copy((u8 *)&dst_mac, reverse_mac);

	kt_data->info.dst_mac = dst_mac;
	kt_data->info.svlan_id = param.vid;
	kt_data->info.template = NBL_EM0_PT_PHY_UP_UNICAST_L2;
	kt_data->info.padding = 0;

	sport = param.eth;
	kt_data->info.sport = sport + NBL_SPORT_ETH_OFFSET;

	return 0;
}

static int nbl_flow_cfg_down_key_value(union nbl_common_data_u *data,
				       struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_l2_phy_down_data_u *kt_data = (union nbl_l2_phy_down_data_u *)data;
	u64 dst_mac = 0;
	u8 sport;
	u8 reverse_mac[ETH_ALEN];

	nbl_convert_mac(param.mac, reverse_mac);

	memset(kt_data->hash_key, 0x0, sizeof(kt_data->hash_key));
	ether_addr_copy((u8 *)&dst_mac, reverse_mac);

	kt_data->info.dst_mac = dst_mac;
	kt_data->info.svlan_id = param.vid;
	kt_data->info.template = NBL_EM0_PT_PHY_DOWN_UNICAST_L2;
	kt_data->info.padding = 0;

	sport = param.vsi >> 8;
	if (eth_mode == NBL_TWO_ETHERNET_PORT)
		sport &= 0xFE;
	kt_data->info.sport = sport;

	return 0;
}

static int nbl_flow_cfg_l2_up_key_value(union nbl_common_data_u *data,
					struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_l2_phy_up_multi_data_u *kt_data = (union nbl_l2_phy_up_multi_data_u *)data;
	u8 sport;

	kt_data->info.dst_mac = 0xFFFFFFFFFFFF;
	kt_data->info.template = NBL_EM0_PT_PHY_UP_MULTICAST_L2;
	kt_data->info.padding = 0;

	sport = param.eth;
	kt_data->info.sport = sport + NBL_SPORT_ETH_OFFSET;

	return 0;
}

static int nbl_flow_cfg_l2_down_key_value(union nbl_common_data_u *data,
					  struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_l2_phy_down_multi_data_u *kt_data = (union nbl_l2_phy_down_multi_data_u *)data;
	u8 sport;

	kt_data->info.dst_mac = 0xFFFFFFFFFFFF;
	kt_data->info.template = NBL_EM0_PT_PHY_DOWN_MULTICAST_L2;
	kt_data->info.padding = 0;

	sport = param.eth;
	if (eth_mode == NBL_TWO_ETHERNET_PORT)
		sport &= 0xFE;
	kt_data->info.sport = sport;

	return 0;
}

static int nbl_flow_cfg_l3_up_key_value(union nbl_common_data_u *data,
					struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_l3_phy_up_multi_data_u *kt_data = (union nbl_l3_phy_up_multi_data_u *)data;
	u8 sport;

	kt_data->info.dst_mac = 0x3333;
	kt_data->info.template = NBL_EM0_PT_PHY_UP_MULTICAST_L3;
	kt_data->info.padding = 0;

	sport = param.eth;
	kt_data->info.sport = sport + NBL_SPORT_ETH_OFFSET;

	return 0;
}

static int nbl_flow_cfg_l3_down_key_value(union nbl_common_data_u *data,
					  struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_l3_phy_down_multi_data_u *kt_data = (union nbl_l3_phy_down_multi_data_u *)data;
	u8 sport;

	kt_data->info.dst_mac = 0x3333;
	kt_data->info.template = NBL_EM0_PT_PHY_DOWN_MULTICAST_L3;
	kt_data->info.padding = 0;

	sport = param.eth;
	if (eth_mode == NBL_TWO_ETHERNET_PORT)
		sport &= 0xFE;
	kt_data->info.sport = sport;

	return 0;
}

static void nbl_flow_cfg_kt_action_up_tnl(union nbl_common_data_u *data, u32 action0, u32 action1)
{
	union nbl_l2_phy_up_data_u *kt_data = (union nbl_l2_phy_up_data_u *)data;

	kt_data->info.act0 = action0;
}

static void nbl_flow_cfg_kt_action_lldp_lacp_up(union nbl_common_data_u *data,
						u32 action0, u32 action1)
{
	union nbl_l2_phy_lldp_lacp_data_u *kt_data = (union nbl_l2_phy_lldp_lacp_data_u *)data;

	kt_data->info.act0 = action0;
}

static void nbl_flow_cfg_kt_action_up(union nbl_common_data_u *data, u32 action0, u32 action1)
{
	union nbl_l2_phy_up_data_u *kt_data = (union nbl_l2_phy_up_data_u *)data;

	kt_data->info.act0 = action0;
}

static void nbl_flow_cfg_kt_action_down(union nbl_common_data_u *data, u32 action0, u32 action1)
{
	union nbl_l2_phy_down_data_u *kt_data = (union nbl_l2_phy_down_data_u *)data;

	kt_data->info.act0 = action0;
}

static void nbl_flow_cfg_kt_action_l2_up(union nbl_common_data_u *data, u32 action0, u32 action1)
{
	union nbl_l2_phy_up_multi_data_u *kt_data = (union nbl_l2_phy_up_multi_data_u *)data;

	kt_data->info.act0 = action0;
	kt_data->info.act1 = action1;
}

static void nbl_flow_cfg_kt_action_l2_down(union nbl_common_data_u *data, u32 action0, u32 action1)
{
	union nbl_l2_phy_down_multi_data_u *kt_data = (union nbl_l2_phy_down_multi_data_u *)data;

	kt_data->info.act0 = action0;
	kt_data->info.act1 = action1;
}

static void nbl_flow_cfg_kt_action_l3_up(union nbl_common_data_u *data, u32 action0, u32 action1)
{
	union nbl_l3_phy_up_multi_data_u *kt_data = (union nbl_l3_phy_up_multi_data_u *)data;

	kt_data->info.act0 = action0;
	kt_data->info.act1 = action1;
}

static void nbl_flow_cfg_kt_action_l3_down(union nbl_common_data_u *data, u32 action0, u32 action1)
{
	union nbl_l3_phy_down_multi_data_u *kt_data = (union nbl_l3_phy_down_multi_data_u *)data;

	kt_data->info.act0 = action0;
	kt_data->info.act1 = action1;
}

#define NBL_FLOW_OPS_ARR_ENTRY(type, action_func, kt_func, kt_action_func)		\
	[type] = {.cfg_action = action_func, .cfg_key = kt_func,			\
		  .cfg_kt_action = kt_action_func}
static const struct nbl_flow_rule_cfg_ops cfg_ops[] = {
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_UP_TNL,
			       nbl_flow_cfg_action_up_tnl,
			       nbl_flow_cfg_up_tnl_key_value,
			       nbl_flow_cfg_kt_action_up_tnl),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_LLDP_LACP_UP,
			       nbl_flow_cfg_action_lldp_lacp_up,
			       nbl_flow_cfg_lldp_lacp_up_key_value,
			       nbl_flow_cfg_kt_action_lldp_lacp_up),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_UP,
			       nbl_flow_cfg_action_up,
			       nbl_flow_cfg_up_key_value,
			       nbl_flow_cfg_kt_action_up),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_DOWN,
			       nbl_flow_cfg_action_down,
			       nbl_flow_cfg_down_key_value,
			       nbl_flow_cfg_kt_action_down),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_L2_UP,
			       nbl_flow_cfg_action_l2_up,
			       nbl_flow_cfg_l2_up_key_value,
			       nbl_flow_cfg_kt_action_l2_up),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_L2_DOWN,
			       nbl_flow_cfg_action_l2_down,
			       nbl_flow_cfg_l2_down_key_value,
			       nbl_flow_cfg_kt_action_l2_down),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_L3_UP,
			       nbl_flow_cfg_action_l3_up,
			       nbl_flow_cfg_l3_up_key_value,
			       nbl_flow_cfg_kt_action_l3_up),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_L3_DOWN,
			       nbl_flow_cfg_action_l3_down,
			       nbl_flow_cfg_l3_down_key_value,
			       nbl_flow_cfg_kt_action_l3_down),
};

static unsigned long find_two_zero_bit(const unsigned long *addr, unsigned long size)
{
	unsigned long flow_id, next_id;

	flow_id = find_first_zero_bit(addr, size);
	next_id = find_next_zero_bit(addr, size, flow_id + 1);
	while ((flow_id + 1) != next_id || (flow_id % 2)) {
		flow_id = next_id;
		next_id = find_next_zero_bit(addr, size, flow_id + 1);
		if (next_id == size)
			return size;
	}

	return flow_id;
}

static int nbl_flow_alloc_flow_id(struct nbl_flow_mgt *flow_mgt, struct nbl_flow_fem_entry *flow)
{
	u32 flow_id;

	if (flow->flow_type == NBL_KT_HALF_MODE) {
		flow_id = find_first_zero_bit(flow_mgt->flow_id, NBL_MACVLAN_TABLE_LEN);
		if (flow_id == NBL_MACVLAN_TABLE_LEN)
			return -ENOSPC;
		set_bit(flow_id, flow_mgt->flow_id);
	} else {
		flow_id = find_two_zero_bit(flow_mgt->flow_id, NBL_MACVLAN_TABLE_LEN);
		if (flow_id == NBL_MACVLAN_TABLE_LEN)
			return -ENOSPC;
		set_bit(flow_id, flow_mgt->flow_id);
		set_bit(flow_id + 1, flow_mgt->flow_id);
	}

	flow->flow_id = flow_id;
	return 0;
}

static void nbl_flow_free_flow_id(struct nbl_flow_mgt *flow_mgt, struct nbl_flow_fem_entry *flow)
{
	if (flow->flow_id == U16_MAX)
		return;

	if (flow->flow_type == NBL_KT_HALF_MODE) {
		clear_bit(flow->flow_id, flow_mgt->flow_id);
		flow->flow_id = 0xFFFF;
	} else {
		clear_bit(flow->flow_id, flow_mgt->flow_id);
		clear_bit(flow->flow_id + 1, flow_mgt->flow_id);
		flow->flow_id = 0xFFFF;
	}
}

static int nbl_flow_alloc_tcam_id(struct nbl_flow_mgt *flow_mgt,
				  struct nbl_tcam_item *tcam_item)
{
	u32 tcam_id;

	tcam_id = find_first_zero_bit(flow_mgt->tcam_id, NBL_TCAM_TABLE_LEN);
	if (tcam_id == NBL_TCAM_TABLE_LEN)
		return -ENOSPC;

	set_bit(tcam_id, flow_mgt->tcam_id);
	tcam_item->tcam_index = tcam_id;

	return 0;
}

static void nbl_flow_free_tcam_id(struct nbl_flow_mgt *flow_mgt,
				  struct nbl_tcam_item *tcam_item)
{
	clear_bit(tcam_item->tcam_index, flow_mgt->tcam_id);
	tcam_item->tcam_index = 0;
}

void nbl_flow_set_mt_input(struct nbl_mt_input *mt_input, union nbl_common_data_u *kt_data,
			   u8 type, u16 flow_id)
{
	int i;
	u16 key_len;

	key_len = ((type) == NBL_KT_HALF_MODE ? NBL_KT_BYTE_HALF_LEN :	NBL_KT_BYTE_LEN);
	for (i = 0; i < key_len; i++)
		mt_input->key[i] = kt_data->hash_key[key_len - 1 - i];

	mt_input->tbl_id = flow_id + NBL_EM_PHY_KT_OFFSET;
	mt_input->depth = 0;
	mt_input->power = 10;
}

static void nbl_flow_key_hash(struct nbl_flow_fem_entry *flow, struct nbl_mt_input *mt_input)
{
	u16 ht0_hash = 0;
	u16 ht1_hash = 0;

	ht0_hash = NBL_CRC16_CCITT(mt_input->key, NBL_KT_BYTE_LEN);
	ht1_hash = NBL_CRC16_IBM(mt_input->key, NBL_KT_BYTE_LEN);
	flow->ht0_hash = nbl_hash_transfer(ht0_hash, mt_input->power, mt_input->depth);
	flow->ht1_hash = nbl_hash_transfer(ht1_hash, mt_input->power, mt_input->depth);
}

static bool nbl_pp_ht0_ht1_search(struct nbl_flow_ht_mng *pp_ht0_mng, u16 ht0_hash,
				  struct nbl_flow_ht_mng *pp_ht1_mng, u16 ht1_hash,
				  struct nbl_common_info *common)
{
	struct nbl_flow_ht_tbl *node0 = NULL;
	struct nbl_flow_ht_tbl *node1 = NULL;
	u16 i = 0;
	bool is_find = false;

	node0 = pp_ht0_mng->hash_map[ht0_hash];
	if (node0)
		for (i = 0; i < NBL_HASH_CFT_MAX; i++)
			if (node0->key[i].vid && node0->key[i].ht_other_index == ht1_hash) {
				is_find = true;
				nbl_info(common, NBL_DEBUG_FLOW,
					 "Conflicted ht on vid %d and kt_index %u\n",
					 node0->key[i].vid, node0->key[i].kt_index);
				return is_find;
			}

	node1 = pp_ht1_mng->hash_map[ht1_hash];
	if (node1)
		for (i = 0; i < NBL_HASH_CFT_MAX; i++)
			if (node1->key[i].vid && node1->key[i].ht_other_index == ht0_hash) {
				is_find = true;
				nbl_info(common, NBL_DEBUG_FLOW,
					 "Conflicted ht on vid %d and kt_index %u\n",
					 node1->key[i].vid, node1->key[i].kt_index);
				return is_find;
			}

	return is_find;
}

static bool nbl_flow_check_ht_conflict(struct nbl_flow_ht_mng *pp_ht0_mng,
				       struct nbl_flow_ht_mng *pp_ht1_mng,
				       u16 ht0_hash, u16 ht1_hash, struct nbl_common_info *common)
{
	return nbl_pp_ht0_ht1_search(pp_ht0_mng, ht0_hash, pp_ht1_mng, ht1_hash, common);
}

static int nbl_flow_find_ht_avail_table(struct nbl_flow_ht_mng *pp_ht0_mng,
					struct nbl_flow_ht_mng *pp_ht1_mng,
					u16 ht0_hash, u16 ht1_hash)
{
	struct nbl_flow_ht_tbl *pp_ht0_node = NULL;
	struct nbl_flow_ht_tbl *pp_ht1_node = NULL;

	pp_ht0_node = pp_ht0_mng->hash_map[ht0_hash];
	pp_ht1_node = pp_ht1_mng->hash_map[ht1_hash];

	if (!pp_ht0_node && !pp_ht1_node) {
		return 0;
	} else if (pp_ht0_node && !pp_ht1_node) {
		if (pp_ht0_node->ref_cnt >= NBL_HASH_CFT_AVL)
			return 1;
		else
			return 0;
	} else if (!pp_ht0_node && pp_ht1_node) {
		if (pp_ht1_node->ref_cnt >= NBL_HASH_CFT_AVL)
			return 0;
		else
			return 1;
	} else {
		if ((pp_ht0_node->ref_cnt <= NBL_HASH_CFT_AVL ||
		     (pp_ht0_node->ref_cnt > NBL_HASH_CFT_AVL &&
		      pp_ht0_node->ref_cnt < NBL_HASH_CFT_MAX &&
		      pp_ht1_node->ref_cnt > NBL_HASH_CFT_AVL)))
			return 0;
		else if (((pp_ht0_node->ref_cnt > NBL_HASH_CFT_AVL &&
			   pp_ht1_node->ref_cnt <= NBL_HASH_CFT_AVL) ||
			  (pp_ht0_node->ref_cnt == NBL_HASH_CFT_MAX &&
			   pp_ht1_node->ref_cnt > NBL_HASH_CFT_AVL &&
			   pp_ht1_node->ref_cnt < NBL_HASH_CFT_MAX)))
			return 1;
		else
			return -1;
	}
}

int nbl_flow_insert_pp_ht(struct nbl_flow_ht_mng *pp_ht_mng,
			  u16 hash, u16 hash_other, u32 key_index)
{
	struct nbl_flow_ht_tbl *node;
	int i;

	node = pp_ht_mng->hash_map[hash];
	if (!node) {
		node = kzalloc(sizeof(*node), GFP_KERNEL);
		if (!node)
			return -ENOSPC;
		pp_ht_mng->hash_map[hash] = node;
	}

	for (i = 0; i < NBL_HASH_CFT_MAX; i++) {
		if (node->key[i].vid == 0) {
			node->key[i].vid = 1;
			node->key[i].ht_other_index = hash_other;
			node->key[i].kt_index = key_index;
			node->ref_cnt++;
			break;
		}
	}

	return i;
}

static void nbl_flow_add_ht(struct nbl_ht_item *ht_item, struct nbl_flow_fem_entry *flow,
			    u32 key_index, struct nbl_flow_ht_mng *pp_ht_mng, u8 ht_table)
{
	u16 ht_hash;
	u16 ht_other_hash;

	ht_hash = ht_table == NBL_HT0 ? flow->ht0_hash : flow->ht1_hash;
	ht_other_hash = ht_table == NBL_HT0 ? flow->ht1_hash : flow->ht0_hash;

	ht_item->hash_bucket = nbl_flow_insert_pp_ht(pp_ht_mng, ht_hash, ht_other_hash, key_index);
	if (ht_item->hash_bucket < 0)
		return;

	ht_item->ht_table = ht_table;
	ht_item->key_index = key_index;
	ht_item->ht0_hash = flow->ht0_hash;
	ht_item->ht1_hash = flow->ht1_hash;

	flow->hash_bucket = ht_item->hash_bucket;
	flow->hash_table = ht_item->ht_table;
}

static void nbl_flow_del_ht(struct nbl_ht_item *ht_item, struct nbl_flow_fem_entry *flow,
			    struct nbl_flow_ht_mng *pp_ht_mng)
{
	struct nbl_flow_ht_tbl *pp_ht_node = NULL;
	u16 ht_hash;
	u16 ht_other_hash;
	int i;

	ht_hash = ht_item->ht_table == NBL_HT0 ? flow->ht0_hash : flow->ht1_hash;
	ht_other_hash = ht_item->ht_table == NBL_HT0 ? flow->ht1_hash : flow->ht0_hash;

	pp_ht_node = pp_ht_mng->hash_map[ht_hash];
	if (!pp_ht_node)
		return;

	for (i = 0; i < NBL_HASH_CFT_MAX; i++) {
		if (pp_ht_node->key[i].vid == 1 &&
		    pp_ht_node->key[i].ht_other_index == ht_other_hash) {
			memset(&pp_ht_node->key[i], 0, sizeof(pp_ht_node->key[i]));
			pp_ht_node->ref_cnt--;
			break;
		}
	}

	if (!pp_ht_node->ref_cnt) {
		kfree(pp_ht_node);
		pp_ht_mng->hash_map[ht_hash] = NULL;
	}
}

static int nbl_flow_send_2hw(struct nbl_resource_mgt *res_mgt, struct nbl_ht_item ht_item,
			     struct nbl_kt_item kt_item, u8 key_type)
{
	struct nbl_phy_ops *phy_ops;
	u16 hash, hash_other;
	int ret = 0;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	ret = phy_ops->set_kt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), kt_item.kt_data.hash_key,
			      ht_item.key_index, key_type);
	if (ret)
		goto set_kt_fail;

	hash = ht_item.ht_table == NBL_HT0 ? ht_item.ht0_hash : ht_item.ht1_hash;
	hash_other = ht_item.ht_table == NBL_HT0 ? ht_item.ht1_hash : ht_item.ht0_hash;
	ret = phy_ops->set_ht(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), hash, hash_other, ht_item.ht_table,
			      ht_item.hash_bucket, ht_item.key_index, 1);
	if (ret)
		goto set_ht_fail;

	ret = phy_ops->search_key(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				  kt_item.kt_data.hash_key, key_type);
	if (ret)
		goto search_fail;

	return 0;

search_fail:
	ret = phy_ops->set_ht(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), hash, 0, ht_item.ht_table,
			      ht_item.hash_bucket, 0, 0);
set_ht_fail:
	memset(kt_item.kt_data.hash_key, 0, sizeof(kt_item.kt_data.hash_key));
	phy_ops->set_kt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), kt_item.kt_data.hash_key,
			ht_item.key_index, key_type);
set_kt_fail:
	return ret;
}

static int nbl_flow_del_2hw(struct nbl_resource_mgt *res_mgt, struct nbl_ht_item ht_item,
			    struct nbl_kt_item kt_item, u8 key_type)
{
	struct nbl_phy_ops *phy_ops;
	u16 hash;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	memset(kt_item.kt_data.hash_key, 0, sizeof(kt_item.kt_data.hash_key));
	phy_ops->set_kt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), kt_item.kt_data.hash_key,
			ht_item.key_index, key_type);

	hash = ht_item.ht_table == NBL_HT0 ? ht_item.ht0_hash : ht_item.ht1_hash;
	phy_ops->set_ht(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), hash, 0, ht_item.ht_table,
			ht_item.hash_bucket, 0, 0);

	return 0;
}

static void nbl_flow_cfg_tcam(struct nbl_tcam_item *tcam_item, struct nbl_ht_item *ht_item,
			      struct nbl_kt_item *kt_item, u32 action0, u32 action1)
{
	tcam_item->key_mode = NBL_KT_HALF_MODE;
	tcam_item->pp_type = NBL_PT_PP0;
	tcam_item->tcam_action[0] = action0;
	tcam_item->tcam_action[1] = action1;
	memcpy(&tcam_item->ht_item, ht_item, sizeof(struct nbl_ht_item));
	memcpy(&tcam_item->kt_item, kt_item, sizeof(struct nbl_kt_item));
}

static int nbl_flow_add_tcam(struct nbl_resource_mgt *res_mgt, struct nbl_tcam_item tcam_item)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->add_tcam(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), tcam_item.tcam_index,
				 tcam_item.kt_item.kt_data.hash_key, tcam_item.tcam_action,
				 tcam_item.key_mode, NBL_PT_PP0);
}

static void nbl_flow_del_tcam(struct nbl_resource_mgt *res_mgt, struct nbl_tcam_item tcam_item)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->del_tcam(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), tcam_item.tcam_index,
			  tcam_item.key_mode, NBL_PT_PP0);
}

static int nbl_flow_add_flow(struct nbl_resource_mgt *res_mgt, struct nbl_flow_param param,
			     s32 type, struct nbl_flow_fem_entry *flow)
{
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_phy_ops *phy_ops;
	struct nbl_common_info *common;
	struct nbl_mt_input mt_input;
	struct nbl_ht_item ht_item;
	struct nbl_kt_item kt_item;
	struct nbl_tcam_item tcam_item;
	struct nbl_flow_ht_mng *pp_ht_mng = NULL;
	u32 action0, action1;
	int ht_table;
	int ret = 0;

	memset(&mt_input, 0, sizeof(mt_input));
	memset(&ht_item, 0, sizeof(ht_item));
	memset(&kt_item, 0, sizeof(kt_item));
	memset(&tcam_item, 0, sizeof(tcam_item));

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	common = NBL_RES_MGT_TO_COMMON(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	flow->flow_type = param.type;
	flow->type = type;
	flow->flow_id = 0xFFFF;

	ret = nbl_flow_alloc_flow_id(flow_mgt, flow);
	if (ret)
		return ret;

	ret = cfg_ops[type].cfg_action(param, &action0, &action1);
	if (ret)
		return ret;

	ret = cfg_ops[type].cfg_key(&kt_item.kt_data, param, NBL_COMMON_TO_ETH_MODE(common));
	if (ret)
		return ret;

	nbl_flow_set_mt_input(&mt_input, &kt_item.kt_data, param.type, flow->flow_id);
	nbl_flow_key_hash(flow, &mt_input);

	if (nbl_flow_check_ht_conflict(&flow_mgt->pp0_ht0_mng, &flow_mgt->pp0_ht1_mng,
				       flow->ht0_hash, flow->ht1_hash, common))
		flow->tcam_flag = true;

	ht_table = nbl_flow_find_ht_avail_table(&flow_mgt->pp0_ht0_mng,
						&flow_mgt->pp0_ht1_mng,
						flow->ht0_hash, flow->ht1_hash);
	if (ht_table < 0)
		flow->tcam_flag = true;

	if (!flow->tcam_flag) {
		pp_ht_mng = ht_table == NBL_HT0 ? &flow_mgt->pp0_ht0_mng : &flow_mgt->pp0_ht1_mng;
		nbl_flow_add_ht(&ht_item, flow, mt_input.tbl_id, pp_ht_mng, ht_table);

		cfg_ops[type].cfg_kt_action(&kt_item.kt_data, action0, action1);
		ret = nbl_flow_send_2hw(res_mgt, ht_item, kt_item, param.type);
	} else {
		ret = nbl_flow_alloc_tcam_id(flow_mgt, &tcam_item);
		if (ret)
			goto out;

		nbl_flow_cfg_tcam(&tcam_item, &ht_item, &kt_item, action0, action1);
		flow->tcam_index = tcam_item.tcam_index;

		ret = nbl_flow_add_tcam(res_mgt, tcam_item);
	}

out:
	if (ret) {
		if (flow->tcam_flag)
			nbl_flow_free_tcam_id(flow_mgt, &tcam_item);
		else
			nbl_flow_del_ht(&ht_item, flow, pp_ht_mng);

		nbl_flow_free_flow_id(flow_mgt, flow);
	}

	return ret;
}

static void nbl_flow_del_flow(struct nbl_resource_mgt *res_mgt, struct nbl_flow_fem_entry *flow)
{
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_phy_ops *phy_ops;
	struct nbl_ht_item ht_item;
	struct nbl_kt_item kt_item;
	struct nbl_tcam_item tcam_item;
	struct nbl_flow_ht_mng *pp_ht_mng = NULL;

	if (flow->flow_id == 0xFFFF)
		return;

	memset(&ht_item, 0, sizeof(ht_item));
	memset(&kt_item, 0, sizeof(kt_item));
	memset(&tcam_item, 0, sizeof(tcam_item));

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	if (!flow->tcam_flag) {
		ht_item.ht_table = flow->hash_table;
		ht_item.ht0_hash = flow->ht0_hash;
		ht_item.ht1_hash = flow->ht1_hash;
		ht_item.hash_bucket = flow->hash_bucket;

		pp_ht_mng = flow->hash_table == NBL_HT0 ? &flow_mgt->pp0_ht0_mng
							: &flow_mgt->pp0_ht1_mng;

		nbl_flow_del_ht(&ht_item, flow, pp_ht_mng);
		nbl_flow_del_2hw(res_mgt, ht_item, kt_item, flow->flow_type);
	} else {
		tcam_item.tcam_index = flow->tcam_index;
		nbl_flow_del_tcam(res_mgt, tcam_item);
		nbl_flow_free_tcam_id(flow_mgt, &tcam_item);
	}

	nbl_flow_free_flow_id(flow_mgt, flow);
}

static int nbl_flow_add_mcc_node(struct nbl_flow_multi_group *multi_group,
				 struct nbl_resource_mgt *res_mgt, int eth, u16 vsi_id, u16 mcc_id)
{
	struct nbl_flow_mcc_node *mcc_node = NULL;
	struct nbl_phy_ops *phy_ops;
	u16 prev_mcc_id, mcc_action;
	int ret = 0;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	mcc_node = kzalloc(sizeof(*mcc_node), GFP_KERNEL);
	if (!mcc_node)
		return -ENOMEM;

	mcc_action = eth >= 0 ? nbl_flow_cfg_action_set_dport_mcc_eth((u8)eth)
			      : nbl_flow_cfg_action_set_dport_mcc_vsi(vsi_id);
	mcc_node->mcc_id = mcc_id;
	list_add_tail(&mcc_node->node, &multi_group->mcc_list);

	if (nbl_list_is_first(&mcc_node->node, &multi_group->mcc_list))
		prev_mcc_id = NBL_MCC_ID_INVALID;
	else
		prev_mcc_id = list_prev_entry(mcc_node, node)->mcc_id;

	ret = phy_ops->add_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mcc_id, prev_mcc_id, mcc_action);
	if (ret) {
		list_del(&mcc_node->node);
		kfree(mcc_node);
		return -EFAULT;
	}

	return 0;
}

static void nbl_flow_del_mcc_node(struct nbl_flow_multi_group *multi_group,
				  struct nbl_resource_mgt *res_mgt,
				  struct nbl_flow_mcc_node *mcc_node)
{
	struct nbl_phy_ops *phy_ops;
	u16 prev_mcc_id, next_mcc_id;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	if (list_entry_is_head(mcc_node, &multi_group->mcc_list, node))
		return;

	if (nbl_list_is_first(&mcc_node->node, &multi_group->mcc_list))
		prev_mcc_id = NBL_MCC_ID_INVALID;
	else
		prev_mcc_id = list_prev_entry(mcc_node, node)->mcc_id;

	if (nbl_list_is_last(&mcc_node->node, &multi_group->mcc_list))
		next_mcc_id = NBL_MCC_ID_INVALID;
	else
		next_mcc_id = list_next_entry(mcc_node, node)->mcc_id;

	phy_ops->del_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mcc_node->mcc_id,
			 prev_mcc_id, next_mcc_id);

	list_del(&mcc_node->node);
	kfree(mcc_node);
}

static void nbl_flow_macvlan_node_del_action_func(void *priv, void *x_key, void *y_key,
						  void *data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_macvlan_node_data *rule_data = (struct nbl_flow_macvlan_node_data *)data;
	int i;

	for (i = 0; i < NBL_FLOW_MACVLAN_MAX; i++)
		nbl_flow_del_flow(res_mgt, &rule_data->entry[i]);
}

static int nbl_flow_add_macvlan(void *priv, u8 *mac, u16 vlan, u16 vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_common_info *common;
	struct nbl_flow_macvlan_node_data *rule_data;
	void *mac_hash_tbl;
	struct nbl_flow_param param = {0};
	int i;
	int ret;
	u16 eth_id;
	u16 node_num;

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	common = NBL_RES_MGT_TO_COMMON(res_mgt);

	eth_id = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);
	mac_hash_tbl = flow_mgt->mac_hash_tbl[eth_id];
	node_num = nbl_common_get_hash_xy_node_num(mac_hash_tbl);
	if (node_num >= flow_mgt->unicast_mac_threshold)
		return -ENOSPC;

	if (nbl_common_get_hash_xy_node(mac_hash_tbl, mac, &vlan))
		return -EEXIST;

	rule_data = kzalloc(sizeof(*rule_data), GFP_KERNEL);
	if (!rule_data)
		return -ENOMEM;

	param.mac = mac;
	param.vid = vlan;
	param.eth = eth_id;
	param.vsi = vsi;

	for (i = 0; i < NBL_FLOW_MACVLAN_MAX; i++) {
		if (nbl_flow_add_flow(res_mgt, param, i, &rule_data->entry[i]))
			break;
	}
	if (i != NBL_FLOW_MACVLAN_MAX) {
		while (--i + 1)
			nbl_flow_del_flow(res_mgt, &rule_data->entry[i]);
		goto rule_err;
	}

	rule_data->vsi = vsi;
	ret = nbl_common_alloc_hash_xy_node(mac_hash_tbl, mac, &vlan, rule_data);
	if (ret)
		goto node_err;

	kfree(rule_data);

	return 0;

node_err:
	for (i = 0; i < NBL_FLOW_MACVLAN_MAX; i++)
		nbl_flow_del_flow(res_mgt, &rule_data->entry[i]);
rule_err:
	kfree(rule_data);
	return -EFAULT;
}

static void nbl_flow_del_macvlan(void *priv, u8 *mac, u16 vlan, u16 vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_flow_macvlan_node_data *rule_data;
	void *mac_hash_tbl;
	int i;
	u16 eth_id;

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	eth_id = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);
	mac_hash_tbl = flow_mgt->mac_hash_tbl[eth_id];

	rule_data = nbl_common_get_hash_xy_node(mac_hash_tbl, mac, &vlan);
	if (!rule_data)
		return;

	if (rule_data->vsi != vsi)
		return;

	for (i = 0; i < NBL_FLOW_MACVLAN_MAX; i++)
		nbl_flow_del_flow(res_mgt, &rule_data->entry[i]);

	nbl_common_free_hash_xy_node(mac_hash_tbl, mac, &vlan);
}

static int nbl_flow_add_lag(void *priv, u16 vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_lacp_rule *rule;
	struct nbl_flow_param param = {0};

	list_for_each_entry(rule, &flow_mgt->lacp_list, node)
		if (rule->vsi == vsi)
			return 0;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;

	param.eth = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);
	param.vsi = vsi;
	param.ether_type = ETH_P_SLOW;

	if (nbl_flow_add_flow(res_mgt, param, NBL_FLOW_LLDP_LACP_UP, &rule->entry)) {
		nbl_err(common, NBL_DEBUG_FLOW, "Fail to add lag flow for vsi %d", vsi);
		kfree(rule);
		return -EFAULT;
	}

	rule->vsi = vsi;
	list_add_tail(&rule->node, &flow_mgt->lacp_list);

	return 0;
}

static void nbl_flow_del_lag(void *priv, u16 vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_flow_lacp_rule *rule;

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);

	list_for_each_entry(rule, &flow_mgt->lacp_list, node)
		if (rule->vsi == vsi)
			break;

	if (list_entry_is_head(rule, &flow_mgt->lacp_list, node))
		return;

	nbl_flow_del_flow(res_mgt, &rule->entry);

	list_del(&rule->node);
	kfree(rule);
}

static int nbl_flow_add_lldp(void *priv, u16 vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_lldp_rule *rule;
	struct nbl_flow_param param = {0};

	list_for_each_entry(rule, &flow_mgt->lldp_list, node)
		if (rule->vsi == vsi)
			return 0;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;

	param.eth = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);
	param.vsi = vsi;
	param.ether_type = ETH_P_LLDP;

	if (nbl_flow_add_flow(res_mgt, param, NBL_FLOW_LLDP_LACP_UP, &rule->entry)) {
		nbl_err(common, NBL_DEBUG_FLOW, "Fail to add lldp flow for vsi %d", vsi);
		kfree(rule);
		return -EFAULT;
	}

	rule->vsi = vsi;
	list_add_tail(&rule->node, &flow_mgt->lldp_list);

	return 0;
}

static void nbl_flow_del_lldp(void *priv, u16 vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_flow_lldp_rule *rule;

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);

	list_for_each_entry(rule, &flow_mgt->lldp_list, node)
		if (rule->vsi == vsi)
			break;

	if (list_entry_is_head(rule, &flow_mgt->lldp_list, node))
		return;

	nbl_flow_del_flow(res_mgt, &rule->entry);

	list_del(&rule->node);
	kfree(rule);
}

static int nbl_flow_add_multi_rule(void *priv, u16 vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_multi_group *multi_group;
	struct nbl_flow_mcc_index_key index_key = {0};
	u16 mcc_id;
	u8 eth = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);

	NBL_FLOW_MCC_INDEX_KEY_INIT(&index_key, NBL_MCC_INDEX_VSI, vsi);
	mcc_id = nbl_common_get_index(flow_mgt->mcc_tbl_priv, &index_key, sizeof(index_key));

	multi_group = &flow_mgt->multi_flow[eth];

	return nbl_flow_add_mcc_node(multi_group, res_mgt, -1, vsi, mcc_id);
}

static void nbl_flow_del_multi_rule(void *priv, u16 vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_multi_group *multi_group;
	struct nbl_flow_mcc_node *mcc_node;
	struct nbl_flow_mcc_index_key index_key = {0};
	u8 eth = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);
	u16 mcc_id;

	NBL_FLOW_MCC_INDEX_KEY_INIT(&index_key, NBL_MCC_INDEX_VSI, vsi);
	mcc_id = nbl_common_get_index(flow_mgt->mcc_tbl_priv, &index_key, sizeof(index_key));
	nbl_common_free_index(flow_mgt->mcc_tbl_priv, &index_key, sizeof(index_key));

	multi_group = &flow_mgt->multi_flow[eth];

	list_for_each_entry(mcc_node, &multi_group->mcc_list, node)
		if (mcc_node->mcc_id == mcc_id) {
			nbl_flow_del_mcc_node(multi_group, res_mgt, mcc_node);
			return;
		}
}

static int nbl_flow_add_multi_group(struct nbl_resource_mgt *res_mgt, u8 eth)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_multi_group *multi_group;
	struct nbl_flow_mcc_index_key index_key = {0};
	struct nbl_flow_param param = {0};
	int i, ret;

	NBL_FLOW_MCC_INDEX_KEY_INIT(&index_key, NBL_MCC_INDEX_ETH, eth);
	param.mcc_id = nbl_common_get_index(flow_mgt->mcc_tbl_priv, &index_key, sizeof(index_key));
	param.eth = eth;

	multi_group = &flow_mgt->multi_flow[eth];
	for (i = NBL_FLOW_MACVLAN_MAX; i < NBL_FLOW_TYPE_MAX; i++) {
		ret = nbl_flow_add_flow(res_mgt, param, i,
					&multi_group->entry[i - NBL_FLOW_MACVLAN_MAX]);
		if (ret)
			goto add_macvlan_fail;
	}

	ret = nbl_flow_add_mcc_node(multi_group, res_mgt, eth, -1, param.mcc_id);
	if (ret)
		goto add_mcc_fail;

	multi_group->ether_id = eth;
	multi_group->mcc_id = param.mcc_id;

	return 0;

add_mcc_fail:
add_macvlan_fail:
	while (--i >= NBL_FLOW_MACVLAN_MAX)
		nbl_flow_del_flow(res_mgt, &multi_group->entry[i - NBL_FLOW_MACVLAN_MAX]);
	return ret;
}

static void nbl_flow_del_multi_group(struct nbl_resource_mgt *res_mgt, u8 eth)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_multi_group *multi_group = &flow_mgt->multi_flow[eth];
	struct nbl_flow_mcc_node *mcc_node, *mcc_node_safe;
	int i;

	if (!multi_group->mcc_id)
		return;

	for (i = NBL_FLOW_MACVLAN_MAX; i < NBL_FLOW_TYPE_MAX; i++)
		nbl_flow_del_flow(res_mgt, &multi_group->entry[i - NBL_FLOW_MACVLAN_MAX]);

	list_for_each_entry_safe(mcc_node, mcc_node_safe, &multi_group->mcc_list, node)
		nbl_flow_del_mcc_node(multi_group, res_mgt, mcc_node);

	memset(multi_group, 0, sizeof(*multi_group));
	INIT_LIST_HEAD(&multi_group->mcc_list);
}

static void nbl_flow_remove_multi_group(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	int i;

	for_each_set_bit(i, eth_info->eth_bitmap, NBL_MAX_ETHERNET)
		nbl_flow_del_multi_group(res_mgt, i);
}

static int nbl_flow_setup_multi_group(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	int i, ret = 0;

	for_each_set_bit(i, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		ret = nbl_flow_add_multi_group(res_mgt, i);
		if (ret)
			goto fail;
	}

	return 0;

fail:
	nbl_flow_remove_multi_group(res_mgt);
	return ret;
}

static int nbl_flow_macvlan_node_vsi_match_func(void *condition, void *x_key, void *y_key,
						void *data)
{
	u16 vsi = *(u16 *)condition;
	struct nbl_flow_macvlan_node_data *rule_data = (struct nbl_flow_macvlan_node_data *)data;

	return rule_data->vsi == vsi ? 0 : -1;
}

static void nbl_flow_clear_flow(void *priv, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	void *mac_hash_tbl;
	struct nbl_hash_xy_tbl_scan_key scan_key;
	u8 eth_id;

	eth_id = nbl_res_vsi_id_to_eth_id(res_mgt, vsi_id);
	mac_hash_tbl = flow_mgt->mac_hash_tbl[eth_id];

	NBL_HASH_XY_TBL_SCAN_KEY_INIT(&scan_key, NBL_HASH_TBL_OP_DELETE, NBL_HASH_TBL_ALL_SCAN,
				      false, NULL, NULL, &vsi_id,
				      &nbl_flow_macvlan_node_vsi_match_func, res_mgt,
				      &nbl_flow_macvlan_node_del_action_func);
	nbl_common_scan_hash_xy_node(mac_hash_tbl, &scan_key);

	nbl_flow_del_multi_rule(res_mgt, vsi_id);
}

char templete_name[NBL_FLOW_TYPE_MAX][16] = {
	"up_tnl",
	"up",
	"down",
	"l2_mc_up",
	"l2_mc_down",
	"l3_mc_up",
	"l3_mc_down"
};

static void nbl_flow_id_dump(struct seq_file *m, struct nbl_flow_fem_entry *entry, char *title)
{
	seq_printf(m, "%s: flow_id %u, ht0 0x%x, ht1 0x%x, table: %u, bucket: %u\n", title,
		   entry->flow_id, entry->ht0_hash, entry->ht1_hash,
		   entry->hash_table, entry->hash_bucket);
}

static void nbl_flow_macvlan_node_show_action_func(void *priv, void *x_key, void *y_key,
						   void *data)
{
	struct seq_file *m = (struct seq_file *)priv;
	u8 *mac = (u8 *)x_key;
	u16 vlan = *(u16 *)y_key;
	struct nbl_flow_macvlan_node_data *rule_data = (struct nbl_flow_macvlan_node_data *)data;
	int i;

	seq_printf(m, "\nvsi %d, vlan %d MAC address %02X:%02X:%02X:%02X:%02X:%02X\n",
		   rule_data->vsi, vlan, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	for (i = 0; i < NBL_FLOW_MACVLAN_MAX; i++)
		nbl_flow_id_dump(m, &rule_data->entry[i], templete_name[i]);
}

static void nbl_flow_dump_flow(void *priv, struct seq_file *m)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_flow_multi_group *multi_group;
	struct nbl_flow_lldp_rule *lldp_rule;
	struct nbl_flow_lacp_rule *lacp_rule;
	struct nbl_hash_xy_tbl_scan_key scan_key;
	int i, j;

	for_each_set_bit(i, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		multi_group = &flow_mgt->multi_flow[i];
		seq_printf(m, "\nether_id %d, mcc_id %d, status %u\n" + !i,
			   multi_group->ether_id, multi_group->mcc_id, multi_group->network_status);
		for (j = NBL_FLOW_MACVLAN_MAX; j < NBL_FLOW_TYPE_MAX; j++)
			nbl_flow_id_dump(m, &multi_group->entry[j - NBL_FLOW_MACVLAN_MAX],
					 templete_name[j]);
	}

	NBL_HASH_XY_TBL_SCAN_KEY_INIT(&scan_key, NBL_HASH_TBL_OP_SHOW, NBL_HASH_TBL_ALL_SCAN,
				      false, NULL, NULL, NULL, NULL, m,
				      &nbl_flow_macvlan_node_show_action_func);
	for (i = 0; i < NBL_MAX_ETHERNET; i++)
		nbl_common_scan_hash_xy_node(flow_mgt->mac_hash_tbl[i], &scan_key);

	seq_puts(m, "\n");

	list_for_each_entry(lldp_rule, &flow_mgt->lldp_list, node)
		seq_printf(m, "LLDP rule: vsi %d\n", lldp_rule->vsi);

	seq_puts(m, "\n");
	list_for_each_entry(lacp_rule, &flow_mgt->lacp_list, node)
		seq_printf(m, "LACP rule: vsi %d\n", lacp_rule->vsi);
}

/* NBL_FLOW_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_FLOW_OPS_TBL								\
do {											\
	NBL_FLOW_SET_OPS(add_macvlan, nbl_flow_add_macvlan);				\
	NBL_FLOW_SET_OPS(del_macvlan, nbl_flow_del_macvlan);				\
	NBL_FLOW_SET_OPS(add_lag_flow, nbl_flow_add_lag);				\
	NBL_FLOW_SET_OPS(del_lag_flow, nbl_flow_del_lag);				\
	NBL_FLOW_SET_OPS(add_lldp_flow, nbl_flow_add_lldp);				\
	NBL_FLOW_SET_OPS(del_lldp_flow, nbl_flow_del_lldp);				\
	NBL_FLOW_SET_OPS(add_multi_rule, nbl_flow_add_multi_rule);			\
	NBL_FLOW_SET_OPS(del_multi_rule, nbl_flow_del_multi_rule);			\
	NBL_FLOW_SET_OPS(setup_multi_group, nbl_flow_setup_multi_group);		\
	NBL_FLOW_SET_OPS(remove_multi_group, nbl_flow_remove_multi_group);		\
	NBL_FLOW_SET_OPS(clear_flow, nbl_flow_clear_flow);				\
	NBL_FLOW_SET_OPS(dump_flow, nbl_flow_dump_flow);				\
} while (0)

static void nbl_flow_remove_mgt(struct device *dev, struct nbl_resource_mgt *res_mgt)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	int i;
	struct nbl_hash_xy_tbl_del_key del_key;

	nbl_common_remove_index_table(flow_mgt->mcc_tbl_priv);

	NBL_HASH_XY_TBL_DEL_KEY_INIT(&del_key, res_mgt, &nbl_flow_macvlan_node_del_action_func);
	for (i = 0; i < NBL_MAX_ETHERNET; i++)
		nbl_common_remove_hash_xy_table(flow_mgt->mac_hash_tbl[i], &del_key);

	devm_kfree(dev, flow_mgt);
	NBL_RES_MGT_TO_FLOW_MGT(res_mgt) = NULL;
}

static int nbl_flow_setup_mgt(struct device *dev, struct nbl_resource_mgt *res_mgt)
{
	struct nbl_index_tbl_key mcc_tbl_key;
	struct nbl_hash_xy_tbl_key macvlan_tbl_key;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_eth_info *eth_info;
	int i;

	flow_mgt = devm_kzalloc(dev, sizeof(struct nbl_flow_mgt), GFP_KERNEL);
	if (!flow_mgt)
		return -ENOMEM;

	NBL_RES_MGT_TO_FLOW_MGT(res_mgt) = flow_mgt;

	NBL_INDEX_TBL_KEY_INIT(&mcc_tbl_key, dev, NBL_FLOW_MCC_INDEX_START,
			       NBL_FLOW_MCC_INDEX_SIZE, sizeof(struct nbl_flow_mcc_index_key));
	flow_mgt->mcc_tbl_priv = nbl_common_init_index_table(&mcc_tbl_key);
	if (!flow_mgt->mcc_tbl_priv)
		goto alloc_mcc_tbl_failed;

	NBL_HASH_XY_TBL_KEY_INIT(&macvlan_tbl_key, dev, ETH_ALEN, sizeof(u16),
				 sizeof(struct nbl_flow_macvlan_node_data),
				 NBL_MACVLAN_TBL_BUCKET_SIZE, NBL_MACVLAN_X_AXIS_BUCKET_SIZE,
				 NBL_MACVLAN_Y_AXIS_BUCKET_SIZE, false);
	for (i = 0; i < NBL_MAX_ETHERNET; i++) {
		(flow_mgt)->mac_hash_tbl[i] = nbl_common_init_hash_xy_table(&macvlan_tbl_key);
		if (!flow_mgt->mac_hash_tbl[i])
			goto alloc_machash_fail;
	}

	for (i = 0; i < NBL_MAX_ETHERNET; i++)
		INIT_LIST_HEAD(&flow_mgt->multi_flow[i].mcc_list);

	INIT_LIST_HEAD(&flow_mgt->lldp_list);
	INIT_LIST_HEAD(&flow_mgt->lacp_list);

	eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	flow_mgt->unicast_mac_threshold = NBL_TOTAL_MACVLAN_NUM / eth_info->eth_num;

	return 0;

alloc_machash_fail:
alloc_mcc_tbl_failed:
	nbl_flow_remove_mgt(dev, res_mgt);
	return -1;
}

int nbl_flow_mgt_start_leonis(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_phy_ops *phy_ops;
	struct device *dev;
	int ret = 0;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	ret = nbl_flow_setup_mgt(dev, res_mgt);
	if (ret)
		goto setup_mgt_fail;

	ret = phy_ops->init_fem(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	if (ret)
		goto init_fem_fail;

	return 0;

init_fem_fail:
	nbl_flow_remove_mgt(dev, res_mgt);
setup_mgt_fail:
	return -1;
}

void nbl_flow_mgt_stop_leonis(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_flow_mgt *flow_mgt;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	if (!flow_mgt)
		return;

	nbl_flow_remove_mgt(dev, res_mgt);
}

int nbl_flow_setup_ops_leonis(struct nbl_resource_ops *res_ops)
{
#define NBL_FLOW_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_FLOW_OPS_TBL;
#undef  NBL_FLOW_SET_OPS

	return 0;
}

void nbl_flow_remove_ops_leonis(struct nbl_resource_ops *res_ops)
{
#define NBL_FLOW_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = NULL; ; } while (0)
	NBL_FLOW_OPS_TBL;
#undef  NBL_FLOW_SET_OPS
}
