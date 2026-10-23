// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_flow_leonis.h"
#include "nbl_p4_actions.h"
#include "nbl_resource_leonis.h"

#define NBL_FLOW_LEONIS_VSI_NUM_PER_ETH		256

static bool nbl_flow_is_mirror_outputport(struct nbl_resource_mgt *res_mgt, u16 vsi_id)
{
	u16 func_id;
	int i;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);

	func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	if (func_id == U16_MAX)
		return false;

	for (i = 0; i < NBL_MIRROR_OUTPUTPORT_MAX_FUNC; i++) {
		if (func_id == flow_mgt->mirror_outputport_func[i])
			return true;
	}

	return false;
}

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

	set_dport.dport.up.upcall_flag = AUX_FWD_TYPE_UPCALL;
	set_dport.dport.up.port_type = SET_DPORT_TYPE_VSI_HOST;
	set_dport.dport.up.port_id = vsi;
	set_dport.dport.up.next_stg_sel = NEXT_STG_SEL_ACL_S0;

	return set_dport.data;
}

static u32 nbl_flow_cfg_action_set_dport_mcc_bmc(void)
{
	union nbl_action_data set_dport = {.data = 0};

	set_dport.dport.up.upcall_flag = AUX_FWD_TYPE_NML_FWD;
	set_dport.dport.up.port_type = SET_DPORT_TYPE_SP_PORT;
	set_dport.dport.up.port_id = NBL_FLOW_MCC_BMC_DPORT;
	set_dport.dport.up.next_stg_sel = NEXT_STG_SEL_EPRO;

	return set_dport.data + (NBL_ACT_SET_DPORT << 16);
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
	if (param.mcc_id == NBL_MCC_ID_INVALID)
		*action0 = nbl_flow_cfg_action_set_dport(AUX_FWD_TYPE_UPCALL,
							 SET_DPORT_TYPE_VSI_HOST,
							 param.vsi, NEXT_STG_SEL_ACL_S0);
	else
		nbl_flow_cfg_action_mcc(param.mcc_id, action0, action1);

	return 0;
}

static int nbl_flow_cfg_action_lldp_lacp_up(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	*action1 = 0;
	*action0 = nbl_flow_cfg_action_set_dport(AUX_FWD_TYPE_UPCALL, SET_DPORT_TYPE_VSI_HOST,
						 param.vsi, NEXT_STG_SEL_ACL_S0);

	return 0;
}

static int nbl_flow_cfg_action_up(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	*action1 = 0;
	if (param.mcc_id == NBL_MCC_ID_INVALID)
		*action0 = nbl_flow_cfg_action_set_dport(AUX_FWD_TYPE_UPCALL,
							 SET_DPORT_TYPE_VSI_HOST,
							 param.vsi, NEXT_STG_SEL_NONE);
	else
		nbl_flow_cfg_action_mcc(param.mcc_id, action0, action1);

	return 0;
}

static int nbl_flow_cfg_action_down(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	*action1 = 0;
	if (param.mcc_id == NBL_MCC_ID_INVALID)
		*action0 = nbl_flow_cfg_action_set_dport(AUX_FWD_TYPE_NML_FWD,
							 SET_DPORT_TYPE_VSI_HOST,
							 param.vsi, NEXT_STG_SEL_ACL_S0);
	else
		nbl_flow_cfg_action_mcc(param.mcc_id, action0, action1);

	return 0;
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
	kt_data->info.template = NBL_EM0_PT_PHY_UP_TUNNEL_L2;
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
	kt_data->info.template = NBL_EM0_PT_PHY_UP_L2;
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
	kt_data->info.template = NBL_EM0_PT_PHY_DOWN_L2;
	kt_data->info.padding = 0;

	sport = param.vsi >> 8;
	if (eth_mode == NBL_TWO_ETHERNET_PORT)
		sport &= 0xFE;
	if (eth_mode == NBL_ONE_ETHERNET_PORT)
		sport = 0;
	kt_data->info.sport = sport;

	return 0;
}

static void nbl_flow_cfg_kt_action_up_tnl(union nbl_common_data_u *data, u32 action0, u32 action1)
{
	union nbl_l2_phy_up_data_u *kt_data = (union nbl_l2_phy_up_data_u *)data;

	kt_data->info.act0 = action0;
	kt_data->info.act1 = action1;
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
	kt_data->info.act1 = action1;
}

static void nbl_flow_cfg_kt_action_down(union nbl_common_data_u *data, u32 action0, u32 action1)
{
	union nbl_l2_phy_down_data_u *kt_data = (union nbl_l2_phy_down_data_u *)data;

	kt_data->info.act0 = action0;
	kt_data->info.act1 = action1;
}

static int nbl_flow_cfg_action_tls_up(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	union nbl_action_data set_prbac_idx = {.data = 0};

	set_prbac_idx.prbac_idx.prbac_id = (u16)param.index;

	*action0 = set_prbac_idx.data + (NBL_ACT_SET_PRBAC << 16);

	return 0;
}

static int nbl_flow_cfg_tls_up_key_value(union nbl_common_data_u *data,
					 struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_phy_ul4s_data_u *kt_data = (union nbl_phy_ul4s_data_u *)data;
	u16 sport, dport;

	sport = param.eth + NBL_SPORT_ETH_OFFSET;
	dport = (0x2 << 10) + param.vsi;

	if (param.type == NBL_KT_HALF_MODE) {
		kt_data->ipv4_info.template = nbl_em0_pt_phy_ul4s_ipv4;
		kt_data->ipv4_info.sip_high = param.data[1] >> 4;
		kt_data->ipv4_info.sip_low = param.data[1];
		kt_data->ipv4_info.dip_high = param.data[5] >> 4;
		kt_data->ipv4_info.dip_low = param.data[5];
		kt_data->ipv4_info.l4_sport = param.data[9];
		kt_data->ipv4_info.l4_dport = param.data[10];
		kt_data->ipv4_info.sport = sport;
	} else {
		kt_data->ipv6_info.template = nbl_em0_pt_phy_ul4s_ipv6;
		kt_data->ipv6_info.sip1 = ((u64)param.data[1] << 28) + (param.data[2] >> 4);
		kt_data->ipv6_info.sip2 = ((u64)param.data[2] << 60) +
					  ((u64)param.data[3] << 28) + (param.data[4] >> 4);
		kt_data->ipv6_info.sip3 = param.data[4];
		kt_data->ipv6_info.l4_sport = param.data[9];
		kt_data->ipv6_info.l4_dport = param.data[10];
		kt_data->ipv6_info.dport = dport;
		kt_data->ipv6_info.sport = sport;
	}

	return 0;
}

static void nbl_flow_cfg_kt_action_tls_up(union nbl_common_data_u *data, u32 action0, u32 action1)
{
	union nbl_phy_ul4s_data_u *kt_data = (union nbl_phy_ul4s_data_u *)data;

	kt_data->ipv4_info.act0 = action0;
}

static int nbl_flow_cfg_action_ipsec_down(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	union nbl_action_data set_prbac_idx = {.data = 0};

	set_prbac_idx.prbac_idx.prbac_id = (u16)param.index;

	*action0 = set_prbac_idx.data + (NBL_ACT_SET_PRBAC << 16);

	return 0;
}

static int nbl_flow_cfg_ipsec_down_key_value(union nbl_common_data_u *data,
					     struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_phy_dprbac_data_u *kt_data = (union nbl_phy_dprbac_data_u *)data;
	u16 sport;

	sport = param.eth;
	if (param.type == NBL_KT_HALF_MODE) {
		kt_data->ipv4_info.template = NBL_EM0_PT_PHY_DPRBAC_IPV4;
		kt_data->ipv4_info.sip_high = param.data[1] >> 4;
		kt_data->ipv4_info.sip_low = param.data[1];
		kt_data->ipv4_info.dip_high = param.data[5] >> 4;
		kt_data->ipv4_info.dip_low = param.data[5];
		kt_data->ipv4_info.sport = sport;
	} else {
		kt_data->ipv6_info.template = NBL_EM0_PT_PHY_DPRBAC_IPV6;
		kt_data->ipv6_info.sip1 = (param.data[1] >> 4);
		kt_data->ipv6_info.sip2 = ((u64)param.data[1] << 60) + ((u64)param.data[2] << 28) +
					  (param.data[3] >> 4);
		kt_data->ipv6_info.sip3 = ((u64)param.data[3] << 32) + param.data[4];
		kt_data->ipv6_info.dip1 = (param.data[5] >> 4);
		kt_data->ipv6_info.dip2 = ((u64)param.data[5] << 60) + ((u64)param.data[6] << 28) +
					  (param.data[7] >> 4);
		kt_data->ipv6_info.dip3 = ((u64)param.data[7] << 32) + param.data[8];
		kt_data->ipv6_info.sport = sport;
	}

	return 0;
}

static void nbl_flow_cfg_kt_action_ipsec_down(union nbl_common_data_u *data,
					      u32 action0, u32 action1)
{
	union nbl_phy_dprbac_data_u *kt_data = (union nbl_phy_dprbac_data_u *)data;

	kt_data->ipv4_info.act0 = action0;
}

static int nbl_flow_cfg_action_nd_upcall(struct nbl_flow_param param,
					 u32 *action0, u32 *action1)
{
	*action1 = 0;

	/* For TC, jump to ACL, the upcall action will be overwritten;
	 * For PMD, upcall and jump to EPRO, skipping ACL
	 */
	if (param.for_pmd)
		*action0 = nbl_flow_cfg_action_set_dport(AUX_FWD_TYPE_UPCALL,
							 SET_DPORT_TYPE_VSI_HOST,
							 param.vsi, NEXT_STG_SEL_EPRO);
	else
		*action0 = nbl_flow_cfg_action_set_dport(AUX_FWD_TYPE_UPCALL,
							 SET_DPORT_TYPE_VSI_HOST,
							 param.vsi, NEXT_STG_SEL_ACL_S0);
	return 0;
}

static int nbl_flow_cfg_nd_upcall_key_value(union nbl_common_data_u *data,
					    struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_nd_upcall_data_u *kt_data = (union nbl_nd_upcall_data_u *)data;

	kt_data->info.template = NBL_EM0_PT_PMD_ND_UPCALL;
	kt_data->info.ptype = param.priv_data;

	return 0;
}

static void nbl_flow_cfg_kt_action_nd_upcall(union nbl_common_data_u *data,
					     u32 action0, u32 action1)
{
	union nbl_nd_upcall_data_u *kt_data = (union nbl_nd_upcall_data_u *)data;

	kt_data->info.act0 = action0;
	kt_data->info.act1 = action1;
}

static int nbl_flow_cfg_action_ecn_count(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	union nbl_action_data flow_idx = {.data = 0};

	flow_idx.flow_idx.flow_id = NBL_FLOW_IDX_MAX_FLOW_ID - param.eth;
	*action0 = flow_idx.data + (NBL_ACT_SET_FLOW_STAT1 << 16);
	*action1 = 0;

	return 0;
}

static int nbl_flow_cfg_ecn_count_key_value(union nbl_common_data_u *data,
					    struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_ecn_count_data_u *kt_data = (union nbl_ecn_count_data_u *)data;
	u8 sport;

	kt_data->info.template = NBL_EM1_PT_PHY_ECN_COUNT;
	kt_data->info.ecn = NBL_EM1_PT_PHY_ECN;

	sport = param.eth;
	kt_data->info.sport = sport + NBL_SPORT_ETH_OFFSET;

	return 0;
}

static void nbl_flow_cfg_kt_action_ecn_count(union nbl_common_data_u *data,
					     u32 action0, u32 action1)
{
	union nbl_l2_phy_lldp_lacp_data_u *kt_data = (union nbl_l2_phy_lldp_lacp_data_u *)data;

	kt_data->info.act0 = action0;
}

static int nbl_flow_cfg_action_multi_mcast(struct nbl_flow_param param, u32 *action0, u32 *action1)
{
	return nbl_flow_cfg_action_mcc(param.mcc_id, action0, action1);
}

static int nbl_flow_cfg_l2up_multi_mcast_key_value(union nbl_common_data_u *data,
						   struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_l2_phy_up_multi_mcast_data_u *kt_data =
				(union nbl_l2_phy_up_multi_mcast_data_u *)data;
	u8 sport;

	kt_data->info.template = NBL_EM0_PT_PHY_L2_UP_MULTI_MCAST;

	sport = param.eth;
	kt_data->info.sport = sport + NBL_SPORT_ETH_OFFSET;

	return 0;
}

static void nbl_flow_cfg_kt_action_l2up_multi_mcast(union nbl_common_data_u *data,
						    u32 action0, u32 action1)
{
	union nbl_l2_phy_up_multi_mcast_data_u *kt_data =
				(union nbl_l2_phy_up_multi_mcast_data_u *)data;

	kt_data->info.act0 = action0;
}

static int nbl_flow_cfg_l3up_multi_mcast_key_value(union nbl_common_data_u *data,
						   struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_l2_phy_up_multi_mcast_data_u *kt_data =
				(union nbl_l2_phy_up_multi_mcast_data_u *)data;
	u8 sport;

	kt_data->info.template = NBL_EM0_PT_PHY_L3_UP_MULTI_MCAST;

	sport = param.eth;
	kt_data->info.sport = sport + NBL_SPORT_ETH_OFFSET;

	return 0;
}

static int nbl_flow_cfg_l2down_multi_mcast_key_value(union nbl_common_data_u *data,
						     struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_l2_phy_down_multi_mcast_data_u *kt_data =
				(union nbl_l2_phy_down_multi_mcast_data_u *)data;
	u8 sport;

	kt_data->info.template = NBL_EM0_PT_PHY_L2_DOWN_MULTI_MCAST;

	sport = param.eth;
	kt_data->info.sport = sport + NBL_SPORT_ETH_OFFSET;

	return 0;
}

static void nbl_flow_cfg_kt_action_l2down_multi_mcast(union nbl_common_data_u *data,
						      u32 action0, u32 action1)
{
	union nbl_l2_phy_down_multi_mcast_data_u *kt_data =
				(union nbl_l2_phy_down_multi_mcast_data_u *)data;

	kt_data->info.act0 = action0;
}

static int nbl_flow_cfg_l3down_multi_mcast_key_value(union nbl_common_data_u *data,
						     struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_l2_phy_down_multi_mcast_data_u *kt_data =
				(union nbl_l2_phy_down_multi_mcast_data_u *)data;
	u8 sport;

	kt_data->info.template = NBL_EM0_PT_PHY_L3_DOWN_MULTI_MCAST;

	sport = param.eth;
	kt_data->info.sport = sport + NBL_SPORT_ETH_OFFSET;

	return 0;
}

#define NBL_FLOW_OPS_ARR_ENTRY(type, action_func, kt_func, kt_action_func)		\
	[type] = {.cfg_action = action_func, .cfg_key = kt_func,			\
		  .cfg_kt_action = kt_action_func}
static const struct nbl_flow_rule_cfg_ops cfg_ops[] = {
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_UP_TNL,
			       nbl_flow_cfg_action_up_tnl,
			       nbl_flow_cfg_up_tnl_key_value,
			       nbl_flow_cfg_kt_action_up_tnl),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_UP,
			       nbl_flow_cfg_action_up,
			       nbl_flow_cfg_up_key_value,
			       nbl_flow_cfg_kt_action_up),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_DOWN,
			       nbl_flow_cfg_action_down,
			       nbl_flow_cfg_down_key_value,
			       nbl_flow_cfg_kt_action_down),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_LLDP_LACP_UP,
			       nbl_flow_cfg_action_lldp_lacp_up,
			       nbl_flow_cfg_lldp_lacp_up_key_value,
			       nbl_flow_cfg_kt_action_lldp_lacp_up),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_L2_UP_MULTI_MCAST,
			       nbl_flow_cfg_action_multi_mcast,
			       nbl_flow_cfg_l2up_multi_mcast_key_value,
			       nbl_flow_cfg_kt_action_l2up_multi_mcast),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_L3_UP_MULTI_MCAST,
			       nbl_flow_cfg_action_multi_mcast,
			       nbl_flow_cfg_l3up_multi_mcast_key_value,
			       nbl_flow_cfg_kt_action_l2up_multi_mcast),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_PMD_ND_UPCALL,
			       nbl_flow_cfg_action_nd_upcall,
			       nbl_flow_cfg_nd_upcall_key_value,
			       nbl_flow_cfg_kt_action_nd_upcall),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_TLS_UP,
			       nbl_flow_cfg_action_tls_up,
			       nbl_flow_cfg_tls_up_key_value,
			       nbl_flow_cfg_kt_action_tls_up),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_IPSEC_DOWN,
			       nbl_flow_cfg_action_ipsec_down,
			       nbl_flow_cfg_ipsec_down_key_value,
			       nbl_flow_cfg_kt_action_ipsec_down),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_L2_DOWN_MULTI_MCAST,
			       nbl_flow_cfg_action_multi_mcast,
			       nbl_flow_cfg_l2down_multi_mcast_key_value,
			       nbl_flow_cfg_kt_action_l2down_multi_mcast),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_L3_DOWN_MULTI_MCAST,
			       nbl_flow_cfg_action_multi_mcast,
			       nbl_flow_cfg_l3down_multi_mcast_key_value,
			       nbl_flow_cfg_kt_action_l2down_multi_mcast),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_FLOW_ECN_COUNT,
			       nbl_flow_cfg_action_ecn_count,
			       nbl_flow_cfg_ecn_count_key_value,
			       nbl_flow_cfg_kt_action_ecn_count),
};

static int nbl_flow_alloc_flow_id(struct nbl_flow_mgt *flow_mgt, struct nbl_flow_fem_entry *flow)
{
	u32 flow_id;

	if (flow->flow_type == NBL_KT_HALF_MODE) {
		flow_id = find_first_zero_bit(flow_mgt->flow_id_bitmap, NBL_MACVLAN_TABLE_LEN);
		if (flow_id == NBL_MACVLAN_TABLE_LEN)
			return -ENOSPC;
		set_bit(flow_id, flow_mgt->flow_id_bitmap);
		flow_mgt->flow_id_cnt--;
	} else {
		flow_id = nbl_common_find_available_idx(flow_mgt->flow_id_bitmap,
							NBL_MACVLAN_TABLE_LEN, 2, 2);
		if (flow_id == NBL_MACVLAN_TABLE_LEN)
			return -ENOSPC;
		set_bit(flow_id, flow_mgt->flow_id_bitmap);
		set_bit(flow_id + 1, flow_mgt->flow_id_bitmap);
		flow_mgt->flow_id_cnt -= 2;
	}

	flow->flow_id = flow_id;
	return 0;
}

static void nbl_flow_free_flow_id(struct nbl_flow_mgt *flow_mgt, struct nbl_flow_fem_entry *flow)
{
	if (flow->flow_id == U16_MAX)
		return;

	if (flow->flow_type == NBL_KT_HALF_MODE) {
		clear_bit(flow->flow_id, flow_mgt->flow_id_bitmap);
		flow->flow_id = 0xFFFF;
		flow_mgt->flow_id_cnt++;
	} else {
		clear_bit(flow->flow_id, flow_mgt->flow_id_bitmap);
		clear_bit(flow->flow_id + 1, flow_mgt->flow_id_bitmap);
		flow->flow_id = 0xFFFF;
		flow_mgt->flow_id_cnt += 2;
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

static int nbl_flow_alloc_mcc_id(struct nbl_flow_mgt *flow_mgt)
{
	u32 mcc_id;

	mcc_id = find_first_zero_bit(flow_mgt->mcc_id_bitmap, NBL_FLOW_MCC_INDEX_SIZE);
	if (mcc_id == NBL_FLOW_MCC_INDEX_SIZE)
		return -ENOSPC;

	set_bit(mcc_id, flow_mgt->mcc_id_bitmap);

	return mcc_id + NBL_FLOW_MCC_INDEX_START;
}

static void nbl_flow_free_mcc_id(struct nbl_flow_mgt *flow_mgt, u32 mcc_id)
{
	if (mcc_id >= NBL_FLOW_MCC_INDEX_START)
		clear_bit(mcc_id - NBL_FLOW_MCC_INDEX_START, flow_mgt->mcc_id_bitmap);
}

static void nbl_flow_set_mt_input(struct nbl_mt_input *mt_input, union nbl_common_data_u *kt_data,
				  u8 type, u16 flow_id)
{
	int i;
	u16 key_len;

	key_len = ((type) == NBL_KT_HALF_MODE ? NBL_KT_BYTE_HALF_LEN :	NBL_KT_BYTE_LEN);
	for (i = 0; i < key_len; i++)
		mt_input->key[i] = kt_data->hash_key[key_len - 1 - i];

	mt_input->tbl_id = flow_id + NBL_EM_PHY_KT_OFFSET;
	mt_input->depth = 0;
	mt_input->power = NBL_PP0_POWER;
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
				nbl_debug(common, NBL_DEBUG_FLOW,
					  "Conflicted ht on vid %d and kt_index %u\n",
					  node0->key[i].vid, node0->key[i].kt_index);
				return is_find;
			}

	node1 = pp_ht1_mng->hash_map[ht1_hash];
	if (node1)
		for (i = 0; i < NBL_HASH_CFT_MAX; i++)
			if (node1->key[i].vid && node1->key[i].ht_other_index == ht0_hash) {
				is_find = true;
				nbl_debug(common, NBL_DEBUG_FLOW,
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

static int nbl_flow_insert_pp_ht(struct nbl_flow_ht_mng *pp_ht_mng,
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

	hash = ht_item.ht_table == NBL_HT0 ? ht_item.ht0_hash : ht_item.ht1_hash;
	phy_ops->set_ht(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), hash, 0, ht_item.ht_table,
			ht_item.hash_bucket, 0, 0);

	return 0;
}

static void nbl_flow_cfg_tcam(struct nbl_tcam_item *tcam_item, struct nbl_ht_item *ht_item,
			      struct nbl_kt_item *kt_item, u32 action0, u32 action1, u8 pp_type)
{
	tcam_item->key_mode = NBL_KT_HALF_MODE;
	tcam_item->pp_type = pp_type;
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
				 tcam_item.key_mode, tcam_item.pp_type);
}

static void nbl_flow_del_tcam(struct nbl_resource_mgt *res_mgt, struct nbl_tcam_item tcam_item)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->del_tcam(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), tcam_item.tcam_index,
			  tcam_item.key_mode, tcam_item.pp_type);
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
	struct nbl_tcam_item *tcam_item = NULL;
	struct nbl_flow_ht_mng *pp_ht_mng = NULL;
	u32 action0, action1;
	u32 cost = 0;
	int ht_table;
	int ret = 0;

	memset(&mt_input, 0, sizeof(mt_input));
	memset(&ht_item, 0, sizeof(ht_item));
	memset(&kt_item, 0, sizeof(kt_item));

	tcam_item = kzalloc(sizeof(*tcam_item), GFP_ATOMIC);
	if (!tcam_item)
		return -ENOMEM;

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	common = NBL_RES_MGT_TO_COMMON(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	flow->flow_type = param.type;
	flow->type = type;
	flow->flow_id = 0xFFFF;

	if (type >= NBL_FLOW_ACCEL_BEGIN && type < NBL_FLOW_ACCEL_END) {
		if (flow->flow_type == NBL_KT_FULL_MODE)
			cost = 2;
		else
			cost = 1;

		if ((flow_mgt->accel_flow_count + cost) > NBL_MACVLAN_TABLE_LEN / 2) {
			ret = -ENOSPC;
			goto free_mem;
		}
	}

	ret = nbl_flow_alloc_flow_id(flow_mgt, flow);
	if (ret)
		goto free_mem;

	ret = cfg_ops[type].cfg_action(param, &action0, &action1);
	if (ret)
		goto free_mem;

	ret = cfg_ops[type].cfg_key(&kt_item.kt_data, param, NBL_COMMON_TO_ETH_MODE(common));
	if (ret)
		goto free_mem;

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
		ret = nbl_flow_alloc_tcam_id(flow_mgt, tcam_item);
		if (ret)
			goto out;

		nbl_flow_cfg_tcam(tcam_item, &ht_item, &kt_item, action0, action1, NBL_PT_PP0);
		flow->tcam_index = tcam_item->tcam_index;

		ret = nbl_flow_add_tcam(res_mgt, *tcam_item);
	}

out:
	if (ret) {
		if (flow->tcam_flag)
			nbl_flow_free_tcam_id(flow_mgt, tcam_item);
		else
			nbl_flow_del_ht(&ht_item, flow, pp_ht_mng);

		nbl_flow_free_flow_id(flow_mgt, flow);
	} else {
		flow_mgt->accel_flow_count += cost;
	}

free_mem:
	kfree(tcam_item);

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
		tcam_item.pp_type = NBL_PT_PP0;
		nbl_flow_del_tcam(res_mgt, tcam_item);
		nbl_flow_free_tcam_id(flow_mgt, &tcam_item);
	}

	nbl_flow_free_flow_id(flow_mgt, flow);

	if (flow->type >= NBL_FLOW_ACCEL_BEGIN && flow->type < NBL_FLOW_ACCEL_END) {
		if (flow->flow_type == NBL_KT_FULL_MODE)
			flow_mgt->accel_flow_count -= 2;
		else
			flow_mgt->accel_flow_count -= 1;
	}
}

static struct nbl_flow_mcc_node *nbl_flow_alloc_mcc_node(struct nbl_flow_mgt *flow_mgt,
							 u8 type, u16 data, u16 head)
{
	struct nbl_flow_mcc_node *node;
	int mcc_id;
	u16 mcc_action;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return NULL;

	mcc_id = nbl_flow_alloc_mcc_id(flow_mgt);
	if (mcc_id < 0) {
		kfree(node);
		return NULL;
	}

	switch (type) {
	case NBL_MCC_INDEX_BOND:
	case NBL_MCC_INDEX_ETH:
		mcc_action = nbl_flow_cfg_action_set_dport_mcc_eth((u8)data);
		break;
	case NBL_MCC_INDEX_VSI:
		mcc_action = nbl_flow_cfg_action_set_dport_mcc_vsi(data);
		break;
	case NBL_MCC_INDEX_BMC:
		mcc_action = nbl_flow_cfg_action_set_dport_mcc_bmc();
		break;
	default:
		nbl_flow_free_mcc_id(flow_mgt, mcc_id);
		kfree(node);
		return NULL;
	}

	INIT_LIST_HEAD(&node->node);
	node->mcc_id = mcc_id;
	node->mcc_head = head;
	node->type = type;
	node->data = data;
	node->mcc_action = mcc_action;

	return node;
}

static void nbl_flow_free_mcc_node(struct nbl_flow_mgt *flow_mgt, struct nbl_flow_mcc_node *node)
{
	nbl_flow_free_mcc_id(flow_mgt, node->mcc_id);
	kfree(node);
}

/* not consider multicast node first change, need modify all macvlan mcc */
static int nbl_flow_add_mcc_node(struct nbl_resource_mgt *res_mgt,
				 struct nbl_flow_mcc_node *mcc_node,
				 struct list_head *head,
				 struct list_head *list,
				 struct list_head *suffix)
{
	struct nbl_flow_mcc_node *mcc_head = NULL;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 prev_mcc_id, next_mcc_id = NBL_MCC_ID_INVALID;
	int ret = 0;

	/* mcc_head must init before mcc_list */
	if (mcc_node->mcc_head) {
		list_add_tail(&mcc_node->node, head);
		prev_mcc_id = NBL_MCC_ID_INVALID;

		WARN_ON(!nbl_list_empty(list));
		ret = phy_ops->add_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mcc_node->mcc_id,
				       prev_mcc_id, NBL_MCC_ID_INVALID, mcc_node->mcc_action, 0, 0);
		goto check_ret;
	}

	list_add_tail(&mcc_node->node, list);

	if (nbl_list_is_first(&mcc_node->node, list))
		prev_mcc_id = NBL_MCC_ID_INVALID;
	else
		prev_mcc_id = list_prev_entry(mcc_node, node)->mcc_id;

	/* not head, next mcc may point suffix */
	if (suffix && !nbl_list_empty(suffix))
		next_mcc_id = list_first_entry(suffix, struct nbl_flow_mcc_node, node)->mcc_id;
	else
		next_mcc_id = NBL_MCC_ID_INVALID;

	/* first add mcc_list */
	if (prev_mcc_id == NBL_MCC_ID_INVALID && !nbl_list_empty(head)) {
		list_for_each_entry(mcc_head, head, node) {
			prev_mcc_id = mcc_head->mcc_id;
			ret |= phy_ops->add_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mcc_node->mcc_id,
						prev_mcc_id, next_mcc_id,
						mcc_node->mcc_action, 0, 0);
		}
		goto check_ret;
	}

	ret = phy_ops->add_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mcc_node->mcc_id,
			       prev_mcc_id, next_mcc_id, mcc_node->mcc_action, 0, 0);
check_ret:
	if (ret) {
		list_del(&mcc_node->node);
		return -EINVAL;
	}

	return 0;
}

/* not consider multicast node first change, need modify all macvlan mcc */
static void nbl_flow_del_mcc_node(struct nbl_resource_mgt *res_mgt,
				  struct nbl_flow_mcc_node *mcc_node,
				  struct list_head *head,
				  struct list_head *list,
				  struct list_head *suffix)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_flow_mcc_node *mcc_head = NULL;
	u16 prev_mcc_id, next_mcc_id;

	if (nbl_list_entry_is_head(mcc_node, head, node) ||
	    nbl_list_entry_is_head(mcc_node, list, node))
		return;

	if (mcc_node->mcc_head) {
		WARN_ON(!nbl_list_empty(list));
		prev_mcc_id = NBL_MCC_ID_INVALID;
		next_mcc_id = NBL_MCC_ID_INVALID;
		phy_ops->del_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mcc_node->mcc_id,
				prev_mcc_id, next_mcc_id, 0, 0);
		goto free_node;
	}

	if (nbl_list_is_first(&mcc_node->node, list))
		prev_mcc_id = NBL_MCC_ID_INVALID;
	else
		prev_mcc_id = list_prev_entry(mcc_node, node)->mcc_id;

	if (nbl_list_is_last(&mcc_node->node, list))
		next_mcc_id = NBL_MCC_ID_INVALID;
	else
		next_mcc_id = list_next_entry(mcc_node, node)->mcc_id;

	/* not head, next mcc may point suffix */
	if (next_mcc_id == NBL_MCC_ID_INVALID && suffix && !nbl_list_empty(suffix))
		next_mcc_id = list_first_entry(suffix, struct nbl_flow_mcc_node, node)->mcc_id;

	if (prev_mcc_id == NBL_MCC_ID_INVALID && !nbl_list_empty(head)) {
		list_for_each_entry(mcc_head, head, node) {
			prev_mcc_id = mcc_head->mcc_id;
			phy_ops->del_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					 mcc_node->mcc_id, prev_mcc_id, next_mcc_id, 0, 0);
		}
		goto free_node;
	}

	phy_ops->del_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mcc_node->mcc_id,
			 prev_mcc_id, next_mcc_id, 0, 0);
free_node:
	list_del(&mcc_node->node);
}

static struct nbl_flow_mcc_group *nbl_flow_alloc_mcc_group(struct nbl_resource_mgt *res_mgt,
							   unsigned long *vsi_bitmap,
							   u16 eth_id, bool multi, u16 vsi_num)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_switch_res *res = &flow_mgt->switch_res[eth_id];
	struct nbl_flow_mcc_group *group;
	struct nbl_flow_mcc_node *mcc_node, *mcc_node_safe;
	int ret;
	int bit;

	/* The structure for mc macvlan list is:
	 *
	 *    macvlan up
	 *         |
	 *         |
	 *        BMC       ->       |
	 *                           VSI 0  ->  VSI 1  ->     -> allmulti list
	 *        ETH       ->       |
	 *         |
	 *         |
	 *    macvlan down
	 *
	 * So that the up mc pkts will be send to BMC, not need broadcast to eth,
	 * but the down mc pkts will send to eth, not send to BMC.
	 *
	 * Per mac flow entry has independent bmc/eth mcc nodes.
	 * All mac flow entry share all allmuti vsi nodes.
	 */
	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return NULL;

	group->vsi_base = eth_id * NBL_FLOW_LEONIS_VSI_NUM_PER_ETH;
	group->multi = multi;
	group->nbits = flow_mgt->vsi_max_per_switch;
	group->ref_cnt = 1;
	group->vsi_num = vsi_num;

	INIT_LIST_HEAD(&group->group_node);
	INIT_LIST_HEAD(&group->mcc_node);
	INIT_LIST_HEAD(&group->mcc_head);

	group->vsi_bitmap = kcalloc(BITS_TO_LONGS(flow_mgt->vsi_max_per_switch), sizeof(long),
				    GFP_KERNEL);
	if (!group->vsi_bitmap)
		goto alloc_vsi_bitmap_failed;

	bitmap_copy(group->vsi_bitmap, vsi_bitmap, flow_mgt->vsi_max_per_switch);
	if (!multi)
		goto add_mcc_node;

	mcc_node = nbl_flow_alloc_mcc_node(flow_mgt, NBL_MCC_INDEX_ETH, eth_id, 1);
	if (!mcc_node)
		goto free_nodes;

	ret = nbl_flow_add_mcc_node(res_mgt, mcc_node, &group->mcc_head,
				    &group->mcc_node, NULL);
	if (ret) {
		nbl_flow_free_mcc_node(flow_mgt, mcc_node);
		goto free_nodes;
	}

	group->down_mcc_id = mcc_node->mcc_id;
	mcc_node = nbl_flow_alloc_mcc_node(flow_mgt, NBL_MCC_INDEX_BMC, NBL_FLOW_MCC_BMC_DPORT, 1);
	if (!mcc_node)
		goto free_nodes;

	ret = nbl_flow_add_mcc_node(res_mgt, mcc_node, &group->mcc_head,
				    &group->mcc_node, NULL);
	if (ret) {
		nbl_flow_free_mcc_node(flow_mgt, mcc_node);
		goto free_nodes;
	}
	group->up_mcc_id = mcc_node->mcc_id;

add_mcc_node:
	for_each_set_bit(bit, vsi_bitmap, flow_mgt->vsi_max_per_switch) {
		mcc_node = nbl_flow_alloc_mcc_node(flow_mgt, NBL_MCC_INDEX_VSI,
						   bit + group->vsi_base, 0);
		if (!mcc_node)
			goto free_nodes;

		if (multi)
			ret = nbl_flow_add_mcc_node(res_mgt, mcc_node, &group->mcc_head,
						    &group->mcc_node, &res->allmulti_list);
		else
			ret = nbl_flow_add_mcc_node(res_mgt, mcc_node, &group->mcc_head,
						    &group->mcc_node, NULL);

		if (ret) {
			nbl_flow_free_mcc_node(flow_mgt, mcc_node);
			goto free_nodes;
		}
	}

	if (nbl_list_empty(&group->mcc_head)) {
		group->down_mcc_id = list_first_entry(&group->mcc_node,
						      struct nbl_flow_mcc_node, node)->mcc_id;
		group->up_mcc_id = list_first_entry(&group->mcc_node,
						    struct nbl_flow_mcc_node, node)->mcc_id;
	}
	list_add_tail(&group->group_node, &res->mcc_group_head);

	return group;

free_nodes:
	list_for_each_entry_safe(mcc_node, mcc_node_safe, &group->mcc_node, node) {
		nbl_flow_del_mcc_node(res_mgt, mcc_node, &group->mcc_head,
				      &group->mcc_node, NULL);
		nbl_flow_free_mcc_node(flow_mgt, mcc_node);
	}

	list_for_each_entry_safe(mcc_node, mcc_node_safe, &group->mcc_head, node) {
		nbl_flow_del_mcc_node(res_mgt, mcc_node, &group->mcc_head,
				      &group->mcc_node, NULL);
		nbl_flow_free_mcc_node(flow_mgt, mcc_node);
	}
	kfree(group->vsi_bitmap);
alloc_vsi_bitmap_failed:
	kfree(group);

	return NULL;
}

static void nbl_flow_free_mcc_group(struct nbl_resource_mgt *res_mgt,
				    struct nbl_flow_mcc_group *group)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_mcc_node *mcc_node, *mcc_node_safe;

	group->ref_cnt--;
	if (group->ref_cnt)
		return;

	list_del(&group->group_node);
	list_for_each_entry_safe(mcc_node, mcc_node_safe, &group->mcc_node, node) {
		nbl_flow_del_mcc_node(res_mgt, mcc_node, &group->mcc_head,
				      &group->mcc_node, NULL);
		nbl_flow_free_mcc_node(flow_mgt, mcc_node);
	}

	list_for_each_entry_safe(mcc_node, mcc_node_safe, &group->mcc_head, node) {
		nbl_flow_del_mcc_node(res_mgt, mcc_node, &group->mcc_head,
				      &group->mcc_node, NULL);
		nbl_flow_free_mcc_node(flow_mgt, mcc_node);
	}

	kfree(group->vsi_bitmap);
	kfree(group);
}

static struct nbl_flow_mcc_group *nbl_find_same_mcc_group(struct nbl_flow_switch_res *res,
							  unsigned long *vsi_bitmap,
							  bool multi)
{
	struct nbl_flow_mcc_group *group = NULL;

	list_for_each_entry(group, &res->mcc_group_head, group_node)
		if (group->multi == multi &&
		    __bitmap_equal(group->vsi_bitmap, vsi_bitmap, group->nbits)) {
			group->ref_cnt++;
			return group;
		}

	return NULL;
}

static void nbl_flow_macvlan_node_del_action_func(void *priv, void *x_key, void *y_key,
						  void *data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_l2_data *rule_data = (struct nbl_flow_l2_data *)data;
	int i;

	for (i = 0; i < NBL_FLOW_MACVLAN_MAX; i++)
		nbl_flow_del_flow(res_mgt, &rule_data->entry[i]);

	/* delete mcc */
	if (rule_data->mcast_flow)
		nbl_flow_free_mcc_group(res_mgt, rule_data->mcc_group);
}

static u32 nbl_flow_get_reserve_macvlan_cnt(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_flow_switch_res *res;
	int i;
	u32 reserve_cnt = 0;

	for_each_set_bit(i, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		res = &flow_mgt->switch_res[i];
		if (res->num_vfs)
			reserve_cnt += (res->num_vfs - res->active_vfs) * 3;
	}

	return reserve_cnt;
}

static int nbl_flow_macvlan_node_vsi_match_func(void *condition, void *x_key, void *y_key,
						void *data)
{
	u16 vsi = *(u16 *)condition;
	struct nbl_flow_l2_data *rule_data = (struct nbl_flow_l2_data *)data;

	if (!rule_data->mcast_flow)
		return rule_data->vsi == vsi ? 0 : -1;
	else
		return !test_bit(vsi - rule_data->mcc_group->vsi_base,
				 rule_data->mcc_group->vsi_bitmap);
}

static void nbl_flow_macvlan_node_found_vsi_action(void *priv, void *x_key, void *y_key,
						   void *data)
{
	bool *match = (bool *)(priv);

	*match = 1;
}

static int nbl_flow_add_macvlan(void *priv, u8 *mac, u16 vlan, u16 vsi)
{
	struct nbl_hash_xy_tbl_scan_key scan_key;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_switch_res *res;
	struct nbl_flow_l2_data *rule_data;
	struct nbl_flow_mcc_group *mcc_group = NULL, *pend_group = NULL;
	unsigned long *vsi_bitmap;
	struct nbl_flow_param param = {0};
	int i;
	int ret = 0;
	int pf_id, vf_id;
	u32 reserve_cnt;
	u16 eth_id;
	u16 vsi_base;
	u16 vsi_num = 0;
	u16 func_id;
	bool alloc_rule = 0;
	bool need_mcast = 0;
	bool vsi_match = 0;

	if (nbl_flow_is_mirror_outputport(res_mgt, vsi))
		return 0;

	eth_id = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);
	res = &flow_mgt->switch_res[eth_id];

	func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi);
	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pf_id, &vf_id);
	reserve_cnt = nbl_flow_get_reserve_macvlan_cnt(res_mgt);

	if (flow_mgt->flow_id_cnt <= reserve_cnt &&
	    (vf_id == U32_MAX || test_bit(vf_id, res->vf_bitmap)))
		return -ENOSPC;

	vsi_bitmap = kcalloc(BITS_TO_LONGS(flow_mgt->vsi_max_per_switch), sizeof(long), GFP_KERNEL);
	if (!vsi_bitmap)
		return -ENOMEM;

	NBL_HASH_XY_TBL_SCAN_KEY_INIT(&scan_key, NBL_HASH_TBL_OP_SHOW, NBL_HASH_TBL_ALL_SCAN,
				      false, NULL, NULL, &vsi,
				      &nbl_flow_macvlan_node_vsi_match_func, &vsi_match,
				      &nbl_flow_macvlan_node_found_vsi_action);

	param.mac = mac;
	param.vid = vlan;
	param.eth = eth_id;
	param.vsi = vsi;
	param.mcc_id = NBL_MCC_ID_INVALID;

	vsi_base = eth_id * NBL_FLOW_LEONIS_VSI_NUM_PER_ETH;
	rule_data = (struct nbl_flow_l2_data *)nbl_common_get_hash_xy_node(res->mac_hash_tbl,
									   mac, &vlan);
	if (rule_data) {
		if (rule_data->mcast_flow &&
		    test_bit(vsi - rule_data->mcc_group->vsi_base,
			     rule_data->mcc_group->vsi_bitmap))
			goto success;
		else if (!rule_data->mcast_flow && rule_data->vsi == vsi)
			goto success;

		if (!rule_data->mcast_flow) {
			vsi_num = 1;
			set_bit(rule_data->vsi - vsi_base, vsi_bitmap);
		} else {
			vsi_num = rule_data->mcc_group->vsi_num;
			bitmap_copy(vsi_bitmap, rule_data->mcc_group->vsi_bitmap,
				    flow_mgt->vsi_max_per_switch);
		}
		need_mcast = 1;

	} else {
		rule_data = kzalloc(sizeof(*rule_data), GFP_KERNEL);
		if (!rule_data) {
			ret = -ENOMEM;
			goto alloc_rule_failed;
		}
		alloc_rule = 1;
		rule_data->multi = is_multicast_ether_addr(mac);
		rule_data->mcast_flow = 0;
		memcpy(rule_data->mac, mac, sizeof(rule_data->mac));
		rule_data->vlan = vlan;
	}

	if (rule_data->multi)
		need_mcast = 1;

	if (need_mcast) {
		set_bit(vsi - vsi_base, vsi_bitmap);
		vsi_num++;
		mcc_group = nbl_find_same_mcc_group(res, vsi_bitmap, rule_data->multi);
		if (!mcc_group) {
			mcc_group = nbl_flow_alloc_mcc_group(res_mgt, vsi_bitmap, eth_id,
							     rule_data->multi, vsi_num);
			if (!mcc_group) {
				ret = -ENOMEM;
				goto alloc_mcc_group_failed;
			}
		}
		if (rule_data->mcast_flow)
			pend_group = rule_data->mcc_group;
	} else {
		rule_data->vsi = vsi;
	}

	if (!alloc_rule) {
		for (i = 0; i < NBL_FLOW_MACVLAN_MAX; i++)
			nbl_flow_del_flow(res_mgt, &rule_data->entry[i]);

		if (pend_group)
			nbl_flow_free_mcc_group(res_mgt, pend_group);
	}

	for (i = 0; i < NBL_FLOW_MACVLAN_MAX; i++) {
		if (mcc_group) {
			if (i <= NBL_FLOW_UP)
				param.mcc_id = mcc_group->up_mcc_id;
			else
				param.mcc_id = mcc_group->down_mcc_id;
		}
		ret = nbl_flow_add_flow(res_mgt, param, i, &rule_data->entry[i]);
		if (ret)
			goto add_flow_failed;
	}

	if (mcc_group) {
		rule_data->mcast_flow = 1;
		rule_data->mcc_group = mcc_group;
	} else {
		rule_data->mcast_flow = 0;
		rule_data->vsi = vsi;
	}

	if (alloc_rule) {
		ret = nbl_common_alloc_hash_xy_node(res->mac_hash_tbl, mac, &vlan, rule_data);
		if (ret)
			goto add_flow_failed;
	}

	if (alloc_rule)
		kfree(rule_data);
success:
	kfree(vsi_bitmap);

	if (vf_id != U32_MAX && !test_bit(vf_id, res->vf_bitmap)) {
		set_bit(vf_id, res->vf_bitmap);
		res->active_vfs++;
	}

	return 0;

add_flow_failed:
	while (--i + 1)
		nbl_flow_del_flow(res_mgt, &rule_data->entry[i]);
	if (!alloc_rule)
		nbl_common_free_hash_xy_node(res->mac_hash_tbl, mac, &vlan);
	if (mcc_group)
		nbl_flow_free_mcc_group(res_mgt, mcc_group);
alloc_mcc_group_failed:
	if (alloc_rule)
		kfree(rule_data);
alloc_rule_failed:
	kfree(vsi_bitmap);

	nbl_common_scan_hash_xy_node(res->mac_hash_tbl, &scan_key);
	if (vf_id != U32_MAX && test_bit(vf_id, res->vf_bitmap) && !vsi_match) {
		clear_bit(vf_id, res->vf_bitmap);
		res->active_vfs--;
	}

	return ret;
}

static void nbl_flow_del_macvlan(void *priv, u8 *mac, u16 vlan, u16 vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_mcc_group *mcc_group = NULL, *pend_group = NULL;
	unsigned long *vsi_bitmap;
	struct nbl_flow_switch_res *res;
	struct nbl_flow_l2_data *rule_data;
	struct nbl_flow_param param = {0};
	struct nbl_hash_xy_tbl_scan_key scan_key;
	int i;
	int ret;
	int pf_id, vf_id;
	u32 vsi_num;
	u16 vsi_base = 0;
	u16 eth_id;
	u16 func_id;
	bool need_mcast = false;
	bool add_flow = false;
	bool vsi_match = 0;

	eth_id = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);
	res = &flow_mgt->switch_res[eth_id];

	rule_data = nbl_common_get_hash_xy_node(res->mac_hash_tbl, mac, &vlan);
	if (!rule_data)
		return;
	if (!rule_data->mcast_flow && rule_data->vsi != vsi)
		return;
	else if (rule_data->mcast_flow &&
		 !test_bit(vsi - rule_data->mcc_group->vsi_base, rule_data->mcc_group->vsi_bitmap))
		return;

	vsi_bitmap = kcalloc(BITS_TO_LONGS(flow_mgt->vsi_max_per_switch), sizeof(long), GFP_KERNEL);
	if (!vsi_bitmap)
		return;

	func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi);
	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pf_id, &vf_id);
	NBL_HASH_XY_TBL_SCAN_KEY_INIT(&scan_key, NBL_HASH_TBL_OP_SHOW, NBL_HASH_TBL_ALL_SCAN,
				      false, NULL, NULL, &vsi,
				      &nbl_flow_macvlan_node_vsi_match_func, &vsi_match,
				      &nbl_flow_macvlan_node_found_vsi_action);

	if (rule_data->mcast_flow) {
		bitmap_copy(vsi_bitmap, rule_data->mcc_group->vsi_bitmap,
			    flow_mgt->vsi_max_per_switch);
		vsi_num = rule_data->mcc_group->vsi_num;
		clear_bit(vsi - rule_data->mcc_group->vsi_base, vsi_bitmap);
		vsi_num--;
		vsi_base = (u16)rule_data->mcc_group->vsi_base;

		if (rule_data->mcc_group->vsi_num > 1)
			add_flow = true;

		if ((rule_data->multi && rule_data->mcc_group->vsi_num > 1) ||
		    (!rule_data->multi && rule_data->mcc_group->vsi_num > 2))
			need_mcast = 1;
		pend_group = rule_data->mcc_group;
	}

	if (need_mcast) {
		mcc_group = nbl_find_same_mcc_group(res, vsi_bitmap, rule_data->multi);
		if (!mcc_group) {
			mcc_group = nbl_flow_alloc_mcc_group(res_mgt, vsi_bitmap, eth_id,
							     rule_data->multi, vsi_num);
			if (!mcc_group)
				goto alloc_mcc_group_failed;
		}
	}

	for (i = 0; i < NBL_FLOW_MACVLAN_MAX; i++)
		nbl_flow_del_flow(res_mgt, &rule_data->entry[i]);

	if (pend_group)
		nbl_flow_free_mcc_group(res_mgt, pend_group);

	if (add_flow) {
		param.mac = mac;
		param.vid = vlan;
		param.eth = eth_id;
		param.mcc_id = NBL_MCC_ID_INVALID;
		param.vsi = (u16)find_first_bit(vsi_bitmap,
						flow_mgt->vsi_max_per_switch) + vsi_base;

		for (i = 0; i < NBL_FLOW_MACVLAN_MAX; i++) {
			if (mcc_group) {
				if (i <= NBL_FLOW_UP)
					param.mcc_id = mcc_group->up_mcc_id;
				else
					param.mcc_id = mcc_group->down_mcc_id;
			}
			ret = nbl_flow_add_flow(res_mgt, param, i, &rule_data->entry[i]);
			if (ret)
				goto add_flow_failed;
		}

		if (mcc_group) {
			rule_data->mcast_flow = 1;
			rule_data->mcc_group = mcc_group;
		} else {
			rule_data->mcast_flow = 0;
			rule_data->vsi = param.vsi;
		}
	}

	if (!add_flow)
		nbl_common_free_hash_xy_node(res->mac_hash_tbl, mac, &vlan);

alloc_mcc_group_failed:
	kfree(vsi_bitmap);

	nbl_common_scan_hash_xy_node(res->mac_hash_tbl, &scan_key);
	if (vf_id != U32_MAX && test_bit(vf_id, res->vf_bitmap) && !vsi_match) {
		clear_bit(vf_id, res->vf_bitmap);
		res->active_vfs--;
	}

	return;

add_flow_failed:
	while (--i + 1)
		nbl_flow_del_flow(res_mgt, &rule_data->entry[i]);
	if (mcc_group)
		nbl_flow_free_mcc_group(res_mgt, mcc_group);
	nbl_common_free_hash_xy_node(res->mac_hash_tbl, mac, &vlan);
	kfree(vsi_bitmap);
	nbl_common_scan_hash_xy_node(res->mac_hash_tbl, &scan_key);
	if (vf_id != U32_MAX && test_bit(vf_id, res->vf_bitmap) && !vsi_match) {
		clear_bit(vf_id, res->vf_bitmap);
		res->active_vfs--;
	}
}

int nbl_flow_set_decap_set(void *priv, struct nbl_ch_prm_set_decap_set *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, NBL_COMMON_TO_MGT_PF(common),
					       NBL_VSI_SERV_PF_DATA_TYPE);

	phy_ops->set_decap_set(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->mac, param->vlan_0,
			       param->vlan_1, param->vlan_layer, param->idx, param->is_add, vsi_id);

	return 0;
}

static void nbl_flow_macvlan_clear_del_action_func(void *priv, void *x_key, void *y_key,
						   void *data)
{
	struct nbl_flow_clear_data *clear_data = (struct nbl_flow_clear_data *)priv;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)clear_data->priv;
	struct nbl_flow_l2_data *rule_data = (struct nbl_flow_l2_data *)data;

	nbl_flow_del_macvlan(res_mgt, rule_data->mac, rule_data->vlan, clear_data->vsi);
}

static int nbl_flow_add_lag(void *priv, u16 *vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_lacp_rule *rule;
	struct nbl_flow_param param = {0};

	list_for_each_entry(rule, &flow_mgt->lacp_list, node)
		if (rule->vsi == *vsi)
			return 0;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;

	param.eth = nbl_res_vsi_id_to_eth_id(res_mgt, *vsi);
	param.vsi = *vsi;
	param.ether_type = ETH_P_SLOW;

	if (nbl_flow_add_flow(res_mgt, param, NBL_FLOW_LLDP_LACP_UP, &rule->entry)) {
		nbl_err(common, NBL_DEBUG_FLOW, "Fail to add lag flow for vsi %d", *vsi);
		kfree(rule);
		return -EFAULT;
	}

	rule->vsi = *vsi;
	list_add_tail(&rule->node, &flow_mgt->lacp_list);

	return 0;
}

static int nbl_flow_del_lag(void *priv, u16 *vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_flow_lacp_rule *rule;

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);

	list_for_each_entry(rule, &flow_mgt->lacp_list, node)
		if (rule->vsi == *vsi)
			break;

	if (nbl_list_entry_is_head(rule, &flow_mgt->lacp_list, node))
		return 0;

	nbl_flow_del_flow(res_mgt, &rule->entry);

	list_del(&rule->node);
	kfree(rule);

	return 0;
}

static int nbl_flow_add_lldp(void *priv, u16 *vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_lldp_rule *rule;
	struct nbl_flow_param param = {0};

	list_for_each_entry(rule, &flow_mgt->lldp_list, node)
		if (rule->vsi == *vsi)
			return 0;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;

	param.eth = nbl_res_vsi_id_to_eth_id(res_mgt, *vsi);
	param.vsi = *vsi;
	param.ether_type = ETH_P_LLDP;

	if (nbl_flow_add_flow(res_mgt, param, NBL_FLOW_LLDP_LACP_UP, &rule->entry)) {
		nbl_err(common, NBL_DEBUG_FLOW, "Fail to add lldp flow for vsi %d", *vsi);
		kfree(rule);
		return -EFAULT;
	}

	rule->vsi = *vsi;
	list_add_tail(&rule->node, &flow_mgt->lldp_list);

	return 0;
}

static int nbl_flow_del_lldp(void *priv, u16 *vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_flow_lldp_rule *rule;

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);

	list_for_each_entry(rule, &flow_mgt->lldp_list, node)
		if (rule->vsi == *vsi)
			break;

	if (nbl_list_entry_is_head(rule, &flow_mgt->lldp_list, node))
		return 0;

	nbl_flow_del_flow(res_mgt, &rule->entry);

	list_del(&rule->node);
	kfree(rule);

	return 0;
}

static int nbl_flow_change_mcc_group_chain(struct nbl_resource_mgt *res_mgt, u8 eth,
					   u16 current_mcc_id)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_switch_res *switch_res = &flow_mgt->switch_res[eth];
	struct nbl_flow_mcc_group *group;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 node_mcc;

	list_for_each_entry(group, &switch_res->mcc_group_head, group_node)
		if (group->multi && !nbl_list_empty(&group->mcc_node)) {
			node_mcc = list_last_entry(&group->mcc_node,
						   struct nbl_flow_mcc_node, node)->mcc_id;
			phy_ops->update_mcc_next_node(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						      node_mcc, current_mcc_id);
		}
	switch_res->allmulti_first_mcc = current_mcc_id;
	return 0;
}

static int nbl_flow_add_multi_mcast(void *priv, u16 vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_switch_res *switch_res;
	struct nbl_flow_mcc_node *node;
	int ret;
	u16 current_mcc_id;
	u8 eth = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);

	switch_res = &flow_mgt->switch_res[eth];
	list_for_each_entry(node, &switch_res->allmulti_list, node)
		if (node->data == vsi && node->type == NBL_MCC_INDEX_VSI)
			return 0;

	node = nbl_flow_alloc_mcc_node(flow_mgt, NBL_MCC_INDEX_VSI, vsi, 0);
	if (!node)
		return -ENOSPC;

	switch_res = &flow_mgt->switch_res[eth];
	ret = nbl_flow_add_mcc_node(res_mgt, node, &switch_res->allmulti_head,
				    &switch_res->allmulti_list, NULL);
	if (ret) {
		nbl_flow_free_mcc_node(flow_mgt, node);
		return ret;
	}

	if (nbl_list_empty(&switch_res->allmulti_list))
		current_mcc_id = NBL_MCC_ID_INVALID;
	else
		current_mcc_id = list_first_entry(&switch_res->allmulti_list,
						  struct nbl_flow_mcc_node, node)->mcc_id;

	if (current_mcc_id != switch_res->allmulti_first_mcc)
		nbl_flow_change_mcc_group_chain(res_mgt, eth, current_mcc_id);

	return 0;
}

static void nbl_flow_del_multi_mcast(void *priv, u16 vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_switch_res *switch_res;
	struct nbl_flow_mcc_node *mcc_node;
	u16 current_mcc_id;
	u8 eth = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);

	switch_res = &flow_mgt->switch_res[eth];
	list_for_each_entry(mcc_node, &switch_res->allmulti_list, node)
		if (mcc_node->data == vsi && mcc_node->type == NBL_MCC_INDEX_VSI) {
			nbl_flow_del_mcc_node(res_mgt, mcc_node, &switch_res->allmulti_head,
					      &switch_res->allmulti_list, NULL);
			nbl_flow_free_mcc_node(flow_mgt, mcc_node);
			break;
		}

	if (nbl_list_empty(&switch_res->allmulti_list))
		current_mcc_id = NBL_MCC_ID_INVALID;
	else
		current_mcc_id = list_first_entry(&switch_res->allmulti_list,
						  struct nbl_flow_mcc_node, node)->mcc_id;

	if (current_mcc_id != switch_res->allmulti_first_mcc)
		nbl_flow_change_mcc_group_chain(res_mgt, eth, current_mcc_id);
}

static int nbl_flow_add_multi_group(struct nbl_resource_mgt *res_mgt, u8 eth)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_switch_res *switch_res = &flow_mgt->switch_res[eth];
	struct nbl_flow_param param_up = {0};
	struct nbl_flow_mcc_node *up_node;
	struct nbl_flow_param param_down = {0};
	struct nbl_flow_mcc_node *down_node;
	int i, ret;

	/* The structure for MCC allmulti list is:
	 *
	 *    l2/l3_mc_mcast_up
	 *         |
	 *         |
	 *        BMC       ->       |
	 *                           VSI 0       ->       VSI 1       -> ...
	 *        ETH       ->       |
	 *         |
	 *         |
	 *    l2/l3_mc_mcast_down
	 *
	 * So that the up mc pkts will be send to BMC, not need broadcast to eth,
	 * but the down mc pkts will send to eth, not send to BMC.
	 */
	down_node = nbl_flow_alloc_mcc_node(flow_mgt, NBL_MCC_INDEX_ETH, eth, 1);
	if (!down_node)
		return -ENOSPC;

	ret = nbl_flow_add_mcc_node(res_mgt, down_node, &switch_res->allmulti_head,
				    &switch_res->allmulti_list, NULL);
	if (ret)
		goto add_eth_mcc_node_failed;

	param_down.mcc_id = down_node->mcc_id;
	param_down.eth = eth;
	for (i = 0; i < NBL_FLOW_DOWN_MULTI_MCAST_END - NBL_FLOW_L2_DOWN_MULTI_MCAST; i++) {
		ret = nbl_flow_add_flow(res_mgt, param_down, i + NBL_FLOW_L2_DOWN_MULTI_MCAST,
					&switch_res->allmulti_down[i]);
		if (ret)
			goto add_down_flow_failed;
	}

	up_node = nbl_flow_alloc_mcc_node(flow_mgt, NBL_MCC_INDEX_BMC, NBL_FLOW_MCC_BMC_DPORT, 1);
	if (!up_node) {
		ret = -ENOSPC;
		goto alloc_bmc_node_failed;
	}

	ret = nbl_flow_add_mcc_node(res_mgt, up_node, &switch_res->allmulti_head,
				    &switch_res->allmulti_list, NULL);
	if (ret)
		goto add_bmc_mcc_node_failed;

	param_up.mcc_id = up_node->mcc_id;
	param_up.eth = eth;
	for (i = 0; i < NBL_FLOW_UP_MULTI_MCAST_END - NBL_FLOW_L2_UP_MULTI_MCAST; i++) {
		ret = nbl_flow_add_flow(res_mgt, param_up, i + NBL_FLOW_L2_UP_MULTI_MCAST,
					&switch_res->allmulti_up[i]);
		if (ret)
			goto add_up_flow_failed;
	}

	switch_res->ether_id = eth;
	switch_res->allmulti_first_mcc = NBL_MCC_ID_INVALID;
	switch_res->vld = 1;

	return 0;

add_up_flow_failed:
	while (--i >= 0)
		nbl_flow_del_flow(res_mgt, &switch_res->allmulti_up[i]);
	nbl_flow_del_mcc_node(res_mgt, up_node, &switch_res->allmulti_head,
			      &switch_res->allmulti_list, NULL);
add_bmc_mcc_node_failed:
	nbl_flow_free_mcc_node(flow_mgt, up_node);
alloc_bmc_node_failed:
add_down_flow_failed:
	while (--i >= 0)
		nbl_flow_del_flow(res_mgt, &switch_res->allmulti_down[i]);
	nbl_flow_del_mcc_node(res_mgt, down_node, &switch_res->allmulti_head,
			      &switch_res->allmulti_list, NULL);
add_eth_mcc_node_failed:
	nbl_flow_free_mcc_node(flow_mgt, down_node);
	return ret;
}

static void nbl_flow_del_multi_group(struct nbl_resource_mgt *res_mgt, u8 eth)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_switch_res *switch_res = &flow_mgt->switch_res[eth];
	struct nbl_flow_mcc_node *mcc_node, *mcc_node_safe;

	if (!switch_res->vld)
		return;

	nbl_flow_del_flow(res_mgt, &switch_res->allmulti_up[0]);
	nbl_flow_del_flow(res_mgt, &switch_res->allmulti_up[1]);
	nbl_flow_del_flow(res_mgt, &switch_res->allmulti_down[0]);
	nbl_flow_del_flow(res_mgt, &switch_res->allmulti_down[1]);

	list_for_each_entry_safe(mcc_node, mcc_node_safe, &switch_res->allmulti_list, node) {
		nbl_flow_del_mcc_node(res_mgt, mcc_node, &switch_res->allmulti_head,
				      &switch_res->allmulti_list, NULL);
		nbl_flow_free_mcc_node(flow_mgt, mcc_node);
	}

	list_for_each_entry_safe(mcc_node, mcc_node_safe, &switch_res->allmulti_head, node) {
		nbl_flow_del_mcc_node(res_mgt, mcc_node, &switch_res->allmulti_head,
				      &switch_res->allmulti_list, NULL);
		nbl_flow_free_mcc_node(flow_mgt, mcc_node);
	}

	INIT_LIST_HEAD(&switch_res->allmulti_list);
	INIT_LIST_HEAD(&switch_res->allmulti_head);
	switch_res->vld = 0;
	switch_res->allmulti_first_mcc = NBL_MCC_ID_INVALID;
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

static int nbl_flow_add_tcam_flow(struct nbl_resource_mgt *res_mgt, struct nbl_flow_param param,
				  s32 type, struct nbl_flow_fem_entry *flow)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_ht_item ht_item;
	struct nbl_kt_item kt_item;
	struct nbl_tcam_item *tcam_item = NULL;
	u32 action0, action1;
	u32 tcam_id;
	int ret = 0;

	memset(&ht_item, 0, sizeof(ht_item));
	memset(&kt_item, 0, sizeof(kt_item));

	tcam_item = kzalloc(sizeof(*tcam_item), GFP_ATOMIC);
	if (!tcam_item)
		return -ENOMEM;

	flow->flow_type = param.type;
	flow->type = type;
	flow->flow_id = 0xFFFF;

	ret = cfg_ops[type].cfg_action(param, &action0, &action1);
	if (ret)
		goto free_mem;

	ret = cfg_ops[type].cfg_key(&kt_item.kt_data, param, NBL_COMMON_TO_ETH_MODE(common));
	if (ret)
		goto free_mem;

	tcam_id = NBL_MAX_TCAM_ID - param.eth;
	tcam_item->tcam_index = tcam_id;
	nbl_flow_cfg_tcam(tcam_item, &ht_item, &kt_item, action0, action1, NBL_PT_PP1);
	flow->tcam_index = tcam_item->tcam_index;

	ret = nbl_flow_add_tcam(res_mgt, *tcam_item);

free_mem:
	kfree(tcam_item);

	return ret;
}

static int nbl_flow_add_ecn(void *priv, u16 eth)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_ecn_rule *rule;
	struct nbl_flow_param param = {0};

	list_for_each_entry(rule, &flow_mgt->ecn_list, node)
		if (rule->eth == eth)
			return 0;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;

	param.eth = eth;
	param.type = NBL_KT_HALF_MODE;

	if (nbl_flow_add_tcam_flow(res_mgt, param, NBL_FLOW_ECN_COUNT, &rule->entry)) {
		nbl_err(common, NBL_DEBUG_FLOW, "Fail to add ecn flow for eth %d", eth);
		kfree(rule);
		return -EFAULT;
	}

	rule->eth = eth;
	list_add_tail(&rule->node, &flow_mgt->ecn_list);

	return 0;
}

static void nbl_flow_del_tcam_flow(struct nbl_resource_mgt *res_mgt,
				   struct nbl_flow_fem_entry *flow)
{
	struct nbl_tcam_item tcam_item;

	memset(&tcam_item, 0, sizeof(tcam_item));

	tcam_item.tcam_index = flow->tcam_index;
	tcam_item.pp_type = NBL_PT_PP1;
	nbl_flow_del_tcam(res_mgt, tcam_item);
}

static void nbl_flow_del_ecn(void *priv, u16 eth)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_flow_ecn_rule *rule;

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);

	list_for_each_entry(rule, &flow_mgt->ecn_list, node)
		if (rule->eth == eth)
			break;

	if (nbl_list_entry_is_head(rule, &flow_mgt->ecn_list, node))
		return;

	nbl_flow_del_tcam_flow(res_mgt, &rule->entry);

	list_del(&rule->node);
	kfree(rule);
}

static void nbl_flow_remove_ecn_stats(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	int i;

	for_each_set_bit(i, eth_info->eth_bitmap, NBL_MAX_ETHERNET)
		nbl_flow_del_ecn(res_mgt, i);
}

static int nbl_flow_setup_ecn_stats(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	int i, ret = 0;

	for_each_set_bit(i, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		ret = nbl_flow_add_ecn(res_mgt, i);
		if (ret)
			goto fail;
	}

	return 0;

fail:
	nbl_flow_remove_ecn_stats(res_mgt);
	return ret;
}

static int nbl_res_flow_cfg_duppkt_mcc(void *priv, struct nbl_lag_member_list_param *param)
{
	return 0;
}

static int nbl_flow_clear_accel_flow(void *priv, u16 *vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_dipsec_rule *dipsec_rule, *dipsec_rule_safe;
	struct nbl_flow_ul4s_rule *ul4s_rule, *ul4s_rule_safe;

	list_for_each_entry_safe(dipsec_rule, dipsec_rule_safe, &flow_mgt->dprbac_head, node)
		if (dipsec_rule->vsi == *vsi_id) {
			nbl_flow_del_flow(res_mgt, &dipsec_rule->dipsec_entry);
			list_del(&dipsec_rule->node);
			kfree(dipsec_rule);
		}

	list_for_each_entry_safe(ul4s_rule, ul4s_rule_safe, &flow_mgt->ul4s_head, node)
		if (ul4s_rule->vsi == *vsi_id) {
			nbl_flow_del_flow(res_mgt, &ul4s_rule->ul4s_entry);
			list_del(&ul4s_rule->node);
			kfree(ul4s_rule);
		}

	return 0;
}

static u16 nbl_vsi_mtu_index(struct nbl_resource_mgt *res_mgt, u16 vsi_id)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 index;

	index = phy_ops->get_mtu_index(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id);
	return index - 1;
}

static void nbl_clear_mtu_entry(struct nbl_resource_mgt *res_mgt, u16 vsi_id)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 mtu_index;

	mtu_index = nbl_vsi_mtu_index(res_mgt, vsi_id);
	if (mtu_index < NBL_MAX_MTU) {
		res_mgt->resource_info->mtu_list[mtu_index].ref_count--;
		phy_ops->set_vsi_mtu(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id, 0);
		if (res_mgt->resource_info->mtu_list[mtu_index].ref_count == 0) {
			phy_ops->set_mtu(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mtu_index + 1, 0);
			res_mgt->resource_info->mtu_list[mtu_index].mtu_value = 0;
		}
	}
}

static int nbl_flow_clear_flow(void *priv, u16 *vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_clear_data data;
	void *mac_hash_tbl;
	struct nbl_hash_xy_tbl_scan_key scan_key;
	u8 eth_id;

	eth_id = nbl_res_vsi_id_to_eth_id(res_mgt, *vsi_id);
	mac_hash_tbl = flow_mgt->switch_res[eth_id].mac_hash_tbl;
	data.priv = priv;
	data.vsi = *vsi_id;

	nbl_clear_mtu_entry(res_mgt, *vsi_id);
	NBL_HASH_XY_TBL_SCAN_KEY_INIT(&scan_key, NBL_HASH_TBL_OP_SHOW, NBL_HASH_TBL_ALL_SCAN,
				      false, NULL, NULL, vsi_id,
				      &nbl_flow_macvlan_node_vsi_match_func, &data,
				      &nbl_flow_macvlan_clear_del_action_func);
	nbl_common_scan_hash_xy_node(mac_hash_tbl, &scan_key);
	nbl_flow_del_multi_mcast(res_mgt, *vsi_id);

	return 0;
}

char templete_name[NBL_FLOW_TYPE_MAX][16] = {
	"up_tnl",
	"up",
	"down",
	"lldp/lacp",
	"pmd_nd_upcall",
	"l2_mul_up",
	"l3_mul_up",
	"l2_mul_down",
	"l3_mul_down",
	"tls_up",
	"ipsec_down",
};

static void nbl_flow_id_dump(struct seq_file *m, struct nbl_flow_fem_entry *entry, char *title)
{
	seq_printf(m, "%s: flow_id %u, ht0 0x%x, ht1 0x%x, table: %u, bucket: %u\n", title,
		   entry->flow_id, entry->ht0_hash, entry->ht1_hash,
		   entry->hash_table, entry->hash_bucket);
}

static void nbl_flow_mcc_node_dump(struct seq_file *m, struct nbl_flow_mcc_node *node)
{
	seq_printf(m, " head: %u, type: %u, id: %u, data: %u; ", node->mcc_head,
		   node->type, node->mcc_id, node->data);
}

static void nbl_flow_mcc_group_dump(struct seq_file *m, struct nbl_flow_mcc_group *group)
{
	struct nbl_flow_mcc_node *mcc_node;

	seq_printf(m, "vsi_base: %u, nbits: %u, vsi_number: %u, ref_cnt %u, multi %u, up_mcc_id %u, down_mcc_id %u\n",
		   group->vsi_base, group->nbits, group->vsi_num, group->ref_cnt, group->multi,
		   group->up_mcc_id, group->down_mcc_id);
	seq_puts(m, "mcc head list\n");
	list_for_each_entry(mcc_node, &group->mcc_head, node)
		nbl_flow_mcc_node_dump(m, mcc_node);
	seq_puts(m, "\nmcc body list\n");
	list_for_each_entry(mcc_node, &group->mcc_node, node)
		nbl_flow_mcc_node_dump(m, mcc_node);
	seq_puts(m, "\n");
}

static void nbl_flow_macvlan_node_show_action_func(void *priv, void *x_key, void *y_key,
						   void *data)
{
	struct seq_file *m = (struct seq_file *)priv;
	u8 *mac = (u8 *)x_key;
	u16 vlan = *(u16 *)y_key;
	struct nbl_flow_l2_data *rule_data = (struct nbl_flow_l2_data *)data;
	int i;

	seq_printf(m, "\nvlan %d MAC address %02X:%02X:%02X:%02X:%02X:%02X, multi %u, mcast %u\n",
		   vlan, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], rule_data->multi,
		   rule_data->mcast_flow);
	for (i = 0; i < NBL_FLOW_MACVLAN_MAX; i++)
		nbl_flow_id_dump(m, &rule_data->entry[i], templete_name[i]);
	if (!rule_data->mcast_flow)
		seq_printf(m, "rule action to vsi %u\n", rule_data->vsi);
	else
		nbl_flow_mcc_group_dump(m, rule_data->mcc_group);
}

static void nbl_flow_dump_flow(void *priv, struct seq_file *m)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_flow_switch_res *switch_res;
	struct nbl_flow_mcc_node *mcc_node;
	struct nbl_flow_lldp_rule *lldp_rule;
	struct nbl_flow_lacp_rule *lacp_rule;
	struct nbl_flow_ecn_rule *ecn_rule;
	struct nbl_flow_fem_entry *entry;
	struct nbl_hash_xy_tbl_scan_key scan_key;
	int i, j;

	NBL_HASH_XY_TBL_SCAN_KEY_INIT(&scan_key, NBL_HASH_TBL_OP_SHOW, NBL_HASH_TBL_ALL_SCAN,
				      false, NULL, NULL, NULL, NULL, m,
				      &nbl_flow_macvlan_node_show_action_func);

	seq_printf(m, "\n flow_mgt flow_id_cnt %u, pp_tcam_count %u, accel_flow_count %u, vsi_max_per_switch %u.\n",
		   flow_mgt->flow_id_cnt, flow_mgt->pp_tcam_count,
		   flow_mgt->accel_flow_count, flow_mgt->vsi_max_per_switch);
	for_each_set_bit(i, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		switch_res = &flow_mgt->switch_res[i];
		seq_printf(m, "\nether_id %d, status %u\n",
			   switch_res->ether_id, switch_res->network_status);
		entry = &switch_res->allmulti_up[0];
		for (j = NBL_FLOW_L2_UP_MULTI_MCAST; j < NBL_FLOW_UP_MULTI_MCAST_END; j++)
			nbl_flow_id_dump(m, &entry[j - NBL_FLOW_L2_UP_MULTI_MCAST],
					 templete_name[j]);
		entry = &switch_res->allmulti_down[0];
		for (j = NBL_FLOW_L2_DOWN_MULTI_MCAST; j < NBL_FLOW_DOWN_MULTI_MCAST_END; j++)
			nbl_flow_id_dump(m, &entry[j - NBL_FLOW_L2_DOWN_MULTI_MCAST],
					 templete_name[j]);
		seq_printf(m, "\nether_id %d, mcc head list\n", switch_res->ether_id);
		list_for_each_entry(mcc_node, &switch_res->allmulti_head, node)
			nbl_flow_mcc_node_dump(m, mcc_node);
		seq_printf(m, "\n\nether_id %d, mcc body list\n", switch_res->ether_id);
		list_for_each_entry(mcc_node, &switch_res->allmulti_list, node)
			nbl_flow_mcc_node_dump(m, mcc_node);
		seq_printf(m, "\nnumber vf %u, active vf %u, vf bitmap: %*pb\n",
			   switch_res->num_vfs, switch_res->active_vfs,
			   switch_res->num_vfs, switch_res->vf_bitmap);
		nbl_common_scan_hash_xy_node(switch_res->mac_hash_tbl, &scan_key);
		seq_puts(m, "\n");
	}

	list_for_each_entry(lldp_rule, &flow_mgt->lldp_list, node)
		seq_printf(m, "LLDP rule: vsi %d\n", lldp_rule->vsi);

	list_for_each_entry(ecn_rule, &flow_mgt->ecn_list, node)
		seq_printf(m, "ECN rule: eth %d tcam_index %d\n",
			   ecn_rule->eth, ecn_rule->entry.tcam_index);

	seq_puts(m, "\n");
	list_for_each_entry(lacp_rule, &flow_mgt->lacp_list, node)
		seq_printf(m, "LACP rule: vsi %d\n", lacp_rule->vsi);
}

static int nbl_flow_add_ktls_rx_flow(void *priv, struct nbl_ch_prm_cfg_ktls_flow *prm)
{
	u32 index = prm->index;
	u32 *data = prm->data;
	u16 vsi = prm->vsi;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_common_info *common;
	struct nbl_flow_ul4s_rule *rule;
	struct nbl_flow_param param = {0};

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	common = NBL_RES_MGT_TO_COMMON(res_mgt);

	list_for_each_entry(rule, &flow_mgt->ul4s_head, node)
		if (rule->index == index)
			return -EEXIST;

	rule = kzalloc(sizeof(*rule), GFP_ATOMIC);
	if (!rule)
		return -ENOMEM;

	param.index = index;
	param.data = data;
	param.vsi = vsi;
	param.eth = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);
	if (data[0] == AF_INET6)
		param.type = NBL_KT_FULL_MODE;
	if (nbl_flow_add_flow(res_mgt, param, NBL_FLOW_TLS_UP, &rule->ul4s_entry)) {
		kfree(rule);
		return -EFAULT;
	}

	rule->index = index;
	rule->vsi = vsi;
	list_add_tail(&rule->node, &flow_mgt->ul4s_head);
	return 0;
}

static int nbl_flow_del_ktls_rx_flow(void *priv, struct nbl_ch_prm_cfg_ktls_flow *prm)
{
	u32 index = prm->index;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_flow_ul4s_rule *rule;

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);

	list_for_each_entry(rule, &flow_mgt->ul4s_head, node)
		if (rule->index == index)
			break;

	if (nbl_list_entry_is_head(rule, &flow_mgt->ul4s_head, node))
		return 0;

	nbl_flow_del_flow(res_mgt, &rule->ul4s_entry);
	list_del(&rule->node);
	kfree(rule);

	return 0;
}

static int nbl_flow_add_ipsec_tx_flow(void *priv, struct nbl_ch_prm_cfg_ipsec_flow *prm)
{
	u32 index = prm->index;
	u32 *data = prm->data;
	u16 vsi = prm->vsi;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_common_info *common;
	struct nbl_flow_dipsec_rule *rule;
	struct nbl_flow_param param = {0};

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	common = NBL_RES_MGT_TO_COMMON(res_mgt);

	list_for_each_entry(rule, &flow_mgt->dprbac_head, node)
		if (rule->index == index)
			return -EEXIST;

	rule = kzalloc(sizeof(*rule), GFP_ATOMIC);
	if (!rule)
		return -ENOMEM;

	param.index = index;
	param.data = data;
	param.vsi = vsi;
	param.eth = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);
	if (data[0] == AF_INET6)
		param.type = NBL_KT_FULL_MODE;
	if (nbl_flow_add_flow(res_mgt, param, NBL_FLOW_IPSEC_DOWN, &rule->dipsec_entry)) {
		kfree(rule);
		return -EFAULT;
	}

	rule->index = index;
	rule->vsi = vsi;
	list_add_tail(&rule->node, &flow_mgt->dprbac_head);
	return 0;
}

static int nbl_flow_del_ipsec_tx_flow(void *priv, struct nbl_ch_prm_cfg_ipsec_flow *prm)
{
	u32 index = prm->index;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_flow_dipsec_rule *rule;

	flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);

	list_for_each_entry(rule, &flow_mgt->dprbac_head, node)
		if (rule->index == index)
			break;

	if (nbl_list_entry_is_head(rule, &flow_mgt->dprbac_head, node))
		return 0;

	nbl_flow_del_flow(res_mgt, &rule->dipsec_entry);
	list_del(&rule->node);
	kfree(rule);

	return 0;
}

static void nbl_res_flr_clear_accel_flow(void *priv, u16 vf_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 func_id = vf_id + NBL_MAX_PF;
	u16 vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);

	nbl_flow_clear_accel_flow(priv, &vsi_id);
}

static void nbl_res_flr_clear_flow(void *priv, u16 vf_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 func_id = vf_id + NBL_MAX_PF;
	u16 vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);

	nbl_flow_clear_flow(priv, &vsi_id);
}

static void nbl_res_flow_del_nd_upcall_flow(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_nd_upcall_rule *rule = NULL;
	int i;

	info->nd_upcall_refnt--;
	if (info->nd_upcall_refnt > 0) {
		nbl_info(common, NBL_DEBUG_FLOW, "nd upcall flow reference count %d",
			 info->nd_upcall_refnt);
		return;
	}

	rule = list_entry(flow_mgt->nd_upcall_list.next, struct nbl_flow_nd_upcall_rule, node);
	if (nbl_list_entry_is_head(rule, &flow_mgt->nd_upcall_list, node))
		return;

	for (i = 0; i < NBL_FLOW_PMD_ND_UPCALL_FLOW_NUM; i++)
		nbl_flow_del_flow(res_mgt, &rule->entry[i]);

	list_del(&rule->node);
	kfree(rule);
	nbl_info(common, NBL_DEBUG_FLOW, "deleting all flows for nd upcall");
}

static int nbl_res_flow_add_nd_upcall_flow(void *priv, u16 vsi, bool for_pmd)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_nd_upcall_rule *rule;
	struct nbl_flow_param param = {0};

	/* TC case: use refcount to track adding flow */
	if (info->nd_upcall_refnt && !for_pmd) {
		info->nd_upcall_refnt++;
		nbl_info(common, NBL_DEBUG_FLOW, "tc: nd upcall flow reference count %d",
			 info->nd_upcall_refnt);
		return 0;
	}

	/* PMD case: if nd flows exist, simply delete them and add flow again */
	if (info->nd_upcall_refnt && for_pmd) {
		nbl_info(common, NBL_DEBUG_FLOW, "pmd active: nd upcall flow will be reset");
		nbl_res_flow_del_nd_upcall_flow(priv);
	}

	nbl_info(common, NBL_DEBUG_FLOW, "adding all flows for nd upcall");
	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;

	param.vsi = vsi;
	param.for_pmd = for_pmd;
	param.ether_type = ETH_P_IPV6;
	param.priv_data = NBL_DUPPKT_PTYPE_NA;
	if (nbl_flow_add_flow(res_mgt, param, NBL_FLOW_PMD_ND_UPCALL,
			      &rule->entry[NBL_FLOW_PMD_ND_UPCALL_NA])) {
		nbl_err(common, NBL_DEBUG_FLOW, "Fail to add icmpv6 na flow for vsi %d", vsi);
		kfree(rule);
		return -EFAULT;
	}

	param.priv_data = NBL_DUPPKT_PTYPE_NS;
	if (nbl_flow_add_flow(res_mgt, param, NBL_FLOW_PMD_ND_UPCALL,
			      &rule->entry[NBL_FLOW_PMD_ND_UPCALL_NS])) {
		nbl_flow_del_flow(res_mgt, &rule->entry[NBL_FLOW_PMD_ND_UPCALL_NA]);
		nbl_err(common, NBL_DEBUG_FLOW, "Fail to add icmpv6 ns flow for vsi %d", vsi);
		kfree(rule);
		return -EFAULT;
	}

	info->nd_upcall_refnt++;
	list_add_tail(&rule->node, &flow_mgt->nd_upcall_list);
	return 0;
}

static int nbl_res_flow_check_flow_table_spec(void *priv, struct nbl_ch_prm_flow_table_spec *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	u32 reserve_cnt = nbl_flow_get_reserve_macvlan_cnt(res_mgt);
	u32 need = param->vlan_list_cnt * NBL_FLOW_MACVLAN_MAX *
		(param->unicast_mac_cnt + param->multi_mac_cnt);

	if (reserve_cnt + need > flow_mgt->flow_id_cnt)
		return -ENOSPC;

	return 0;
}

static int nbl_res_set_mtu(void *priv, u16 vsi_id, u16 mtu)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_mtu_entry *mtu_list = &res_mgt->resource_info->mtu_list[0];
	int i, found_idx = -1, first_zero_idx = -1;
	u16 real_mtu = mtu + ETH_HLEN + 2 * VLAN_HLEN;

	nbl_clear_mtu_entry(res_mgt, vsi_id);
	if (mtu == 0)
		return 0;

	for (i = 0; i < NBL_MAX_MTU; i++) {
		if (mtu_list[i].mtu_value == real_mtu) {
			found_idx = i;
			break;
		}

		if (!mtu_list[i].mtu_value)
			first_zero_idx = i;
	}

	if (first_zero_idx == -1 && found_idx == -1)
		return 0;

	if (found_idx != -1) {
		mtu_list[found_idx].ref_count++;
		phy_ops->set_vsi_mtu(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id, found_idx + 1);
		return 0;
	}

	if (first_zero_idx != -1) {
		mtu_list[first_zero_idx].ref_count++;
		mtu_list[first_zero_idx].mtu_value = real_mtu;
		phy_ops->set_vsi_mtu(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id, first_zero_idx + 1);
		phy_ops->set_mtu(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), first_zero_idx + 1, real_mtu);
	}

	return 0;
}

static int nbl_flow_handle_mirror_outputport_event(u16 type, void *event_data, void *callback_data)
{
	int i;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)callback_data;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_event_mirror_outputport_data *mirror_outputport =
				(struct nbl_event_mirror_outputport_data *)event_data;

	if (mirror_outputport->opcode) {
		for (i = 0; i < NBL_MIRROR_OUTPUTPORT_MAX_FUNC; i++) {
			if (flow_mgt->mirror_outputport_func[i] == mirror_outputport->func_id)
				return 0;
		}
		for (i = 0; i < NBL_MIRROR_OUTPUTPORT_MAX_FUNC; i++) {
			if (flow_mgt->mirror_outputport_func[i] == U16_MAX) {
				flow_mgt->mirror_outputport_func[i] = mirror_outputport->func_id;
				break;
			}

			if (i >= NBL_MIRROR_OUTPUTPORT_MAX_FUNC)
				nbl_err(common, NBL_DEBUG_FLOW, "Macvlan blacklist exceed max func:%d",
					mirror_outputport->func_id);
		}
	} else {
		for (i = 0; i < NBL_MIRROR_OUTPUTPORT_MAX_FUNC; i++) {
			if (flow_mgt->mirror_outputport_func[i] == mirror_outputport->func_id) {
				flow_mgt->mirror_outputport_func[i] = U16_MAX;
				break;
			}
		}
	}

	return 0;
}

static void nbl_flow_cfg_mirror_outputport_event(void *priv, bool enable)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_event_callback event_callback = {0};

	event_callback.callback_data = res_mgt;
	if (enable) {
		event_callback.callback = nbl_flow_handle_mirror_outputport_event;
		nbl_event_register(NBL_EVENT_MIRROR_OUTPUTPORT, &event_callback,
				   NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	} else {
		event_callback.callback = nbl_flow_handle_mirror_outputport_event;
		nbl_event_unregister(NBL_EVENT_MIRROR_OUTPUTPORT, &event_callback,
				     NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	}
}

/* NBL_FLOW_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_FLOW_OPS_TBL								\
do {											\
	NBL_FLOW_SET_OPS(add_macvlan, nbl_flow_add_macvlan);				\
	NBL_FLOW_SET_OPS(del_macvlan, nbl_flow_del_macvlan);				\
	NBL_FLOW_SET_OPS(set_decap_set, nbl_flow_set_decap_set);			\
	NBL_FLOW_SET_OPS(add_lag_flow, nbl_flow_add_lag);				\
	NBL_FLOW_SET_OPS(del_lag_flow, nbl_flow_del_lag);				\
	NBL_FLOW_SET_OPS(add_lldp_flow, nbl_flow_add_lldp);				\
	NBL_FLOW_SET_OPS(del_lldp_flow, nbl_flow_del_lldp);				\
	NBL_FLOW_SET_OPS(add_multi_mcast, nbl_flow_add_multi_mcast);			\
	NBL_FLOW_SET_OPS(del_multi_mcast, nbl_flow_del_multi_mcast);			\
	NBL_FLOW_SET_OPS(setup_multi_group, nbl_flow_setup_multi_group);		\
	NBL_FLOW_SET_OPS(remove_multi_group, nbl_flow_remove_multi_group);		\
	NBL_FLOW_SET_OPS(setup_ecn_stats, nbl_flow_setup_ecn_stats);			\
	NBL_FLOW_SET_OPS(remove_ecn_stats, nbl_flow_remove_ecn_stats);			\
	NBL_FLOW_SET_OPS(clear_accel_flow, nbl_flow_clear_accel_flow);			\
	NBL_FLOW_SET_OPS(clear_flow, nbl_flow_clear_flow);				\
	NBL_FLOW_SET_OPS(dump_flow, nbl_flow_dump_flow);				\
	NBL_FLOW_SET_OPS(add_ktls_rx_flow, nbl_flow_add_ktls_rx_flow);			\
	NBL_FLOW_SET_OPS(del_ktls_rx_flow, nbl_flow_del_ktls_rx_flow);			\
	NBL_FLOW_SET_OPS(add_ipsec_tx_flow, nbl_flow_add_ipsec_tx_flow);		\
	NBL_FLOW_SET_OPS(del_ipsec_tx_flow, nbl_flow_del_ipsec_tx_flow);		\
	NBL_FLOW_SET_OPS(flr_clear_accel_flow, nbl_res_flr_clear_accel_flow);		\
	NBL_FLOW_SET_OPS(flr_clear_flows, nbl_res_flr_clear_flow);			\
	NBL_FLOW_SET_OPS(cfg_duppkt_mcc, nbl_res_flow_cfg_duppkt_mcc);			\
	NBL_FLOW_SET_OPS(add_nd_upcall_flow, nbl_res_flow_add_nd_upcall_flow);		\
	NBL_FLOW_SET_OPS(del_nd_upcall_flow, nbl_res_flow_del_nd_upcall_flow);		\
	NBL_FLOW_SET_OPS(set_mtu, nbl_res_set_mtu);					\
	NBL_FLOW_SET_OPS(cfg_mirror_outputport_event, nbl_flow_cfg_mirror_outputport_event);	\
	NBL_FLOW_SET_OPS(check_flow_table_spec, nbl_res_flow_check_flow_table_spec);	\
} while (0)

static void nbl_flow_remove_mgt(struct device *dev, struct nbl_resource_mgt *res_mgt)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	int i;
	struct nbl_hash_xy_tbl_del_key del_key;

	NBL_HASH_XY_TBL_DEL_KEY_INIT(&del_key, res_mgt, &nbl_flow_macvlan_node_del_action_func);
	for (i = 0; i < NBL_MAX_ETHERNET; i++) {
		nbl_common_remove_hash_xy_table(flow_mgt->switch_res[i].mac_hash_tbl, &del_key);
		if (flow_mgt->switch_res[i].vf_bitmap)
			devm_kfree(dev, flow_mgt->switch_res[i].vf_bitmap);
	}

	if (flow_mgt->flow_id_bitmap)
		devm_kfree(dev, flow_mgt->flow_id_bitmap);
	if (flow_mgt->mcc_id_bitmap)
		devm_kfree(dev, flow_mgt->mcc_id_bitmap);
	flow_mgt->flow_id_cnt = 0;
	devm_kfree(dev, flow_mgt);
	NBL_RES_MGT_TO_FLOW_MGT(res_mgt) = NULL;
}

static int nbl_flow_setup_mgt(struct device *dev, struct nbl_resource_mgt *res_mgt)
{
	struct nbl_hash_xy_tbl_key macvlan_tbl_key;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_eth_info *eth_info;
	int i;
	int vf_num = -1;
	u16 pf_id;

	flow_mgt = devm_kzalloc(dev, sizeof(struct nbl_flow_mgt), GFP_KERNEL);
	if (!flow_mgt)
		return -ENOMEM;

	NBL_RES_MGT_TO_FLOW_MGT(res_mgt) = flow_mgt;
	eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);

	flow_mgt->flow_id_bitmap = devm_kcalloc(dev, BITS_TO_LONGS(NBL_MACVLAN_TABLE_LEN),
						sizeof(long), GFP_KERNEL);
	if (!flow_mgt->flow_id_bitmap)
		goto setup_mgt_failed;
	flow_mgt->flow_id_cnt = NBL_MACVLAN_TABLE_LEN;

	flow_mgt->mcc_id_bitmap = devm_kcalloc(dev, BITS_TO_LONGS(NBL_FLOW_MCC_INDEX_SIZE),
					       sizeof(long), GFP_KERNEL);
	if (!flow_mgt->mcc_id_bitmap)
		goto setup_mgt_failed;

	NBL_HASH_XY_TBL_KEY_INIT(&macvlan_tbl_key, dev, ETH_ALEN, sizeof(u16),
				 sizeof(struct nbl_flow_l2_data),
				 NBL_MACVLAN_TBL_BUCKET_SIZE, NBL_MACVLAN_X_AXIS_BUCKET_SIZE,
				 NBL_MACVLAN_Y_AXIS_BUCKET_SIZE, false);
	for (i = 0; i < NBL_MAX_ETHERNET; i++) {
		INIT_LIST_HEAD(&flow_mgt->switch_res[i].allmulti_head);
		INIT_LIST_HEAD(&flow_mgt->switch_res[i].allmulti_list);
		INIT_LIST_HEAD(&flow_mgt->switch_res[i].mcc_group_head);

		flow_mgt->switch_res[i].mac_hash_tbl =
				nbl_common_init_hash_xy_table(&macvlan_tbl_key);
		if (!flow_mgt->switch_res[i].mac_hash_tbl)
			goto setup_mgt_failed;
		pf_id = find_first_bit((unsigned long *)&eth_info->pf_bitmap[i], 8);
		if (pf_id != 8)
			vf_num = nbl_res_get_pf_vf_num(res_mgt, pf_id);

		if (vf_num != -1) {
			flow_mgt->switch_res[i].num_vfs = vf_num;
			flow_mgt->switch_res[i].vf_bitmap = devm_kcalloc(dev, BITS_TO_LONGS(vf_num),
									 sizeof(long), GFP_KERNEL);
			if (!flow_mgt->switch_res[i].vf_bitmap)
				goto setup_mgt_failed;
		} else {
			flow_mgt->switch_res[i].num_vfs = 0;
			flow_mgt->switch_res[i].vf_bitmap = NULL;
		}
		flow_mgt->switch_res[i].active_vfs = 0;
	}

	memset(flow_mgt->mirror_outputport_func, 0xff, sizeof(flow_mgt->mirror_outputport_func));
	INIT_LIST_HEAD(&flow_mgt->lldp_list);
	INIT_LIST_HEAD(&flow_mgt->lacp_list);
	INIT_LIST_HEAD(&flow_mgt->ul4s_head);
	INIT_LIST_HEAD(&flow_mgt->dprbac_head);
	INIT_LIST_HEAD(&flow_mgt->nd_upcall_list);
	INIT_LIST_HEAD(&flow_mgt->ecn_list);

	flow_mgt->vsi_max_per_switch = NBL_VSI_MAX_ID / eth_info->eth_num;

	return 0;

setup_mgt_failed:
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
