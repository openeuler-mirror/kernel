// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_flow_draco.h"
#include "nbl_p4_actions.h"
#include "nbl_resource.h"
#include "nbl_resource_draco.h"

static int nbl_flow_cfg_kt_action_macvlan(union nbl_common_data_u *data, u8 ab, u16 ad)
{
	union nbl_phy_l2_data_u *kt_data = (union nbl_phy_l2_data_u *)data;

	kt_data->info.base_ab = ab;
	kt_data->info.base_ad = ad;

	return 0;
}

static int nbl_flow_cfg_action_macvlan(struct nbl_flow_param param, u8 *ab, u16 *ad)
{
	union nbl_base_action_bits base_ab = {.data = 0};
	union dport_action set_dport = {.data = 0};

	base_ab.baseab.SET_DEST = 1;
	base_ab.baseab.SET_UDF = 0;
	base_ab.baseab.VLAN_OP = 0;

	if (param.mcc_id == NBL_MCC_ID_INVALID) {
		set_dport.up.vsi_id = param.vsi_id;
		set_dport.up.DQ_V = 0;
		set_dport.up.dir = DPORT_DIR_RX;
		set_dport.up.strip_act = 0;
		set_dport.up.next_stg = NBL_NEXT_STAGE_PP1;
	} else {
		set_dport.mcc.mgid = param.mcc_id;
		set_dport.mcc.other_type = DPORT_OTHER_TYPE_MC;
		set_dport.mcc.dir = DPORT_DIR_OTHER;
		set_dport.mcc.strip_act = 0;
		set_dport.mcc.next_stg = NBL_NEXT_STAGE_INIT;
	}

	*ab = base_ab.data;
	*ad = set_dport.data;

	return 0;
}

static int nbl_flow_cfg_key_value_macvlan(union nbl_common_data_u *data,
					  struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_phy_l2_data_u *kt_data = (union nbl_phy_l2_data_u *)data;
	u64 dst_mac = 0;
	u8 reverse_mac[ETH_ALEN];

	nbl_convert_mac(param.mac, reverse_mac);

	memset(kt_data->hash_key, 0x0, sizeof(kt_data->hash_key));
	ether_addr_copy((u8 *)&dst_mac, reverse_mac);

	kt_data->info.dst_mac = dst_mac;
	kt_data->info.svlan_id = param.vid;
	kt_data->info.template = GET_LKP_ID(is_multicast_ether_addr(param.mac));
	kt_data->info.sport_phy = 1;
	kt_data->info.sport_sw_id = param.eth_id;

	return 0;
}

static int nbl_flow_cfg_action_ipsec_down(struct nbl_flow_param param, u8 *ab, u16 *ad)
{
	union nbl_base_action_bits base_ab = {.data = 0};
	union nbl_action_data set_sec_idx = {.data = 0};

	base_ab.baseab.SET_DEST = 0;
	base_ab.baseab.SET_UDF = 6;
	base_ab.baseab.VLAN_OP = 0;

	set_sec_idx.sec_idx.sec_id = (u16)param.index;
	set_sec_idx.sec_idx.vld = 1;

	*ab = base_ab.data;
	*ad = set_sec_idx.data;

	return 0;
}

static int nbl_flow_cfg_ipsec_down_key_value(union nbl_common_data_u *data,
					     struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_phy_accel_data_u *kt_data = (union nbl_phy_accel_data_u *)data;

	if (param.kt_type == NBL_KT_HALF_MODE) {
		kt_data->ipv4_info.template = NBL_EM0_PT_PHY_DIPSEC_IPV4;
		kt_data->ipv4_info.sip_high = param.data[1] >> 8;
		kt_data->ipv4_info.sip_low = param.data[1];
		kt_data->ipv4_info.dip_high = param.data[5] >> 8;
		kt_data->ipv4_info.dip_low = param.data[5];
		kt_data->ipv4_info.l4_sport = 0;
		kt_data->ipv4_info.l4_dporth = 0;
		kt_data->ipv4_info.l4_dportl = 0;
		kt_data->ipv4_info.sport_phy = 1;
		kt_data->ipv4_info.sport_sw_id = param.eth_id;
		kt_data->ipv4_info.sport_dir = 0;
	} else {
		kt_data->ipv6_info.template = NBL_EM0_PT_PHY_DIPSEC_IPV6;
		kt_data->ipv6_info.sip1 = ((u64)param.data[1] << 24) + ((u64)param.data[2] >> 8);
		kt_data->ipv6_info.sip2 = ((u64)param.data[2] << 56) +
					  ((u64)param.data[3] << 24) + (param.data[4] >> 8);
		kt_data->ipv6_info.sip3 = (u64)param.data[4];
		kt_data->ipv6_info.dip1 = ((u64)param.data[5] << 24) + (param.data[6] >> 8);
		kt_data->ipv6_info.dip2 = ((u64)param.data[6] << 56) +
					  ((u64)param.data[7] << 24) + (param.data[8] >> 8);
		kt_data->ipv6_info.dip3 = (u64)param.data[8];
		kt_data->ipv6_info.l4_sport = 0;
		kt_data->ipv6_info.l4_dport = 0;
		kt_data->ipv6_info.sport_phy = 1;
		kt_data->ipv6_info.sport_sw_id = param.eth_id;
		kt_data->ipv6_info.sport_dir = 0;
	}

	return 0;
}

static int nbl_flow_cfg_kt_action_ipsec_down(union nbl_common_data_u *data,
					     u8 ab, u16 ad)
{
	union nbl_phy_accel_data_u *kt_data = (union nbl_phy_accel_data_u *)data;

	if (kt_data->ipv6_info.template) {
		kt_data->ipv6_info.base_ab = ab;
		//kt_data->ipv6_info.base_ad = ad;
	} else {
		kt_data->ipv4_info.base_ab = ab;
		kt_data->ipv4_info.base_ad = ad;
	}

	return 0;
}

static int nbl_flow_cfg_action_tls_up(struct nbl_flow_param param, u8 *ab, u16 *ad)
{
	union nbl_base_action_bits base_ab = {.data = 0};
	union nbl_action_data set_sec_idx = {.data = 0};

	base_ab.baseab.SET_DEST = 0;
	base_ab.baseab.SET_UDF = 6;
	base_ab.baseab.VLAN_OP = 0;

	set_sec_idx.sec_idx.sec_id = (u16)param.index;
	set_sec_idx.sec_idx.vld = 1;

	*ab = base_ab.data;
	*ad = set_sec_idx.data;

	return 0;
}

static int nbl_flow_cfg_tls_up_key_value(union nbl_common_data_u *data,
					 struct nbl_flow_param param, u8 eth_mode)
{
	union nbl_phy_accel_data_u *kt_data = (union nbl_phy_accel_data_u *)data;

	if (param.kt_type == NBL_KT_HALF_MODE) {
		kt_data->ipv4_info.template = NBL_EM0_PT_PHY_UTLS_IPV4;
		kt_data->ipv4_info.sip_high = param.data[1] >> 8;
		kt_data->ipv4_info.sip_low = param.data[1];
		kt_data->ipv4_info.dip_high = param.data[5] >> 8;
		kt_data->ipv4_info.dip_low = param.data[5];
		kt_data->ipv4_info.l4_sport = param.data[9];
		kt_data->ipv4_info.l4_dporth = param.data[10] >> 8;
		kt_data->ipv4_info.l4_dportl = param.data[10];
		kt_data->ipv4_info.sport_phy = 1;
		kt_data->ipv4_info.sport_sw_id = param.eth_id;
		kt_data->ipv4_info.sport_dir = 1;
	} else {
		kt_data->ipv6_info.template = NBL_EM0_PT_PHY_UTLS_IPV6;
		kt_data->ipv6_info.sip1 = ((u64)param.data[1] << 24) + ((u64)param.data[2] >> 8);
		kt_data->ipv6_info.sip2 = ((u64)param.data[2] << 56) +
					  ((u64)param.data[3] << 24) + (param.data[4] >> 8);
		kt_data->ipv6_info.sip3 = (u64)param.data[4];
		kt_data->ipv6_info.dip1 = ((u64)param.data[5] << 24) + (param.data[6] >> 8);
		kt_data->ipv6_info.dip2 = ((u64)param.data[6] << 56) +
					  ((u64)param.data[7] << 24) + (param.data[8] >> 8);
		kt_data->ipv6_info.dip3 = (u64)param.data[8];
		kt_data->ipv6_info.l4_sport = param.data[9];
		kt_data->ipv6_info.l4_dport = param.data[10];
		kt_data->ipv6_info.sport_phy = 1;
		kt_data->ipv6_info.sport_sw_id = param.eth_id;
		kt_data->ipv6_info.sport_dir = 1;
	}

	return 0;
}

static int nbl_flow_cfg_kt_action_tls_up(union nbl_common_data_u *data, u8 ab, u16 ad)
{
	union nbl_phy_accel_data_u *kt_data = (union nbl_phy_accel_data_u *)data;

	if (kt_data->ipv6_info.template) {
		kt_data->ipv6_info.base_ab = ab;
		// kt_data->ipv6_info.base_ad = ad;
	} else {
		kt_data->ipv4_info.base_ab = ab;
		kt_data->ipv4_info.base_ad = ad;
	}

	return 0;
}

#define NBL_FLOW_OPS_ARR_ENTRY(type, action_func, kt_func, kt_action_func)	\
	[type] = {.cfg_action = action_func,					\
		  .cfg_key = kt_func,						\
		  .cfg_kt_action = kt_action_func				\
		}
static const struct nbl_flow_rule_cfg_ops cfg_ops[] = {
	NBL_FLOW_OPS_ARR_ENTRY(NBL_PHY_FLOW_MACVLAN,
			       nbl_flow_cfg_action_macvlan,
			       nbl_flow_cfg_key_value_macvlan,
			       nbl_flow_cfg_kt_action_macvlan),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_PHY_FLOW_DIPSEC,
			       nbl_flow_cfg_action_ipsec_down,
			       nbl_flow_cfg_ipsec_down_key_value,
			       nbl_flow_cfg_kt_action_ipsec_down),
	NBL_FLOW_OPS_ARR_ENTRY(NBL_PHY_FLOW_UTLS,
			       nbl_flow_cfg_action_tls_up,
			       nbl_flow_cfg_tls_up_key_value,
			       nbl_flow_cfg_kt_action_tls_up),
};

static int nbl_flow_cfg_req_head_ktalloc(union nbl_fem_cmd_head_u *req_head,
					 struct nbl_flow_param *param)
{
	memset(req_head->head_data, 0x0, sizeof(req_head->head_data));

	req_head->info.module = NBL_FEM_CMD_HEAD_MODULE_FEM;
	req_head->info.opcode = NBL_FEM_CMD_HEAD_OPCODE_KTALLOC;
	req_head->info.cmd_len = 16;

	return 0;
}

static int nbl_flow_cfg_req_param_ktalloc(union nbl_fem_cmd_data_u *data,
					  struct nbl_flow_param *param)
{
	union nbl_fem_req_param_ktalloc_u *req_param = (union nbl_fem_req_param_ktalloc_u *)data;

	memset(req_param->param_data, 0x0, sizeof(req_param->param_data));

	req_param->info.pf_id = param->pf_id;

	return 0;
}

static int nbl_flow_cfg_req_head_ktfree(union nbl_fem_cmd_head_u *req_head,
					struct nbl_flow_param *param)
{
	memset(req_head->head_data, 0x0, sizeof(req_head->head_data));

	req_head->info.module = NBL_FEM_CMD_HEAD_MODULE_FEM;
	req_head->info.opcode = NBL_FEM_CMD_HEAD_OPCODE_KTFREE;
	req_head->info.cmd_len = 16;

	return 0;
}

static int nbl_flow_cfg_req_param_ktfree(union nbl_fem_cmd_data_u *data,
					 struct nbl_flow_param *param)
{
	union nbl_fem_req_param_ktfree_u *req_param = (union nbl_fem_req_param_ktfree_u *)data;

	memset(req_param->param_data, 0x0, sizeof(req_param->param_data));

	req_param->info.mode = NBL_FEM_CMD_PARAM_KTFREE_MODE_PF;
	req_param->info.pf_id = param->pf_id;

	return 0;
}

static int nbl_flow_cfg_req_head_tbladd(union nbl_fem_cmd_head_u *req_head,
					struct nbl_flow_param *param)
{
	memset(req_head->head_data, 0x0, sizeof(req_head->head_data));

	req_head->info.module = NBL_FEM_CMD_HEAD_MODULE_FEM;
	req_head->info.opcode = NBL_FEM_CMD_HEAD_OPCODE_TBLADD;
	req_head->info.cmd_len = 76;

	return 0;
}

static int nbl_flow_cfg_req_param_tbladd(union nbl_fem_cmd_data_u *data,
					 struct nbl_flow_param *param)
{
	union nbl_fem_req_param_tbladd_u *req_param = (union nbl_fem_req_param_tbladd_u *)data;

	memset(req_param->param_data, 0x0, sizeof(req_param->param_data));

	req_param->info.pf_id = param->pf_id;
	req_param->info.oft = param->alloc_oft;
	req_param->info.kt_mode = param->kt_mode;
	req_param->info.kt_idx = param->kt_idx;
	if (param->kt_type == NBL_KT_HALF_MODE) {
		memcpy(req_param->info.key + 42, param->key, param->key_len);
	} else {
		memcpy(req_param->info.key + 22, param->key, param->key_len);
		memcpy(req_param->info.key + 20, &param->sec_idx, 2);
	}

	return 0;
}

static int nbl_flow_cfg_req_head_tbllookup(union nbl_fem_cmd_head_u *req_head,
					   struct nbl_flow_param *param)
{
	memset(req_head->head_data, 0x0, sizeof(req_head->head_data));

	req_head->info.module = NBL_FEM_CMD_HEAD_MODULE_FEM;
	req_head->info.opcode = NBL_FEM_CMD_HEAD_OPCODE_TBLLOOKUP;
	req_head->info.cmd_len = 56;

	return 0;
}

static int nbl_flow_cfg_req_param_tbllookup(union nbl_fem_cmd_data_u *data,
					    struct nbl_flow_param *param)
{
	union nbl_fem_req_param_tbllookup_u *req_param;

	req_param = (union nbl_fem_req_param_tbllookup_u *)data;
	memset(req_param->param_data, 0x0, sizeof(req_param->param_data));

	req_param->info.sport_flag = param->template;
	req_param->info.del_on_hit = param->del_on_hit;
	req_param->info.mode = param->lkp_mode;
	req_param->info.pf_id = param->pf_id;
	if (param->kt_type == NBL_KT_HALF_MODE)
		memcpy(req_param->info.lkp_key + 20, param->key, param->key_len);
	else
		memcpy(req_param->info.lkp_key, param->key, param->key_len);
	req_param->info.ht_id = param->ht_id;
	req_param->info.ht_slot_id = param->ht_slot_id;
	req_param->info.kt_idx = param->kt_idx;

	return 0;
}

static int nbl_flow_cfg_req_head_tblread(union nbl_fem_cmd_head_u *req_head,
					 struct nbl_flow_param *param)
{
	memset(req_head->head_data, 0x0, sizeof(req_head->head_data));

	req_head->info.module = NBL_FEM_CMD_HEAD_MODULE_FEM;
	req_head->info.table = param->tbl_to_read;
	req_head->info.opcode = NBL_FEM_CMD_HEAD_OPCODE_TBLREAD;
	req_head->info.cmd_len = NBL_FEM_CMD_HEAD_READ_CMD_LEN;

	return 0;
}

static int nbl_flow_cfg_req_param_tblread(union nbl_fem_cmd_data_u *data,
					  struct nbl_flow_param *param)
{
	union nbl_fem_req_param_tblread_u *req_param;

	req_param = (union nbl_fem_req_param_tblread_u *)data;
	memset(req_param->param_data, 0x0, sizeof(req_param->param_data));

	switch (param->tbl_to_read) {
	case NBL_FEM_CMD_HEAD_TABLE_OFT_AT:
		req_param->oftad.pf_id = param->pf_id;
		req_param->oftad.tbl_addr = param->read_addr & 0x3f;
		break;
	case NBL_FEM_CMD_HEAD_TABLE_KT_BIND_PF:
		req_param->kt_bind_pf.pf_id = param->pf_id;
		break;
	default:
		break;
	}
	return 0;
}

static int nbl_flow_cfg_req_head_tblwrite(union nbl_fem_cmd_head_u *req_head,
					  struct nbl_flow_param *param)
{
	memset(req_head->head_data, 0x0, sizeof(req_head->head_data));

	req_head->info.module = NBL_FEM_CMD_HEAD_MODULE_FEM;
	req_head->info.opcode = NBL_FEM_CMD_HEAD_OPCODE_TBLWRITE;
	req_head->info.cmd_len = NBL_FEM_CMD_HEAD_WRITE_CMD_LEN;
	req_head->info.table = param->tbl_to_write;

	return 0;
}

static int nbl_flow_cfg_req_param_tblwrite(union nbl_fem_cmd_data_u *data,
					   struct nbl_flow_param *param)
{
	union nbl_fem_req_param_tblwrite_u *req_param;

	req_param = (union nbl_fem_req_param_tblwrite_u *)data;
	memset(req_param->param_data, 0x0, sizeof(req_param->param_data));

	switch (param->tbl_to_write) {
	case NBL_DRACO_DFT_TBL:
		req_param->dft_tbl.pf_id = param->pf_id;
		req_param->dft_tbl.tbl_addr = param->dft_addr;
		break;
	case NBL_DRACO_PROFILE_TBL:
	default:
		break;
	}

	memcpy(req_param->dft_tbl.data, param->tbl, NBL_DRACO_CMD_TBLWRITE_DFT_DATALEN);

	return 0;
}

#define NBL_FLOW_CMD_OPS_ARR_ENTRY(type, cfg_req_head_func, cfg_req_param_func)	\
	[type] = {.cfg_req_head = cfg_req_head_func,				\
		  .cfg_req_param = cfg_req_param_func,				\
		}
static const struct nbl_fem_cmd_cfg_ops cmd_cfg_ops[] = {
	NBL_FLOW_CMD_OPS_ARR_ENTRY(NBL_FEM_CMD_HEAD_OPCODE_KTALLOC,
				   nbl_flow_cfg_req_head_ktalloc,
				   nbl_flow_cfg_req_param_ktalloc),
	NBL_FLOW_CMD_OPS_ARR_ENTRY(NBL_FEM_CMD_HEAD_OPCODE_KTFREE,
				   nbl_flow_cfg_req_head_ktfree,
				   nbl_flow_cfg_req_param_ktfree),
	NBL_FLOW_CMD_OPS_ARR_ENTRY(NBL_FEM_CMD_HEAD_OPCODE_TBLADD,
				   nbl_flow_cfg_req_head_tbladd,
				   nbl_flow_cfg_req_param_tbladd),
	NBL_FLOW_CMD_OPS_ARR_ENTRY(NBL_FEM_CMD_HEAD_OPCODE_TBLLOOKUP,
				   nbl_flow_cfg_req_head_tbllookup,
				   nbl_flow_cfg_req_param_tbllookup),
	NBL_FLOW_CMD_OPS_ARR_ENTRY(NBL_FEM_CMD_HEAD_OPCODE_TBLREAD,
				   nbl_flow_cfg_req_head_tblread,
				   nbl_flow_cfg_req_param_tblread),
	NBL_FLOW_CMD_OPS_ARR_ENTRY(NBL_FEM_CMD_HEAD_OPCODE_TBLWRITE,
				   nbl_flow_cfg_req_head_tblwrite,
				   nbl_flow_cfg_req_param_tblwrite),
};

static int nbl_flow_alloc_kt(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_flow_param param = {0};
	union nbl_fem_cmd_head_u req_head = {.info = {0}};
	union nbl_fem_cmd_data_u req_param;
	union nbl_fem_cmd_head_u resp_head = {.info = {0}};
	union nbl_fem_resp_data_ktalloc_u resp_data = {.info = {0}};
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	int ret = 0;

	memset(&req_param, 0, sizeof(req_param));

	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_KTALLOC].cfg_req_head(&req_head, &param);
	if (ret)
		return ret;

	param.pf_id = pf_id;
	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_KTALLOC].cfg_req_param(&req_param, &param);
	if (ret)
		return ret;

	ret = phy_ops->alloc_kt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), pf_id,
				req_head.head_data, req_param.cmd_data,
				resp_head.head_data, resp_data.resp_data);

	if (!ret && resp_head.info.status == NBL_FEM_CMD_HEAD_STATUS_SUCCESS) {
		/* kt_idx 0 is invalid, use from kt_idx 1 */
		if (!(resp_data.info.kt_idx)) {
			resp_data.info.kt_idx = 1;
			flow_mgt->max_flow_idx = NBL_MAX_MACVLAN_NUM - 1;
		} else {
			flow_mgt->max_flow_idx = NBL_MAX_MACVLAN_NUM;
		}
		flow_mgt->start_flow_idx = resp_data.info.kt_idx;
		dev_info(dev, "Alloc kt success, start kt_idx:%d\n", resp_data.info.kt_idx);
	} else {
		dev_err(dev, "Alloc kt failed, ret:%d, status:%d, errcode:%d, kt_idx:%d\n",
			ret, resp_head.info.status, resp_head.info.errcode, resp_data.info.kt_idx);
		ret = EIO;
	}

	return ret;
}

static int nbl_flow_free_kt(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_flow_param param = {0};
	union nbl_fem_cmd_head_u req_head = {.info = {0}};
	union nbl_fem_cmd_data_u req_param;
	union nbl_fem_cmd_head_u resp_head = {.info = {0}};
	union nbl_fem_resp_data_ktfree_u resp_data;
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	int ret = 0;

	memset(&req_param, 0, sizeof(req_param));
	memset(&resp_data, 0, sizeof(resp_data));

	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_KTFREE].cfg_req_head(&req_head, &param);
	if (ret)
		return ret;

	param.pf_id = pf_id;
	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_KTFREE].cfg_req_param(&req_param, &param);
	if (ret)
		return ret;

	ret = phy_ops->free_kt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), pf_id,
			       req_head.head_data, req_param.cmd_data,
			       resp_head.head_data, resp_data.resp_data);

	if (resp_head.info.status == NBL_FEM_CMD_HEAD_STATUS_SUCCESS) {
		dev_info(dev, "Free kt of pf %d success\n", pf_id);
	} else {
		dev_err(dev, "Free kt of pf %d failed, status:%d, errcode:%d\n",
			pf_id, resp_head.info.status, resp_head.info.errcode);
		ret = EIO;
	}

	return ret;
}

static int nbl_flow_alloc_flow_id(struct nbl_flow_mgt *flow_mgt, struct nbl_flow_fem_entry *flow)
{
	u32 flow_id;

	if (flow->kt_type == NBL_KT_HALF_MODE) {
		flow_id = find_first_zero_bit(flow_mgt->flow_id_bitmap, flow_mgt->max_flow_idx);
		if (flow_id >= flow_mgt->max_flow_idx)
			return -ENOSPC;
		set_bit(flow_id, flow_mgt->flow_id_bitmap);
		flow_mgt->flow_id_cnt--;
	} else {
		flow_id = nbl_common_find_available_idx(flow_mgt->flow_id_bitmap,
							flow_mgt->max_flow_idx, 2, 2);
		if (flow_id >= flow_mgt->max_flow_idx)
			return -ENOSPC;
		set_bit(flow_id, flow_mgt->flow_id_bitmap);
		set_bit(flow_id + 1, flow_mgt->flow_id_bitmap);
		flow_mgt->flow_id_cnt -= 2;
	}

	flow->flow_id = flow_id;
	flow->kt_idx = flow_mgt->start_flow_idx + NBL_EM_PHY_KT_OFFSET + flow->flow_id;
	if (flow->kt_type == NBL_KT_FULL_MODE && (flow->kt_idx % 2))
		flow->kt_idx++;

	return 0;
}

static void nbl_flow_free_flow_id(struct nbl_flow_mgt *flow_mgt, struct nbl_flow_fem_entry *flow)
{
	if (flow->flow_id == U16_MAX)
		return;

	if (flow->kt_type == NBL_KT_HALF_MODE) {
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

static int nbl_flow_alloc_mcc_id(struct nbl_flow_mgt *flow_mgt,
				 u8 eth_id, u8 eth_num, u16 *alloc_mcc_id)
{
	u32 mcc_id;

	mcc_id = find_first_zero_bit(flow_mgt->switch_res[0].mcc_id_bitmap,
				     NBL_DRACO_ETH_MAX_MCC_NUM(eth_num));
	if (mcc_id == NBL_DRACO_ETH_MAX_MCC_NUM(eth_num))
		return -ENOSPC;

	set_bit(mcc_id, flow_mgt->switch_res[0].mcc_id_bitmap);

	*alloc_mcc_id = mcc_id + NBL_DRACO_ETH_MCC_ID_BASE(eth_id);

	return 0;
}

static void nbl_flow_free_mcc_id(struct nbl_flow_mgt *flow_mgt, u32 mcc_id, u8 eth_id)
{
	clear_bit((mcc_id - NBL_DRACO_ETH_MCC_ID_BASE(eth_id)),
		  flow_mgt->switch_res[0].mcc_id_bitmap);
}

static int nbl_flow_search_key(struct nbl_resource_mgt *res_mgt, u8 *search_key, u8 kt_type)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_flow_param param = {0};
	union nbl_fem_cmd_head_u req_head = {.info = {0}};
	union nbl_fem_cmd_data_u req_param;
	union nbl_fem_cmd_head_u resp_head = {.info = {0}};
	union nbl_fem_resp_data_tbllookup_u resp_data = {.info = {0}};
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	u16 ht_index;
	u16 hash_bucket;
	u16 ht0_hash;
	u16 ht1_hash;
	u16 hash_table;
	u32 kt_idx;
	u16 tcam_table;
	u16 tcam_index;
	int ret = 0;

	memset(&req_param, 0, sizeof(req_param));

	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLLOOKUP].cfg_req_head(&req_head, &param);
	if (ret)
		return ret;

	param.template = 0;
	param.del_on_hit = 0;
	param.lkp_mode = NBL_FEM_CMD_PARAM_MODE_NORMAL;
	param.pf_id = pf_id;
	param.key = search_key;
	if (kt_type == NBL_KT_HALF_MODE) {
		param.kt_type = NBL_KT_HALF_MODE;
		param.key_len = 20;
	} else if (kt_type == NBL_KT_FULL_MODE) {
		param.kt_type = NBL_KT_FULL_MODE;
		param.key_len = 40;
	}

	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLLOOKUP].cfg_req_param(&req_param, &param);
	if (ret)
		return ret;

	nbl_debug(common, NBL_DEBUG_FLOW, "Search key:0x%08x-%08x-%08x-%08x-%08x-%08x-%08x-%08x-%08x-%08x",
		  ((u32 *)search_key)[9], ((u32 *)search_key)[8],
		  ((u32 *)search_key)[7], ((u32 *)search_key)[6],
		  ((u32 *)search_key)[5], ((u32 *)search_key)[4],
		  ((u32 *)search_key)[3], ((u32 *)search_key)[2],
		  ((u32 *)search_key)[1], ((u32 *)search_key)[0]);

	ret = phy_ops->lookup_key(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), pf_id,
				  req_head.head_data, req_param.cmd_data,
				  resp_head.head_data, resp_data.resp_data);

	if (!ret && resp_head.info.status == NBL_FEM_CMD_HEAD_STATUS_SUCCESS) {
		if (resp_data.info.hit_pos == NBL_FEM_CMD_PARAM_HIT_POS_HT_KT) {
			hash_table = (resp_data.info.ht_addr & 0x4000) >> 14;
			ht_index = resp_data.info.ht_addr & 0x3FFF;
			hash_bucket = resp_data.info.slot_id;
			ht0_hash = resp_data.info.hash0_idx;
			ht1_hash = resp_data.info.hash1_idx;
			kt_idx = resp_data.info.kt_idx;

			nbl_debug(common, NBL_DEBUG_FLOW, "Hit ht, response data - kt_idx:%d, hash_table:%d, ht_index:%d, hash_bucket:%d, ht0_hash:0x%x, ht1_hash:0x%x, ab:0x%x, ad:0x%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x\n",
				  kt_idx, hash_table, ht_index, hash_bucket, ht0_hash, ht1_hash,
				  resp_data.info.ab, resp_data.info.ad_l[0], resp_data.info.ad_l[1],
				  resp_data.info.ad_l[2], resp_data.info.ad_l[3],
				  resp_data.info.ad_l[4], resp_data.info.ad_l[5],
				  resp_data.info.ad_l[6], resp_data.info.ad_l[7],
				  resp_data.info.ad_l[8], resp_data.info.ad_l[9],
				  resp_data.info.ad_l[10], resp_data.info.ad_h);
		} else if (resp_data.info.hit_pos == NBL_FEM_CMD_PARAM_HIT_POS_OFT) {
			tcam_table = resp_data.info.ht_addr & 0x1;
			tcam_index = (resp_data.info.ht_addr & 0x7E) >> 1;
			kt_idx = resp_data.info.kt_idx;

			nbl_debug(common, NBL_DEBUG_FLOW, "Hit tcam, response data - kt_idx:%d, tcam_table:%d, tcam_index:%d, ab:0x%x, ad:0x%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x\n",
				  kt_idx, tcam_table, tcam_index,
				  resp_data.info.ab, resp_data.info.ad_l[0], resp_data.info.ad_l[1],
				  resp_data.info.ad_l[2], resp_data.info.ad_l[3],
				  resp_data.info.ad_l[4], resp_data.info.ad_l[5],
				  resp_data.info.ad_l[6], resp_data.info.ad_l[7],
				  resp_data.info.ad_l[8], resp_data.info.ad_l[9],
				  resp_data.info.ad_l[10], resp_data.info.ad_h);
		}
	} else {
		dev_err(dev, "Search kt/tcam failed, ret:%d, status:%d, errcode:%d\n",
			ret, resp_head.info.status, resp_head.info.errcode);
		ret = EIO;
	}

	return ret;
}

static int nbl_flow_send_2hw(struct nbl_resource_mgt *res_mgt,
			     struct nbl_kt_item kt_item, struct nbl_flow_fem_entry *flow)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_flow_param param = {0};
	union nbl_fem_cmd_head_u req_head = {.info = {0}};
	union nbl_fem_cmd_data_u req_param;
	union nbl_fem_cmd_head_u resp_head = {.info = {0}};
	union nbl_fem_resp_data_tbladd_u resp_data = {.info = {0}};
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	int ret = 0;

	memset(&req_param, 0, sizeof(req_param));

	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLADD].cfg_req_head(&req_head, &param);
	if (ret)
		return ret;

	param.pf_id = pf_id;
	param.alloc_oft = NBL_FEM_CMD_PARAM_OFT_ENABLE;
	param.kt_idx = flow->kt_idx;
	param.kt_mode = NBL_FEM_CMD_PARAM_KT_MODE_160;
	param.key = kt_item.kt_data.hash_key;
	if (flow->kt_type == NBL_KT_HALF_MODE) {
		param.key_len = 20;
		param.kt_type = NBL_KT_HALF_MODE;
	} else if (flow->kt_type == NBL_KT_FULL_MODE) {
		param.key_len = 40;
		param.kt_type = NBL_KT_FULL_MODE;
		param.sec_idx = flow->sec_idx;
	}

	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLADD].cfg_req_param(&req_param, &param);
	if (ret)
		return ret;

	ret = phy_ops->add_kt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), pf_id,
			      req_head.head_data, req_param.cmd_data,
			      resp_head.head_data, resp_data.resp_data);

	if (!ret && resp_head.info.status == NBL_FEM_CMD_HEAD_STATUS_SUCCESS) {
		if (resp_data.info.tbl_type == NBL_FEM_CMD_PARAM_TBL_TYPE_HT) {
			flow->tcam_flag = false;
			flow->hash_table = (resp_data.info.tbl_idx & 0x4000) >> 14;
			flow->ht_index = resp_data.info.tbl_idx & 0x3FFF;
			flow->hash_bucket = resp_data.info.slot_id;
			flow->ht0_hash = resp_data.info.hash_data0;
			flow->ht1_hash = resp_data.info.hash_data1;
			memcpy(flow->key, param.key, param.key_len);
		} else if (resp_data.info.tbl_type == NBL_FEM_CMD_PARAM_TBL_TYPE_OFT) {
			flow->tcam_flag = true;
			flow->tcam_table = resp_data.info.tbl_idx & 0x1;
			flow->tcam_index = (resp_data.info.tbl_idx & 0x7E) >> 1;
			memcpy(flow->key, param.key, param.key_len);
		}
	} else {
		dev_err(dev, "Add kt failed for kt_idx:%d, ret:%d, status:%d, errcode:%d\n",
			param.kt_idx, ret, resp_head.info.status, resp_head.info.errcode);
		ret = EIO;
		goto set_kt_fail;
	}

	nbl_debug(common, NBL_DEBUG_FLOW,
		  "%s flow->key = %08x-%08x-%08x-%08x-%08x|%08x-%08x-%08x-%08x-%08x\n",
		  __func__, ((u32 *)flow->key)[0], ((u32 *)flow->key)[1], ((u32 *)flow->key)[2],
		  ((u32 *)flow->key)[3], ((u32 *)flow->key)[4], ((u32 *)flow->key)[5],
		  ((u32 *)flow->key)[6], ((u32 *)flow->key)[7], ((u32 *)flow->key)[8],
		  ((u32 *)flow->key)[9]);

	ret = nbl_flow_search_key(res_mgt, kt_item.kt_data.hash_key, flow->kt_type);
	if (ret)
		goto search_fail;

	return 0;

search_fail:
set_kt_fail:
	return ret;
}

static int nbl_flow_add_flow(struct nbl_resource_mgt *res_mgt, struct nbl_flow_param param,
			     s32 type, struct nbl_flow_fem_entry *flow)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_kt_item kt_item;
	u8 ab = 0;
	u16 ad = 0;
	int ret = 0;

	if (flow_mgt->offload_status)
		return 0;

	memset(&kt_item, 0, sizeof(kt_item));
	flow->kt_type = param.kt_type;
	flow->type = type;
	flow->flow_id = 0xFFFF;

	ret = nbl_flow_alloc_flow_id(flow_mgt, flow);
	if (ret)
		goto alloc_flow_id_fail;

	ret = cfg_ops[type].cfg_action(param, &ab, &ad);
	if (ret)
		goto cfg_action_fail;

	ret = cfg_ops[type].cfg_key(&kt_item.kt_data, param, NBL_COMMON_TO_ETH_MODE(common));
	if (ret)
		goto cfg_key_fail;

	ret = cfg_ops[type].cfg_kt_action(&kt_item.kt_data, ab, ad);
	if (ret)
		goto cfg_kt_action_fail;

	flow->sec_idx = ad;
	ret = nbl_flow_send_2hw(res_mgt, kt_item, flow);
	if (ret)
		goto send_2hw_fail;

	return 0;

send_2hw_fail:
cfg_kt_action_fail:
cfg_key_fail:
cfg_action_fail:
	nbl_flow_free_flow_id(flow_mgt, flow);
alloc_flow_id_fail:
	return ret;
}

/* del ht or overflow tcam, donot del kt */
static int nbl_flow_del_2hw(struct nbl_resource_mgt *res_mgt, struct nbl_flow_fem_entry *flow)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_flow_param param = {0};
	union nbl_fem_cmd_head_u req_head = {.info = {0}};
	union nbl_fem_cmd_data_u req_param;
	union nbl_fem_cmd_head_u resp_head = {.info = {0}};
	union nbl_fem_resp_data_tbllookup_u resp_data = {.info = {0}};
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	u16 ht_index;
	u16 hash_bucket;
	u16 ht0_hash;
	u16 ht1_hash;
	u16 hash_table;
	u32 kt_idx;
	u16 tcam_table;
	u16 tcam_index;
	int ret = 0;

	memset(&req_param, 0, sizeof(req_param));

	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLLOOKUP].cfg_req_head(&req_head, &param);
	if (ret)
		return ret;

	param.del_on_hit = 1;
	param.lkp_mode = NBL_FEM_CMD_PARAM_MODE_FAST;
	param.pf_id = pf_id;
	param.ht_id = flow->hash_table;
	param.ht_slot_id = flow->hash_bucket;
	param.kt_idx = flow->kt_idx;
	param.key = flow->key;
	param.kt_type = flow->kt_type;
	param.key_len =
		(flow->kt_type == NBL_KT_HALF_MODE ? NBL_KT_BYTE_HALF_LEN : NBL_KT_BYTE_LEN);
	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLLOOKUP].cfg_req_param(&req_param, &param);
	if (ret)
		return ret;

	ret = phy_ops->del_ht_oft(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), pf_id,
			      req_head.head_data, req_param.cmd_data,
			      resp_head.head_data, resp_data.resp_data);

	if (!ret && resp_head.info.status == NBL_FEM_CMD_HEAD_STATUS_SUCCESS) {
		if (resp_data.info.hit_pos == NBL_FEM_CMD_PARAM_HIT_POS_HT_KT) {
			hash_table = (resp_data.info.ht_addr & 0x4000) >> 14;
			ht_index = resp_data.info.ht_addr & 0x3FFF;
			hash_bucket = resp_data.info.slot_id;
			ht0_hash = resp_data.info.hash0_idx;
			ht1_hash = resp_data.info.hash1_idx;
			kt_idx = resp_data.info.kt_idx;
		} else if (resp_data.info.hit_pos == NBL_FEM_CMD_PARAM_HIT_POS_OFT) {
			tcam_table = resp_data.info.ht_addr & 0x1;
			tcam_index = (resp_data.info.ht_addr & 0x7E) >> 1;
			kt_idx = resp_data.info.kt_idx;
		}
	} else {
		if ((resp_head.info.status == NBL_FEM_CMD_HEAD_STATUS_FAIL &&
		     resp_head.info.errcode == NBL_FEM_CMD_ERRCODE_NOT_HIT)) {
			ret = 0;
		} else {
			dev_err(dev, "Del %s failed for kt_idx:%d tcam_flag:%d, ret:%d, status:%d, errcode:%d\n",
				flow->tcam_flag ? "tcam" : "ht",
				param.kt_idx, flow->tcam_flag,
				ret, resp_head.info.status, resp_head.info.errcode);
			ret = EIO;
		}
	}

	return ret;
}

static void nbl_flow_del_flow(struct nbl_resource_mgt *res_mgt, struct nbl_flow_fem_entry *flow)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	int ret = 0;

	if (flow->flow_id == 0xFFFF)
		return;

	if (flow_mgt->offload_status)
		goto free_flow_id;

	/* del ht or overflow tcam, donot del kt */
	ret = nbl_flow_del_2hw(res_mgt, flow);

free_flow_id:
	nbl_flow_free_flow_id(flow_mgt, flow);
}

static int nbl_flow_add_mcc_node(struct nbl_resource_mgt *res_mgt,
				 u16 mcc_id, u8 eth_id, u16 vsi_id)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int ret = 0;

	ret = phy_ops->add_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mcc_id, 0,
			       NBL_MCC_ID_INVALID, 0, eth_id, vsi_id);
	if (ret)
		return -EIO;

	return 0;
}

static int nbl_flow_del_mcc_node(struct nbl_resource_mgt *res_mgt,
				 u16 mcc_id, u8 eth_id, u16 vsi_id)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->del_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mcc_id, 0, 0, eth_id, vsi_id);

	return 0;
}

static int nbl_flow_init_mcc_node(struct nbl_resource_mgt *res_mgt, u16 mcc_id)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int ret = 0;

	ret = phy_ops->init_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mcc_id);

	return ret;
}

static int nbl_flow_clear_mcc_node(struct nbl_resource_mgt *res_mgt, u16 mcc_id)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->clear_mcc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), mcc_id);

	return 0;
}

static void nbl_flow_del_multi_group(struct nbl_resource_mgt *res_mgt, u8 eth_id)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_switch_res *res = &flow_mgt->switch_res[0];

	nbl_flow_clear_mcc_node(res_mgt, res->allmulti_mcc_id);

	kfree(res->allmulti_vsi_bitmap);

	nbl_flow_free_mcc_id(flow_mgt, res->allmulti_mcc_id, eth_id);

	res->num_vsi_allmulti_active = 0;
}

static void nbl_flow_remove_multi_group(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);

	nbl_flow_del_multi_group(res_mgt, eth_info->eth_id[pf_id]);
}

static int nbl_flow_cfg_default_action(struct nbl_resource_mgt *res_mgt, u16 mcc_id)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u8 write_data[NBL_DRACO_CMD_TBLWRITE_DFT_DATALEN] = {0};
	struct nbl_draco_tbl_ab_ad *tbl_wdat = (struct nbl_draco_tbl_ab_ad *)write_data;
	union nbl_base_action_bits *ab = (union nbl_base_action_bits *)&tbl_wdat->action_bits;
	union nbl_base_action_datas *ad = (union nbl_base_action_datas *)&tbl_wdat->action_data;
	struct nbl_flow_param param = {0};
	union nbl_fem_cmd_head_u resp_head = {{0}};
	union nbl_fem_cmd_head_u req_head = {{0}};
	union nbl_fem_cmd_data_u req_param;
	union nbl_fem_resp_data_tblwrite_u resp_data;
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	int ret;
	union nbl_fem_req_param_tblwrite_u *tbl_req_param;

	memset(&req_param, 0, sizeof(req_param));
	memset(&resp_data, 0, sizeof(resp_data));

	tbl_req_param = (union nbl_fem_req_param_tblwrite_u *)&req_param;
	param.pf_id = pf_id;
	param.tbl_to_write = NBL_DRACO_DFT_TBL;
	param.dft_addr = eth_info->eth_id[pf_id] + NBL_DRACO_DFT_BASEADDR;
	ab->baseab.SET_DEST = 1;
	ab->baseab.SET_UDF = 0;
	ab->baseab.VLAN_OP = 0;
	ad->dport.mcc.mgid = mcc_id;
	ad->dport.mcc.other_type = DPORT_OTHER_TYPE_MC;
	ad->dport.mcc.dir = DPORT_DIR_OTHER;
	ad->dport.mcc.strip_act = 0;
	ad->dport.mcc.next_stg = NBL_NEXT_STAGE_INIT;
	param.tbl = write_data;

	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLWRITE].cfg_req_head(&req_head, &param);
	ret |= cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLWRITE].cfg_req_param(&req_param, &param);
	if (ret)
		return ret;

	ret = phy_ops->write_fem_tbl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), pf_id,
				    req_head.head_data, req_param.cmd_data,
				    resp_head.head_data, resp_data.resp_data);
	if (ret || resp_head.info.status != NBL_FEM_CMD_HEAD_STATUS_SUCCESS)
		dev_err(dev, "write fem tbl DFT failed, ret:%d, status:%d, errcode:%d\n",
			ret, resp_head.info.status, resp_head.info.errcode);

	return ret;
}

static int nbl_flow_add_multi_group(struct nbl_resource_mgt *res_mgt, u8 eth_id)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_switch_res *res = &flow_mgt->switch_res[0];
	struct nbl_flow_param param = {0};
	u16 alloc_mcc_id = 0;
	int ret;

	ret = nbl_flow_alloc_mcc_id(flow_mgt, eth_id, eth_info->eth_num, &alloc_mcc_id);
	if (ret)
		return ret;
	param.mcc_id = alloc_mcc_id;
	param.eth_id = eth_id;
	ret = nbl_flow_cfg_default_action(res_mgt, param.mcc_id);
	if (ret)
		goto add_flow_fail;

	ret = nbl_flow_init_mcc_node(res_mgt, param.mcc_id);
	if (ret)
		goto init_mcc_node_fail;

	res->allmulti_vsi_bitmap = kcalloc(BITS_TO_LONGS(flow_mgt->vsi_max_per_switch),
					   sizeof(long), GFP_KERNEL);
	if (!res->allmulti_vsi_bitmap)
		goto alloc_vsi_bitmap_fail;

	ret = nbl_flow_add_mcc_node(res_mgt, param.mcc_id, eth_id, U16_MAX);
	if (ret)
		goto add_mcc_node_fail;

	if (NBL_COMMON_TO_OCP_CAP(common)) {
		ret = nbl_flow_add_mcc_node(res_mgt, param.mcc_id, U8_MAX,
					    NBL_DRACO_FLOW_MCC_BMC_DPORT);
		if (ret)
			goto add_mcc_node_fail;
		ret = nbl_flow_add_mcc_node(res_mgt, param.mcc_id, U8_MAX,
					    NBL_DRACO_FLOW_MCC_EMP_DPORT);
		if (ret)
			goto add_mcc_node_fail;

		set_bit(NBL_DRACO_FLOW_MCC_BMC_DPORT, res->allmulti_vsi_bitmap);
		set_bit(NBL_DRACO_FLOW_MCC_EMP_DPORT, res->allmulti_vsi_bitmap);
		res->num_vsi_allmulti_active += 2;
	}

	res->ether_id = eth_id;
	res->allmulti_mcc_id = param.mcc_id;

	return 0;

add_mcc_node_fail:
	nbl_flow_clear_mcc_node(res_mgt, param.mcc_id);
alloc_vsi_bitmap_fail:
	kfree(res->allmulti_vsi_bitmap);
init_mcc_node_fail:
add_flow_fail:
	nbl_flow_free_mcc_id(flow_mgt, param.mcc_id, eth_id);
	return ret;
}

static int nbl_flow_setup_multi_group(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	int ret = 0;

	ret = nbl_flow_add_multi_group(res_mgt, eth_info->eth_id[pf_id]);
	if (ret)
		nbl_flow_remove_multi_group(res_mgt);

	return ret;
}

static void nbl_flow_macvlan_node_add_vsi_func(void *priv, void *x_key, void *y_key, void *data)
{
	struct nbl_flow_change_data *change_data = (struct nbl_flow_change_data *)priv;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)change_data->priv;
	struct nbl_flow_l2_data *rule_data = (struct nbl_flow_l2_data *)data;
	int ret = 0;

	if (rule_data->mcast_flow) {
		ret = nbl_flow_add_mcc_node(res_mgt, rule_data->mcc_group->mcc_id, U8_MAX,
					    change_data->vsi);
		if (ret) {
			nbl_flow_del_mcc_node(res_mgt, rule_data->mcc_group->mcc_id, U8_MAX,
					      change_data->vsi);
		}
	}
}

static int nbl_flow_add_multi_mcast(void *priv, u16 vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_flow_switch_res *switch_res;
	struct nbl_hash_xy_tbl_scan_key scan_key;
	struct nbl_flow_change_data data;
	int ret = 0;

	switch_res = &flow_mgt->switch_res[0];

	if (test_bit(vsi, switch_res->allmulti_vsi_bitmap)) {
		dev_info(dev, "Add multi mcast vsi%d is already exists\n", vsi);
		return 0;
	}

	ret = nbl_flow_add_mcc_node(res_mgt, switch_res->allmulti_mcc_id, U8_MAX, vsi);
	if (ret) {
		nbl_flow_del_mcc_node(res_mgt, switch_res->allmulti_mcc_id, U8_MAX, vsi);
		return ret;
	}

	set_bit(vsi, switch_res->allmulti_vsi_bitmap);
	switch_res->num_vsi_allmulti_active++;

	// add vsi to all multi griup
	data.priv = priv;
	data.vsi = vsi;
	NBL_HASH_XY_TBL_SCAN_KEY_INIT(&scan_key, NBL_HASH_TBL_OP_SHOW, NBL_HASH_TBL_ALL_SCAN,
				      false, NULL, NULL, NULL, NULL, &data,
				      &nbl_flow_macvlan_node_add_vsi_func);

	nbl_common_scan_hash_xy_node(flow_mgt->mac_hash_tbl[0], &scan_key);

	return 0;
}

static void nbl_flow_macvlan_node_del_vsi_func(void *priv, void *x_key, void *y_key, void *data)
{
	struct nbl_flow_change_data *change_data = (struct nbl_flow_change_data *)priv;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)change_data->priv;
	struct nbl_flow_l2_data *rule_data = (struct nbl_flow_l2_data *)data;

	if (rule_data->mcast_flow)
		nbl_flow_del_mcc_node(res_mgt, rule_data->mcc_group->mcc_id, U8_MAX,
				      change_data->vsi);
}

static void nbl_flow_del_multi_mcast(void *priv, u16 vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_switch_res *switch_res;
	struct nbl_hash_xy_tbl_scan_key scan_key;
	struct nbl_flow_change_data data;

	switch_res = &flow_mgt->switch_res[0];
	if (!test_bit(vsi, switch_res->allmulti_vsi_bitmap))
		return;

	nbl_flow_del_mcc_node(res_mgt, switch_res->allmulti_mcc_id, U8_MAX, vsi);
	clear_bit(vsi, switch_res->allmulti_vsi_bitmap);
	switch_res->num_vsi_allmulti_active--;

	// del vsi to all multi griup
	data.priv = priv;
	data.vsi = vsi;
	NBL_HASH_XY_TBL_SCAN_KEY_INIT(&scan_key, NBL_HASH_TBL_OP_SHOW, NBL_HASH_TBL_ALL_SCAN,
				      false, NULL, NULL, NULL, NULL, &data,
				      &nbl_flow_macvlan_node_del_vsi_func);

	nbl_common_scan_hash_xy_node(flow_mgt->mac_hash_tbl[0], &scan_key);
}

static void nbl_flow_macvlan_node_del_action_func(void *priv, void *x_key, void *y_key,
						  void *data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_l2_data *rule_data = (struct nbl_flow_l2_data *)data;

	nbl_flow_del_flow(res_mgt, &rule_data->entry);
}

static struct nbl_flow_mcc_group *nbl_flow_alloc_mcc_group(struct nbl_resource_mgt *res_mgt,
							   unsigned long *vsi_bitmap,
							   u16 eth_id, bool multi, u16 vsi_num)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_flow_switch_res *res = &flow_mgt->switch_res[0];
	struct nbl_flow_mcc_group *group = NULL;
	u16 alloc_mcc_id = 0;
	int ret = 0;
	int bit = 0;

	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return NULL;

	ret = nbl_flow_alloc_mcc_id(flow_mgt, eth_id, eth_info->eth_num, &alloc_mcc_id);
	if (ret)
		goto alloc_mcc_id_failed;

	group->mcc_id = alloc_mcc_id;
	group->multi = multi;
	group->nbits = flow_mgt->vsi_max_per_switch;
	group->ref_cnt = 1;
	group->vsi_num = vsi_num;

	INIT_LIST_HEAD(&group->group_node);

	group->vsi_bitmap = kcalloc(BITS_TO_LONGS(flow_mgt->vsi_max_per_switch), sizeof(long),
				    GFP_KERNEL);
	if (!group->vsi_bitmap)
		goto alloc_vsi_bitmap_failed;

	bitmap_copy(group->vsi_bitmap, vsi_bitmap, flow_mgt->vsi_max_per_switch);

	ret = nbl_flow_init_mcc_node(res_mgt, group->mcc_id);
	if (ret)
		goto free_nodes;

	for_each_set_bit(bit, vsi_bitmap, flow_mgt->vsi_max_per_switch) {
		if (multi)
			//  send to eth + bmc + vsi
			ret = nbl_flow_add_mcc_node(res_mgt, group->mcc_id, eth_id, bit);
		else
			ret = nbl_flow_add_mcc_node(res_mgt, group->mcc_id, U8_MAX, bit);

		if (ret)
			goto free_nodes;
	}

	list_add_tail(&group->group_node, &res->mcc_group_head);

	return group;

free_nodes:
	nbl_flow_clear_mcc_node(res_mgt, group->mcc_id);
	kfree(group->vsi_bitmap);

alloc_vsi_bitmap_failed:
	nbl_flow_free_mcc_id(flow_mgt, group->mcc_id, eth_id);

alloc_mcc_id_failed:
	kfree(group);
	return NULL;
}

static void nbl_flow_free_mcc_group(struct nbl_resource_mgt *res_mgt,
				    struct nbl_flow_mcc_group *group, u8 eth_id)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);

	group->ref_cnt--;
	if (group->ref_cnt)
		return;

	list_del(&group->group_node);
	nbl_flow_clear_mcc_node(res_mgt, group->mcc_id);
	nbl_flow_free_mcc_id(flow_mgt, group->mcc_id, eth_id);
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

static u32 nbl_flow_get_reserve_macvlan_cnt(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_flow_switch_res *res;
	int i;
	u32 reserve_cnt = 0;

	for_each_set_bit(i, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		res = &flow_mgt->switch_res[0];
		if (res->num_vfs)
			reserve_cnt += (res->num_vfs - res->active_vfs);
	}

	return reserve_cnt;
}

static u32 nbl_flow_get_reserve_mcc_id_conut(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	int max_mcc_num = NBL_DRACO_ETH_MAX_MCC_NUM(eth_info->eth_num);
	u32 count = 0;
	int i;

	for (i = 0; i < max_mcc_num; i++) {
		if (!test_bit(i, flow_mgt->switch_res[0].mcc_id_bitmap))
			count++;
	}

	return count;
}

static void nbl_flow_macvlan_node_found_vsi_action(void *priv, void *x_key, void *y_key,
						   void *data)
{
	bool *match = (bool *)(priv);

	*match = 1;
}

static int nbl_flow_macvlan_node_vsi_match_func(void *condition, void *x_key, void *y_key,
						void *data)
{
	u16 vsi = *(u16 *)condition;
	struct nbl_flow_l2_data *rule_data = (struct nbl_flow_l2_data *)data;

	if (!rule_data->mcast_flow)
		return rule_data->vsi == vsi ? 0 : -1;
	else
		return !test_bit(vsi, rule_data->mcc_group->vsi_bitmap);
}

static int nbl_flow_add_macvlan(void *priv, u8 *mac, u16 vlan, u16 vsi)
{
	struct nbl_hash_xy_tbl_scan_key scan_key;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_switch_res *res = &flow_mgt->switch_res[0];
	struct nbl_flow_l2_data *rule_data;
	struct nbl_flow_mcc_group *mcc_group = NULL, *pend_group = NULL;
	unsigned long *vsi_bitmap;
	struct nbl_flow_param param = {0};
	int ret = 0;
	int pf_id, vf_id;
	u32 reserve_cnt;
	u16 eth_id;
	u16 vsi_num = 0;
	u16 func_id;
	bool alloc_rule = 0;
	bool need_mcast = 0;
	bool vsi_match = 0;

	eth_id = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);

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
	param.eth_id = eth_id;
	param.vsi_id = vsi;
	param.mcc_id = NBL_MCC_ID_INVALID;

	rule_data = (struct nbl_flow_l2_data *)
		nbl_common_get_hash_xy_node(flow_mgt->mac_hash_tbl[0],
					    mac, &vlan);
	if (rule_data) {
		if (rule_data->mcast_flow && test_bit(vsi, rule_data->mcc_group->vsi_bitmap))
			goto success;
		else if (!rule_data->mcast_flow && rule_data->vsi == vsi)
			goto success;

		if (!rule_data->mcast_flow) {
			vsi_num = 1;
			set_bit(rule_data->vsi, vsi_bitmap);
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
	// 1. add new group
	if (need_mcast) {
		set_bit(vsi, vsi_bitmap);
		if (rule_data->multi && NBL_COMMON_TO_OCP_CAP(common)) {
			set_bit(NBL_DRACO_FLOW_MCC_BMC_DPORT, vsi_bitmap);
			set_bit(NBL_DRACO_FLOW_MCC_EMP_DPORT, vsi_bitmap);
		}

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

	// 2. remove old flow and group
	if (!alloc_rule) {
		nbl_flow_del_flow(res_mgt, &rule_data->entry);

		if (pend_group)
			nbl_flow_free_mcc_group(res_mgt, pend_group, eth_id);
	}

	// 3. add new flow
	if (mcc_group)
		param.mcc_id = mcc_group->mcc_id;

	ret = nbl_flow_add_flow(res_mgt, param, NBL_PHY_FLOW_MACVLAN, &rule_data->entry);
	if (ret)
		goto add_flow_failed;

	if (mcc_group) {
		rule_data->mcast_flow = 1;
		rule_data->mcc_group = mcc_group;
	} else {
		rule_data->mcast_flow = 0;
		rule_data->vsi = vsi;
	}

	if (alloc_rule) {
		ret = nbl_common_alloc_hash_xy_node(flow_mgt->mac_hash_tbl[0],
						    mac, &vlan, rule_data);
		if (ret)
			goto alloc_node_failed;
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

alloc_node_failed:
	nbl_flow_del_flow(res_mgt, &rule_data->entry);
add_flow_failed:
	if (!alloc_rule)
		nbl_common_free_hash_xy_node(flow_mgt->mac_hash_tbl[0], mac, &vlan);
	if (mcc_group)
		nbl_flow_free_mcc_group(res_mgt, mcc_group, eth_id);
alloc_mcc_group_failed:
	if (alloc_rule)
		kfree(rule_data);
alloc_rule_failed:
	kfree(vsi_bitmap);

	nbl_common_scan_hash_xy_node(flow_mgt->mac_hash_tbl[0], &scan_key);
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
	struct nbl_flow_switch_res *res = &flow_mgt->switch_res[0];
	struct nbl_flow_l2_data *rule_data;
	struct nbl_flow_param param = {0};
	struct nbl_hash_xy_tbl_scan_key scan_key;
	int ret;
	int pf_id, vf_id;
	u32 vsi_num;
	u16 eth_id;
	u16 func_id;
	bool need_mcast = false;
	bool add_flow = false;
	bool vsi_match = 0;

	eth_id = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);

	rule_data = nbl_common_get_hash_xy_node(flow_mgt->mac_hash_tbl[0], mac, &vlan);
	if (!rule_data)
		return;
	if (!rule_data->mcast_flow && rule_data->vsi != vsi)
		return;
	else if (rule_data->mcast_flow &&
		 !test_bit(vsi, rule_data->mcc_group->vsi_bitmap))
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
		clear_bit(vsi, vsi_bitmap);
		vsi_num--;
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

	nbl_flow_del_flow(res_mgt, &rule_data->entry);

	if (pend_group)
		nbl_flow_free_mcc_group(res_mgt, pend_group, eth_id);

	if (add_flow) {
		param.mac = mac;
		param.vid = vlan;
		param.eth_id = eth_id;
		param.mcc_id = NBL_MCC_ID_INVALID;
		param.vsi_id = (u16)find_first_bit(vsi_bitmap, flow_mgt->vsi_max_per_switch);

		if (mcc_group)
			param.mcc_id = mcc_group->mcc_id;
		ret = nbl_flow_add_flow(res_mgt, param, NBL_PHY_FLOW_MACVLAN, &rule_data->entry);
		if (ret)
			goto add_flow_failed;

		if (mcc_group) {
			rule_data->mcast_flow = 1;
			rule_data->mcc_group = mcc_group;
		} else {
			rule_data->mcast_flow = 0;
			rule_data->vsi = param.vsi_id;
		}
	}

	if (!add_flow)
		nbl_common_free_hash_xy_node(flow_mgt->mac_hash_tbl[0], mac, &vlan);

alloc_mcc_group_failed:
	kfree(vsi_bitmap);

	nbl_common_scan_hash_xy_node(flow_mgt->mac_hash_tbl[0], &scan_key);
	if (vf_id != U32_MAX && test_bit(vf_id, res->vf_bitmap) && !vsi_match) {
		clear_bit(vf_id, res->vf_bitmap);
		res->active_vfs--;
	}

	return;

add_flow_failed:
	if (mcc_group)
		nbl_flow_free_mcc_group(res_mgt, pend_group, eth_id);
	nbl_common_free_hash_xy_node(flow_mgt->mac_hash_tbl[0], mac, &vlan);
	kfree(vsi_bitmap);
	nbl_common_scan_hash_xy_node(flow_mgt->mac_hash_tbl[0], &scan_key);
	if (vf_id != U32_MAX && test_bit(vf_id, res->vf_bitmap) && !vsi_match) {
		clear_bit(vf_id, res->vf_bitmap);
		res->active_vfs--;
	}
}

static int nbl_draco_read_fem_tbl(struct nbl_resource_mgt *res_mgt,
				  u8 tbl_type, u32 addr,
				  union nbl_fem_resp_data_tblread_u *resp_data)
{
	int ret = 0;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);

	struct nbl_flow_param param = {0};
	union nbl_fem_cmd_head_u req_head = {{0}};
	union nbl_fem_cmd_data_u req_param;
	union nbl_fem_cmd_head_u resp_head = {{0}};

	memset(&req_param, 0, sizeof(req_param));
	param.tbl_to_read = tbl_type;
	param.pf_id = pf_id;
	param.read_addr = addr;
	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLREAD].cfg_req_head(&req_head, &param);
	if (ret)
		return ret;
	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLREAD].cfg_req_param(&req_param, &param);
	if (ret)
		return ret;

	ret = phy_ops->read_fem_tbl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), pf_id,
				    req_head.head_data, req_param.cmd_data,
				    resp_head.head_data, resp_data->resp_data);
	if (ret)
		nbl_err(common, NBL_DEBUG_FLOW, "read fem tbl %d failed, ret:%d\n", tbl_type, ret);

	if (resp_head.info.status != NBL_FEM_CMD_HEAD_STATUS_SUCCESS)
		nbl_info(common, NBL_DEBUG_FLOW, "read fem tbl %d failed, ret:%d\n", tbl_type, ret);

	return resp_head.info.status;
}

static int nbl_draco_read_fem_kt_bind_pf(struct nbl_resource_mgt *res_mgt,
					 union nbl_fem_resp_data_tblread_u *resp_data)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	int ret = nbl_draco_read_fem_tbl(res_mgt, NBL_FEM_CMD_HEAD_TABLE_KT_BIND_PF,
									0, resp_data);
	if (!ret) {
		nbl_info(common, NBL_DEBUG_FLOW, "kt bind pf%d: %08x %08x %08x %08x\n", pf_id,
			 resp_data->kt_bind_pf_info.kt_bind[3],
			 resp_data->kt_bind_pf_info.kt_bind[2],
			 resp_data->kt_bind_pf_info.kt_bind[1],
			 resp_data->kt_bind_pf_info.kt_bind[0]);
	}
	return ret;
}

static int nbl_draco_read_fem_tcam(struct nbl_resource_mgt *res_mgt, u32 oft_addr,
				   union nbl_fem_resp_data_tblread_u *resp_data)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	int ret = nbl_draco_read_fem_tbl(res_mgt, NBL_FEM_CMD_HEAD_TABLE_OFT_AT,
					 oft_addr, resp_data);
	if (!ret) {
		if (resp_data->oft_info.oft0_valid || resp_data->oft_info.oft1_valid) {
			nbl_info(common, NBL_DEBUG_FLOW,
				 "tcam full addr %d: oft0(vld=%d,size=%d,ktidx=%d),oft1(vld=%d,size=%d,ktidx=%d)\n",
				 oft_addr << 1,
				 resp_data->oft_info.oft0_valid,
				 resp_data->oft_info.oft0_size,
				 resp_data->oft_info.oft0_ktidx,
				 resp_data->oft_info.oft1_valid,
				 resp_data->oft_info.oft1_size,
				 resp_data->oft_info.oft1_ktidx);
			nbl_info(common, NBL_DEBUG_FLOW,
				 "addr %d: oft0_key=0x%08x %08x %08x %08x %08x,oft1_key=0x%08x %08x %08x %08x %08x\n",
				 oft_addr << 1,
				 resp_data->oft_info.oft0_key[4], resp_data->oft_info.oft0_key[3],
				 resp_data->oft_info.oft0_key[2], resp_data->oft_info.oft0_key[1],
				 resp_data->oft_info.oft0_key[0], resp_data->oft_info.oft1_key[4],
				 resp_data->oft_info.oft1_key[3], resp_data->oft_info.oft1_key[2],
				 resp_data->oft_info.oft1_key[1], resp_data->oft_info.oft1_key[0]);
		}
	} else {
		nbl_err(common, NBL_DEBUG_FLOW, "read fem tcam failed, pf:%d, oft addr:%d",
			pf_id, oft_addr << 1);
	}
	return ret;
}

static int nbl_draco_flow_remove_node_from_tcam(struct nbl_resource_mgt *res_mgt,
						u32 kt_idx, bool kt_full_mode, u32 *key)
{
	int ret;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_fem_entry flow = {0};

	flow.tcam_flag = 1;
	if (kt_full_mode)
		flow.kt_type = NBL_KT_FULL_MODE;
	else
		flow.kt_type = NBL_KT_HALF_MODE;

	flow.kt_idx = kt_idx;
	memcpy(flow.key, key, sizeof(flow.key));
	ret = nbl_flow_del_2hw(res_mgt, &flow);
	if (ret)
		nbl_err(common, NBL_DEBUG_FLOW, "delete node by kt idx: 0x%x, full: %d failed",
			kt_idx, kt_full_mode);
	else
		nbl_info(common, NBL_DEBUG_FLOW, "delete node by kt idx: 0x%x, full: %d success",
			 kt_idx, kt_full_mode);
	return ret;
}

static bool nbl_is_kt_belong_pf(u32 ktidx, union nbl_fem_resp_data_tblread_u *kt_bind_pf)
{
	u32 bolok_id = NBL_DRACO_GET_KT_BLOCK_IDX(ktidx) % NBL_DRACO_KT_MAX_BLOCK;

	return kt_bind_pf->kt_bind_pf_info.kt_bind[bolok_id / 32] & (1 << (bolok_id % 32));
}

static void nbl_flow_clear_fem_tcam(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	union nbl_fem_resp_data_tblread_u kt_bind_pf;
	union nbl_fem_resp_data_tblread_u tcam_resp;
	u32 key[NBL_TABLE_KEY_LEN] = {0};
	u32 tcam_addr;
	int ret = 0;

	memset(&kt_bind_pf, 0, sizeof(union nbl_fem_resp_data_tblread_u));
	memset(&tcam_resp, 0, sizeof(union nbl_fem_resp_data_tblread_u));

	ret = nbl_draco_read_fem_kt_bind_pf(res_mgt, &kt_bind_pf);
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "read kt bind pf tbl failed, ret:%d", ret);
		return;
	}

	nbl_info(common, NBL_DEBUG_FLOW, "nbl draco free fem tcam for pf:%d", pf_id);
	for (tcam_addr = 0; tcam_addr < NBL_DRACO_FULL_TCAM_NUM; tcam_addr++) {
		ret = nbl_draco_read_fem_tcam(res_mgt, tcam_addr, &tcam_resp);
		if (ret)
			continue;

		if (!tcam_resp.oft_info.oft0_valid && !tcam_resp.oft_info.oft1_valid)
			continue;

		if (tcam_resp.oft_info.oft0_size && tcam_resp.oft_info.oft1_size) {
			if (nbl_is_kt_belong_pf(tcam_resp.oft_info.oft0_ktidx, &kt_bind_pf)) {
				memset(key, 0, sizeof(key));
				memcpy(key,
				       tcam_resp.oft_info.oft0_key,
				       sizeof(tcam_resp.oft_info.oft0_key));
				memcpy((u8 *)key + sizeof(tcam_resp.oft_info.oft0_key),
				       tcam_resp.oft_info.oft1_key,
				       sizeof(tcam_resp.oft_info.oft1_key));
				nbl_draco_flow_remove_node_from_tcam(res_mgt,
								     tcam_resp.oft_info.oft0_ktidx,
								     true, key);
			}
		} else {
			if (tcam_resp.oft_info.oft0_valid &&
			    nbl_is_kt_belong_pf(tcam_resp.oft_info.oft0_ktidx, &kt_bind_pf)) {
				memset(key, 0, sizeof(key));
				memcpy(key,
				       tcam_resp.oft_info.oft0_key,
				       sizeof(tcam_resp.oft_info.oft0_key));
				nbl_draco_flow_remove_node_from_tcam(res_mgt,
								     tcam_resp.oft_info.oft0_ktidx,
								     false, key);
			}
			if (tcam_resp.oft_info.oft1_valid &&
			    nbl_is_kt_belong_pf(tcam_resp.oft_info.oft1_ktidx, &kt_bind_pf)) {
				memset(key, 0, sizeof(key));
				memcpy(key,
				       tcam_resp.oft_info.oft1_key,
				       sizeof(tcam_resp.oft_info.oft1_key));
				nbl_draco_flow_remove_node_from_tcam(res_mgt,
								     tcam_resp.oft_info.oft1_ktidx,
								     false, key);
			}
		}
	}
}

static void nbl_flow_clear_em(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);

	phy_ops->clear_em(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), pf_id);
}

static void nbl_flow_clear_ipro_decap(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->clear_ipro_decap(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
}

static void nbl_flow_macvlan_clear_del_action_func(void *priv, void *x_key, void *y_key,
						   void *data)
{
	struct nbl_flow_change_data *clear_data = (struct nbl_flow_change_data *)priv;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)clear_data->priv;
	struct nbl_flow_l2_data *rule_data = (struct nbl_flow_l2_data *)data;

	nbl_flow_del_macvlan(res_mgt, rule_data->mac, rule_data->vlan, clear_data->vsi);
}

static int nbl_flow_clear_flow(void *priv, u16 *vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_change_data data;
	void *mac_hash_tbl;
	struct nbl_hash_xy_tbl_scan_key scan_key;

	data.priv = priv;
	data.vsi = *vsi_id;
	mac_hash_tbl = flow_mgt->mac_hash_tbl[0];
	NBL_HASH_XY_TBL_SCAN_KEY_INIT(&scan_key, NBL_HASH_TBL_OP_SHOW, NBL_HASH_TBL_ALL_SCAN,
				      false, NULL, NULL, vsi_id,
				      &nbl_flow_macvlan_node_vsi_match_func, &data,
				      &nbl_flow_macvlan_clear_del_action_func);
	nbl_common_scan_hash_xy_node(mac_hash_tbl, &scan_key);
	nbl_flow_del_multi_mcast(res_mgt, *vsi_id);

	return 0;
}

static int nbl_flow_clear_accel_flow(void *priv, u16 *vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_flow_dipsec_rule *dipsec_rule;
	struct nbl_flow_dipsec_rule *dipsec_rule_safe;
	struct nbl_flow_ul4s_rule *ul4s_rule;
	struct nbl_flow_ul4s_rule *ul4s_rule_safe;

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

static void nbl_flow_macvlan_node_add_action_func(void *priv, void *x_key, void *y_key,
						  void *data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_flow_l2_data *rule_data = (struct nbl_flow_l2_data *)data;
	struct nbl_flow_param param = {0};
	u8 *mac = (u8 *)x_key;
	u16 vlan = *(u16 *)y_key;
	u16 vsi_id = 0;
	int ret = 0;

	if (!rule_data->mcast_flow)
		vsi_id = rule_data->vsi;

	param.mac = mac;
	param.vid = vlan;
	param.eth_id = common->eth_id;
	param.vsi_id = vsi_id;
	if (rule_data->mcast_flow)
		param.mcc_id = rule_data->mcc_group->mcc_id;
	else
		param.mcc_id = NBL_MCC_ID_INVALID;

	ret = nbl_flow_add_flow(res_mgt, param, NBL_PHY_FLOW_MACVLAN, &rule_data->entry);
	if (ret)
		dev_err(dev, "restore uc flow failed, ret: %d\n", ret);
}

static void nbl_flow_clear_flow_fem_kt(void *priv)
{
	nbl_flow_clear_fem_tcam(priv);
	nbl_flow_clear_em(priv);
	nbl_flow_clear_ipro_decap(priv);
	nbl_flow_free_kt(priv);
}

void nbl_flow_restore_flow(void *priv, bool restore_all)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_hash_xy_tbl_scan_key scan_key;
	void *mac_hash_tbl;
	int i = 0;

	struct nbl_resource_mgt *draco_mgt = (struct nbl_resource_mgt *)res_mgt;
	struct nbl_upcall_port_info *upcall_port_info = &draco_mgt->pmd_status.upcall_port_info;

	if (!restore_all) {
		if (!upcall_port_info->has_upcall) {
			dev_info(dev, "device is not a offload-dev, no need restore cfg\n");
			return;
		}
	}
	upcall_port_info->has_upcall = false;
	dev_info(dev, "restore flow\n");
	nbl_flow_clear_flow_fem_kt(priv);
	/* clear flow id */
	for (i = 0; i < NBL_MAX_MACVLAN_NUM; i++)
		clear_bit(i, flow_mgt->flow_id_bitmap);

	nbl_flow_alloc_kt(priv);

	NBL_HASH_XY_TBL_SCAN_KEY_INIT(&scan_key, NBL_HASH_TBL_OP_SHOW, NBL_HASH_TBL_ALL_SCAN,
				      false, NULL, NULL, NULL, NULL, res_mgt,
				      &nbl_flow_macvlan_node_add_action_func);

	mac_hash_tbl = flow_mgt->mac_hash_tbl[0];
	nbl_common_scan_hash_xy_node(mac_hash_tbl, &scan_key);
}

int nbl_phy_cfg_flow_default_action(struct nbl_resource_mgt *res_mgt, u16 vsi_id,
				    u16 eth_id, bool status)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u8 write_data[NBL_DRACO_CMD_TBLWRITE_DFT_DATALEN] = {0};
	struct nbl_draco_tbl_ab_ad *tbl_wdat = (struct nbl_draco_tbl_ab_ad *)write_data;
	union nbl_base_action_bits *ab = (union nbl_base_action_bits *)&tbl_wdat->action_bits;
	union nbl_base_action_datas *ad = (union nbl_base_action_datas *)&tbl_wdat->action_data;
	struct nbl_flow_param param = {0};
	union nbl_fem_cmd_head_u resp_head = {{0}};
	union nbl_fem_cmd_head_u req_head = {{0}};
	union nbl_fem_cmd_data_u req_param = {{{0}}};
	union nbl_fem_resp_data_tblwrite_u resp_data;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	int ret = 0;
	union nbl_fem_req_param_tblwrite_u *tbl_req_param;

	memset(&resp_data, 0, sizeof(resp_data));
	tbl_req_param = (union nbl_fem_req_param_tblwrite_u *)&req_param;
	param.pf_id = pf_id;
	param.tbl_to_write = NBL_DRACO_DFT_TBL;
	if (eth_info->eth_num == NBL_FOUR_ETHERNET_PORT)
		param.dft_addr = pf_id + 1;
	else
		param.dft_addr = 2 * pf_id + 1;

	if (status) {
		ab->baseab.SET_DEST = 1;
		ad->dport.up.dir = 0;
		ad->dport.up.next_stg = NBL_NEXT_STAGE_ACL0;
		ad->dport.up.vsi_id = vsi_id;
	}
	param.tbl = write_data;

	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLWRITE].cfg_req_head(&req_head, &param);
	ret |= cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLWRITE].cfg_req_param(&req_param, &param);
	if (ret)
		return ret;

	ret |= phy_ops->write_fem_tbl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), pf_id,
				req_head.head_data, req_param.cmd_data,
				resp_head.head_data, resp_data.resp_data);
	if (ret || resp_head.info.status != NBL_FEM_CMD_HEAD_STATUS_SUCCESS)
		nbl_err(common, NBL_DEBUG_FLOW, "write fem tbl DFT failed, ret:%d, status:%d, errcode:%d\n",
			ret, resp_head.info.status, resp_head.info.errcode);

	return ret;
}

static void nbl_flow_id_dump(struct seq_file *m, struct nbl_flow_fem_entry *entry, char *title)
{
	seq_printf(m, "%s:  flow_id:%u, kt_idx:%u, ht_table:%u, ht_index:%u, bucket:%u, ht0:0x%x, ht1:0x%x, tcam_flag:%d, tcam_table:%d, tcam_index:%d\n",
		   title, entry->flow_id, entry->kt_idx, entry->hash_table, entry->ht_index,
		   entry->hash_bucket, entry->ht0_hash, entry->ht1_hash,
		   entry->tcam_flag, entry->tcam_table, entry->tcam_index);
}

static void nbl_flow_mcc_group_dump(struct seq_file *m, struct nbl_flow_mcc_group *group)
{
	seq_printf(m, "nbits: %u, vsi_number: %u, ref_cnt %u, multi %u, mcc_id %u\n",
		   group->nbits, group->vsi_num, group->ref_cnt, group->multi, group->mcc_id);
	seq_printf(m, "vsi bitmap: %*pb\n", group->nbits, group->vsi_bitmap);

	seq_puts(m, "\n");
}

static void nbl_flow_macvlan_node_show_action_func(void *priv, void *x_key, void *y_key,
						   void *data)
{
	struct seq_file *m = (struct seq_file *)priv;
	u8 *mac = (u8 *)x_key;
	u16 vlan = *(u16 *)y_key;
	struct nbl_flow_l2_data *rule_data = (struct nbl_flow_l2_data *)data;

	seq_printf(m, "\nvlan %d MAC address %02X:%02X:%02X:%02X:%02X:%02X\n",
		   vlan, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	nbl_flow_id_dump(m, &rule_data->entry, "macvlan");

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
	struct nbl_flow_switch_res *res;
	struct nbl_hash_xy_tbl_scan_key scan_key;
	int i;

	NBL_HASH_XY_TBL_SCAN_KEY_INIT(&scan_key, NBL_HASH_TBL_OP_SHOW, NBL_HASH_TBL_ALL_SCAN,
				      false, NULL, NULL, NULL, NULL, m,
				      &nbl_flow_macvlan_node_show_action_func);

	for_each_set_bit(i, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		res = &flow_mgt->switch_res[0];
		seq_printf(m, "\nether_id %d, status %u, flow_mgt flow_id_cnt %u\n",
			   res->ether_id, res->network_status, flow_mgt->flow_id_cnt);

		if (res->vf_bitmap) {
			seq_printf(m, "\nnumber vf %u, active vf %u, vf bitmap: %*pb\n",
				   res->num_vfs, res->active_vfs,
				   res->num_vfs, res->vf_bitmap);
		}

		if (res->allmulti_vsi_bitmap) {
			seq_printf(m, "\nallmulti_mcc_id: %u, number allmulti vsi: %u, allmulti_vsi_bitmap: %*pb\n",
				   res->allmulti_mcc_id, res->num_vsi_allmulti_active,
				   flow_mgt->vsi_max_per_switch, res->allmulti_vsi_bitmap);
		}
		nbl_common_scan_hash_xy_node(flow_mgt->mac_hash_tbl[0], &scan_key);

		seq_puts(m, "\n");
	}
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

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;

	param.index = index;
	param.data = data;
	param.vsi_id = vsi;
	param.eth_id = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);
	if (data[0] == AF_INET6)
		param.kt_type = NBL_KT_FULL_MODE;
	if (nbl_flow_add_flow(res_mgt, param, NBL_PHY_FLOW_UTLS, &rule->ul4s_entry)) {
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

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;

	param.index = index;
	param.data = data;
	param.vsi_id = vsi;
	param.eth_id = nbl_res_vsi_id_to_eth_id(res_mgt, vsi);
	if (data[0] == AF_INET6)
		param.kt_type = NBL_KT_FULL_MODE;
	if (nbl_flow_add_flow(res_mgt, param, NBL_PHY_FLOW_DIPSEC, &rule->dipsec_entry)) {
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

static int nbl_flow_add_lag(void *priv, u16 *vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_lacp_lldp(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), 1, 1, *vsi);

	return 0;
}

static int nbl_flow_del_lag(void *priv, u16 *vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_lacp_lldp(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), 1, 0, *vsi);

	return 0;
}

static int nbl_flow_add_lldp(void *priv, u16 *vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_lacp_lldp(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), 0, 1, *vsi);

	return 0;
}

static int nbl_flow_del_lldp(void *priv, u16 *vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_lacp_lldp(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), 0, 0, *vsi);

	return 0;
}

static int nbl_res_flow_check_flow_table_spec(void *priv,
					      struct nbl_ch_prm_flow_table_spec *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	u32 reserve_cnt = nbl_flow_get_reserve_macvlan_cnt(res_mgt);
	u32 reserve_mcc_id_cnt = nbl_flow_get_reserve_mcc_id_conut(res_mgt);
	u32 need = param->vlan_list_cnt * (param->unicast_mac_cnt + param->multi_mac_cnt);
	u32 mcc_id_exhausted = 0;

	if (param->multi_mac_cnt > reserve_mcc_id_cnt)
		mcc_id_exhausted = 1;

	if ((reserve_cnt + need > flow_mgt->flow_id_cnt) || mcc_id_exhausted)
		return -ENOSPC;

	return 0;
}

/* NBL_FLOW_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_FLOW_OPS_TBL								\
do {											\
	NBL_FLOW_SET_OPS(alloc_kt, nbl_flow_alloc_kt);					\
	NBL_FLOW_SET_OPS(free_kt, nbl_flow_free_kt);					\
	NBL_FLOW_SET_OPS(setup_multi_group, nbl_flow_setup_multi_group);		\
	NBL_FLOW_SET_OPS(remove_multi_group, nbl_flow_remove_multi_group);		\
	NBL_FLOW_SET_OPS(add_multi_mcast, nbl_flow_add_multi_mcast);			\
	NBL_FLOW_SET_OPS(del_multi_mcast, nbl_flow_del_multi_mcast);			\
	NBL_FLOW_SET_OPS(add_macvlan, nbl_flow_add_macvlan);				\
	NBL_FLOW_SET_OPS(del_macvlan, nbl_flow_del_macvlan);				\
	NBL_FLOW_SET_OPS(clear_accel_flow, nbl_flow_clear_accel_flow);			\
	NBL_FLOW_SET_OPS(clear_flow, nbl_flow_clear_flow);				\
	NBL_FLOW_SET_OPS(dump_flow, nbl_flow_dump_flow);				\
	NBL_FLOW_SET_OPS(add_ktls_rx_flow, nbl_flow_add_ktls_rx_flow);			\
	NBL_FLOW_SET_OPS(del_ktls_rx_flow, nbl_flow_del_ktls_rx_flow);			\
	NBL_FLOW_SET_OPS(add_ipsec_tx_flow, nbl_flow_add_ipsec_tx_flow);		\
	NBL_FLOW_SET_OPS(del_ipsec_tx_flow, nbl_flow_del_ipsec_tx_flow);		\
	NBL_FLOW_SET_OPS(flr_clear_accel_flow, nbl_res_flr_clear_accel_flow);		\
	NBL_FLOW_SET_OPS(flr_clear_flows, nbl_res_flr_clear_flow);			\
	NBL_FLOW_SET_OPS(add_lag_flow, nbl_flow_add_lag);				\
	NBL_FLOW_SET_OPS(del_lag_flow, nbl_flow_del_lag);				\
	NBL_FLOW_SET_OPS(add_lldp_flow, nbl_flow_add_lldp);				\
	NBL_FLOW_SET_OPS(del_lldp_flow, nbl_flow_del_lldp);				\
	NBL_FLOW_SET_OPS(check_flow_table_spec, nbl_res_flow_check_flow_table_spec);	\
} while (0)

static void nbl_flow_remove_mgt(struct device *dev, struct nbl_resource_mgt *res_mgt)
{
	struct nbl_flow_mgt *flow_mgt = NBL_RES_MGT_TO_FLOW_MGT(res_mgt);
	struct nbl_hash_xy_tbl_del_key del_key;

	NBL_HASH_XY_TBL_DEL_KEY_INIT(&del_key, res_mgt, &nbl_flow_macvlan_node_del_action_func);
	nbl_common_remove_hash_xy_table(flow_mgt->mac_hash_tbl[0], &del_key);
	if (flow_mgt->switch_res[0].vf_bitmap)
		devm_kfree(dev, flow_mgt->switch_res[0].vf_bitmap);

	if (flow_mgt->switch_res[0].mcc_id_bitmap)
		devm_kfree(dev, flow_mgt->switch_res[0].mcc_id_bitmap);

	nbl_flow_clear_flow_fem_kt((void *)res_mgt);
	devm_kfree(dev, flow_mgt->flow_id_bitmap);

	flow_mgt->flow_id_cnt = 0;
	devm_kfree(dev, flow_mgt);
	NBL_RES_MGT_TO_FLOW_MGT(res_mgt) = NULL;
}

static int nbl_flow_setup_mgt(struct device *dev, struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	u16 func_id = NBL_COMMON_TO_MGT_PF(common);
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_hash_xy_tbl_key macvlan_tbl_key;
	int vf_num = -1;
	int diff = 0;
	struct nbl_sriov_info *sriov_info;

	flow_mgt = devm_kzalloc(dev, sizeof(struct nbl_flow_mgt), GFP_KERNEL);
	if (!flow_mgt)
		return -ENOMEM;

	NBL_RES_MGT_TO_FLOW_MGT(res_mgt) = flow_mgt;

	flow_mgt->flow_id_bitmap = devm_kcalloc(dev, BITS_TO_LONGS(NBL_MAX_MACVLAN_NUM),
						sizeof(long), GFP_KERNEL);
	if (!flow_mgt->flow_id_bitmap)
		goto settup_mgt_failed;

	NBL_HASH_XY_TBL_KEY_INIT(&macvlan_tbl_key, dev, ETH_ALEN, sizeof(u16),
				 sizeof(struct nbl_flow_l2_data),
				 NBL_MACVLAN_TBL_BUCKET_SIZE, NBL_MACVLAN_X_AXIS_BUCKET_SIZE,
				 NBL_MACVLAN_Y_AXIS_BUCKET_SIZE, false);

	INIT_LIST_HEAD(&flow_mgt->switch_res[0].mcc_group_head);
	flow_mgt->mac_hash_tbl[0] = nbl_common_init_hash_xy_table(&macvlan_tbl_key);
	if (!flow_mgt->mac_hash_tbl[0])
		goto settup_mgt_failed;

	diff = nbl_common_pf_id_subtraction_mgtpf_id(common, func_id);
	sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + diff;
	vf_num = sriov_info->num_vfs;

	if (vf_num != -1) {
		flow_mgt->switch_res[0].num_vfs = vf_num;
		flow_mgt->switch_res[0].vf_bitmap = devm_kcalloc(dev, BITS_TO_LONGS(vf_num),
								 sizeof(long), GFP_KERNEL);
		if (!flow_mgt->switch_res[0].vf_bitmap)
			goto settup_mgt_failed;
	} else {
		flow_mgt->switch_res[0].num_vfs = 0;
		flow_mgt->switch_res[0].vf_bitmap = NULL;
	}

	flow_mgt->switch_res[0].active_vfs = 0;
	flow_mgt->switch_res[0].mcc_id_bitmap =
		devm_kcalloc(dev, BITS_TO_LONGS(NBL_DRACO_ETH_MAX_MCC_NUM(eth_info->eth_num)),
			     sizeof(long), GFP_KERNEL);
	if (!flow_mgt->switch_res[0].mcc_id_bitmap)
		goto settup_mgt_failed;

	INIT_LIST_HEAD(&flow_mgt->ul4s_head);
	INIT_LIST_HEAD(&flow_mgt->dprbac_head);

	flow_mgt->switch_res[0].num_vsi_allmulti_active = 0;
	flow_mgt->flow_id_cnt = NBL_MAX_MACVLAN_NUM;
	flow_mgt->vsi_max_per_switch = NBL_DRACO_VSI_MAX_ID;

	return 0;

settup_mgt_failed:
	nbl_flow_remove_mgt(dev, res_mgt);
	return -1;
}

int nbl_flow_mgt_start_draco(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_phy_ops *phy_ops;
	struct device *dev;
	int ret = 0;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	ret = nbl_flow_setup_mgt(dev, res_mgt);
	if (ret)
		goto setup_mgt_fail;

	nbl_flow_clear_flow_fem_kt((void *)res_mgt);

	return 0;

setup_mgt_fail:
	return ret;
}

void nbl_flow_mgt_stop_draco(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_flow_mgt **flow_mgt;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	flow_mgt = &NBL_RES_MGT_TO_FLOW_MGT(res_mgt);

	if (!(*flow_mgt))
		return;

	nbl_flow_remove_mgt(dev, res_mgt);
}

int nbl_flow_setup_ops_draco(struct nbl_resource_ops *res_ops)
{
#define NBL_FLOW_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_FLOW_OPS_TBL;
#undef  NBL_FLOW_SET_OPS

	return 0;
}

void nbl_flow_remove_ops_draco(struct nbl_resource_ops *res_ops)
{
#define NBL_FLOW_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = NULL; ; } while (0)
	NBL_FLOW_OPS_TBL;
#undef  NBL_FLOW_SET_OPS
}
