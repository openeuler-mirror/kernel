// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_tc_flow.h"

static inline void nbl_flow_set_bits(u8 *p, u8 mask)
{
	*p |= mask;
}

static inline void nbl_flow_clr_bits(u8 *p, u8 mask)
{
	*p &= ~mask;
}

bool nbl_flow_is_available(struct nbl_tc_flow_mgt *tc_flow_mgt)
{
	u8 ret = tc_flow_mgt->init_status & NBL_FLOW_AVAILABLE_BIT;

	return ret != 0;
}

void nbl_flow_clean_create_destroy_cnt(struct nbl_tc_flow_mgt *tc_flow_mgt)
{
	atomic64_set(&tc_flow_mgt->destroy_num, 0);
	atomic64_set(&tc_flow_mgt->create_num, 0);
}

bool nbl_flow_is_resource_ready(struct nbl_tc_flow_mgt *tc_flow_mgt)
{
	u8 ret = tc_flow_mgt->init_status & NBL_FLOW_INIT_BIT;

	return ret != 0;
}

void nbl_flow_set_resource_init_status(struct nbl_tc_flow_mgt *tc_flow_mgt, bool status)
{
	if (status)
		nbl_flow_set_bits(&tc_flow_mgt->init_status,
				  NBL_FLOW_INIT_BIT);
	else
		nbl_flow_clr_bits(&tc_flow_mgt->init_status,
				  NBL_FLOW_INIT_BIT);
}

void nbl_flow_resource_available(struct nbl_tc_flow_mgt *tc_flow_mgt)
{
	nbl_flow_set_bits(&tc_flow_mgt->init_status, NBL_FLOW_AVAILABLE_BIT);
}

void nbl_flow_resource_unavailable(struct nbl_tc_flow_mgt *tc_flow_mgt)
{
	nbl_flow_clr_bits(&tc_flow_mgt->init_status, NBL_FLOW_AVAILABLE_BIT);
}

void nbl_flow_wait_flows_free_done(struct nbl_tc_flow_mgt *tc_flow_mgt)
{
#define WAIT_CNT 100
#define WAIT_TIME 10 /* ms */
	u32 cnt = 0;

	while (1) {
		if (cnt > WAIT_CNT)
			break;
		cnt++;

		if (!atomic64_read(&tc_flow_mgt->ref_cnt))
			break;
		mdelay(WAIT_TIME);
	}
}

struct nbl_tc_flow *
nbl_tc_flow_index_lookup(struct nbl_resource_mgt *res_mgt, struct nbl_flow_index_key *key)
{
	struct nbl_tc_flow *tc_flow_node = NULL;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_index_key_extra extra_key;

	mutex_lock(&tc_flow_mgt->flow_lock);
	NBL_INDEX_EXTRA_KEY_INIT(&extra_key, 0, 0, true);
	nbl_common_get_index_with_data(tc_flow_mgt->flow_idx_tbl, key, &extra_key, NULL,
				       0, (void **)&tc_flow_node);
	mutex_unlock(&tc_flow_mgt->flow_lock);

	return tc_flow_node;
}

int nbl_tc_flow_idx_lookup(void *priv, struct nbl_flow_index_key key)
{
	int ret = -ENOKEY;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_tc_flow *tc_flow_ptr = NULL;

	if (!tc_flow_mgt || !nbl_flow_is_available(tc_flow_mgt))
		return -EPERM;

	tc_flow_ptr = nbl_tc_flow_index_lookup(res_mgt, &key);
	if (tc_flow_ptr)
		ret = 0;

	return ret;
}

struct nbl_tc_flow *
nbl_tc_flow_insert_index(struct nbl_resource_mgt *res_mgt, struct nbl_flow_index_key *key)
{
	int idx;
	struct nbl_tc_flow *tc_flow_node = NULL;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_tc_flow tc_node_tmp;

	mutex_lock(&tc_flow_mgt->flow_lock);
	memset(&tc_node_tmp, 0, sizeof(struct nbl_tc_flow));
	idx = nbl_common_alloc_index(tc_flow_mgt->flow_idx_tbl, key, NULL, &tc_node_tmp,
				     sizeof(tc_node_tmp), (void **)&tc_flow_node);
	if (idx == U32_MAX)
		goto out;

	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow hw cookie=%llx add success!\n", key->cookie);
out:
	mutex_unlock(&tc_flow_mgt->flow_lock);
	return tc_flow_node;
}

int nbl_tc_flow_delete_index(struct nbl_resource_mgt *res_mgt, struct nbl_flow_index_key *key)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	mutex_lock(&tc_flow_mgt->flow_lock);
	nbl_common_free_index(tc_flow_mgt->flow_idx_tbl, key);
	mutex_unlock(&tc_flow_mgt->flow_lock);

	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow hw cookie=%llx del success!\n", key->cookie);

	return 0;
}

void nbl_assign_key(u32 *kt_data, bool full, u32 offset, u16 length, u32 value)
{
	u32 full_offset = NBL_FEM_KT_LEN - offset - length;
	u32 index = full_offset / NBL_BITS_IN_U32;
	u32 remain = full_offset % NBL_BITS_IN_U32;
	u32 shifted = 0;

	if (NBL_BITS_IN_U32 - remain < length) {
		/* if the value span across u32 boundary */
		shifted = NBL_BITS_IN_U32 - remain;
		kt_data[index] += (value << remain);
		kt_data[index + 1] += (value >> shifted);
	} else {
		kt_data[index] += (value << remain);
	}
}

static void nbl_assign_flow_key_input(u32 *kt_data, bool full,
				      const struct nbl_flow_key_info *key,
				      struct nbl_fdir_fltr *input,
				      u16 tab_index)
{
	const u32 *data = NULL;
	const u32 *mask = NULL;
	u16 temp_etype = 0;
	u16 length = (u16)(key->length / NBL_BITS_IN_U32);
	int i = 0;

	switch (1ULL << key->key_id) {
	case NBL_FLOW_KEY_TABLE_IDX_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       tab_index);
		break;
	case NBL_FLOW_KEY_INPORT16_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->encoded_port);
		break;
	case NBL_FLOW_KEY_INPORT8_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->port & 0xFF);
		break;
	case NBL_FLOW_KEY_INPORT4_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       (input->port >> NBL_BITS_IN_U8) & 0xF);
		break;
	case NBL_FLOW_KEY_T_DIPV4_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->ip_outer.dst_ip.addr);
		break;
	case NBL_FLOW_KEY_T_DIPV6_FLAG:
		data = (u32 *)(&input->ip_outer.dst_ip.v6_addr);
		for (i = length - 1; i >= 0; i--, data++)
			nbl_assign_key(kt_data, full,
				       key->offset + NBL_BITS_IN_U32 * i,
				       NBL_BITS_IN_U32, (*data));
		break;
	case NBL_FLOW_KEY_T_SRCPORT_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->l4_outer.src_port);
		break;
	case NBL_FLOW_KEY_T_DSTPORT_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->l4_outer.dst_port);
		break;
	case NBL_FLOW_KEY_T_PROTOCOL_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->ip_outer.proto);
		break;
	case NBL_FLOW_KEY_T_TOS_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->ip_outer.tos);
		break;
	case NBL_FLOW_KEY_T_TTL_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->ip_outer.ttl);
		break;
	case NBL_FLOW_KEY_T_VNI_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->tnl.vni);
		break;
	case NBL_FLOW_KEY_SIPV4_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->ip.src_ip.addr & input->ip_mask.src_ip.addr);
		break;
	case NBL_FLOW_KEY_SIPV6_FLAG:
		data = (u32 *)(&input->ip.src_ip.v6_addr);
		mask = (u32 *)(&input->ip_mask.src_ip.v6_addr);
		for (i = length - 1; i >= 0; i--, data++, mask++)
			nbl_assign_key(kt_data, full,
				       key->offset + NBL_BITS_IN_U32 * i,
				       NBL_BITS_IN_U32, (*data) & (*mask));
		break;
	case NBL_FLOW_KEY_DIPV4_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->ip.dst_ip.addr);
		break;
	case NBL_FLOW_KEY_DIPV6_FLAG:
		data = (u32 *)(&input->ip.dst_ip.v6_addr);
		for (i = length - 1; i >= 0; i--, data++, mask++)
			nbl_assign_key(kt_data, full,
				       key->offset + NBL_BITS_IN_U32 * i,
				       NBL_BITS_IN_U32, (*data));
		break;
	case NBL_FLOW_KEY_DSTMAC_FLAG:
		data = (u32 *)input->l2_data.dst_mac;
		nbl_assign_key(kt_data, full, key->offset + NBL_BITS_IN_U16,
			       NBL_BITS_IN_U32, *data);
		nbl_assign_key(kt_data, full, key->offset, NBL_BITS_IN_U16,
			       (*(data + 1)) & 0x0000FFFF);
		break;
	case NBL_FLOW_KEY_SRCMAC_FLAG:
		data = (u32 *)input->l2_data.src_mac;
		nbl_assign_key(kt_data, full, key->offset + NBL_BITS_IN_U16,
			       NBL_BITS_IN_U32, *data);
		nbl_assign_key(kt_data, full, key->offset, NBL_BITS_IN_U16,
			       (*(data + 1)) & 0x0000FFFF);
		break;
	case NBL_FLOW_KEY_SVLAN_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->svlan_tag & 0xFFF);
		break;
	case NBL_FLOW_KEY_CVLAN_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->cvlan_tag & 0xFFF);
		break;
	case NBL_FLOW_KEY_ETHERTYPE_FLAG:
		if (input->cvlan_type)
			temp_etype = input->cvlan_type;
		else if (input->svlan_type)
			temp_etype = input->svlan_type;
		else
			temp_etype = input->l2_data.ether_type;
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       temp_etype);
		break;
	case NBL_FLOW_KEY_SRCPORT_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->l4.src_port & input->l4_mask.src_port);
		break;
	case NBL_FLOW_KEY_DSTPORT_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->l4.dst_port & input->l4_mask.dst_port);
		break;
	case NBL_FLOW_KEY_PROTOCOL_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->ip.proto & input->ip_mask.proto);
		break;
	case NBL_FLOW_KEY_TCPSTAT_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->l4.tcp_flag);
		break;
	case NBL_FLOW_KEY_TOS_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->ip.tos);
		break;
	case NBL_FLOW_KEY_TTL_FLAG:
		nbl_assign_key(kt_data, full, key->offset, key->length,
			       input->ip.ttl);
		break;
	case NBL_FLOW_KEY_T_DSTMAC_FLAG:
	case NBL_FLOW_KEY_T_SRCMAC_FLAG:
	case NBL_FLOW_KEY_T_SVLAN_FLAG:
	case NBL_FLOW_KEY_T_CVLAN_FLAG:
	case NBL_FLOW_KEY_T_ETHERTYPE_FLAG:
	case NBL_FLOW_KEY_T_NPROTO_FLAG:
	case NBL_FLOW_KEY_T_TCPSTAT_FLAG:
	case NBL_FLOW_KEY_ARP_OP_FLAG:
	case NBL_FLOW_KEY_ICMPV6_TYPE_FLAG:
	case NBL_FLOW_KEY_RDMA_ACK_SEQ_FLAG:
	case NBL_FLOW_KEY_RDMA_QPN_FLAG:
	case NBL_FLOW_KEY_RDMA_OP_FLAG:
	case NBL_FLOW_KEY_INPORT2_FLAG:
	case NBL_FLOW_KEY_INPORT2L_FLAG:
	default:
		break;
	}
}

/* kt_data: five u64 data */
void nbl_assign_hash_key_key(u32 *kt_data,
			     struct nbl_flow_key_info *key,
			     struct nbl_profile_msg *prf_msg,
			     struct nbl_fdir_fltr *input,
			     u32 value,
			     u16 tab_index)
{
	/* assign profile id, key PHVs (key and action data) */
	/* ignore bit setter and masks, actions */
	switch (key->key_type) {
	case NBL_FLOW_KEY_TYPE_PID:
		nbl_assign_key(kt_data, prf_msg->key_full, key->offset,
			       key->length, value);
		break;
	case NBL_FLOW_KEY_TYPE_PHV:
		nbl_assign_flow_key_input(kt_data, prf_msg->key_full, key,
					  input, tab_index);
		break;
	case NBL_FLOW_KEY_TYPE_ACTION:
		break;
	case NBL_FLOW_KEY_TYPE_BTS:
		break;
	case NBL_FLOW_KEY_TYPE_MASK:
		break;
	default:
		break;
	}
}

/**
 * @brief: flow_tab.insert hash tab node func
 *
 * @param[in] tc_flow_mgt: tc flow hw mgt
 * @param[in] node: node key info
 * @return int: 0-success other-fail
 */
int nbl_insert_flow_tab_filter(struct nbl_resource_mgt *res_mgt,
			       void *key,
			       void *node,
			       void **new_node,
			       u8 profile_id)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	int ret;

	if (!tc_flow_mgt->flow_tab_hash[profile_id].flow_tab_hash)
		return -EINVAL;

	ret = nbl_common_alloc_hash_node(tc_flow_mgt->flow_tab_hash[profile_id].flow_tab_hash, key,
					 node, new_node);
	if (ret)
		return ret;

	tc_flow_mgt->flow_tab_hash[profile_id].tab_cnt++;
	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow hw insert pid=%d tab_cnt++ =%d\n",
		  profile_id, tc_flow_mgt->flow_tab_hash[profile_id].tab_cnt);

	return 0;
}
