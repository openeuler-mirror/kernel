// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */
#include "nbl_accel.h"

static int nbl_res_alloc_ktls_tx_index(void *priv, u16 *vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt;
	u32 index;

	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	index = find_first_zero_bit(accel_mgt->tx_ktls_bitmap, NBL_MAX_KTLS_SESSION);
	if (index >= NBL_MAX_KTLS_SESSION)
		return -ENOSPC;

	set_bit(index, accel_mgt->tx_ktls_bitmap);
	accel_mgt->dtls_cfg_info[index].vld = true;
	accel_mgt->dtls_cfg_info[index].vsi = *vsi;
	return index;
}

static int nbl_res_free_ktls_tx_index(void *priv, u32 *index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt;

	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	clear_bit(*index, accel_mgt->tx_ktls_bitmap);
	memset(&accel_mgt->dtls_cfg_info[*index], 0, sizeof(struct nbl_tls_cfg_info));

	return 0;
}

static int nbl_res_cfg_ktls_tx_keymat(void *priv, struct nbl_ch_prm_cfg_ktls_keymat *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_ktls_tx_keymat(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				    param->index, param->mode, param->salt,
				    param->key, param->key_len);

	return 0;
}

static int nbl_res_alloc_ktls_rx_index(void *priv, u16 *vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt;
	u32 index;

	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	index = find_first_zero_bit(accel_mgt->rx_ktls_bitmap, NBL_MAX_KTLS_SESSION);
	if (index >= NBL_MAX_KTLS_SESSION)
		return -ENOSPC;

	set_bit(index, accel_mgt->rx_ktls_bitmap);
	accel_mgt->utls_cfg_info[index].vld = true;
	accel_mgt->utls_cfg_info[index].vsi = *vsi;
	return index;
}

static int nbl_res_free_ktls_rx_index(void *priv, u32 *index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt;

	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	clear_bit(*index, accel_mgt->rx_ktls_bitmap);
	memset(&accel_mgt->utls_cfg_info[*index], 0, sizeof(struct nbl_tls_cfg_info));

	return 0;
}

static int nbl_res_cfg_ktls_rx_keymat(void *priv, struct nbl_ch_prm_cfg_ktls_keymat *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_ktls_rx_keymat(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				    param->index, param->mode, param->salt,
				    param->key, param->key_len);

	return 0;
}

static int nbl_res_cfg_ktls_rx_record(void *priv, struct nbl_ch_prm_cfg_ktls_record *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_ktls_rx_record(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				    param->index, param->tcp_sn, param->rec_num,
				    param->init);

	return 0;
}

static int nbl_res_alloc_ipsec_tx_index(void *priv, struct nbl_ch_prm_ipsec_index *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt;
	u32 index;

	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	index = find_first_zero_bit(accel_mgt->tx_ipsec_bitmap, NBL_MAX_IPSEC_SESSION);
	if (index >= NBL_MAX_IPSEC_SESSION)
		return -ENOSPC;

	set_bit(index, accel_mgt->tx_ipsec_bitmap);
	memcpy(&accel_mgt->tx_cfg_info[index], &param->cfg_info, sizeof(struct nbl_ipsec_cfg_info));
	return index;
}

static int nbl_res_free_ipsec_tx_index(void *priv, struct nbl_ch_prm_ipsec_index *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt;

	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	clear_bit(param->index, accel_mgt->tx_ipsec_bitmap);
	memset(&accel_mgt->tx_cfg_info[param->index], 0, sizeof(struct nbl_ipsec_cfg_info));

	return 0;
}

static int nbl_res_alloc_ipsec_rx_index(void *priv, struct nbl_ch_prm_ipsec_index *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt;
	u32 index;

	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	index = find_first_zero_bit(accel_mgt->rx_ipsec_bitmap, NBL_MAX_IPSEC_SESSION);
	if (index >= NBL_MAX_IPSEC_SESSION)
		return -ENOSPC;

	set_bit(index, accel_mgt->rx_ipsec_bitmap);
	memcpy(&accel_mgt->rx_cfg_info[index], &param->cfg_info, sizeof(struct nbl_ipsec_cfg_info));
	return index;
}

static int nbl_res_free_ipsec_rx_index(void *priv, struct nbl_ch_prm_ipsec_index *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt;

	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	clear_bit(param->index, accel_mgt->rx_ipsec_bitmap);
	memset(&accel_mgt->rx_cfg_info[param->index], 0, sizeof(struct nbl_ipsec_cfg_info));

	return 0;
}

static int nbl_res_cfg_ipsec_tx_sad(void *priv, struct nbl_ch_prm_cfg_ipsec_sad *param)
{
	u32 index = param->index;
	struct nbl_ipsec_sa_entry *sa_entry = &param->sa_entry;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;
	struct nbl_ipsec_esn_state *esn_state = &sa_entry->esn_state;
	struct nbl_accel_esp_xfrm_attrs *attrs = &sa_entry->attrs;
	struct nbl_ipsec_cfg_info *cfg_info = &sa_entry->cfg_info;
	struct aes_gcm_keymat *aes_gcm = &attrs->aes_gcm;
	u32 ip_data[NBL_DIPSEC_SAD_IP_TOTAL] = {0};
	int i;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	if (attrs->nat_flag)
		phy_ops->cfg_dipsec_nat(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), attrs->sport);

	phy_ops->cfg_dipsec_sad_iv(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), index, aes_gcm->seq_iv);

	phy_ops->cfg_dipsec_sad_esn(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				    index, esn_state->sn, esn_state->esn,
				    esn_state->wrap_en, esn_state->enable);

	phy_ops->cfg_dipsec_sad_lifetime(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					 index, cfg_info->lft_cnt, cfg_info->lft_diff,
					 cfg_info->limit_enable, cfg_info->limit_type);

	phy_ops->cfg_dipsec_sad_crypto(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				       index, aes_gcm->aes_key, aes_gcm->salt,
				       aes_gcm->crypto_type, attrs->tunnel_mode, aes_gcm->icv_len);

	if (attrs->is_ipv6) {
		for (i = 0; i < NBL_DIPSEC_SAD_IP_LEN; i++)
			ip_data[i] = ntohl(attrs->daddr.a6[NBL_DIPSEC_SAD_IP_LEN - i - 1]);

		for (i = 0; i < NBL_DIPSEC_SAD_IP_LEN; i++)
			ip_data[i + NBL_DIPSEC_SAD_IP_LEN] =
				ntohl(attrs->saddr.a6[NBL_DIPSEC_SAD_IP_LEN - i - 1]);
	} else {
		ip_data[0] = ntohl(attrs->daddr.a4);
		ip_data[NBL_DIPSEC_SAD_IP_LEN] = ntohl(attrs->saddr.a4);
	}

	phy_ops->cfg_dipsec_sad_encap(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				      index, attrs->nat_flag, attrs->dport, attrs->spi, ip_data);

	return 0;
}

static int nbl_res_cfg_ipsec_rx_sad(void *priv, struct nbl_ch_prm_cfg_ipsec_sad *param)
{
	u32 index = param->index;
	struct nbl_ipsec_sa_entry *sa_entry = &param->sa_entry;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;
	struct nbl_ipsec_esn_state *esn_state = &sa_entry->esn_state;
	struct nbl_accel_esp_xfrm_attrs *attrs = &sa_entry->attrs;
	struct nbl_ipsec_cfg_info *cfg_info = &sa_entry->cfg_info;
	struct aes_gcm_keymat *aes_gcm = &attrs->aes_gcm;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	if (attrs->nat_flag)
		phy_ops->cfg_uipsec_nat(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					attrs->nat_flag, attrs->dport);

	phy_ops->cfg_uipsec_sad_esn(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				    index, esn_state->sn, esn_state->esn,
				    esn_state->overlap, esn_state->enable);

	phy_ops->cfg_uipsec_sad_lifetime(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					 index, cfg_info->lft_cnt, cfg_info->lft_diff,
					 cfg_info->limit_enable, cfg_info->limit_type);

	phy_ops->cfg_uipsec_sad_crypto(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				       index, aes_gcm->aes_key, aes_gcm->salt,
				       aes_gcm->crypto_type, attrs->tunnel_mode, aes_gcm->icv_len);

	if (esn_state->window_en)
		phy_ops->cfg_uipsec_sad_window(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					       index, esn_state->window_en, esn_state->option);

	return 0;
}

static void nbl_uipsec_get_em_hash(struct nbl_flow_fem_entry *flow, u8 *key_data)
{
	u16 ht0_hash = 0;
	u16 ht1_hash = 0;
	u8 key[NBL_UIPSEC_BYTE_LEN];
	int i;

	for (i = 0; i < NBL_UIPSEC_BYTE_LEN; i++)
		key[NBL_UIPSEC_BYTE_LEN - 1 - i] = key_data[i];

	ht0_hash = NBL_CRC16_CCITT(key, NBL_UIPSEC_BYTE_LEN);
	ht1_hash = NBL_CRC16_IBM(key, NBL_UIPSEC_BYTE_LEN);

	flow->ht0_hash  = nbl_hash_transfer(ht0_hash, NBL_UIPSEC_POWER, 0);
	flow->ht1_hash = nbl_hash_transfer(ht1_hash, NBL_UIPSEC_POWER, 0);
}

static bool nbl_uipsec_ht0_ht1_search(struct nbl_ipsec_ht_mng *ipsec_ht0_mng, uint16_t ht0_hash,
				      struct nbl_ipsec_ht_mng *ipsec_ht1_mng, uint16_t ht1_hash,
				      struct nbl_common_info *common)
{
	struct nbl_flow_ht_tbl *node0 = NULL;
	struct nbl_flow_ht_tbl *node1 = NULL;
	u16 i = 0;

	node0 = ipsec_ht0_mng->hash_map[ht0_hash];
	if (node0)
		for (i = 0; i < NBL_HASH_CFT_MAX; i++)
			if (node0->key[i].vid == 1 && node0->key[i].ht_other_index == ht1_hash) {
				nbl_info(common, NBL_DEBUG_ACCEL,
					 "Conflicted ht on vid %d and kt_index %u\n",
					 node0->key[i].vid, node0->key[i].kt_index);
				return true;
			}

	node1 = ipsec_ht1_mng->hash_map[ht1_hash];
	if (node1)
		for (i = 0; i < NBL_HASH_CFT_MAX; i++)
			if (node1->key[i].vid == 1 && node1->key[i].ht_other_index == ht0_hash) {
				nbl_info(common, NBL_DEBUG_ACCEL,
					 "Conflicted ht on vid %d and kt_index %u\n",
					 node1->key[i].vid, node1->key[i].kt_index);
				return true;
			}

	return false;
}

static int nbl_uipsec_find_ht_avail_table(struct nbl_ipsec_ht_mng *ipsec_ht0_mng,
					  struct nbl_ipsec_ht_mng *ipsec_ht1_mng,
					  u16 ht0_hash, u16 ht1_hash)
{
	struct nbl_flow_ht_tbl *pp_ht0_node = NULL;
	struct nbl_flow_ht_tbl *pp_ht1_node = NULL;

	pp_ht0_node = ipsec_ht0_mng->hash_map[ht0_hash];
	pp_ht1_node = ipsec_ht1_mng->hash_map[ht1_hash];

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

static void nbl_uipsec_cfg_em_tcam(struct nbl_resource_mgt *res_mgt, u32 index,
				   u32 *data, struct nbl_flow_fem_entry *flow)
{
	struct nbl_accel_mgt *accel_mgt;
	struct nbl_common_info *common;
	struct nbl_phy_ops *phy_ops;
	u16 tcam_index;

	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	common = NBL_RES_MGT_TO_COMMON(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	tcam_index = find_first_zero_bit(accel_mgt->ipsec_tcam_id, NBL_MAX_IPSEC_TCAM);
	if (tcam_index >= NBL_MAX_IPSEC_TCAM) {
		nbl_err(common, NBL_DEBUG_ACCEL,
			"There is no available ipsec tcam id left for sa index %u\n", index);
		return;
	}

	nbl_info(common, NBL_DEBUG_ACCEL,
		 "put sad index %u to ipsec tcam index %u.\n", index, tcam_index);
	phy_ops->cfg_uipsec_em_tcam(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), tcam_index, data);
	phy_ops->cfg_uipsec_em_ad(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), tcam_index, index);

	flow->tcam_index = tcam_index;
	flow->tcam_flag = true;
	set_bit(tcam_index, accel_mgt->ipsec_tcam_id);
}

static int nbl_uipsec_insert_em_ht(struct nbl_ipsec_ht_mng *ipsec_ht_mng,
				   struct nbl_flow_fem_entry *flow)
{
	struct nbl_flow_ht_tbl *node;
	u16 ht_index;
	u16 ht_other_index;
	int i;

	ht_index = (flow->hash_table == NBL_HT0 ? flow->ht0_hash : flow->ht1_hash);
	ht_other_index = (flow->hash_table == NBL_HT0 ? flow->ht1_hash : flow->ht0_hash);

	node = ipsec_ht_mng->hash_map[ht_index];
	if (!node) {
		node = kzalloc(sizeof(*node), GFP_ATOMIC);
		if (!node)
			return -ENOMEM;
		ipsec_ht_mng->hash_map[ht_index] = node;
	}

	for (i = 0; i < NBL_HASH_CFT_MAX; i++) {
		if (node->key[i].vid == 0) {
			node->key[i].vid = 1;
			node->key[i].ht_other_index = ht_other_index;
			node->key[i].kt_index = flow->flow_id;
			node->ref_cnt++;
			flow->hash_bucket = i;
			break;
		}
	}

	return 0;
}

static void nbl_uipsec_cfg_em_flow(struct nbl_resource_mgt *res_mgt, u32 index,
				   u32 *data, struct nbl_flow_fem_entry *flow)
{
	struct nbl_phy_ops *phy_ops;
	u16 ht_table;
	u16 ht_index;
	u16 ht_other_index;
	u16 ht_bucket;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	ht_table = flow->hash_table;
	ht_index = (flow->hash_table == NBL_HT0 ? flow->ht0_hash : flow->ht1_hash);
	ht_other_index = (flow->hash_table == NBL_HT0 ? flow->ht1_hash : flow->ht0_hash);
	ht_bucket = flow->hash_bucket;

	phy_ops->cfg_uipsec_em_ht(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), index, ht_table,
				  ht_index, ht_other_index, ht_bucket);
	phy_ops->cfg_uipsec_em_kt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), index, data);
}

static int nbl_accel_add_uipsec_rule(struct nbl_resource_mgt *res_mgt, u32 index, u32 *data,
				     struct nbl_flow_fem_entry *flow)
{
	struct nbl_accel_mgt *accel_mgt;
	struct nbl_common_info *common;
	struct nbl_phy_ops *phy_ops;
	struct nbl_ipsec_ht_mng *ipsec_ht_mng = NULL;
	u8 key_data[NBL_UIPSEC_BYTE_LEN];
	int ht_table;

	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	common = NBL_RES_MGT_TO_COMMON(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	flow->flow_id = index;
	memcpy(key_data, data, NBL_UIPSEC_BYTE_LEN);
	nbl_uipsec_get_em_hash(flow, key_data);

	/* two flows have the same ht0&ht1, put the conflicted one to tcam */
	if (nbl_uipsec_ht0_ht1_search(&accel_mgt->ipsec_ht0_mng, flow->ht0_hash,
				      &accel_mgt->ipsec_ht1_mng, flow->ht1_hash, common))
		flow->tcam_flag = true;

	ht_table = nbl_uipsec_find_ht_avail_table(&accel_mgt->ipsec_ht0_mng,
						  &accel_mgt->ipsec_ht1_mng,
						  flow->ht0_hash, flow->ht1_hash);
	if (ht_table < 0)
		flow->tcam_flag = true;

	if (flow->tcam_flag) {
		nbl_uipsec_cfg_em_tcam(res_mgt, index, data, flow);
		return 0;
	}

	ipsec_ht_mng =
		(ht_table == NBL_HT0 ? &accel_mgt->ipsec_ht0_mng : &accel_mgt->ipsec_ht1_mng);
	flow->hash_table = ht_table;
	if (nbl_uipsec_insert_em_ht(ipsec_ht_mng, flow))
		return -ENOMEM;

	nbl_info(common, NBL_DEBUG_ACCEL, "cfg uipsec flow_item: %u, %u, %u, %u, %u\n",
		 flow->flow_id, flow->hash_table, flow->ht0_hash,
		 flow->ht1_hash, flow->hash_bucket);
	nbl_uipsec_cfg_em_flow(res_mgt, index, data, flow);

	return 0;
}

static int nbl_accel_add_uipsec_fem(struct nbl_resource_mgt *res_mgt, u32 index, u32 *data,
				    struct nbl_flow_fem_entry *flow)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_ipsec_tbl_add tbl_add = {0};
	struct nbl_ipsec_tbl_add_rsp *tbl_add_rsp;
	struct nbl_ipsec_tbl_write tbl_write = {0};
	struct nbl_ipsec_tbl_write_rsp *tbl_write_rsp;

	flow->kt_idx = index;
	tbl_add.opcode = 0;
	tbl_add.pf_id = NBL_COMMON_TO_ETH_ID(common);
	tbl_add.kt_idx = index;
	tbl_add.oft = 1;
	tbl_add.key_l = data[0];
	tbl_add.key_m[0] = (data[0] >> 15) + (data[1] << 17);
	tbl_add.key_m[1] = (data[1] >> 15) + (data[2] << 17);
	tbl_add.key_m[2] = (data[2] >> 15) + (data[3] << 17);
	tbl_add.key_m[3] = (data[3] >> 15) + (data[4] << 17);
	tbl_add.key_h = (data[4] >> 15) + (tbl_add.pf_id << 17);
	tbl_add.act = index;

	nbl_info(common, NBL_DEBUG_ACCEL, "%s tbl_add = %08x-%08x-%08x-%08x|%08x-%08x-%08x-%08x\n",
		 __func__, ((u32 *)&tbl_add)[0], ((u32 *)&tbl_add)[1], ((u32 *)&tbl_add)[2],
		 ((u32 *)&tbl_add)[3], ((u32 *)&tbl_add)[4], ((u32 *)&tbl_add)[5],
		 ((u32 *)&tbl_add)[6], ((u32 *)&tbl_add)[7]);

	phy_ops->cfg_uipsec_em_cmd(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), (u8 *)&tbl_add);
	tbl_add_rsp = (struct nbl_ipsec_tbl_add_rsp *)&tbl_add;

	nbl_info(common, NBL_DEBUG_ACCEL, "%s tbl_add_rsp = %08x-%08x-%08x-%08x|%08x-%08x-%08x-%08x\n",
		 __func__, ((u32 *)tbl_add_rsp)[0], ((u32 *)tbl_add_rsp)[1],
		 ((u32 *)tbl_add_rsp)[2], ((u32 *)tbl_add_rsp)[3],
		 ((u32 *)tbl_add_rsp)[4], ((u32 *)tbl_add_rsp)[5],
		 ((u32 *)tbl_add_rsp)[6], ((u32 *)tbl_add_rsp)[7]);

	if (tbl_add_rsp->opcode == 0 && tbl_add_rsp->status != 0)
		return -1;

	flow->flow_id = index;
	flow->tcam_flag = tbl_add_rsp->tbl_type;
	flow->hash_table = tbl_add_rsp->tbl_idx >> 8;
	flow->ht_index = tbl_add_rsp->tbl_idx & 0xff;
	flow->ht0_hash = tbl_add_rsp->hash0_data;
	flow->ht1_hash = (tbl_add_rsp->hash1_datal << 6) + tbl_add_rsp->hash1_datah;
	flow->hash_bucket = tbl_add_rsp->slot;
	memcpy(flow->key, data, 20);

	if (!flow->tcam_flag) {
		tbl_write.opcode = 4;
		tbl_write.tbl_type = 2;
		tbl_write.pf_id = NBL_COMMON_TO_ETH_ID(common);
		tbl_write.tbl_addr = index;
		tbl_write.tbl_wdat_l = data[0];
		tbl_write.tbl_wdat_m[0] = (data[0] >> 10) + (data[1] << 22);
		tbl_write.tbl_wdat_m[1] = (data[1] >> 10) + (data[2] << 22);
		tbl_write.tbl_wdat_m[2] = (data[2] >> 10) + (data[3] << 22);
		tbl_write.tbl_wdat_m[3] = (data[3] >> 10) + (data[4] << 22);
		tbl_write.tbl_wdat_m[4] = (data[4] >> 10) + (tbl_write.pf_id << 22) + (index << 24);
		tbl_write.tbl_wdat_h = index >> 8;

		nbl_info(common, NBL_DEBUG_ACCEL, "%s write_kt = %08x-%08x-%08x-%08x|%08x-%08x-%08x-%08x\n",
			 __func__, ((u32 *)&tbl_write)[0], ((u32 *)&tbl_write)[1],
			 ((u32 *)&tbl_write)[2], ((u32 *)&tbl_write)[3],
			 ((u32 *)&tbl_write)[4], ((u32 *)&tbl_write)[5],
			 ((u32 *)&tbl_write)[6], ((u32 *)&tbl_write)[7]);

		phy_ops->cfg_uipsec_em_cmd(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), (u8 *)&tbl_write);
		tbl_write_rsp = (struct nbl_ipsec_tbl_write_rsp *)&tbl_write;
		if (tbl_write_rsp->opcode == 4 && tbl_write_rsp->status != 0)
			return -1;

		nbl_info(common, NBL_DEBUG_ACCEL, "%s tbl_write_rsp = %08x-%08x-%08x-%08x|%08x-%08x-%08x-%08x\n",
			 __func__, ((u32 *)tbl_write_rsp)[0], ((u32 *)tbl_write_rsp)[1],
			 ((u32 *)tbl_write_rsp)[2], ((u32 *)tbl_write_rsp)[3],
			 ((u32 *)tbl_write_rsp)[4], ((u32 *)tbl_write_rsp)[5],
			 ((u32 *)tbl_write_rsp)[6], ((u32 *)tbl_write_rsp)[7]);
	}

	nbl_info(common, NBL_DEBUG_ACCEL, "cfg uipsec flow_item: %u, %u, %u, %u, %u, %u, %u\n",
		 flow->tcam_flag, flow->flow_id, flow->hash_table, flow->ht_index,
		 flow->ht0_hash, flow->ht1_hash, flow->hash_bucket);

	return 0;
}

static int nbl_res_add_ipsec_rx_flow(void *priv, struct nbl_ch_prm_cfg_ipsec_flow *prm)
{
	u32 index = prm->index;
	u32 *data = prm->data;
	u16 vsi = prm->vsi;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_accel_mgt *accel_mgt;
	struct nbl_accel_uipsec_rule *rule;

	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);

	list_for_each_entry(rule, &accel_mgt->uprbac_head, node)
		if (rule->index == index) {
			nbl_err(common, NBL_DEBUG_ACCEL, "rule index %u already exist.\n", index);
			return -EEXIST;
		}

	rule = kzalloc(sizeof(*rule), GFP_ATOMIC);
	if (!rule)
		return -ENOMEM;

	switch (common->product_type) {
	case NBL_LEONIS_TYPE:
		if (nbl_accel_add_uipsec_rule(res_mgt, index, data,  &rule->uipsec_entry)) {
			kfree(rule);
			return -EFAULT;
		}
		break;
	case NBL_DRACO_TYPE:
		if (nbl_accel_add_uipsec_fem(res_mgt, index, data,  &rule->uipsec_entry)) {
			kfree(rule);
			return -EFAULT;
		}
		break;
	default:
		return -EINVAL;
	}

	rule->index = index;
	rule->vsi = vsi;
	list_add_tail(&rule->node, &accel_mgt->uprbac_head);

	return 0;
}

static void nbl_uipsec_clear_em_tcam(struct nbl_resource_mgt *res_mgt,
				     struct nbl_flow_fem_entry *flow)
{
	struct nbl_accel_mgt *accel_mgt;
	struct nbl_common_info *common;
	struct nbl_phy_ops *phy_ops;
	u16 tcam_index;

	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	common = NBL_RES_MGT_TO_COMMON(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	tcam_index = flow->tcam_index;

	nbl_info(common, NBL_DEBUG_ACCEL,
		 "del sad index %u from ipsec tcam index %u.\n", flow->flow_id, tcam_index);
	phy_ops->clear_uipsec_tcam_ad(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), tcam_index);
	clear_bit(tcam_index, accel_mgt->ipsec_tcam_id);
}

static void nbl_uipsec_remove_em_ht(struct nbl_ipsec_ht_mng *ipsec_ht_mng,
				    struct nbl_flow_fem_entry *flow)
{
	struct nbl_flow_ht_tbl *node;
	u16 ht_index;

	ht_index = (flow->hash_table == NBL_HT0 ? flow->ht0_hash : flow->ht1_hash);
	node = ipsec_ht_mng->hash_map[ht_index];
	if (!node)
		return;

	memset(&node->key[flow->hash_bucket], 0, sizeof(node->key[flow->hash_bucket]));
	node->ref_cnt--;
	if (!node->ref_cnt) {
		kfree(node);
		ipsec_ht_mng->hash_map[ht_index] = NULL;
	}
}

static void nbl_uipsec_clear_em_flow(struct nbl_resource_mgt *res_mgt,
				     struct nbl_flow_fem_entry *flow)
{
	struct nbl_phy_ops *phy_ops;
	u16 ht_table;
	u16 ht_index;
	u16 ht_bucket;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	ht_table = flow->hash_table;
	ht_index = (flow->hash_table == NBL_HT0 ? flow->ht0_hash : flow->ht1_hash);
	ht_bucket = flow->hash_bucket;

	phy_ops->clear_uipsec_ht_kt(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), flow->flow_id,
				    ht_table, ht_index, ht_bucket);
}

static void nbl_accel_del_uipsec_rule(struct nbl_resource_mgt *res_mgt,
				      struct nbl_flow_fem_entry *flow)
{
	struct nbl_accel_mgt *accel_mgt;
	struct nbl_common_info *common;
	struct nbl_phy_ops *phy_ops;
	struct nbl_ipsec_ht_mng *ipsec_ht_mng = NULL;

	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	common = NBL_RES_MGT_TO_COMMON(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	if (flow->tcam_flag) {
		nbl_uipsec_clear_em_tcam(res_mgt, flow);
		return;
	}

	ipsec_ht_mng = (flow->hash_table == NBL_HT0 ?
			&accel_mgt->ipsec_ht0_mng : &accel_mgt->ipsec_ht1_mng);
	nbl_uipsec_remove_em_ht(ipsec_ht_mng, flow);
	nbl_info(common, NBL_DEBUG_ACCEL, "del uipsec flow_item: %u, %u, %u, %u, %u\n",
		 flow->flow_id, flow->hash_table, flow->ht0_hash,
		 flow->ht1_hash, flow->hash_bucket);

	nbl_uipsec_clear_em_flow(res_mgt, flow);
}

static int nbl_accel_del_uipsec_fem(struct nbl_resource_mgt *res_mgt,
				    struct nbl_flow_fem_entry *flow)
{
	struct nbl_common_info *common;
	struct nbl_phy_ops *phy_ops;
	struct nbl_ipsec_tbl_search tbl_search = {0};
	struct nbl_ipsec_tbl_search_rsp *tbl_search_rsp;

	common = NBL_RES_MGT_TO_COMMON(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	tbl_search.opcode = 1;
	tbl_search.pf_id = NBL_COMMON_TO_ETH_ID(common);
	if (flow->tcam_flag)
		tbl_search.mode = 1;
	tbl_search.del_on_hit = 1;
	tbl_search.key_l = flow->key[0] + (flow->key[1] << 8) + (flow->key[2] << 16);
	memcpy(tbl_search.key_m, &flow->key[3], 16);
	tbl_search.key_h = flow->key[19] + (tbl_search.pf_id << 8);
	phy_ops->cfg_uipsec_em_cmd(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), (u8 *)&tbl_search);
	tbl_search_rsp = (struct nbl_ipsec_tbl_search_rsp *)&tbl_search;
	if (tbl_search_rsp->opcode == 1 && tbl_search_rsp->status != 0)
		return -1;

	return 0;
}

static int nbl_res_del_ipsec_rx_flow(void *priv, struct nbl_ch_prm_cfg_ipsec_flow *prm)
{
	u32 index = prm->index;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	struct nbl_accel_uipsec_rule *rule;

	list_for_each_entry(rule, &accel_mgt->uprbac_head, node)
		if (rule->index == index)
			break;

	if (nbl_list_entry_is_head(rule, &accel_mgt->uprbac_head, node))
		return 0;

	switch (common->product_type) {
	case NBL_LEONIS_TYPE:
		nbl_accel_del_uipsec_rule(res_mgt, &rule->uipsec_entry);
		break;
	case NBL_DRACO_TYPE:
		nbl_accel_del_uipsec_fem(res_mgt, &rule->uipsec_entry);
		break;
	default:
		return 0;
	}

	list_del(&rule->node);
	kfree(rule);

	return 0;
}

static void nbl_res_flr_clear_accel(void *priv, u16 vf_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	struct nbl_accel_uipsec_rule *uipsec_rule, *uipsec_rule_safe;
	u16 func_id = vf_id + NBL_MAX_PF;
	u16 vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);
	int i;

	for (i = 0; i < NBL_MAX_IPSEC_SESSION; i++) {
		if (accel_mgt->tx_cfg_info[i].vld &&
		    accel_mgt->tx_cfg_info[i].vsi == vsi_id) {
			clear_bit(i, accel_mgt->tx_ipsec_bitmap);
			memset(&accel_mgt->tx_cfg_info[i], 0,
			       sizeof(struct nbl_ipsec_cfg_info));
		}
	}

	list_for_each_entry_safe(uipsec_rule, uipsec_rule_safe,
				 &accel_mgt->uprbac_head, node)
		if (uipsec_rule->vsi == vsi_id) {
			nbl_accel_del_uipsec_rule(res_mgt, &uipsec_rule->uipsec_entry);
			list_del(&uipsec_rule->node);
			kfree(uipsec_rule);
		}

	for (i = 0; i < NBL_MAX_IPSEC_SESSION; i++) {
		if (accel_mgt->rx_cfg_info[i].vld &&
		    accel_mgt->rx_cfg_info[i].vsi == vsi_id) {
			clear_bit(i, accel_mgt->rx_ipsec_bitmap);
			memset(&accel_mgt->rx_cfg_info[i], 0,
			       sizeof(struct nbl_ipsec_cfg_info));
		}
	}

	for (i = 0; i < NBL_MAX_KTLS_SESSION; i++) {
		if (accel_mgt->dtls_cfg_info[i].vld &&
		    accel_mgt->dtls_cfg_info[i].vsi == vsi_id) {
			clear_bit(i, accel_mgt->tx_ktls_bitmap);
			memset(&accel_mgt->dtls_cfg_info[i], 0,
			       sizeof(struct nbl_tls_cfg_info));
		}
	}

	for (i = 0; i < NBL_MAX_KTLS_SESSION; i++) {
		if (accel_mgt->utls_cfg_info[i].vld &&
		    accel_mgt->utls_cfg_info[i].vsi == vsi_id) {
			clear_bit(i, accel_mgt->rx_ktls_bitmap);
			memset(&accel_mgt->utls_cfg_info[i], 0,
			       sizeof(struct nbl_tls_cfg_info));
		}
	}
}

static bool nbl_res_check_ipsec_status(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;
	u32 dipsec_status;
	u32 uipsec_status;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	dipsec_status = phy_ops->read_dipsec_status(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	uipsec_status = phy_ops->read_uipsec_status(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));

	if ((dipsec_status & NBL_IPSEC_SOFT_EXPIRE) ||
	    (dipsec_status & NBL_IPSEC_HARD_EXPIRE) ||
	    ((uipsec_status) & NBL_IPSEC_SOFT_EXPIRE) ||
	    ((uipsec_status) & NBL_IPSEC_HARD_EXPIRE))
		return true;

	return false;
}

static u32 nbl_res_get_dipsec_lft_info(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;
	union nbl_ipsec_lft_info lft_info;
	u32 dipsec_status;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	lft_info.data = phy_ops->read_dipsec_lft_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	dipsec_status = phy_ops->reset_dipsec_status(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	lft_info.soft_vld = !!(dipsec_status & NBL_IPSEC_SOFT_EXPIRE);
	lft_info.hard_vld = !!(dipsec_status & NBL_IPSEC_HARD_EXPIRE);

	return lft_info.data;
}

static int nbl_res_handle_dipsec_soft_expire(void *priv, u32 *index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common;
	struct nbl_accel_mgt *accel_mgt;
	struct nbl_phy_ops *phy_ops;
	struct nbl_ipsec_cfg_info *cfg_info;
	u32 lifetime_diff;
	u32 flag_wen;
	u32 msb_wen;
	bool need = false;

	common = NBL_RES_MGT_TO_COMMON(res_mgt);
	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	cfg_info = &accel_mgt->tx_cfg_info[*index];

	if (!cfg_info->vld)
		return 0;

	if (cfg_info->soft_round == 0) {
		nbl_info(common, NBL_DEBUG_ACCEL, "dipsec sa %u soft expire.\n", *index);
		if (cfg_info->hard_round == 0) {
			lifetime_diff = 0;
			flag_wen = 1;
			msb_wen = 0;
			need = true;
		}
	}

	if (cfg_info->hard_round == 1) {
		if (cfg_info->hard_remain > cfg_info->soft_remain)
			lifetime_diff = cfg_info->hard_remain -
					cfg_info->soft_remain;
		else
			lifetime_diff = (1 << NBL_IPSEC_LIFETIME_ROUND) +
					cfg_info->hard_remain -
					cfg_info->soft_remain;
		flag_wen = 1;
		msb_wen = 0;
		need = true;
		if (cfg_info->soft_round > 0)
			nbl_info(common, NBL_DEBUG_ACCEL,
				 "dipsec sa %u soft expire in advance.\n", *index);
	}

	if (cfg_info->hard_round > 1) {
		lifetime_diff = 0;
		flag_wen = 0;
		msb_wen = 1;
		need = true;
		if (cfg_info->soft_round)
			cfg_info->soft_round--;
		cfg_info->hard_round--;
	}

	if (need)
		phy_ops->cfg_dipsec_lft_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), *index,
					     lifetime_diff, flag_wen, msb_wen);

	return 0;
}

static u32 nbl_res_get_uipsec_lft_info(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;
	union nbl_ipsec_lft_info lft_info;
	u32 uipsec_status;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	lft_info.data = phy_ops->read_uipsec_lft_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	uipsec_status = phy_ops->reset_uipsec_status(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	lft_info.soft_vld = !!(uipsec_status & NBL_IPSEC_SOFT_EXPIRE);
	lft_info.hard_vld = !!(uipsec_status & NBL_IPSEC_HARD_EXPIRE);

	return lft_info.data;
}

static int nbl_res_handle_uipsec_soft_expire(void *priv, u32 *index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common;
	struct nbl_accel_mgt *accel_mgt;
	struct nbl_phy_ops *phy_ops;
	struct nbl_ipsec_cfg_info *cfg_info;
	u32 lifetime_diff;
	u32 flag_wen;
	u32 msb_wen;
	bool need = false;

	common = NBL_RES_MGT_TO_COMMON(res_mgt);
	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	cfg_info = &accel_mgt->rx_cfg_info[*index];

	if (!cfg_info->vld)
		return 0;

	if (cfg_info->soft_round == 0) {
		nbl_info(common, NBL_DEBUG_ACCEL, "uipsec sa %u soft expire.\n", *index);
		if (cfg_info->hard_round == 0) {
			lifetime_diff = 0;
			flag_wen = 1;
			msb_wen = 0;
			need = true;
		}
	}

	if (cfg_info->hard_round == 1) {
		if (cfg_info->hard_remain > cfg_info->soft_remain)
			lifetime_diff = cfg_info->hard_remain -
					cfg_info->soft_remain;
		else
			lifetime_diff = (1 << NBL_IPSEC_LIFETIME_ROUND) +
					cfg_info->hard_remain -
					cfg_info->soft_remain;
		flag_wen = 1;
		msb_wen = 0;
		need = true;
		if (cfg_info->soft_round > 0)
			nbl_info(common, NBL_DEBUG_ACCEL,
				 "uipsec sa %u soft expire in advance.\n", *index);
	}

	if (cfg_info->hard_round > 1) {
		lifetime_diff = 0;
		flag_wen = 0;
		msb_wen = 1;
		need = true;
		if (cfg_info->soft_round)
			cfg_info->soft_round--;
		cfg_info->hard_round--;
	}

	if (need)
		phy_ops->cfg_uipsec_lft_info(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), *index,
					     lifetime_diff, flag_wen, msb_wen);

	return 0;
}

static int nbl_res_handle_dipsec_hard_expire(void *priv, u32 *index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common;
	struct nbl_channel_ops *chan_ops;
	struct nbl_accel_mgt *accel_mgt;
	struct nbl_sa_search_key param;
	struct nbl_chan_send_info chan_send;
	u16 vsid;
	u16 dstid;

	chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	common = NBL_RES_MGT_TO_COMMON(res_mgt);

	if (!accel_mgt->tx_cfg_info[*index].vld)
		return 0;

	vsid = accel_mgt->tx_cfg_info[*index].vsi;
	dstid = nbl_res_vsi_id_to_func_id(res_mgt, vsid);
	param.family = accel_mgt->tx_cfg_info[*index].sa_key.family;
	param.mark = accel_mgt->tx_cfg_info[*index].sa_key.mark;
	param.spi = accel_mgt->tx_cfg_info[*index].sa_key.spi;
	memcpy(&param.daddr, &accel_mgt->tx_cfg_info[*index].sa_key.daddr, sizeof(param.daddr));

	nbl_info(common, NBL_DEBUG_ACCEL, "dipsec sa %u hard expire.\n", *index);
	NBL_CHAN_SEND(chan_send, dstid, NBL_CHAN_MSG_NOTIFY_IPSEC_HARD_EXPIRE, &param,
		      sizeof(param), NULL, 0, 0);
	chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);

	return 0;
}

static int nbl_res_handle_uipsec_hard_expire(void *priv, u32 *index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common;
	struct nbl_channel_ops *chan_ops;
	struct nbl_accel_mgt *accel_mgt;
	struct nbl_sa_search_key param;
	struct nbl_chan_send_info chan_send;
	u16 vsid;
	u16 dstid;

	chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	common = NBL_RES_MGT_TO_COMMON(res_mgt);

	if (!accel_mgt->rx_cfg_info[*index].vld)
		return 0;

	vsid = accel_mgt->rx_cfg_info[*index].vsi;
	dstid = nbl_res_vsi_id_to_func_id(res_mgt, vsid);
	param.family = accel_mgt->rx_cfg_info[*index].sa_key.family;
	param.mark = accel_mgt->rx_cfg_info[*index].sa_key.mark;
	param.spi = accel_mgt->rx_cfg_info[*index].sa_key.spi;
	memcpy(&param.daddr, &accel_mgt->rx_cfg_info[*index].sa_key.daddr, sizeof(param.daddr));

	nbl_info(common, NBL_DEBUG_ACCEL, "uipsec sa %u hard expire.\n", *index);
	NBL_CHAN_SEND(chan_send, dstid, NBL_CHAN_MSG_NOTIFY_IPSEC_HARD_EXPIRE, &param,
		      sizeof(param), NULL, 0, 0);
	chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);

	return 0;
}

/* NBL_ACCEL_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_ACCEL_OPS_TBL								\
do {											\
	NBL_ACCEL_SET_OPS(alloc_ktls_tx_index, nbl_res_alloc_ktls_tx_index);		\
	NBL_ACCEL_SET_OPS(free_ktls_tx_index, nbl_res_free_ktls_tx_index);		\
	NBL_ACCEL_SET_OPS(cfg_ktls_tx_keymat, nbl_res_cfg_ktls_tx_keymat);		\
	NBL_ACCEL_SET_OPS(alloc_ktls_rx_index, nbl_res_alloc_ktls_rx_index);		\
	NBL_ACCEL_SET_OPS(free_ktls_rx_index, nbl_res_free_ktls_rx_index);		\
	NBL_ACCEL_SET_OPS(cfg_ktls_rx_keymat, nbl_res_cfg_ktls_rx_keymat);		\
	NBL_ACCEL_SET_OPS(cfg_ktls_rx_record, nbl_res_cfg_ktls_rx_record);		\
	NBL_ACCEL_SET_OPS(alloc_ipsec_tx_index, nbl_res_alloc_ipsec_tx_index);		\
	NBL_ACCEL_SET_OPS(free_ipsec_tx_index, nbl_res_free_ipsec_tx_index);		\
	NBL_ACCEL_SET_OPS(alloc_ipsec_rx_index, nbl_res_alloc_ipsec_rx_index);		\
	NBL_ACCEL_SET_OPS(free_ipsec_rx_index, nbl_res_free_ipsec_rx_index);		\
	NBL_ACCEL_SET_OPS(cfg_ipsec_tx_sad, nbl_res_cfg_ipsec_tx_sad);			\
	NBL_ACCEL_SET_OPS(cfg_ipsec_rx_sad, nbl_res_cfg_ipsec_rx_sad);			\
	NBL_ACCEL_SET_OPS(add_ipsec_rx_flow, nbl_res_add_ipsec_rx_flow);		\
	NBL_ACCEL_SET_OPS(del_ipsec_rx_flow, nbl_res_del_ipsec_rx_flow);		\
	NBL_ACCEL_SET_OPS(flr_clear_accel, nbl_res_flr_clear_accel);			\
	NBL_ACCEL_SET_OPS(check_ipsec_status, nbl_res_check_ipsec_status);		\
	NBL_ACCEL_SET_OPS(get_dipsec_lft_info, nbl_res_get_dipsec_lft_info);		\
	NBL_ACCEL_SET_OPS(handle_dipsec_soft_expire, nbl_res_handle_dipsec_soft_expire);\
	NBL_ACCEL_SET_OPS(handle_dipsec_hard_expire, nbl_res_handle_dipsec_hard_expire);\
	NBL_ACCEL_SET_OPS(get_uipsec_lft_info, nbl_res_get_uipsec_lft_info);		\
	NBL_ACCEL_SET_OPS(handle_uipsec_soft_expire, nbl_res_handle_uipsec_soft_expire);\
	NBL_ACCEL_SET_OPS(handle_uipsec_hard_expire, nbl_res_handle_uipsec_hard_expire);\
} while (0)

/* temp code*/
static DECLARE_BITMAP(tx_ktls_bitmap, NBL_ACCEL_TMEP_SPEC);

static int nbl_res_alloc_ktls_tx_index_draco(void *priv, u16 *vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	u32 index;

	index = find_first_zero_bit(tx_ktls_bitmap, NBL_ACCEL_TMEP_SPEC);
	if (index >= NBL_ACCEL_TMEP_SPEC)
		return -ENOSPC;

	set_bit(index, tx_ktls_bitmap);
	accel_mgt->dtls_cfg_info[index].vld = true;
	accel_mgt->dtls_cfg_info[index].vsi = *vsi;

	return index;
}

static int nbl_res_free_ktls_tx_index_draco(void *priv, u32 *index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);

	clear_bit(*index, tx_ktls_bitmap);
	memset(&accel_mgt->dtls_cfg_info[*index], 0, sizeof(struct nbl_tls_cfg_info));

	return 0;
}

/* temp code*/
static DECLARE_BITMAP(rx_ktls_bitmap, NBL_ACCEL_TMEP_SPEC);

static int nbl_res_alloc_ktls_rx_index_draco(void *priv, u16 *vsi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	u32 index;

	index = find_first_zero_bit(rx_ktls_bitmap, NBL_ACCEL_TMEP_SPEC);
	if (index >= NBL_ACCEL_TMEP_SPEC)
		return -ENOSPC;

	set_bit(index, rx_ktls_bitmap);
	accel_mgt->utls_cfg_info[index].vld = true;
	accel_mgt->utls_cfg_info[index].vsi = *vsi;

	return index;
}

static int nbl_res_free_ktls_rx_index_draco(void *priv, u32 *index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);

	clear_bit(*index, rx_ktls_bitmap);
	memset(&accel_mgt->utls_cfg_info[*index], 0, sizeof(struct nbl_tls_cfg_info));

	return 0;
}

/* temp code*/
static DECLARE_BITMAP(tx_ipsec_bitmap, NBL_ACCEL_TMEP_SPEC);

static int nbl_res_alloc_ipsec_tx_index_draco(void *priv, struct nbl_ch_prm_ipsec_index *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	u32 index;

	index = find_next_zero_bit(tx_ipsec_bitmap, NBL_ACCEL_TMEP_SPEC, 1);
	if (index >= NBL_ACCEL_TMEP_SPEC)
		return -ENOSPC;

	set_bit(index, tx_ipsec_bitmap);
	memcpy(&accel_mgt->tx_cfg_info[index], &param->cfg_info, sizeof(struct nbl_ipsec_cfg_info));
	return index;
}

static int nbl_res_free_ipsec_tx_index_draco(void *priv, struct nbl_ch_prm_ipsec_index *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);

	clear_bit(param->index, tx_ipsec_bitmap);
	memset(&accel_mgt->tx_cfg_info[param->index], 0, sizeof(struct nbl_ipsec_cfg_info));

	return 0;
}

static int nbl_res_alloc_ipsec_rx_index_draco(void *priv, struct nbl_ch_prm_ipsec_index *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_ipsec_kt_alloc kt_alloc = {0};
	struct nbl_ipsec_kt_alloc_rsp *kt_alloc_rsp;
	u32 index, i;
	bool find = false;

	for (i = 0; i < NBL_IPSEC_BLOCK_NUM; i++) {
		if (accel_mgt->available_ipsec_idx[i] != 0) {
			find = true;
			break;
		}
	}

	if (!find) {
		kt_alloc.opcode = 2;
		kt_alloc.pf_id = NBL_COMMON_TO_ETH_ID(common);
		phy_ops->cfg_uipsec_em_cmd(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), (u8 *)&kt_alloc);
		kt_alloc_rsp = (struct nbl_ipsec_kt_alloc_rsp *)&kt_alloc;
		if (kt_alloc_rsp->opcode == 2 && kt_alloc_rsp->status != 0)
			return -ENOSPC;

		i = kt_alloc_rsp->kt_idx / 16;
		accel_mgt->start_ipsec_idx[i] = kt_alloc_rsp->kt_idx;
		accel_mgt->available_ipsec_idx[i] = 16;

		if (kt_alloc_rsp->kt_idx == 0) {
			set_bit(0, accel_mgt->rx_ipsec_bitmap);
			accel_mgt->available_ipsec_idx[0]--;
		}
	}

	index = find_next_zero_bit(accel_mgt->rx_ipsec_bitmap,
				   NBL_ACCEL_TMEP_SPEC, accel_mgt->start_ipsec_idx[i]);
	set_bit(index, accel_mgt->rx_ipsec_bitmap);
	accel_mgt->available_ipsec_idx[i]--;
	memcpy(&accel_mgt->rx_cfg_info[index], &param->cfg_info, sizeof(struct nbl_ipsec_cfg_info));

	return index;
}

static int nbl_res_free_ipsec_rx_index_draco(void *priv, struct nbl_ch_prm_ipsec_index *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_ipsec_kt_free kt_free = {0};
	u32 index = param->index;
	u32 i = index / 16;

	memset(&accel_mgt->rx_cfg_info[index], 0, sizeof(struct nbl_ipsec_cfg_info));
	clear_bit(index, accel_mgt->rx_ipsec_bitmap);
	accel_mgt->available_ipsec_idx[i]++;

	if (accel_mgt->available_ipsec_idx[i] == 16) {
		kt_free.opcode = 3;
		kt_free.mode = 0;
		kt_free.pf_id = NBL_COMMON_TO_ETH_ID(common);
		kt_free.kt_idx = accel_mgt->start_ipsec_idx[i];
		phy_ops->cfg_uipsec_em_cmd(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), (u8 *)&kt_free);
		accel_mgt->start_ipsec_idx[i] = 0;
		accel_mgt->available_ipsec_idx[i] = 0;
	}

	return 0;
}

static int nbl_res_alloc_macsec_txsc_index(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u8 eth_id = NBL_COMMON_TO_ETH_ID(common);
	u8 eth_mode = NBL_COMMON_TO_ETH_MODE(common);
	u8 index, per_sc, sc_start, sc_end;

	per_sc = NBL_MAX_MACSEC_SC / eth_mode;
	sc_start = per_sc * eth_id;
	sc_end = per_sc * (eth_id + 1) - 1;

	index = find_first_zero_bit(accel_mgt->tx_macsec_sc_bitmap, NBL_MAX_MACSEC_SC);
	while (index < sc_start) {
		index = find_next_zero_bit(accel_mgt->tx_macsec_sc_bitmap,
					   NBL_MAX_MACSEC_SC, index + 1);
	}

	if (index > sc_end)
		return -ENOSPC;

	set_bit(index, accel_mgt->tx_macsec_sc_bitmap);
	return index;
}

static void nbl_res_free_macsec_txsc_index(void *priv, u8 index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);

	clear_bit(index, accel_mgt->tx_macsec_sc_bitmap);
}

static int nbl_res_alloc_macsec_rxsc_index(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u8 eth_id = NBL_COMMON_TO_ETH_ID(common);
	u8 eth_mode = NBL_COMMON_TO_ETH_MODE(common);
	u8 index, per_sc, sc_start, sc_end;

	per_sc = NBL_MAX_MACSEC_SC / eth_mode;
	sc_start = per_sc * eth_id;
	sc_end = per_sc * (eth_id + 1) - 1;

	index = find_first_zero_bit(accel_mgt->rx_macsec_sc_bitmap, NBL_MAX_MACSEC_SC);
	while (index < sc_start) {
		index = find_next_zero_bit(accel_mgt->rx_macsec_sc_bitmap,
					   NBL_MAX_MACSEC_SC, index + 1);
	}

	if (index > sc_end)
		return -ENOSPC;

	set_bit(index, accel_mgt->rx_macsec_sc_bitmap);
	return index;
}

static void nbl_res_free_macsec_rxsc_index(void *priv, u8 index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_accel_mgt *accel_mgt = NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);

	clear_bit(index, accel_mgt->rx_macsec_sc_bitmap);
}

static void nbl_res_cfg_macsec_fs(void *priv, u32 index, struct nbl_macsec_fs *macsec_fs)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_macsec_fs(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), index, macsec_fs);
}

static void nbl_res_cfg_macsec_txsc(void *priv, u32 index, struct nbl_macsec_tx_sc *tx_sc)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_macsec_txsc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), index, tx_sc);
}

static void nbl_res_cfg_macsec_rxsc(void *priv, u32 index, struct nbl_macsec_rx_sc *rx_sc)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_macsec_rxsc(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), index, rx_sc);
}

static void nbl_res_cfg_macsec_sa(void *priv, u32 index, struct nbl_macsec_sa *sa, bool is_tx)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->cfg_macsec_sa(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), index, sa, is_tx);
}

#define NBL_ACCEL_OPS_TBL_DRACO								\
do {											\
	NBL_ACCEL_SET_OPS(alloc_ktls_tx_index, nbl_res_alloc_ktls_tx_index_draco);	\
	NBL_ACCEL_SET_OPS(free_ktls_tx_index, nbl_res_free_ktls_tx_index_draco);	\
	NBL_ACCEL_SET_OPS(alloc_ktls_rx_index, nbl_res_alloc_ktls_rx_index_draco);	\
	NBL_ACCEL_SET_OPS(free_ktls_rx_index, nbl_res_free_ktls_rx_index_draco);	\
	NBL_ACCEL_SET_OPS(alloc_ipsec_tx_index, nbl_res_alloc_ipsec_tx_index_draco);	\
	NBL_ACCEL_SET_OPS(free_ipsec_tx_index, nbl_res_free_ipsec_tx_index_draco);	\
	NBL_ACCEL_SET_OPS(alloc_ipsec_rx_index, nbl_res_alloc_ipsec_rx_index_draco);	\
	NBL_ACCEL_SET_OPS(free_ipsec_rx_index, nbl_res_free_ipsec_rx_index_draco);	\
	NBL_ACCEL_SET_OPS(alloc_macsec_txsc_index, nbl_res_alloc_macsec_txsc_index);	\
	NBL_ACCEL_SET_OPS(free_macsec_txsc_index, nbl_res_free_macsec_txsc_index);	\
	NBL_ACCEL_SET_OPS(alloc_macsec_rxsc_index, nbl_res_alloc_macsec_rxsc_index);	\
	NBL_ACCEL_SET_OPS(free_macsec_rxsc_index, nbl_res_free_macsec_rxsc_index);	\
	NBL_ACCEL_SET_OPS(cfg_macsec_fs, nbl_res_cfg_macsec_fs);			\
	NBL_ACCEL_SET_OPS(cfg_macsec_txsc, nbl_res_cfg_macsec_txsc);			\
	NBL_ACCEL_SET_OPS(cfg_macsec_rxsc, nbl_res_cfg_macsec_rxsc);			\
	NBL_ACCEL_SET_OPS(cfg_macsec_sa, nbl_res_cfg_macsec_sa);			\
} while (0)

/* Structure starts here, adding an op should not modify anything below */
static int nbl_accel_setup_mgt(struct device *dev, struct nbl_accel_mgt **accel_mgt)
{
	*accel_mgt = devm_kzalloc(dev, sizeof(struct nbl_accel_mgt), GFP_KERNEL);
	if (!*accel_mgt)
		return -ENOMEM;

	INIT_LIST_HEAD(&(*accel_mgt)->uprbac_head);
	return 0;
}

static void nbl_accel_remove_mgt(struct device *dev, struct nbl_accel_mgt **accel_mgt)
{
	devm_kfree(dev, *accel_mgt);
	*accel_mgt = NULL;
}

int nbl_accel_mgt_start(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_accel_mgt **accel_mgt;
	struct nbl_phy_ops *phy_ops;
	struct device *dev;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	accel_mgt = &NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->init_dprbac(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	phy_ops->init_uprbac(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));

	return nbl_accel_setup_mgt(dev, accel_mgt);
}

void nbl_accel_mgt_stop(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_accel_mgt **accel_mgt;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	accel_mgt = &NBL_RES_MGT_TO_ACCEL_MGT(res_mgt);

	if (!(*accel_mgt))
		return;

	nbl_accel_remove_mgt(dev, accel_mgt);
}

int nbl_accel_setup_ops(struct nbl_resource_ops *res_ops, bool is_draco)
{
	if (!res_ops)
		return -EINVAL;

#define NBL_ACCEL_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_ACCEL_OPS_TBL;
#undef  NBL_ACCEL_SET_OPS

	if (is_draco) {
#define NBL_ACCEL_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
		NBL_ACCEL_OPS_TBL_DRACO;
#undef  NBL_ACCEL_SET_OPS
	}

	return 0;
}

