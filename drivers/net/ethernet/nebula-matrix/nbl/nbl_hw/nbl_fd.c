// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_fd.h"
#include "nbl_p4_actions.h"

struct nbl_fd_get_tlv_udf {
	u64 val;
	u64 mask;
	bool valid;
};

struct nbl_fd_tcam_default_entry {
	union nbl_fd_tcam_default_data_u data;
	union nbl_fd_tcam_default_data_u mask;
	struct nbl_flow_direct_entry *entry;
	struct nbl_resource_mgt *res_mgt;
	/* leonis action is 32bit, draco action is 82bit */
	u32 action[3];
};

struct nbl_rdma_tcam_default_entry {
	union nbl_rdma_tcam_default_data_u data;
	union nbl_rdma_tcam_default_data_u mask;
	u32 action[3];
};

static int nbl_fd_get_profile_id(enum nbl_chan_fdir_flow_type type, u8 mode)
{
	switch (type) {
	case NBL_CHAN_FDIR_FLOW_TCP_IPv4:
	case NBL_CHAN_FDIR_FLOW_UDP_IPv4:
	case NBL_CHAN_FDIR_FLOW_IPv4:
		return mode == NBL_FD_MODE_DEFAULT ? NBL_FD_PROFILE_DEFAULT : NBL_FD_PROFILE_IPV4;
	case NBL_CHAN_FDIR_FLOW_TCP_IPv6:
	case NBL_CHAN_FDIR_FLOW_UDP_IPv6:
	case NBL_CHAN_FDIR_FLOW_IPv6:
	case NBL_CHAN_FDIR_FLOW_ETHER:
	case NBL_CHAN_FDIR_FLOW_FULL:
		return mode == NBL_FD_MODE_DEFAULT ? NBL_FD_PROFILE_DEFAULT :
						     NBL_FD_PROFILE_L2_IPV6;
	default:
		break;
	};

	return -1;
}

static struct nbl_flow_direct_entry *nbl_fd_find_flow(struct nbl_flow_direct_info *info,
						      enum nbl_chan_fdir_rule_type rule_type,
						      u32 loc)
{
	struct nbl_flow_direct_entry *entry = NULL;

	if (rule_type >= NBL_CHAN_FDIR_RULE_MAX)
		return NULL;

	list_for_each_entry(entry, &info->list[rule_type], node)
		if (entry->param.location == loc)
			return entry;

	return NULL;
}

static int nbl_fd_get_udf(u16 type, u16 length, u8 *val, void *data)
{
	struct nbl_fd_get_tlv_udf *udf = (struct nbl_fd_get_tlv_udf *)data;

	if (type != NBL_CHAN_FDIR_KEY_UDF)
		return 0;

	udf->valid = 1;
	udf->val = *(u64 *)val;
	udf->mask = *(u64 *)(val + 8);

	return 1;
}

static u16 nbl_fd_get_flow_layer(enum nbl_chan_fdir_flow_type type)
{
	switch (type) {
	case NBL_CHAN_FDIR_FLOW_ETHER:
		return 0;
	case NBL_CHAN_FDIR_FLOW_IPv4:
	case NBL_CHAN_FDIR_FLOW_IPv6:
		return 1;
	case NBL_CHAN_FDIR_FLOW_TCP_IPv4:
	case NBL_CHAN_FDIR_FLOW_TCP_IPv6:
	case NBL_CHAN_FDIR_FLOW_UDP_IPv4:
	case NBL_CHAN_FDIR_FLOW_UDP_IPv6:
	case NBL_CHAN_FDIR_FLOW_FULL:
	default:
		return 2;
	}
}

static int nbl_fd_send_udf_event(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u8 pf_id = NBL_COMMON_TO_MGT_PF(common);
	struct nbl_udf_cfg udf_cfg = {0};

	udf_cfg.udf_cnt = fd_mgt->udf_cnt;
	udf_cfg.udf_offset = fd_mgt->udf_offset;
	udf_cfg.udf_layer = fd_mgt->udf_layer;
	udf_cfg.pf_id = pf_id;
	nbl_devcomm_send_event(fd_mgt->comp_dev, NBL_DEVCOMM_FD_CFG_UPDATE_UDF_EVENT,
			       NBL_DEVCOMM_FD_CFG_UPDATE_UDF_EVENT, &udf_cfg);
	return 0;
}

static int nbl_fd_validate_udf_rule(struct nbl_resource_mgt *res_mgt, u16 udf_offset, u16 udf_layer)
{
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u8 pf_id = NBL_COMMON_TO_MGT_PF(common);
	int i = 0;

	for (i = 0; i < eth_info->eth_num; i++) {
		if (i == pf_id)
			continue;

		if (fd_mgt->other_udf_cfg[i].udf_cnt > 0 &&
		    (fd_mgt->other_udf_cfg[i].udf_offset != udf_offset ||
		     fd_mgt->other_udf_cfg[i].udf_layer != udf_layer))
			return -EINVAL;
	}
	return 0;
}

static int nbl_fd_validate_rule(struct nbl_resource_mgt *res_mgt,
				struct nbl_chan_param_fdir_replace *param,
				struct nbl_flow_direct_entry *entry)
{
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_fd_get_tlv_udf udf = {0};
	int pid = -1;
	u16 udf_offset;
	u16 udf_layer;
	bool rule_udf = false;
	u8 *tlv;

	if (param->rule_type >= NBL_CHAN_FDIR_RULE_MAX)
		return -EINVAL;

	tlv = (u8 *)param + param->base_length;
	nbl_flow_direct_parse_tlv_data(tlv, param->tlv_length, nbl_fd_get_udf, &udf);
	if (udf.valid) {
		udf_offset = (udf.val & NBL_FD_UDF_FLEX_OFFS_M) >> NBL_FD_UDF_FLEX_OFFS_S;
		udf_layer = nbl_fd_get_flow_layer(param->flow_type);

		if (entry)
			rule_udf = entry->udf;

		/* Offset must be the same for all rules */
		if (fd_mgt->udf_cnt > 0 &&
		    (fd_mgt->udf_offset != udf_offset || fd_mgt->udf_layer != udf_layer) &&
		    (fd_mgt->udf_cnt != 1 || !rule_udf))
			return -EINVAL;

		if (udf_offset > 52)
			return -EINVAL;

		/* For offset, we don't support mask */
		if (((udf.mask & NBL_FD_UDF_FLEX_OFFS_M) >> NBL_FD_UDF_FLEX_OFFS_S) != 0xFFFFFFFF)
			return -EINVAL;

		if (nbl_fd_validate_udf_rule(res_mgt, udf_offset, udf_layer))
			return -EINVAL;
	}

	/* replace rule not check cnt current, alway keep full mode */
	if (entry)
		return 0;

	pid = nbl_fd_get_profile_id(param->flow_type, fd_mgt->mode);
	switch (pid) {
	case NBL_FD_PROFILE_DEFAULT:
		if (fd_mgt->cnt[NBL_FD_PROFILE_DEFAULT] >= fd_mgt->max_spec)
			return -EINVAL;
		break;
	case NBL_FD_PROFILE_IPV4:
		if (fd_mgt->mode == NBL_FD_MODE_LITE &&
		    fd_mgt->cnt[NBL_FD_PROFILE_IPV4] >= NBL_FD_RULE_MAX_1536)
			return -EINVAL;
		if (fd_mgt->mode == NBL_FD_MODE_FULL &&
		    fd_mgt->cnt[NBL_FD_PROFILE_IPV4] >= NBL_FD_RULE_MAX_512 &&
		    fd_mgt->cnt[NBL_FD_PROFILE_L2_IPV6] > 0)
			return -EINVAL;
		break;
	case NBL_FD_PROFILE_L2_IPV6:
		/* We will always try to change the mode to FULL, so if we are in LITE now,
		 * then don't support any IPV6 rules whatsoever.
		 */
		if (fd_mgt->mode == NBL_FD_MODE_LITE ||
		    fd_mgt->cnt[NBL_FD_PROFILE_L2_IPV6] >= NBL_FD_RULE_MAX_512)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static struct nbl_flow_direct_entry *nbl_fd_add_flow(struct nbl_resource_mgt *res_mgt,
						     struct nbl_flow_direct_info *info,
						     struct nbl_chan_param_fdir_replace *param)
{
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_flow_direct_entry *entry = NULL, *next = NULL;
	struct nbl_fd_get_tlv_udf udf = {0};
	u8 pid;

	pid = nbl_fd_get_profile_id(param->flow_type, fd_mgt->mode);
	if (pid > NBL_FD_PROFILE_MAX)
		return NULL;

	entry = kzalloc(sizeof(*entry) + param->tlv_length, GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->pid = pid;
	memcpy(&entry->param, param, min_t(u32, sizeof(entry->param), param->base_length));
	memcpy(entry->param.tlv, ((u8 *)param + param->base_length), param->tlv_length);
	entry->param.base_length = sizeof(entry->param);

	/* Maintain order */
	if (param->order) {
		list_for_each_entry(next, &info->list[param->rule_type], node)
			if (next->param.location >= entry->param.location)
				break;

		if (nbl_list_entry_is_head(next, &info->list[param->rule_type], node))
			list_add_tail(&entry->node, &info->list[param->rule_type]);
		else
			list_add(&entry->node, &list_prev_entry(next, node)->node);
	} else {
		list_add_tail(&entry->node, &info->list[param->rule_type]);
	}

	info->cnt[param->rule_type]++;
	fd_mgt->cnt[entry->pid]++;

	/* We have judged the capacity in validation, so we shouldn't have any trouble now. */
	if (fd_mgt->mode == NBL_FD_MODE_FULL &&
	    fd_mgt->cnt[NBL_FD_PROFILE_IPV4] > NBL_FD_RULE_MAX_512)
		fd_mgt->mode = NBL_FD_MODE_LITE;

	nbl_flow_direct_parse_tlv_data(param->tlv, param->tlv_length, nbl_fd_get_udf, &udf);
	if (udf.valid) {
		entry->udf = 1;
		fd_mgt->udf_offset = (udf.val & NBL_FD_UDF_FLEX_OFFS_M) >> NBL_FD_UDF_FLEX_OFFS_S;
		fd_mgt->udf_cnt++;
		fd_mgt->udf_layer = nbl_fd_get_flow_layer(param->flow_type);
		nbl_fd_send_udf_event(res_mgt);
	}

	return entry;
}

static void nbl_fd_del_flow(struct nbl_resource_mgt *res_mgt,
			    struct nbl_flow_direct_info *info,
			    struct nbl_flow_direct_entry *entry)
{
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);

	info->cnt[entry->param.rule_type]--;
	fd_mgt->cnt[entry->pid]--;

	if (entry->udf) {
		fd_mgt->udf_cnt--;
		nbl_fd_send_udf_event(res_mgt);
	}

	if (fd_mgt->mode == NBL_FD_MODE_LITE &&
	    fd_mgt->cnt[NBL_FD_PROFILE_IPV4] <= NBL_FD_RULE_MAX_512)
		fd_mgt->mode = NBL_FD_MODE_FULL;

	list_del(&entry->node);
	kfree(entry);
}

static int nbl_fd_find_and_del_flow(struct nbl_resource_mgt *res_mgt,
				    struct nbl_flow_direct_info *info,
				    enum nbl_chan_fdir_rule_type rule_type,
				    u32 loc)
{
	struct nbl_flow_direct_entry *entry = nbl_fd_find_flow(info, rule_type, loc);

	if (!entry)
		return -ENOENT;

	nbl_fd_del_flow(res_mgt, info, entry);

	return 0;
}

static void nbl_fd_del_flow_all(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_flow_direct_entry *entry = NULL, *entry_safe = NULL;
	int i = 0, j;

	for_each_set_bit(i, NBL_RES_MGT_TO_OWNED_PF_BITMAP(res_mgt),
			 NBL_RES_MGT_TO_PF_NUM(res_mgt)) {
		for (j = 0; j < NBL_CHAN_FDIR_RULE_MAX; j++)
			list_for_each_entry_safe(entry, entry_safe, &fd_mgt->info[i].list[j], node)
				nbl_fd_del_flow(res_mgt, &fd_mgt->info[i], entry);
	}
}

static int nbl_rdma_setup_tcam_cfg(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->set_rdma_tcam_cfg_default(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					   NBL_RDMA_PROFILE_RX, NBL_RDMA_RX_TCAM_ID);
	return 0;
}

static int nbl_fd_setup_tcam_cfg(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	switch (fd_mgt->mode) {
	case NBL_FD_MODE_DEFAULT:
		phy_ops->set_fd_tcam_cfg_default(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
		break;
	case NBL_FD_MODE_FULL:
		phy_ops->set_fd_tcam_cfg_full(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
		break;
	case NBL_FD_MODE_LITE:
		phy_ops->set_fd_tcam_cfg_lite(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
		break;
	default:
		return -EINVAL;
	}

	if (fd_mgt->udf_cnt)
		phy_ops->set_fd_udf(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				    (u8)fd_mgt->udf_layer,
				    (u8)fd_mgt->udf_offset);
	else
		phy_ops->clear_fd_udf(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));

	return 0;
}

static int nbl_fd_config_default_key_action_leonis(u16 type, u16 length, u8 *val, void *data)
{
	struct nbl_fd_tcam_default_entry *tcam_entry = (struct nbl_fd_tcam_default_entry *)data;
	union nbl_fd_tcam_default_data_u *tcam_data = &tcam_entry->data;
	union nbl_fd_tcam_default_data_u *tcam_mask = &tcam_entry->mask;
	struct nbl_flow_direct_entry *entry = tcam_entry->entry;
	union nbl_action_data action = {{0}};
	u8 reverse_mac[ETH_ALEN];
	u64 temp, mask;
	u32 offset, udf_data, udf_mask;

	switch (type) {
	case NBL_CHAN_FDIR_KEY_SRC_MAC:
		nbl_convert_mac(val, reverse_mac);
		ether_addr_copy((u8 *)&temp, reverse_mac);
		tcam_data->info.src_mac = temp;
		nbl_convert_mac(val + ETH_ALEN, reverse_mac);
		ether_addr_copy((u8 *)&temp, reverse_mac);
		tcam_mask->info.src_mac = temp;
		break;
	case NBL_CHAN_FDIR_KEY_DST_MAC:
		nbl_convert_mac(val, reverse_mac);
		ether_addr_copy((u8 *)&temp, reverse_mac);
		tcam_data->info.dst_mac = temp;
		nbl_convert_mac(val + ETH_ALEN, reverse_mac);
		ether_addr_copy((u8 *)&temp, reverse_mac);
		tcam_mask->info.dst_mac = temp;
		break;
	case NBL_CHAN_FDIR_KEY_PROTO:
		tcam_data->info.ethertype = be16_to_cpu(*(u16 *)val);
		tcam_mask->info.ethertype = be16_to_cpu(*(u16 *)(val + 2));
		break;
	case NBL_CHAN_FDIR_KEY_SVLAN:
		tcam_data->info.svlan = be16_to_cpu(*(u16 *)val);
		tcam_mask->info.svlan = be16_to_cpu(*(u16 *)(val + 2));
		break;
	case NBL_CHAN_FDIR_KEY_SRC_IPv4:
		tcam_data->info.sip_l = be32_to_cpu(*(u32 *)val);
		tcam_mask->info.sip_l = be32_to_cpu(*(u32 *)(val + 4));
		break;
	case NBL_CHAN_FDIR_KEY_DST_IPv4:
		tcam_data->info.dip_l = be32_to_cpu(*(u32 *)val);
		tcam_mask->info.dip_l = be32_to_cpu(*(u32 *)(val + 4));
		break;
	case NBL_CHAN_FDIR_KEY_L4PROTO:
		tcam_data->info.l4_proto = *val;
		tcam_mask->info.l4_proto = *(val + 1);
		break;
	case NBL_CHAN_FDIR_KEY_SRC_IPv6:
		tcam_data->info.sip_l = be64_to_cpu(*((u64 *)val + 1));
		tcam_mask->info.sip_l = be64_to_cpu(*((u64 *)val + 3));
		tcam_data->info.sip_h = be64_to_cpu(*(u64 *)val);
		tcam_mask->info.sip_h = be64_to_cpu(*(u64 *)val + 2);
		break;
	case NBL_CHAN_FDIR_KEY_DST_IPv6:
		tcam_data->info.dip_l = be64_to_cpu(*((u64 *)val + 1));
		tcam_mask->info.dip_l = be64_to_cpu(*((u64 *)val + 3));
		tcam_data->info.dip_h = be64_to_cpu(*(u64 *)val);
		tcam_mask->info.dip_h = be64_to_cpu(*(u64 *)val + 2);
		break;
	case NBL_CHAN_FDIR_KEY_SPORT:
		/* hw generate key is little endian */
		tcam_data->info.l4_sport = be16_to_cpu(*(u16 *)val);
		tcam_mask->info.l4_sport = be16_to_cpu(*(u16 *)(val + 2));
		break;
	case NBL_CHAN_FDIR_KEY_DPORT:
		tcam_data->info.l4_dport = be16_to_cpu(*(u16 *)val);
		tcam_mask->info.l4_dport = be16_to_cpu(*(u16 *)(val + 2));
		break;
	case NBL_CHAN_FDIR_KEY_UDF:
		temp = *(u64 *)val;
		mask = *(u64 *)(val + 8);
		offset = (temp & NBL_FD_UDF_FLEX_OFFS_M) >> NBL_FD_UDF_FLEX_OFFS_S;
		udf_data = temp & NBL_FD_UDF_FLEX_WORD_M;
		udf_mask = mask & NBL_FD_UDF_FLEX_WORD_M;

		/* data: high addr means payload first bytes. */
		if (offset % 4 == 1) {
			udf_data = (u8)udf_data << 24 | udf_data >> 8;
			udf_mask = (u8)udf_mask << 24 | udf_mask >> 8;

		} else if (offset % 4 == 3) {
			udf_data = udf_data >> 24 | udf_data << 8;
			udf_mask = udf_mask >> 24 | udf_mask << 8;
		}

		tcam_data->info.udf = udf_data;
		tcam_mask->info.udf = udf_mask;
		break;
	case NBL_CHAN_FDIR_ACTION_QUEUE:
		if (entry->param.global_queue_id != 0xFFFF) {
			action.dqueue.que_id = entry->param.global_queue_id;
			tcam_entry->action[0] = action.data + (NBL_ACT_SET_QUE_IDX << 16);
		} else {
			action.data = 0xFFF;
			tcam_entry->action[0] = action.data + (NBL_ACT_SET_DPORT << 16);
		}
		break;
	case NBL_CHAN_FDIR_ACTION_VSI:
		if (entry->param.dport != 0xFFFF) {
			action.dport.up.port_type = SET_DPORT_TYPE_VSI_HOST;
			action.dport.up.port_id = entry->param.dport;
			action.dport.up.upcall_flag = AUX_KEEP_FWD_TYPE;
			action.dport.up.next_stg_sel = NEXT_STG_SEL_EPRO;
		} else {
			action.data = 0xFFF;
		}
		tcam_entry->action[0] = action.data + (NBL_ACT_SET_DPORT << 16);

		break;
	default:
		break;
	}

	return 0;
}

int nbl_fd_config_key_leonis(struct nbl_resource_mgt *res_mgt,
			     struct nbl_flow_direct_entry *entry,
			     struct nbl_acl_tcam_param *data, struct nbl_acl_tcam_param *mask,
			     u32 *action, u16 vsi_id)
{
	struct nbl_fd_tcam_default_entry tcam_default_entry;

	memset(&tcam_default_entry, 0, sizeof(tcam_default_entry));
	tcam_default_entry.entry = entry;

	switch (entry->pid) {
	case NBL_FD_PROFILE_DEFAULT:
		nbl_flow_direct_parse_tlv_data(entry->param.tlv, entry->param.tlv_length,
					       nbl_fd_config_default_key_action_leonis,
					       &tcam_default_entry);

		tcam_default_entry.data.info.dport = (0x2 << 10) + vsi_id;
		tcam_default_entry.mask.info.dport = 0xFFFF;
		tcam_default_entry.data.info.pid = NBL_FD_PROFILE_DEFAULT;
		tcam_default_entry.mask.info.pid = 0xE;

		memcpy(&data->info.data, &tcam_default_entry.data, sizeof(tcam_default_entry.data));
		memcpy(&mask->info.data, &tcam_default_entry.mask, sizeof(tcam_default_entry.mask));
		data->len = sizeof(tcam_default_entry.data);
		mask->len = sizeof(tcam_default_entry.mask);
		memcpy(action, tcam_default_entry.action, sizeof(tcam_default_entry.action));

		break;
	case NBL_FD_PROFILE_IPV4:
	case NBL_FD_PROFILE_L2_IPV6:
	default:
		return -EINVAL;
	}

	return 0;
}

static int nbl_fd_alloc_action_slot_index(struct nbl_flow_direct_mgt *fd_mgt,
					  u16 *slot_index, u16 global_queue_id)
{
	int i = 0;

	for (i = 0; i < NBL_EXTRA_VSI_SLOT_NUM; i++) {
		if (global_queue_id == fd_mgt->extra_vsi_slot_info[i].global_queue_id)
			break;
	}
	if (i < NBL_EXTRA_VSI_SLOT_NUM) {
		*slot_index = i;
		fd_mgt->extra_vsi_slot_info[i].ref_cnt++;
		return 0;
	}
	for (i = 0; i < NBL_EXTRA_VSI_SLOT_NUM; i++) {
		if (fd_mgt->extra_vsi_slot_info[i].global_queue_id == 0xFFFF)
			break;
	}
	if (i < NBL_EXTRA_VSI_SLOT_NUM) {
		*slot_index = i;
		fd_mgt->extra_vsi_slot_info[i].ref_cnt = 1;
		fd_mgt->extra_vsi_slot_info[i].global_queue_id = global_queue_id;
		return 0;
	}

	return -ENOSPC;
}

static int nbl_fd_free_action_slot_index(struct nbl_flow_direct_mgt *fd_mgt, u16 slot_index)
{
	fd_mgt->extra_vsi_slot_info[slot_index].ref_cnt--;

	if (!(fd_mgt->extra_vsi_slot_info[slot_index].ref_cnt))
		fd_mgt->extra_vsi_slot_info[slot_index].global_queue_id = 0xFFFF;

	return 0;
}

static int nbl_fd_config_default_key_action_draco(u16 type, u16 length, u8 *val, void *data)
{
	struct nbl_fd_tcam_default_entry *tcam_entry = (struct nbl_fd_tcam_default_entry *)data;
	union nbl_fd_tcam_default_data_u *tcam_data = &tcam_entry->data;
	union nbl_fd_tcam_default_data_u *tcam_mask = &tcam_entry->mask;
	struct nbl_flow_direct_entry *entry = tcam_entry->entry;
	union nbl_base_action_bits base_ab = {.data = 0};
	union nbl_base_action_datas base_ad = {.data = 0};
	struct nbl_resource_mgt *res_mgt = tcam_entry->res_mgt;
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	u8 reverse_mac[ETH_ALEN];
	u64 temp, mask;
	u32 offset, udf_data, udf_mask;
	u16 slot_index = 0;
	int ret = 0;

	switch (type) {
	case NBL_CHAN_FDIR_KEY_SRC_MAC:
		nbl_convert_mac(val, reverse_mac);
		ether_addr_copy((u8 *)&temp, reverse_mac);
		tcam_data->draco.src_mac = temp;
		nbl_convert_mac(val + ETH_ALEN, reverse_mac);
		ether_addr_copy((u8 *)&temp, reverse_mac);
		tcam_mask->draco.src_mac = temp;
		break;
	case NBL_CHAN_FDIR_KEY_DST_MAC:
		nbl_convert_mac(val, reverse_mac);
		ether_addr_copy((u8 *)&temp, reverse_mac);
		tcam_data->draco.dst_mac = temp;
		nbl_convert_mac(val + ETH_ALEN, reverse_mac);
		ether_addr_copy((u8 *)&temp, reverse_mac);
		tcam_mask->draco.dst_mac = temp;
		break;
	case NBL_CHAN_FDIR_KEY_PROTO:
		tcam_data->draco.ethertype = be16_to_cpu(*(u16 *)val);
		tcam_mask->draco.ethertype = be16_to_cpu(*(u16 *)(val + 2));
		break;
	case NBL_CHAN_FDIR_KEY_SVLAN:
		tcam_data->draco.svlan = be16_to_cpu(*(u16 *)val);
		tcam_mask->draco.svlan = be16_to_cpu(*(u16 *)(val + 2));
		break;
	case NBL_CHAN_FDIR_KEY_SRC_IPv4:
		tcam_data->draco.sip_l = be32_to_cpu(*(u32 *)val);
		tcam_mask->draco.sip_l = be32_to_cpu(*(u32 *)(val + 4));
		break;
	case NBL_CHAN_FDIR_KEY_DST_IPv4:
		tcam_data->draco.dip_l = be32_to_cpu(*(u32 *)val);
		tcam_mask->draco.dip_l = be32_to_cpu(*(u32 *)(val + 4));
		break;
	case NBL_CHAN_FDIR_KEY_L4PROTO:
		tcam_data->draco.l4_proto = *val;
		tcam_mask->draco.l4_proto = *(val + 1);
		break;
	case NBL_CHAN_FDIR_KEY_SRC_IPv6:
		tcam_data->draco.sip_l = be64_to_cpu(*((u64 *)val + 1));
		tcam_mask->draco.sip_l = be64_to_cpu(*((u64 *)val + 3));
		tcam_data->draco.sip_h = be64_to_cpu(*(u64 *)val);
		tcam_mask->draco.sip_h = be64_to_cpu(*(u64 *)val + 2);
		break;
	case NBL_CHAN_FDIR_KEY_DST_IPv6:
		tcam_data->draco.dip_l = be64_to_cpu(*((u64 *)val + 1));
		tcam_mask->draco.dip_l = be64_to_cpu(*((u64 *)val + 3));
		tcam_data->draco.dip_h = be64_to_cpu(*(u64 *)val);
		tcam_mask->draco.dip_h = be64_to_cpu(*(u64 *)val + 2);
		break;
	case NBL_CHAN_FDIR_KEY_SPORT:
		/* hw generate key is little endian */
		tcam_data->draco.l4_sport = be16_to_cpu(*(u16 *)val);
		tcam_mask->draco.l4_sport = be16_to_cpu(*(u16 *)(val + 2));
		break;
	case NBL_CHAN_FDIR_KEY_DPORT:
		tcam_data->draco.l4_dport = be16_to_cpu(*(u16 *)val);
		tcam_mask->draco.l4_dport = be16_to_cpu(*(u16 *)(val + 2));
		break;
	case NBL_CHAN_FDIR_KEY_UDF:
		temp = *(u64 *)val;
		mask = *(u64 *)(val + 8);
		offset = (temp & NBL_FD_UDF_FLEX_OFFS_M) >> NBL_FD_UDF_FLEX_OFFS_S;
		udf_data = temp & NBL_FD_UDF_FLEX_WORD_M;
		udf_mask = mask & NBL_FD_UDF_FLEX_WORD_M;
		tcam_data->draco.udf = udf_data;
		tcam_mask->draco.udf = udf_mask;
		break;
	case NBL_CHAN_FDIR_ACTION_QUEUE:
		if (entry->param.global_queue_id != 0xFFFF) {
			ret = nbl_fd_alloc_action_slot_index(fd_mgt, &slot_index,
							     entry->param.global_queue_id);
			if (ret)
				return ret;
			ret = nbl_res_queue_set_epro_rss_ret(res_mgt,
							     slot_index,
							     entry->param.global_queue_id);
			if (ret) {
				nbl_fd_free_action_slot_index(fd_mgt, slot_index);
				return ret;
			}
			entry->slot_index = slot_index;
			entry->slot_index_valid = true;

			base_ab.baseab.SET_DEST = 1;
			base_ab.baseab.SET_UDF = 0;
			base_ab.baseab.VLAN_OP = 0;
			/* dport action */
			base_ad.dport.up.vsi_id = fd_mgt->extra_vsi_id;
			base_ad.dport.up.DQ_V = 1;
			base_ad.dport.up.dir = DPORT_DIR_RX;
			base_ad.dport.up.next_stg = NBL_NEXT_STAGE_EPRO;
			/* dqueue action */
			base_ad.dq.dq_info.loc_qid = slot_index;
			base_ad.dq.dq_info.mode = DQ_INFO_MODE_LOCAL_QUEUE_ID;
			/* [69,52] extend ab, [51:0] ad */
			base_ad.data = base_ad.data >> 12;
			memcpy(tcam_entry->action, &base_ad.data, sizeof(base_ad));
			tcam_entry->action[2] = (base_ab.data & 0xFC) >> 2;
			tcam_entry->action[1] = ((base_ab.data & 0x3) << 30) +
							(tcam_entry->action[1] & 0x3FFFFFFF);
		} else {
			base_ab.baseab.SET_DEST = 1;
			base_ab.baseab.SET_UDF = 0;
			base_ab.baseab.VLAN_OP = 0;
			/* drop action */
			base_ad.dport.drop.drop_code = 1;
			base_ad.dport.drop.other_type = DPORT_OTHER_TYPE_DROP;
			base_ad.dport.drop.dir = DPORT_DIR_OTHER;
			base_ad.dport.drop.next_stg = NBL_NEXT_STAGE_EPRO;
			/* [69,52] extend ab, [51:0] ad */
			base_ad.data = base_ad.data >> 12;
			memcpy(tcam_entry->action, &base_ad.data, sizeof(base_ad));
			tcam_entry->action[2] = (base_ab.data & 0xFC) >> 2;
			tcam_entry->action[1] = ((base_ab.data & 0x3) << 30) +
							(tcam_entry->action[1] & 0x3FFFFFFF);
		}
		break;
	case NBL_CHAN_FDIR_ACTION_VSI:
		if (entry->param.dport != 0xFFFF) {
			base_ab.baseab.SET_DEST = 1;
			base_ab.baseab.SET_UDF = 0;
			base_ab.baseab.VLAN_OP = 0;
			/* dport action */
			base_ad.dport.up.vsi_id = entry->param.dport;
			base_ad.dport.up.DQ_V = 0;
			base_ad.dport.up.dir = DPORT_DIR_RX;
			base_ad.dport.up.next_stg = NBL_NEXT_STAGE_EPRO;
			/* [69,52] extend ab, [51:0] ad */
			base_ad.data = base_ad.data >> 12;
			memcpy(tcam_entry->action, &base_ad.data, sizeof(base_ad));
			tcam_entry->action[2] = (base_ab.data & 0xFC) >> 2;
			tcam_entry->action[1] = ((base_ab.data & 0x3) << 30) +
							(tcam_entry->action[1] & 0x3FFFFFFF);
		} else {
			base_ab.baseab.SET_DEST = 1;
			base_ab.baseab.SET_UDF = 0;
			base_ab.baseab.VLAN_OP = 0;
			/* drop action */
			base_ad.dport.drop.drop_code = 1;
			base_ad.dport.drop.other_type = DPORT_OTHER_TYPE_DROP;
			base_ad.dport.drop.dir = DPORT_DIR_OTHER;
			base_ad.dport.drop.next_stg = NBL_NEXT_STAGE_EPRO;
			/* [69,52] extend ab, [51:0] ad */
			base_ad.data = base_ad.data >> 12;
			memcpy(tcam_entry->action, &base_ad.data, sizeof(base_ad));
			tcam_entry->action[2] = (base_ab.data & 0xFC) >> 2;
			tcam_entry->action[1] = ((base_ab.data & 0x3) << 30) +
							(tcam_entry->action[1] & 0x3FFFFFFF);
		}
		break;
	default:
		break;
	}

	return 0;
}

int nbl_fd_config_key_draco(struct nbl_resource_mgt *res_mgt,
			    struct nbl_flow_direct_entry *entry,
			    struct nbl_acl_tcam_param *data, struct nbl_acl_tcam_param *mask,
			    u32 *action, u16 vsi_id)
{
	struct nbl_fd_tcam_default_entry tcam_default_entry;
	union dport_action set_dport = {.data = 0};
	int ret = 0;

	memset(&tcam_default_entry, 0, sizeof(tcam_default_entry));
	tcam_default_entry.entry = entry;
	tcam_default_entry.res_mgt = res_mgt;

	switch (entry->pid) {
	case NBL_FD_PROFILE_DEFAULT:
		ret = nbl_flow_direct_parse_tlv_data(entry->param.tlv, entry->param.tlv_length,
						     nbl_fd_config_default_key_action_draco,
						     &tcam_default_entry);
		if (ret)
			return ret;

		set_dport.up.vsi_id = vsi_id;
		set_dport.up.DQ_V = 0;
		set_dport.up.dir = DPORT_DIR_RX;
		set_dport.up.next_stg = NBL_NEXT_STAGE_PP1;

		tcam_default_entry.data.draco.dport_ab = 0x8000;
		tcam_default_entry.mask.draco.dport_ab = 0xFFFF;
		tcam_default_entry.data.draco.dport_ad = set_dport.data;
		/* dport bit 13-15 is next stage */
		tcam_default_entry.mask.draco.dport_ad = 0x1FFF;
		tcam_default_entry.data.draco.pid = NBL_FD_PROFILE_DEFAULT;
		tcam_default_entry.mask.draco.pid = 0xE;

		memcpy(&data->info.data, &tcam_default_entry.data, sizeof(tcam_default_entry.data));
		memcpy(&mask->info.data, &tcam_default_entry.mask, sizeof(tcam_default_entry.mask));
		data->len = sizeof(tcam_default_entry.data);
		mask->len = sizeof(tcam_default_entry.mask);
		memcpy(action, tcam_default_entry.action, sizeof(tcam_default_entry.action));

		break;
	case NBL_FD_PROFILE_IPV4:
	case NBL_FD_PROFILE_L2_IPV6:
	default:
		return -EINVAL;
	}

	return 0;
}

static int nbl_fd_get_tcam_index(struct nbl_fd_tcam_index_info *info, u8 pid,
				 u16 *ram_index, u16 *depth_index, int mode)
{
	switch (pid) {
	case NBL_FD_PROFILE_DEFAULT:
		if (info->default_index[0].depth_index >=
				info->default_index[0].depth_index_max_spec)
			return -EINVAL;

		*ram_index = 0;
		*depth_index = info->default_index[0].start_depth_index +
					info->default_index[0].depth_index++;

		break;
	case NBL_FD_PROFILE_IPV4:
		if (mode != NBL_FD_MODE_LITE &&
		    (info->v4_cnt > 1 || info->v4[0].depth_index >= NBL_FD_TCAM_DEPTH))
			return -EINVAL;

		if (info->v4[info->v4_cnt].depth_index < NBL_FD_TCAM_DEPTH) {
			*ram_index = info->v4_cnt;
			*depth_index = info->v4[info->v4_cnt].depth_index++;
		} else {
			*ram_index = info->v4_cnt++;
			*depth_index = info->v4[info->v4_cnt].depth_index++;
		}

		break;
	case NBL_FD_PROFILE_L2_IPV6:
		if (mode == NBL_FD_MODE_LITE || info->v6[0].depth_index >= NBL_FD_TCAM_DEPTH)
			return -EINVAL;

		*ram_index = NBL_FD_IPV4_TCAM_WIDTH;
		*depth_index = info->v6[0].depth_index++;

		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static u16 nbl_fd_get_action_index(u16 ram_index)
{
	/* This is a bit tricky...
	 *
	 * For DEFAULT mode, ram_index is always 0, so we always use action_ram 0.
	 *
	 * For FULL mode, IPV4 rules always have ram_index 0, so they use action_ram 0, and
	 * IPV6 rules always have ram_index equals to NBL_FD_IPV4_TCAM_WIDTH, so they use
	 * action_ram 1.
	 *
	 * For LITE mode, every 512 IPV4 rules use one action_ram.
	 */
	return ram_index / NBL_FD_IPV4_TCAM_WIDTH;
}

static int nbl_fd_setup_tcam_for_list(struct nbl_resource_mgt *res_mgt,
				      struct nbl_fd_tcam_index_info *index_info,
				      struct list_head *head, u16 vsi_id)
{
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_acl_tcam_param data, mask;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	struct nbl_flow_direct_entry *entry = NULL;
	u16 ram_index = 0, depth_index = 0, action_index = 0;
	u32 action[3] = {0};
	int ret;

	memset(&data, 0, sizeof(data));
	memset(&mask, 0, sizeof(mask));
	list_for_each_entry(entry, head, node) {
		ret = nbl_fd_get_tcam_index(index_info, entry->pid, &ram_index,
					    &depth_index, fd_mgt->mode);
		if (ret)
			return ret;

		ret = NBL_OPS_CALL(product_ops->config_key,
				   (res_mgt, entry, &data, &mask, action, vsi_id));
		if (ret)
			return ret;

		action_index = nbl_fd_get_action_index(ram_index);

		entry->action_index = action_index;
		entry->depth_index = depth_index;
		ret = phy_ops->set_fd_action_ram(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						 action, action_index, depth_index);

		ret = phy_ops->set_fd_tcam_ram(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						&data, &mask, ram_index, depth_index);
		if (ret)
			return ret;
	}

	return 0;
}

static int nbl_fd_setup_tcam(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_fd_tcam_index_info index_info;
	u16 vsi_id = 0;
	int i = 0, j, ret = 0;

	memset(&index_info, 0, sizeof(index_info));
	index_info.default_index[0].start_depth_index = fd_mgt->start_depth_index;
	index_info.default_index[0].depth_index_max_spec = fd_mgt->max_spec;

	for (i = 0; i < NBL_EXTRA_VSI_SLOT_NUM; i++)
		(fd_mgt->extra_vsi_slot_info)[i].global_queue_id = 0xFFFF;

	for_each_set_bit(i, NBL_RES_MGT_TO_OWNED_PF_BITMAP(res_mgt),
			 NBL_RES_MGT_TO_PF_NUM(res_mgt)) {
		vsi_id = nbl_res_pfvfid_to_vsi_id(res_mgt, i, -1, NBL_VSI_DATA);
		for (j = 0; j < NBL_CHAN_FDIR_RULE_MAX; j++) {
			ret = nbl_fd_setup_tcam_for_list(res_mgt, &index_info,
							 &fd_mgt->info[i].list[j], vsi_id);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int nbl_fd_setup_flow(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int ret = 0;

	if (fd_mgt->state != NBL_FD_STATE_ON)
		return 0;

	phy_ops->clear_acl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
			   fd_mgt->start_depth_index, fd_mgt->start_depth_index + fd_mgt->max_spec);

	ret = nbl_fd_setup_tcam_cfg(res_mgt);
	if (ret)
		goto fail;

	ret = nbl_fd_setup_tcam(res_mgt);
	if (ret)
		goto fail;

	return 0;

fail:
	phy_ops->clear_acl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
			   fd_mgt->start_depth_index, fd_mgt->start_depth_index + fd_mgt->max_spec);
	return ret;
}

static void nbl_fd_remove_flow(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);

	phy_ops->clear_acl(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
			   fd_mgt->start_depth_index, fd_mgt->start_depth_index + fd_mgt->max_spec);
}

static void nbl_rdma_remove_flow(struct nbl_resource_mgt *res_mgt)
{
	enum nbl_fix_cap_type cap_type = NBL_UDF_EXTRACT_CAP;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u8 pf_id;
	u8 vsi_id;
	u16 func_id;

	if (!nbl_res_get_fix_capability(res_mgt, &cap_type))
		return;

	pf_id = NBL_COMMON_TO_MGT_PF(common);
	vsi_id = nbl_res_pfvfid_to_vsi_id(res_mgt, pf_id, -1, NBL_VSI_DATA);
	func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	if (test_bit(func_id, resource_info->rdma_info.func_cap))
		phy_ops->clear_acl_rdma(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), pf_id, pf_id + 1);
}

static int nbl_rdma_setup_flow(struct nbl_resource_mgt *res_mgt, u16 vsi_id)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_rdma_tcam_default_entry tcam_default_entry;
	struct nbl_acl_tcam_param data, mask;
	u8 pf_id = NBL_COMMON_TO_MGT_PF(common);
	union dport_action set_dport = {.data = 0};
	union nbl_base_action_bits base_ab = {.data = 0};
	union nbl_base_action_datas base_ad = {.data = 0};
	u32 action[3] = {0};
	int ret = 0;
	u16 action_ram_index = NBL_RDMA_RX_TCAM_ID;
	u16 depth_index = pf_id;
	u16 tcam_ram_index = NBL_RDMA_RX_TCAM_ID;

	memset(&data, 0, sizeof(data));
	memset(&mask, 0, sizeof(mask));
	memset(&tcam_default_entry, 0, sizeof(tcam_default_entry));
	set_dport.up.vsi_id = vsi_id;
	set_dport.up.DQ_V = 0;
	set_dport.up.dir = DPORT_DIR_RX;
	set_dport.up.next_stg = NBL_NEXT_STAGE_PP1;

	tcam_default_entry.data.info.dport_ab = 0x8000;
	tcam_default_entry.mask.info.dport_ab = 0xFFFF;
	tcam_default_entry.data.info.dport_ad = set_dport.data;
	/* dport bit 13-15 is next stage */
	tcam_default_entry.mask.info.dport_ad = 0x1FFF;
	tcam_default_entry.data.info.pid = NBL_RDMA_PROFILE_RX;
	tcam_default_entry.mask.info.pid = 0xF;

	base_ab.baseab.SET_DEST = 1;
	base_ab.baseab.SET_UDF = 0;
	base_ab.baseab.VLAN_OP = 0;
	/* dport action */
	base_ad.dport.up.vsi_id = RDMA_RX_VLAN_VSI_ID(vsi_id);
	base_ad.dport.up.DQ_V = 0;
	base_ad.dport.up.dir = DPORT_DIR_RX;
	base_ad.dport.up.next_stg = NBL_NEXT_STAGE_EPRO;
	/* [69,52] extend ab, [51:0] ad */
	base_ad.data = base_ad.data >> 12;
	memcpy(action, &base_ad.data, sizeof(base_ad));
	action[2] = (base_ab.data & 0xFC) >> 2;
	action[1] = ((base_ab.data & 0x3) << 30) + (action[1] & 0x3FFFFFFF);

	memcpy(&data.info.data, &tcam_default_entry.data, sizeof(tcam_default_entry.data));
	memcpy(&mask.info.data, &tcam_default_entry.mask, sizeof(tcam_default_entry.mask));
	mask.len = 5;
	data.len = 5;
	ret = phy_ops->set_fd_action_ram(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						 action, action_ram_index, depth_index);

	ret = phy_ops->set_rdma_tcam_ram(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						&data, &mask, tcam_ram_index, depth_index);
	return ret;
}

int nbl_fd_configure_tx_mirror_to_rdma(struct nbl_resource_mgt *res_mgt, u8 mt_id)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	union nbl_rdma_tcam_default_data_u tcam_data;
	union nbl_rdma_tcam_default_data_u tcam_mask;
	union nbl_base_action_bits base_ab = {.data = 0};
	union nbl_base_action_datas base_ad = {.data = 0};
	union sport_action sport_data = {.data = 0};
	struct nbl_acl_tcam_param data, mask;
	u32 action[3] = {0};
	u16 action_ram_index = NBL_RDMA_TX_TCAM_ID;
	u16 tcam_ram_index = NBL_RDMA_TX_TCAM_ID;
	u8 pf_id = NBL_COMMON_TO_MGT_PF(common);
	u8 eth_id = eth_info->eth_id[pf_id];
	u32 depth_index = NBL_RDMA_MIRROR_DEPTH_BASE + pf_id;
	int ret;

	/* Ensure RDMA RX TCAM base config (action/tct/kgen) is initialized */
	phy_ops->set_rdma_tcam_cfg_default(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					   NBL_RDMA_BOND_PROFILE_TX, NBL_RDMA_TX_TCAM_ID);

	memset(&tcam_data, 0, sizeof(tcam_data));
	memset(&tcam_mask, 0, sizeof(tcam_mask));
	memset(&data, 0, sizeof(data));
	memset(&mask, 0, sizeof(mask));

	sport_data.down.vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, pf_id, NBL_VSI_DATA);
	sport_data.down.cpu_fwd = SPORT_CPU_FWD_NO;
	sport_data.down.rdma = SPORT_RDMA_NO;
	sport_data.down.dir = SPORT_DIR_TX;
	sport_data.down.phy_flag = SPORT_PHY_FLAG_YES;

	tcam_data.sport.sport_ad = sport_data.data;
	tcam_mask.sport.sport_ad = 0x8FFF;
	tcam_data.sport.pid = NBL_RDMA_BOND_PROFILE_TX;
	tcam_mask.sport.pid = 0xF;

	base_ab.baseab.SET_DEST = 0;
	base_ab.baseab.SET_UDF = BASE_ACTION_SET_ACL_UDF_CAR_MIRR;
	base_ab.baseab.VLAN_OP = 0;
	base_ad.data |= (u64)(NBL_MIRROR_ID_ENABLE + mt_id) << 32;

	/* [69,52] extend ab, [51:0] ad */
	base_ad.data = base_ad.data >> 12;
	memcpy(action, &base_ad.data, sizeof(base_ad));
	action[2] = (base_ab.data & 0xFC) >> 2;
	action[1] = ((base_ab.data & 0x3) << 30) + (action[1] & 0x3FFFFFFF);

	memcpy(&data.info.data, &tcam_data, sizeof(tcam_data));
	memcpy(&mask.info.data, &tcam_mask, sizeof(tcam_mask));
	data.len = 5;
	mask.len = 5;

	ret = phy_ops->set_fd_action_ram(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				   action, action_ram_index, depth_index);

	ret = phy_ops->set_rdma_tcam_ram(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				   &data, &mask, tcam_ram_index, depth_index);

	nbl_info(common, NBL_DEBUG_FLOW, "tx mirror to rdma: eth_id=%u mt_id=%u depth=%u ret=%d\n",
		 eth_id, mt_id, depth_index, ret);

	return ret;
}

void nbl_fd_remove_tx_mirror_to_rdma(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u8 pf_id = NBL_COMMON_TO_MGT_PF(common);
	u16 vsi_id = nbl_res_pfvfid_to_vsi_id(res_mgt, pf_id, -1, NBL_VSI_DATA);
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	u16 depth_index = NBL_RDMA_MIRROR_DEPTH_BASE + pf_id;

	if (!test_bit(func_id, resource_info->rdma_info.func_cap))
		return;

	/* clear TCAM valid bit and action for tx mirror to rdma entry */
	phy_ops->clear_acl_rdma(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
				depth_index, depth_index + 1);

	nbl_info(common, NBL_DEBUG_FLOW, "tx mirror to rdma removed: pf_id=%d depth=%u\n",
		 pf_id, depth_index);
}

static int nbl_fd_handle_queue_update(u16 type, void *event_data, void *callback_data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)callback_data;
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	int ret = 0;

	dev_dbg(dev, "recv NBL_EVENT_ACL_STATE_UPDATE\n");
	ret = NBL_OPS_CALL(product_ops->handle_queue_update, (type, event_data, callback_data));
	return ret;
}

int nbl_fd_handle_queue_update_leonis(u16 type, void *event_data, void *callback_data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)callback_data;
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_event_queue_update_data *data =
		(struct nbl_event_queue_update_data *)event_data;
	struct nbl_flow_direct_entry *entry = NULL;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	union nbl_action_data action = {{0}};
	int pf_id, vf_id;
	u32 action_data = {0};
	u16 func_id = data->func_id;

	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pf_id, &vf_id);

	if (pf_id < 0 || pf_id >= NBL_MAX_PF)
		return 0;

	vf_id = vf_id + 1;
	list_for_each_entry(entry, &fd_mgt->info[pf_id].list[NBL_CHAN_FDIR_RULE_NORMAL], node) {
		if (entry->param.vf != vf_id)
			continue;

		if (entry->param.ring < data->ring_num) {
			entry->param.global_queue_id = data->map[entry->param.ring];
			action.dqueue.que_id = entry->param.global_queue_id;
			action_data = action.data + (NBL_ACT_SET_QUE_IDX << 16);
		} else {
			entry->param.global_queue_id = 0xFFFF;
			action.dport.up.port_type = SET_DPORT_TYPE_VSI_HOST;
			action.dport.up.port_id = 0x3FF;
			action.dport.up.upcall_flag = AUX_KEEP_FWD_TYPE;
			action.dport.up.next_stg_sel = NEXT_STG_SEL_EPRO;
			action_data = action.data + (NBL_ACT_SET_DPORT << 16);
		}

		phy_ops->set_fd_action_ram(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					   &action_data, entry->action_index, entry->depth_index);
	}

	return 0;
}

int nbl_fd_handle_queue_update_draco(u16 type, void *event_data, void *callback_data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)callback_data;
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_event_queue_update_data *data =
		(struct nbl_event_queue_update_data *)event_data;
	struct nbl_flow_direct_entry *entry = NULL;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	union nbl_base_action_bits base_ab = {.data = 0};
	union nbl_base_action_datas base_ad = {.data = 0};
	int pf_id, vf_id;
	u32 action_data[3] = {0};
	u16 func_id = data->func_id;
	u16 slot_index = 0;
	int ret = 0;

	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pf_id, &vf_id);

	if (pf_id < 0 || pf_id >= NBL_MAX_PF)
		return 0;

	vf_id = vf_id + 1;
	list_for_each_entry(entry, &fd_mgt->info[pf_id].list[NBL_CHAN_FDIR_RULE_NORMAL], node) {
		if (entry->param.vf != vf_id)
			continue;

		if (entry->param.ring < data->ring_num) {
			entry->param.global_queue_id = data->map[entry->param.ring];
			ret = nbl_fd_alloc_action_slot_index(fd_mgt, &slot_index,
							     entry->param.global_queue_id);
			if (ret)
				return ret;
			ret = nbl_res_queue_set_epro_rss_ret(res_mgt,
							     slot_index,
							     entry->param.global_queue_id);
			if (ret) {
				nbl_fd_free_action_slot_index(fd_mgt, slot_index);
				return ret;
			}
			entry->slot_index = slot_index;
			entry->slot_index_valid = true;

			base_ab.baseab.SET_DEST = 1;
			base_ab.baseab.SET_UDF = 0;
			base_ab.baseab.VLAN_OP = 0;
			/* dport action */
			base_ad.dport.up.vsi_id = fd_mgt->extra_vsi_id;
			base_ad.dport.up.DQ_V = 1;
			base_ad.dport.up.dir = DPORT_DIR_RX;
			base_ad.dport.up.next_stg = NBL_NEXT_STAGE_EPRO;
			/* dqueue action */
			base_ad.dq.dq_info.loc_qid = slot_index;
			base_ad.dq.dq_info.mode = DQ_INFO_MODE_LOCAL_QUEUE_ID;
			/* [69,52] extend ab, [51:0] ad */
			base_ad.data = base_ad.data >> 12;
			memcpy(action_data, &base_ad.data, sizeof(base_ad));
			action_data[2] = (base_ab.data & 0xFC) >> 2;
			action_data[1] = ((base_ab.data & 0x3) << 30) +
							(action_data[1] & 0x3FFFFFFF);
		} else {
			if (entry->slot_index_valid) {
				nbl_fd_free_action_slot_index(fd_mgt, entry->slot_index);
				entry->slot_index = 0;
				entry->slot_index_valid = false;
			}

			base_ab.baseab.SET_DEST = 1;
			base_ab.baseab.SET_UDF = 0;
			base_ab.baseab.VLAN_OP = 0;
			/* drop action */
			base_ad.dport.drop.drop_code = 2;
			base_ad.dport.drop.other_type = DPORT_OTHER_TYPE_DROP;
			base_ad.dport.drop.dir = DPORT_DIR_OTHER;
			base_ad.dport.drop.next_stg = NBL_NEXT_STAGE_EPRO;
			/* [69,52] extend ab, [51:0] ad */
			base_ad.data = base_ad.data >> 12;
			memcpy(action_data, &base_ad.data, sizeof(base_ad));
			action_data[2] = (base_ab.data & 0xFC) >> 2;
			action_data[1] = ((base_ab.data & 0x3) << 30) +
							(action_data[1] & 0x3FFFFFFF);
		}
		phy_ops->set_fd_action_ram(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					   action_data, entry->action_index, entry->depth_index);
	}

	return 0;
}

static int nbl_fd_handle_state_update(u16 type, void *event_data, void *callback_data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)callback_data;
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_event_acl_state_update_data *data =
		(struct nbl_event_acl_state_update_data *)event_data;

	if (fd_mgt->state == NBL_FD_STATE_OFF && !data->is_offload) {
		fd_mgt->state = NBL_FD_STATE_ON;
		nbl_fd_setup_flow(res_mgt);
	} else if (fd_mgt->state == NBL_FD_STATE_ON && data->is_offload) {
		nbl_fd_remove_flow(res_mgt);
		fd_mgt->state = NBL_FD_STATE_OFF;
	}

	return 0;
}

/* ---------  Res-layer ops Fucntions  --------- */

static int nbl_fd_get_fd_flow_cnt(void *priv, enum nbl_chan_fdir_rule_type rule_type, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	int pf_id = nbl_res_vsi_id_to_pf_id(res_mgt, vsi_id);

	if (pf_id < 0 || pf_id >= NBL_MAX_PF)
		return -EINVAL;

	if (rule_type >= NBL_CHAN_FDIR_RULE_MAX)
		return -EINVAL;

	return fd_mgt->info[pf_id].cnt[rule_type];
}

static int nbl_fd_get_fd_flow_all(void *priv, struct nbl_chan_param_get_fd_flow_all *param,
				  u32 *rule_locs)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_flow_direct_entry *entry = NULL;
	int pf_id = nbl_res_vsi_id_to_pf_id(res_mgt, param->vsi_id), index = 0;

	if (pf_id < 0 || pf_id >= NBL_MAX_PF)
		return -EINVAL;

	if (param->rule_type >= NBL_CHAN_FDIR_RULE_MAX)
		return -EINVAL;

	list_for_each_entry(entry, &fd_mgt->info[pf_id].list[param->rule_type], node) {
		if (index < param->start)
			continue;

		if (index >= param->start + param->num)
			break;

		rule_locs[index++] = entry->param.location;
	}

	return 0;
}

static int nbl_fd_get_fd_flow_max(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);

	return fd_mgt->max_spec;
}

static int nbl_fd_config_fd_flow_state(void *priv, enum nbl_chan_fdir_rule_type rule_type,
				       u16 vsi_id, u16 state)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_flow_direct_entry *entry = NULL, *entry_safe = NULL;
	int pf_id;

	pf_id = nbl_res_vsi_id_to_pf_id(res_mgt, vsi_id);
	if (pf_id < 0 || pf_id >= NBL_MAX_PF)
		return -EINVAL;

	if (rule_type >= NBL_CHAN_FDIR_RULE_MAX)
		return -EINVAL;

	if (state == NBL_FD_STATE_OFF || state == NBL_FD_STATE_FLUSH) {
		list_for_each_entry_safe(entry, entry_safe,
					 &fd_mgt->info[pf_id].list[rule_type], node)
			nbl_fd_del_flow(res_mgt, &fd_mgt->info[pf_id], entry);
		nbl_fd_setup_flow(res_mgt);
	}
	if (state != NBL_FD_STATE_FLUSH)
		fd_mgt->info[pf_id].state[rule_type] = state;

	return 0;
}

static int nbl_fd_get_fd_flow(void *priv, u16 vsi_id, u32 location,
			      enum nbl_chan_fdir_rule_type rule_type,
			      struct nbl_chan_param_fdir_replace *cmd)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_flow_direct_entry *entry = NULL;
	int pf_id = nbl_res_vsi_id_to_pf_id(res_mgt, vsi_id);

	if (location < 0 || location >= fd_mgt->max_spec || pf_id < 0 || pf_id >= NBL_MAX_PF)
		return -EINVAL;

	entry = nbl_fd_find_flow(&fd_mgt->info[pf_id], rule_type, location);
	if (!entry)
		return -ENOENT;

	memcpy(cmd, &entry->param, sizeof(*cmd) + entry->param.tlv_length);
	return 0;
}

static int nbl_fd_replace_fd_flow(void *priv, struct nbl_chan_param_fdir_replace *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_flow_direct_info *info = NULL;
	struct nbl_flow_direct_entry *entry = NULL;
	int pf_id = nbl_res_vsi_id_to_pf_id(res_mgt, param->vsi), ret = 0;

	if (pf_id < 0 || pf_id >= NBL_MAX_PF || param->location >= fd_mgt->max_spec)
		return -EINVAL;

	if (param->rule_type == NBL_CHAN_FDIR_RULE_NORMAL &&
	    fd_mgt->info[pf_id].state[param->rule_type] == NBL_FD_STATE_OFF)
		return -EINVAL;

	info = &fd_mgt->info[pf_id];
	entry = nbl_fd_find_flow(info, param->rule_type, param->location);
	ret = nbl_fd_validate_rule(res_mgt, param, entry);
	if (ret)
		return ret;

	if (entry)
		nbl_fd_del_flow(res_mgt, info, entry);

	entry = nbl_fd_add_flow(res_mgt, info, param);
	if (!entry)
		goto add_entry_fail;

	ret = nbl_fd_setup_flow(res_mgt);
	if (ret)
		goto setup_flow_fail;

	return 0;

setup_flow_fail:
	nbl_fd_find_and_del_flow(res_mgt, info, param->rule_type, param->location);
add_entry_fail:
	return ret;
}

static int nbl_fd_remove_fd_flow(void *priv, enum nbl_chan_fdir_rule_type rule_type,
				 u32 loc, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_flow_direct_info *info = NULL;
	int pf_id = nbl_res_vsi_id_to_pf_id(res_mgt, vsi_id);
	int ret;

	if (pf_id < 0 || pf_id >= NBL_MAX_PF || loc >= fd_mgt->max_spec)
		return -EINVAL;

	info = &fd_mgt->info[pf_id];
	ret = nbl_fd_find_and_del_flow(res_mgt, info, rule_type, loc);
	if (ret)
		return ret;

	return nbl_fd_setup_flow(res_mgt);
}

static void nbl_fd_cfg_update_event(void *priv, bool enable)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_event_callback event_callback = {0};

	event_callback.callback_data = res_mgt;

	if (enable) {
		event_callback.callback = nbl_fd_handle_state_update;
		nbl_event_register(NBL_EVENT_ACL_STATE_UPDATE, &event_callback,
				   NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
		event_callback.callback = nbl_fd_handle_queue_update;
		nbl_event_register(NBL_EVENT_QUEUE_ALLOC, &event_callback,
				   NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	} else {
		event_callback.callback = nbl_fd_handle_state_update;
		nbl_event_unregister(NBL_EVENT_ACL_STATE_UPDATE, &event_callback,
				     NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
		event_callback.callback = nbl_fd_handle_queue_update;
		nbl_event_unregister(NBL_EVENT_QUEUE_ALLOC, &event_callback,
				     NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	}
}

char flow_type_name[NBL_CHAN_FDIR_FLOW_MAX_TYPE][16] = {
	"Full/Isolate",
	"ETHER",
	"IPV4",
	"IPV6",
	"TCP_V4",
	"TCP_V6",
	"UDP_V4",
	"UDP_V6",
};

char mode_name[NBL_FD_MODE_MAX][16] = {
	"DEFAULT",
	"FULL",
	"LITE",
};

static int nbl_fd_dump_entry_tlv(u16 type, u16 length, u8 *val, void *data)
{
	struct seq_file *m = (struct seq_file *)(data);

	switch (type) {
	case NBL_CHAN_FDIR_KEY_SRC_MAC:
		seq_printf(m, "\tCompo [ SRC-MAC ]: data %02x-%02x-%02x-%02x-%02x-%02x, mask %02x-%02x-%02x-%02x-%02x-%02x\n",
			   val[0], val[1], val[2], val[3], val[4], val[5],
			   val[6], val[7], val[8], val[9], val[10], val[11]);
		break;
	case NBL_CHAN_FDIR_KEY_DST_MAC:
		seq_printf(m, "\tCompo [ DST-MAC ]: data %02x-%02x-%02x-%02x-%02x-%02x, mask %02x-%02x-%02x-%02x-%02x-%02x\n",
			   val[0], val[1], val[2], val[3], val[4], val[5],
			   val[6], val[7], val[8], val[9], val[10], val[11]);
		break;
	case NBL_CHAN_FDIR_KEY_PROTO:
		seq_printf(m, "\tCompo [ ETHERTYPE ]: data 0x%04x, mask 0x%04x\n",
			   *(u16 *)val, *(u16 *)(val + 2));
		break;
	case NBL_CHAN_FDIR_KEY_SVLAN:
		seq_printf(m, "\tCompo [ SVLAN ]: data 0x%04x, mask 0x%04x\n",
			   *(u16 *)val, *(u16 *)(val + 2));
		break;
	case NBL_CHAN_FDIR_KEY_SRC_IPv4:
		seq_printf(m, "\tCompo [ SRC-IPV4 ]: data %pI4, mask %pI4\n",
			   (u32 *)val, (u32 *)(val + 4));
		break;
	case NBL_CHAN_FDIR_KEY_DST_IPv4:
		seq_printf(m, "\tCompo [ DST-IPV4 ]: data %pI4, mask %pI4\n",
			   (u32 *)val, (u32 *)(val + 4));
		break;
	case NBL_CHAN_FDIR_KEY_L4PROTO:
		seq_printf(m, "\tCompo [ IPPROTO ]: data 0x%x, mask 0x%x\n",
			   *(u8 *)val, *(u8 *)(val + 1));
		break;
	case NBL_CHAN_FDIR_KEY_SRC_IPv6:
		seq_printf(m, "\tCompo [SRC-IPV6 ]: data %pI6, mask %pI6\n",
			   val, val + 12);
		break;
	case NBL_CHAN_FDIR_KEY_DST_IPv6:
		seq_printf(m, "\tCompo [DST-IPV6 ]: data %pI6, mask %pI6\n",
			   val, val + 12);
		break;
	case NBL_CHAN_FDIR_KEY_SPORT:
		seq_printf(m, "\tCompo [ L4-SPORT ]: data 0x%x, mask 0x%x\n",
			   *(u16 *)val, *(u16 *)(val + 2));
		break;
	case NBL_CHAN_FDIR_KEY_DPORT:
		seq_printf(m, "\tCompo [ L4-DPORT ]: data 0x%x, mask 0x%x\n",
			   *(u16 *)val, *(u16 *)(val + 2));
		break;
	case NBL_CHAN_FDIR_KEY_UDF:
		seq_printf(m, "\tCompo [ USER-DEF ]: data 0x%llx, mask 0x%llx\n",
			   *(u64 *)val, *(u64 *)(val + 8));
		break;
	case NBL_CHAN_FDIR_ACTION_QUEUE:
		seq_printf(m, "\tCompo [ GLOBAL-QUE ]: data 0x%llx\n", *(u64 *)val);
		break;
	case NBL_CHAN_FDIR_ACTION_VSI:
		seq_printf(m, "\tCompo [ VSI ]: vsi 0x%llx\n", *(u64 *)val);
		break;
	default:
		break;
	}

	return 0;
}

static void nbl_fd_dump_entry(struct seq_file *m, struct nbl_flow_direct_entry *entry)
{
	struct nbl_chan_param_fdir_replace *param = &entry->param;

	seq_printf(m, "\n[ %-10s]: pid %d, location %4d, global queue id %4u\n",
		   flow_type_name[param->flow_type], entry->pid,
		   param->location, param->global_queue_id);

	nbl_flow_direct_parse_tlv_data(entry->param.tlv, entry->param.tlv_length,
				       nbl_fd_dump_entry_tlv, m);
}

static void nbl_fd_dump_flow(void *priv, struct seq_file *m)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_flow_direct_entry *entry = NULL;
	int i, j;

	seq_puts(m, "\n/* -----------------------  Flow Direct  ----------------------- */\n\n");

	seq_printf(m, "[STATE\t\t %-4s\t]\n[MODE\t\t %-4s\t]\n[DEFAULT_CNT\t %-4d]\n[IPV4_CNT\t %-4d\t]\n[L2&IPV6_CNT\t %-4d\t]\n[UDF cnt/layer/offset:\t %-4d %-4d %-4d\t]\n",
		   fd_mgt->state == NBL_FD_STATE_OFF ? "OFF" : "ON", mode_name[fd_mgt->mode],
		   fd_mgt->cnt[NBL_FD_PROFILE_DEFAULT], fd_mgt->cnt[NBL_FD_PROFILE_IPV4],
		   fd_mgt->cnt[NBL_FD_PROFILE_L2_IPV6], fd_mgt->udf_cnt, fd_mgt->udf_layer,
		   fd_mgt->udf_offset);

	for (i = 0; i < eth_info->eth_num; i++)
		seq_printf(m, "[PF %d, UDF cnt/layer/offset:\t %-4d %-4d %-4d\t]\n",
			   i, fd_mgt->other_udf_cfg[i].udf_cnt,
			   fd_mgt->other_udf_cfg[i].udf_layer,
			   fd_mgt->other_udf_cfg[i].udf_offset);

	for_each_set_bit(i, NBL_RES_MGT_TO_OWNED_PF_BITMAP(res_mgt),
			 NBL_RES_MGT_TO_PF_NUM(res_mgt)) {
		for (j = 0; j < NBL_CHAN_FDIR_RULE_MAX; j++) {
			seq_printf(m, "\nPF %d/%d: %d flows state %-4s -------------------\n",
				   i, j, fd_mgt->info[i].cnt[j],
				   fd_mgt->info[i].state[j] == NBL_FD_STATE_OFF ? "OFF" : "ON");

			list_for_each_entry(entry, &fd_mgt->info[i].list[j], node)
				nbl_fd_dump_entry(m, entry);
		}
	}

	seq_puts(m, "\n");
}

static int nbl_set_rdma_rx_vsi_remap(void *priv, bool init)
{
	enum nbl_fix_cap_type cap_type = NBL_UDF_EXTRACT_CAP;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u8 pf_id;
	u8 vsi_id;
	u16 func_id;
	int ret = 0;

	if (!nbl_res_get_fix_capability(res_mgt, &cap_type))
		return 0;

	pf_id = NBL_COMMON_TO_MGT_PF(common);
	vsi_id = nbl_res_pfvfid_to_vsi_id(res_mgt, pf_id, -1, NBL_VSI_DATA);
	func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);
	if (test_bit(func_id, resource_info->rdma_info.func_cap)) {
		if (init) {
			nbl_rdma_setup_tcam_cfg(res_mgt);
			ret = nbl_rdma_setup_flow(res_mgt, vsi_id);
			if (ret)
				nbl_rdma_remove_flow(res_mgt);
		} else {
			nbl_rdma_remove_flow(res_mgt);
		}
	}
	return ret;
}

/* NBL_FD_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_FD_OPS_TBL									\
do {											\
	NBL_FD_SET_OPS(get_fd_flow, nbl_fd_get_fd_flow);				\
	NBL_FD_SET_OPS(get_fd_flow_cnt, nbl_fd_get_fd_flow_cnt);			\
	NBL_FD_SET_OPS(get_fd_flow_all, nbl_fd_get_fd_flow_all);			\
	NBL_FD_SET_OPS(get_fd_flow_max, nbl_fd_get_fd_flow_max);			\
	NBL_FD_SET_OPS(config_fd_flow_state, nbl_fd_config_fd_flow_state);		\
	NBL_FD_SET_OPS(replace_fd_flow, nbl_fd_replace_fd_flow);			\
	NBL_FD_SET_OPS(remove_fd_flow, nbl_fd_remove_fd_flow);				\
	NBL_FD_SET_OPS(cfg_fd_update_event, nbl_fd_cfg_update_event);			\
	NBL_FD_SET_OPS(dump_fd_flow, nbl_fd_dump_flow);					\
	NBL_FD_SET_OPS(set_rdma_rx_vsi_remap, nbl_set_rdma_rx_vsi_remap);			\
} while (0)

/* Structure starts here, adding an op should not modify anything below */
static int nbl_fd_setup_mgt(struct device *dev, struct nbl_flow_direct_mgt **fd_mgt)
{
	*fd_mgt = devm_kzalloc(dev, sizeof(struct nbl_flow_direct_mgt), GFP_KERNEL);
	if (!*fd_mgt)
		return -ENOMEM;

	return 0;
}

static void nbl_fd_remove_mgt(struct device *dev, struct nbl_flow_direct_mgt **fd_mgt)
{
	devm_kfree(dev, *fd_mgt);
	*fd_mgt = NULL;
}

static int nbl_fd_fdcfg_comp_event_cb(int event, void *priv_data, void *event_data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv_data;
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_udf_cfg *udf_cfg = (struct nbl_udf_cfg *)event_data;

	switch (event) {
	case NBL_DEVCOMM_FD_CFG_UPDATE_UDF_EVENT:
		fd_mgt->other_udf_cfg[udf_cfg->pf_id] = *udf_cfg;
		dev_dbg(dev, "recv comp update udf event, pf_id:%d, udf_cnt:%d, udf_offset:0x%x, udf_layer:%d\n",
			udf_cfg->pf_id,
			udf_cfg->udf_cnt, udf_cfg->udf_offset, udf_cfg->udf_layer);
		break;
	default:
		break;
	}

	return 0;
}

static int nbl_fd_mgt_register_fdcfg_comp(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_devcomm_match_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.key.val = pci_domain_nr(common->pdev->bus) << 16 | common->pdev->bus->number;
	fd_mgt->comp_dev = nbl_devcomm_register_component(NBL_DEVCOMM_FDCFG, &attr,
							  nbl_fd_fdcfg_comp_event_cb, res_mgt);
	if (!fd_mgt->comp_dev)
		return -ENOMEM;

	return 0;
}

static void nbl_fd_mgt_unregister_fdcfg_comp(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_flow_direct_mgt *fd_mgt = NBL_RES_MGT_TO_FD_MGT(res_mgt);

	nbl_devcomm_unregister_component(fd_mgt->comp_dev);
	fd_mgt->comp_dev = NULL;
}

int nbl_fd_mgt_start(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_flow_direct_mgt **fd_mgt = &NBL_RES_MGT_TO_FD_MGT(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u8 pf_id = NBL_COMMON_TO_MGT_PF(common);
	u16 data_vsi_id = nbl_res_pfvfid_to_vsi_id(res_mgt, pf_id, -1, NBL_VSI_DATA);
	u16 extra_vsi_id = RDMA_RX_VLAN_VSI_ID(data_vsi_id);
	int i, j;
	int ret = 0;

	ret = nbl_fd_setup_mgt(dev, fd_mgt);
	if (ret)
		return ret;

	for (i = 0; i < NBL_MAX_PF; i++) {
		for (j = 0; j < NBL_CHAN_FDIR_RULE_MAX; j++) {
			INIT_LIST_HEAD(&(*fd_mgt)->info[i].list[j]);
			(*fd_mgt)->info[i].state[j] = NBL_FD_STATE_OFF;
		}
	}

	(*fd_mgt)->udf_cnt = 0;
	(*fd_mgt)->udf_layer = 0;
	(*fd_mgt)->mode = NBL_FD_MODE_DEFAULT;
	(*fd_mgt)->state = NBL_FD_STATE_ON;
	if (bitmap_weight(NBL_RES_MGT_TO_OWNED_PF_BITMAP(res_mgt), NBL_MAX_PF) > 1) {
		(*fd_mgt)->max_spec = NBL_FD_RULE_MAX_DEFAULT;
		(*fd_mgt)->start_depth_index = 0;
	} else {
		(*fd_mgt)->max_spec = NBL_FD_RULE_MAX_DEFAULT / eth_info->eth_num;
		(*fd_mgt)->start_depth_index = (*fd_mgt)->max_spec * pf_id;
	}
	(*fd_mgt)->extra_vsi_id = extra_vsi_id;
	for (i = 0; i < NBL_EXTRA_VSI_SLOT_NUM; i++)
		(((*fd_mgt)->extra_vsi_slot_info)[i]).global_queue_id = 0xFFFF;

	ret = nbl_fd_mgt_register_fdcfg_comp(res_mgt);

	return ret;
}

void nbl_fd_mgt_stop(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_flow_direct_mgt **fd_mgt = &NBL_RES_MGT_TO_FD_MGT(res_mgt);

	if (!(*fd_mgt))
		return;

	nbl_fd_mgt_unregister_fdcfg_comp(res_mgt);
	nbl_fd_remove_flow(res_mgt);
	nbl_fd_del_flow_all(res_mgt);
	nbl_fd_remove_mgt(dev, fd_mgt);
}

int nbl_fd_setup_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_FD_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_FD_OPS_TBL;
#undef  NBL_FD_SET_OPS

	return 0;
}

void nbl_fd_remove_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_FD_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = NULL; ; } while (0)
	NBL_FD_OPS_TBL;
#undef  NBL_FD_SET_OPS
}
