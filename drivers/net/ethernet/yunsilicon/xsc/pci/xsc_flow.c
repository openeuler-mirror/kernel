// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "xsc_flow.h"
#include "xsc_flow_pool.h"
#include "common/fs_core.h"

static struct xsc_hw_tbl *xsc_flow_create_hw_tbl(struct xsc_core_device *dev,
						 struct xsc_hw_flow *hw_flow,
						 enum xsc_offload_tbl tbl_type,
						 const void *data,
						 u16 data_len,
						 u64 *new_tbl_bitmap)
{
	struct xsc_hw_tbl *hw_tbl = NULL;
	u32 idx;
	int ret;

	if (data && data_len != 0) {
		hw_tbl = xsc_hw_tbl_find(dev, tbl_type, data, data_len);
		if (hw_tbl) {
			xsc_core_info(dev,
				      "[hw_tbl] already exist, tbl_type:%d, idx:%d, refcnt:%d",
				      tbl_type, hw_tbl->idx, atomic_read(&hw_tbl->refcnt));
			XSC_HW_FLOW_ADD_TBL(hw_flow, tbl_type, hw_tbl);
			return hw_tbl;
		}
	}

	if (tbl_type == XSC_OFLD_PCT_TBL)
		ret = xsc_flow_grp_res_alloc_idx(dev, hw_flow->grp_id, &idx);
	else
		ret = xsc_hw_tbl_alloc_idx(dev, tbl_type, &idx);

	if (ret) {
		xsc_core_err(dev, "failed to alloc flow hw tbl idx, tbl_type:%d", tbl_type);
		return NULL;
	}

	hw_tbl = xsc_hw_tbl_create(dev, tbl_type, data, data_len, idx,
				   XSC_TBL_INDEX_LOCAL_MGR);
	if (!hw_tbl) {
		xsc_core_err(dev, "failed to add flow hw tbl idx, idx:%d, tbl_type:%d",
			     idx, tbl_type);
		return NULL;
	}

//	xsc_core_info(dev, "create flow hw tbl, idx:%d, tbl_type:%d", idx, tbl_type);

	XSC_HW_FLOW_ADD_TBL(hw_flow, tbl_type, hw_tbl);
	*new_tbl_bitmap |= TBL_BIT(tbl_type);

	return hw_tbl;
}

static struct xsc_hw_tbl *xsc_flow_create_hw_tbl_with_idx(struct xsc_core_device *dev,
							  struct xsc_hw_flow *hw_flow,
							  enum xsc_offload_tbl tbl_type,
							  enum xsc_tbl_index_mgr_type idx_mgr_type,
							  u32 idx,
							  u64 *new_tbl_bitmap)
{
	struct xsc_hw_tbl *hw_tbl = NULL;

	hw_tbl = xsc_hw_tbl_find_with_idx(dev, tbl_type, idx);
	if (hw_tbl) {
		XSC_HW_FLOW_ADD_TBL(hw_flow, tbl_type, hw_tbl);
		return hw_tbl;
	}

	hw_tbl = xsc_hw_tbl_create(dev, tbl_type, NULL, 0, idx, idx_mgr_type);
	XSC_HW_FLOW_ADD_TBL(hw_flow, tbl_type, hw_tbl);
	*new_tbl_bitmap |= TBL_BIT(tbl_type);

	return hw_tbl;
}

static struct xsc_hw_tbl *xsc_flow_create_hw_tbl_with_prio(struct xsc_core_device *dev,
							   struct xsc_hw_flow *hw_flow,
							   enum xsc_offload_tbl ofld_tbl_id,
							   u32 prio, u64 *new_tbl_bitmap)
{
	struct xsc_hw_tbl *hw_tbl = NULL;
	struct xsc_flow_tbl_mgr *tbl_mgr = dev->board_info->flow_tbl_mgr;
	struct xsc_flow_tbl_res *tbl_res;
	u32 tbl_idx;
	u8 res_tbl_id;
	unsigned long flags;

	if (!tbl_mgr) {
		xsc_core_err(dev, "flow table mgr is null");
		return ERR_PTR(-EINVAL);
	}

	if (ofld_tbl_id >= XSC_OFLD_MAX_TBL_NUM) {
		xsc_core_err(dev, "invalid hw tbl ofld table id %d", ofld_tbl_id);
		return ERR_PTR(-EINVAL);
	}

	res_tbl_id = tbl_mgr->ofld_tables[ofld_tbl_id].res_mgr_tbl;
	tbl_res = &tbl_mgr->res_tables[res_tbl_id];

	spin_lock_irqsave(&tbl_res->lock, flags);
	if (prio < tbl_res->max_entries) {
		set_bit(prio, tbl_res->bitmap);
		tbl_idx = tbl_res->base_idx + prio;
	} else {
		spin_unlock_irqrestore(&tbl_res->lock, flags);
		xsc_core_err(dev, "no resources available for flow res table id %d", res_tbl_id);
		return ERR_PTR(-ENOMEM);
	}
	spin_unlock_irqrestore(&tbl_res->lock, flags);

	hw_tbl = xsc_hw_tbl_create(dev, ofld_tbl_id, NULL, 0, tbl_idx, XSC_TBL_INDEX_LOCAL_MGR);
	XSC_HW_FLOW_ADD_TBL(hw_flow, ofld_tbl_id, hw_tbl);
	*new_tbl_bitmap |= TBL_BIT(ofld_tbl_id);

	return hw_tbl;
}

static int xsc_flow_create_encap_hw_tbl(struct xsc_core_device *dev,
					const struct xsc_ifc_l2_encap_info *encap_info,
					struct xsc_hw_flow *hw_flow,
					u64 *new_tbl_bitmap)
{
	struct xsc_hw_tbl *ecp_tnl_tbl = NULL;
	struct xsc_hw_tbl *ecp_hdr_tbl = NULL;
	struct xsc_hw_tbl *ecp_tnl_tp_tbl = NULL;
	struct xsc_hw_tbl *dmac_tbl = NULL;
	struct xsc_hw_tbl *smac_tbl = NULL;
	struct xsc_hw_tbl *dip_tbl = NULL;
	struct xsc_hw_tbl *sip_tbl = NULL;
	struct xsc_hw_tbl *dport_tbl = NULL;
	struct xsc_ecp_tnl_action_data *ecp_tnl_data;
	struct xsc_ecp_hdr_action_data *ecp_hdr_data;
	struct xsc_ecp_tnl_tp_action_data *ecp_tnl_tp_data;
	u32 dmac_idx, smac_idx, dip_idx, sip_idx, dport_idx;
	int ret = 0;

	ecp_tnl_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_TNL_ENCAP_TBL,
					     encap_info, sizeof(*encap_info),
					     new_tbl_bitmap);
	if (!ecp_tnl_tbl)
		return -EINVAL;

	if (!(*new_tbl_bitmap & TBL_BIT(XSC_OFLD_TNL_ENCAP_TBL))) {
		ecp_tnl_data = (struct xsc_ecp_tnl_action_data *)ecp_tnl_tbl->action_data;
		ecp_hdr_tbl = xsc_hw_tbl_find_with_idx(dev, XSC_OFLD_ECP_TNL_HDR_TBL,
						       ecp_tnl_tbl->idx);
		if (!ecp_hdr_tbl)
			return -EINVAL;

		ecp_hdr_data = (struct xsc_ecp_hdr_action_data *)ecp_hdr_tbl->action_data;
		ecp_tnl_tp_tbl = xsc_hw_tbl_find_with_idx(dev, XSC_OFLD_ECP_TNL_TP_TBL,
							  ecp_hdr_data->tp_tnl_idx);
		if (!ecp_tnl_tp_tbl)
			return -EINVAL;
		ecp_tnl_tp_data = (struct xsc_ecp_tnl_tp_action_data *)ecp_tnl_tp_tbl->action_data;

		dmac_idx = ecp_tnl_data->dmac_idx;
		smac_idx = ecp_hdr_data->smac_idx;
		dip_idx = ecp_hdr_data->dip_idx;
		sip_idx = ecp_hdr_data->sip_idx;
		dport_idx = ecp_tnl_tp_data->dport_idx;

		dmac_tbl = xsc_hw_tbl_find_with_idx(dev, XSC_OFLD_ECP_DMAC_TBL, dmac_idx);
		smac_tbl = xsc_hw_tbl_find_with_idx(dev, XSC_OFLD_ECP_SMAC_TBL, smac_idx);
		dip_tbl  = xsc_hw_tbl_find_with_idx(dev, XSC_OFLD_ECP_DIP_TBL, dip_idx);
		sip_tbl = xsc_hw_tbl_find_with_idx(dev, XSC_OFLD_ECP_SIP_TBL, sip_idx);
		dport_tbl = xsc_hw_tbl_find_with_idx(dev, XSC_OFLD_ECP_DPORT_TBL, dport_idx);

		if (!dmac_tbl || !smac_tbl || !dip_tbl || !sip_tbl || !dport_tbl)
			return -EINVAL;

		XSC_HW_FLOW_ADD_TBL(hw_flow, XSC_OFLD_TNL_ENCAP_TBL, ecp_tnl_tbl);
		XSC_HW_FLOW_ADD_TBL(hw_flow, XSC_OFLD_ECP_TNL_HDR_TBL, ecp_hdr_tbl);
		XSC_HW_FLOW_ADD_TBL(hw_flow, XSC_OFLD_ECP_TNL_TP_TBL, ecp_tnl_tp_tbl);
		XSC_HW_FLOW_ADD_TBL(hw_flow, XSC_OFLD_ECP_DMAC_TBL, dmac_tbl);
		XSC_HW_FLOW_ADD_TBL(hw_flow, XSC_OFLD_ECP_SMAC_TBL, smac_tbl);
		XSC_HW_FLOW_ADD_TBL(hw_flow, XSC_OFLD_ECP_DIP_TBL, dip_tbl);
		XSC_HW_FLOW_ADD_TBL(hw_flow, XSC_OFLD_ECP_SIP_TBL, sip_tbl);
		XSC_HW_FLOW_ADD_TBL(hw_flow, XSC_OFLD_ECP_DPORT_TBL, dport_tbl);
	} else {
		//New create
		ecp_tnl_data = kzalloc(sizeof(*ecp_tnl_data), GFP_KERNEL);
		ecp_hdr_data = kzalloc(sizeof(*ecp_hdr_data), GFP_KERNEL);
		ecp_tnl_tp_data = kzalloc(sizeof(*ecp_tnl_tp_data), GFP_KERNEL);

		ecp_tnl_tp_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_ECP_TNL_TP_TBL,
							NULL, 0, new_tbl_bitmap);

		ecp_hdr_tbl = xsc_flow_create_hw_tbl_with_idx(dev, hw_flow,
							      XSC_OFLD_ECP_TNL_HDR_TBL,
							      XSC_TBL_INDEX_LOCAL_MGR,
							      ecp_tnl_tbl->idx, new_tbl_bitmap);

		dmac_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_ECP_DMAC_TBL,
						  encap_info->ecp_dmac,
						  sizeof(encap_info->ecp_dmac),
						  new_tbl_bitmap);
		smac_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_ECP_SMAC_TBL,
						  encap_info->ecp_smac,
						  sizeof(encap_info->ecp_smac),
						  new_tbl_bitmap);

		if (encap_info->ip_type == XSC_IFC_MATCH_IP_TYPE_IPV4)
			dip_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_ECP_DIP_TBL,
							 &encap_info->ipv4.ecp_dip,
							 sizeof(encap_info->ipv4.ecp_dip),
							 new_tbl_bitmap);
		else
			dip_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_ECP_DIP_TBL,
							 encap_info->ipv6.ecp_dip,
							 sizeof(encap_info->ipv6.ecp_dip),
							 new_tbl_bitmap);

		if (encap_info->ip_type == XSC_IFC_MATCH_IP_TYPE_IPV4)
			sip_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_ECP_SIP_TBL,
							 &encap_info->ipv4.ecp_sip,
							 sizeof(encap_info->ipv4.ecp_sip),
							 new_tbl_bitmap);
		else
			sip_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_ECP_SIP_TBL,
							 encap_info->ipv6.ecp_sip,
							 sizeof(encap_info->ipv6.ecp_sip),
							 new_tbl_bitmap);

		dport_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_ECP_DPORT_TBL,
						   &encap_info->ecp_dport,
						   sizeof(encap_info->ecp_dport),
						   new_tbl_bitmap);

		if (!ecp_tnl_tp_tbl || !ecp_hdr_tbl || !dmac_tbl || !smac_tbl ||
		    !dip_tbl || !sip_tbl || !dport_tbl) {
			kfree(ecp_tnl_data);
			kfree(ecp_hdr_data);
			kfree(ecp_tnl_tp_data);
			return -EINVAL;
		}

		ecp_tnl_data->dmac_idx = dmac_tbl->idx;
		ecp_hdr_data->tp_tnl_idx = ecp_tnl_tp_tbl->idx;
		ecp_hdr_data->smac_idx = smac_tbl->idx;
		ecp_hdr_data->dip_idx = dip_tbl->idx;
		ecp_hdr_data->sip_idx = sip_tbl->idx;
		ecp_tnl_tp_data->dport_idx = dport_tbl->idx;

		ret = xsc_hw_tbl_fill_action_data(dev, ecp_tnl_tbl,
						  ecp_tnl_data, sizeof(*ecp_tnl_data));
		ret |= xsc_hw_tbl_fill_action_data(dev, ecp_hdr_tbl,
						   ecp_hdr_data, sizeof(*ecp_hdr_data));
		ret |= xsc_hw_tbl_fill_action_data(dev, ecp_tnl_tp_tbl,
						   ecp_tnl_tp_data, sizeof(*ecp_tnl_tp_data));

		if (ret)
			return ret;
	}

	return 0;
}

static int xsc_flow_create_action_hw_tbl(struct xsc_core_device *dev,
					 const struct xsc_ifc_action *actions,
					 const struct xsc_ifc_flow_group *grp,
					 struct xsc_hw_flow *hw_flow,
					 u64 *new_tbl_bitmap)
{
	const struct xsc_ifc_l2_encap_info *encap_info = &actions->l2_encap_info;
	const struct xsc_ifc_modify_hdr *modify_hdr = &actions->modify_hdr;
	const struct xsc_ifc_action_flag *type_flag = &actions->type_flag;
	struct xsc_hw_tbl *hw_tbl = NULL;
	u8 action_bit;
	int ret;

	if (!(*new_tbl_bitmap & TBL_BIT(XSC_OFLD_EM_TBL)) &&
	    (grp->pct_ad_type & PCT_AD_TYPE_TO_FT ||
	     grp->pct_ad_type & PCT_AD_TYPE_TO_CHAIN_FT ||
	     grp->wct_ad_type & WCT_AD_TYPE_TO_FT)) {
		xsc_core_info(dev, "[hw_tbl] em/fat tbl already exist");
		return 0;
	}

	for (action_bit = 0; action_bit < XSC_IFC_ACTION_MAX_NUM; action_bit++) {
		if (!XSC_IFC_ACTION_BIT_TEST(type_flag, action_bit))
			continue;

		switch (action_bit) {
		case XSC_ACTION_ENCAP_VXLAN:
		case XSC_ACTION_ENCAP_GENEVE:
			ret = xsc_flow_create_encap_hw_tbl(dev, encap_info, hw_flow,
							   new_tbl_bitmap);
			if (ret)
				return ret;
			break;
		case XSC_ACTION_COUNTER:
			hw_tbl = xsc_flow_create_hw_tbl_with_idx(dev, hw_flow,
								 XSC_OFLD_CT_TBL,
								 XSC_TBL_INDEX_NONE_LOCAL_MGR,
								 actions->counter,
								 new_tbl_bitmap);
			if (!hw_tbl)
				return -EINVAL;

			hw_flow->ft_counter = hw_tbl->idx;
			hw_flow->counter_type |= XSC_HW_FLOW_CT_TYPE_FT;
			break;
		case XSC_ACTION_SET_SRC_MAC:
			hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_MDF_SMAC_TBL,
							modify_hdr->src, 6, new_tbl_bitmap);
			if (!hw_tbl)
				return -EINVAL;
			break;
		case XSC_ACTION_SET_DST_MAC:
			hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_MDF_DMAC_TBL,
							modify_hdr->dst, 6, new_tbl_bitmap);
			if (!hw_tbl)
				return -EINVAL;
			break;
		case XSC_ACTION_SET_SRC_IPV4:
			hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_MDF_SIP_TBL,
							(const void *)&modify_hdr->src_addr,
							sizeof(modify_hdr->src_addr),
							new_tbl_bitmap);
			if (!hw_tbl)
				return -EINVAL;
			break;
		case XSC_ACTION_SET_DST_IPV4:
			hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_MDF_DIP_TBL,
							(const void *)&modify_hdr->dst_addr,
							sizeof(modify_hdr->dst_addr),
							new_tbl_bitmap);
			if (!hw_tbl)
				return -EINVAL;
			break;
		case XSC_ACTION_SET_SRC_IPV6:
			hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_MDF_SIP_TBL,
							(const void *)modify_hdr->ipv6_src,
							sizeof(modify_hdr->ipv6_src),
							new_tbl_bitmap);
			if (!hw_tbl)
				return -EINVAL;
			break;
		case XSC_ACTION_SET_DST_IPV6:
			hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_MDF_DIP_TBL,
							(const void *)modify_hdr->ipv6_dst,
							sizeof(modify_hdr->ipv6_dst),
							new_tbl_bitmap);
			if (!hw_tbl)
				return -EINVAL;
			break;

		case XSC_ACTION_PUSH_VLAN:
			//TODO: support more tunnel types
			if (XSC_IFC_ACTION_BIT_TEST(&type_flag, XSC_ACTION_ENCAP_VXLAN)) {
				hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_ECP_TPID_TBL,
								(const void *)&actions->vlan.tpid,
								sizeof(actions->vlan.tpid),
								new_tbl_bitmap);
			} else {
				hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_MDF_TPID_TBL,
								(const void *)&actions->vlan.tpid,
								sizeof(actions->vlan.tpid),
								new_tbl_bitmap);
			}
			if (!hw_tbl)
				return -EINVAL;
			break;

		default:
			break;
		}
	}

	if (grp->pct_ad_type & PCT_AD_TYPE_TO_FT ||
	    grp->pct_ad_type & PCT_AD_TYPE_TO_CHAIN_FT ||
	    grp->wct_ad_type & WCT_AD_TYPE_TO_FT) {
		hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_EM_FAT_TBL,
						NULL, 0, new_tbl_bitmap);
		if (!hw_tbl)
			return -EINVAL;
	}

	if (grp->wct_ad_type & WCT_AD_TYPE_TO_FAT) {
		hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_NONE_EM_FAT_TBL,
						NULL, 0, new_tbl_bitmap);
		if (!hw_tbl)
			return -EINVAL;
	}

	return 0;
}

static void xsc_flow_match_flag_hton(struct xsc_ifc_match_flag *dst,
				     const struct xsc_ifc_match_flag *src)
{
	u8 index;

	for (index = 0; index < XSC_IFC_MATCH_U64_NUM; index++)
		dst->bits[index] = cpu_to_be64(src->bits[index]);
}

static inline void xsc_flow_match_flag_ntoh(struct xsc_ifc_match_flag *dst,
					    const struct xsc_ifc_match_flag *src)
{
	u8 index;

	for (index = 0; index < XSC_IFC_MATCH_U64_NUM; index++)
		dst->bits[index] = be64_to_cpu(src->bits[index]);
}

struct xsc_ifc_match_flag match_fields;

static inline void xsc_flow_attr_hton(struct xsc_ifc_flow_attr *dst,
				      const struct xsc_ifc_flow_attr *src)
{
	dst->table_id		= cpu_to_be32(src->table_id);
	dst->group_id		= be32_to_cpu(src->group_id);
	dst->start_flow_index	= cpu_to_be32(src->start_flow_index);
	dst->end_flow_index	= cpu_to_be32(src->end_flow_index);
	dst->match_mask_enable	= src->match_mask_enable;
	dst->priority		= cpu_to_be16(src->priority);
	dst->chain_no		= src->chain_no;
	dst->dest_type		= src->dest_type;
	dst->vport		= cpu_to_be16(src->vport);
	dst->vhca_id		= cpu_to_be16(src->vhca_id);

	dst->tnl_valid = src->tnl_valid;
	dst->fdir      = src->fdir;
	dst->ingress   = src->ingress;
	dst->egress    = src->egress;
	dst->chain_no    = src->chain_no;
	dst->dest_type = src->dest_type;
	dst->tnl_valid = src->tnl_valid;
	dst->fdir      = src->fdir;
	dst->acl       = src->acl;
	xsc_flow_match_flag_hton(&dst->match_fields, &src->match_fields);
	xsc_flow_match_flag_hton(&dst->mask_fields, &src->mask_fields);
}

static inline void xsc_flow_group_hton(struct xsc_ifc_flow_group *dst,
				       const struct xsc_ifc_flow_group *src)
{
	dst->grp_id		= cpu_to_be32(src->grp_id);
	dst->priority		= cpu_to_be16(src->priority);
	dst->base_idx		= cpu_to_be32(src->base_idx);
	dst->max_entries	= cpu_to_be32(src->max_entries);
	dst->direction		= src->direction;
	dst->is_reserved	= src->is_reserved;
	dst->pct_ad_type	= src->pct_ad_type;
	dst->wct_ad_type	= src->wct_ad_type;
	dst->tbl_bitmap		= src->tbl_bitmap;
	dst->dst_port_flag	= src->dst_port_flag;
	dst->grp_dip_mask_len	= src->grp_dip_mask_len;
	xsc_flow_match_flag_hton(&dst->full_key, &src->full_key);
	xsc_flow_match_flag_hton(&dst->pct_template, &src->pct_template);
	xsc_flow_match_flag_hton(&dst->wct_template, &src->wct_template);
	xsc_flow_match_flag_hton(&dst->em_template, &src->em_template);
}

static inline void xsc_flow_group_ntoh(struct xsc_ifc_flow_group *dst,
				       const struct xsc_ifc_flow_group *src)
{
	dst->grp_id		= be32_to_cpu(src->grp_id);
	dst->priority		= be16_to_cpu(src->priority);
	dst->base_idx		= be32_to_cpu(src->base_idx);
	dst->max_entries	= be32_to_cpu(src->max_entries);
	dst->direction		= src->direction;
	dst->is_reserved	= src->is_reserved;
	dst->pct_ad_type	= src->pct_ad_type;
	dst->wct_ad_type	= src->wct_ad_type;
	dst->tbl_bitmap		= src->tbl_bitmap;
	dst->dst_port_flag	= src->dst_port_flag;
	dst->grp_dip_mask_len	= src->grp_dip_mask_len;
	xsc_flow_match_flag_ntoh(&dst->full_key, &src->full_key);
	xsc_flow_match_flag_ntoh(&dst->pct_template, &src->pct_template);
	xsc_flow_match_flag_ntoh(&dst->wct_template, &src->wct_template);
	xsc_flow_match_flag_ntoh(&dst->em_template, &src->em_template);
}

static inline void xsc_flow_match_headers_hton(struct xsc_ifc_fte_match_set_lyr_2_4 *dst,
					       const struct xsc_ifc_fte_match_set_lyr_2_4 *src,
					       bool ipv6)
{
	dst->ip_type  = src->ip_type;
	dst->ethertype  = cpu_to_be16(src->ethertype);
	dst->tp_type = src->tp_type;
	dst->dscp    = src->dscp;
	dst->ttl_hoplimit    = src->ttl_hoplimit;
	dst->dport   = cpu_to_be16(src->dport);
	dst->sport   = cpu_to_be16(src->sport);
	dst->icmp_code   = src->icmp_code;
	dst->icmp_type   = src->icmp_type;
	dst->vlan_tpid	= cpu_to_be16(src->vlan_tpid);
	dst->vlan_id     = cpu_to_be16(src->vlan_id);
	dst->vlan_pcp     = src->vlan_pcp;
	dst->cvlan_tpid	= cpu_to_be16(src->cvlan_tpid);
	dst->cvlan_id     = cpu_to_be16(src->cvlan_id);
	dst->cvlan_pcp     = src->cvlan_pcp;

	xsc_bytes_le2be(dst->src_mac, src->src_mac, 6);
	xsc_bytes_le2be(dst->dst_mac, src->dst_mac, 6);

	if (ipv6) {
		xsc_bytes_le2be(dst->ipv6.src_addr, src->ipv6.src_addr, 16);
		xsc_bytes_le2be(dst->ipv6.dst_addr, src->ipv6.dst_addr, 16);
	} else {
		dst->ipv4.sip = cpu_to_be32(src->ipv4.sip);
		dst->ipv4.dip = cpu_to_be32(src->ipv4.dip);
	}
}

static inline void xsc_flow_match_fields_hton(struct xsc_ifc_fte_match_param *dst,
					      const struct xsc_ifc_fte_match_param *src,
					      bool ipv6)
{
	dst->misc.vport			= cpu_to_be16(src->misc.vport);
	dst->misc.vhca_id		= cpu_to_be16(src->misc.vhca_id);
	dst->misc.logical_in_port	= cpu_to_be16(src->misc.logical_in_port);
	dst->misc.tag			= cpu_to_be16(src->misc.tag);
	dst->misc.pkt_type		= src->misc.pkt_type;
	dst->misc.member_bitmap		= src->misc.member_bitmap;
	dst->misc.tunnel_id		= cpu_to_be32(src->misc.tunnel_id);
	dst->misc.tunnel_type		= src->misc.tunnel_type;
	dst->misc.udf0			= cpu_to_be16(src->misc.udf0);
	dst->misc.udf1			= cpu_to_be16(src->misc.udf1);
	dst->misc.udf2			= cpu_to_be16(src->misc.udf2);

	xsc_flow_match_headers_hton(&dst->inner_headers, &src->inner_headers, ipv6);
	xsc_flow_match_headers_hton(&dst->outer_headers, &src->outer_headers, ipv6);
}

static inline void xsc_flow_match_hton(struct xsc_ifc_fte_match *dst,
				       const struct xsc_ifc_fte_match *src)
{
	bool ipv6 = false;

	if (XSC_TEST_FTE_MATCH_ATTR(&src->attr.match_fields, SRC_IPV6) ||
	    XSC_TEST_FTE_MATCH_ATTR(&src->attr.match_fields, DST_IPV6))
		ipv6 = true;

	xsc_flow_attr_hton(&dst->attr, &src->attr);
	xsc_flow_match_fields_hton(&dst->match_value, &src->match_value, ipv6);
	xsc_flow_match_fields_hton(&dst->match_mask, &src->match_mask, ipv6);
}

static inline void xsc_flow_group_match_hton(struct xsc_ifc_create_flow_group_in *dst,
					     const struct xsc_ifc_create_flow_group_in *src)
{
	bool ipv6 = false;

	if (XSC_TEST_FTE_MATCH_ATTR(&src->match_attr.match_fields, SRC_IPV6) ||
	    XSC_TEST_FTE_MATCH_ATTR(&src->match_attr.match_fields, DST_IPV6))
		ipv6 = true;

	xsc_flow_attr_hton(&dst->match_attr, &src->match_attr);
	xsc_flow_match_fields_hton(&dst->match_mask, &src->match_mask, ipv6);
}

static inline void xsc_flow_l2_encap_info_hton(struct xsc_ifc_l2_encap_info *dst,
					       const struct xsc_ifc_l2_encap_info *src)
{
	dst->ecp_pkt_type = src->ecp_pkt_type;
	dst->ecp_vlan_flag = src->ecp_vlan_flag;
	dst->ecp_ttl = src->ecp_ttl;
	dst->ip_type = src->ip_type;

	xsc_bytes_le2be(dst->ecp_dmac, src->ecp_dmac, 6);
	xsc_bytes_le2be(dst->ecp_smac, src->ecp_smac, 6);

	if (src->ip_type == 4) {
		dst->ipv4.ecp_sip = cpu_to_be32(src->ipv4.ecp_sip);
		dst->ipv4.ecp_dip = cpu_to_be32(src->ipv4.ecp_dip);
	} else {
		xsc_bytes_le2be(dst->ipv6.ecp_sip, src->ipv6.ecp_sip, 16);
		xsc_bytes_le2be(dst->ipv6.ecp_dip, src->ipv6.ecp_dip, 16);
	}

	dst->tunnel_id = cpu_to_be32(src->tunnel_id);
	dst->ecp_sport = cpu_to_be16(src->ecp_sport);
	dst->ecp_dport = cpu_to_be16(src->ecp_dport);
	dst->flags = src->flags;
	dst->proto = cpu_to_be16(src->proto);
	dst->opt_len = src->opt_len;
	memcpy(dst->opt_data, src->opt_data, 8);
	memcpy(dst->vx_rsvd0, src->vx_rsvd0, 3);
	dst->vx_rsvd1 = src->vx_rsvd1;
}

static inline void xsc_flow_modify_hdr_hton(struct xsc_ifc_modify_hdr *dst,
					    const struct xsc_ifc_modify_hdr *src)
{
	//mac addr not convert in driver
	xsc_bytes_le2be(dst->src, src->src, 6);
	xsc_bytes_le2be(dst->dst, src->dst, 6);

	dst->src_addr = cpu_to_be32(src->src_addr);
	dst->dst_addr = cpu_to_be32(src->dst_addr);
	dst->tp_sport = cpu_to_be16(src->tp_sport);
	dst->tp_dport = cpu_to_be16(src->tp_dport);
	dst->time_to_live = src->time_to_live;
	dst->dscp = src->dscp;
	dst->ecn = src->ecn;
	xsc_bytes_le2be(dst->ipv6_src, src->ipv6_src, 16);
	xsc_bytes_le2be(dst->ipv6_dst, src->ipv6_dst, 16);
}

static inline void xsc_flow_mirror_info_hton(struct xsc_ifc_mirror_info *dst,
					     const struct xsc_ifc_mirror_info *src)
{
	u8 index;

	xsc_flow_l2_encap_info_hton(&dst->encap_info, &src->encap_info);
	for (index = 0; index < XSC_IFC_ACTION_U64_NUM; index++)
		dst->type_flag.bits[index] = cpu_to_be64(src->type_flag.bits[index]);
	dst->port_id = cpu_to_be16(src->port_id);
	dst->qpid = cpu_to_be16(src->qpid);
	dst->mtr_id0 = cpu_to_be16(src->mtr_id0);
	dst->pop_vlan = src->pop_vlan;
	dst->nxt_mirror_index = src->nxt_mirror_index;
	dst->ratio = src->ratio;
	dst->direction = src->direction;
}

static inline void xsc_flow_vlan_info_hton(struct xsc_ifc_vlan_info *dst,
					   const struct xsc_ifc_vlan_info *src)
{
	dst->tpid = cpu_to_be16(src->tpid);
	dst->vid  = cpu_to_be16(src->vid);
	dst->pcp  = src->pcp;
}

static inline void xsc_flow_action_hton(struct xsc_ifc_action *dst,
					const struct xsc_ifc_action *src)
{
	u8 index;

	for (index = 0; index < XSC_IFC_ACTION_U64_NUM; index++)
		dst->type_flag.bits[index] = cpu_to_be64(src->type_flag.bits[index]);
	dst->counter   = cpu_to_be32(src->counter);
	dst->vport   = cpu_to_be16(src->vport);
	dst->vhca_id   = cpu_to_be16(src->vhca_id);

	dst->port_id   = cpu_to_be16(src->port_id);
	dst->def_port  = cpu_to_be16(src->def_port);
	dst->queue_id  = src->queue_id;

	dst->recirc_flag = src->recirc_flag;
	dst->recirc_id   = cpu_to_be16(src->recirc_id);
	dst->recirc_data = cpu_to_be32(src->recirc_data);

	dst->tag  = cpu_to_be16(src->tag);
	dst->mirror_flag = src->mirror_flag;
	dst->chain_no = src->chain_no;

	xsc_flow_vlan_info_hton(&dst->vlan, &src->vlan);
	xsc_flow_vlan_info_hton(&dst->cvlan, &src->cvlan);
	xsc_flow_l2_encap_info_hton(&dst->l2_encap_info, &src->l2_encap_info);
	xsc_flow_modify_hdr_hton(&dst->modify_hdr, &src->modify_hdr);
	xsc_flow_mirror_info_hton(&dst->mirror_info, &src->mirror_info);
}

static inline void xsc_flow_em_key_ntoh(struct xsc_flow_em_key *dst,
					const struct xsc_flow_em_key *src)
{
	dst->prf_bitmap     = be32_to_cpu(src->prf_bitmap);
	dst->table_id       = src->table_id;
	dst->logic_in_port  = be16_to_cpu(src->logic_in_port);
	dst->tunnel_id      = be32_to_cpu(src->tunnel_id);
	xsc_bytes_le2be(dst->smac,    src->smac, sizeof(src->smac));
	xsc_bytes_le2be(dst->dmac,    src->dmac, sizeof(src->dmac));
	dst->vid            = be16_to_cpu(src->vid);
	dst->ip_tp_type     = src->ip_tp_type;
	xsc_bytes_le2be(dst->sip_v6h, src->sip_v6h, sizeof(src->sip_v6h));
	dst->sip_v4_v6l     = be32_to_cpu(src->sip_v4_v6l);
	xsc_bytes_le2be(dst->dip_v6h, src->dip_v6h, sizeof(src->dip_v6h));
	dst->dip_v4_v6l     = be32_to_cpu(src->dip_v4_v6l);
	dst->sport_type     = be16_to_cpu(src->sport_type);
	dst->dport_code     = be16_to_cpu(src->dport_code);
	dst->ttl            = src->ttl;
	dst->dscp           = src->dscp;
	dst->udf0           = be16_to_cpu(src->udf0);
	dst->udf1           = be16_to_cpu(src->udf1);
	dst->udf2           = be16_to_cpu(src->udf2);
}

static inline void xsc_flow_em_key_hton(struct xsc_flow_em_key *dst,
					const struct xsc_flow_em_key *src)
{
	dst->prf_bitmap     = cpu_to_be32(src->prf_bitmap);
	dst->table_id       = src->table_id;
	dst->logic_in_port  = cpu_to_be16(src->logic_in_port);
	dst->tunnel_id      = cpu_to_be32(src->tunnel_id);
	xsc_bytes_le2be(dst->smac,    src->smac, sizeof(src->smac));
	xsc_bytes_le2be(dst->dmac,    src->dmac, sizeof(src->dmac));
	dst->vid            = cpu_to_be16(src->vid);
	dst->ip_tp_type     = src->ip_tp_type;
	xsc_bytes_le2be(dst->sip_v6h, src->sip_v6h, sizeof(src->sip_v6h));
	dst->sip_v4_v6l     = cpu_to_be32(src->sip_v4_v6l);
	xsc_bytes_le2be(dst->dip_v6h, src->dip_v6h, sizeof(src->dip_v6h));
	dst->dip_v4_v6l     = cpu_to_be32(src->dip_v4_v6l);
	dst->sport_type     = cpu_to_be16(src->sport_type);
	dst->dport_code     = cpu_to_be16(src->dport_code);
	dst->ttl            = src->ttl;
	dst->dscp           = src->dscp;
	dst->udf0           = cpu_to_be16(src->udf0);
	dst->udf1           = cpu_to_be16(src->udf1);
	dst->udf2           = cpu_to_be16(src->udf2);
}

static struct xsc_hw_tbl *xsc_flow_find_hw_tbl_with_type(struct xsc_hw_flow *hw_flow,
							 enum xsc_offload_tbl tbl_type)
{
	struct xsc_flow_hw_tbl *flow_hw_tbl = NULL;
	u8 idx;

	for (idx = 0; idx < hw_flow->hw_tbl_num; idx++) {
		flow_hw_tbl = &hw_flow->hw_tbl_array[idx];
		if (flow_hw_tbl->ofld_tbl_type == tbl_type)
			return flow_hw_tbl->hw_tbl;
	}

	return NULL;
}

static int xsc_cmd_create_flow_group(struct xsc_core_device *dev,
				     struct xsc_ifc_create_flow_group_in *req,
				     struct xsc_ifc_flow_group *grp)
{
	struct xsc_create_flow_grp_mbox_in *in;
	struct xsc_create_flow_grp_mbox_out *out;
	struct xsc_ifc_create_flow_group_in *in_req = NULL;
	struct xsc_ifc_flow_group *rsp = NULL;
	u16 req_data_size;
	u16 rsp_data_size;
	int err;

	req_data_size = sizeof(struct xsc_ifc_create_flow_group_in);
	rsp_data_size = sizeof(struct xsc_ifc_flow_group);
	in = kzalloc(sizeof(*in) + req_data_size, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	out = kzalloc(sizeof(*out) + rsp_data_size, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_FLOW_GROUP_CREATE);
	in_req = (struct xsc_ifc_create_flow_group_in *)in->data;
	memcpy(in_req, req, sizeof(struct xsc_ifc_create_flow_group_in));
	xsc_flow_match_flag_hton(&in_req->match_attr.match_fields, &req->match_attr.match_fields);
	xsc_flow_match_flag_hton(&in_req->match_attr.mask_fields, &req->match_attr.mask_fields);

	xsc_core_info(dev, "[match_attr] match_flag:(0x%llx,0x%llx), mask_flag:(0x%llx,0x%llx)",
		      req->match_attr.match_fields.bits[0], req->match_attr.match_fields.bits[1],
		      req->match_attr.mask_fields.bits[0], req->match_attr.mask_fields.bits[1]);

	err = xsc_cmd_exec(dev, in, sizeof(*in) + req_data_size,
			   out, sizeof(*out) + rsp_data_size);
	if (err) {
		xsc_core_err(dev, "xsc_cmd_exec failed, err:%d", err);
		return err;
	}

	if (out->hdr.status) {
		xsc_core_err(dev, "xsc_cmd hdr status invalid, status:%d",
			     out->hdr.status);
		err = xsc_cmd_status_to_err(&out->hdr);
		return err;
	}

	rsp = (struct xsc_ifc_flow_group *)out->data;
	xsc_flow_group_ntoh(grp, rsp);

	return 0;
}

int xsc_hflow_create_group(struct xsc_core_device *dev, struct xsc_flow_table *ft,
			   u32 *in, struct xsc_flow_group *fg)
{
	struct xsc_ifc_flow_group *grp = NULL;
	struct xsc_flow_grp_pool *grp_pool = dev->board_info->flow_grp_pool;
	int ret;

	if (!grp_pool) {
		xsc_core_err(dev, "flow group pool is null");
		return -EINVAL;
	}

	grp = kzalloc(sizeof(*grp), GFP_KERNEL);
	ret = xsc_cmd_create_flow_group(dev, (struct xsc_ifc_create_flow_group_in *)in, grp);
	if (ret) {
		xsc_core_err(dev, "failed to create flow group");
		return ret;
	}

	ret = xsc_flow_grp_alloc_idx(dev, grp_pool, grp);
	if (ret) {
		xsc_core_err(dev, "failed to alloc group index");
		return ret;
	}

	xsc_core_info(dev, "[create_grp] id:%d, dir:%d, pri:%d, is_res:%d",
		      grp->grp_id, grp->direction, grp->priority, grp->is_reserved);

	ret = xsc_flow_grp_res_alloc(dev, grp->grp_id);
	if (ret) {
		xsc_core_err(dev, "failed to alloc group res, err=%d", ret);
		return ret;
	}

	fg->id = grp->grp_id;

	return 0;
}

int xsc_hflow_destroy_group(struct xsc_core_device *dev,
			    struct xsc_flow_table *ft,
			    struct xsc_flow_group *fg)
{
	struct xsc_flow_grp_pool *grp_pool = dev->board_info->flow_grp_pool;
	struct xsc_ifc_flow_group *grp = NULL;
	bool del_group_flag = false;

	if (!grp_pool) {
		xsc_core_err(dev, "flow group pool is null");
		return -EINVAL;
	}

	grp = xsc_flow_grp_find_with_idx(dev, grp_pool, fg->id);
	if (!grp) {
		xsc_core_err(dev, "failed to find group for grp id %d", fg->id);
		return -EINVAL;
	}

	del_group_flag = xsc_flow_grp_res_free(dev, grp->grp_id);

	if (del_group_flag) {
		xsc_core_info(dev, "[del_grp] group_id: %d", fg->id);
		xsc_flow_grp_free_idx(dev, grp_pool, fg->id);
	}

	return 0;
}

static int xsc_cmd_del_hw_flow(struct xsc_core_device *dev,
			       const struct xsc_hw_flow *hw_flow,
			       const u64 del_tbl_bitmap)
{
	struct xsc_del_hw_flow_mbox_in *in = NULL;
	struct xsc_del_hw_flow_mbox_out out;
	struct xsc_del_hw_flow_req *req = NULL;
	const struct xsc_flow_hw_tbl *flow_hw_tbl = NULL;
	const struct xsc_hw_tbl *hw_tbl = NULL;
	u16 req_data_size;
	u8 tbl_id;
	int err;

	req_data_size = sizeof(struct xsc_del_hw_flow_req);
	in = kzalloc(sizeof(*in) + req_data_size, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	memset(&out, 0, sizeof(out));

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_HW_FLOW_DELETE);
	req = (struct xsc_del_hw_flow_req *)in->data;
	req->hw_tbl_bitmap = cpu_to_be64(del_tbl_bitmap);
	for (tbl_id = 0; tbl_id < hw_flow->hw_tbl_num; tbl_id++) {
		flow_hw_tbl = &hw_flow->hw_tbl_array[tbl_id];
		hw_tbl = flow_hw_tbl->hw_tbl;
		req->hw_tbl[flow_hw_tbl->ofld_tbl_type].idx = cpu_to_be32(hw_tbl->idx);
		if (flow_hw_tbl->ofld_tbl_type == XSC_OFLD_EM_TBL)
			xsc_flow_em_key_hton(&req->em_key, (struct xsc_flow_em_key *)hw_tbl->key);
	}

	err = xsc_cmd_exec(dev, in, sizeof(*in) + req_data_size, &out, sizeof(out));
	if (err)
		goto error;

	if (out.hdr.status) {
		err = xsc_cmd_status_to_err(&out.hdr);
		goto error;
	}

	return 0;

error:
	kfree(in);
	return err;
}

static int xsc_ifc_del_hw_flow(struct xsc_core_device *dev,
			       struct xsc_hw_flow *hw_flow, bool hw_flow_flag)
{
	struct xsc_flow_hw_tbl *flow_hw_tbl = NULL;
	struct xsc_hw_tbl *hw_tbl = NULL;
	u64 del_tbl_bitmap = 0;
	u8 idx;
	int ret = 0;

	for (idx = 0; idx < hw_flow->hw_tbl_num; idx++) {
		flow_hw_tbl = &hw_flow->hw_tbl_array[idx];
		hw_tbl = flow_hw_tbl->hw_tbl;
		if (atomic_dec_and_test(&hw_tbl->refcnt))
			del_tbl_bitmap |= TBL_BIT(flow_hw_tbl->ofld_tbl_type);
	}

	xsc_core_info(dev, "[del_flow] hw_flow_flag:%d, del_tbl_bitmap:0x%llx",
		      hw_flow_flag, del_tbl_bitmap);
	if (!del_tbl_bitmap)
		return 0;

	if (hw_flow_flag)
		ret = xsc_cmd_del_hw_flow(dev, hw_flow, del_tbl_bitmap);

	for (idx = 0; idx < hw_flow->hw_tbl_num; idx++) {
		flow_hw_tbl = &hw_flow->hw_tbl_array[idx];
		hw_tbl = flow_hw_tbl->hw_tbl;
		if (del_tbl_bitmap & TBL_BIT(flow_hw_tbl->ofld_tbl_type)) {
			if (flow_hw_tbl->ofld_tbl_type == XSC_OFLD_PCT_TBL)
				xsc_flow_grp_res_free_idx(dev, hw_flow->grp_id, hw_tbl->idx);
			else
				xsc_hw_tbl_free_idx(dev, hw_tbl, flow_hw_tbl->ofld_tbl_type);

			xsc_hw_tbl_free(dev, hw_tbl);
		}
	}

	return ret;
}

static int xsc_cmd_create_hw_flow(struct xsc_core_device *dev,
				  const struct xsc_ifc_fte_match *matches,
				  const struct xsc_ifc_action *actions,
				  const struct xsc_ifc_flow_group *grp,
				  struct xsc_hw_flow *hw_flow,
				  const u64 new_tbl_bitmap)
{
	struct xsc_create_hw_flow_mbox_in *in = NULL;
	struct xsc_create_hw_flow_mbox_out *out = NULL;
	struct xsc_create_hw_flow_req *req = NULL;
	struct xsc_create_hw_flow_rsp *rsp = NULL;
	struct xsc_flow_hw_tbl *flow_hw_tbl = NULL;
	struct xsc_hw_tbl *hw_tbl = NULL;
	struct xsc_flow_em_key em_key;
	u16 req_data_size;
	u16 rsp_data_size;
	u8 index;
	int ret = -1;

	xsc_core_info(dev, "[hw_flow] new_grp_tbl_bitmap:0x%llx", new_tbl_bitmap);

	req_data_size = sizeof(struct xsc_create_hw_flow_req);
	rsp_data_size = sizeof(struct xsc_create_hw_flow_rsp);
	in = kzalloc(sizeof(*in) + req_data_size, GFP_KERNEL);
	out = kzalloc(sizeof(*out) + rsp_data_size, GFP_KERNEL);
	if (!in || !out)
		goto error_free_idx;

	xsc_core_info(dev,
		      "[match_attr] vport=0x%04x, vhca_id:0x%04x, chain:%d, prio:%d, dir:%d, dest_type:%d",
		      matches->attr.vport, matches->attr.vhca_id,
		      matches->attr.chain_no, matches->attr.priority,
		      matches->attr.ingress, matches->attr.dest_type);
	xsc_core_info(dev, "[match_value] misc: vport=0x%04x(0x%04x), vhca_id:0x%04x(0x%04x)",
		      matches->match_value.misc.vport, matches->match_mask.misc.vport,
		      matches->match_value.misc.vhca_id, matches->match_mask.misc.vhca_id);
	xsc_core_info(dev,
		      "[match_value] outer_header: ip=%d(0x%x), tcp:%d(0x%x), dport:0x%04x(0x%04x), sport:0x%04x(0x%04x)",
		      matches->match_value.outer_headers.ip_type,
		      matches->match_mask.outer_headers.ip_type,
		      matches->match_value.outer_headers.tp_type,
		      matches->match_mask.outer_headers.tp_type,
		      matches->match_value.outer_headers.dport,
		      matches->match_mask.outer_headers.dport,
		      matches->match_value.outer_headers.sport,
		      matches->match_mask.outer_headers.sport);
	xsc_core_info(dev, "[match_value] outer_header: dipv6=0x%llx %llx (0x%llx %llx)",
		      *(u64 *)&matches->match_value.outer_headers.ipv6.dst_addr[8],
		      *(u64 *)&matches->match_value.outer_headers.ipv6.dst_addr[0],
		      *(u64 *)&matches->match_mask.outer_headers.ipv6.dst_addr[8],
		      *(u64 *)&matches->match_mask.outer_headers.ipv6.dst_addr[0]);
	xsc_core_info(dev, "[match_value] outer_header: sipv6=0x%llx %llx (0x%llx %llx)",
		      *(u64 *)&matches->match_value.outer_headers.ipv6.src_addr[8],
		      *(u64 *)&matches->match_value.outer_headers.ipv6.src_addr[0],
		      *(u64 *)&matches->match_mask.outer_headers.ipv6.src_addr[8],
		      *(u64 *)&matches->match_mask.outer_headers.ipv6.src_addr[0]);
	xsc_core_info(dev, "[match_value] outer_header: dipv4=0x%08x(0x%08x), sipv4=0x%08x(0x%08x)",
		      matches->match_value.outer_headers.ipv4.dip,
		      matches->match_mask.outer_headers.ipv4.dip,
		      matches->match_value.outer_headers.ipv4.sip,
		      matches->match_mask.outer_headers.ipv4.sip);
	xsc_core_info(dev, "[match_value] outer_header: dmac=0x%08x(0x%08x), smac=0x%08x(0x%08x)",
		      *(u32 *)matches->match_value.outer_headers.dst_mac,
		      *(u32 *)matches->match_mask.outer_headers.dst_mac,
		      *(u32 *)matches->match_value.outer_headers.src_mac,
		      *(u32 *)matches->match_mask.outer_headers.src_mac);

	xsc_core_info(dev,
		      "[actions] flag=(0x%llx, 0x%llx), dst_vport:0x%04x, vhca_id:0x%04x, chain:%d, counter:%d",
		      actions->type_flag.bits[0], actions->type_flag.bits[1],
		      actions->vport, actions->vhca_id, actions->chain_no, actions->counter);
	xsc_core_info(dev,
		      "[actions] mac=(%pM, %pM), port=(%d, %d), ipv4=(%pI4, %pI4), ipv6=(%pI6, %pI6)",
		      actions->modify_hdr.dst, actions->modify_hdr.src,
		      actions->modify_hdr.tp_dport, actions->modify_hdr.tp_sport,
		      &actions->modify_hdr.dst_addr, &actions->modify_hdr.src_addr,
		      actions->modify_hdr.ipv6_dst, actions->modify_hdr.ipv6_src);

	req = (struct xsc_create_hw_flow_req *)in->data;
	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_HW_FLOW_CREATE);

	req->hw_tbl_bitmap = cpu_to_be64(new_tbl_bitmap);
	xsc_flow_group_hton(&req->group, grp);

	memcpy(&req->matches, matches, sizeof(struct xsc_ifc_fte_match));
	xsc_flow_match_flag_hton(&req->matches.attr.match_fields, &matches->attr.match_fields);
	xsc_flow_match_flag_hton(&req->matches.attr.mask_fields, &matches->attr.mask_fields);

	xsc_flow_action_hton(&req->actions, actions);

	for (index = 0; index < hw_flow->hw_tbl_num; index++) {
		flow_hw_tbl = &hw_flow->hw_tbl_array[index];
		hw_tbl = flow_hw_tbl->hw_tbl;
		req->hw_tbl[flow_hw_tbl->ofld_tbl_type].idx = cpu_to_be32(hw_tbl->idx);
		xsc_core_dbg(dev, "[hw_tbl] ofld_tbl:%d, idx:%d",
			     flow_hw_tbl->ofld_tbl_type, hw_tbl->idx);
	}

	ret = xsc_cmd_exec(dev, in, sizeof(*in) + req_data_size,
			   out, sizeof(*out) + rsp_data_size);
	if (ret || out->hdr.status) {
		xsc_core_err(dev, "failed to create hw flow, ret=%d, status=%d\n",
			     ret, out->hdr.status);
		ret = xsc_cmd_status_to_err(&out->hdr);
		goto error_free_idx;
	}

	rsp = (struct xsc_create_hw_flow_rsp *)out->data;

	if (new_tbl_bitmap & TBL_BIT(XSC_OFLD_EM_TBL)) {
		hw_tbl = xsc_flow_find_hw_tbl_with_type(hw_flow, XSC_OFLD_EM_TBL);
		if (!hw_tbl) {
			xsc_core_err(dev, "failed to find hw tbl, abnormal");
			ret = -EINVAL;
			goto error_del_hw;
		}
		xsc_flow_em_key_ntoh(&em_key, &rsp->em_key);
		ret = xsc_hw_tbl_fill_em_key(dev, hw_tbl, &em_key, sizeof(em_key));
		if (ret)
			goto error_del_hw;
	}

	//TODO, index get in fw for prg tbls
	if (new_tbl_bitmap & TBL_BIT(XSC_OFLD_EACL_TBL)) {
		hw_tbl = xsc_flow_find_hw_tbl_with_type(hw_flow, XSC_OFLD_EACL_TBL);
		if (!hw_tbl) {
			xsc_core_err(dev, "failed to find hw tbl, abnormal");
			ret = -EINVAL;
			goto error_del_hw;
		}
		hw_tbl->idx = be32_to_cpu(rsp->hw_tbl[XSC_OFLD_EACL_TBL].idx);
	}

	return 0;

error_free_idx:
	xsc_core_err(dev, "error free idx process");
	xsc_ifc_del_hw_flow(dev, hw_flow, false);
	kfree(in);
	kfree(out);

	return ret;

error_del_hw:
	xsc_core_err(dev, "error del hw tbl process");
	xsc_ifc_del_hw_flow(dev, hw_flow, true);
	kfree(in);
	kfree(out);

	return ret;
}

static u8 count_ones_u8(u8 val)
{
	u8 count = 0;

	while (val) {
		count += val & 1;
		val >>= 1;
	}

	return count;
}

static u8 xsc_ipv6_mask_len(const u8 *ipv6, u8 len)
{
	u8 sum = 0;
	int i;

	for (i = 0; i < len; i++)
		sum += count_ones_u8(ipv6[i]);

	return sum;
}

static void xsc_apply_ipv6_prefix_mask(u8 ipv6_mask[16], int prefix_len)
{
	int full_bytes = prefix_len / 8;
	int remaining_bits = prefix_len % 8;
	int i;

	memset(ipv6_mask, 0, 16);

	for (i = 0; i < full_bytes; i++)
		ipv6_mask[i] = 0xFF;

	if (remaining_bits && full_bytes < 16)
		ipv6_mask[full_bytes] = 0xFF << (8 - remaining_bits);
}

static void xsc_flow_pct_match_key_padding(struct xsc_core_device *dev,
					   struct xsc_flow_pct_match_key *pct_key,
					   const struct xsc_ifc_fte_match *matches,
					   const struct xsc_ifc_flow_group *grp)
{
	const struct xsc_ifc_fte_match_param *match = &matches->match_value;
	const struct xsc_ifc_fte_match_param *mask = &matches->match_mask;
	u8 ipv6_mask[16];
	u8 ipv6[16];
	u8 index;
	u8 match_bit;

	memset(pct_key, 0, sizeof(*pct_key));

	pct_key->grp_id = grp->grp_id;
	pct_key->direction = grp->direction;
	memcpy(ipv6, match->outer_headers.ipv6.dst_addr, 16);
	memcpy(ipv6_mask, mask->outer_headers.ipv6.dst_addr, 16);
	memcpy(&pct_key->pct_template, &grp->pct_template, sizeof(pct_key->pct_template));

	for (match_bit = 0; match_bit < XSC_IFC_MATCH_END; match_bit++) {
		if (!XSC_IFC_MATCH_BIT_TEST(&grp->pct_template, match_bit))
			continue;
		switch (match_bit) {
		case XSC_IFC_MATCH_IN_PORT:
			if (mask->misc.vport > 0 &&
			    mask->misc.vhca_id > 0) {
				pct_key->vport = be16_to_cpu(match->misc.vport);
				pct_key->vhca_id = be16_to_cpu(match->misc.vhca_id);
			} else {
				pct_key->vport = be16_to_cpu(matches->attr.vport);
				pct_key->vhca_id = be16_to_cpu(matches->attr.vhca_id);
			}
			break;
		case XSC_IFC_MATCH_IP_TYPE:
			pct_key->ip_type = match->outer_headers.ip_type;
			break;
		case XSC_IFC_MATCH_TP_TYPE:
			pct_key->tp_type = match->outer_headers.tp_type;
			break;
		case XSC_IFC_MATCH_SPORT:
			pct_key->sport = be16_to_cpu(match->outer_headers.sport);
			break;
		case XSC_IFC_MATCH_DST_IPV6:
			if (grp->grp_dip_mask_len > 0 && grp->grp_dip_mask_len < 128)
				xsc_apply_ipv6_prefix_mask(ipv6_mask, grp->grp_dip_mask_len);

			for (index = 0; index < 16; index++)
				pct_key->dip[index] = ipv6[index] & ipv6_mask[index];
		default:
			break;
		}
	}

	xsc_core_info(dev,
		      "[pct_key] dir:%d, vport:%d, vhca_id:%d, ip_type:%d, tp_type:%d, sport:%d",
		      pct_key->direction, pct_key->vport, pct_key->vhca_id,
		      pct_key->ip_type, pct_key->tp_type, pct_key->sport);
	xsc_core_info(dev, "[pct_key] dipv6=0x%llx %llx",
		      *(u64 *)&pct_key->dip[8], *(u64 *)&pct_key->dip[0]);
}

static void xsc_flow_em_pf_match_key_padding(struct xsc_core_device *dev,
					     struct xsc_flow_em_pf_match_key *em_pf_key,
					     const struct xsc_ifc_fte_match *matches,
					     const struct xsc_ifc_flow_group *grp)
{
	const struct xsc_ifc_fte_match_param *mask = &matches->match_mask;

	memset(em_pf_key, 0, sizeof(*em_pf_key));
	memcpy(&em_pf_key->em_template, &grp->em_template, sizeof(em_pf_key->em_template));
	if (XSC_IFC_MATCH_BIT_TEST(&grp->pct_template, XSC_IFC_MATCH_DST_IPV6))
		em_pf_key->dip_mask_len =
			xsc_ipv6_mask_len(mask->outer_headers.ipv6.dst_addr, 16);

	xsc_core_info(dev,
		      "[em_prf] em_template:(0x%llx,0x%llx), dip_mask_len=%d",
		      em_pf_key->em_template.bits[0], em_pf_key->em_template.bits[1],
		      em_pf_key->dip_mask_len);
}

static void xsc_flow_em_match_key_padding(struct xsc_core_device *dev,
					  struct xsc_flow_em_match_key *em_key,
					  const struct xsc_ifc_fte_match *matches,
					  const struct xsc_ifc_flow_group *group,
					  u8 table_id)
{
	const struct xsc_ifc_fte_match_param *match = &matches->match_value;
	const struct xsc_ifc_fte_match_param *mask = &matches->match_mask;
	const struct xsc_ifc_flow_attr *attr = &matches->attr;
	u8 match_bit;

	memset(em_key, 0, sizeof(*em_key));
	memcpy(&em_key->em_template, &group->em_template, sizeof(em_key->em_template));
	em_key->table_id = table_id;

	for (match_bit = 0; match_bit < XSC_IFC_MATCH_END; match_bit++) {
		if (!XSC_IFC_MATCH_BIT_TEST(&group->em_template, match_bit))
			continue;

		switch (match_bit) {
		case XSC_IFC_MATCH_IN_PORT:
			if (mask->misc.vport > 0 && mask->misc.vhca_id > 0) {
				em_key->vport = match->misc.vport;
				em_key->vhca_id = match->misc.vhca_id;
			} else {
				em_key->vport = attr->vport;
				em_key->vhca_id = attr->vhca_id;
			}
			break;
		case XSC_IFC_MATCH_TNL_ID:
			em_key->tunnel_id = match->misc.tunnel_id;
			break;
		case XSC_IFC_MATCH_VLAN_ID:
			em_key->vid = match->outer_headers.vlan_id;
			break;
		case XSC_IFC_MATCH_ETH_SRC:
			memcpy(em_key->smac, match->outer_headers.src_mac, 6);
			break;
		case XSC_IFC_MATCH_ETH_DST:
			memcpy(em_key->dmac, match->outer_headers.dst_mac, 6);
			break;
		case XSC_IFC_MATCH_SRC_IPV4:
			em_key->src_v4 = match->outer_headers.ipv4.sip;
			break;
		case XSC_IFC_MATCH_DST_IPV4:
			em_key->dst_v4 = match->outer_headers.ipv4.dip;
			break;
		case XSC_IFC_MATCH_SRC_IPV6:
			memcpy(em_key->src_v6, match->outer_headers.ipv6.src_addr, 16);
			break;
		case XSC_IFC_MATCH_DST_IPV6:
			memcpy(em_key->dst_v6, match->outer_headers.ipv6.dst_addr, 16);
			break;
		case XSC_IFC_MATCH_DSCP:
			em_key->dscp = match->outer_headers.dscp;
			break;
		case XSC_IFC_MATCH_TTL:
			break;
		case XSC_IFC_MATCH_SPORT:
			em_key->sport_type = match->outer_headers.sport;
			break;
		case XSC_IFC_MATCH_DPORT:
			em_key->dport_code = match->outer_headers.dport;
			break;
		case XSC_IFC_MATCH_IP_TYPE:
			em_key->ip_type = match->outer_headers.ip_type;
			break;
		case XSC_IFC_MATCH_TP_TYPE:
			em_key->tp_type = match->outer_headers.tp_type;
			break;
		case XSC_IFC_MATCH_UDF0:
			em_key->udf0 = match->misc.udf0;
			break;
		case XSC_IFC_MATCH_UDF1:
			em_key->udf1 = match->misc.udf1;
			break;
		case XSC_IFC_MATCH_UDF2:
			em_key->udf0 = match->misc.udf2;
			break;
		default:
			break;
		}
	}

	xsc_core_info(dev,
		      "[em_key] vport:%d, vhca_id:%d, ip_type:%d, tp_type:%d, sport:%d, dport=%d",
		      em_key->vport, em_key->vhca_id, em_key->ip_type,
		      em_key->tp_type, em_key->sport_type, em_key->dport_code);
	xsc_core_info(dev,
		      "[em_key] em_template:(0x%llx,0x%llx), sipv6=0x%llx %llx, dipv6=0x%llx %llx",
		      em_key->em_template.bits[0], em_key->em_template.bits[1],
		      *(u64 *)&em_key->src_v6[8], *(u64 *)&em_key->src_v6[0],
		      *(u64 *)&em_key->dst_v6[8], *(u64 *)&em_key->dst_v6[0]);
}

static struct xsc_hw_flow *xsc_ifc_create_hw_flow(struct xsc_core_device *dev,
						  const struct xsc_ifc_fte_match *matches,
						  const struct xsc_ifc_action *actions,
						  const struct xsc_ifc_flow_group *grp)
{
	struct xsc_hw_flow *hw_flow = NULL;
	struct xsc_hw_tbl *hw_tbl = NULL;
	struct xsc_flow_pct_match_key pct_key;
	struct xsc_flow_em_pf_match_key em_pf_key;
	struct xsc_flow_em_match_key em_key;
	u64 new_tbl_bitmap = 0;
	u8 grp_tbl_bitmap = grp->tbl_bitmap;
	int ret;

	hw_flow = kzalloc(sizeof(*hw_flow), GFP_KERNEL);
	if (!hw_flow)
		return NULL;

	hw_flow->grp_id = grp->grp_id;

	xsc_core_info(dev, "[hw_flow] grp_id:%d, tbl_bitmap:0x%x, pct_ad=0x%x\n",
		      hw_flow->grp_id, grp_tbl_bitmap, grp->pct_ad_type);

	if (grp_tbl_bitmap & GROUP_TBL_PCT) {
		xsc_flow_pct_match_key_padding(dev, &pct_key, matches, grp);
		hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_PCT_TBL,
						&pct_key, sizeof(pct_key),
						&new_tbl_bitmap);
		if (!hw_tbl)
			goto error;

		if (grp->pct_ad_type & PCT_AD_TYPE_TO_FDIR)
			goto cmd;
	}

	if (grp_tbl_bitmap & GROUP_TBL_WCT) {
		hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_WCT_PF_TBL,
						&grp->wct_template,
						sizeof(grp->wct_template),
						&new_tbl_bitmap);
		if (!hw_tbl)
			goto error;

		hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_WCT_TBL,
						NULL, 0, &new_tbl_bitmap);
		if (!hw_tbl)
			goto error;
	}

	if (grp_tbl_bitmap & GROUP_TBL_WCT_CHAIN) {
		u16 prio = be16_to_cpu(matches->attr.priority);

		hw_tbl = xsc_flow_create_hw_tbl_with_prio(dev, hw_flow, XSC_OFLD_WCT_CHAIN_TBL,
							  prio, &new_tbl_bitmap);
		if (!hw_tbl)
			goto error;
	}

	if (grp_tbl_bitmap & GROUP_TBL_EM) {
		xsc_flow_em_pf_match_key_padding(dev, &em_pf_key, matches, grp);
		hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_EM_PF_TBL,
						&em_pf_key,
						sizeof(em_pf_key),
						&new_tbl_bitmap);
		if (!hw_tbl)
			goto error;

		xsc_flow_em_match_key_padding(dev, &em_key, matches, grp, hw_tbl->idx);
		//FT idx is not used
		hw_tbl = xsc_flow_create_hw_tbl(dev, hw_flow, XSC_OFLD_EM_TBL,
						&em_key, sizeof(em_key), &new_tbl_bitmap);
		if (!hw_tbl)
			goto error;
	}

	if (XSC_IFC_ACTION_IS_SET(actions->type_flag)) {
		ret = xsc_flow_create_action_hw_tbl(dev, actions, grp,
						    hw_flow, &new_tbl_bitmap);
		if (ret)
			goto error;
	}

cmd:
	ret = xsc_cmd_create_hw_flow(dev, matches, actions,
				     grp, hw_flow, new_tbl_bitmap);
	if (ret) {
		kfree(hw_flow);
		return NULL;
	}

	return hw_flow;

error:
	xsc_core_err(dev, "error process");
	xsc_ifc_del_hw_flow(dev, hw_flow, false);
	kfree(hw_flow);

	return NULL;
}

int xsc_hflow_create_fte(struct xsc_core_device *dev,
			 struct xsc_ifc_fte_match *matches,
			 struct xsc_ifc_action *actions,
			 u32 grp_id, u32 *flow_id)
{
	struct xsc_hw_flow *hw_flow;
	struct xsc_ifc_flow_group *grp = NULL;
	struct xsc_flow_pool *flow_pool = dev->board_info->flow_pool;
	struct xsc_flow_grp_pool *grp_pool = dev->board_info->flow_grp_pool;
	int ret;

	xsc_core_info(dev, "[match_attr] group_id=%d, match_flag:(0x%llx,0x%llx), action_flag:(0x%llx,0x%llx)",
		      grp_id, matches->attr.match_fields.bits[0],
		      matches->attr.match_fields.bits[1],
		      actions->type_flag.bits[0], actions->type_flag.bits[1]);

	if (!flow_pool || !grp_pool) {
		xsc_core_err(dev, "flow pool is null");
		return -EINVAL;
	}

	grp = xsc_flow_grp_find_with_idx(dev, grp_pool, grp_id);
	if (!grp) {
		xsc_core_err(dev, "failed to find flow group for grp_id %d", grp_id);
		return -EINVAL;
	}

	hw_flow = xsc_ifc_create_hw_flow(dev, matches, actions, grp);
	if (!hw_flow) {
		xsc_core_err(dev, "failed to create hw flow");
		return -EINVAL;
	}

	ret = xsc_flow_alloc_idx(dev, flow_pool, hw_flow, flow_id);
	if (ret) {
		xsc_ifc_del_hw_flow(dev, hw_flow, true);
		return ret;
	}

	xsc_core_info(dev, "success to create flow fte, flow_id:%d", *flow_id);

	return 0;
}

int xsc_hflow_delete_fte(struct xsc_core_device *dev,
			 struct xsc_flow_table *ft,
			 struct fs_fte *fte)
{
	struct xsc_hw_flow *hw_flow;
	struct xsc_flow_pool *flow_pool = dev->board_info->flow_pool;
	int ret;

	if (!flow_pool) {
		xsc_core_err(dev, "flow pool is null");
		return -EINVAL;
	}

	xsc_core_info(dev, "[del_flow] flow_idx: %d", fte->hw_index);
	hw_flow = xsc_flow_free_idx(dev, flow_pool, fte->hw_index);
	if (!hw_flow) {
		xsc_core_err(dev, "no hw flow for flow id %d", fte->hw_index);
		return -EINVAL;
	}

	ret = xsc_ifc_del_hw_flow(dev, hw_flow, true);
	kfree(hw_flow);
	if (ret)
		return ret;

	return 0;
}

static int xsc_cmd_fc_bulk_query(struct xsc_core_device *dev,
				 void *query_out, u32 base_id, u32 num_counters)
{
	struct xsc_ifc_query_flow_counter_mbox_in in;
	struct xsc_ifc_query_flow_counter_mbox_out *out =
			(struct xsc_ifc_query_flow_counter_mbox_out *)query_out;
	int err, out_len;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_FLOW_COUNTER_BULK_QUERY);
	in.base_id = cpu_to_be32(base_id);
	in.num_counters = cpu_to_be32(num_counters);

	out_len = sizeof(*out) + num_counters * sizeof(struct xsc_ifc_traffic_counter);
	err = xsc_cmd_exec(dev, &in, sizeof(in), out, out_len);
	if (err) {
		xsc_core_err(dev, "xsc_cmd_exec failed, err:%d", err);
		return err;
	}

	if (out->hdr.status) {
		xsc_core_err(dev, "xsc_cmd hdr status invalid, status:%d",
			     out->hdr.status);
		err = xsc_cmd_status_to_err(&out->hdr);
		return err;
	}

	return 0;
}

int xsc_hflow_counter_bulk_query(struct xsc_core_device *dev,
				 void *out, u32 base_id, u32 num_counters)
{
	return xsc_cmd_fc_bulk_query(dev, out, base_id, num_counters);
}

int xsc_hflow_counter_bulk_alloc(struct xsc_core_device *dev,
				 u32 *base_id, u32 num_counters)
{
	return xsc_hw_tbl_bulk_alloc(dev, XSC_OFLD_CT_TBL, base_id, num_counters);
}

int xsc_hflow_counter_bulk_free(struct xsc_core_device *dev,
				u32 base_id, u32 num_counters)
{
	return xsc_hw_tbl_bulk_free(dev, XSC_OFLD_CT_TBL, base_id, num_counters);
}
