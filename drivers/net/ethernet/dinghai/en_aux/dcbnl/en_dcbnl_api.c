// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

//#include <linux/device.h>
#include "../../en_aux.h"
#include "en_dcbnl.h"
#include "en_dcbnl_api.h"
#include "en_np/qos/include/dpp_drv_qos.h"
#include "en_np/table/include/dpp_tbl_tm.h"
#include "en_np/fc/include/dpp_drv_fc.h"
#include "en_np/sdk/include/api/dpp_pbu_api.h"
#include "en_np/sdk/include/api/dpp_ppu_api.h"

u32 zxdh_dcbnl_get_se_flow_resources(struct zxdh_en_device *en_dev,
				     struct zxdh_dcbnl_ets_se_flow_resource *tree_resource)
{
	u64 gsch_id = 0;
	u32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	if (tree_resource->level == ZXDH_DCBNL_ETS_TREE_ROOT_LEVEL) {
		err = dpp_sch_base_node_get(&pf_info, en_dev->phy_port, &gsch_id);
	} else {
		err = dpp_cosq_gsch_id_add(&pf_info, en_dev->phy_port, tree_resource->numq,
					   tree_resource->level, tree_resource->flags, &gsch_id);
	}

	if (err) {
		LOG_ERR("get se/flow failed, level: %d, type: %d, err:%d\n",
			tree_resource->level, tree_resource->flags, err);
		return err;
	}
	tree_resource->gsch_id = gsch_id;
	tree_resource->resource_id = ZXDH_DCBNL_GET_GSCHID_MSG(gsch_id, ZXDH_DCBNL_GSCHID_ID_MASK,
							       ZXDH_DCBNL_GSCHID_ID_SHIFT);
	/* debug */
	LOG_INFO(" gsch_id:0x%llx,resource_id:0x%x level:%d, flags:%d\n", gsch_id,
		 tree_resource->resource_id, tree_resource->level, tree_resource->flags);

	return 0;
}

u32 zxdh_dcbnl_find_se_link_id(struct zxdh_en_priv *en_priv, u32 level, u32 link_level,
			       u32 link_idx, u32 link_sp, u32 *link_id)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_ets_se_node *se_link_node = NULL;
	struct zxdh_dcbnl_ets_node_list_head *ets_node_list_head =
		&en_dev->dcb_para.ets_node_list_head[link_level];

	*link_id = ZXDH_DCBNL_NULL_ID;

	if (level < ZXDH_DCBNL_ETS_TREE_ROOT_LEVEL) {
		if (!ets_node_list_head->se_next) {
			LOG_ERR("dcbnl: no nodes in the link_level: %d\n", link_level);
			return 1;
		}

		se_link_node = ets_node_list_head->se_next;

		while ((se_link_node) && (se_link_node->node_idx != link_idx))
			se_link_node = se_link_node->se_next;

		if (se_link_node) {
			*link_id = se_link_node->se_id + link_sp;
		} else {
			LOG_ERR("dcbnl: find se link_id failed, link_level: %d, link_idx: %d\n",
				link_level, link_idx);
			return 1;
		}
	}

	return 0;
}

u32 zxdh_dcbnl_save_se_resources(struct zxdh_en_priv *en_priv,
				 struct zxdh_dcbnl_se_tree_config *tree_node_cfg)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_ets_se_flow_resource tree_resource = { 0 };
	struct zxdh_dcbnl_ets_se_node *new_se_node = NULL;
	struct zxdh_dcbnl_ets_node_list_head *ets_node_list_head = NULL;
	u32 level = 0;
	u32 link_level = 0;
	u32 link_idx = 0;
	u32 link_id = 0;
	u32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	level = tree_node_cfg->level;
	link_level = tree_node_cfg->link_level;
	link_idx = tree_node_cfg->link_idx;

	if ((level == 0) || (level > 4) || (link_level > 5) || (level >= link_level)) {
		LOG_ERR("dcbnl_init_ets: configuration level error, level: %d, link_level: %d\n",
			level, link_level);
		return 1;
	}

	ets_node_list_head = &en_dev->dcb_para.ets_node_list_head[level];

	tree_resource.numq = 1;
	tree_resource.level = level;
	tree_resource.flags = tree_node_cfg->type;
	err = zxdh_dcbnl_get_se_flow_resources(en_dev, &tree_resource);
	if (err) {
		LOG_ERR("dcbnl_init_ets: get se resources failed, level: %d, idx: %d\n",
			tree_resource.level, tree_node_cfg->idx);
		return err;
	}

	err = zxdh_dcbnl_find_se_link_id(en_priv, level, link_level, link_idx,
					 tree_node_cfg->link_sp, &link_id);
	if (err) {
		LOG_ERR("dcbnl_init_ets: find se link_id failed, link_level: %d, link_idx: %d\n",
			link_level, link_idx);
		return err;
	}

	new_se_node = kmalloc(sizeof(struct zxdh_dcbnl_ets_se_node), GFP_KERNEL);
	if (!new_se_node) {
		LOG_ERR("dcbnl_init_ets: kmalloc se node failed\n");
		return 1;
	}

	new_se_node->se_next = NULL;
	new_se_node->gsch_id = tree_resource.gsch_id;
	new_se_node->node_idx = tree_node_cfg->idx;
	new_se_node->node_type = tree_node_cfg->type;
	new_se_node->se_id = tree_resource.resource_id;
	new_se_node->se_link_id = link_id;
	new_se_node->se_link_weight = tree_node_cfg->link_weight;
	new_se_node->se_link_sp = tree_node_cfg->link_sp;
	new_se_node->link_point = tree_node_cfg->link_point;

	if (level < ZXDH_DCBNL_ETS_TREE_ROOT_LEVEL) {
		err = dpp_crdt_se_link_set(&pf_info, new_se_node->se_id, new_se_node->se_link_id,
					   new_se_node->se_link_weight, new_se_node->se_link_sp);
		if (err) {
			LOG_ERR(" dpp_crdt_se_link_set failed, level: %d, idx: %d, err:%d\n",
				level, tree_node_cfg->idx, err);
			kfree(new_se_node);
			return err;
		}
	}

	new_se_node->se_next = ets_node_list_head->se_next;
	ets_node_list_head->se_next = new_se_node;

	ets_node_list_head->node_num += 1;

	LOG_INFO(" level:%d, node_idx:%d, node_num:%d\n", level, new_se_node->node_idx,
		 ets_node_list_head->node_num);
	return 0;
}

u32 zxdh_dcbnl_build_ets_scheduling_tree(struct zxdh_en_priv *en_priv)
{
	u32 i = 0;
	u32 err = 0;

	struct zxdh_dcbnl_se_tree_config ets_se_config_table[ZXDH_DCBNL_MAX_SE_NODE_NUM + 1] = {
		{ 4, 0, ZXDH_DCBNL_ETS_NODE_WFQ, 5, 0, 1, 0, ZXDH_DCBNL_ETS_NODE_NULL },
		{ 3, 0, ZXDH_DCBNL_ETS_NODE_FQ2, 4, 0, 1, 0, ZXDH_DCBNL_ETS_NODE_NULL },
		{ 2, 0, ZXDH_DCBNL_ETS_NODE_FQ4, 3, 0, 1, 0, ZXDH_DCBNL_ETS_NODE_NULL },
		{ 2, 1, ZXDH_DCBNL_ETS_NODE_FQ4, 3, 0, 1, 1, ZXDH_DCBNL_ETS_NODE_NULL },
		{ 1, 0, ZXDH_DCBNL_ETS_NODE_FQ, 2, 0, 1, 0, ZXDH_DCBNL_ETS_NODE_VENDOR_C },
		{ 1, 1, ZXDH_DCBNL_ETS_NODE_FQ8, 2, 0, 1, 1, ZXDH_DCBNL_ETS_NODE_STRICT_C },
		{ 1, 2, ZXDH_DCBNL_ETS_NODE_WFQ, 2, 0, 1, 2, ZXDH_DCBNL_ETS_NODE_ETS_C },
		{ 1, 3, ZXDH_DCBNL_ETS_NODE_WFQ, 2, 0, 1, 3, ZXDH_DCBNL_ETS_NODE_ZEROBW_ETS_C },
		{ 1, 4, ZXDH_DCBNL_ETS_NODE_FQ, 2, 1, 1, 0, ZXDH_DCBNL_ETS_NODE_VENDOR_E },
		{ 1, 5, ZXDH_DCBNL_ETS_NODE_FQ8, 2, 1, 1, 1, ZXDH_DCBNL_ETS_NODE_STRICT_E },
		{ 1, 6, ZXDH_DCBNL_ETS_NODE_WFQ, 2, 1, 1, 2, ZXDH_DCBNL_ETS_NODE_ETS_E },
		{ 1, 7, ZXDH_DCBNL_ETS_NODE_WFQ, 2, 1, 1, 3, ZXDH_DCBNL_ETS_NODE_ZEROBW_ETS_E },
		{ 0xff }
	};

	for (i = 0; i < ZXDH_DCBNL_MAX_SE_NODE_NUM && ets_se_config_table[i].level != 0xff; i++) {
		err = zxdh_dcbnl_save_se_resources(en_priv, &ets_se_config_table[i]);
		if (err) {
			LOG_ERR("dcbnl_init_ets: build_tc_scheduling_tree failed, entry: %d\n", i);
			return err;
		}
	}

	return 0;
}

void zxdh_dcbnl_tc_map_to_link_point(u32 tc_type, u32 *c_type, u32 *e_type)
{
	switch (tc_type) {
	case ZXDH_DCBNL_VENDOR_TC:
		*c_type = ZXDH_DCBNL_ETS_NODE_VENDOR_C;
		*e_type = ZXDH_DCBNL_ETS_NODE_VENDOR_E;
		break;

	case ZXDH_DCBNL_STRICT_TC:
		*c_type = ZXDH_DCBNL_ETS_NODE_STRICT_C;
		*e_type = ZXDH_DCBNL_ETS_NODE_STRICT_E;
		break;

	case ZXDH_DCBNL_ETS_TC:
		*c_type = ZXDH_DCBNL_ETS_NODE_ETS_C;
		*e_type = ZXDH_DCBNL_ETS_NODE_ETS_E;
		break;

	case ZXDH_DCBNL_ZEROBW_ETS_TC:
		*c_type = ZXDH_DCBNL_ETS_NODE_ZEROBW_ETS_C;
		*e_type = ZXDH_DCBNL_ETS_NODE_ZEROBW_ETS_E;
		break;
	default:
		break;
	}
}

void zxdh_dcbnl_get_tc_weight_sp(u32 tc_type, u32 tc_tx_bw, u32 tc_id, u32 *c_weight, u32 *e_weight,
				 u32 *c_sp, u32 *e_sp)
{
	if (tc_tx_bw == ZXDH_DCBNL_MAX_BW_ALLOC) {
		*c_weight = 1;
		*e_weight = 1;
	} else {
		*c_weight = ZXDH_DCBNL_MAX_WEIGHT * tc_tx_bw / ZXDH_DCBNL_MAX_BW_ALLOC;
		*e_weight = ZXDH_DCBNL_MAX_WEIGHT * tc_tx_bw / ZXDH_DCBNL_MAX_BW_ALLOC;
	}

	if ((tc_type == ZXDH_DCBNL_STRICT_TC) && (tc_id < ZXDH_DCBNL_MAX_TRAFFIC_CLASS)) {
		*c_sp = ZXDH_DCBNL_MAX_TRAFFIC_CLASS - 1 - tc_id;
		*e_sp = ZXDH_DCBNL_MAX_TRAFFIC_CLASS - 1 - tc_id;
	} else {
		*c_sp = 0;
		*e_sp = 0;
	}
}

u32 zxdh_dcbnl_find_flow_link_se_id(struct zxdh_en_priv *en_priv, u32 tc_type, u32 link_level,
				    u32 *c_linkid, u32 *e_linkid, u32 c_sp, u32 e_sp)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_ets_se_node *se_node =
		en_dev->dcb_para.ets_node_list_head[link_level].se_next;
	u32 c_type = 0;
	u32 e_type = 0;

	if (!se_node) {
		LOG_ERR("dcbnl: find_flow_link_se_id no nodes\n");
		return 1;
	}

	zxdh_dcbnl_tc_map_to_link_point(tc_type, &c_type, &e_type);

	*c_linkid = ZXDH_DCBNL_NULL_ID;
	*e_linkid = ZXDH_DCBNL_NULL_ID;

	while ((se_node) &&
	       ((*c_linkid == ZXDH_DCBNL_NULL_ID) || (*e_linkid == ZXDH_DCBNL_NULL_ID))) {
		if (se_node->link_point == c_type)
			*c_linkid = se_node->se_id + c_sp;
		else if (se_node->link_point == e_type)
			*e_linkid = se_node->se_id + e_sp;

		se_node = se_node->se_next;
	}

	if ((*c_linkid == ZXDH_DCBNL_NULL_ID) || (*e_linkid == ZXDH_DCBNL_NULL_ID)) {
		LOG_ERR("dcbnl: find_flow_link_se_id failed, c_linkid: 0x%x, e_linkid: 0x%x\n",
			*c_linkid, *e_linkid);
		return 1;
	}
	return 0;
}

u32 zxdh_dcbnl_get_ieee_tsa(u32 tc_type)
{
	u32 tsa = 0;

	switch (tc_type) {
	case ZXDH_DCBNL_ETS_TC:
	case ZXDH_DCBNL_ZEROBW_ETS_TC:
		tsa = IEEE_8021QAZ_TSA_ETS;
		break;
	case ZXDH_DCBNL_STRICT_TC:
		tsa = IEEE_8021QAZ_TSA_STRICT;
		break;
	case ZXDH_DCBNL_VENDOR_TC:
		tsa = IEEE_8021QAZ_TSA_VENDOR;
		break;
	default:
		tsa = IEEE_8021QAZ_TSA_STRICT;
		LOG_ERR("dcbnl:tsa error, change to strict\n");
		break;
	}
	return tsa;
}

u32 zxdh_dcbnl_save_flow_resources(struct zxdh_en_priv *en_priv,
				   struct zxdh_dcbnl_tc_flow_config *tc_flow_config,
				   struct zxdh_dcbnl_ets_se_flow_resource *tree_resource, u32 tc_id)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_ets_flow_node *new_flow_node = NULL;
	struct zxdh_dcbnl_ets_node_list_head *ets_node_list_head = NULL;
	struct zxdh_dcbnl_tc_flow_shape_para p_para = { 0 };
	u32 c_linkid = 0;
	u32 e_linkid = 0;
	u32 c_weight = 0;
	u32 e_weight = 0;
	u32 c_sp = 0;
	u32 e_sp = 0;
	u32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (tc_flow_config->link_level != 1) {
		LOG_ERR("dcbnl_init_ets: zxdh dcbnl_save_flow_resources link_level err\n");
		return 1;
	}

	ets_node_list_head = &en_dev->dcb_para.ets_node_list_head[ZXDH_DCBNL_ETS_TREE_FLOW_LEVEL];

	if (tc_id == 0) {
		tree_resource->numq = ZXDH_DCBNL_MAX_TRAFFIC_CLASS;
		tree_resource->level = ZXDH_DCBNL_ETS_TREE_FLOW_LEVEL;
		tree_resource->flags = ZXDH_DCBNL_ETS_NODE_FLOW;
		err = zxdh_dcbnl_get_se_flow_resources(en_dev, tree_resource);
		if (err) {
			LOG_ERR("dcbnl_init_ets: get flow resources err\n");
			return err;
		}

		err = dpp_tm_flowid_pport_table_set(&pf_info, en_dev->phy_port,
						    tree_resource->resource_id);
		if (err) {
			LOG_ERR("flowid set failed, port: %d, flowid:%d, err:%d\n",
				en_dev->phy_port, tree_resource->resource_id, err);
			return err;
		}
	}

	zxdh_dcbnl_get_tc_weight_sp(tc_flow_config->tc_type, tc_flow_config->tc_tx_bw, tc_id,
				    &c_weight, &e_weight, &c_sp, &e_sp);

	err = zxdh_dcbnl_find_flow_link_se_id(en_priv, tc_flow_config->tc_type,
					      tc_flow_config->link_level, &c_linkid, &e_linkid,
					      c_sp, e_sp);
	if (err) {
		LOG_ERR(" init ets: find_flow_link_se_id failed, tc_id: %d, tc_type: %d\n",
			tc_id, tc_flow_config->tc_type);
		return err;
	}

	new_flow_node = kmalloc(sizeof(struct zxdh_dcbnl_ets_flow_node), GFP_KERNEL);
	if (!new_flow_node) {
		LOG_ERR("dcbnl_init_ets: kmalloc new flow node failed\n");
		return 1;
	}

	new_flow_node->flow_next = NULL;
	new_flow_node->gsch_id = tree_resource->gsch_id + tc_id;
	new_flow_node->flow_id = tree_resource->resource_id + tc_id;
	new_flow_node->tc_id = tc_id;
	new_flow_node->tc_type = tc_flow_config->tc_type;
	new_flow_node->tc_tx_bw = tc_flow_config->tc_tx_bw;
	new_flow_node->td_th = tc_flow_config->td_th;
	new_flow_node->c_linkid = c_linkid;
	new_flow_node->c_weight = c_weight;
	new_flow_node->c_sp = c_sp;
	new_flow_node->c_rate = tc_flow_config->c_rate;
	new_flow_node->mode = 1;
	new_flow_node->e_linkid = e_linkid;
	new_flow_node->e_weight = e_weight;
	new_flow_node->e_sp = e_sp;
	new_flow_node->e_rate = tc_flow_config->e_rate;

	err = dpp_flow_map_port_set(&pf_info, new_flow_node->flow_id, en_dev->phy_port);
	if (err) {
		LOG_ERR(":flow_map_port_set failed, flow_id: %d, phy_port: %d, err:%d\n",
			new_flow_node->flow_id, en_dev->phy_port, err);
		kfree(new_flow_node);
		return err;
	}

	err = dpp_crdt_flow_link_set(&pf_info, new_flow_node->flow_id, c_linkid, c_weight, c_sp,
				     new_flow_node->mode, e_linkid, e_weight, e_sp);
	if (err) {
		LOG_ERR(" crdt_flow_set failed, flow_id: %d, c_linkid: %d, e_linkid: %d, err:%d\n",
			new_flow_node->flow_id, c_linkid, e_linkid, err);
		kfree(new_flow_node);
		return err;
	}

	err = dpp_flow_td_th_set(&pf_info, new_flow_node->flow_id, new_flow_node->td_th);
	if (err) {
		LOG_ERR("flow_td_th_set failed,vport:%d flow_id: %d, td_th: %d, err:%d\n",
			en_dev->vport, new_flow_node->flow_id, new_flow_node->td_th, err);
	}

	p_para.cir = new_flow_node->c_rate;
	p_para.cbs = ZXDH_DCBNL_FLOW_RATE_CBS;
	p_para.db_en = 1;
	p_para.eir = new_flow_node->e_rate;
	p_para.ebs = ZXDH_DCBNL_FLOW_RATE_EBS;

	err = dpp_flow_shape_set(&pf_info, new_flow_node->flow_id, p_para.cir, p_para.cbs,
				 p_para.db_en, p_para.eir, p_para.ebs);
	if (err) {
		LOG_ERR("shape_set failed, vport:%d, flowid:%d, tc_id:%d, e_rate:%d, err:%d\n",
			en_dev->vport, new_flow_node->flow_id, new_flow_node->tc_id,
			new_flow_node->e_rate, err);
	}

	new_flow_node->flow_next = ets_node_list_head->flow_next;
	ets_node_list_head->flow_next = new_flow_node;
	ets_node_list_head->node_num += 1;

	en_dev->dcb_para.ets_cfg.tc_tsa[tc_id] = zxdh_dcbnl_get_ieee_tsa(new_flow_node->tc_type);
	en_dev->dcb_para.ets_cfg.tc_tx_bw[tc_id] = tc_flow_config->tc_tx_bw;
	en_dev->dcb_para.tc_maxrate[tc_id] = new_flow_node->e_rate;

	LOG_DEBUG(" level:%d, tc_id:%d, flow_id:%d, node_num:%d\n", tree_resource->level,
		  new_flow_node->tc_id, new_flow_node->flow_id, ets_node_list_head->node_num);

	return 0;
}

u32 zxdh_dcbnl_scheduling_tree_link_tc(struct zxdh_en_priv *en_priv)
{
	struct zxdh_dcbnl_ets_se_flow_resource tree_resource;
	u32 i = 0;
	u32 err = 0;

	struct zxdh_dcbnl_tc_flow_config ets_tc_config_table[ZXDH_DCBNL_MAX_TRAFFIC_CLASS + 1] = {
		{ 1, ZXDH_DCBNL_STRICT_TC, 100, ZXDH_DCBNL_FLOW_RATE_CIR,
		  ZXDH_DCBNL_INITRATE_KBITPS, ZXDH_DCBNL_FLOW_TDTH_UPF },
		{ 1, ZXDH_DCBNL_STRICT_TC, 100, ZXDH_DCBNL_FLOW_RATE_CIR,
		  ZXDH_DCBNL_INITRATE_KBITPS, ZXDH_DCBNL_FLOW_TDTH },
		{ 1, ZXDH_DCBNL_STRICT_TC, 100, ZXDH_DCBNL_FLOW_RATE_CIR,
		  ZXDH_DCBNL_INITRATE_KBITPS, ZXDH_DCBNL_FLOW_TDTH },
		{ 1, ZXDH_DCBNL_STRICT_TC, 100, ZXDH_DCBNL_FLOW_RATE_CIR,
		  ZXDH_DCBNL_INITRATE_KBITPS, ZXDH_DCBNL_FLOW_TDTH },
		{ 1, ZXDH_DCBNL_STRICT_TC, 100, ZXDH_DCBNL_FLOW_RATE_CIR,
		  ZXDH_DCBNL_INITRATE_KBITPS, ZXDH_DCBNL_FLOW_TDTH },
		{ 1, ZXDH_DCBNL_STRICT_TC, 100, ZXDH_DCBNL_FLOW_RATE_CIR,
		  ZXDH_DCBNL_INITRATE_KBITPS, ZXDH_DCBNL_FLOW_TDTH },
		{ 1, ZXDH_DCBNL_STRICT_TC, 100, ZXDH_DCBNL_FLOW_RATE_CIR,
		  ZXDH_DCBNL_INITRATE_KBITPS, ZXDH_DCBNL_FLOW_TDTH },
		{ 1, ZXDH_DCBNL_STRICT_TC, 100, ZXDH_DCBNL_FLOW_RATE_CIR,
		  ZXDH_DCBNL_INITRATE_KBITPS, ZXDH_DCBNL_FLOW_TDTH },
		{ 0xff }
	};

	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS && ets_tc_config_table[i].link_level != 0xff;
	     i++) {
		err = zxdh_dcbnl_save_flow_resources(en_priv, &ets_tc_config_table[i],
						     &tree_resource, i);
		if (err) {
			LOG_ERR("dcbnl_init_ets: save_flow_resources failed, entry: %d\n", i);
			return err;
		}
	}

	return 0;
}

u32 zxdh_dcbnl_set_ets_trust(struct zxdh_en_priv *en_priv, u32 trust)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	err = dpp_tm_pport_trust_mode_table_set(&pf_info, en_dev->phy_port, trust);
	if (err) {
		LOG_ERR("dcbnl_set_ets: set_ets_trust failed, vport: %d, trust: %d, err:%d\n",
			en_dev->vport, trust, err);
		return err;
	}
	en_dev->dcb_para.trust = trust;
	LOG_DEBUG(" trust:%d\n", trust);
	return 0;
}

u32 zxdh_dcbnl_init_trust_and_table(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 i = 0;
	u32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	for (i = 0; i < ZXDH_DCBNL_MAX_PRIORITY; i++) {
		err = dpp_tm_pport_up_map_table_set(&pf_info, en_dev->phy_port, i, i);
		if (err) {
			LOG_ERR("pport_up_table_set failed, vport: %d, phy_port: %d, err:%d\n",
				en_dev->vport, en_dev->phy_port, err);
			return err;
		}
		en_dev->dcb_para.ets_cfg.prio_tc[i] = i;
	}
	LOG_DEBUG(" vport:%d,phy_port:%d prio2tc ok\n", en_dev->vport, en_dev->phy_port);

	for (i = 0; i < ZXDH_DCBNL_MAX_DSCP; i++) {
		err = dpp_tm_pport_dscp_map_table_set(&pf_info, en_dev->phy_port, i, i >> 3);
		if (err) {
			LOG_ERR("dscp_map_table_set failed, vport: %d, phy_port: %d, err:%d\n",
				en_dev->vport, en_dev->phy_port, err);
			return err;
		}

		en_dev->dcb_para.dscp2prio[i] = i >> 3;
	}
	LOG_DEBUG("vport:%d,phy_port:%d,dscp2prio ok\n", en_dev->vport, en_dev->phy_port);

	err = zxdh_dcbnl_set_ets_trust(en_priv, ZXDH_DCBNL_ETS_TRUST_PCP);
	if (err) {
		LOG_INFO("set_ets_trust failed\n");
		return err;
	}
	en_dev->dcb_para.trust = ZXDH_DCBNL_ETS_TRUST_PCP;
	LOG_DEBUG(" vport:%d,phy_port:%d,trust:%d\n", en_dev->vport, en_dev->phy_port,
		  en_dev->dcb_para.trust);
	return 0;
}

u32 zxdh_dcbnl_init_ets_list(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 level = 0;

	for (level = 0; level < ZXDH_DCBNL_MAX_TREE_LEVEL; level++) {
		en_dev->dcb_para.ets_node_list_head[level].se_next = NULL;
		en_dev->dcb_para.ets_node_list_head[level].flow_next = NULL;
		en_dev->dcb_para.ets_node_list_head[level].node_num = 0;
	}
	return 0;
}

/* Normal release se*/
u32 zxdh_dcbnl_free_se_resources(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_ets_se_node *se_node = NULL;
	struct zxdh_dcbnl_ets_node_list_head *ets_node_list_head = NULL;
	u32 err = 0;
	u32 level = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	LOG_DEBUG(" vport:%d, phy_port:%d\n", en_dev->vport, en_dev->phy_port);
	for (level = 1; level <= ZXDH_DCBNL_ETS_TREE_ROOT_LEVEL; level++) {
		ets_node_list_head = &en_dev->dcb_para.ets_node_list_head[level];
		while (ets_node_list_head->se_next) {
			se_node = ets_node_list_head->se_next;
			ets_node_list_head->se_next = se_node->se_next;
			if (level < ZXDH_DCBNL_ETS_TREE_ROOT_LEVEL) {
				if (!en_dev->quick_remove) {
					err = dpp_crdt_del_se_link_set(&pf_info, se_node->se_id,
								       se_node->se_id);
					if (err) {
						LOG_ERR("se_link_set failed, se_id: %d, err:%d\n",
							se_node->se_id, err);
					}
					LOG_DEBUG(" dpp_crdt_del_se_link_set");

					err = dpp_cosq_gsch_id_delete(&pf_info, en_dev->phy_port,
								      se_node->gsch_id);
					if (err) {
						LOG_ERR("gsch delete failed, seid:%lld, err:%d\n",
							se_node->gsch_id, err);
					}
					LOG_DEBUG("del se id dpp_cosq_gsch_id_delete");
				}
			}
			LOG_DEBUG(" free level:%d se_id:%x\n", level, se_node->se_id);
			kfree(se_node);
			ets_node_list_head->node_num -= 1;
			LOG_DEBUG("current node_num:%d\n", ets_node_list_head->node_num);
		}
	}

	return 0;
}

u32 zxdh_dcbnl_free_flow_resources(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_ets_flow_node *flow_node = NULL;
	struct zxdh_dcbnl_ets_node_list_head *ets_node_list_head =
		&en_dev->dcb_para.ets_node_list_head[ZXDH_DCBNL_ETS_TREE_FLOW_LEVEL];
	u32 err = 0;
	bool have_flow = false;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_dcbnl_tc_flow_shape_para p_para = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	LOG_DEBUG(" vport:%d, phy_port:%d\n", en_dev->vport, en_dev->phy_port);
	while (ets_node_list_head->flow_next) {
		have_flow = true;
		flow_node = ets_node_list_head->flow_next;
		ets_node_list_head->flow_next = flow_node->flow_next;

		p_para.cir = 0;
		p_para.cbs = ZXDH_DCBNL_FLOW_RATE_CBS_REFRESH;
		p_para.db_en = 1;
		p_para.eir = 0;
		p_para.ebs = ZXDH_DCBNL_FLOW_RATE_EBS_REFRESH;
		if (!en_dev->quick_remove) {
			err = dpp_flow_shape_set(&pf_info, flow_node->flow_id, p_para.cir,
						 p_para.cbs, p_para.db_en, p_para.eir, p_para.ebs);
			if (err) {
				LOG_ERR("vport: %d, flowid: %d, tcid: %d, eir: %d, err:%d\n",
					en_dev->vport, flow_node->flow_id, flow_node->tc_id,
					p_para.eir, err);
				return err;
			}
			LOG_INFO("clean maxrate");
			err = dpp_flow_td_th_set(&pf_info, flow_node->flow_id, 0);
			if (err) {
				LOG_ERR("th_set failed,vport:%d flow_id: %d, td_th: 0, err:%d\n",
					en_dev->vport, flow_node->flow_id, err);
			}
			LOG_INFO(" clean TD ");

			err = dpp_crdt_del_flow_link_set(&pf_info, flow_node->flow_id,
							 flow_node->flow_id);
			if (err) {
				LOG_ERR("crdt_del_flow_link_set failed, flow_id: %d, err:%d\n",
					flow_node->flow_id, err);
			}
			LOG_INFO(" dpp_crdt_del_flow_link_set");

			err = dpp_cosq_gsch_id_delete(&pf_info, en_dev->phy_port,
						      flow_node->gsch_id);
			if (err) {
				LOG_ERR("gsch_id_delete failed, gsch_id: %lld ,err:%d\n",
					flow_node->gsch_id, err);
			}
			LOG_INFO("del id  dpp_cosq_gsch_id_delete");

			LOG_INFO(" free level:0, flow_id:%d, tc:%d\n", flow_node->flow_id,
				 flow_node->tc_id);
		}

		kfree(flow_node);
		ets_node_list_head->node_num -= 1;
		LOG_INFO("current node_num:%d\n", ets_node_list_head->node_num);
	}

	if (have_flow) {
		if (!en_dev->quick_remove) {
			err = dpp_tm_flowid_pport_table_del(&pf_info, en_dev->phy_port);
			if (err) {
				LOG_ERR("tm_flowid_pport_table_del failed,vport:%d, phy_port: %d\n",
					en_dev->vport, en_dev->phy_port);
			}
			LOG_INFO("del table dpp_tm_flowid_pport_table_del");
		}
	}

	return 0;
}

/* host no reset，risc reset? */
u32 zxdh_dcbnl_check_and_free_node_memory(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_ets_flow_node *flow_node = NULL;
	struct zxdh_dcbnl_ets_se_node *se_node = NULL;
	struct zxdh_dcbnl_ets_node_list_head *ets_node_list_head = NULL;
	u32 level = 0;

	ets_node_list_head = &en_dev->dcb_para.ets_node_list_head[ZXDH_DCBNL_ETS_TREE_FLOW_LEVEL];
	while (ets_node_list_head->flow_next) {
		flow_node = ets_node_list_head->flow_next;
		ets_node_list_head->flow_next = flow_node->flow_next;
		kfree(flow_node);
		ets_node_list_head->node_num -= 1;
	}

	for (level = 1; level < ZXDH_DCBNL_ETS_TREE_ROOT_LEVEL + 1; level++) {
		ets_node_list_head = &en_dev->dcb_para.ets_node_list_head[level];
		while (ets_node_list_head->se_next) {
			se_node = ets_node_list_head->se_next;
			ets_node_list_head->se_next = se_node->se_next;
			kfree(se_node);
			ets_node_list_head->node_num -= 1;
		}
	}

	return 0;
}

u32 zxdh_dcbnl_set_tc_scheduling(struct zxdh_en_priv *en_priv, u8 *tc_type, u8 *tc_tx_bw)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_ets_flow_node *flow_node =
		en_dev->dcb_para.ets_node_list_head[ZXDH_DCBNL_ETS_TREE_FLOW_LEVEL].flow_next;
	u32 tc_id = 0;
	u32 c_linkid = 0;
	u32 e_linkid = 0;
	u32 c_weight = 0;
	u32 e_weight = 0;
	u32 c_sp = 0;
	u32 e_sp = 0;
	u32 i = 0;
	u32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_dcbnl_tc_flow_shape_para p_para = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (!flow_node) {
		LOG_ERR("dcbnl_set_ets: set_tc_scheduling no flow in the tree\n");
		return 1;
	}

	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS && flow_node; i++) {
		tc_id = flow_node->tc_id;
		if ((flow_node->tc_type == tc_type[tc_id]) &&
		    (flow_node->tc_tx_bw == tc_tx_bw[tc_id])) {
			LOG_DEBUG("Same configuration,tc_id:%d, tc_type:%d, tc_tx_bw:%d\n", tc_id,
				  tc_type[tc_id], tc_tx_bw[tc_id]);
			flow_node = flow_node->flow_next;
			continue;
		}

		zxdh_dcbnl_get_tc_weight_sp(tc_type[tc_id], tc_tx_bw[tc_id], tc_id, &c_weight,
					    &e_weight, &c_sp, &e_sp);

		err = zxdh_dcbnl_find_flow_link_se_id(en_priv, tc_type[tc_id], 1, &c_linkid,
						      &e_linkid, c_sp, e_sp);
		if (err) {
			LOG_ERR("link_se_id failed, tc_id: %d, tc_type: %d\n",
				tc_id, tc_type[tc_id]);
			return err;
		}

		p_para.cir = 0;
		p_para.cbs = ZXDH_DCBNL_FLOW_RATE_CBS_REFRESH;
		p_para.db_en = 1;
		p_para.eir = 0;
		p_para.ebs = ZXDH_DCBNL_FLOW_RATE_EBS_REFRESH;

		LOG_DEBUG(
			"clean maxrate vport%d,phy_port:%d, flow_id:%d,tc_id:%d, cir:%d, cbs:%d, db_en:%d, eir:%d,ebs:%d\n",
			en_dev->vport, en_dev->phy_port, flow_node->flow_id, tc_id, p_para.cir,
			p_para.cbs, p_para.db_en, p_para.eir, p_para.ebs);

		err = dpp_flow_shape_set(&pf_info, flow_node->flow_id, p_para.cir, p_para.cbs,
					 p_para.db_en, p_para.eir, p_para.ebs);
		if (err) {
			LOG_ERR("failed, vport: %d, flowid: %d, tcid: %d, eir: %d, err:%d\n",
				en_dev->vport, flow_node->flow_id, tc_id, p_para.eir, err);
			return err;
		}

		err = dpp_flow_td_th_set(&pf_info, flow_node->flow_id, 0);
		if (err) {
			LOG_ERR("td_th_set failed,vport:%d flow_id: %d, td_th: 0, err:%d\n",
				en_dev->vport, flow_node->flow_id, err);
		}

		err = dpp_crdt_del_flow_link_set(&pf_info, flow_node->flow_id, flow_node->flow_id);
		if (err) {
			LOG_ERR("crdt_del_flow_set failed, vport: %d, flow_id: %d, err:%d\n",
				en_dev->vport, flow_node->flow_id, err);
			return err;
		}

		err = dpp_crdt_flow_link_set(&pf_info, flow_node->flow_id, c_linkid, c_weight, c_sp,
					     1, e_linkid, e_weight, e_sp);
		if (err) {
			LOG_ERR("crdt_set failed, flow_id: %d, flow_id: %d, flow_id: %d,err:%d\n",
				flow_node->flow_id, c_linkid, e_linkid, err);
			return err;
		}

		err = dpp_flow_td_th_set(&pf_info, flow_node->flow_id, flow_node->td_th);
		if (err) {
			LOG_ERR("td_th_set failed,vport:%d flow_id: %d, td_th:%d, err:%d\n",
				en_dev->vport, flow_node->flow_id, flow_node->td_th, err);
		}

		p_para.cir = ZXDH_DCBNL_FLOW_RATE_CIR;
		p_para.cbs = ZXDH_DCBNL_FLOW_RATE_CBS;
		p_para.db_en = 1;
		p_para.eir = flow_node->e_rate;
		p_para.ebs = ZXDH_DCBNL_FLOW_RATE_EBS;

		err = dpp_flow_shape_set(&pf_info, flow_node->flow_id, p_para.cir, p_para.cbs,
					 p_para.db_en, p_para.eir, p_para.ebs);
		if (err) {
			LOG_ERR("failed, vport: %d, flowid: %d, tcid: %d, eir: %d, err:%d\n",
				en_dev->vport, flow_node->flow_id, tc_id, p_para.eir, err);
			return err;
		}
		LOG_INFO(" dpp_flow_shape_set end");
		flow_node->tc_type = tc_type[tc_id];
		flow_node->tc_tx_bw = tc_tx_bw[tc_id];

		flow_node->c_linkid = c_linkid;
		flow_node->c_weight = c_weight;
		flow_node->c_sp = c_sp;

		flow_node->e_linkid = e_linkid;
		flow_node->e_weight = e_weight;
		flow_node->e_sp = e_sp;

		LOG_DEBUG(
			" tc_id:%d, tc_type:%d, c_linkid:%x, e_weight:%d, e_sp:%d ,e_linkid:%x, e_weight:%d, e_sp:%d\n",
			tc_id, flow_node->tc_type, flow_node->c_linkid, flow_node->c_weight,
			flow_node->c_sp, flow_node->e_linkid, flow_node->e_weight, flow_node->e_sp);

		flow_node = flow_node->flow_next;
	}

	return 0;
}

u32 zxdh_dcbnl_set_ets_up_tc_map(struct zxdh_en_priv *en_priv, u8 *prio_tc)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 i = 0;
	u32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	u32 tc_td_th[ZXDH_DCBNL_MAX_TRAFFIC_CLASS] = { 0 };

	LOG_DEBUG(" begin\n");
	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	for (i = 0; i < ZXDH_DCBNL_MAX_PRIORITY; i++) {
		err = dpp_tm_pport_up_map_table_set(&pf_info, en_dev->phy_port, i, prio_tc[i]);
		if (err) {
			LOG_ERR("dcbnl_set_ets:  failed, vport: %d, prio: %d, tc: %d, err:%d\n",
				en_dev->vport, i, prio_tc[i], err);
			return err;
		}
		LOG_DEBUG(" vport:%d, phy_port:%d, prio:%d, tc:%d\n", en_dev->vport,
			  en_dev->phy_port, i, prio_tc[i]);
	}

	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; i++)
		tc_td_th[i] = ZXDH_DCBNL_FLOW_TDTH;

	if (prio_tc[0] < ZXDH_DCBNL_MAX_TRAFFIC_CLASS)
		tc_td_th[prio_tc[0]] = ZXDH_DCBNL_FLOW_TDTH_UPF;

	err = zxdh_dcbnl_set_flow_td_th(en_priv, tc_td_th);
	if (err)
		return err;

	return 0;
}

u32 zxdh_dcbnl_set_tc_maxrate(struct zxdh_en_priv *en_priv, u32 *maxrate)
{
	struct zxdh_en_device *en_dev;
	struct zxdh_dcbnl_ets_flow_node *flow_node;
	struct zxdh_dcbnl_tc_flow_shape_para p_para = { 0 };
	u32 tc_id = 0;
	u32 i = 0;
	u32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	u32 temp = 0;
	struct dh_core_dev *dh_dev;
	struct zxdh_pf_device *pf_dev;

	if (en_priv == NULL || maxrate == NULL)
		return ZXDH_DCBNL_INVALID_PARA;

	en_dev = &en_priv->edev;
	if (en_dev == NULL)
		return ZXDH_DCBNL_INVALID_PARA;

	flow_node = en_dev->dcb_para.ets_node_list_head[ZXDH_DCBNL_ETS_TREE_FLOW_LEVEL].flow_next;
	dh_dev = en_dev->parent;
	if (dh_dev == NULL)
		return ZXDH_DCBNL_INVALID_PARA;

	pf_dev = dh_core_priv(dh_dev->parent);
	if (pf_dev == NULL)
		return ZXDH_DCBNL_INVALID_PARA;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (!flow_node) {
		LOG_ERR("dcbnl_set_ets: set_tc_maxrate no flow in the tree\n");
		return 1;
	}

	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS && flow_node; i++) {
		tc_id = flow_node->tc_id;
		if (tc_id >= ZXDH_DCBNL_MAX_TRAFFIC_CLASS)
			return ZXDH_DCBNL_INVALID_PARA;
		if (flow_node->e_rate == maxrate[tc_id]) {
			LOG_DEBUG("Same configuration, tc_id:%d, maxrate:%d\n", tc_id,
				  maxrate[tc_id]);
			flow_node = flow_node->flow_next;
			continue;
		}
		/* clean CBS、EBS*/
		p_para.cir = 0;
		p_para.cbs = ZXDH_DCBNL_FLOW_RATE_CBS_REFRESH;
		p_para.db_en = 1;
		p_para.eir = 0;
		p_para.ebs = ZXDH_DCBNL_FLOW_RATE_EBS_REFRESH;
		LOG_DEBUG(" refresh maxrate ");
		err = dpp_flow_shape_set(&pf_info, flow_node->flow_id, p_para.cir, p_para.cbs,
					 p_para.db_en, p_para.eir, p_para.ebs);
		if (err) {
			LOG_ERR("failed, vport: %d, flowid: %d, tcid: %d, eir: %d, err:%d\n",
				en_dev->vport, flow_node->flow_id, tc_id, p_para.eir, err);
			return err;
		}
		/* 2、set maxrate*/
		p_para.cir = ZXDH_DCBNL_FLOW_RATE_CIR;
		p_para.cbs = ZXDH_DCBNL_FLOW_RATE_CBS;
		p_para.db_en = 1;
		p_para.eir = maxrate[tc_id];
		LOG_DEBUG(" new pf_dev-boardtype %d\n", pf_dev->board_type);

		temp = maxrate[tc_id] / 20;
		if ((maxrate[tc_id] != ZXDH_DCBNL_MAXRATE_KBITPS) && maxrate[tc_id] != 0)
			p_para.eir = maxrate[tc_id] + temp;

		p_para.ebs = ZXDH_DCBNL_FLOW_RATE_EBS;

		LOG_DEBUG(
			" vport%d,phy_port:%d, flow_id:%d,tc_id:%d, cir:%d, cbs:%d, db_en:%d, eir:%d,ebs:%d\n",
			en_dev->vport, en_dev->phy_port, flow_node->flow_id, tc_id, p_para.cir,
			p_para.cbs, p_para.db_en, p_para.eir, p_para.ebs);

		err = dpp_flow_shape_set(&pf_info, flow_node->flow_id, p_para.cir, p_para.cbs,
					 p_para.db_en, p_para.eir, p_para.ebs);
		if (err) {
			LOG_ERR("failed, vport: %d, flowid: %d, tcid: %d, eir: %d, err:%d\n",
				en_dev->vport, flow_node->flow_id, tc_id, p_para.eir, err);
			return err;
		}

		flow_node->e_rate = maxrate[tc_id];
		en_dev->dcb_para.tc_maxrate[tc_id] = maxrate[tc_id];

		flow_node = flow_node->flow_next;
	}

	return 0;
}

u32 zxdh_dcbnl_set_dscp2prio(struct zxdh_en_priv *en_priv, u16 dscp, u8 prio)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	err = dpp_tm_pport_dscp_map_table_set(&pf_info, en_dev->phy_port, dscp, prio);
	if (err) {
		LOG_ERR("set_dscp2prio failed, vport: %d, dscp: %d, prio: %d, err:%d\n",
			en_dev->vport, dscp, prio, err);
		return err;
	}
	en_dev->dcb_para.dscp2prio[dscp] = prio;
	LOG_DEBUG(" vport:%d, ephy_port:%d,dscp:%d, up:%d\n", en_dev->vport, en_dev->phy_port, dscp,
		  prio);

	return 0;
}
u32 zxdh_dcbnl_set_single_td_th(struct zxdh_en_priv *en_priv, u32 tc, u32 tc_td_th)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_ets_flow_node *flow_node =
		en_dev->dcb_para.ets_node_list_head[ZXDH_DCBNL_ETS_TREE_FLOW_LEVEL].flow_next;
	u32 err = 0;
	u32 i = 0;
	u32 tc_id = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (!flow_node) {
		LOG_ERR("dcbnl_set_ets: set_flow_td_th no flow in the tree\n");
		return 1;
	}

	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS && flow_node; i++) {
		tc_id = flow_node->tc_id;
		if (tc_id == tc) {
			err = dpp_flow_td_th_set(&pf_info, flow_node->flow_id, tc_td_th);
			if (err) {
				LOG_ERR("th vport:%d, flowid:%d, tcid:%d, tdth:%d, err:%d\n",
					en_dev->vport, flow_node->flow_id, tc_id, tc_td_th, err);
				return err;
			}
			return 0;
		}
		flow_node = flow_node->flow_next;
	}

	return 0;
}
u32 zxdh_dcbnl_set_flow_td_th(struct zxdh_en_priv *en_priv, u32 *tc_td_th)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_ets_flow_node *flow_node =
		en_dev->dcb_para.ets_node_list_head[ZXDH_DCBNL_ETS_TREE_FLOW_LEVEL].flow_next;
	u32 err = 0;
	u32 i = 0;
	u32 tc_id = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (!flow_node) {
		LOG_ERR("dcbnl_set_ets: set_flow_td_th no flow in the tree\n");
		return 1;
	}

	if (!tc_td_th) {
		LOG_ERR("dcbnl_set_ets: tc_td_th is null\n");
		return 1;
	}

	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS && flow_node; i++) {
		tc_id = flow_node->tc_id;
		if (flow_node->td_th != tc_td_th[tc_id]) {
			err = dpp_flow_td_th_set(&pf_info, flow_node->flow_id, tc_td_th[tc_id]);
			if (err) {
				LOG_ERR("th vport:%d, flowid:%d, tcid:%d, tdth:%d, err:%d\n",
					en_dev->vport, flow_node->flow_id, tc_id, tc_td_th[tc_id],
					err);
				return err;
			}
			flow_node->td_th = tc_td_th[tc_id];
		}
		flow_node = flow_node->flow_next;
	}

	return 0;
}

u32 zxdh_dcbnl_clear_flow_td_th(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_ets_flow_node *flow_node =
		en_dev->dcb_para.ets_node_list_head[ZXDH_DCBNL_ETS_TREE_FLOW_LEVEL].flow_next;
	u32 err = 0;
	u32 i = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (!flow_node) {
		LOG_ERR("dcbnl_set_ets: clear_flow_td_th no flow in the tree\n");
		return 1;
	}

	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS && flow_node; i++) {
		if (flow_node->td_th != 0) {
			err = dpp_flow_td_th_set(&pf_info, flow_node->flow_id, 0);
			if (err) {
				LOG_ERR(" clear_td_th failed, vport: %d, flow_id:%d, err:%d\n",
					en_dev->vport, flow_node->flow_id, err);
				return err;
			}
			flow_node->td_th = 0;
		}
		flow_node = flow_node->flow_next;
	}

	LOG_INFO("clear td_th success!\n");

	return 0;
}

u32 zxdh_dcbnl_get_flow_td_th(struct zxdh_en_priv *en_priv, u32 *tc_td_th)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_ets_flow_node *flow_node =
		en_dev->dcb_para.ets_node_list_head[ZXDH_DCBNL_ETS_TREE_FLOW_LEVEL].flow_next;
	u32 err = 0;
	u32 i = 0;
	u32 tc_id = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (!flow_node) {
		LOG_ERR("get_flow_td_th no flow in the tree\n");
		return 1;
	}

	if (!tc_td_th) {
		LOG_ERR(" tc_td_th is null\n");
		return 1;
	}

	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS && flow_node; i++) {
		tc_id = flow_node->tc_id;
		err = dpp_flow_td_th_get(&pf_info, flow_node->flow_id, &tc_td_th[tc_id]);
		if (err) {
			LOG_ERR("get_flow_td_th failed, vport: %d, flow_id:%d, tc_id:%d, err:%d\n",
				en_dev->vport, flow_node->flow_id, tc_id, err);
			return err;
		}
		flow_node = flow_node->flow_next;
	}

	return 0;
}

u32 zxdh_dcbnl_init_port_speed(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_tc_flow_shape_para p_para = { 0 };
	u32 err = 0;
	u32 speed = 0;
	u32 max_speed = ZXDH_DCBNL_MAXRATE_KBITPS / ZXDH_DCBNL_RATEUNIT_K;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	speed = en_dev->speed;
	if ((speed == 0) || (speed > max_speed)) {
		LOG_INFO("get port speed is : %u ,set to max:%u\n", speed, max_speed);
		speed = max_speed;
	}

	p_para.cir = speed * ZXDH_DCBNL_RATEUNIT_K; //Mbps->Kbps
	p_para.cbs = ZXDH_DCBNL_PORT_RATE_CBS;
	p_para.db_en = 0;
	p_para.eir = 0;
	p_para.ebs = 0;

	LOG_DEBUG(" vport:%d,phy_port:%d, p_para.cir:%d, speed:%d\n", en_dev->vport,
		  en_dev->phy_port, p_para.cir, speed);

	err = dpp_port_shape_set(&pf_info, en_dev->phy_port, p_para.cir, p_para.cbs, 1);
	if (err) {
		LOG_ERR("port_shape_set failed, port:%d, speed:%d, speed:%d,err:%d\n",
			en_dev->phy_port, speed, p_para.cir, err);
		return err;
	}

	return 0;
}

u32 zxdh_dcbnl_printk_ets_tree(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_ets_flow_node *flow_node = NULL;
	struct zxdh_dcbnl_ets_se_node *se_node = NULL;
	struct zxdh_dcbnl_ets_node_list_head *ets_node_list_head = NULL;
	u32 level = 0;

	LOG_DEBUG(" ***vport:%d port:%d\n", en_dev->vport, en_dev->phy_port);

	for (level = ZXDH_DCBNL_ETS_TREE_ROOT_LEVEL; level > 0; level--) {
		ets_node_list_head = &en_dev->dcb_para.ets_node_list_head[level];
		se_node = ets_node_list_head->se_next;
		while (se_node) {
			LOG_DEBUG(" se_node *** level:%d, node_idx:%d, se_id:0x%x ***\n", level,
				  se_node->node_idx, se_node->se_id);
			LOG_DEBUG(" se_node gsch_id:0x%llx, node_type:%d, se_id:0x%x\n",
				  se_node->gsch_id, se_node->node_type, se_node->se_id);
			LOG_DEBUG(
				" se_node se_link_id:0x%x, se_link_weight:%d, se_link_sp:%d, link_point:%d\n",
				se_node->se_link_id, se_node->se_link_weight, se_node->se_link_sp,
				se_node->link_point);
			se_node = se_node->se_next;
		}
	}

	ets_node_list_head = &en_dev->dcb_para.ets_node_list_head[ZXDH_DCBNL_ETS_TREE_FLOW_LEVEL];
	flow_node = ets_node_list_head->flow_next;
	while (flow_node) {
		LOG_DEBUG(" flow_node *** tc_id:%d, flow_id:%d ***\n", flow_node->tc_id,
			  flow_node->flow_id);
		LOG_DEBUG(" flow_node gsch_id:0x%llx,  tc_type:%d, td_th:%d\n", flow_node->gsch_id,
			  flow_node->tc_type, flow_node->td_th);
		LOG_DEBUG(" flow_node c_linkid:0x%x, c_weight:%d, c_sp:%d, c_rate:%d\n",
			  flow_node->c_linkid, flow_node->c_weight, flow_node->c_sp,
			  flow_node->c_rate);
		LOG_DEBUG(" flow_node e_linkid:0x%x, e_weight:%d, e_sp:%d, e_rate:%d\n",
			  flow_node->e_linkid, flow_node->e_weight, flow_node->e_sp,
			  flow_node->e_rate);
		flow_node = flow_node->flow_next;
	}

	return 0;
}

u32 zxdh_dcbnl_init_ets_scheduling_tree(struct zxdh_en_priv *en_priv)
{
	u32 err = 0;

	zxdh_dcbnl_init_ets_list(en_priv);

	err = zxdh_dcbnl_build_ets_scheduling_tree(en_priv);
	if (err) {
		LOG_ERR("dcbnl_init_ets: build_tc_scheduling_tree failed\n");
		goto init_ets_se_error;
	}

	err = zxdh_dcbnl_scheduling_tree_link_tc(en_priv);
	if (err) {
		LOG_ERR("dcbnl_init_ets: scheduling_tree_link_tc failed\n");
		goto init_ets_error;
	}

	err = zxdh_dcbnl_init_trust_and_table(en_priv);
	if (err) {
		LOG_ERR("dcbnl_init_ets: init_trust_and_table failed\n");
		goto init_ets_error;
	}

	return 0;

init_ets_error:
	zxdh_dcbnl_free_flow_resources(en_priv);
init_ets_se_error:
	zxdh_dcbnl_free_se_resources(en_priv);
	LOG_INFO("dcbnl_init_ets failed\n");
	return err;
}

u32 zxdh_dcbnl_set_tm_gate(struct zxdh_en_priv *en_priv, u32 mode)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (!en_dev->quick_remove) {
		if (mode == 1) {
			err = dpp_tm_pport_mcode_switch_set(&pf_info, en_dev->phy_port, 1);
			if (err)
				LOG_ERR(" set_tm_gate open failed\n");
		} else if (mode == 0) {
			err = dpp_tm_pport_mcode_switch_del(&pf_info, en_dev->phy_port);
			if (err)
				LOG_ERR(" set_tm_gate close failed\n");
		} else {
			LOG_ERR(" error\n");
		}
	}

	return err;
}

u32 zxdh_dcbnl_enable_debug(struct zxdh_en_priv *en_priv)
{
	u32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 dbg_status = 0;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	err = dpp_ppu_set_debug_mode(&pf_info, &dbg_status);
	if (err)
		LOG_ERR(" set debug mode enable failed\n");
	if (dbg_status == 0) {
		LOG_ERR("many packet into PPU!!!\n");
		return 0;
	}
	return err;
}
u32 zxdh_dcbnl_disable_debug(struct zxdh_en_priv *en_priv)
{
	u32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_en_device *en_dev = &en_priv->edev;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	err = dpp_ppu_close_debug_mode(&pf_info);
	if (err)
		LOG_ERR(" set debug mode disable failed\n");
	return err;
}
