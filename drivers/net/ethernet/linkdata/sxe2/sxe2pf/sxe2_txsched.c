// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_txsched.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2.h"
#include "sxe2_hw.h"
#include "sxe2_log.h"
#include "sxe2_vsi.h"
#include "sxe2_sriov.h"
#include "sxe2_txsched.h"
#include "sxe2_com_cdev.h"
#include "sxe2_cmd_channel.h"
#include "sxe2_spec.h"

#define SXE2_AA_MODE_QSET_NUM 16
#define SXE2_TXSCH_LAYER_BY_TEID_MASK 0x7
#define SXE2_TXSCH_VF_IDX_INVAL SXE2_VF_NUM
#define SXE2_TXSCHED_NODE_TEID_GET(x) ((x)->info.node_teid)

STATIC u32 node_adj_lvl = SXE2_TXSCH_NODE_ADJ_LVL_DFLT;
module_param(node_adj_lvl, uint, 0644);
MODULE_PARM_DESC(node_adj_lvl,
		 "txsch node adj lvl, 0:Physical, 1:Data Link 2:Network 3(Default):Transport");

static inline u8 sxe2_txsch_node_adj_lvl_get(void)
{
	return (u8)node_adj_lvl;
}

static inline u8 sxe2_txsch_teid2hwl(u16 teid)
{
	return (u8)teid & SXE2_TXSCH_LAYER_BY_TEID_MASK;
}

static inline struct sxe2_txsched_context *
sxe2_txsched_ctxt_get(struct sxe2_adapter *adapter)
{
	return &adapter->tx_sched_ctxt;
}

static inline u8 sxe2_txsched_layer_max_get(struct sxe2_txsched_context *ctxt)
{
	return ctxt->cap.generic.layer_max;
}

static inline u8 sxe2_txsched_sw_vsi_layer_get(void)
{
	return SXE2_TXSCHED_SW_VSI_LAYER;
}

static inline u8 sxe2_txsched_sw_qp_layer_get(void)
{
	return SXE2_TXSCHED_SW_QG_LAYER;
}

static u8 sxe2_txsched_sw_q_layer_get(void)
{
	return SXE2_TXSCHED_SW_Q_LAYER;
}

bool sxe2_txsch_is_vf_vsi_agg_mode(struct sxe2_adapter *adapter)
{
	return (sxe2_vf_num_get(adapter) <= SXE2_TXSCH_VF_VSIG_AGG_MAX) ? true : false;
}

static inline bool sxe2_txsch_is_vf_by_vsitype(enum sxe2_vsi_type vsi_type)
{
	if (vsi_type == SXE2_VSI_T_VF || vsi_type == SXE2_VSI_T_DPDK_VF)
		return true;
	else
		return false;
}

STATIC enum sxe2_txsch_vsi_type sxe2_txsch_vsi_type_get(struct sxe2_adapter *adapter,
							struct sxe2_vsi *vsi)
{
	if (!(vsi->type == SXE2_VSI_T_VF || vsi->type == SXE2_VSI_T_DPDK_VF))
		return (vsi->type == SXE2_VSI_T_DPDK_PF) ? OTHER_MODE_UVSI : OTHER_MODE_KVSI;

	if (sxe2_txsch_is_vf_vsi_agg_mode(adapter)) {
		return (vsi->type == SXE2_VSI_T_VF) ?
			FUSION_VF2VSIG_MODE_VF_KVSI : FUSION_VF2VSIG_MODE_VF_UVSI;
	} else {
		return (vsi->type == SXE2_VSI_T_VF) ?
			FUSION_VF2VSI_NODE_VF_KVSI : FUSION_VF2VSI_MODE_VF_UVSI;
	}

	return OTHER_MODE_UNKNOWN;
}

struct sxe2_txsched_node *
sxe2_txsched_find_node_by_teid(struct sxe2_txsched_node *start_node, u16 teid)
{
	u16 i;
	struct sxe2_txsched_node *node;

	if (!start_node)
		return NULL;

	if (SXE2_TXSCHED_NODE_TEID_GET(start_node) == teid) {
		node = start_node;
		goto l_end;
	}

	if (!start_node->child_cnt ||
	    start_node->info.data.hw_layer >= SXE2_TXSCHED_LAYER_MAX) {
		node = NULL;
		goto l_end;
	}

	for (i = 0; i < start_node->child_cnt; i++) {
		if (SXE2_TXSCHED_NODE_TEID_GET(start_node->child[i]) == teid) {
			node = start_node->child[i];
			goto l_end;
		}
	}

	for (i = 0; i < start_node->child_cnt; i++) {
		node = sxe2_txsched_find_node_by_teid(start_node->child[i], teid);
		if (node)
			break;
	}

l_end:
	return node;
}

STATIC struct sxe2_vsi_txsched_queue *
sxe2_txsched_q_ctxt_get(struct sxe2_vsi *vsi, u8 tc, u16 q_idx_in_vsi)
{
	u32 idx = (u32)(q_idx_in_vsi - vsi->tc.info[tc].txq_offset);

	return &vsi->txsched.q[tc][idx];
}

static inline void sxe2_txsched_q_ctxt_dflt_bw_cfg(struct sxe2_vsi *vsi, u8 tc,
						   u16 q_idx_in_tc)
{
	struct sxe2_vsi_txsched_queue *q_ctxt;

	q_ctxt			= &vsi->txsched.q[tc][q_idx_in_tc];
	q_ctxt->bw_info.rl_type = SXE2_NODE_RL_TYPE_EIR;
	q_ctxt->bw_info.pir_bw	= SXE2_TXSCHED_DFLT_BW;
	q_ctxt->bw_info.cir_bw	= SXE2_TXSCHED_DFLT_BW;
}

void sxe2_txsched_vsi_q_ctxt_free(struct sxe2_vsi *vsi)
{
	u8 i;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (!sxe2_txsched_support_chk(adapter))
		return;

	if (vsi->type == SXE2_VSI_T_DPDK_PF || vsi->type == SXE2_VSI_T_DPDK_VF)
		return;

	sxe2_for_each_tc(i) {
		if (vsi->txsched.q[i]) {
			devm_kfree(&vsi->adapter->pdev->dev, vsi->txsched.q[i]);
			vsi->txsched.q[i] = NULL;
		}
	}

	LOG_INFO_BDF("txsched vsi[%d] txq ctxt free success\n", vsi->idx_in_dev);
}

STATIC s32 sxe2_txsched_vsi_q_ctxt_alloc(struct sxe2_vsi *vsi, u8 tc,
					 u16 q_cnt)
{
	u16 i;
	u16 prev_num;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev	     = &adapter->pdev->dev;
	struct sxe2_vsi_txsched_queue *q_ctxt;

	if (!vsi->txsched.q[tc]) {
		vsi->txsched.q[tc] = devm_kcalloc(dev, q_cnt, sizeof(*q_ctxt), GFP_KERNEL);
		if (!vsi->txsched.q[tc]) {
			LOG_ERROR_BDF("txsche vsi queue ctxt alloc failed\n");
			return -ENOMEM;
		}

		vsi->txsched.q_cnt[tc] = q_cnt;

		for (i = 0; i < q_cnt; i++)
			sxe2_txsched_q_ctxt_dflt_bw_cfg(vsi, tc, i);

		LOG_INFO_BDF("txsched vsi[%d] tc[%d] txq ctxt alloc success\n",
			     vsi->idx_in_dev, tc);

	} else if (q_cnt > vsi->txsched.q_cnt[tc]) {
		prev_num = vsi->txsched.q_cnt[tc];

		q_ctxt = devm_kcalloc(dev, q_cnt, sizeof(*q_ctxt), GFP_KERNEL);
		if (!q_ctxt) {
			LOG_ERROR_BDF("txsche vsi queue ctxt alloc failed\n");
			return -ENOMEM;
		}

		(void)memcpy(q_ctxt, vsi->txsched.q[tc], (prev_num * sizeof(*q_ctxt)));
		devm_kfree(dev, vsi->txsched.q[tc]);
		vsi->txsched.q[tc]     = q_ctxt;
		vsi->txsched.q_cnt[tc] = q_cnt;

		for (i = prev_num; i < q_cnt; i++)
			sxe2_txsched_q_ctxt_dflt_bw_cfg(vsi, tc, i);

		LOG_INFO_BDF("txsched vsi[%d] tc[%d] txq ctxt extend success\n",
			     vsi->idx_in_dev, tc);
	}

	return 0;
}

static inline void
sxe2_txsched_node_rl_info_get(struct sxe2_txsched_node *node, u8 rl_type,
			      struct scbge_txsched_node_bw *rl)
{
	switch (rl_type) {
	case SXE2_NODE_RL_TYPE_CIR:
		rl->bw	    = node->info.data.cir.bw;
		rl->prof_id = node->info.data.cir.prof_id;
		break;

	case SXE2_NODE_RL_TYPE_EIR:
	case SXE2_NODE_RL_TYPE_SRL:
		rl->bw	    = node->info.data.srlPir.bw;
		rl->prof_id = node->info.data.srlPir.prof_id;
		break;
	default:
		rl->bw	    = SXE2_TXSCHED_DFLT_BW;
		rl->prof_id = SXE2_TXSCHED_DFLT_RL_PROF_ID;
		break;
	}
}

static inline void sxe2_txsched_node_rl_record(struct sxe2_vsi *vsi,
					       struct sxe2_txsched_node *node,
					       u8 rl_type, u32 bw,
					       u32 prof_idx)
{
	struct sxe2_vsi_txsched_queue *q_ctxt;
	u8 q_sw_layer = sxe2_txsched_sw_q_layer_get();

	node->info.data.rl_type |= rl_type;

	switch (rl_type) {
	case SXE2_NODE_RL_TYPE_CIR:
		node->info.data.cir.bw	    = bw;
		node->info.data.cir.prof_id = prof_idx;
		break;

	case SXE2_NODE_RL_TYPE_EIR:
	case SXE2_NODE_RL_TYPE_SRL:
		node->info.data.srlPir.bw      = bw;
		node->info.data.srlPir.prof_id = prof_idx;
		break;
	}

	if (vsi->type == SXE2_VSI_T_DPDK_PF || vsi->type == SXE2_VSI_T_DPDK_VF)
		return;

	if (node->info.data.hw_layer == (q_sw_layer + 1)) {
		q_ctxt = sxe2_txsched_q_ctxt_get(vsi, node->tc,
						 node->txq_idx_in_vsi);

		q_ctxt->bw_info.rl_type = rl_type;
		q_ctxt->teid		= node->info.node_teid;
		q_ctxt->idx_in_dev	= node->txq_idx_in_dev;
		switch (rl_type) {
		case SXE2_NODE_RL_TYPE_CIR:
			q_ctxt->bw_info.cir_bw = bw;
			break;

		case SXE2_NODE_RL_TYPE_EIR:
		case SXE2_NODE_RL_TYPE_SRL:
			q_ctxt->bw_info.pir_bw = bw;
			break;
		}
	}
}

s32 sxe2_txsched_node_bw_lmt_cfg(struct sxe2_vsi *vsi,
				 struct sxe2_txsched_node *node, u8 rl_type,
				 u32 bw)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};
	struct scbge_txsched_node_bw orig_rl;
	struct sxe2_txsched_cfg_node_rl_req req;
	struct sxe2_txsched_cfg_node_rl_resp resp;
	struct sxe2_adapter *adapter = vsi->adapter;

	sxe2_txsched_node_rl_info_get(node, rl_type, &orig_rl);
	if (orig_rl.bw == bw) {
		LOG_INFO_BDF("txsched bw==node bw not modify, \t"
			     "teid=%#x, rl_type=%#x, bw=%u\n",
			     node->info.node_teid, rl_type, bw);
	}

	req.orig_prof_id = (u16)orig_rl.prof_id;
	req.bw		 = bw;
	req.hw_layer	 = node->info.data.hw_layer;
	req.prof_type	 = rl_type;
	req.teid	 = node->info.node_teid;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TX_SCHED_NODE_RL_CFG, &req,
				  sizeof(req), &resp, sizeof(resp));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("txsched node rl cfg failed, \t"
			      "node_teid=%#x, layer=%u, \t"
			      "bw=%u, orig_prof_idx=%u, orig_bw=%u, \t"
			      "ret=%d\n",
			      req.teid, req.hw_layer, bw, orig_rl.prof_id,
			      orig_rl.bw, ret);
		return -EIO;
	}

	sxe2_txsched_node_rl_record(vsi, node, rl_type, bw, resp.prof_id);

	LOG_INFO_BDF("txsched node rl cfg success, \t"
		     "node_teid=%#x, layer=%u, \t"
		     "rl_type=%x, orig_prof_idx=%u, orig_bw=%u, \t"
		     "bw=%u, prof_idx=%u\n",
		     req.teid, req.hw_layer, rl_type, orig_rl.prof_id,
		     orig_rl.bw, bw, resp.prof_id);

	return 0;
}

STATIC s32 sxe2_txsche_replay_node_bw(struct sxe2_vsi *vsi,
				      struct sxe2_txsched_node *node,
				      struct sxe2_txsched_q_bw_info *bw_info)
{
	s32 ret = 0;

	if (bw_info->rl_type == SXE2_NODE_RL_TYPE_CIR &&
	    bw_info->cir_bw != node->info.data.cir.bw) {
		ret = sxe2_txsched_node_bw_lmt_cfg(vsi, node, SXE2_NODE_RL_TYPE_CIR,
						   bw_info->cir_bw);

		if (ret)
			goto l_err;
	}

	if (bw_info->rl_type == SXE2_NODE_RL_TYPE_EIR &&
	    bw_info->pir_bw != node->info.data.srlPir.bw) {
		ret = sxe2_txsched_node_bw_lmt_cfg(vsi, node,
						   SXE2_NODE_RL_TYPE_EIR, bw_info->pir_bw);
		if (ret)
			goto l_err;
	}

l_err:
	return ret;
}

STATIC s32 sxe2_txsched_replay_q_bw(struct sxe2_vsi *vsi,
				    struct sxe2_vsi_txsched_queue *q_ctxt)
{
	s32 ret;
	struct sxe2_txsched_node *node;
	struct sxe2_txsched_context *sched_ctxt = &vsi->adapter->tx_sched_ctxt;

	node = sxe2_txsched_find_node_by_teid(sched_ctxt->root, (u16)q_ctxt->teid);
	if (!node)
		return -EINVAL;

	ret = sxe2_txsche_replay_node_bw(vsi, node, &q_ctxt->bw_info);

	return ret;
}

s32 sxe2_txsched_q_bw_lmt_cfg(struct sxe2_vsi *vsi, struct sxe2_queue *txq,
			      u8 rl_type, u32 bw)
{
	s32 ret;
	struct sxe2_txsched_node *node;
	struct sxe2_adapter *adapter		= vsi->adapter;
	struct sxe2_txsched_context *sched_ctxt = &adapter->tx_sched_ctxt;

	if (!sxe2_txsched_support_chk(adapter))
		return -EOPNOTSUPP;

	mutex_lock(&sched_ctxt->lock);

	node = sxe2_txsched_find_node_by_teid(sched_ctxt->root, txq->txq_teid);
	if (!node) {
		LOG_ERROR_BDF("txsched txq leaf node get failed, \t"
			     "node_teid=%#x, txq_idx=%u, bw=%u\n",
			     txq->txq_teid, txq->idx_in_vsi, bw);
		ret = -ENXIO;
		goto l_unlock;
	}

	ret = sxe2_txsched_node_bw_lmt_cfg(vsi, node, rl_type, bw);

l_unlock:
	mutex_unlock(&sched_ctxt->lock);
	return ret;
}

STATIC enum sxe2_node_type
sxe2_txsched_veb_node_type_get(enum sxe2_vsi_type vsi_type)
{
	enum sxe2_node_type node_type = SXE2_TXSCHD_NODE_TYPE_UNKNOWN;

	if (vsi_type == SXE2_VSI_T_PF ||
	    vsi_type == SXE2_VSI_T_LB ||
	    vsi_type == SXE2_VSI_T_CTRL ||
	    vsi_type == SXE2_VSI_T_DPDK_PF)
		node_type = SXE2_TXSCHD_VEB_TYPE_PF;

	else if (vsi_type == SXE2_VSI_T_VF ||
		 vsi_type == SXE2_VSI_T_DPDK_VF)
		node_type = SXE2_TXSCHD_VEB_TYPE_VF;

	else if (vsi_type == SXE2_VSI_T_MACVLAN ||
		 vsi_type == SXE2_VSI_T_ESW)
		node_type = SXE2_TXSCHD_VEB_TYPE_MACVLAN_ESW;

	return node_type;
}

STATIC enum sxe2_node_type
sxe2_txsched_vsi_node_type_get(enum sxe2_vsi_type vsi_type, u8 owner)
{
	enum sxe2_node_type node_type = SXE2_TXSCHD_NODE_TYPE_UNKNOWN;

		switch (vsi_type) {
		case SXE2_VSI_T_PF:
			if (owner == SXE2_TXSCHED_NODE_OWNER_LAN)
				node_type = SXE2_TXSCHD_VSI_TYPE_PF;
			else if (owner == SXE2_TXSCHED_NODE_OWNER_RDMA)
				node_type = SXE2_TXSCHD_VSI_TYPE_PF_RDMA;
			break;
		case SXE2_VSI_T_LB:
			node_type = SXE2_TXSCHD_VSI_TYPE_PF_LOOPBACK;
			break;
		case SXE2_VSI_T_CTRL:
			node_type = SXE2_TXSCHD_VSI_TYPE_PF_CTRL;
			break;
		case SXE2_VSI_T_VF:
			node_type = SXE2_TXSCHD_VSI_TYPE_VF;
			break;
		case SXE2_VSI_T_MACVLAN:
		case SXE2_VSI_T_ESW:
			node_type = SXE2_TXSCHD_VSI_TYPE_MACVLAN_ESW;
			break;
		case SXE2_VSI_T_DPDK_PF:
			node_type = SXE2_TXSCHD_VSI_TYPE_USER_PF;
			break;
		case SXE2_VSI_T_DPDK_VF:
			node_type = SXE2_TXSCHD_VSI_TYPE_USER_VF;
			break;
		default:
			node_type = SXE2_TXSCHD_NODE_TYPE_UNKNOWN;
	}

	return node_type;
}

STATIC s32 sxe2_txsched_node_info_query(struct sxe2_adapter *adapter,
					struct sxe2_txsched_node_param *param,
					struct sxe2_txsched_node_info *node_info)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_txsched_query_node_req req;

	req.node_teid	= param->node_teid;
	req.parent_teid = param->parent_teid;
	req.sibling_idx = param->node_silbing_idx;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TX_SCHED_NODE_INFO_QUERY,
				  &req, sizeof(req), node_info,
				  sizeof(*node_info));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("sched node query failed, \t"
			      "teid=%#x, parent_teid=%#x, sibling_idx=%d, ret=%d\n",
			      param->node_teid, param->parent_teid,
			      param->node_silbing_idx, ret);
	}

	return ret;
}

static s32 sxe2_txsched_sw_node_add(struct sxe2_adapter *adapter,
				    struct sxe2_txsched_node_param *param)
{
	s32 ret;
	struct sxe2_txsched_node *node;
	struct sxe2_txsched_node *parent;
	struct sxe2_txsched_node_info node_info;
	struct device *dev		  = &adapter->pdev->dev;
	struct sxe2_txsched_context *ctxt = sxe2_txsched_ctxt_get(adapter);

	parent = sxe2_txsched_find_node_by_teid(ctxt->root, param->parent_teid);
	if (!parent) {
		LOG_ERROR_BDF("parent node not found, parent_teid=0x%x\n",
			      param->parent_teid);
		return -EINVAL;
	}

	if (parent->child_cnt >= SXE2_TXSCHED_NODE_CHILD_MAX) {
		LOG_ERROR_BDF("the number of child nodes ara full, parent_teid=%#x\n",
			      parent->info.node_teid);
		return -EINVAL;
	}

	ret = sxe2_txsched_node_info_query(adapter, param, &node_info);
	if (ret)
		return ret;

	node = devm_kzalloc(dev, sizeof(*node), GFP_KERNEL);
	if (!node) {
		LOG_ERROR_BDF("alloc sw node failed, teid=0x%x\n",
			      node_info.node_teid);
		return -ENOMEM;
	}

	node->child = devm_kcalloc(dev, SXE2_TXSCHED_NODE_CHILD_MAX,
				   sizeof(*node->child), GFP_KERNEL);
	if (!node->child) {
		LOG_ERROR_BDF("alloc child array of sw node failed, teid=0x%x\n",
			      node_info.node_teid);
		devm_kfree(dev, node);
		return -ENOMEM;
	}

	if (param->sw_layer == sxe2_txsched_sw_q_layer_get()) {
		node->txq_idx_in_dev = param->txq_idx_in_dev;
		node->txq_idx_in_vsi = param->txq_idx_in_vsi;
	}

	if (param->sw_layer > sxe2_txsched_sw_vsi_layer_get())
		node->vsi_idx_in_dev = param->vsi_idx_in_dev;

	node->in_use			   = true;
	node->tc			   = (u8)param->tc;
	node->parent			   = parent;
	node->info			   = node_info;
	node->owner			   = (u8)param->owner;
	parent->child[parent->child_cnt++] = node;

	LOG_DEBUG_BDF("tx sched create node success, \t"
		      "teid=%#x, parentTied=%#x, childIdx=%d, child_cnt=%u, addr=%p\n",
		      node->info.node_teid, node->info.parent_teid,
		      node->info.sibling_idx, parent->child_cnt, (void *)parent);

	return 0;
}

static s32 sxe2_txsched_root_node_add(struct sxe2_adapter *adapter,
				      struct sxe2_txsched_node_info *root_info)
{
	struct sxe2_txsched_node *root;
	struct device *dev = &adapter->pdev->dev;

	root = devm_kzalloc(dev, sizeof(*root), GFP_KERNEL);
	if (!root) {
		LOG_DEV_ERR("sched alloc root node failed\n");
		return -ENOMEM;
	}

	root->child = devm_kcalloc(dev, SXE2_TXSCHED_NODE_CHILD_MAX,
				   sizeof(*root->child), GFP_KERNEL);
	if (!root->child) {
		LOG_DEV_ERR("sched alloc for child array of root node failed\n");
		devm_kfree(dev, root);
		return -ENOMEM;
	}

	(void)memcpy(&root->info, root_info, sizeof(*root_info));
	adapter->tx_sched_ctxt.root = root;

	return 0;
}

static void sxe2_txsched_root_node_del(struct sxe2_adapter *adapter)
{
	struct sxe2_txsched_node *root = adapter->tx_sched_ctxt.root;
	struct device *dev	       = &adapter->pdev->dev;

	if (root) {
		if (root->child) {
			devm_kfree(dev, root->child);
			adapter->tx_sched_ctxt.root->child = NULL;
		}
		devm_kfree(dev, root);
		adapter->tx_sched_ctxt.root = NULL;
	}
}

s32 sxe2_txsched_dflt_tc_node_add(struct sxe2_adapter *adapter,
				  struct sxe2_txsched_node_info *tc0_info)
{
	struct sxe2_txsched_node *node;
	struct device *dev	       = &adapter->pdev->dev;
	struct sxe2_txsched_node *root = adapter->tx_sched_ctxt.root;

	node = devm_kzalloc(dev, sizeof(*node), GFP_KERNEL);
	if (!node) {
		LOG_ERROR_BDF("alloc tc0 node failed, teid=0x%x\n",
			      tc0_info->node_teid);
		return -ENOMEM;
	}

	node->child = devm_kcalloc(dev, SXE2_TXSCHED_NODE_CHILD_MAX,
				   sizeof(*node->child), GFP_KERNEL);
	if (!node->child) {
		LOG_ERROR_BDF("alloc child array of tc0 node failed, teid=0x%x\n",
			      tc0_info->node_teid);
		devm_kfree(dev, node);
		return -ENOMEM;
	}

	node->in_use		       = true;
	node->parent		       = root;
	node->tc		       = 0;
	node->info		       = *tc0_info;
	root->child[root->child_cnt++] = node;

	return 0;
}

STATIC void sxe2_txsched_dflt_tc_node_del(struct sxe2_adapter *adapter)
{
	struct sxe2_txsched_node *root = adapter->tx_sched_ctxt.root;
	struct device *dev	       = &adapter->pdev->dev;

	if (root && root->child) {
		if (root->child[0]) {
			if (root->child[0]->child) {
				devm_kfree(dev, root->child[0]->child);
				root->child[0]->child = NULL;
			}
			devm_kfree(dev, root->child[0]);
			root->child[0] = NULL;
		}
	}
}

bool sxe2_txsched_support_chk(struct sxe2_adapter *adapter)
{
	if (adapter->tx_sched_ctxt.cap.generic.layer_max)
		return true;
	else
		return false;
}

static s32 sxe2_fwc_txsched_cap_get(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd	      = {};
	struct sxe2_fwc_txsched_cap_resp *cap = &adapter->tx_sched_ctxt.cap;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TXSCHED_CAP_QUERY, NULL, 0,
				  cap, sizeof(*cap));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_INFO_BDF("sched cap get failed, ret=%d\n", ret);
	else
		LOG_INFO_BDF("sched cap get success: max_hw_layer=%d\n", cap->generic.layer_max);

	return ret;
}

static inline void
sxe2_tx_sched_res_init(struct sxe2_txsched_context *sched_ctxt)
{
	sched_ctxt->user_root_teid = SXE2_TXSCHED_TEID_INVALID;
	mutex_init(&sched_ctxt->lock);
}

static inline void
sxe2_tx_sched_res_deinit(struct sxe2_txsched_context *sched_ctxt)
{
	(void)mutex_destroy(&sched_ctxt->lock);
}

STATIC s32 sxe2_txsched_hw_dflt_topo_get(struct sxe2_adapter *adapter,
					 struct sxe2_fwc_txsched_dflt_topo_resp *dflt_topo)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TXSCHED_DFLT_TOPO_QUERY, NULL,
				  0, dflt_topo, sizeof(*dflt_topo));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("tx sched dflt topo get failed, ret=%d\n", ret);

	return ret;
}

s32 sxe2_txsched_dflt_topo_init(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct device *dev = &adapter->pdev->dev;
	struct sxe2_fwc_txsched_dflt_topo_resp *dflt_topo;
	struct sxe2_txsched_context *sched_ctxt = &adapter->tx_sched_ctxt;

	if (!sxe2_txsched_support_chk(adapter))
		return 0;

	dflt_topo = devm_kzalloc(dev, sizeof(*dflt_topo), GFP_KERNEL);
	if (!dflt_topo) {
		LOG_DEV_ERR("sched dflt topo init: alloc failed\n");
		return -ENOMEM;
	}

	mutex_lock(&sched_ctxt->lock);
	ret = sxe2_txsched_hw_dflt_topo_get(adapter, dflt_topo);
	if (ret) {
		LOG_DEV_ERR("sxe2_txsched_hw_dflt_topo_get: failed, ret:%d\n", ret);
		goto l_free_topo;
	}

	ret = sxe2_txsched_root_node_add(adapter,
					 &dflt_topo->node_info[SXE2_TXSCHED_SW_PORT_LAYER]);
	if (ret)
		goto l_free_topo;

	ret = sxe2_txsched_dflt_tc_node_add(adapter,
					    &dflt_topo->node_info[SXE2_TXSCHED_SW_TC_LAYER]);
	if (ret) {
		LOG_DEV_ERR("sxe2_txsched_dflt_tc_node_add: failed, ret:%d\n", ret);
		goto l_free_root;
	}

	LOG_DEV_INFO("tx sched dflt topo init success, port_teid=%#x, tc_teid=%#x ret:%d\n",
		     dflt_topo->node_info[SXE2_TXSCHED_SW_PORT_LAYER].node_teid,
		     dflt_topo->node_info[SXE2_TXSCHED_SW_TC_LAYER].node_teid, ret);

	sched_ctxt->state = SXE2_TX_SCHED_STATE_READY;
	goto l_free_topo;

l_free_root:
	sxe2_txsched_root_node_del(adapter);

l_free_topo:
	mutex_unlock(&sched_ctxt->lock);
	devm_kfree(dev, dflt_topo);
	LOG_DEV_INFO("sxe2 txsched dflt topo init ret:%d\n", ret);
	return ret;
}

void sxe2_txsched_dflt_topo_deinit(struct sxe2_adapter *adapter)
{
	if (!sxe2_txsched_support_chk(adapter))
		return;

	sxe2_txsched_dflt_tc_node_del(adapter);
	sxe2_txsched_root_node_del(adapter);
}

STATIC s32 sxe2_tx_sched_hw_node_del(struct sxe2_adapter *adapter,
				     u16 parent_teid, u16 start_child_idx,
				     u16 node_num, u16 node_teid[])
{
	s32 ret;
	u32 i, req_size;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_txsched_del_nodes_req *req;
	struct device *dev = &adapter->pdev->dev;

	req_size = struct_size(req, teid, node_num);
	req	 = devm_kzalloc(dev, req_size, GFP_KERNEL);
	if (!req) {
		LOG_ERROR_BDF("sched node del: alloc failed\n");
		ret = -ENOMEM;
		goto l_end;
	}

	req->hdr.parent_teid	 = cpu_to_le16(parent_teid);
	req->hdr.start_child_idx = cpu_to_le16(start_child_idx);
	req->hdr.node_num	 = cpu_to_le16(node_num);
	for (i = 0; i < node_num; i++)
		req->teid[i] = cpu_to_le16(node_teid[i]);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TX_SCHED_NODE_DEL, req,
				  req_size, NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("tx sched node del failed, ret=%d\n", ret);

l_end:
	devm_kfree(dev, req);
	return ret;
}

STATIC s32 sxe2_tx_sched_hw_lan_leaf_node_del(struct sxe2_adapter *adapter,
					      u16 parent_teid, u16 sibling_idx,
					      u16 node_teid,
					      u16 txq_idx_in_dev)
{
	s32 ret, req_size;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_txsched_del_leaf_req *req;
	struct device *dev = &adapter->pdev->dev;

	req_size = sizeof(struct sxe2_txsched_del_leaf_req);
	req	 = devm_kzalloc(dev, (u32)req_size, GFP_KERNEL);
	if (!req) {
		LOG_ERROR_BDF("sched node del: alloc failed\n");
		ret = -ENOMEM;
		goto l_end;
	}

	LOG_INFO_BDF("parent_teid=%#x, sibling_idx=%d node=%#x idx=%#x\n",
		     parent_teid, sibling_idx, node_teid, txq_idx_in_dev);

	req->parent_teid    = cpu_to_le16(parent_teid);
	req->sibling_idx    = cpu_to_le16(sibling_idx);
	req->node_teid	    = cpu_to_le16(node_teid);
	req->txq_idx_in_dev = cpu_to_le16(txq_idx_in_dev);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TX_SCHED_QUEUE_LEAF_DEL, req,
				  (u32)req_size, NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("tx sched node del failed, ret=%d\n", ret);

l_end:
	devm_kfree(dev, req);
	return ret;
}

static inline struct sxe2_txsched_node *
sxe2_txsched_first_node_get(struct sxe2_txsched_context *sched_ctxt, u8 tc,
			    u8 sw_layer)
{
	if (tc < SXE2_MAX_TRAFFIC_CLASS && sw_layer < SXE2_TXSCHED_LAYER_MAX)
		return sched_ctxt->sib_head[tc][sw_layer];
	else
		return NULL;
}

STATIC void sxe2_txsched_sw_node_del(struct sxe2_adapter *adapter,
				     struct sxe2_txsched_node *node)
{
	u32 i, j;
	struct sxe2_txsched_node *parent;
	struct sxe2_txsched_node *node_list;
	struct device *dev = &adapter->pdev->dev;
	u8 sw_layer	   = node->info.data.hw_layer - 1;
	struct sxe2_txsched_context *sched_ctxt = sxe2_txsched_ctxt_get(adapter);

	parent = node->parent;
	if (parent) {
		for (i = 0; i < parent->child_cnt; i++) {
			if (parent->child[i] == node) {
				if ((i + 1) == parent->child_cnt) {
					parent->child[i] = NULL;
				} else {
					for (j = i + 1; j < parent->child_cnt; j++)
						parent->child[j - 1] = parent->child[j];
				}

				parent->child_cnt--;
				break;
			}
		}

		node_list = sxe2_txsched_first_node_get(sched_ctxt, node->tc,
							sw_layer);
		if (node_list == node) {
			sched_ctxt->sib_head[node->tc][sw_layer] = node->sibling;
		} else {
			while (node_list) {
				if (node_list->sibling == node) {
					node_list->sibling = node->sibling;
					break;
				}

				node_list = node_list->sibling;
			}
		}
	}

	if (node->child)
		devm_kfree(dev, node->child);

	devm_kfree(dev, node);
}

STATIC s32 sxe2_txsched_subtree_clean(struct sxe2_adapter *adapter,
				      struct sxe2_txsched_node *node)
{
	s32 ret = 0;
	u8 q_layer = sxe2_txsched_sw_q_layer_get();

	if (!node)
		return 0;

	while (node->child_cnt) {
		ret = sxe2_txsched_subtree_clean(adapter, node->child[0]);
		if (ret) {
			LOG_ERROR_BDF("sched hw node del(child) failed, teid=%#x, \t"
				      "parent_teid=%#x, sibling_idx=%d\n",
				      node->child[0]->info.node_teid,
				      node->child[0]->parent->info.node_teid,
				      node->child[0]->info.sibling_idx);
			ret = 0;
			goto l_end;
		}
	}

	if (node->info.data.hw_layer != (q_layer + 1) &&
	    node->info.data.hw_layer > SXE2_TXSCHED_HW_LAYER_TC) {
		ret = sxe2_tx_sched_hw_node_del(adapter,
						node->parent->info.node_teid,
						(u16)node->info.sibling_idx, 1,
						&node->info.node_teid);
		if (ret) {
			LOG_ERROR_BDF("sched hw node del failed, teid=%#x, \t"
				      "parent_teid=%#x, sibling_idx=%d\n",
				      node->info.node_teid,
				      node->parent->info.node_teid,
				      node->info.sibling_idx);
			ret = 0;
		}
	}

l_end:
	sxe2_txsched_sw_node_del(adapter, node);
	return ret;
}

STATIC s32 sxe2_txsched_node_del(struct sxe2_adapter *adapter,
				 struct sxe2_txsched_node *node,
				 u16 not_del_root_teid,
				 u8 owner)
{
	u8 i = 0;
	s32 ret = 0;
	u8 q_layer = sxe2_txsched_sw_q_layer_get();

	if (!node)
		return 0;

	i = node->child_cnt;
	while (i) {
		--i;
		ret = sxe2_txsched_node_del(adapter, node->child[i],
					    not_del_root_teid, owner);
		if (ret) {
			LOG_ERROR_BDF("sched hw node del(child) failed, teid=%#x, \t"
				      "parent_teid=%#x, sibling_idx=%d\n",
				      node->child[i]->info.node_teid,
				      node->child[i]->parent->info.node_teid,
				      node->child[i]->info.sibling_idx);
			ret = 0;
			goto l_end;
		}
	}

	if (node->info.data.hw_layer != (q_layer + 1) &&
	    node->info.data.hw_layer > SXE2_TXSCHED_HW_LAYER_TC &&
	    node->owner == owner &&
	    node->info.node_teid != not_del_root_teid) {
		ret = sxe2_tx_sched_hw_node_del(adapter,
						node->parent->info.node_teid,
						(u16)node->info.sibling_idx, 1,
						&node->info.node_teid);
		if (ret) {
			LOG_ERROR_BDF("sched hw node del failed, teid=%#x, \t"
				      "parent_teid=%#x, sibling_idx=%d\n",
				      node->info.node_teid,
				      node->parent->info.node_teid,
				      node->info.sibling_idx);
			ret = 0;
		} else {
			sxe2_txsched_sw_node_del(adapter, node);
		}
	}

l_end:
	return ret;
}

s32 sxe2_txsched_init(struct sxe2_adapter *adapter)
{
	s32 ret;

	ret = sxe2_fwc_txsched_cap_get(adapter);
	if (ret)
		goto l_err;

	if (!sxe2_txsched_support_chk(adapter))
		goto l_err;

	sxe2_tx_sched_res_init(&adapter->tx_sched_ctxt);

	ret = sxe2_txsched_dflt_topo_init(adapter);
	if (ret) {
		sxe2_tx_sched_res_deinit(&adapter->tx_sched_ctxt);
		goto l_err;
	}

	LOG_INFO_BDF("tx sched init success\n");
l_err:
	return ret;
}

void sxe2_txsched_deinit(struct sxe2_adapter *adapter)
{
	if (!sxe2_txsched_support_chk(adapter))
		return;

	sxe2_txsched_dflt_topo_deinit(adapter);

	sxe2_tx_sched_res_deinit(&adapter->tx_sched_ctxt);
}

STATIC struct sxe2_txsched_node *
sxe2_txsched_tc_node_get(struct sxe2_txsched_context *ctxt, u8 tc)
{
	u8 i;
	struct sxe2_txsched_node *node = NULL;

	if (!ctxt->root)
		return node;

	for (i = 0; i < ctxt->root->child_cnt; i++) {
		if (ctxt->root->child[i]->tc == tc) {
			node = ctxt->root->child[i];
			break;
		}
	}

	return node;
}

struct sxe2_txsched_node *
sxe2_txsched_vsi_first_node_get(struct sxe2_txsched_context *ctxt, u8 tc,
				u16 vsi_idx, u8 owner)
{
	u8 sw_layer;
	struct sxe2_txsched_node *node;

	sw_layer = sxe2_txsched_sw_vsi_layer_get();
	if (!sw_layer)
		return NULL;

	node = sxe2_txsched_first_node_get(ctxt, tc, sw_layer);

	while (node) {
		if (node->vsi_idx_in_dev == vsi_idx && node->owner == owner)
			return node;
		node = node->sibling;
	}

	return NULL;
}

STATIC struct sxe2_txsched_node *
sxe2_txsch_vsi_node_get(struct sxe2_adapter *adapter,
			struct sxe2_vsi *vsi, u8 tc, u8 owner)
{
	if (tc != 0 && vsi->type != SXE2_VSI_T_PF) {
		LOG_ERROR_BDF("vsi node get failed, vsi_idx=%d, vsi_type=%u, tc=%d, owner=%d\n",
			      vsi->idx_in_dev, vsi->type, tc, owner);
		return NULL;
	}

	if (vsi->type == SXE2_VSI_T_DPDK_VF &&
	    !sxe2_txsch_is_vf_vsi_agg_mode(adapter)) {
		if (vsi->txsched.node)
			return vsi->txsched.node;
		else if (vsi->vf_node->vsi)
			return vsi->vf_node->vsi->txsched.node;
		else
			return NULL;
	}

	return sxe2_txsched_vsi_first_node_get(&adapter->tx_sched_ctxt,
					       tc, vsi->idx_in_dev, owner);
}

static struct sxe2_txsched_node *
sxe2_txsch_qg_head_node_get(struct sxe2_txsched_node *vsi_node, u8 owner)
{
	u32 i;

	while (vsi_node) {
		for (i = 0; i < SXE2_TXSCHED_NODE_CHILD_MAX; i++) {
			if (!(vsi_node->child[i]))
				continue;

			if (owner == vsi_node->child[i]->owner)
				return vsi_node->child[i];
		}

		vsi_node = vsi_node->group;
	}

	return NULL;
}

static struct sxe2_txsched_node *
sxe2_txsch_qg_tail_node_get(struct sxe2_txsched_node *vsi_node, u8 owner)
{
	struct sxe2_txsched_node *node;
	struct sxe2_txsched_node *tail = NULL;

	node = sxe2_txsch_qg_head_node_get(vsi_node, owner);
	if (!node)
		goto l_end;

	while (node) {
		tail = node;
		node = node->group;
	}

l_end:
	return tail;
}

static inline u32
sxe2_txsched_qg_num_get(struct sxe2_txsched_node *fist_vsi_node, u8 owner)
{
	u32 qg_cnt = 0;
	struct sxe2_txsched_node *qgrp_node;

	if (!fist_vsi_node)
		return 0;

	qgrp_node = sxe2_txsch_qg_head_node_get(fist_vsi_node, owner);
	if (!qgrp_node)
		return 0;

	while (qgrp_node) {
		qgrp_node = qgrp_node->group;
		qg_cnt++;
	}

	return qg_cnt;
}

static struct sxe2_txsched_node *
sxe2_txsch_first_vsig_lookup_by_type(struct sxe2_txsched_node *tc_node,
				     enum sxe2_node_type veb_node_type,
				     enum sxe2_node_type vsig_node_type)
{
	u8 i, j;
	struct sxe2_txsched_node *veb_node;

	for (i = 0; i < tc_node->child_cnt; i++) {
		veb_node = tc_node->child[i];
		if (veb_node->node_type == veb_node_type)
			for (j = 0; j < veb_node->child_cnt; j++)
				if (veb_node->child[j]->node_type == vsig_node_type)
					return veb_node->child[j];
	}

	return NULL;
}

s32 sxe2_txsched_tc_max_bw_lmt_cfg(struct sxe2_vsi *vsi, u8 tc, u32 max_tx_rate)
{
	s32 ret;
	struct sxe2_txsched_node *tc_node;
	struct sxe2_txsched_node *vsig_node;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_txsched_context *sched_ctxt = &adapter->tx_sched_ctxt;

	if (!sxe2_txsched_support_chk(adapter))
		return -EOPNOTSUPP;

	mutex_lock(&sched_ctxt->lock);
	tc_node = sxe2_txsched_tc_node_get(sched_ctxt, tc);
	if (!tc_node) {
		LOG_ERROR_BDF("txsched tc node get failed, tc_id=%u, max_tx_rate=%u\n",
			      tc, max_tx_rate);
		ret = -ENXIO;
		goto l_unlock;
	}

	vsig_node = sxe2_txsch_first_vsig_lookup_by_type(tc_node,
							 SXE2_TXSCHD_VEB_TYPE_PF,
							 SXE2_TXSCHD_VSIG_TYPE_PF_AGG);
	if (!vsig_node) {
		LOG_ERROR_BDF("txsched vsig node get failed, tc_id=%u, max_tx_rate=%u\n",
			      tc, max_tx_rate);
		ret = -ENXIO;
		goto l_unlock;
	}

	ret = sxe2_txsched_node_bw_lmt_cfg(vsi, vsig_node,
					   SXE2_NODE_RL_TYPE_EIR, max_tx_rate);
	if (ret) {
		LOG_ERROR_BDF("unable to set tc max rate, ret=%d, tc=%u, maxrate=%u\n",
			      ret, tc, max_tx_rate);
	}

l_unlock:
	mutex_unlock(&sched_ctxt->lock);
	return ret;
}

static bool sxe2_txsched_is_leaf_node_present(struct sxe2_txsched_node *node,
					      u8 q_layer)
{
	u8 i;

	for (i = 0; i < node->child_cnt; i++)
		if (sxe2_txsched_is_leaf_node_present(node->child[i], q_layer))
			return true;

	return (node->info.data.hw_layer == q_layer);
}

static bool sxe2_txsched_vsi_qset_left(struct sxe2_adapter *adapter, u8 tc,
				       u16 vsi_idx, u8 owner)
{
	struct sxe2_txsched_node *node;
	struct sxe2_txsched_node *vsi_node;
	struct sxe2_txsched_context *ctxt = &adapter->tx_sched_ctxt;
	u8 max_layer			  = sxe2_txsched_layer_max_get(ctxt);
	bool left = false;

	vsi_node = sxe2_txsched_vsi_first_node_get(ctxt, tc, vsi_idx, owner);
	if (!vsi_node)
		goto l_end;

	while (vsi_node) {
		node = vsi_node->group;
		if (sxe2_txsched_is_leaf_node_present(vsi_node, max_layer)) {
			left = true;
			LOG_INFO_BDF("sched VSI has leaf nodes in TC %d\n", tc);
			goto l_end;
		}
		vsi_node = node;
	}

l_end:
	return left;
}

bool sxe2_txsched_qset_left(struct sxe2_adapter *adapter, u16 vsi_idx)
{
	bool left = false;
	u8 tc;
	struct sxe2_txsched_node *tc_node;
	struct sxe2_txsched_context *ctxt = sxe2_txsched_ctxt_get(adapter);

	mutex_lock(&adapter->tx_sched_ctxt.lock);
	sxe2_for_each_tc(tc)
	{
		tc_node = sxe2_txsched_tc_node_get(ctxt, tc);
		if (!tc_node)
			continue;

		left = sxe2_txsched_vsi_qset_left(adapter, tc,
						  vsi_idx, SXE2_TXSCHED_NODE_OWNER_RDMA);
		if (left) {
			LOG_INFO_BDF("tc[%d] vsi node has left qset, left=%d\n", tc, left);
			break;
		}
	}
	mutex_unlock(&adapter->tx_sched_ctxt.lock);
	return left;
}

STATIC s32 sxe2_txsched_vsi_node_del(struct sxe2_adapter *adapter, u8 tc,
				     struct sxe2_vsi *vsi, u8 owner)
{
	struct sxe2_txsched_node *node;
	struct sxe2_txsched_node *vsi_node;
	struct sxe2_txsched_context *ctxt = &adapter->tx_sched_ctxt;
	u8 max_layer			  = sxe2_txsched_layer_max_get(ctxt);

	vsi_node = sxe2_txsch_vsi_node_get(adapter, vsi, tc, owner);
	if (!vsi_node) {
		LOG_WARN_BDF("txsch vsi node del failed, vsi_node=NULL, \t"
			     "vsi_type=%d, vsi_idx=%d, owner=%d\n",
			     vsi->type, vsi->idx_in_dev, owner);
		return 0;
	}

	if (sxe2_txsched_is_leaf_node_present(vsi_node, max_layer)) {
		LOG_ERROR_BDF("sched VSI has leaf nodes in TC %d\n", tc);
		return -EBUSY;
	}

	while (vsi_node) {
		node = vsi_node->group;
		(void)sxe2_txsched_node_del(adapter, vsi_node, SXE2_TXSCHED_TEID_INVALID, owner);
		vsi_node = node;
	}

	return 0;
}

STATIC s32 sxe2_txsched_del_vsi_node_for_each_tc(struct sxe2_adapter *adapter,
						 struct sxe2_vsi *vsi,
						 u8 owner)
{
	u8 tc;
	s32 ret = 0;
	struct sxe2_txsched_node *tc_node;
	struct sxe2_txsched_context *ctxt = sxe2_txsched_ctxt_get(adapter);

	sxe2_for_each_tc(tc)
	{
		tc_node = sxe2_txsched_tc_node_get(ctxt, tc);
		if (!tc_node)
			continue;

		ret = sxe2_txsched_vsi_node_del(adapter, tc, vsi, owner);
		if (ret) {
			LOG_ERROR_BDF("tc[%d] vsi node del failed, ret=%d\n", tc, ret);
			break;
		}
	}

	return ret;
}

static inline void
sxe2_txsched_vsi_layer_calc(u8 max_layer, u32 queue_num,
			    enum sxe2_vsi_type vsi_type, u8 owner,
			    struct sxe2_txsched_add_node_info *add_node_info)
{
	u32 num_node = 0;

	num_node = DIV_ROUND_UP(queue_num, (SXE2_TXSCHED_NODE_CHILD_MAX *
				SXE2_TXSCHED_NODE_CHILD_MAX));
	add_node_info->num  = (u8)num_node;
	add_node_info->type = sxe2_txsched_vsi_node_type_get(vsi_type, owner);
	add_node_info->node = NULL;
}

static struct sxe2_txsched_node *
sxe2_txsched_enough_slot_node_lookup(struct sxe2_txsched_context *sched_ctxt,
				     u8 tc, u8 sw_layer, u8 need_slot_num,
				     enum sxe2_node_type node_type)
{
	struct sxe2_txsched_node *node;

	node = sxe2_txsched_first_node_get(sched_ctxt, tc, sw_layer);
	while (node) {
		if (node_type == node->node_type &&
		    (SXE2_TXSCHED_NODE_CHILD_MAX - node->child_cnt) >= need_slot_num)
			break;

		node = node->sibling;
	}

	return node;
}

static struct sxe2_txsched_node *
sxe2_txsched_node_lookup_by_type(struct sxe2_txsched_context *sched_ctxt,
				 u8 tc, u8 sw_layer,
				 enum sxe2_node_type node_type)
{
	struct sxe2_txsched_node *node;

	node = sxe2_txsched_first_node_get(sched_ctxt, tc, sw_layer);
	while (node) {
		if (node_type == node->node_type)
			break;

		node = node->sibling;
	}

	return node;
}

static struct sxe2_txsched_node *
sxe2_txsched_no_child_vsig_lookup(struct sxe2_txsched_node *tc_node,
				  enum sxe2_node_type veb_node_type)
{
	u8 i, j;
	struct sxe2_txsched_node *veb_node;

	for (i = 0; i < tc_node->child_cnt; i++) {
		veb_node = tc_node->child[i];
		if (veb_node->node_type == veb_node_type) {
			for (j = 0; j < veb_node->child_cnt; j++) {
				if (!veb_node->child[j]->child_cnt)
					return veb_node->child[j];
			}
		}
	}

	return NULL;
}

static struct sxe2_txsched_node *
sxe2_txsched_enough_slot_vsig_lookup(struct sxe2_txsched_node *tc_node,
				     enum sxe2_node_type veb_node_type,
				     enum sxe2_node_type vsig_node_type, u32 need_slot_num)
{
	u8 i, j;
	struct sxe2_txsched_node *veb_node;

	for (i = 0; i < tc_node->child_cnt; i++) {
		veb_node = tc_node->child[i];
		if (veb_node->node_type == veb_node_type) {
			for (j = 0; j < veb_node->child_cnt; j++) {
				if (vsig_node_type ==
				     veb_node->child[j]->node_type &&
				    (u32)((SXE2_TXSCHED_NODE_CHILD_MAX -
					   veb_node->child[j]->child_cnt)) >=
					    need_slot_num)

					return veb_node->child[j];
			}
		}
	}

	return NULL;
}

static struct sxe2_txsched_node *
sxe2_txsch_vf_agg_node_lookup(struct sxe2_txsched_node *tc_node,
			      enum sxe2_node_type veb_node_type, u16 vf_idx_in_pf)
{
	u8 i, j;
	struct sxe2_txsched_node *veb_node;

	for (i = 0; i < tc_node->child_cnt; i++) {
		veb_node = tc_node->child[i];
		if (veb_node->node_type == veb_node_type) {
			for (j = 0; j < veb_node->child_cnt; j++) {
				if (vf_idx_in_pf == veb_node->child[j]->vf_idx_in_pf &&
				    veb_node->child[j]->node_type == SXE2_TXSCHD_VSIG_TYPE_VF_AGG) {
					return veb_node->child[j];
				}
			}
		}
	}

	return NULL;
}

STATIC void sxe2_txsch_vsi_node_map(struct sxe2_adapter *adapter,
				    struct sxe2_vsi *vsi, u8 owner,
				    struct sxe2_txsched_node *vsi_node)
{
	if (owner == SXE2_TXSCHED_NODE_OWNER_RDMA)
		return;

	if (sxe2_txsch_vsi_type_get(adapter, vsi) == FUSION_VF2VSI_MODE_VF_UVSI)
		goto l_update_vsi;

	vsi_node->vsi_idx_in_dev = vsi->idx_in_dev;

l_update_vsi:
	vsi->txsched.node = vsi_node;
	vsi->txsched.vsi_node_cnt = vsi_node->same_node_num_pre_tc;
}

STATIC void sxe2_txsch_vsi_node_unmap(struct sxe2_vsi *vsi, u8 owner)
{
	if (!vsi)
		return;

	if (owner == SXE2_TXSCHED_NODE_OWNER_RDMA)
		return;

	vsi->txsched.node = NULL;
	vsi->txsched.vsi_node_cnt = 0;
}

s32 sxe2_txsched_vf_bw_lmt_cfg(struct sxe2_adapter *adapter,
			       struct sxe2_vf_node *vf_node, u8 rl_type, u32 bw)
{
	s32 ret;
	u8 owner;
	struct sxe2_vsi *vsi;
	struct sxe2_txsched_node *rl_node;
	struct sxe2_txsched_context *ctx = &adapter->tx_sched_ctxt;

	if (!sxe2_txsched_support_chk(adapter))
		return -EOPNOTSUPP;

	mutex_lock(&ctx->lock);

	vsi = vf_node->vsi ? vf_node->vsi : vf_node->dpdk_vf_vsi;
	if (!vsi) {
		LOG_ERROR_BDF("vsi for vf %d is null\n", vf_node->vf_idx);
		ret = -EINVAL;
		goto l_unlock;
	}

	if (sxe2_txsch_is_vf_vsi_agg_mode(adapter)) {
		rl_node = sxe2_txsch_vf_agg_node_lookup(ctx->root->child[0],
							SXE2_TXSCHD_VEB_TYPE_VF,
							vf_node->vf_idx);
	} else {
		owner = (vsi->type == SXE2_VSI_T_DPDK_VF) ?
			SXE2_TXSCHED_NODE_OWNER_USER : SXE2_TXSCHED_NODE_OWNER_LAN;
		rl_node = sxe2_txsch_vsi_node_get(adapter, vsi, 0, owner);
	}

	if (!rl_node) {
		LOG_ERROR_BDF("vf node get failed, active_vf_num=%d, vf[%d], bw=%u\n",
			      adapter->vf_ctxt.num_vfs, vf_node->vf_idx, bw);
		ret = -ENXIO;
		goto l_unlock;
	}

	ret = sxe2_txsched_node_bw_lmt_cfg(vsi, rl_node, rl_type, bw);

l_unlock:
	mutex_unlock(&ctx->lock);
	return ret;
}

static void
sxe2_txsched_vsig_layer_calc(struct sxe2_adapter *adapter,
			     struct sxe2_txsched_node *tc_node,
			     struct sxe2_vsi *vsi, u32 vsi_node_num,
			     struct sxe2_txsched_add_node_info *add_node_info)
{
	enum sxe2_node_type type;
	enum sxe2_node_type veb_node_type;
	struct sxe2_txsched_node *vsig_node;
	enum sxe2_txsch_vsi_type txsch_vsi_type;
	enum sxe2_vsi_type vsi_type = vsi->type;
	struct sxe2_txsched_context *sched_ctxt = sxe2_txsched_ctxt_get(adapter);

	txsch_vsi_type = sxe2_txsch_vsi_type_get(adapter, vsi);

	veb_node_type = sxe2_txsched_veb_node_type_get(vsi_type);

	if (vsi_type == SXE2_VSI_T_PF || vsi_type == SXE2_VSI_T_DPDK_PF) {
		type = (vsi_type == SXE2_VSI_T_PF) ?
		       SXE2_TXSCHD_VSIG_TYPE_PF_AGG : SXE2_TXSCHED_VSIG_TYPE_USER_PF;
		vsig_node = sxe2_txsched_node_lookup_by_type(sched_ctxt,
							     tc_node->tc,
							     SXE2_TXSCHED_SW_VSIG_LAYER, type);

	} else if (txsch_vsi_type == FUSION_VF2VSIG_MODE_VF_KVSI ||
		   txsch_vsi_type == FUSION_VF2VSIG_MODE_VF_UVSI) {
		vsig_node = sxe2_txsch_vf_agg_node_lookup(tc_node,
							  veb_node_type,
							  vsi->vf_node->vf_idx);
		type = SXE2_TXSCHD_VSIG_TYPE_VF_AGG;

	} else {
		if (vsi_node_num > 1) {
			vsig_node = sxe2_txsched_no_child_vsig_lookup(tc_node, veb_node_type);
			if (vsig_node)
				vsig_node->node_type = SXE2_TXSCHD_VSIG_TYPE_AGG;
			type = SXE2_TXSCHD_VSIG_TYPE_AGG;

		} else {
			vsig_node = sxe2_txsched_enough_slot_vsig_lookup(tc_node,
									 veb_node_type,
									 SXE2_TXSCHD_VSIG_TYPE_GEN,
									 vsi_node_num);

			type = SXE2_TXSCHD_VSIG_TYPE_GEN;
		}
	}

	add_node_info->num = vsig_node ? 0 : 1;
	add_node_info->type = type;
	add_node_info->node = vsig_node;
}

static void
sxe2_txsched_veb_layer_calc(struct sxe2_txsched_context *sched_ctxt, u8 tc,
			    enum sxe2_vsi_type vsi_type, u32 vsig_node_num,
			    struct sxe2_txsched_add_node_info *add_node_info)
{
	enum sxe2_node_type node_type;
	struct sxe2_txsched_node *node;

	node_type = sxe2_txsched_veb_node_type_get(vsi_type);

	node = sxe2_txsched_enough_slot_node_lookup(sched_ctxt, tc,
						    SXE2_TXSCHED_SW_VEB_LAYER,
						    (u8)vsig_node_num, node_type);

	add_node_info->num  = node ? 0 : 1;
	add_node_info->type = node_type;
	add_node_info->node = node;
}

STATIC void sxe2_txsch_non_veb_calc(struct sxe2_adapter *adapter,
				    struct sxe2_vsi *vsi,
				    enum sxe2_node_type veb_node_type,
				    struct sxe2_txsched_add_node_info add_node_info[])
{
	enum sxe2_node_type type;
	enum sxe2_txsch_vsi_type txsch_vsi_type;

	add_node_info[SXE2_TXSCHED_SW_VEB_LAYER].num  = 1;
	add_node_info[SXE2_TXSCHED_SW_VEB_LAYER].type = veb_node_type;
	add_node_info[SXE2_TXSCHED_SW_VEB_LAYER].node = NULL;

	txsch_vsi_type = sxe2_txsch_vsi_type_get(adapter, vsi);
	if (vsi->type == SXE2_VSI_T_PF ||
	    vsi->type == SXE2_VSI_T_LB ||
	    vsi->type == SXE2_VSI_T_CTRL) {
		type = SXE2_TXSCHD_VSIG_TYPE_PF_AGG;

	} else if (vsi->type == SXE2_VSI_T_DPDK_PF) {
		type = SXE2_TXSCHED_VSIG_TYPE_USER_PF;

	} else if (txsch_vsi_type == FUSION_VF2VSIG_MODE_VF_KVSI ||
		   txsch_vsi_type == FUSION_VF2VSIG_MODE_VF_UVSI) {
		type = SXE2_TXSCHD_VSIG_TYPE_VF_AGG;

	} else {
		type = (add_node_info[SXE2_TXSCHED_SW_VSI_LAYER].num > 1) ?
			SXE2_TXSCHD_VSIG_TYPE_AGG : SXE2_TXSCHD_VSIG_TYPE_GEN;
	}

	add_node_info[SXE2_TXSCHED_SW_VSIG_LAYER].num = 1;
	add_node_info[SXE2_TXSCHED_SW_VSIG_LAYER].type = type;
	add_node_info[SXE2_TXSCHED_SW_VSIG_LAYER].node = NULL;
}

STATIC void
sxe2_txsched_vsi_to_tc_calc(struct sxe2_adapter *adapter, struct sxe2_txsched_node *tc_node,
			    u32 queue_num, struct sxe2_vsi *vsi,
			    struct sxe2_txsched_add_node_info add_node_info[], u8 owner)
{
	struct sxe2_txsched_context *ctxt = sxe2_txsched_ctxt_get(adapter);
	enum sxe2_vsi_type vsi_type = vsi->type;
	enum sxe2_node_type veb_node_type;
	struct sxe2_txsched_node *veb_node;
	u8 max_layer = sxe2_txsched_layer_max_get(ctxt);

	add_node_info[SXE2_TXSCHED_SW_PORT_LAYER].num = 0;
	add_node_info[SXE2_TXSCHED_SW_PORT_LAYER].type = SXE2_TXSCHD_NODE_TYPE_PORT;

	add_node_info[SXE2_TXSCHED_SW_TC_LAYER].num = 0;
	add_node_info[SXE2_TXSCHED_SW_TC_LAYER].type = SXE2_TXSCHD_NODE_TYPE_TC;

	sxe2_txsched_vsi_layer_calc(max_layer, queue_num, vsi_type, owner,
				    &add_node_info[SXE2_TXSCHED_SW_VSI_LAYER]);

	veb_node_type = sxe2_txsched_veb_node_type_get(vsi_type);
	veb_node = sxe2_txsched_node_lookup_by_type(ctxt, tc_node->tc,
						    SXE2_TXSCHED_SW_VEB_LAYER,
						    veb_node_type);
	if (!veb_node) {
		sxe2_txsch_non_veb_calc(adapter, vsi, veb_node_type, add_node_info);
		add_node_info[SXE2_TXSCHED_SW_VSIG_LAYER].node = NULL;
		return;
	}

	sxe2_txsched_vsig_layer_calc(adapter, tc_node, vsi,
				     add_node_info[SXE2_TXSCHED_SW_VSI_LAYER].num,
				     &add_node_info[SXE2_TXSCHED_SW_VSIG_LAYER]);

	sxe2_txsched_veb_layer_calc(ctxt, tc_node->tc, vsi_type,
				    add_node_info[SXE2_TXSCHED_SW_VSIG_LAYER].num,
				    &add_node_info[SXE2_TXSCHED_SW_VEB_LAYER]);
}

static s32
sxe2_txsched_hw_node_add(struct sxe2_adapter *adapter,
			 struct sxe2_txsch_add_nodes_req *nodes_param,
			 u32 resp_size, struct sxe2_fwc_txsched_add_nodes_resp *resp)
{
	s32 ret;
	u32 i, req_size;
	struct sxe2_cmd_params cmd = {};
	struct device *dev	   = &adapter->pdev->dev;
	struct sxe2_fwc_txsched_add_nodes_req *req;

	req_size = (u32)struct_size(req, node, nodes_param->num);
	req	 = devm_kzalloc(dev, req_size, GFP_KERNEL);
	if (!req) {
		LOG_ERROR_BDF("sched node add: alloc failed\n");
		ret = -ENOMEM;
		goto l_end;
	}

	req->hdr.node_num    = nodes_param->num;
	req->hdr.parent_teid = nodes_param->parent_teid;
	for (i = 0; i < nodes_param->num; i++) {
		req->node[i].parent_teid   = nodes_param->parent_teid;
		req->node[i].data.prio	   = nodes_param->prio;
		req->node[i].data.hw_layer = nodes_param->sw_layer + 1;
		req->node[i].data.arb_mode = SXE2_NODE_ARB_MODE_BPS;
		req->node[i].data.status   = SXE2_NODE_STATUS_ENABLE;
		req->node[i].data.rl_type  = SXE2_NODE_RL_TYPE_EIR;
		req->node[i].data.cir.bw =
			SXE2_TXSCHED_DFLT_BW;
		req->node[i].data.cir.weight  = nodes_param->weight;
		req->node[i].data.cir.prof_id = SXE2_TXSCHED_DFLT_RL_PROF_ID;
		req->node[i].data.srlPir.bw =
			SXE2_TXSCHED_DFLT_BW;
		req->node[i].data.srlPir.weight = nodes_param->weight;
		req->node[i].data.srlPir.prof_id =
			SXE2_TXSCHED_DFLT_RL_PROF_ID;
		req->node[i].data.adj_lvl  = nodes_param->adj_lvl;
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TX_SCHED_NODE_ADD, req,
				  req_size, resp, resp_size);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret || resp->add_node_num != nodes_param->num) {
		LOG_ERROR_BDF("tx sched node add failed, ret=%d\n", ret);
		ret = -EIO;
	}

	devm_kfree(dev, req);
l_end:
	return ret;
}

STATIC s32 sxe2_txsched_nodes_add(struct sxe2_adapter *adapter,
				  struct sxe2_txsched_node *parent,
				  struct sxe2_txsch_add_nodes_req *nodes_param,
				  struct sxe2_txsched_node **first_node,
				  u16 *num_nodes_added)
{
	s32 ret;
	u16 teid;
	u32 resp_size, i;
	u8 tc       = nodes_param->tc;
	u8 swl      = nodes_param->sw_layer;
	struct device *dev = &adapter->pdev->dev;
	struct sxe2_txsched_node *prev, *new_node;
	struct sxe2_txsched_node_param node_param;
	struct sxe2_fwc_txsched_add_nodes_resp *resp;
	struct sxe2_txsched_context *sched_ctxt = &adapter->tx_sched_ctxt;

	resp_size = struct_size(resp, node_teid, nodes_param->num);
	resp	  = devm_kzalloc(dev, resp_size, GFP_KERNEL);
	if (!resp) {
		LOG_ERROR_BDF("txshced alloc node failed\n");
		return -ENOMEM;
	}

	ret = sxe2_txsched_hw_node_add(adapter, nodes_param, resp_size, resp);
	if (ret)
		goto l_free;

	*num_nodes_added = (u16)resp->add_node_num;
	for (i = 0; i < *num_nodes_added; i++) {
		node_param.tc		    = tc;
		node_param.owner	    = nodes_param->owner;
		node_param.sw_layer	    = swl;
		node_param.node_teid	    = resp->node_teid[i];
		node_param.parent_teid	    = parent->info.node_teid;
		node_param.node_silbing_idx = (u8)resp->sibling_idx[i];
		ret = sxe2_txsched_sw_node_add(adapter, &node_param);
		if (ret) {
			LOG_ERROR_BDF("add nodes in sw failed, ret =%d\n", ret);
			break;
		}

		teid	 = resp->node_teid[i];
		new_node = sxe2_txsched_find_node_by_teid(parent, teid);
		if (!new_node) {
			ret = -ENOMEM;
			LOG_ERROR_BDF("node is missing for teid =%d\n", teid);
			break;
		}

		new_node->sibling = NULL;
		prev = sxe2_txsched_first_node_get(sched_ctxt, tc, swl);
		if (prev && prev != new_node) {
			while (prev->sibling)
				prev = prev->sibling;
			prev->sibling = new_node;
		}

		if (!sched_ctxt->sib_head[tc][swl])
			sched_ctxt->sib_head[tc][swl] = new_node;
		if (i == 0)
			*first_node = new_node;
	}

l_free:
	devm_kfree(dev, resp);
	return ret;
}

static inline void
sxe2_txsched_node_group_list_updata(struct sxe2_txsched_node *first_node,
				    u32 num_added)
{
	struct sxe2_txsched_node *node = NULL;

	node = first_node;
	while (--num_added && node) {
		node->group = node->sibling;
		node	    = node->sibling;
	}

	if (node)
		node->group = NULL;
}

STATIC s32 sxe2_txsched_add_nodes_to_parent(struct sxe2_adapter *adapter,
					    struct sxe2_txsched_node *parent,
					    struct sxe2_txsch_add_nodes_req *nodes_param,
					    struct sxe2_txsched_node **first_node,
					    u16 *num_nodes_added)
{
	s32 ret = 0;

	if (!nodes_param->num) {
		*first_node	 = NULL;
		*num_nodes_added = 0;
		LOG_DEBUG_BDF("dont need create node, need_add==0\n");
		return 0;
	}

	if ((parent->child_cnt + nodes_param->num) > SXE2_TXSCHED_NODE_CHILD_MAX) {
		LOG_ERROR_BDF("txsched are not enough slot,\t"
			      "parent->child_cnt=%u, need_node=%u , ret=%d\n",
			      parent->child_cnt, nodes_param->num, ret);
		return -ENOSPC;
	}

	ret = sxe2_txsched_nodes_add(adapter, parent,
				     nodes_param, first_node, num_nodes_added);
	if (ret) {
		LOG_ERROR_BDF("txsched node create failed, ret=%d\n", ret);
		return ret;
	}

	sxe2_txsched_node_group_list_updata(*first_node, *num_nodes_added);

	return ret;
}

static inline void
sxe2_txsched_node_info_setup(struct sxe2_txsched_node *first,
			     struct sxe2_vsi *vsi, u8 sw_layer, u32 node_num,
			     enum sxe2_node_type node_type, u8 owner)
{
	struct sxe2_txsched_node *node;
	enum sxe2_txsch_vsi_type txsch_vsi_type;

	node = first;
	while (node) {
		node->in_use = true;

		txsch_vsi_type = sxe2_txsch_vsi_type_get(vsi->adapter, vsi);

		if (sw_layer == SXE2_TXSCHED_SW_VSI_LAYER) {
			if (txsch_vsi_type != FUSION_VF2VSI_MODE_VF_UVSI)
				node->vsi_idx_in_dev = vsi->idx_in_dev;

			node->vf_idx_in_pf = (sxe2_txsch_is_vf_by_vsitype(vsi->type)) ?
					     vsi->vf_node->vf_idx : SXE2_TXSCH_VF_IDX_INVAL;
		}

		if (sw_layer == SXE2_TXSCHED_SW_VSIG_LAYER) {
			if (txsch_vsi_type == FUSION_VF2VSIG_MODE_VF_UVSI ||
			    txsch_vsi_type == FUSION_VF2VSIG_MODE_VF_KVSI) {
				node->vf_idx_in_pf = vsi->vf_node->vf_idx;
			}
		}

		node->same_node_num_pre_tc = (u8)node_num;
		node->node_type		   = node_type;
		node->owner		   = owner;
		node			   = node->group;
	}
}

STATIC struct
sxe2_txsched_node *sxe2_txsched_vsi_node_add(struct sxe2_adapter *adapter,
					     struct sxe2_txsched_node *tc_node,
					     struct sxe2_vsi *vsi,
					     struct sxe2_txsched_add_node_info add_node_info[],
					     u8 owner)
{
	s32 ret;
	u8 swl, vsil;
	u16 num_added = 0;
	struct sxe2_txsched_node *first_node;
	struct sxe2_txsched_node *parent  = tc_node;
	struct sxe2_txsch_add_nodes_req nodes_param;

	vsil = sxe2_txsched_sw_vsi_layer_get();

	for (swl = SXE2_TXSCHED_SW_VEB_LAYER; swl <= vsil; swl++) {
		nodes_param.sw_layer    = swl;
		nodes_param.owner       = owner;
		nodes_param.tc          = tc_node->tc;
		nodes_param.num         = add_node_info[swl].num;
		nodes_param.parent_teid = parent->info.node_teid;
		nodes_param.prio        = SXE2_TXSCH_NODE_PRIO_DLFT;
		nodes_param.weight      = SXE2_TXSCHED_ARB_CREDIT_DFLT;
		nodes_param.adj_lvl     = sxe2_txsch_node_adj_lvl_get();
		ret = sxe2_txsched_add_nodes_to_parent(adapter, parent,
						       &nodes_param, &first_node, &num_added);
		if (ret || add_node_info[swl].num != num_added) {
			first_node = NULL;
			goto l_end;
		}

		if (num_added && add_node_info[swl].num)
			parent = first_node;
		else
			parent = add_node_info[swl].node;

		if (!parent) {
			first_node = NULL;
			LOG_ERROR_BDF("txsched vsi build failed, \t"
				      "dont find parent node\n");
			goto l_end;
		}

		if (num_added)
			sxe2_txsched_node_info_setup(first_node, vsi, swl,
						     num_added,
						     add_node_info[swl].type,
						     owner);
	}

	return first_node;

l_end:
	return NULL;
}

STATIC struct sxe2_txsched_node *
sxe2_txsched_vsi_build(struct sxe2_adapter *adapter,
		       struct sxe2_txsched_node *tc_node,
		       struct sxe2_vsi *vsi, u32 queue_num,
		       u8 owner)
{
	struct sxe2_txsched_add_node_info add_node_info[SXE2_TXSCHED_LAYER_MAX];

	(void)memset(add_node_info, 0,
		     (sizeof(struct sxe2_txsched_add_node_info) *
		     SXE2_TXSCHED_LAYER_MAX));

	sxe2_txsched_vsi_to_tc_calc(adapter, tc_node, queue_num, vsi,
				    add_node_info, owner);

#ifndef SXE2_CFG_RELEASE
	LOG_INFO("evb node calc, \t"
		 "hwlayer[3] node cnt = %u, node type = %d\n",
		 add_node_info[SXE2_TXSCHED_SW_VEB_LAYER].num,
		 add_node_info[SXE2_TXSCHED_SW_VEB_LAYER].type);
	if (SXE2_TXSCHED_SW_VSIG_LAYER < SXE2_TXSCHED_LAYER_MAX)
		LOG_INFO("vsig node calc, \t"
			 "hwlayer[4] node cnt = %u, node type = %d\n",
			 add_node_info[SXE2_TXSCHED_SW_VSIG_LAYER].num,
			 add_node_info[SXE2_TXSCHED_SW_VSIG_LAYER].type);
	if (SXE2_TXSCHED_SW_VSI_LAYER < SXE2_TXSCHED_LAYER_MAX)
		LOG_INFO("vsi node calc, \t"
			 "hwlayer[5] node cnt = %u, node type = %d\n",
			 add_node_info[SXE2_TXSCHED_SW_VSI_LAYER].num,
			 add_node_info[SXE2_TXSCHED_SW_VSI_LAYER].type);
#endif
	return sxe2_txsched_vsi_node_add(adapter, tc_node, vsi, add_node_info, owner);
}

static inline u32
sxe2_txsched_vsi_node_num_get(struct sxe2_txsched_node *fist_vsi_node)
{
	u32 vsi_cnt			   = 0;
	struct sxe2_txsched_node *vsi_node = fist_vsi_node;

	while (vsi_node) {
		vsi_node = vsi_node->group;
		vsi_cnt++;
	}

	return vsi_cnt;
}

static inline bool
sxe2_txsched_vsi_node_enough(struct sxe2_txsched_node *fist_vsi_node, u16 q_cnt)
{
	u32 vsi_node_num;
	u32 num_node = 0;

	num_node = (u32)DIV_ROUND_UP(q_cnt, (SXE2_TXSCHED_NODE_CHILD_MAX *
					     SXE2_TXSCHED_NODE_CHILD_MAX));

	vsi_node_num = sxe2_txsched_vsi_node_num_get(fist_vsi_node);

	return (vsi_node_num >= num_node);
}

static inline void
sxe2_txsched_qp_group_update(struct sxe2_txsched_node *start_node,
			     u32 num_added, u8 owner, u16 vsi_idx,
			     struct sxe2_txsched_node **prev_node)
{
	struct sxe2_txsched_node *node;

	node = start_node;
	do {
		node->owner	     = owner;
		node->vsi_idx_in_dev = vsi_idx;
		node		     = node->group;
	} while (node && node->group);

	if (node) {
		node->owner	     = owner;
		node->vsi_idx_in_dev = vsi_idx;
	}

	if (*prev_node)
		(*prev_node)->group = start_node;

	*prev_node = node;
}

static s32
sxe2_txsched_vsi_child_nodes_add(struct sxe2_adapter *adapter,
				 struct sxe2_vsi *vsi,
				 struct sxe2_txsched_node *parent,
				 struct sxe2_txsched_node *tc_node,
				 u16 qg_nodes, u8 owner)
{
	s32 ret;
	u8 qgl;
	u32 add_nodes;
	u16 num_added = 0;
	struct sxe2_txsched_node *first_node;
	struct sxe2_txsch_add_nodes_req nodes_param;
	struct sxe2_txsched_node *prev_node = NULL;

	qgl = sxe2_txsched_sw_qp_layer_get();

	prev_node = sxe2_txsch_qg_tail_node_get(parent, owner);
	while (parent) {
		add_nodes = SXE2_TXSCHED_NODE_CHILD_MAX - (u32)parent->child_cnt;
		add_nodes = qg_nodes > add_nodes ? add_nodes : qg_nodes;

		nodes_param.sw_layer    = qgl;
		nodes_param.owner       = owner;
		nodes_param.tc          = tc_node->tc;
		nodes_param.num         = (u16)add_nodes;
		nodes_param.parent_teid = parent->info.node_teid;
		nodes_param.weight      = SXE2_TXSCHED_ARB_CREDIT_DFLT;
		nodes_param.adj_lvl     = sxe2_txsch_node_adj_lvl_get();
		nodes_param.prio = (sxe2_txsch_vsi_type_get(adapter, vsi) ==
				    FUSION_VF2VSI_NODE_VF_KVSI) ?
				    SXE2_TXSCH_NODE_PRIO_HIGH : SXE2_TXSCH_NODE_PRIO_DLFT;
		ret = sxe2_txsched_add_nodes_to_parent(adapter, parent,
						       &nodes_param, &first_node, &num_added);
		if (ret || add_nodes != num_added) {
			LOG_ERROR_BDF("create vsi child node failed, \t"
				      "vsi_idx=%u, nend_node=%u, \t"
				      "qg_nodes =%u num_added=%u\n",
				      vsi->idx_in_dev, add_nodes,
				      qg_nodes, num_added);
			return -EIO;
		}

		if (num_added)
			sxe2_txsched_qp_group_update(first_node, num_added,
						     owner, vsi->idx_in_dev,
						     &prev_node);

		qg_nodes -= num_added;
		if (qg_nodes)
			parent = parent->group;
		else
			break;
	}

	return 0;
}

static inline u32
sxe2_txsched_vsi_child_nodes_calc(struct sxe2_txsched_node *fist_vsi_node,
				  u32 queue_num, u8 owner)
{
	u32 need_num;
	u32 cur_qg_num;

	need_num = DIV_ROUND_UP(queue_num, SXE2_TXSCHED_NODE_CHILD_MAX);
	need_num = need_num ? need_num : 1;

	cur_qg_num = sxe2_txsched_qg_num_get(fist_vsi_node, owner);

	return (need_num <= cur_qg_num) ? 0 : (need_num - cur_qg_num);
}

STATIC s32
sxe2_txsched_vsi_children_build(struct sxe2_adapter *adapter,
				struct sxe2_vsi *vsi,
				struct sxe2_txsched_node *vsi_node,
				u8 tc, u32 new_numqs, u8 owner)
{
	int ret	     = 0;
	u16 qg_nodes = 0x3fff;
	struct sxe2_txsched_node *tc_node;
	struct sxe2_txsched_context *ctxt = &adapter->tx_sched_ctxt;

	tc_node = sxe2_txsched_tc_node_get(ctxt, tc);
	if (!tc_node) {
		LOG_ERROR_BDF("tc node = NULL, tc=%d\n", tc);
		return -EIO;
	}

	if (new_numqs) {
		if (sxe2_txsch_vsi_type_get(adapter, vsi) == FUSION_VF2VSI_MODE_VF_UVSI) {
			qg_nodes = (u16)DIV_ROUND_UP(new_numqs, SXE2_TXSCHED_NODE_CHILD_MAX);
			qg_nodes = qg_nodes ? qg_nodes : 1;
		} else {
			qg_nodes = (u16)sxe2_txsched_vsi_child_nodes_calc(vsi_node,
									  new_numqs, owner);
		}
	}

	LOG_INFO_BDF("txsched queue grep node num=%d, q_num=%d\n", qg_nodes, new_numqs);

	ret = sxe2_txsched_vsi_child_nodes_add(adapter, vsi, vsi_node, tc_node,
					       qg_nodes, owner);
	return ret;
}

STATIC s32 sxe2_txsched_vsi_topo_build(struct sxe2_adapter *adapter,
				       struct sxe2_vsi *vsi, u32 max_qs[], u8 owner,
				       struct sxe2_txsched_node **tc0_vsi_node)
{
	u32 i;
	s32 ret = 0;
	struct sxe2_txsched_node *vsi_node, *tc_node;
	struct sxe2_txsched_context *sched_ctxt = &adapter->tx_sched_ctxt;

	sxe2_for_each_tc(i) {
		if (!max_qs[i])
			continue;

		tc_node = sxe2_txsched_tc_node_get(sched_ctxt, i);
		if (!tc_node || !tc_node->in_use)
			continue;

		vsi_node = sxe2_txsch_vsi_node_get(adapter, vsi, i, owner);
		if (vsi_node) {
			if (sxe2_txsched_vsi_node_enough(vsi_node, (u16)max_qs[i]))
				goto l_child;

			ret = sxe2_txsched_vsi_node_del(adapter, i, vsi, owner);
			if (ret) {
				LOG_ERROR_BDF("tc[%u] vsi node del failed, ret=%d\n", i, ret);
				goto l_err;
			}
		}

		vsi_node = sxe2_txsched_vsi_build(adapter, tc_node, vsi, max_qs[i],
						  owner);
		if (!vsi_node) {
			ret = -EIO;
			LOG_ERROR_BDF("sched vsi[%d] node build failed, owner=%d\n ",
				      vsi->idx_in_dev, owner);
			break;
		}

l_child:
		if (i == 0)
			*tc0_vsi_node = vsi_node;

		ret = sxe2_txsched_vsi_children_build(adapter, vsi, vsi_node, i,
						      max_qs[i], owner);
		if (ret) {
			LOG_ERROR_BDF("sched vsi[%d] children build failed\n ",
				      vsi->idx_in_dev);
			break;
		}
	}

l_err:
	return ret;
}

s32 sxe2_txsched_lan_vsi_cfg(struct sxe2_vsi *vsi)
{
	u8 i;
	s32 ret;
	u32 q_cnt[SXE2_MAX_TRAFFIC_CLASS];
	struct sxe2_txsched_node *vsi_node;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (!sxe2_txsched_support_chk(adapter))
		return 0;

	if (vsi->type == SXE2_VSI_T_DPDK_PF || vsi->type == SXE2_VSI_T_DPDK_VF)
		return 0;

	(void)memset(q_cnt, 0, sizeof(u32) * SXE2_MAX_TRAFFIC_CLASS);
	sxe2_for_each_tc(i) {
		if (!(vsi->tc.tc_map & BIT(i)))
			continue;

		if (vsi->type == SXE2_VSI_T_PF) {
			q_cnt[i] = vsi->tc.info[i].txq_cnt;
			if (i == 0)
				q_cnt[i] += vsi->num_xdp_txq;
		} else if (vsi->type == SXE2_VSI_T_CTRL) {
			q_cnt[i] = 1;
		} else if (vsi->type == SXE2_VSI_T_VF) {
			q_cnt[i] = vsi->tc.info[i].txq_cnt;
			if (i == 0)
				q_cnt[i] += IEEE_8021Q_MAX_PRIORITIES;
		} else {
			q_cnt[i] = vsi->tc.info[i].txq_cnt;
		}

		ret = sxe2_txsched_vsi_q_ctxt_alloc(vsi, i, (u16)q_cnt[i]);
		if (ret)
			return ret;
	}

	mutex_lock(&adapter->tx_sched_ctxt.lock);
	if (adapter->tx_sched_ctxt.state != SXE2_TX_SCHED_STATE_READY) {
		mutex_unlock(&adapter->tx_sched_ctxt.lock);
		LOG_ERROR_BDF("sched dont ready, state=%d\n", adapter->tx_sched_ctxt.state);
		return -EIO;
	}

	ret = sxe2_txsched_vsi_topo_build(adapter, vsi, q_cnt,
					  SXE2_TXSCHED_NODE_OWNER_LAN, &vsi_node);
	if (ret)
		LOG_ERROR_BDF("txsched lan vsi build failed, ret=%d\n", ret);
	else
		sxe2_txsch_vsi_node_map(adapter, vsi, SXE2_TXSCHED_NODE_OWNER_LAN, vsi_node);

	mutex_unlock(&adapter->tx_sched_ctxt.lock);

	return ret;
}

s32 sxe2_txsched_lan_vsi_rm(struct sxe2_vsi *vsi)
{
	s32 ret;

	if (!sxe2_txsched_support_chk(vsi->adapter))
		return 0;

	if (vsi->type == SXE2_VSI_T_DPDK_PF || vsi->type == SXE2_VSI_T_DPDK_VF)
		return 0;

	mutex_lock(&vsi->adapter->tx_sched_ctxt.lock);

	ret = sxe2_txsched_del_vsi_node_for_each_tc(vsi->adapter,
						    vsi, SXE2_TXSCHED_NODE_OWNER_LAN);

	sxe2_txsch_vsi_node_unmap(vsi, SXE2_TXSCHED_NODE_OWNER_LAN);

	mutex_unlock(&vsi->adapter->tx_sched_ctxt.lock);

	return ret;
}

s32 sxe2_txsched_rdma_vsi_rm(struct sxe2_vsi *vsi)
{
	s32 ret;

	if (!sxe2_txsched_support_chk(vsi->adapter))
		return 0;

	if (vsi->type == SXE2_VSI_T_DPDK_PF || vsi->type == SXE2_VSI_T_DPDK_VF)
		return 0;

	mutex_lock(&vsi->adapter->tx_sched_ctxt.lock);

	ret = sxe2_txsched_del_vsi_node_for_each_tc(vsi->adapter,
						    vsi, SXE2_TXSCHED_NODE_OWNER_RDMA);

	sxe2_txsch_vsi_node_unmap(vsi, SXE2_TXSCHED_NODE_OWNER_RDMA);

	mutex_unlock(&vsi->adapter->tx_sched_ctxt.lock);

	return ret;
}

STATIC struct sxe2_txsched_node *
sxe2_txsched_get_free_qg(struct sxe2_txsched_node *qgrp_node, u16 vsi_idx,
			 u32 owner)
{
	u8 min_children;
	struct sxe2_txsched_node *min_qgrp;

	min_children = qgrp_node->child_cnt;
	if (!min_children)
		return qgrp_node;

	min_qgrp = qgrp_node;
	while (qgrp_node) {
		if (vsi_idx == qgrp_node->vsi_idx_in_dev &&
		    qgrp_node->child_cnt <= SXE2_TXSCHED_NODE_CHILD_MAX) {
			if (qgrp_node->child_cnt < min_children &&
			    qgrp_node->owner == owner) {
				min_qgrp     = qgrp_node;
				min_children = min_qgrp->child_cnt;
				if (!min_children)
					break;
			}
		}
		qgrp_node = qgrp_node->group;
	}

	return min_qgrp;
}

STATIC struct sxe2_txsched_node *
sxe2_txsched_get_free_qparent(struct sxe2_adapter *adapter,
			      struct sxe2_vsi *vsi, u8 tc, u8 owner)
{
	struct sxe2_txsched_node *vsi_node;
	struct sxe2_txsched_node *qgrp_node;

	vsi_node = sxe2_txsch_vsi_node_get(adapter, vsi, tc, owner);
	if (!vsi_node) {
		LOG_ERROR_BDF("sched vsi_node == NULL, vsi_idx=%d, owner=%d\n",
			      vsi->idx_in_dev, owner);
		return NULL;
	}

	qgrp_node = sxe2_txsch_qg_head_node_get(vsi_node, owner);
	if (!qgrp_node) {
		LOG_ERROR_BDF("sched qgrp == NULL, vsi=%d\n", vsi->idx_in_dev);
		return NULL;
	}

	return sxe2_txsched_get_free_qg(qgrp_node, vsi->idx_in_dev, owner);
}

s32 sxe2_txsched_txq_node_add(struct sxe2_adapter *adapter,
			      struct sxe2_vsi *vsi, struct sxe2_queue *txq,
			      enum sxe2_txsched_node_owner owner,
			      struct sxe2_fwc_cfg_txq_req *req)
{
	s32 ret;
	u8 q_layer;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_txsched_node *parent;
	struct sxe2_fwc_cfg_txq_resp resp;
	struct sxe2_vsi_txsched_queue *q_ctxt;
	struct sxe2_txsched_node_param node_param;
	struct sxe2_txsched_context *sched_ctxt = &adapter->tx_sched_ctxt;

	if (!sxe2_txsched_support_chk(adapter))
		return 0;

	q_layer = sxe2_txsched_sw_q_layer_get();

	mutex_lock(&sched_ctxt->lock);
	if (sched_ctxt->state != SXE2_TX_SCHED_STATE_READY) {
		ret = -EIO;
		goto l_unlock;
	}

	parent = sxe2_txsched_get_free_qparent(adapter, vsi, txq->dcb_tc, owner);
	if (!parent) {
		ret = -EINVAL;
		goto l_unlock;
	}

	if ((parent->child_cnt + 1) > SXE2_TXSCHED_NODE_CHILD_MAX) {
		ret = -ENOSPC;
		LOG_ERROR_BDF("vsi[%u] are not enough slot, parent_teid=%#x, \t"
			      "parent->child_cnt=%u, need_node=1 , ret=%d\n",
			      vsi->idx_in_dev, parent->info.node_teid,
			      parent->child_cnt, ret);

		goto l_unlock;
	}

	req->leaf.port = adapter->port_idx;
	req->leaf.tc   = txq->dcb_tc;
	req->leaf.txq_idx_in_dev =
		txq->idx_in_pf + adapter->q_ctxt.txq_base_idx_in_dev;
	req->leaf.node.parent_teid   = parent->info.node_teid;
	req->leaf.node.data.hw_layer = q_layer + 1;
	req->leaf.node.data.status   = SXE2_NODE_STATUS_ENABLE;
	req->leaf.node.data.arb_mode = SXE2_NODE_ARB_MODE_BPS;
	req->leaf.node.data.rl_type  = SXE2_NODE_RL_TYPE_EIR;
	req->leaf.node.data.cir.bw = SXE2_TXSCHED_DFLT_BW;
	req->leaf.node.data.cir.weight	= SXE2_TXSCHED_ARB_CREDIT_DFLT;
	req->leaf.node.data.cir.prof_id = SXE2_TXSCHED_DFLT_RL_PROF_ID;
	req->leaf.node.data.srlPir.bw	= SXE2_TXSCHED_DFLT_BW;
	req->leaf.node.data.srlPir.weight  = SXE2_TXSCHED_ARB_CREDIT_DFLT;
	req->leaf.node.data.srlPir.prof_id = SXE2_TXSCHED_DFLT_RL_PROF_ID;
	req->leaf.node.data.prio     = 0;
	req->leaf.node.data.adj_lvl = sxe2_txsch_node_adj_lvl_get();

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TX_SCHED_Q_CFG, req,
				  sizeof(*req), &resp, sizeof(resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("tx sched txq add failed, ret=%d\n", ret);
		ret = -EIO;
		goto l_unlock;
	}

	node_param.tc		    = txq->dcb_tc;
	node_param.owner            = owner;
	node_param.sw_layer	    = q_layer;
	node_param.node_teid	    = resp.node_teid;
	node_param.vsi_idx_in_dev   = vsi->idx_in_dev;
	node_param.txq_idx_in_vsi   = txq->idx_in_vsi;
	node_param.node_silbing_idx = resp.sibling_idx;
	node_param.parent_teid	    = parent->info.node_teid;
	node_param.txq_idx_in_dev   = req->leaf.txq_idx_in_dev;
	ret = sxe2_txsched_sw_node_add(adapter, &node_param);
	if (ret) {
		LOG_ERROR_BDF("tx sched txq add failed, ret=%d\n", ret);
		goto l_unlock;
	}
	txq->txq_teid = resp.node_teid;

	if (vsi->type == SXE2_VSI_T_DPDK_PF || vsi->type == SXE2_VSI_T_DPDK_VF)
		goto l_end;

	q_ctxt = sxe2_txsched_q_ctxt_get(vsi, txq->dcb_tc, txq->idx_in_vsi);
	q_ctxt->teid	   = resp.node_teid;
	q_ctxt->idx_in_dev = req->leaf.txq_idx_in_dev;
	ret = sxe2_txsched_replay_q_bw(vsi, q_ctxt);
	if (ret) {
		LOG_ERROR_BDF("tx sched txq replay bw failed, ret=%d\n", ret);
		goto l_unlock;
	}
l_end:
	LOG_INFO_BDF("txq node add success,teid:%#x,parent teid:%#x\n",
		     txq->txq_teid, node_param.parent_teid);
l_unlock:
	mutex_unlock(&sched_ctxt->lock);
	return ret;
}

s32 sxe2_txsched_txq_node_del(struct sxe2_adapter *adapter, struct sxe2_queue *txq)
{
	s32 ret			   = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_txsched_node *node;
	struct sxe2_fwc_disable_txq_req req;
	struct sxe2_txsched_context *sched_ctxt = &adapter->tx_sched_ctxt;

	if (!sxe2_txsched_support_chk(adapter))
		return 0;

	mutex_lock(&sched_ctxt->lock);

	LOG_INFO_BDF("[txq_teid:%#x]\n", txq->txq_teid);

	node = sxe2_txsched_find_node_by_teid(sched_ctxt->root, txq->txq_teid);
	if (!node) {
		LOG_ERROR_BDF("sched txq node unexit, dont need del\n");
		goto l_end;
	}

	req.leaf.tc   = txq->dcb_tc;
	req.leaf.port = adapter->port_idx;
	req.txq_idx_in_func  = txq->idx_in_pf;
	req.leaf.node_teid   = node->info.node_teid;
	req.leaf.parent_teid = node->info.parent_teid;
	req.leaf.sibling_idx = (u16)node->info.sibling_idx;
	req.txq_idx_in_nic   = adapter->q_ctxt.txq_base_idx_in_dev + txq->idx_in_pf;
	req.leaf.txq_idx_in_dev = adapter->q_ctxt.txq_base_idx_in_dev + txq->idx_in_pf;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TX_SCHED_Q_STOP, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("sched txq del failed, ret=%d\n", ret);

	LOG_INFO_BDF("sched txq node del success,teid:%#x,parent teid:%#x\n",
		     txq->txq_teid, node->info.parent_teid);

	sxe2_txsched_sw_node_del(adapter, node);

	txq->txq_teid = 0;

l_end:
	mutex_unlock(&sched_ctxt->lock);
	return ret;
}

void sxe2_txsched_tree_clean(struct sxe2_adapter *adapter)
{
	if (!sxe2_txsched_support_chk(adapter))
		return;

	mutex_lock(&adapter->tx_sched_ctxt.lock);
	if (adapter->tx_sched_ctxt.state != SXE2_TX_SCHED_STATE_READY) {
		(void)mutex_unlock(&adapter->tx_sched_ctxt.lock);
		return;
	}

	adapter->tx_sched_ctxt.state = SXE2_TX_SCHED_STATE_INIT;
	(void)sxe2_txsched_subtree_clean(adapter, adapter->tx_sched_ctxt.root);
	adapter->tx_sched_ctxt.root = NULL;
	mutex_unlock(&adapter->tx_sched_ctxt.lock);
}

void sxe2_txsched_vf_tree_clean(struct sxe2_adapter *adapter)
{
	u8 i, idx;
	u8 child_cnt;
	struct sxe2_txsched_node *tc_node;
	struct sxe2_txsched_node *veb_node;

	if (!sxe2_txsched_support_chk(adapter))
		return;

	mutex_lock(&adapter->tx_sched_ctxt.lock);
	if (adapter->tx_sched_ctxt.state != SXE2_TX_SCHED_STATE_READY) {
		(void)mutex_unlock(&adapter->tx_sched_ctxt.lock);
		return;
	}

	tc_node = adapter->tx_sched_ctxt.root->child[0];
	child_cnt = tc_node->child_cnt;
	for (i = 0, idx = 0; i < child_cnt; i++) {
		veb_node = tc_node->child[idx];
		if (!veb_node) {
			idx++;
			continue;
		}

		if (veb_node->node_type == SXE2_TXSCHD_VEB_TYPE_VF) {
			(void)sxe2_txsched_subtree_clean(adapter, veb_node);
		} else {
			idx++;
			continue;
		}
	}

	mutex_unlock(&adapter->tx_sched_ctxt.lock);
}

void sxe2_txsched_sw_subtree_dump(struct sxe2_adapter *adapter,
				  struct sxe2_txsched_node *node)
{
	u8 i;

	if (!node)
		return;

	for (i = 0; i < node->child_cnt; i++)
		sxe2_txsched_sw_subtree_dump(adapter, node->child[i]);

	LOG_DEV_INFO("vsi_idx:%d, hw_layer:%#x teid:%#x \t"
		     "parent_teid:%#x num_children:%d tc_idx:%#x \t"
		     "type:%#x use:%#x owner:%#x\n",
		     node->vsi_idx_in_dev, node->info.data.hw_layer,
		     le16_to_cpu(node->info.node_teid),
		     le16_to_cpu(node->info.parent_teid),
		     node->child_cnt,
		     node->tc,
		     node->node_type,
		     node->in_use,
		     node->owner);

	LOG_DEV_INFO("prio:%d, is_suspend:%#x is_pps:%#x profiled_type:%#x\n",
		     node->info.data.prio, node->info.data.status,
		     node->info.data.arb_mode, node->info.data.rl_type);

	LOG_DEV_INFO("cir_prof_id:%u bw:%u, crlweight:%u srl_prof_id:%u bw:%u srl_weight:%u \t"
		     " pri:#%x\n\n",
		     le32_to_cpu(node->info.data.cir.prof_id),
		     le32_to_cpu(node->info.data.cir.bw),
		     le16_to_cpu(node->info.data.cir.weight),
		     le32_to_cpu(node->info.data.srlPir.prof_id),
		     le32_to_cpu(node->info.data.srlPir.bw),
		     le16_to_cpu(node->info.data.srlPir.weight),
		     node->info.data.prio);
}

void sxe2_txsched_hw_subtree_dump(struct sxe2_adapter *adapter,
				  struct sxe2_txsched_node *node)
{
	u8 i;
	s32 ret;
	struct sxe2_txsched_node_param param;
	struct sxe2_txsched_node_props *data;
	struct sxe2_txsched_node_info node_info;

	if (!node)
		return;

	for (i = 0; i < node->child_cnt; i++)
		sxe2_txsched_hw_subtree_dump(adapter, node->child[i]);

	LOG_DEV_INFO("vsi_idx:%#x, hw_layer:%#x, node_teid:%#x, parent_teid:%#x, child_idx:%#x,\t"
		     " num_children:%#x, tc_idx:%#x, type:%#x, pri:%#x, cirwgt:%#x, pirwgt:%#x,\t"
		     " cirbw:%#x, srlpirbw:%#x\n",
		     node->vsi_idx_in_dev, node->info.data.hw_layer,
		     le16_to_cpu(node->info.node_teid),
		     le16_to_cpu(node->info.parent_teid),
		     node->info.sibling_idx,
		     node->child_cnt,
		     node->tc, node->node_type,
		     node->info.data.prio,
		     node->info.data.cir.weight,
		     node->info.data.srlPir.weight,
		     node->info.data.cir.bw,
		     node->info.data.srlPir.bw);

	param.node_teid	       = node->info.node_teid;
	param.parent_teid      = node->info.parent_teid;
	param.node_silbing_idx = (u8)node->info.sibling_idx;
	ret = sxe2_txsched_node_info_query(adapter, &param, &node_info);
	if (ret)
		return;

	data = &node_info.data;
	LOG_DEV_INFO("fw_is_pps:%#x, fw_is_enable:%#x, fw_profile_type:%#x\n",
		     data->arb_mode, data->status, data->rl_type);
	LOG_DEV_INFO("fw_cir_id:%#x, fw_cir_bw:%#x, fw_cir_wgt:%#x,\t"
		     " fw_srl_pir_id:%#x, fw_srl_pir_bw:%#x, fw_srl_pir_wgt:%#x\n",
		     le32_to_cpu(data->cir.prof_id), le32_to_cpu(data->cir.bw),
		     le16_to_cpu(data->cir.weight),
		     le32_to_cpu(data->srlPir.prof_id),
		     le32_to_cpu(data->srlPir.bw),
		     le16_to_cpu(data->srlPir.weight));
}

void sxe2_txsched_tree_dump(struct sxe2_adapter *adapter)
{
	struct sxe2_txsched_context *sched_ctxt = sxe2_txsched_ctxt_get(adapter);

	if (!sxe2_txsched_support_chk(adapter))
		return;

	mutex_lock(&adapter->tx_sched_ctxt.lock);
	sxe2_txsched_hw_subtree_dump(adapter, sched_ctxt->root);
	mutex_unlock(&adapter->tx_sched_ctxt.lock);
}

void sxe2_txsched_sw_tree_dump(struct sxe2_adapter *adapter)
{
	struct sxe2_txsched_context *sched_ctxt = sxe2_txsched_ctxt_get(adapter);

	if (!sxe2_txsched_support_chk(adapter))
		return;

	mutex_lock(&adapter->tx_sched_ctxt.lock);
	sxe2_txsched_sw_subtree_dump(adapter, sched_ctxt->root);
	mutex_unlock(&adapter->tx_sched_ctxt.lock);
}

STATIC s32 sxe2_txsched_ets_query(struct sxe2_adapter *adapter, u8 tc_cnt,
				  struct sxe2_txsched_ets_query_resp *resp)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_txsched_ets_query_rep req;

	req.tc_cnt = tc_cnt;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TX_SCHED_ETS_QUERY, &req,
				  sizeof(req), resp, sizeof(*resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("sched ets query failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

STATIC s32 sxe2_txsched_tc_node_update(struct sxe2_adapter *adapter,
				       struct sxe2_txsched_ets_query_resp *resp)
{
	u8 i, j;
	s32 ret = 0;
	u32 teid1, teid2;
	struct sxe2_txsched_node *tc_node;
	struct sxe2_txsched_node_param param;
	struct sxe2_txsched_context *sched_ctxt = sxe2_txsched_ctxt_get(adapter);

	if (!sched_ctxt->root) {
		LOG_ERROR_BDF("tc node update failed: tx sched root node is null\n");
		return -EBUSY;
	}

	for (i = 0; i < sched_ctxt->root->child_cnt; i++) {
		teid1 = le32_to_cpu(sched_ctxt->root->child[i]->info.node_teid);

		sxe2_for_each_tc(j) {
			teid2 = le32_to_cpu(resp->tc_node[j].teid);
			if (teid1 == teid2)
				break;
		}

		if (j < IEEE_8021QAZ_MAX_TCS)
			continue;

		sched_ctxt->root->child[i]->in_use = false;
	}

	sxe2_for_each_tc(j) {
		teid2 = le32_to_cpu(resp->tc_node[j].teid);
		if (teid2 == SXE2_TXSCHED_TEID_INVALID)
			continue;

		for (i = 0; i < sched_ctxt->root->child_cnt; i++) {
			tc_node = sched_ctxt->root->child[i];
			if (!tc_node)
				continue;

			teid1 = le16_to_cpu(tc_node->info.node_teid);
			if (teid1 == teid2) {
				tc_node->tc	= j;
				tc_node->in_use = true;
				break;
			}
		}

		if (i < sched_ctxt->root->child_cnt)
			continue;

		param.tc	       = j;
		param.node_teid	       = (u16)teid2;
		param.vsi_idx_in_dev   = 0;
		param.owner            = SXE2_TXSCHED_NODE_OWNER_LAN;
		param.sw_layer	       = SXE2_TXSCHED_SW_TC_LAYER;
		param.node_silbing_idx = (u8)resp->tc_node[j].silbing_idx;
		param.parent_teid      = resp->tc_node[j].parent_teid;
		ret = sxe2_txsched_sw_node_add(adapter, &param);
		if (ret) {
			LOG_ERROR_BDF("txsched alloc tc sw node failed, teid=0x%x\n", teid2);
			goto l_err;
		}
	}
l_err:
	return ret;
}

s32 sxe2_txsched_ets_update(struct sxe2_adapter *adapter, u8 tc_cnt)
{
	s32 ret;
	struct sxe2_txsched_ets_query_resp resp = { 0 };

	if (!sxe2_txsched_support_chk(adapter))
		return 0;

	mutex_lock(&adapter->tx_sched_ctxt.lock);

	ret = sxe2_txsched_ets_query(adapter, tc_cnt, &resp);
	if (ret)
		goto l_unlock;

	ret = sxe2_txsched_tc_node_update(adapter, &resp);
	if (ret)
		goto l_unlock;

	LOG_INFO_BDF("dcb sched tc node update success\n");

l_unlock:
	mutex_unlock(&adapter->tx_sched_ctxt.lock);
	return ret;
}

s32 sxe2_txsched_qset_node_move(struct sxe2_adapter *adapter,
				struct sxe2_adapter *new_adapter,
				struct aux_rdma_qset_params *dqset,
				u16 *new_teid, u8 is_aa)

{
	s32 ret;
	u8 old_tc;
	u8 new_tc;
	struct sxe2_txsched_node *node;
	struct sxe2_txsched_context *sched_ctxt = &adapter->tx_sched_ctxt;

	if (!sxe2_txsched_support_chk(adapter))
		goto l_end;

	LOG_INFO("sched rdma node move user_prio %d pf %d(teid %d, qset %d) to pf %d.\n",
		 dqset->user_pri, adapter->pf_idx, dqset->teid, dqset->qset_id,
		 new_adapter->pf_idx);

	mutex_lock(&sched_ctxt->lock);
	node = sxe2_txsched_find_node_by_teid(sched_ctxt->root, dqset->teid);
	mutex_unlock(&sched_ctxt->lock);
	if (!node) {
		*new_teid = dqset->teid;
		LOG_INFO_BDF("sched qset node unexit, dont move\n");
		goto l_end;
	}

	old_tc = sxe2_rdma_aux_get_qset_tc(adapter, dqset);
	ret = sxe2_txsched_qset_node_del(adapter, dqset, old_tc);
	if (ret) {
		LOG_ERROR_BDF("rdma qset move node del failed, ret=%d\n", ret);
		return ret;
	}

	ret = sxe2_txsched_rdma_vsi_cfg(new_adapter->vsi_ctxt.main_vsi, is_aa);
	if (ret) {
		LOG_ERROR_BDF("rdma move vsi cfg failed, ret=%d\n", ret);
		return ret;
	}

	new_tc = sxe2_rdma_aux_get_qset_tc(new_adapter, dqset);
	ret = sxe2_txsched_qset_node_add(new_adapter,
					 new_adapter->vsi_ctxt.main_vsi, dqset, new_tc);
	if (ret) {
		LOG_ERROR_BDF("rdma qset move node add failed, ret=%d\n", ret);
		return ret;
	}

	*new_teid = dqset->teid;

	LOG_INFO_BDF("sched rdma node move user_prio %d \t"
		     "pf %d(teid %d, qset %d) to pf %d(teid %d) success.\n",
		     dqset->user_pri, adapter->pf_idx, dqset->teid, dqset->qset_id,
		     new_adapter->pf_idx, *new_teid);
l_end:
	return 0;
}

s32 sxe2_txsched_qset_node_add(struct sxe2_adapter *adapter,
			       struct sxe2_vsi *vsi,
			       struct aux_rdma_qset_params *qset, u8 tc)
{
	s32 ret;
	u8 q_layer;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_txsched_node *parent;
	struct sxe2_fwc_add_qset_req add_req = {};
	struct sxe2_fwc_add_qset_req *req    = &add_req;
	struct sxe2_fwc_cfg_txq_resp resp;
	struct sxe2_txsched_node_param node_param;
	struct sxe2_txsched_context *sched_ctxt = &adapter->tx_sched_ctxt;

	if (!sxe2_txsched_support_chk(adapter))
		return 0;

	q_layer = sxe2_txsched_sw_q_layer_get();

	mutex_lock(&sched_ctxt->lock);
	if (sched_ctxt->state != SXE2_TX_SCHED_STATE_READY) {
		ret = -EIO;
		goto l_unlock;
	}

	if (vsi->type != SXE2_VSI_T_VF) {
		parent = sxe2_txsched_get_free_qparent(adapter, vsi, tc,
						       SXE2_TXSCHED_NODE_OWNER_RDMA);
	} else {
		parent = sxe2_txsched_get_free_qparent(adapter, vsi, tc,
						       SXE2_TXSCHED_NODE_OWNER_LAN);
	}
	if (!parent) {
		ret = -EINVAL;
		goto l_unlock;
	}

	req->leaf.port		     = adapter->port_idx;
	req->leaf.tc		     = tc;
	req->leaf.txq_idx_in_dev     = qset->qset_id;
	req->leaf.node.parent_teid   = parent->info.node_teid;
	req->leaf.node.data.hw_layer = q_layer + 1;
	req->leaf.node.data.status   = SXE2_NODE_STATUS_ENABLE;
	req->leaf.node.data.arb_mode = SXE2_NODE_ARB_MODE_BPS;
	req->leaf.node.data.rl_type  = SXE2_NODE_RL_TYPE_EIR;
	req->leaf.node.data.cir.bw = SXE2_TXSCHED_DFLT_BW;
	req->leaf.node.data.cir.weight	= SXE2_TXSCHED_ARB_CREDIT_DFLT;
	req->leaf.node.data.cir.prof_id = SXE2_TXSCHED_DFLT_RL_PROF_ID;
	req->leaf.node.data.srlPir.bw	= SXE2_TXSCHED_DFLT_BW;
	req->leaf.node.data.srlPir.weight  = SXE2_TXSCHED_ARB_CREDIT_DFLT;
	req->leaf.node.data.srlPir.prof_id = SXE2_TXSCHED_DFLT_RL_PROF_ID;
	req->leaf.node.data.prio     = 0;
	req->leaf.node.data.adj_lvl = sxe2_txsch_node_adj_lvl_get();

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TX_SCHED_QSET_LEAF_ADD, req,
				  sizeof(*req), &resp, sizeof(resp));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("tx sched txq add failed, ret=%d\n", ret);
		ret = -EIO;
		goto l_unlock;
	}

	node_param.tc		    = tc;
	node_param.sw_layer	    = q_layer;
	node_param.node_teid	    = resp.node_teid;
	node_param.vsi_idx_in_dev   = vsi->idx_in_dev;
	node_param.node_silbing_idx = resp.sibling_idx;
	node_param.parent_teid	    = parent->info.node_teid;
	node_param.txq_idx_in_dev   = req->leaf.txq_idx_in_dev;
	ret = sxe2_txsched_sw_node_add(adapter, &node_param);
	if (ret) {
		LOG_ERROR_BDF("tx sched qset add failed, ret=%d\n", ret);
		goto l_unlock;
	}
	qset->teid = resp.node_teid;

	LOG_INFO_BDF("qset node add success,pf_id:%d, user_pri:%d, \t"
		     "tc:%d,teid:%#x,parent teid:%#x\n",
		     adapter->pf_idx, qset->user_pri, tc,
		     qset->teid, node_param.parent_teid);

l_unlock:
	mutex_unlock(&sched_ctxt->lock);

	return ret;
}

s32 sxe2_txsched_qset_node_del(struct sxe2_adapter *adapter,
			       struct aux_rdma_qset_params *qset, u8 tc)
{
	s32 ret			   = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_txsched_node *node;
	struct sxe2_fwc_del_qset_req req;
	struct sxe2_txsched_context *ctx = &adapter->tx_sched_ctxt;

	if (!sxe2_txsched_support_chk(adapter))
		return 0;

	mutex_lock(&ctx->lock);
	node = sxe2_txsched_find_node_by_teid(ctx->root, qset->teid);
	if (!node) {
		LOG_DEBUG_BDF("sched qset node unexit, dont need del\n");
		goto l_end;
	}

	req.leaf.tc		= tc;
	req.leaf.port		= adapter->port_idx;
	req.leaf.node_teid	= node->info.node_teid;
	req.leaf.parent_teid	= node->info.parent_teid;
	req.leaf.sibling_idx	= (u16)node->info.sibling_idx;
	req.leaf.txq_idx_in_dev = qset->qset_id;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TX_SCHED_QSET_LEAF_DEL, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("sched qset del failed, ret=%d\n", ret);
		ret = 0;
	}

	LOG_DEBUG_BDF("sched qset node del success, pfid:%d, user_pri:%d, \t"
		      "teid:%#x,parent teid:%#x\n",
		      adapter->pf_idx, qset->user_pri, qset->teid, node->info.parent_teid);

	sxe2_txsched_sw_node_del(adapter, node);

l_end:
	mutex_unlock(&ctx->lock);
	return ret;
}

STATIC s32 sxe2_txsched_lan_child_tree_node_del(struct sxe2_adapter *adapter,
						struct sxe2_txsched_node *node,
						u16 not_del_root_teid,
						u8 owner)
{
	u8 i;
	s32 ret = 0;
	u8 q_layer = sxe2_txsched_sw_q_layer_get();

	if (!node)
		return 0;

	i = node->child_cnt;
	while (i) {
		i--;
		ret = sxe2_txsched_lan_child_tree_node_del(adapter,
							   node->child[i],
							   not_del_root_teid, owner);
		if (ret) {
			LOG_ERROR_BDF("sched hw node del(child) failed, teid=%#x, \t"
				      "parent_teid=%#x, sibling_idx=%d\n",
				      node->child[i]->info.node_teid,
				      node->child[i]->parent->info.node_teid,
				      node->child[i]->info.sibling_idx);
			ret = 0;
			goto l_end;
		}
	}

	if (node->info.data.hw_layer > SXE2_TXSCHED_HW_LAYER_TC &&
	    node->owner == owner &&
	    node->info.node_teid != not_del_root_teid) {
		if (node->info.data.hw_layer != (q_layer + 1)) {
			ret = sxe2_tx_sched_hw_node_del(adapter,
							node->parent->info.node_teid,
							(u16)node->info.sibling_idx, 1,
							&node->info.node_teid);
			if (ret) {
				LOG_ERROR_BDF("sched hw node del failed, teid=%#x, \t"
					      "parent_teid=%#x, sibling_idx=%d\n",
					      node->info.node_teid,
					      node->parent->info.node_teid,
					      node->info.sibling_idx);
				ret = 0;
			}
		} else {
			ret = sxe2_tx_sched_hw_lan_leaf_node_del(adapter,
								 node->parent->info.node_teid,
								 (u16)node->info.sibling_idx,
								 node->info.node_teid,
								 node->txq_idx_in_dev);
			if (ret) {
				LOG_ERROR_BDF("sched hw leaf node del failed, teid=%#x, \t"
					      "parent_teid=%#x, sibling_idx=%d idx=%#x\n",
					      node->info.node_teid,
					      node->parent->info.node_teid,
					      node->info.sibling_idx,
					      node->txq_idx_in_dev);
				ret = 0;
			}
		}

		if (!ret)
			sxe2_txsched_sw_node_del(adapter, node);
	}

l_end:
	return ret;
}

s32 sxe2_txsched_rdma_vsi_cfg(struct sxe2_vsi *vsi, u8 is_aa)
{
	s32 ret;
	struct sxe2_txsched_node *vsi_node;
	u32 i, qset[SXE2_MAX_TRAFFIC_CLASS];
	struct sxe2_adapter *adapter = vsi->adapter;

	if (!sxe2_txsched_support_chk(adapter))
		return 0;

	if (vsi->type == SXE2_VSI_T_DPDK_PF || vsi->type == SXE2_VSI_T_DPDK_VF)
		return 0;

	if (is_aa) {
		sxe2_for_each_tc(i) {
			qset[i] = SXE2_AA_MODE_QSET_NUM;
		}
	} else {
		sxe2_for_each_tc(i) {
			qset[i] = IEEE_8021QAZ_MAX_TCS;
		}
	}

	mutex_lock(&adapter->tx_sched_ctxt.lock);
	if (adapter->tx_sched_ctxt.state != SXE2_TX_SCHED_STATE_READY) {
		mutex_unlock(&adapter->tx_sched_ctxt.lock);
		LOG_ERROR_BDF("sched dont ready, state=%d\n",
			      adapter->tx_sched_ctxt.state);
		return -EIO;
	}

	ret = sxe2_txsched_vsi_topo_build(adapter, vsi, qset,
					  SXE2_TXSCHED_NODE_OWNER_RDMA, &vsi_node);
	if (ret) {
		LOG_ERROR_BDF("txsched rdma vsi build failed, ret=%d\n", ret);
	} else {
		sxe2_txsch_vsi_node_map(adapter, vsi,
					SXE2_TXSCHED_NODE_OWNER_RDMA, vsi_node);
	}

	mutex_unlock(&adapter->tx_sched_ctxt.lock);

	return ret;
}

s32 sxe2_txsch_ucmd_root_vsi_cfg(struct sxe2_vsi *vsi, u16 *user_root_teid)
{
	s32 ret;
	u32 q_cnt[SXE2_MAX_TRAFFIC_CLASS];
	struct sxe2_txsched_node *vsi_node;
	u8 owner = SXE2_TXSCHED_NODE_OWNER_USER;
	struct sxe2_adapter *adapter;

	*user_root_teid = SXE2_TXSCHED_TEID_INVALID;

	if (!vsi) {
		LOG_ERROR("ucmd root add params invalid, vsi == NULL\n");
		return -EINVAL;
	}

	adapter = vsi->adapter;

	if (!sxe2_txsched_support_chk(adapter))
		return 0;

	LOG_INFO_BDF("txsch ucmd root add start, vsi_idx=%d\n", vsi->idx_in_dev);

	if (vsi->type != SXE2_VSI_T_DPDK_PF && vsi->type != SXE2_VSI_T_DPDK_VF) {
		LOG_ERROR_BDF("Non-DPDK type vsi, vsi type=%d\n", vsi->type);
		return -EINVAL;
	}

	if (!(vsi->tc.tc_map & BIT(0))) {
		LOG_ERROR_BDF("ucmd vsi build failed, tc0 not map\n");
		return -EINVAL;
	}

	(void)memset(q_cnt, 0, sizeof(u32) * SXE2_MAX_TRAFFIC_CLASS);
	if (vsi->type == SXE2_VSI_T_DPDK_PF)
		q_cnt[0] = SXE2_TX_SCHED_VSI_MAX_TXQ_NUM;
	else if (vsi->type == SXE2_VSI_T_DPDK_VF)
		q_cnt[0] = vsi->tc.info[0].txq_cnt;

	mutex_lock(&adapter->tx_sched_ctxt.lock);

	if (adapter->tx_sched_ctxt.state != SXE2_TX_SCHED_STATE_READY) {
		mutex_unlock(&adapter->tx_sched_ctxt.lock);
		LOG_ERROR_BDF("sched dont ready, state=%d\n",
			      adapter->tx_sched_ctxt.state);
		return -EIO;
	}

	ret = sxe2_txsched_vsi_topo_build(adapter, vsi, q_cnt, owner, &vsi_node);
	if (ret) {
		LOG_ERROR_BDF("txsch ucmd root add failed, vsi_idx=%d, vsi_type=%d, ret=%d\n",
			      vsi->idx_in_dev, vsi->type, ret);
	} else {
		sxe2_txsch_vsi_node_map(adapter, vsi, owner, vsi_node);
		if (vsi->type == SXE2_VSI_T_DPDK_PF) {
			*user_root_teid = vsi_node->parent->info.node_teid;
			adapter->tx_sched_ctxt.user_root_teid = *user_root_teid;
		} else {
			*user_root_teid = vsi_node->info.node_teid;
		}

		LOG_INFO_BDF("txsch ucmd root add, vsi_idx=%d, vsi_teid=%#x, \t"
			     "owner=%d, parent_teid=%#x\n",
			     vsi->idx_in_dev, vsi_node->info.node_teid,
			     vsi_node->owner, vsi_node->parent->info.node_teid);

		LOG_INFO_BDF("txsch ucmd root add success, vsi_idx=%d, root_teid=%#x\n",
			     vsi->idx_in_dev, *user_root_teid);
	}

	mutex_unlock(&adapter->tx_sched_ctxt.lock);

	return ret;
}

s32 sxe2_txsch_ucmd_subtree_del(struct sxe2_adapter *adapter,
				u16 vsi_idx, u16 node_teid,
				bool del_root)
{
	s32 ret = 0;
	u16 no_del_root_teid;
	struct sxe2_vsi *vsi;
	struct sxe2_txsched_node *node;
	struct sxe2_txsched_context *ctxt = &adapter->tx_sched_ctxt;
	u8 q_layer = sxe2_txsched_sw_q_layer_get();

	LOG_INFO_BDF("txsch ucmd root del start, vsi_idx=%d, teid=%#x, del_root=%d\n",
		     vsi_idx, node_teid, del_root);

	if (!sxe2_vsi_id_is_valid(adapter, vsi_idx)) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", vsi_idx);
		return -EINVAL;
	}

	mutex_lock(&ctxt->lock);

	node = sxe2_txsched_find_node_by_teid(ctxt->root, node_teid);
	if (!node) {
		LOG_INFO_BDF("txsch ucmd root node unexit, vsi_idx[%d], teid=%#x\n",
			     vsi_idx, node_teid);
		ret = -EIO;
		goto l_unlock;
	}

	no_del_root_teid = del_root ? SXE2_TXSCHED_TEID_INVALID : node_teid;

	if (sxe2_txsched_is_leaf_node_present(node, q_layer)) {
		ret = sxe2_txsched_lan_child_tree_node_del(adapter, node,
							   no_del_root_teid,
							   SXE2_TXSCHED_NODE_OWNER_USER);
	} else {
		ret = sxe2_txsched_node_del(adapter, node,
					    no_del_root_teid, SXE2_TXSCHED_NODE_OWNER_USER);
	}

	if (ret) {
		LOG_DEBUG_BDF("usr txsch del node failed, vsi_idx=%d, subtree root_teid=%#x\n",
			      vsi_idx, node_teid);
		goto l_unlock;
	}

	vsi = sxe2_vsi_get_by_idx(adapter, vsi_idx);
	if (!vsi)
		goto l_unlock;

	sxe2_txsch_vsi_node_unmap(vsi, SXE2_TXSCHED_NODE_OWNER_USER);

	if (vsi->type == SXE2_VSI_T_DPDK_PF && del_root)
		adapter->tx_sched_ctxt.user_root_teid = SXE2_TXSCHED_TEID_INVALID;

l_unlock:
	mutex_unlock(&ctxt->lock);
	return ret;
}

STATIC struct
sxe2_txsched_node *sxe2_txsched_ucmd_node_create(struct sxe2_adapter *adapter,
						 struct sxe2_vsi *vsi,
						 struct sxe2_txsched_ucmd_node_params *ucmd)
{
	s32 ret = 0;
	u16 num_nodes_added;
	struct sxe2_txsched_node *parent;
	struct sxe2_txsched_node *first_node = NULL;
	struct sxe2_txsch_add_nodes_req nodes_param;
	struct sxe2_txsched_context *ctx = sxe2_txsched_ctxt_get(adapter);

	parent = sxe2_txsched_find_node_by_teid(ctx->root, ucmd->parent_teid);
	if (!parent) {
		LOG_ERROR("ucmd node add: parent node unexit, parent_teid=%#x\n",
			  ucmd->parent_teid);
		return NULL;
	}

	if (parent->child_cnt >= SXE2_TXSCHED_NODE_CHILD_MAX) {
		LOG_ERROR_BDF("ucmd node add: parent children cnt is max, parent_teid = %#x\n",
			      ucmd->parent_teid);
		return NULL;
	}

	nodes_param.num         = 1;
	nodes_param.owner       = SXE2_TXSCHED_NODE_OWNER_USER;
	nodes_param.parent_teid = parent->info.node_teid;
	nodes_param.prio        = ucmd->priority;
	nodes_param.sw_layer    = sxe2_txsch_teid2hwl(parent->info.node_teid);
	nodes_param.tc          = 0;
	nodes_param.weight      = ucmd->weight;
	nodes_param.adj_lvl     = ucmd->adj_lvl;
	ret = sxe2_txsched_nodes_add(adapter, parent,
				     &nodes_param, &first_node, &num_nodes_added);
	if (ret) {
		first_node = NULL;
		LOG_ERROR_BDF("ucmd node create failed, vsi_idx=%d, parent_teid=%#x\n",
			      vsi->idx_in_dev, ucmd->parent_teid);
	} else {
		LOG_INFO_BDF("ucmd node create success, vsi_idx=%d, parent_teid = %#x, teid=%#x\n",
			     vsi->idx_in_dev, ucmd->parent_teid, first_node->info.node_teid);
	}

	return first_node;
}

static bool sxe2_txsch_ucmd_add_node_is_valid(struct sxe2_vsi *vsi,
					      struct sxe2_txsched_ucmd_node_params *params)
{
	struct sxe2_adapter *adapter;

	if (!vsi) {
		LOG_ERROR("invalid vsi=NULL\n");
		return false;
	}

	adapter = vsi->adapter;
	if (!params) {
		LOG_ERROR_BDF("invalid params = NULL\n");
		return false;
	}

	if (params->committed < SXE2_TXSCHED_MIN_BW ||
	    (params->committed > SXE2_TXSCHED_MAX_BW &&
	    params->committed != SXE2_TXSCHED_DFLT_BW)) {
		LOG_ERROR_BDF("cir err, bw must > 500 Kbps, < %u Kbps, usrBw=%u\n",
			      SXE2_TXSCHED_MAX_BW, params->committed);
		return false;
	}

	if (params->peak < SXE2_TXSCHED_MIN_BW ||
	    (params->peak > SXE2_TXSCHED_MAX_BW &&
	    params->peak != SXE2_TXSCHED_DFLT_BW)) {
		LOG_ERROR_BDF("eir err, bw must > 500 Kbps, < %u Kbps, usrBw=%u\n",
			      SXE2_TXSCHED_MAX_BW, params->peak);
		return false;
	}

	if (params->priority >= SXE2_TC_MAX_CNT) {
		LOG_ERROR_BDF("prio err, priority must < 8, usr_prio=%u\n",
			      params->priority);
		return false;
	}

	return true;
}

s32 sxe2_txsched_ucmd_node_add(struct sxe2_vsi *vsi,
			       struct sxe2_txsched_ucmd_node_params *node_params)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter;
	struct sxe2_txsched_context *ctx;
	struct sxe2_txsched_node *node = NULL;

	if (!sxe2_txsch_ucmd_add_node_is_valid(vsi, node_params)) {
		LOG_ERROR("ucmd add node param invalid\n");
		return -EINVAL;
	}

	adapter = vsi->adapter;
	ctx = sxe2_txsched_ctxt_get(adapter);

	LOG_INFO_BDF("ucmd add node, params parent_teid=%#x, node_teid=%#x, \t"
		     "committed=%u, peak=%u, prio=%d, weight=%d\n",
		     node_params->parent_teid, node_params->node_teid,
		     node_params->committed, node_params->peak,
		     node_params->priority, node_params->weight);

	mutex_lock(&ctx->lock);

	node = sxe2_txsched_ucmd_node_create(adapter, vsi, node_params);
	if (!node) {
		ret = -EIO;
		node_params->node_teid = SXE2_TXSCHED_TEID_INVALID;
		LOG_ERROR_BDF("ucmd add node failed, parent_teid=%d\n",
			      node_params->parent_teid);
		goto l_unlock;
	}

	node_params->node_teid = node->info.node_teid;

	ret = sxe2_txsched_node_bw_lmt_cfg(vsi, node, SXE2_NODE_RL_TYPE_CIR,
					   node_params->committed);
	if (ret) {
		LOG_ERROR_BDF("ucmd add node cir failed, teid=%#x, parent_teid=%#x, cir=%u\n",
			      node->info.node_teid,
			      node_params->parent_teid,
			      node_params->committed);
		goto l_unlock;
	}

	ret = sxe2_txsched_node_bw_lmt_cfg(vsi, node, SXE2_NODE_RL_TYPE_EIR,
					   node_params->peak);
	if (ret) {
		LOG_ERROR_BDF("ucmd add node cir failed, teid=%#x, parent_teid=%#x, eir=%u\n",
			      node->info.node_teid,
			      node_params->parent_teid,
			      node_params->peak);
	}

l_unlock:
	mutex_unlock(&ctx->lock);
	return ret;
}

STATIC s32 sxe2_txsch_ucmd_tm_qnode_create(struct sxe2_vsi *vsi,
					   struct sxe2_txsch_ucmd_qnode_params *ucmd,
					   u16 *node_teid)
{
	s32 ret;
	u8 q_layer;
	struct sxe2_cmd_params cmd   = {};
	struct sxe2_txsched_node *parent;
	struct sxe2_fwc_cfg_txq_req req;
	struct sxe2_fwc_cfg_txq_resp resp;
	struct sxe2_queue *txq = vsi->txqs.q[ucmd->queue_id];
	struct sxe2_txsched_node_param node_param;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_txsched_context *ctx = &adapter->tx_sched_ctxt;

	if (!sxe2_txsched_support_chk(adapter))
		return 0;

	if (ctx->state != SXE2_TX_SCHED_STATE_READY) {
		LOG_ERROR_BDF("txsch ucmd tm qnode add : txsch not ready\n");
		return -EIO;
	}

	parent = sxe2_txsched_find_node_by_teid(ctx->root, ucmd->parent_teid);
	if (!parent) {
		LOG_ERROR_BDF("txsch ucmd tm qnode add: parent node is invalid parent_teid=%#x\n",
			      ucmd->parent_teid);
		return -EINVAL;
	}

	if ((parent->child_cnt + 1) > SXE2_TXSCHED_NODE_CHILD_MAX) {
		LOG_ERROR_BDF("txsch ucmd tm qnode add: vsi[%u] parent node are not enough slot, \t"
			      "parent_teid=%#x, parent->child_cnt=%u, need_node=1\n",
			      vsi->idx_in_dev, parent->info.node_teid,
			      parent->child_cnt);

		return -ENOSPC;
	}

	q_layer = sxe2_txsched_sw_q_layer_get();
	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req.leaf.tc   = 0;
	req.leaf.port = adapter->port_idx;
	req.leaf.txq_idx_in_dev = txq->idx_in_pf +
				   adapter->q_ctxt.txq_base_idx_in_dev;
	req.leaf.node.parent_teid	   = parent->info.node_teid;
	req.leaf.node.data.hw_layer	   = q_layer + 1;
	req.leaf.node.data.prio		   = ucmd->priority;
	req.leaf.node.data.status	   = SXE2_NODE_STATUS_ENABLE;
	req.leaf.node.data.arb_mode	   = SXE2_NODE_ARB_MODE_BPS;
	req.leaf.node.data.rl_type	   = SXE2_NODE_RL_TYPE_EIR;
	req.leaf.node.data.cir.bw	   = ucmd->committed;
	req.leaf.node.data.cir.weight	   = ucmd->weight;
	req.leaf.node.data.cir.prof_id	   = SXE2_TXSCHED_DFLT_RL_PROF_ID;
	req.leaf.node.data.srlPir.bw	   = ucmd->peak;
	req.leaf.node.data.srlPir.weight   = ucmd->weight;
	req.leaf.node.data.srlPir.prof_id  = SXE2_TXSCHED_DFLT_RL_PROF_ID;
	req.leaf.node.data.adj_lvl         = ucmd->adj_lvl;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_TX_SCHED_QUEUE_LEAF_ADD, &req,
				  sizeof(req), &resp, sizeof(resp));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("txsch ucmd tm hw qnode add failed, vsi[%d] parent_teid=%#x, \t"
			      "parent->child_cnt=%u, ret=%d\n",
			      vsi->idx_in_dev, parent->info.node_teid,
			      parent->child_cnt, ret);
		return -EIO;
	}

	node_param.tc		    = 0;
	node_param.owner            = SXE2_TXSCHED_NODE_OWNER_USER;
	node_param.sw_layer	    = q_layer;
	node_param.node_teid	    = resp.node_teid;
	node_param.vsi_idx_in_dev   = vsi->idx_in_dev;
	node_param.txq_idx_in_vsi   = txq->idx_in_vsi;
	node_param.node_silbing_idx = resp.sibling_idx;
	node_param.parent_teid	    = parent->info.node_teid;
	node_param.txq_idx_in_dev   = req.leaf.txq_idx_in_dev;
	ret = sxe2_txsched_sw_node_add(adapter, &node_param);
	if (ret) {
		LOG_ERROR_BDF("txsch ucmd tm sw qnode add failed, vsi[%d] parent_teid=%#x, \t"
			      "parent->child_cnt=%u, ret=%d\n",
			      vsi->idx_in_dev, parent->info.node_teid,
			      parent->child_cnt, ret);
		return ret;
	}
	txq->txq_teid = resp.node_teid;
	*node_teid = resp.node_teid;

	LOG_DEBUG_BDF("txq node add success,teid:%#x,parent teid:%#x\n",
		      txq->txq_teid, node_param.parent_teid);

	return ret;
}

static bool sxe2_txsch_ucmd_add_txq_node_is_valid(struct sxe2_vsi *vsi,
						  struct sxe2_txsch_ucmd_qnode_params *params)
{
	struct sxe2_adapter *adapter;

	if (!vsi) {
		LOG_ERROR("invalid vsi=NULL\n");
		return false;
	}

	adapter = vsi->adapter;
	if (!params) {
		LOG_ERROR_BDF("invalid params = NULL\n");
		return false;
	}

	if (params->committed < SXE2_TXSCHED_MIN_BW ||
	    (params->committed > SXE2_TXSCHED_MAX_BW &&
	    params->committed != SXE2_TXSCHED_DFLT_BW)) {
		LOG_ERROR_BDF("cir err, bw must > 500 Kbps, < %u Kbps, usrBw=%u\n",
			      SXE2_TXSCHED_MAX_BW, params->committed);
		return false;
	}

	if (params->peak < SXE2_TXSCHED_MIN_BW ||
	    (params->peak > SXE2_TXSCHED_MAX_BW &&
	    params->peak != SXE2_TXSCHED_DFLT_BW)) {
		LOG_ERROR_BDF("eir err, bw must > 500 Kbps, < %u Kbps, usrBw=%u\n",
			      SXE2_TXSCHED_MAX_BW, params->peak);
		return false;
	}

	if (params->priority >= SXE2_TC_MAX_CNT) {
		LOG_ERROR_BDF("prio err, priority must < 8, usr_prio=%u\n",
			      params->priority);
		return false;
	}

	if (params->queue_id > vsi->txqs.q_cnt) {
		LOG_ERROR_BDF("txq id:%u invalid, max:%u vsi_id:%d\n",
			      params->queue_id, vsi->txqs.q_cnt, vsi->idx_in_dev);
		return false;
	}

	if (params->adj_lvl > SXE2_TXSCH_NODE_ADJ_LVL_MAX) {
		LOG_ERROR_BDF("adj lvl:%u invalid, max:%u vsi_id:%d\n",
			      params->adj_lvl, SXE2_TXSCH_NODE_ADJ_LVL_MAX,
			      vsi->idx_in_dev);
		return false;
	}

	return true;
}

s32 sxe2_txsched_ucmd_qnode_add(struct sxe2_vsi *vsi,
				struct sxe2_txsch_ucmd_qnode_params *node_params)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter;
	struct sxe2_txsched_context *ctx;
	struct sxe2_txsched_node *node = NULL;
	u16 node_teid;

	if (!sxe2_txsch_ucmd_add_txq_node_is_valid(vsi, node_params)) {
		LOG_ERROR("ucmd add txq node param invalid\n");
		return -EINVAL;
	}

	adapter = vsi->adapter;
	ctx = sxe2_txsched_ctxt_get(adapter);

	LOG_INFO_BDF("ucmd add tm queue node, params parent_teid=%#x, \t"
		     "node_teid=%#x committed=%u, peak=%u, prio=%d, weight=%u, qidx=%u\n",
		     node_params->parent_teid, node_params->node_teid,
		     node_params->committed, node_params->peak,
		     node_params->priority, node_params->weight,
		     node_params->queue_id);

	mutex_lock(&ctx->lock);

	ret = sxe2_txsch_ucmd_tm_qnode_create(vsi, node_params, &node_teid);
	if (ret) {
		node_params->node_teid = SXE2_TXSCHED_TEID_INVALID;
		LOG_ERROR_BDF("txsch ucmd tm qnode add failed\n");
		goto l_unlock;
	}

	node_params->node_teid = node_teid;

	node = sxe2_txsched_find_node_by_teid(ctx->root, node_teid);
	if (!node) {
		ret = -EIO;
		LOG_ERROR_BDF("txsch ucmd tm qnode add : \t"
			      "find node failed, parent_teid=%#x, teid=%#x\n",
			      node_params->parent_teid, node_params->node_teid);
		goto l_unlock;
	}

	ret = sxe2_txsched_node_bw_lmt_cfg(vsi, node, SXE2_NODE_RL_TYPE_CIR,
					   node_params->committed);
	if (ret) {
		LOG_ERROR_BDF("txsch ucmd tm qnode add : cir cfg failed, \t"
			      "parent_teid=%#x, teid=%#x, cir=%u\n",
			      node_params->parent_teid,
			      node_params->node_teid,
			      node_params->committed);
		goto l_unlock;
	}

	ret = sxe2_txsched_node_bw_lmt_cfg(vsi, node, SXE2_NODE_RL_TYPE_EIR,
					   node_params->peak);
	if (ret) {
		LOG_ERROR_BDF("txsch ucmd tm qnode add : eir cfg failed, \t"
			      "parent_teid=%#x, teid=%#x, eir=%u\n",
			      node_params->parent_teid,
			      node_params->node_teid,
			      node_params->peak);
	}

l_unlock:
	mutex_unlock(&ctx->lock);
	return ret;
}
