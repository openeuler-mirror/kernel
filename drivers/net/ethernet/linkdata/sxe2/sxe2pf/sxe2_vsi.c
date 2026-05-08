// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_vsi.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/if_bridge.h>
#include <linux/bitmap.h>

#include "sxe2_compat.h"
#include "sxe2_tx.h"
#include "sxe2_rx.h"
#include "sxe2_vsi.h"
#include "sxe2_log.h"
#include "sxe2_dcb.h"
#include "sxe2_common.h"
#include "sxe2_netdev.h"
#include "sxe2_txsched.h"
#include "sxe2_rss.h"
#include "sxe2_sriov.h"
#include "sxe2_eswitch.h"
#include "sxe2_switch.h"
#include "sxe2_xsk.h"
#include "sxe2_linkchg.h"
#include "sxe2_txsched.h"
#include "sxe2_com_vlan.h"
#ifndef NOT_HAVE_MINMAX_H
#include <linux/minmax.h>
#endif
#include "sxe2_acl.h"
#include "sxe2_com_ioctl.h"

#define SXE2_IRQ_NAME_STR_LEN (IFNAMSIZ + 32)

struct sxe2_vsi *sxe2_vsi_create(struct sxe2_adapter *adapter,
				 struct sxe2_vsi_cfg_params *vsi_create);

bool sxe2_vsi_id_is_valid(struct sxe2_adapter *adapter, u16 vsi_id)
{
	if ((vsi_id >=
	     (adapter->vsi_ctxt.max_cnt + adapter->vsi_ctxt.base_idx_in_dev)) ||
	    vsi_id < adapter->vsi_ctxt.base_idx_in_dev) {
		return false;
	} else {
		return true;
	}
}

STATIC void sxe2_mac_addr_clear(struct sxe2_vsi *vsi)
{
	struct sxe2_addr_node *node;
	struct sxe2_addr_node *tmp;

	list_for_each_entry_safe(node, tmp, &vsi->mac_filter.mac_addr_list, list) {
		sxe2_switch_mac_node_del_and_free(node);
	}
}

u16 sxe2_vsi_get(struct sxe2_vsi_context *vsi_ctxt)
{
	u16 next = SXE2_INVAL_U16;
	struct sxe2_vsi **array = vsi_ctxt->vsi;
	u16 size = vsi_ctxt->max_cnt;
	u16 curr = vsi_ctxt->next_vsi_id;

	for (; curr < size; curr++) {
		if (!array[curr]) {
			next = curr;
			vsi_ctxt->next_vsi_id = curr + 1;
			break;
		}
	}

	if (next != SXE2_INVAL_U16)
		vsi_ctxt->cnt++;

	return next;
}

void sxe2_vsi_put(struct sxe2_vsi_context *vsi_ctxt, u16 vsi_id)
{
	if (vsi_id > vsi_ctxt->max_cnt - 1) {
		LOG_ERROR("invali vsi id:%d max cnt:%d\n", vsi_id,
			  vsi_ctxt->max_cnt);
		return;
	}

	vsi_ctxt->vsi[vsi_id] = NULL;

	if (vsi_id < vsi_ctxt->next_vsi_id)
		vsi_ctxt->next_vsi_id = vsi_id;

	vsi_ctxt->cnt--;
}

STATIC s32 sxe2_vsi_qs_stats_num_set(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;

	switch (vsi->type) {
	case SXE2_VSI_T_PF:
	case SXE2_VSI_T_DPDK_PF:
		vsi->vsi_qs_stats.vsi_qs_stats_maxcnt = (u16)SXE2_VSI_TXRX_Q_MAX_CNT;
		break;

	case SXE2_VSI_T_LB:
		vsi->vsi_qs_stats.vsi_qs_stats_maxcnt = 1;
		break;

	case SXE2_VSI_T_VF:
	case SXE2_VSI_T_DPDK_VF:
		vsi->vsi_qs_stats.vsi_qs_stats_maxcnt = SXE2_VF_RSS_Q_NUM;
		break;

	case SXE2_VSI_T_MACVLAN:
		vsi->vsi_qs_stats.vsi_qs_stats_maxcnt = SXE2_DFLT_TXQ_VMDQ_VSI;
		break;

	case SXE2_VSI_T_CTRL:
		vsi->vsi_qs_stats.vsi_qs_stats_maxcnt = 1;
		break;
	case SXE2_VSI_T_ESW:
	case SXE2_VSI_T_DPDK_ESW:
		vsi->vsi_qs_stats.vsi_qs_stats_maxcnt = SXE2_VF_NUM;
		break;
	default:
		LOG_DEV_WARN("unknown vsi type: %d\n", vsi->type);
		ret = -EINVAL;
		goto l_end;
	}

	LOG_DEBUG_BDF("vsi id:%u type:%u set qs stats num: %d.\n", vsi->id_in_pf,
		      vsi->type, vsi->vsi_qs_stats.vsi_qs_stats_maxcnt);

l_end:
	return ret;
}

STATIC struct sxe2_vsi *sxe2_vsi_init(struct sxe2_adapter *adapter,
				      struct sxe2_vsi_cfg_params *vsi_create)
{
	struct sxe2_vsi *vsi = NULL;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	if (adapter->vsi_ctxt.cnt >= adapter->vsi_ctxt.max_cnt) {
		LOG_DEV_ERR("alloc vsi failed: Reach the limit of max_vsi %d.\n",
			    adapter->vsi_ctxt.max_cnt);
		goto l_end;
	}

	vsi = devm_kzalloc(dev, sizeof(*vsi), GFP_KERNEL);
	if (!vsi) {
		LOG_DEV_ERR("alloc vsi struct failed.\n");
		goto l_end;
	}

	vsi->idx_in_dev = SXE2_INVAL_U16;
	vsi->src_prune.vsi_id_u = SXE2_VSI_ID_INVALID;
	vsi->src_prune.vsi_id_k = SXE2_VSI_ID_INVALID;
	vsi->type = vsi_create->type;
	vsi->vf_node = vsi_create->vf;
	vsi->adapter = adapter;

	if (vsi_create->type == SXE2_VSI_T_VF ||
	    vsi_create->type == SXE2_VSI_T_DPDK_VF) {
		vsi->txqs.q_cnt = vsi_create->txq_cnt;
		vsi->rxqs.q_cnt = vsi_create->rxq_cnt;
		vsi->irqs.cnt = vsi_create->irq_cnt;
		vsi->id_in_pf = (u16)(vsi_create->vsi_id -
				      adapter->vsi_ctxt.base_idx_in_dev);
		vsi->txqs.base_idx_in_feature = vsi_create->txq_base_idx;
		vsi->rxqs.base_idx_in_feature = vsi_create->rxq_base_idx;
		vsi->irqs.base_idx_in_feature = vsi_create->irq_base_idx;
	}

	if (sxe2_vsi_qs_stats_num_set(vsi))
		goto l_err;

	set_bit(SXE2_VSI_S_DOWN, vsi->state);
	set_bit(SXE2_VSI_S_CLOSE, vsi->state);

	if (vsi_create->type != SXE2_VSI_T_VF &&
	    vsi_create->type != SXE2_VSI_T_DPDK_VF) {
		vsi->id_in_pf = sxe2_vsi_get(&adapter->vsi_ctxt);
		if (vsi->id_in_pf == SXE2_INVAL_U16) {
			LOG_DEV_ERR("No Free Vsis.\n");
			goto l_err;
		}
	}

	vsi->idx_in_dev = vsi->id_in_pf + adapter->vsi_ctxt.base_idx_in_dev;

	adapter->vsi_ctxt.vsi[vsi->id_in_pf] = vsi;

	INIT_LIST_HEAD(&vsi->mac_filter.mac_addr_list);
	mutex_init(&vsi->mac_filter.sync_lock);

	return vsi;

l_err:
	devm_kfree(dev, vsi);
	vsi = NULL;

l_end:
	return vsi;
}

STATIC void sxe2_vsi_deinit(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter;
	struct device *dev;
	u16 idx_in_pf = vsi->id_in_pf;

	sxe2_vsi_fltr_clean(vsi);

	adapter = vsi->adapter;
	dev = SXE2_ADAPTER_TO_DEV(adapter);

	sxe2_mac_addr_clear(vsi);

	if (vsi->type != SXE2_VSI_T_VF && vsi->type != SXE2_VSI_T_DPDK_VF)
		sxe2_vsi_put(&adapter->vsi_ctxt, vsi->id_in_pf);

	devm_kfree(dev, vsi);

	if (idx_in_pf < adapter->vsi_ctxt.max_cnt)
		adapter->vsi_ctxt.vsi[idx_in_pf] = NULL;
}

STATIC s32 sxe2_vsi_queues_num_set(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;

	switch (vsi->type) {
	case SXE2_VSI_T_PF:
		if (vsi->txqs.req_q_cnt)
			vsi->txqs.q_cnt = vsi->txqs.req_q_cnt;
		else
			vsi->txqs.q_cnt = adapter->q_ctxt.txq_layout.lan;

		if (vsi->rxqs.req_q_cnt)
			vsi->rxqs.q_cnt = vsi->rxqs.req_q_cnt;
		else
			vsi->rxqs.q_cnt = adapter->q_ctxt.rxq_layout.lan;
		break;
	case SXE2_VSI_T_LB:
		vsi->txqs.q_cnt = 1;
		vsi->rxqs.q_cnt = 1;
		break;

	case SXE2_VSI_T_VF:
	case SXE2_VSI_T_DPDK_VF:
		LOG_DEBUG_BDF("vsi id:%u type:%u queue cnt %d %d already set.\n",
			      vsi->id_in_pf, vsi->type, vsi->txqs.q_cnt,
			      vsi->rxqs.q_cnt);
		break;

	case SXE2_VSI_T_MACVLAN:
		vsi->txqs.q_cnt = SXE2_DFLT_TXQ_VMDQ_VSI;
		vsi->rxqs.q_cnt = SXE2_DFLT_RXQ_VMDQ_VSI;
		break;

	case SXE2_VSI_T_CTRL:
		vsi->txqs.q_cnt = 1;
		vsi->rxqs.q_cnt = 1;
		break;
	case SXE2_VSI_T_ESW:
		vsi->txqs.q_cnt = sxe2_vf_num_get(adapter);
		vsi->rxqs.q_cnt = vsi->txqs.q_cnt;
		break;
	case SXE2_VSI_T_DPDK_PF:
		vsi->txqs.q_cnt = adapter->q_ctxt.txq_layout.dpdk;
		vsi->rxqs.q_cnt = adapter->q_ctxt.rxq_layout.dpdk;
		break;
	case SXE2_VSI_T_DPDK_ESW:
		vsi->txqs.q_cnt = sxe2_vf_num_get(adapter);
		vsi->rxqs.q_cnt = vsi->txqs.q_cnt;
		break;
	default:
		LOG_DEV_WARN("unknown vsi type: %d\n", vsi->type);
		ret = -EINVAL;
		goto l_end;
	}

	vsi->txqs.q_alloc = vsi->txqs.q_cnt;
	vsi->rxqs.q_alloc = vsi->rxqs.q_cnt;

	if (vsi->txqs.q_cnt == 0 || vsi->rxqs.q_cnt == 0) {
		LOG_DEV_ERR("vsi set queues num failed: txq alloced %d, rxq alloced \t"
			    "%d.\n",
			    vsi->txqs.q_cnt, vsi->rxqs.q_cnt);
		ret = -ENOMEM;
	}

	LOG_DEBUG_BDF("vsi id:%u type:%u set queues num: txq alloced %d, rxq \t"
		      "alloced %d.\n",
		      vsi->id_in_pf, vsi->type, vsi->txqs.q_cnt, vsi->rxqs.q_cnt);

l_end:
	return ret;
}

STATIC s32 sxe2_vsi_irqs_num_set(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	u16 max_q_cnt = 0;

	switch (vsi->type) {
	case SXE2_VSI_T_PF:
		max_q_cnt = (u16)max(vsi->txqs.q_cnt, vsi->rxqs.q_cnt);
		vsi->irqs.cnt = (u16)min(adapter->irq_ctxt.irq_layout.lan,
					 max_q_cnt);
		break;
	case SXE2_VSI_T_DPDK_PF:
		vsi->irqs.cnt = adapter->irq_ctxt.irq_layout.dpdk;
		break;
	case SXE2_VSI_T_LB:
		vsi->irqs.cnt = SXE2_LB_RXQ_MSIX_CNT;
		break;
	case SXE2_VSI_T_VF:
	case SXE2_VSI_T_DPDK_VF:
		LOG_DEBUG_BDF("vsi id:%u type:%u irq cnt %d already set.\n",
			      vsi->id_in_pf, vsi->type, vsi->irqs.cnt);
		break;
	case SXE2_VSI_T_MACVLAN:
		vsi->irqs.cnt = SXE2_DFLT_VEC_VMDQ_VSI;
		break;
	case SXE2_VSI_T_CTRL:
		vsi->irqs.cnt = SXE2_FNAV_MSIX_CNT;
		break;
	case SXE2_VSI_T_ESW:
		vsi->irqs.cnt = SXE2_ESWITCH_MSIX_CNT;
		break;
	case SXE2_VSI_T_DPDK_ESW:
		vsi->irqs.cnt = SXE2_DPDK_ESWITCH_MSIX_CNT;
		break;
	default:
		LOG_DEV_WARN("unknown vsi type: %d, qcnt: %d\n", vsi->type,
			     max_q_cnt);
		ret = -EINVAL;
		goto l_end;
	}

	if (vsi->irqs.cnt == 0) {
		LOG_DEV_ERR("vsi set irqs num failed: irq cnt %d.\n", vsi->irqs.cnt);
		ret = -ENOMEM;
	}

l_end:
	return ret;
}

STATIC void sxe2_vsi_queues_free(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u16 i;

	if (vsi->af_xdp_zc_qps) {
		bitmap_free(vsi->af_xdp_zc_qps);
		vsi->af_xdp_zc_qps = NULL;
	}

	if (vsi->rxqs.q) {
		sxe2_for_each_vsi_alloc_rxq(vsi, i)
		{
			if (vsi->rxqs.q[i]) {
				kfree_rcu(vsi->rxqs.q[i], rcu);
				WRITE_ONCE(vsi->rxqs.q[i], NULL);
			}
		}
		devm_kfree(dev, vsi->rxqs.q);
		vsi->rxqs.q = NULL;
	}

	if (vsi->txqs.q) {
		sxe2_for_each_vsi_alloc_txq(vsi, i)
		{
			if (vsi->txqs.q[i]) {
				kfree_rcu(vsi->txqs.q[i], rcu);
				WRITE_ONCE(vsi->txqs.q[i], NULL);
			}
		}
		devm_kfree(dev, vsi->txqs.q);
		vsi->txqs.q = NULL;
	}

	if (vsi->origin_txqs) {
		devm_kfree(dev, vsi->origin_txqs);
		vsi->origin_txqs = NULL;
	}

	if (vsi->xdp_rings.q) {
		for (i = 0; i < vsi->num_xdp_txq; i++) {
			if (vsi->xdp_rings.q[i]) {
				kfree_rcu(vsi->xdp_rings.q[i], rcu);
				WRITE_ONCE(vsi->xdp_rings.q[i], NULL);
			}
		}

		devm_kfree(dev, vsi->xdp_rings.q);
		vsi->xdp_rings.q = NULL;
	}
}

STATIC void sxe2_vsi_irqs_data_free(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u16 i;

	if (vsi->irqs.irq_data) {
		sxe2_for_each_vsi_irq(vsi, i)
		{
			if (vsi->irqs.irq_data[i]) {
				devm_kfree(dev, vsi->irqs.irq_data[i]);
				vsi->irqs.irq_data[i] = NULL;
			}
		}
		devm_kfree(dev, vsi->irqs.irq_data);
		vsi->irqs.irq_data = NULL;
	}
}

STATIC s32 sxe2_vsi_queues_alloc(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_queue *q;
	u16 i;

	vsi->txqs.q = devm_kcalloc(dev, vsi->txqs.q_alloc, sizeof(*vsi->txqs.q),
				   GFP_KERNEL);
	if (!vsi->txqs.q) {
		ret = -ENOMEM;
		LOG_DEV_ERR("alloc txqs failed, count: %d, size: %zu.\n",
			    vsi->txqs.q_alloc, sizeof(*vsi->txqs.q));
		goto l_failed;
	}

	vsi->rxqs.q = devm_kcalloc(dev, vsi->rxqs.q_alloc, sizeof(*vsi->rxqs.q),
				   GFP_KERNEL);
	if (!vsi->rxqs.q) {
		ret = -ENOMEM;
		LOG_DEV_ERR("alloc rxqs failed, count: %d, size: %zu.\n",
			    vsi->rxqs.q_alloc, sizeof(*vsi->rxqs.q));
		goto l_failed;
	}

	sxe2_for_each_vsi_alloc_txq(vsi, i)
	{
		q = kzalloc(sizeof(*q), GFP_KERNEL);
		if (!q) {
			ret = -ENOMEM;
			goto l_failed;
		}
		q->vsi = vsi;
		q->idx_in_vsi = i;
		q->idx_in_pf = SXE2_Q_IDX_INVAL;
		q->dev = dev;
		q->depth = vsi->txqs.depth;
		u64_stats_init(&q->syncp);
		WRITE_ONCE(vsi->txqs.q[i], q);
	}

	sxe2_for_each_vsi_alloc_rxq(vsi, i)
	{
		q = kzalloc(sizeof(*q), GFP_KERNEL);
		if (!q) {
			ret = -ENOMEM;
			goto l_failed;
		}
		q->vsi = vsi;
		q->idx_in_vsi = i;
		q->idx_in_pf = SXE2_Q_IDX_INVAL;
		q->dev = dev;
		q->depth = vsi->rxqs.depth;
		u64_stats_init(&q->syncp);
		WRITE_ONCE(vsi->rxqs.q[i], q);
	}
	vsi->af_xdp_zc_qps = bitmap_zalloc((unsigned int)max(vsi->rxqs.q_cnt, vsi->txqs.q_cnt),
					   GFP_KERNEL);
	if (!vsi->af_xdp_zc_qps) {
		ret = -ENOMEM;
		goto l_failed;
	}

	return ret;

l_failed:
	sxe2_vsi_queues_free(vsi);
	return ret;
}

STATIC s32 sxe2_vsi_irq_data_alloc(struct sxe2_vsi *vsi, u16 idx)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_irq_data *irq_data;

	irq_data = devm_kzalloc(dev, sizeof(*irq_data), GFP_KERNEL);
	if (!irq_data) {
		LOG_DEV_ERR("irq_data alloc failed.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	irq_data->vsi = vsi;
	irq_data->idx_in_vsi = idx;
	irq_data->idx_in_pf = SXE2_IRQ_IDX_INVAL;

	vsi->irqs.irq_data[idx] = irq_data;

l_end:
	return ret;
}

STATIC s32 sxe2_vsi_irqs_data_alloc(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u16 i;

	vsi->irqs.irq_data = devm_kcalloc(dev, vsi->irqs.cnt,
					  sizeof(*vsi->irqs.irq_data), GFP_KERNEL);
	if (!vsi->irqs.irq_data) {
		ret = -ENOMEM;
		LOG_DEV_ERR("alloc irq_data failed, count: %d, size: %zu.\n",
			    vsi->irqs.cnt, sizeof(*vsi->irqs.irq_data));
		goto l_end;
	}

	sxe2_for_each_vsi_irq(vsi, i)
	{
		ret = sxe2_vsi_irq_data_alloc(vsi, i);
		if (ret)
			goto l_failed;
	}

	return ret;

l_failed:
	sxe2_vsi_irqs_data_free(vsi);
l_end:
	return ret;
}

STATIC void sxe2_vsi_rxqs_info_trans(struct sxe2_vsi *vsi,
				     struct sxe2_fwc_vsi_crud_info *info)
{
	struct sxe2_fwc_vsi_q_info *q_info = &info->props.rxq_info;
	struct sxe2_vsi_queues *qs = &vsi->rxqs;

	q_info->cnt = cpu_to_le16(qs->q_cnt);
	q_info->base_idx = cpu_to_le16(qs->q[0]->idx_in_pf);

	info->props.rxq_valid = 1;
}

STATIC void sxe2_vsi_txqs_info_trans(struct sxe2_vsi *vsi,
				     struct sxe2_fwc_vsi_crud_info *info)
{
	struct sxe2_fwc_vsi_q_info *q_info = &info->props.txq_info;
	struct sxe2_vsi_queues *qs = &vsi->txqs;

	q_info->cnt = cpu_to_le16(qs->q_cnt);
	q_info->base_idx = cpu_to_le16(qs->q[0]->idx_in_pf);
}

STATIC void sxe2_vsi_base_info_trans(struct sxe2_vsi *vsi,
				     struct sxe2_fwc_vsi_crud_info *info)
{
	info->vsi_id = cpu_to_le16(vsi->idx_in_dev);

	switch (vsi->type) {
	case SXE2_VSI_T_PF:
	case SXE2_VSI_T_LB:
	case SXE2_VSI_T_CTRL:
	case SXE2_VSI_T_DPDK_PF:
		info->type = SXE2_VSI_HW_T_PF;
		break;
	case SXE2_VSI_T_VF:
	case SXE2_VSI_T_DPDK_VF:
		info->type = SXE2_VSI_HW_T_VF;
		info->vf_id = cpu_to_le16(vsi->vf_node->vf_idx);
		break;
	case SXE2_VSI_T_MACVLAN:
	case SXE2_VSI_T_ESW:
	case SXE2_VSI_T_DPDK_ESW:
		info->type = SXE2_VSI_HW_T_VMDQ2;
		break;
	default:
		break;
	}
}

static void sxe2_vsi_tc_rxqs_info_trans(struct sxe2_vsi *vsi,
					struct sxe2_fwc_vsi_crud_info *info)
{
	u32 i;

	sxe2_for_each_tc(i)
	{
		if (vsi->type == SXE2_VSI_T_VF) {
			info->props.rxq_info.tc_q_map[i].offset =
					vsi->tc.info[0].rxq_offset;
			info->props.rxq_info.tc_q_map[i].pow =
					(u16)order_base_2(vsi->tc.info[0].rxq_cnt);
		} else {
			info->props.rxq_info.tc_q_map[i].offset =
					vsi->tc.info[i].rxq_offset;
			info->props.rxq_info.tc_q_map[i].pow =
					(u16)order_base_2(vsi->tc.info[i].rxq_cnt);
		}
	}
}

static void sxe2_vsi_fnav_info_trans(struct sxe2_vsi *vsi,
				     struct sxe2_fwc_vsi_crud_info *info)
{
	if (vsi->type != SXE2_VSI_T_PF && vsi->type != SXE2_VSI_T_VF &&
	    vsi->type != SXE2_VSI_T_CTRL && vsi->type != SXE2_VSI_T_DPDK_PF &&
	    vsi->type != SXE2_VSI_T_DPDK_VF) {
		return;
	}
	info->props.fnav_info.gsize = vsi->fnav.space_gsize;
	info->props.fnav_info.bsize = vsi->fnav.space_bsize;
	info->props.fnav_info.fnav_enable = 1;
	info->props.fnav_info.auto_evict = 0;
	info->props.fnav_info.prog_enable = 1;
}

STATIC void sxe2_vsi_info_trans(struct sxe2_vsi *vsi,
				struct sxe2_fwc_vsi_crud_info *info)
{
	sxe2_vsi_base_info_trans(vsi, info);

	sxe2_vsi_rxqs_info_trans(vsi, info);

	sxe2_vsi_txqs_info_trans(vsi, info);

	sxe2_vsi_tc_rxqs_info_trans(vsi, info);

	sxe2_vsi_fnav_info_trans(vsi, info);
}

STATIC s32 sxe2_fwc_vsi_cfg(struct sxe2_adapter *adapter,
			    struct sxe2_fwc_vsi_crud_info *info)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_VSI_CFG, info, sizeof(*info), NULL,
				  0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_DEV_ERR("add vsi failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

STATIC s32 sxe2_vsi_hw_decfg(struct sxe2_adapter *adapter, u16 vsi_id)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_vsi_crud_info info = {};

	info.vsi_id = cpu_to_le16(vsi_id);
	info.is_clear = true;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_VSI_CFG, &info, sizeof(info), NULL,
				  0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_DEV_ERR("del vsi(%d in device) failed, ret=%d\n", vsi_id, ret);
		ret = -EIO;
	}

	return ret;
}

STATIC s32 sxe2_vsi_hw_cfg(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_fwc_vsi_crud_info info = {};
	struct sxe2_adapter *adapter = vsi->adapter;

	sxe2_vsi_info_trans(vsi, &info);

	ret = sxe2_fwc_vsi_cfg(adapter, &info);
	if (ret)
		goto l_end;

l_end:
	return ret;
}

void sxe2_queue_add(struct sxe2_queue *queue, struct sxe2_list *head)
{
	struct sxe2_adapter *adapter = queue->vsi->adapter;

	if (queue->next) {
		LOG_WARN_BDF("queue[%d][%d] next pointer is not NULL",
			     queue->idx_in_vsi, queue->idx_in_pf);
	}

	queue->next = head->next;
	head->next = queue;
	head->cnt++;
}

STATIC void sxe2_map_txq_to_irq(struct sxe2_vsi *vsi, u16 cnt, u16 q_idx,
				u16 irq_idx)
{
	struct sxe2_queue *queue;
	struct sxe2_irq_data *irq_data = vsi->irqs.irq_data[irq_idx];
	struct sxe2_adapter *adapter = vsi->adapter;

	irq_data->tx.list.cnt = 0;
	irq_data->tx.list.next = NULL;

	while (cnt) {
		queue = vsi->txqs.q[q_idx];
		queue->irq_data = irq_data;
		sxe2_queue_add(queue, &irq_data->tx.list);
		cnt--;
		q_idx++;
		LOG_INFO_BDF("map txq=%d  to irq=%d\n", q_idx, irq_idx);
	}
}

STATIC void sxe2_map_rxq_to_irq(struct sxe2_vsi *vsi, u16 cnt, u16 q_idx,
				u16 irq_idx)
{
	struct sxe2_queue *queue;
	struct sxe2_irq_data *irq_data = vsi->irqs.irq_data[irq_idx];

	irq_data->rx.list.cnt = 0;
	irq_data->rx.list.next = NULL;

	while (cnt) {
		queue = vsi->rxqs.q[q_idx];
		queue->irq_data = irq_data;
		sxe2_queue_add(queue, &irq_data->rx.list);
		cnt--;
		q_idx++;
	}
}

void sxe2_vsi_queues_irqs_map(struct sxe2_vsi *vsi)
{
	u16 irq_cnt = vsi->irqs.cnt;
	u16 txq_remain = vsi->txqs.q_cnt;
	u16 rxq_remain = vsi->rxqs.q_cnt;
	u16 i;
	u16 txq_cnt, rxq_cnt, txq_idx = 0, rxq_idx = 0;

	sxe2_for_each_vsi_irq(vsi, i)
	{
		txq_cnt = (u16)DIV_ROUND_UP(txq_remain, irq_cnt - i);
		rxq_cnt = (u16)DIV_ROUND_UP(rxq_remain, irq_cnt - i);

		sxe2_map_txq_to_irq(vsi, txq_cnt, txq_idx, i);
		sxe2_map_rxq_to_irq(vsi, rxq_cnt, rxq_idx, i);

		txq_idx += txq_cnt;
		rxq_idx += rxq_cnt;
		txq_remain -= txq_cnt;
		rxq_remain -= rxq_cnt;
	}
}

void sxe2_vsi_queues_irqs_unmap(struct sxe2_vsi *vsi)
{
	struct sxe2_irq_data *irq_data;
	struct sxe2_queue *queue;
	u16 i;

	if (vsi->irqs.cnt == 0 || !vsi->irqs.irq_data)
		return;

	sxe2_for_each_vsi_irq(vsi, i)
	{
		irq_data = vsi->irqs.irq_data[i];

		sxe2_for_each_queue(queue, irq_data->tx.list)
		{
			queue->irq_data = NULL;
			queue->next = NULL;
			irq_data->tx.list.cnt--;
		}
		irq_data->tx.list.next = NULL;
		irq_data->tx.list.cnt = 0;

		sxe2_for_each_queue(queue, irq_data->rx.list)
		{
			queue->irq_data = NULL;
			queue->next = NULL;
			irq_data->rx.list.cnt--;
		}
		irq_data->rx.list.next = NULL;
		irq_data->rx.list.cnt = 0;
	}
}

STATIC void sxe2_vsi_queues_cfg(struct sxe2_vsi *vsi)
{
	if (!vsi->txqs.depth)
		vsi->txqs.depth = SXE2_DFLT_NUM_TX_DESC;

	if (!vsi->rxqs.depth)
		vsi->rxqs.depth = SXE2_DFLT_NUM_RX_DESC;
}

STATIC void sxe2_vsi_dcb_tc_cfg(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_dcbx_cfg *dcbxcfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	if (!test_bit(SXE2_FLAG_DCB_ENABLE, adapter->flags)) {
		vsi->tc.tc_cnt = 1;
		vsi->tc.tc_map = SXE2_VSI_DFLT_TC;
	}

	switch (vsi->type) {
	case SXE2_VSI_T_PF:
		vsi->tc.tc_cnt = sxe2_dcb_tc_cnt_get(dcbxcfg);
		vsi->tc.tc_map = sxe2_dcb_tc_bitmap_get(dcbxcfg);
		break;

	case SXE2_VSI_T_CTRL:
	case SXE2_VSI_T_LB:
	default:
		vsi->tc.tc_cnt = 1;
		vsi->tc.tc_map = SXE2_VSI_DFLT_TC;
		break;
	}
}

void sxe2_vsi_tc_cfg(struct sxe2_vsi *vsi)
{
	u16 i, txqs_per_tc, rxqs_per_tc;
	u16 rx_offset = 0, tx_offset = 0, txq_cnt = 0, rxq_cnt = 0;
	struct sxe2_adapter *adapter = vsi->adapter;

	sxe2_vsi_dcb_tc_cfg(vsi);

	LOG_INFO_BDF("vsi tc cfg, tc_cnt=%d, tc_map=%x\n", vsi->tc.tc_cnt,
		     vsi->tc.tc_map);

	txqs_per_tc = vsi->txqs.q_alloc / vsi->tc.tc_cnt;
	rxqs_per_tc = vsi->rxqs.q_alloc / vsi->tc.tc_cnt;

	if (!txqs_per_tc)
		txqs_per_tc = 1;
	if (!rxqs_per_tc)
		rxqs_per_tc = 1;

	if (vsi->tc.tc_cnt > 1) {
		txqs_per_tc = rounddown_pow_of_two(txqs_per_tc);
		rxqs_per_tc = rounddown_pow_of_two(rxqs_per_tc);
	}

	sxe2_for_each_tc(i)
	{
		if (!(vsi->tc.tc_map & BIT(i))) {
			vsi->tc.info[i].txq_offset = 0;
			vsi->tc.info[i].rxq_offset = 0;
			vsi->tc.info[i].rxq_cnt = 1;
			vsi->tc.info[i].txq_cnt = 1;
			LOG_INFO_BDF("vsi tc[%d] q cfg, txq_cnt=%d, txq_offset=%d\n",
				     i, vsi->tc.info[i].txq_cnt,
				     vsi->tc.info[i].txq_offset);
			continue;
		}

		vsi->tc.info[i].txq_offset = tx_offset;
		vsi->tc.info[i].rxq_offset = rx_offset;
		vsi->tc.info[i].txq_cnt = txqs_per_tc;
		vsi->tc.info[i].rxq_cnt = rxqs_per_tc;

		rx_offset += rxqs_per_tc;
		tx_offset += txqs_per_tc;
		txq_cnt += txqs_per_tc;
		rxq_cnt += rxqs_per_tc;
		LOG_INFO_BDF("vsi tc[%d] q cfg, txq_cnt=%d, txq_offset=%d \t"
			     "rxq_offset=%d\n",
			     i, vsi->tc.info[i].txq_cnt, vsi->tc.info[i].txq_offset,
			     vsi->tc.info[i].rxq_offset);
	}

	if (rx_offset)
		rxq_cnt = rx_offset;
	else
		rxq_cnt = rxqs_per_tc;

	if (tx_offset)
		txq_cnt = tx_offset;
	else
		txq_cnt = txqs_per_tc;

	if (rxq_cnt > vsi->rxqs.q_alloc) {
		LOG_DEV_ERR("Trying to use more Rx queues (%u), than were allocated \t"
			    "(%u)!\n",
			    rxq_cnt, vsi->rxqs.q_alloc);
		return;
	}

	if (txq_cnt > vsi->txqs.q_alloc) {
		LOG_DEV_ERR("Trying to use more Tx queues (%u), than were allocated \t"
			    "(%u)!\n",
			    txq_cnt, vsi->txqs.q_alloc);
		return;
	}

	vsi->txqs.q_cnt = txq_cnt;
	vsi->rxqs.q_cnt = rxq_cnt;

	LOG_INFO_BDF("vsi txq_cnt=%d, rxq_cnt=%d\n", txq_cnt, rxq_cnt);
}

STATIC void sxe2_vsi_irq_cfg(struct sxe2_vsi *vsi, u16 idx)
{
	struct sxe2_irq_data *irq_data = vsi->irqs.irq_data[idx];

	irq_data->tx.itr_idx = SXE2_TX_ITR_IDX;
	irq_data->tx.itr_setting = SXE2_TX_DFLT_ITR;
	irq_data->rx.itr_idx = SXE2_RX_ITR_IDX;
	irq_data->rx.itr_setting = SXE2_RX_DFLT_ITR;
	if (vsi->type == SXE2_VSI_T_CTRL) {
		irq_data->tx.itr_mode = SXE2_ITR_STATIC;
		irq_data->rx.itr_mode = SXE2_ITR_STATIC;
	} else {
		irq_data->tx.itr_mode = SXE2_ITR_DYNAMIC;
		irq_data->rx.itr_mode = SXE2_ITR_DYNAMIC;
	}

	switch (vsi->type) {
	case SXE2_VSI_T_PF:
	case SXE2_VSI_T_MACVLAN:
		vsi->irqs.proc = sxe2_msix_ring_irq_handler;
		break;
	case SXE2_VSI_T_CTRL:
		vsi->irqs.proc = sxe2_msix_ctrl_vsi_handler;
		break;
	case SXE2_VSI_T_ESW:
		vsi->irqs.proc = sxe2_eswitch_msix_ring_irq_handler;
		break;
	case SXE2_VSI_T_LB:
		vsi->irqs.proc = sxe2_msix_lb_rx_irq_handler;
		break;
	default:
		break;
	}

	if (cpu_online(idx))
		cpumask_set_cpu(idx, &irq_data->affinity_mask);
}

STATIC void sxe2_vsi_irqs_cfg(struct sxe2_vsi *vsi)
{
	u16 i;

	sxe2_vsi_queues_irqs_map(vsi);

	sxe2_for_each_vsi_irq(vsi, i)
	{
		sxe2_vsi_irq_cfg(vsi, i);
	}

	if (vsi->netdev)
		sxe2_napi_add(vsi);
}

STATIC s32 sxe2_vsi_irqs_get(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	u16 i;
	s32 offset;

	if (vsi->type == SXE2_VSI_T_VF ||
	    vsi->type == SXE2_VSI_T_DPDK_VF) {
		vsi->irqs.base_idx_in_pf = vsi->vf_node->irq_base_idx +
					   vsi->irqs.base_idx_in_feature;
	} else {
		offset = sxe2_irq_offset_get(adapter, vsi->irqs.cnt, vsi->type);
		if (offset < 0) {
			ret = offset;
			LOG_DEV_ERR("vsi get %d irqs failed.\n", vsi->irqs.cnt);
			goto l_end;
		}

		vsi->irqs.base_idx_in_pf = (u16)offset;
	}

	sxe2_for_each_vsi_irq(vsi, i) vsi->irqs.irq_data[i]->idx_in_pf =
			vsi->irqs.base_idx_in_pf + i;

l_end:
	return ret;
}

STATIC void sxe2_vsi_irqs_put(struct sxe2_vsi *vsi)
{
	u16 i;
	struct sxe2_adapter *adapter = vsi->adapter;
	unsigned long *map = adapter->irq_ctxt.map;
	unsigned long size = adapter->irq_ctxt.avail_cnt;
	struct sxe2_irq_layout *irq_layout = &adapter->irq_ctxt.irq_layout;

	sxe2_for_each_vsi_irq(vsi, i)
	{
		vsi->irqs.irq_data[i]->idx_in_pf = SXE2_IRQ_IDX_INVAL;
	}

	if (vsi->type == SXE2_VSI_T_MACVLAN) {
		if (vsi->irqs.base_idx_in_pf + vsi->irqs.cnt > size) {
			LOG_ERROR_BDF("put %d irq from index %d failed, size=%lu.\n",
				      vsi->irqs.cnt, vsi->irqs.base_idx_in_pf, size);
			SXE2_BUG();
			return;
		}
		mutex_lock(&adapter->irq_ctxt.lock);
		bitmap_clear(map, vsi->irqs.base_idx_in_pf, vsi->irqs.cnt);
		irq_layout->macvlan--;
		mutex_unlock(&adapter->irq_ctxt.lock);
	}

	vsi->irqs.base_idx_in_pf = SXE2_IRQ_IDX_INVAL;
}

STATIC s32 sxe2_vsi_queues_init(struct sxe2_vsi *vsi)
{
	s32 ret;

	ret = sxe2_vsi_queues_num_set(vsi);
	if (ret)
		goto l_end;

	sxe2_vsi_queues_cfg(vsi);

	sxe2_vsi_tc_cfg(vsi);

	ret = sxe2_vsi_queues_alloc(vsi);
	if (ret)
		goto l_end;

	ret = sxe2_vsi_txrx_queues_get(vsi);
	if (ret)
		goto l_failed;

	sxe2_vsi_netdev_tc_cfg(vsi, vsi->tc.tc_map);

	return ret;

l_failed:
	sxe2_vsi_queues_free(vsi);
l_end:
	return ret;
}

STATIC void sxe2_vsi_queues_deinit(struct sxe2_vsi *vsi)
{
	if (!vsi->rxqs.q && !vsi->txqs.q)
		return;

	sxe2_vsi_txrx_queues_put(vsi);
	sxe2_vsi_queues_free(vsi);
}

STATIC s32 sxe2_vsi_irqs_init(struct sxe2_vsi *vsi)
{
	s32 ret;

	ret = sxe2_vsi_irqs_num_set(vsi);
	if (ret)
		goto l_end;

	ret = sxe2_vsi_irqs_data_alloc(vsi);
	if (ret)
		goto l_end;

	ret = sxe2_vsi_irqs_get(vsi);
	if (ret)
		goto l_failed;

	if (vsi->type != SXE2_VSI_T_VF && vsi->type != SXE2_VSI_T_DPDK_VF &&
	    vsi->type != SXE2_VSI_T_DPDK_PF) {
		sxe2_vsi_irqs_cfg(vsi);
	}

	return ret;

l_failed:
	sxe2_vsi_irqs_data_free(vsi);
	vsi->irqs.cnt = 0;
l_end:
	return ret;
}

STATIC void sxe2_vsi_irqs_deinit(struct sxe2_vsi *vsi)
{
	if (vsi->irqs.cnt == 0 || !vsi->irqs.irq_data)
		return;

	sxe2_vsi_queues_irqs_unmap(vsi);

	sxe2_napi_del(vsi);

	sxe2_vsi_irqs_put(vsi);
	sxe2_vsi_irqs_data_free(vsi);
}

bool sxe2_vsi_rxft_support_get(struct sxe2_vsi *vsi)
{
	switch (vsi->type) {
	case SXE2_VSI_T_PF:
	case SXE2_VSI_T_VF:
	case SXE2_VSI_T_DPDK_PF:
	case SXE2_VSI_T_DPDK_VF:
		return true;
	default:
		break;
	}

	return false;
}

STATIC s32 sxe2_vsi_rss_init(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	bool new_lut = false;
	bool new_hkey = false;

	if (!sxe2_vsi_rxft_support_get(vsi)) {
		LOG_INFO_BDF("unsupport vsi type: %u\n", vsi->type);
		return 0;
	}

	sxe2_rss_ctxt_init(vsi);

	if (vsi->type != SXE2_VSI_T_PF)
		return 0;

	ret = sxe2_fwc_rss_hash_ctrl_set(vsi);
	if (ret != 0) {
		LOG_ERROR_BDF("sxe2_rss_hash_ctrl_set failed, ret: %d\n", ret);
		return ret;
	}

	if (!vsi->rss_ctxt.lut) {
		vsi->rss_ctxt.lut = devm_kzalloc(dev, vsi->rss_ctxt.lut_size,
						 GFP_KERNEL);
		if (!vsi->rss_ctxt.lut) {
			ret = -ENOMEM;
			LOG_ERROR_BDF("No memory!\n");
			goto l_end;
		}
		new_lut = true;
		sxe2_rss_fill_lut(vsi->rss_ctxt.lut, vsi->rss_ctxt.lut_size,
				  vsi->rss_ctxt.queue_size);
	}
	ret = sxe2_fwc_rss_lut_set(vsi, vsi->rss_ctxt.lut, vsi->rss_ctxt.lut_size);
	if (ret != 0) {
		LOG_ERROR_BDF("sxe2_rss_lut_set failed, ret: %d, lut: %p, lut_size: \t"
			      "%u\n",
			      ret, vsi->rss_ctxt.lut, vsi->rss_ctxt.lut_size);
		goto l_lut_free;
	}

	if (!vsi->rss_ctxt.hkey) {
		vsi->rss_ctxt.hkey = devm_kzalloc(dev, SXE2_RSS_HASH_KEY_SIZE,
						  GFP_KERNEL);
		if (!vsi->rss_ctxt.hkey) {
			ret = -ENOMEM;
			LOG_ERROR_BDF("No memory!\n");
			goto l_lut_free;
		}
		new_hkey = true;
		netdev_rss_key_fill((void *)vsi->rss_ctxt.hkey,
				    SXE2_RSS_HASH_KEY_SIZE);
	}
	ret = sxe2_fwc_rss_hkey_set(vsi, vsi->rss_ctxt.hkey);
	if (ret != 0) {
		LOG_ERROR_BDF("sxe2_fwc_rss_hkey_set failed, ret: %d, key: %p\n",
			      ret, vsi->rss_ctxt.hkey);
		goto l_key_free;
	}

	(void)sxe2_rss_default_flow_set(vsi);

	goto l_end;

l_key_free:
	if (new_hkey) {
		devm_kfree(dev, vsi->rss_ctxt.hkey);
		vsi->rss_ctxt.hkey = NULL;
	}
l_lut_free:
	if (new_lut) {
		devm_kfree(dev, vsi->rss_ctxt.lut);
		vsi->rss_ctxt.lut = NULL;
	}
l_end:
	return ret;
}

STATIC void sxe2_vsi_rss_deinit(struct sxe2_vsi *vsi)
{
	u8 *lut = NULL;
	u8 *hash_key = NULL;
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	if (!sxe2_vsi_rxft_support_get(vsi)) {
		LOG_INFO_BDF("unsupport vsi type: %u\n", vsi->type);
		return;
	}

	if (vsi->rss_ctxt.lut) {
		devm_kfree(dev, vsi->rss_ctxt.lut);
		vsi->rss_ctxt.lut = NULL;
	}

	if (vsi->rss_ctxt.hkey) {
		devm_kfree(dev, vsi->rss_ctxt.hkey);
		vsi->rss_ctxt.hkey = NULL;
	}

	sxe2_rss_vsi_flow_clean(vsi);

	lut = kzalloc(vsi->rss_ctxt.lut_size, GFP_KERNEL);
	if (!lut) {
		LOG_ERROR_BDF("no memory for lut!\n");
		goto hkey_clean;
	}
	ret = sxe2_fwc_rss_lut_set(vsi, lut, vsi->rss_ctxt.lut_size);
	if (ret != 0) {
		LOG_ERROR_BDF("sxe2_rss_lut_set failed, ret: %d, lut: %p, lut_size: \t"
			      "%u\n",
			      ret, lut, vsi->rss_ctxt.lut_size);
	}
	kfree(lut);

hkey_clean:
	hash_key = kzalloc(SXE2_RSS_HASH_KEY_SIZE, GFP_KERNEL);
	if (!hash_key) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("no memory for hkey!\n");
		goto l_end;
	}
	ret = sxe2_fwc_rss_hkey_set(vsi, hash_key);
	if (ret != 0) {
		LOG_ERROR_BDF("sxe2_fwc_rss_hkey_set failed, ret: %d, key: %p\n",
			      ret, hash_key);
	}
	kfree(hash_key);

l_end:
	LOG_INFO_BDF("sxe2 vsi rss deinit done, id=%u type=%u!\n", vsi->id_in_pf,
		     vsi->type);
}

STATIC void sxe2_vsi_qs_stats_deinit(struct sxe2_vsi *vsi)
{
	struct sxe2_vsi_qs_stats *vsi_qs_stat = &vsi->vsi_qs_stats;

	kfree(vsi_qs_stat->txqs_stats);
	vsi_qs_stat->txqs_stats = NULL;

	kfree(vsi_qs_stat->rxqs_stats);
	vsi_qs_stat->rxqs_stats = NULL;
}

STATIC s32 sxe2_vsi_qs_stats_init(struct sxe2_vsi *vsi)
{
	struct sxe2_vsi_qs_stats *vsi_qs_stats;
	struct sxe2_adapter *adapter = vsi->adapter;
	u16 i;

	vsi_qs_stats = &vsi->vsi_qs_stats;

	if (!vsi_qs_stats->txqs_stats) {
		vsi_qs_stats->txqs_stats = kcalloc(vsi_qs_stats->vsi_qs_stats_maxcnt,
						   sizeof(*vsi_qs_stats->txqs_stats),
						   GFP_KERNEL);
		if (!vsi_qs_stats->txqs_stats) {
			LOG_ERROR_BDF("alloc txqs stats failed, count: %d, size: \t"
				      "%zu.\n",
				      vsi_qs_stats->vsi_qs_stats_maxcnt,
				      sizeof(*vsi_qs_stats->txqs_stats));
			goto err_out;
		}

		sxe2_for_each_vsi_q_maxcnt(vsi, i)
		{
			u64_stats_init(&vsi_qs_stats->txqs_stats[i].syncp);
		}
	}

	if (!vsi_qs_stats->rxqs_stats) {
		vsi_qs_stats->rxqs_stats = kcalloc(vsi_qs_stats->vsi_qs_stats_maxcnt,
						   sizeof(*vsi_qs_stats->rxqs_stats),
						   GFP_KERNEL);
		if (!vsi_qs_stats->rxqs_stats) {
			LOG_ERROR_BDF("alloc rxqs stats failed, count: %d, size: \t"
				      "%zu.\n",
				      vsi_qs_stats->vsi_qs_stats_maxcnt,
				      sizeof(*vsi_qs_stats->rxqs_stats));
			goto err_out;
		}

		sxe2_for_each_vsi_q_maxcnt(vsi, i)
		{
			u64_stats_init(&vsi_qs_stats->rxqs_stats[i].syncp);
		}
	}

	sxe2_for_each_vsi_alloc_txq(vsi, i)
	{
		struct sxe2_queue *txq = vsi->txqs.q[i];

		txq->stats = &vsi_qs_stats->txqs_stats[i];
	}

	sxe2_for_each_vsi_alloc_rxq(vsi, i)
	{
		struct sxe2_queue *rxq = vsi->rxqs.q[i];

		rxq->stats = &vsi_qs_stats->rxqs_stats[i];
	}

	return 0;

err_out:
	sxe2_vsi_qs_stats_deinit(vsi);
	return -ENOMEM;
}

STATIC void sxe2_vsi_fnav_init(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	u16 g_val = adapter->caps_ctxt.fnav_space_gsize;
	u16 b_val = adapter->caps_ctxt.fnav_space_bsize;

	if (!sxe2_vsi_rxft_support_get(vsi)) {
		LOG_INFO_BDF("unsupport vsi type: %u\n", vsi->type);
		return;
	}

	memset(&vsi->fnav, 0, sizeof(vsi->fnav));

	if (vsi->type == SXE2_VSI_T_PF || vsi->type == SXE2_VSI_T_DPDK_PF) {
		vsi->fnav.space_gsize = g_val;
		vsi->fnav.space_bsize = b_val;
	} else if (vsi->type == SXE2_VSI_T_VF || vsi->type == SXE2_VSI_T_DPDK_VF) {
		vsi->fnav.space_gsize = 0;
		vsi->fnav.space_bsize = b_val;
	}

	mutex_init(&vsi->fnav.flow_cfg_lock);
	INIT_LIST_HEAD(&vsi->fnav.filter_list);
	INIT_LIST_HEAD(&vsi->fnav.flow_cfg_list);
}

STATIC void sxe2_vsi_fnav_deinit(struct sxe2_vsi *vsi)
{
	struct sxe2_vsi_fnav *vsi_fnav = &vsi->fnav;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (!sxe2_vsi_rxft_support_get(vsi))
		return;

	sxe2_fnav_clean_by_vsi(vsi, true);

	sxe2_fnav_stats_free_by_vsi(vsi);
	sxe2_fnav_filter_free_by_vsi(vsi);
	sxe2_fnav_flow_cfg_free(vsi);

	mutex_destroy(&vsi_fnav->flow_cfg_lock);

	LOG_INFO_BDF("sxe2 fnav deinit done, id=%u type=%u!\n", vsi->id_in_pf,
		     vsi->type);
}

static struct sxe2_vsi *
sxe2_vsi_create_unlock(struct sxe2_adapter *adapter,
		       struct sxe2_vsi_cfg_params *vsi_create)
{
	struct sxe2_vsi *vsi;

	vsi = sxe2_vsi_init(adapter, vsi_create);
	if (!vsi)
		goto l_end;

	if (sxe2_vsi_queues_init(vsi) != 0)
		goto l_queue_init_failed;

	if (sxe2_vsi_qs_stats_init(vsi))
		goto l_queues_stats_init_failed;

	if (sxe2_vsi_irqs_init(vsi) != 0)
		goto l_irq_init_failed;

	sxe2_vsi_fnav_init(vsi);

	sxe2_vsi_acl_init(vsi);
	sxe2_udptunnel_vsi_init(vsi);

	if (sxe2_vsi_hw_cfg(vsi) != 0)
		goto l_vsi_setup_failed;

	if (sxe2_txsched_lan_vsi_cfg(vsi) != 0)
		goto l_vsi_sched_failed;

	if (vsi_create->type != SXE2_VSI_T_LB) {
		if (sxe2_vsi_rss_init(vsi) != 0) {
			LOG_DEBUG_BDF("sxe2_rss_init failed!");
			goto l_vsi_update_config;
		}
	}

	(void)mutex_lock(&adapter->switch_ctxt.evb_mode_lock);
	if ((adapter->switch_ctxt.evb_mode == BRIDGE_MODE_VEB ||
	     vsi_create->type == SXE2_VSI_T_LB) &&
	    sxe2_vsi_loopback_control(adapter, vsi->idx_in_dev, true)) {
		(void)mutex_unlock(&adapter->switch_ctxt.evb_mode_lock);
		goto l_vsi_rss_deinit;
	}
	(void)mutex_unlock(&adapter->switch_ctxt.evb_mode_lock);

	if (!sxe2_eswitch_is_offload(adapter) &&
	    (vsi_create->type == SXE2_VSI_T_PF ||
	     vsi_create->type == SXE2_VSI_T_VF ||
	     vsi_create->type == SXE2_VSI_T_DPDK_PF ||
	     vsi_create->type == SXE2_VSI_T_DPDK_VF)) {
		if (!sxe2_is_safe_mode(adapter)) {
			if (sxe2_etype_fltr_init(vsi)) {
				LOG_ERROR("etype filter config failed.\n");
				goto l_vsi_rss_deinit;
			}
		}

		if (sxe2_src_vsi_prune_control(adapter, vsi->idx_in_dev, true))
			goto l_vsi_rss_deinit;

		if (sxe2_srcvsi_rule_add(vsi)) {
			LOG_ERROR("vsi[%u][%u] srcvsi rule add failed.\n",
				  vsi->id_in_pf, vsi->idx_in_dev);
			goto l_vsi_rss_deinit;
		}

		if (vsi_create->type == SXE2_VSI_T_VF ||
		    vsi_create->type == SXE2_VSI_T_DPDK_VF) {
			if (sxe2_vsi_spoofchk_control(adapter, vsi->idx_in_dev,
						      vsi_create->vf->prop.spoofchk)) {
				LOG_ERROR("vsi[%u][%u] spoofchk set %s failed.\n",
					  vsi->id_in_pf, vsi->idx_in_dev,
					  vsi_create->vf->prop.spoofchk ? "on"
									: "off");
				goto l_vsi_rss_deinit;
			}

			if (sxe2_mac_spoofchk_rule_add(adapter, vsi->idx_in_dev)) {
				LOG_ERROR("vsi[%u][%u] spoofchk rule add failed.\n",
					  vsi->id_in_pf, vsi->idx_in_dev);
				goto l_vsi_rss_deinit;
			}
		}
	}

	return vsi;

l_vsi_rss_deinit:
	sxe2_vsi_rss_deinit(vsi);
l_vsi_update_config:
	(void)sxe2_txsched_lan_vsi_rm(vsi);
l_vsi_sched_failed:
	sxe2_vsi_fltr_remove(adapter, vsi->idx_in_dev);
	(void)sxe2_vsi_hw_decfg(adapter, vsi->idx_in_dev);
l_vsi_setup_failed:
	sxe2_vsi_irqs_deinit(vsi);
l_irq_init_failed:
	sxe2_vsi_qs_stats_deinit(vsi);
l_queues_stats_init_failed:
	sxe2_vsi_queues_deinit(vsi);
l_queue_init_failed:
	sxe2_vsi_deinit(vsi);

l_end:
	return NULL;
}

struct sxe2_vsi *sxe2_vsi_create(struct sxe2_adapter *adapter,
				 struct sxe2_vsi_cfg_params *vsi_create)
{
	struct sxe2_vsi *vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_create_unlock(adapter, vsi_create);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	return vsi;
}

STATIC void sxe2_vsi_irqs_coalesce_deinit(struct sxe2_vsi *vsi)
{
	kfree(vsi->irqs.coalesce);
	vsi->irqs.coalesce = NULL;
}

void sxe2_vsi_destroy_unlock(struct sxe2_vsi *vsi)
{
	if (vsi->type == SXE2_VSI_T_ESW)
		(void)sxe2_esw_vsi_disable_unlock(vsi);
	else
		(void)sxe2_vsi_disable_unlock(vsi);

	(void)sxe2_txsched_lan_vsi_rm(vsi);

	sxe2_vsi_fltr_remove(vsi->adapter, vsi->idx_in_dev);

	sxe2_vsi_fnav_deinit(vsi);

	sxe2_vsi_rss_deinit(vsi);

	sxe2_vsi_acl_deinit(vsi);

	(void)sxe2_user_vlan_destroy(vsi);

	sxe2_udptunnel_vsi_deinit(vsi);

	(void)sxe2_vsi_hw_decfg(vsi->adapter, vsi->idx_in_dev);

	sxe2_txsched_vsi_q_ctxt_free(vsi);

	sxe2_vsi_irqs_deinit(vsi);
	sxe2_vsi_qs_stats_deinit(vsi);
#ifdef HAVE_XDP_SUPPORT
	sxe2_vsi_xdp_qs_stats_deinit(vsi);
#endif
	sxe2_vsi_queues_deinit(vsi);

	sxe2_vsi_irqs_coalesce_deinit(vsi);

	sxe2_vsi_deinit(vsi);
}

void sxe2_vsi_destroy(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;

	mutex_lock(&adapter->vsi_ctxt.lock);

	sxe2_vsi_destroy_unlock(vsi);

	mutex_unlock(&adapter->vsi_ctxt.lock);
}

s32 sxe2_main_vsi_create(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_vsi_cfg_params vsi_create = {};

	vsi_create.type = SXE2_VSI_T_PF;

	adapter->vsi_ctxt.main_vsi = sxe2_vsi_create(adapter, &vsi_create);
	if (!adapter->vsi_ctxt.main_vsi)
		ret = -EIO;

	return ret;
}

static s32 sxe2_ctrl_vsi_create(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_vsi_cfg_params vsi_create = {};

	vsi_create.type = SXE2_VSI_T_CTRL;

	adapter->vsi_ctxt.ctrl_vsi = sxe2_vsi_create(adapter, &vsi_create);
	if (!adapter->vsi_ctxt.ctrl_vsi)
		ret = -EIO;

	return ret;
}

static void sxe2_ctrl_vsi_destroy(struct sxe2_adapter *adapter)
{
	if (adapter->vsi_ctxt.ctrl_vsi) {
		sxe2_vsi_destroy(adapter->vsi_ctxt.ctrl_vsi);
		adapter->vsi_ctxt.ctrl_vsi = NULL;
	}
}

s32 sxe2_ctrl_vsi_init(struct sxe2_adapter *adapter)
{
	s32 ret = 0;

	ret = sxe2_ctrl_vsi_create(adapter);
	if (ret) {
		LOG_ERROR_BDF("ctrl vsi create failed, ret:%d\n", ret);
		goto l_out;
	}

	ret = sxe2_vsi_open(adapter->vsi_ctxt.ctrl_vsi);
	if (ret) {
		LOG_ERROR_BDF("ctrl vsi open failed, ret:%d\n", ret);
		goto l_vsi_open_failed;
	}

	return 0;

l_vsi_open_failed:
	sxe2_ctrl_vsi_destroy(adapter);
l_out:
	return ret;
}

void sxe2_ctrl_vsi_deinit(struct sxe2_adapter *adapter)
{
	if (sxe2_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK) {
		LOG_WARN_BDF("dpdk only mode no need deinit ctrl vsi.\n");
		return;
	}

	if (adapter->vsi_ctxt.ctrl_vsi) {
		(void)sxe2_vsi_close(adapter->vsi_ctxt.ctrl_vsi);
		sxe2_ctrl_vsi_destroy(adapter);
	}
}

void sxe2_vsi_destroy_all(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *vsi;
	u16 i;

	mutex_lock(&adapter->vsi_ctxt.lock);

	sxe2_for_each_vsi(&adapter->vsi_ctxt, i)
	{
		vsi = adapter->vsi_ctxt.vsi[i];
		if (!vsi)
			continue;
		sxe2_vsi_destroy_unlock(vsi);
	}
	adapter->vsi_ctxt.main_vsi = NULL;

	mutex_unlock(&adapter->vsi_ctxt.lock);
}

struct sxe2_vsi *sxe2_loopback_vsi_create(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi_cfg_params vsi_create = {};
	struct sxe2_vsi *vsi;

	vsi_create.type = SXE2_VSI_T_LB;

	vsi = sxe2_vsi_create_unlock(adapter, &vsi_create);
	if (!vsi)
		return NULL;

	return vsi;
}

s32 sxe2_eswitch_vsi_create(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi_cfg_params vsi_create = {};
	struct sxe2_vsi *vsi;

	vsi_create.type = SXE2_VSI_T_ESW;
	vsi = sxe2_vsi_create(adapter, &vsi_create);
	if (!vsi) {
		LOG_ERROR_BDF("eswitch vsi create fail.\n");
		return -ENOMEM;
	}
	adapter->eswitch_ctxt.esw_vsi = vsi;

	LOG_INFO_BDF("eswitch vsi:%p [%u][%u].\n", vsi, vsi->id_in_pf,
		     vsi->idx_in_dev);

	adapter->eswitch_ctxt.user_esw_vsi = NULL;
	if (sxe2_com_mode_get(adapter) != SXE2_COM_MODULE_KERNEL) {
		vsi_create.type = SXE2_VSI_T_DPDK_ESW;
		vsi = sxe2_vsi_create(adapter, &vsi_create);
		if (!vsi) {
			LOG_ERROR_BDF("user eswitch vsi create fail.\n");
		} else {
			adapter->eswitch_ctxt.user_esw_vsi = vsi;
			LOG_INFO_BDF("user eswitch vsi:%p [%u][%u].\n", vsi,
				     vsi->id_in_pf, vsi->idx_in_dev);
		}
	}

	if (sxe2_com_mode_get(adapter) != SXE2_COM_MODULE_DPDK) {
		adapter->eswitch_ctxt.uplink_vsi = adapter->vsi_ctxt.main_vsi;
		LOG_INFO_BDF("uplink_vsi:%p [%u][%u].\n",
			     adapter->eswitch_ctxt.uplink_vsi,
			     adapter->eswitch_ctxt.uplink_vsi->id_in_pf,
			     adapter->eswitch_ctxt.uplink_vsi->idx_in_dev);
	} else {
		adapter->eswitch_ctxt.uplink_vsi = NULL;
	}

	return 0;
}

STATIC void sxe2_irq_affinity_notify(struct irq_affinity_notify *notify,
				     const cpumask_t *mask)
{
	struct sxe2_irq_data *irq_data =
			container_of(notify, struct sxe2_irq_data, affinity_notify);

	cpumask_copy(&irq_data->affinity_mask, mask);
}

STATIC void sxe2_irq_affinity_release(struct kref __always_unused *ref)
{
}

STATIC void sxe2_vsi_get_q_idx(struct sxe2_vsi *vsi, u16 irq_idx, u16 *txq, u16 *rxq)
{
	u16 txq_per_irq, txq_remainder, rxq_per_irq, rxq_remainder;

	txq_per_irq = vsi->txqs.q_cnt / vsi->irqs.cnt;
	rxq_per_irq = vsi->rxqs.q_cnt / vsi->irqs.cnt;
	txq_remainder = vsi->txqs.q_cnt % vsi->irqs.cnt;
	rxq_remainder = vsi->rxqs.q_cnt % vsi->irqs.cnt;

	*txq = (u16)((txq_per_irq * irq_idx) +
		     (irq_idx < txq_remainder ? irq_idx : txq_remainder));
	*rxq = (u16)((rxq_per_irq * irq_idx) +
		     (irq_idx < rxq_remainder ? irq_idx : rxq_remainder));
}

STATIC s32 sxe2_vsi_irq_request(struct sxe2_vsi *vsi, s8 *base_name, u16 idx)
{
	s32 ret = 0;
	struct sxe2_irq_data *irq_data;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u16 rx_idx, tx_idx;
	unsigned int irq_num;

	irq_data = vsi->irqs.irq_data[idx];
	irq_num = adapter->irq_ctxt.msix_entries[vsi->irqs.base_idx_in_pf + idx]
				  .vector;

	sxe2_vsi_get_q_idx(vsi, idx, &tx_idx, &rx_idx);

	if (SXE2_IRQ_HAS_TXQ(irq_data) && SXE2_IRQ_HAS_RXQ(irq_data)) {
		if (irq_data->rx.list.cnt == 1)
			(void)snprintf(irq_data->name, sizeof(irq_data->name) - 1,
				       "%s-%s-%d", base_name, "TxRx", rx_idx);
		else
			(void)snprintf(irq_data->name, sizeof(irq_data->name) - 1,
				       "%s-%s-%d-%d", base_name, "TxRx", rx_idx,
				       rx_idx + irq_data->rx.list.cnt - 1);
	} else if (SXE2_IRQ_HAS_TXQ(irq_data)) {
		(void)snprintf(irq_data->name, sizeof(irq_data->name) - 1,
			       "%s-%s-%d", base_name, "Tx", tx_idx);
	} else if (SXE2_IRQ_HAS_RXQ(irq_data)) {
		(void)snprintf(irq_data->name, sizeof(irq_data->name) - 1,
			       "%s-%s-%d", base_name, "Rx", rx_idx);
	} else {
		goto l_end;
	}

	ret = devm_request_irq(dev, irq_num, vsi->irqs.proc, 0, irq_data->name,
			       irq_data);
	if (ret) {
		LOG_DEV_ERR("MSI-X devm_request_irq failed, result: %d\n", ret);
		goto l_end;
	}
	if (!IS_ENABLED(CONFIG_RFS_ACCEL)) {
		irq_data->affinity_notify.notify = sxe2_irq_affinity_notify;
		irq_data->affinity_notify.release = sxe2_irq_affinity_release;
		(void)irq_set_affinity_notifier(irq_num, &irq_data->affinity_notify);
	}

l_end:
	return ret;
}

s32 sxe2_vsi_irqs_request(struct sxe2_vsi *vsi)
{
	s32 ret;
	s8 base_name[SXE2_IRQ_NAME_STR_LEN];
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u16 i;
	u32 irq_num;
	struct sxe2_irq_data *irq_data;

	if (vsi->type == SXE2_VSI_T_CTRL) {
		(void)snprintf(base_name, sizeof(base_name) - 1, "%s-%s:ctrl",
			       dev_driver_string(dev), dev_name(dev));
	} else if (vsi->type == SXE2_VSI_T_ESW) {
		(void)snprintf(base_name, sizeof(base_name) - 1, "%s-%s:eswitch",
			       dev_driver_string(dev), dev_name(dev));
	} else if (vsi->type == SXE2_VSI_T_LB) {
		(void)snprintf(base_name, sizeof(base_name) - 1, "%s-lbtest",
			       dev_driver_string(dev));
	} else {
		(void)snprintf(base_name, sizeof(base_name) - 1, "%s-%s",
			       dev_driver_string(dev), vsi->netdev->name);
	}

	sxe2_for_each_vsi_irq(vsi, i)
	{
		ret = sxe2_vsi_irq_request(vsi, base_name, i);
		if (ret)
			goto l_end;
	}

	ret = sxe2_cpu_rx_rmap_set(vsi);
	if (ret) {
		LOG_DEV_ERR("failed to setup CPU RMAP on vsi %u: %d\n",
			    vsi->id_in_pf, ret);
		goto l_end;
	}

	sxe2_for_each_vsi_irq(vsi, i)
	{
		irq_data = vsi->irqs.irq_data[i];
		irq_num = adapter->irq_ctxt
					  .msix_entries[vsi->irqs.base_idx_in_pf + i]
					  .vector;
		(void)irq_set_affinity_hint(irq_num, &irq_data->affinity_mask);
	}

	return 0;

l_end:
	while (i) {
		i--;
		irq_num = adapter->irq_ctxt
					  .msix_entries[vsi->irqs.base_idx_in_pf + i]
					  .vector;
		if (!IS_ENABLED(CONFIG_RFS_ACCEL))
			(void)irq_set_affinity_notifier(irq_num, NULL);

		(void)irq_set_affinity_hint(irq_num, NULL);
		devm_free_irq(dev, irq_num, vsi->irqs.irq_data[i]);
	}
	return ret;
}

STATIC void sxe2_vsi_irq_free(struct sxe2_vsi *vsi, u16 idx)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_irq_data *irq_data = vsi->irqs.irq_data[idx];
	u32 irq_num = adapter->irq_ctxt.msix_entries[vsi->irqs.base_idx_in_pf + idx]
				      .vector;

	if (!irq_data || !(SXE2_IRQ_HAS_TXQ(irq_data) || SXE2_IRQ_HAS_RXQ(irq_data)))
		return;

	if (!IS_ENABLED(CONFIG_RFS_ACCEL))
		(void)irq_set_affinity_notifier(irq_num, NULL);

	(void)irq_set_affinity_hint(irq_num, NULL);
	synchronize_irq(irq_num);
	devm_free_irq(dev, irq_num, irq_data);
}

STATIC void sxe2_vsi_irqs_free(struct sxe2_vsi *vsi)
{
	u16 i;

	sxe2_cpu_rx_rmap_free(vsi);

	sxe2_for_each_vsi_irq(vsi, i)
	{
		sxe2_vsi_irq_free(vsi, i);
	}
}

void sxe2_irq_txqs_cause_setup(struct sxe2_irq_data *irq_data)
{
	struct sxe2_hw *hw = &irq_data->vsi->adapter->hw;
	struct sxe2_queue *queue;

	sxe2_for_each_queue(queue, irq_data->tx.list)
	{
		sxe2_hw_txq_irq_cause_setup(hw, queue->idx_in_pf,
					    irq_data->tx.itr_idx,
					    irq_data->idx_in_pf);
		sxe2_flush(hw);
	}
}

void sxe2_irq_txqs_cause_clear(struct sxe2_irq_data *irq_data)
{
	struct sxe2_hw *hw = &irq_data->vsi->adapter->hw;
	struct sxe2_queue *queue;

	sxe2_for_each_queue(queue, irq_data->tx.list)
	{
		sxe2_hw_txq_irq_cause_clear(hw, queue->idx_in_pf);
		sxe2_flush(hw);
	}
}

void sxe2_irq_rxqs_cause_setup(struct sxe2_irq_data *irq_data)
{
	struct sxe2_hw *hw = &irq_data->vsi->adapter->hw;
	struct sxe2_queue *queue;

	sxe2_for_each_queue(queue, irq_data->rx.list)
	{
		sxe2_hw_rxq_irq_cause_setup(hw, queue->idx_in_pf,
					    irq_data->rx.itr_idx,
					    irq_data->idx_in_pf);
		sxe2_flush(hw);
	}
}

void sxe2_irq_rxqs_cause_clear(struct sxe2_irq_data *irq_data)
{
	struct sxe2_hw *hw = &irq_data->vsi->adapter->hw;
	struct sxe2_queue *queue;

	sxe2_for_each_queue(queue, irq_data->rx.list)
	{
		sxe2_hw_rxq_irq_cause_clear(hw, queue->idx_in_pf);
		sxe2_flush(hw);
	}
}

STATIC void sxe2_vsi_irq_setup(struct sxe2_vsi *vsi, u16 idx)
{
	struct sxe2_irq_data *irq_data = vsi->irqs.irq_data[idx];
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_vf_node *vf;
	u16 i;

	if (vsi->type != SXE2_VSI_T_VF)
		sxe2_irq_itr_init(irq_data);

	sxe2_irq_rate_limit_init(irq_data);

	if (vsi->type == SXE2_VSI_T_ESW) {
		sxe2_for_each_vsi_rxq(vsi, i)
		{
			vf = SXE2_VF_NODE(adapter, i);
			if (!vf) {
				LOG_WARN_BDF("vf:%u has freed.\n", i);
				continue;
			}

			sxe2_irq_txqs_cause_setup(vf->repr->irq_data);

			sxe2_irq_rxqs_cause_setup(vf->repr->irq_data);
		}
	} else {
		sxe2_irq_txqs_cause_setup(irq_data);

		sxe2_irq_rxqs_cause_setup(irq_data);
	}

	if (vsi->netdev &&
	    (SXE2_IRQ_HAS_TXQ(irq_data) || SXE2_IRQ_HAS_RXQ(irq_data))) {
		napi_enable(&irq_data->napi);
	}

	if (vsi->type == SXE2_VSI_T_ESW) {
		sxe2_for_each_vf(adapter, idx)
		{
			vf = SXE2_VF_NODE(adapter, idx);
			napi_enable(&vf->repr->irq_data->napi);
		}
	}

	if (vsi->type != SXE2_VSI_T_VF) {
		sxe2_hw_irq_enable(&irq_data->vsi->adapter->hw, irq_data->idx_in_pf);
		sxe2_hw_irq_trigger(&irq_data->vsi->adapter->hw,
				    irq_data->idx_in_pf);
	}
}

STATIC void sxe2_vsi_irq_release(struct sxe2_vsi *vsi, u16 idx)
{
	struct sxe2_irq_data *irq_data = vsi->irqs.irq_data[idx];
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_hw *hw = &adapter->hw;
	struct sxe2_queue *queue;
	struct sxe2_vf_node *vf;
	u16 i;

	if (vsi->type == SXE2_VSI_T_ESW) {
		sxe2_for_each_vsi_rxq(vsi, i)
		{
			vf = SXE2_VF_NODE(adapter, i);
			if (!vf) {
				LOG_WARN_BDF("vf:%u has freed.\n", i);
				continue;
			}

			sxe2_for_each_queue(queue, vf->repr->irq_data->tx.list)
			{
				sxe2_hw_txq_irq_cause_clear(hw, queue->idx_in_pf);
			}
			sxe2_for_each_queue(queue, vf->repr->irq_data->rx.list)
			{
				sxe2_hw_rxq_irq_cause_clear(hw, queue->idx_in_pf);
			}
		}
	} else {
		sxe2_for_each_queue(queue, irq_data->tx.list)
		{
			sxe2_hw_txq_irq_cause_clear(hw, queue->idx_in_pf);
		}
		sxe2_for_each_queue(queue, irq_data->rx.list)
		{
			sxe2_hw_rxq_irq_cause_clear(hw, queue->idx_in_pf);
		}
	}

	if (SXE2_IRQ_HAS_TXQ(irq_data))
		sxe2_itr_set(irq_data, &irq_data->tx, 0);

	if (SXE2_IRQ_HAS_RXQ(irq_data))
		sxe2_itr_set(irq_data, &irq_data->rx, 0);

	sxe2_hw_irq_rate_limit_set(hw, irq_data->idx_in_pf, 0);
	sxe2_flush(hw);
}

void sxe2_vsi_irqs_setup(struct sxe2_vsi *vsi)
{
	u16 i;

	sxe2_for_each_vsi_irq(vsi, i)
	{
		sxe2_vsi_irq_setup(vsi, i);
	}
}

void sxe2_vsi_irqs_release(struct sxe2_vsi *vsi)
{
	u16 i;

	sxe2_for_each_vsi_irq(vsi, i)
	{
		sxe2_vsi_irq_release(vsi, i);
	}
}

s32 sxe2_vsi_irqs_configure(struct sxe2_vsi *vsi)
{
	s32 ret;

	ret = sxe2_vsi_irqs_request(vsi);
	if (ret)
		goto l_end;

	sxe2_vsi_irqs_setup(vsi);

l_end:
	return ret;
}

void sxe2_vsi_irqs_clear_free(struct sxe2_vsi *vsi)
{
	sxe2_vsi_irqs_release(vsi);
	sxe2_vsi_irqs_free(vsi);
}

s32 sxe2_vsi_check(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;

	ret = sxe2_hw_txqs_disable_check(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi[%d] type %d check txqs disable failed.\n",
			      vsi->id_in_pf, vsi->type);
	}

	return ret;
}

static inline void sxe2_vsi_carrier_on(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct net_device *netdev = vsi->netdev;

	if (netdev) {
		mutex_lock(&adapter->link_ctxt.link_status_lock);
		if (sxe2_get_pf_link_status(adapter)) {
			netif_carrier_on(netdev);
			netif_tx_start_all_queues(netdev);
			LOG_DEV_INFO("nic link is up\n");
		}
		mutex_unlock(&adapter->link_ctxt.link_status_lock);
	}
}

s32 sxe2_vsi_open(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (!test_bit(SXE2_VSI_S_CLOSE, vsi->state)) {
		LOG_WARN_BDF("vsi opened already.\n");
		return 0;
	}

	ret = sxe2_vsi_check(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi[%u][%u] type:%u check failed ret:%d.\n",
			      vsi->id_in_pf, vsi->idx_in_dev, vsi->type, ret);
		SXE2_BUG_ON(ret);
	}

	ret = sxe2_tx_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi[%u][%u] type:%u open: tx config err, ret=%d\n",
			      vsi->id_in_pf, vsi->idx_in_dev, vsi->type, ret);
		goto l_end;
	}

	if (sxe2_xdp_is_enable(vsi)) {
		ret = sxe2_xdp_tx_cfg(vsi);
		if (ret) {
			LOG_ERROR_BDF("vsi[%u][%u] type:%u open: tx config err, \t"
				      "ret=%d\n",
				      vsi->id_in_pf, vsi->idx_in_dev, vsi->type,
				      ret);
			goto l_xdp_fail;
		}
	}

	ret = sxe2_rx_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi[%u][%u] type:%u open: rx config err, ret=%d\n",
			      vsi->id_in_pf, vsi->idx_in_dev, vsi->type, ret);
		goto l_rx_fail;
	}

	ret = sxe2_vsi_irqs_configure(vsi);
	if (ret)
		goto l_irq_fail;

	if (vsi->netdev && vsi->type == SXE2_VSI_T_PF)
		sxe2_vsi_carrier_on(vsi);

	clear_bit(SXE2_VSI_S_DOWN, vsi->state);
	clear_bit(SXE2_VSI_S_CLOSE, vsi->state);

	return 0;

l_irq_fail:
	(void)sxe2_rxqs_stop(vsi);
	sxe2_rx_rings_res_free(vsi);
l_rx_fail:
	if (sxe2_xdp_is_enable(vsi))
		(void)sxe2_xdp_txqs_stop(vsi);
l_xdp_fail:
	(void)sxe2_txqs_stop(vsi);
	sxe2_tx_rings_res_free(vsi);
l_end:
	return ret;
}

STATIC void sxe2_vsi_irq_disable(struct sxe2_vsi *vsi, u16 idx)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_hw *hw = &adapter->hw;
	struct sxe2_queue *queue;
	struct sxe2_irq_data *irq_data = vsi->irqs.irq_data[idx];
	u16 vf_idx;
	struct sxe2_vf_node *vf;

	sxe2_for_each_queue(queue, irq_data->tx.list)
	{
		sxe2_hw_txq_irq_cause_switch(hw, queue->idx_in_pf, false);
	}

	sxe2_for_each_queue(queue, irq_data->rx.list)
	{
		sxe2_hw_rxq_irq_cause_switch(hw, queue->idx_in_pf, false);
	}

	if (vsi->type != SXE2_VSI_T_VF)
		synchronize_irq(adapter->irq_ctxt.msix_entries[irq_data->idx_in_pf]
						.vector);

	if (vsi->type == SXE2_VSI_T_ESW) {
		sxe2_for_each_vf(adapter, vf_idx)
		{
			vf = SXE2_VF_NODE(adapter, vf_idx);
			if (!vf->repr->dst)
				continue;
			napi_disable(&vf->repr->irq_data->napi);
		}
	} else {
		if (vsi->netdev) {
			if (irq_data->rx.list.next || irq_data->tx.list.next)
				napi_disable(&irq_data->napi);

			cancel_work_sync(&irq_data->tx.dim.work);
			cancel_work_sync(&irq_data->rx.dim.work);
		}
	}

	sxe2_hw_irq_disable(hw, irq_data->idx_in_pf);
	sxe2_flush(hw);
}

void sxe2_vsi_irqs_disable(struct sxe2_vsi *vsi)
{
	u16 i;

	sxe2_for_each_vsi_irq(vsi, i)
	{
		sxe2_vsi_irq_disable(vsi, i);
	}
}

void sxe2_napi_add(struct sxe2_vsi *vsi)
{
	u16 i;

	sxe2_for_each_vsi_irq(vsi, i)
	{
		netif_napi_add(vsi->netdev, &vsi->irqs.irq_data[i]->napi,
			       sxe2_napi_poll, NAPI_POLL_WEIGHT);
	}
	set_bit(SXE2_VSI_S_NAPI_ADDED, vsi->state);
}

void sxe2_napi_del(struct sxe2_vsi *vsi)
{
	u16 i;

	if (!test_bit(SXE2_VSI_S_NAPI_ADDED, vsi->state))
		return;

	sxe2_for_each_vsi_irq(vsi, i)
	{
		netif_napi_del(&vsi->irqs.irq_data[i]->napi);
	}

	clear_bit(SXE2_VSI_S_NAPI_ADDED, vsi->state);
}

STATIC void sxe2_vsi_txq_clean(struct sxe2_vsi *vsi)
{
	u32 i;

	sxe2_for_each_vsi_txq(vsi, i)
	{
		sxe2_tx_ring_clean(vsi->txqs.q[i]);
	}

	if (sxe2_xdp_is_enable(vsi)) {
		for (i = 0; i < vsi->num_xdp_txq; i++)
			sxe2_tx_ring_clean(vsi->xdp_rings.q[i]);
	}
}

void sxe2_vsi_rxq_clean(struct sxe2_vsi *vsi)
{
	u16 i;

	sxe2_for_each_vsi_rxq(vsi, i)
	{
		sxe2_rx_ring_clean(vsi->rxqs.q[i]);
	}
}

s32 sxe2_vsi_down(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;
	bool need_reset = false;

	if (vsi->netdev && vsi->type == SXE2_VSI_T_PF) {
		netif_carrier_off(vsi->netdev);
		netif_tx_disable(vsi->netdev);
	} else if (vsi->type == SXE2_VSI_T_ESW) {
		sxe2_eswitch_txqs_stop(adapter);
	}

	ret = sxe2_txqs_stop(vsi);
	if (ret) {
		need_reset = true;
		LOG_ERROR_BDF("stop tx queues failed, vsi %d error %d\n",
			      vsi->idx_in_dev, ret);
	}

	if (sxe2_xdp_is_enable(vsi)) {
		ret = sxe2_xdp_txqs_stop(vsi);
		if (ret) {
			need_reset = true;
			LOG_ERROR_BDF("failed stop xdp rings, vsi %d error %d\n",
				      vsi->id_in_pf, ret);
		}
	}

	ret = sxe2_rxqs_stop(vsi);
	if (ret) {
		need_reset = true;
		LOG_ERROR_BDF("stop rx queues failed, vsi %d error %d\n",
			      vsi->idx_in_dev, ret);
	}

	sxe2_vsi_irqs_disable(vsi);

	if (need_reset)
		sxe2_trigger_and_wait_resetting(adapter);

	sxe2_vsi_txq_clean(vsi);

	sxe2_vsi_rxq_clean(vsi);

	return ret;
}

s32 sxe2_vsi_up(struct sxe2_vsi *vsi)
{
	s32 ret;
	s32 rc;
	struct sxe2_adapter *adapter = vsi->adapter;

	ret = sxe2_tx_hw_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("tx hw configure failed, ret=%d\n", ret);
		goto l_end;
	}

	if (sxe2_xdp_is_enable(vsi)) {
		ret = sxe2_xdp_tx_hw_cfg(vsi);
		if (ret) {
			LOG_ERROR_BDF("xdp tx hw configure failed, ret=%d\n", ret);
			goto l_xdp_err;
		}
	}

	ret = sxe2_rx_hw_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi:%u type:%u rx queue cfg failed.(err:%d)\n",
			      vsi->idx_in_dev, vsi->type, ret);
		goto l_rx_err;
	}

	sxe2_vsi_irqs_setup(vsi);

	clear_bit(SXE2_VSI_S_DOWN, vsi->state);

	if (vsi->netdev && vsi->type == SXE2_VSI_T_PF)
		sxe2_vsi_carrier_on(vsi);

	return 0;

l_rx_err:
	if (sxe2_xdp_is_enable(vsi)) {
		rc = sxe2_xdp_txqs_stop(vsi);
		if (rc)
			LOG_ERROR_BDF("failed stop xdp rings, vsi %d error %d\n",
				      vsi->id_in_pf, rc);
	}

l_xdp_err:
	rc = sxe2_txqs_stop(vsi);
	if (rc) {
		LOG_ERROR_BDF("stop tx queues failed, vsi %d error %d\n",
			      vsi->idx_in_dev, rc);
	}

l_end:
	return ret;
}

s32 sxe2_vsi_down_up_unlock(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (!test_and_set_bit(SXE2_VSI_S_DOWN, vsi->state)) {
		ret = sxe2_vsi_down(vsi);
		if (ret) {
			LOG_DEV_ERR("sxe2_vsi_down err %d\n", ret);
			goto l_end;
		}

		ret = sxe2_vsi_up(vsi);
		if (ret) {
			LOG_DEV_ERR("sxe2_vsi_up err %d\n", ret);
			goto l_end;
		}
	}

l_end:

	return ret;
}

s32 sxe2_vsi_down_up(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;

	mutex_lock(&adapter->vsi_ctxt.lock);
	ret = sxe2_vsi_down_up_unlock(vsi);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_vsi_close(struct sxe2_vsi *vsi)
{
	s32 ret = 0;

	if (!test_and_set_bit(SXE2_VSI_S_CLOSE, vsi->state)) {
		if (!test_and_set_bit(SXE2_VSI_S_DOWN, vsi->state))
			ret = sxe2_vsi_down(vsi);

		sxe2_vsi_irqs_clear_free(vsi);

		sxe2_tx_rings_res_free(vsi);

		sxe2_rx_rings_res_free(vsi);
	}

	return ret;
}

static s32 __sxe2_vsi_disable_unlock(struct sxe2_vsi *vsi)
{
	s32 ret = 0;

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state))
		return ret;

	ret = sxe2_vsi_close(vsi);

	set_bit(SXE2_VSI_S_DISABLE, vsi->state);

	return ret;
}

s32 sxe2_vsi_disable_unlock(struct sxe2_vsi *vsi)
{
	s32 ret = 0;

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state))
		return ret;

	switch (vsi->type) {
	case SXE2_VSI_T_PF:
		ret = sxe2_main_vsi_disable_unlock(vsi);
		break;
	case SXE2_VSI_T_CTRL:
		ret = sxe2_ctrl_vsi_disable_unlock(vsi);
		break;
	case SXE2_VSI_T_MACVLAN:
		ret = sxe2_macvlan_vsi_disable(vsi);
		break;
	default:
		break;
	}

	set_bit(SXE2_VSI_S_DISABLE, vsi->state);

	return ret;
}

s32 sxe2_main_vsi_disable_unlock(struct sxe2_vsi *vsi)
{
	s32 ret = 0;

	if (vsi->type != SXE2_VSI_T_PF)
		return -EINVAL;

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state))
		return ret;

	if (vsi->netdev)
		ret = sxe2_vsi_close(vsi);

	set_bit(SXE2_VSI_S_DISABLE, vsi->state);

	return ret;
}

s32 sxe2_ctrl_vsi_disable_unlock(struct sxe2_vsi *vsi)
{
	if (vsi->type != SXE2_VSI_T_CTRL)
		return -EINVAL;

	return __sxe2_vsi_disable_unlock(vsi);
}

s32 sxe2_macvlan_vsi_disable(struct sxe2_vsi *vsi)
{
	if (vsi->type != SXE2_VSI_T_MACVLAN)
		return -EINVAL;

	return __sxe2_vsi_disable_unlock(vsi);
}

s32 sxe2_esw_vsi_disable_unlock(struct sxe2_vsi *vsi)
{
	s32 ret = 0;

	if (vsi->type != SXE2_VSI_T_ESW)
		return ret;

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state))
		return ret;

	ret = sxe2_vsi_close(vsi);

	set_bit(SXE2_VSI_S_DISABLE, vsi->state);

	return ret;
}

static s32 __sxe2_vsi_enable_unlock(struct sxe2_vsi *vsi)
{
	s32 ret = 0;

	if (!test_bit(SXE2_VSI_S_DISABLE, vsi->state))
		return 0;

	ret = sxe2_vsi_open(vsi);
	if (!ret)
		clear_bit(SXE2_VSI_S_DISABLE, vsi->state);

	return ret;
}

s32 sxe2_main_vsi_open(struct sxe2_vsi *vsi)
{
	s32 ret = 0;

	if (vsi->type != SXE2_VSI_T_PF)
		return -EINVAL;

	if (vsi->netdev && netif_running(vsi->netdev)) {
		ret = sxe2_vsi_open(vsi);
		if (ret)
			return ret;
	}

	return ret;
}

s32 sxe2_main_vsi_enable_unlock(struct sxe2_vsi *vsi)
{
	s32 ret = 0;

	if (vsi->type != SXE2_VSI_T_PF)
		return -EINVAL;

	if (!test_bit(SXE2_VSI_S_DISABLE, vsi->state))
		return 0;

	if (vsi->netdev && netif_running(vsi->netdev)) {
		ret = sxe2_vsi_open(vsi);
		if (ret)
			return ret;
	}

	clear_bit(SXE2_VSI_S_DISABLE, vsi->state);

	return ret;
}

s32 sxe2_ctrl_vsi_enable_unlock(struct sxe2_vsi *vsi)
{
	if (vsi->type != SXE2_VSI_T_CTRL)
		return -EINVAL;

	return __sxe2_vsi_enable_unlock(vsi);
}

s32 sxe2_macvlan_vsi_enable_unlock(struct sxe2_vsi *vsi)
{
	if (vsi->type != SXE2_VSI_T_MACVLAN)
		return -EINVAL;

	if (test_bit(SXE2_VSI_S_MACVLAN_DEL, vsi->state))
		return 0;

	return __sxe2_vsi_enable_unlock(vsi);
}

s32 sxe2_esw_vsi_enable_unlock(struct sxe2_vsi *vsi)
{
	if (vsi->type != SXE2_VSI_T_ESW)
		return -EINVAL;
	return __sxe2_vsi_enable_unlock(vsi);
}

s32 sxe2_vsi_enable_unlock(struct sxe2_vsi *vsi)
{
	s32 ret = 0;

	if (!test_bit(SXE2_VSI_S_DISABLE, vsi->state))
		return 0;

	switch (vsi->type) {
	case SXE2_VSI_T_PF:
		ret = sxe2_main_vsi_enable_unlock(vsi);
		break;
	case SXE2_VSI_T_CTRL:
		ret = sxe2_ctrl_vsi_enable_unlock(vsi);
		break;
	case SXE2_VSI_T_MACVLAN:
		ret = sxe2_macvlan_vsi_enable_unlock(vsi);
		break;
	case SXE2_VSI_T_ESW:
		ret = sxe2_esw_vsi_enable_unlock(vsi);
		break;
	default:
		break;
	}

	return ret;
}

s32 sxe2_vsi_disable_all(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi;
	u16 i;

	rtnl_lock();
	mutex_lock(&adapter->vsi_ctxt.lock);
	sxe2_for_each_vsi(&adapter->vsi_ctxt, i)
	{
		vsi = adapter->vsi_ctxt.vsi[i];
		if (!vsi)
			continue;
		if (sxe2_vsi_disable_unlock(vsi))
			ret = -EIO;
	}
	mutex_unlock(&adapter->vsi_ctxt.lock);
	rtnl_unlock();

	return ret;
}

s32 sxe2_vsi_enable_by_type(struct sxe2_adapter *adapter, enum sxe2_vsi_type type)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi;
	u16 i;

	mutex_lock(&adapter->vsi_ctxt.lock);
	sxe2_for_each_vsi(&adapter->vsi_ctxt, i)
	{
		vsi = adapter->vsi_ctxt.vsi[i];
		if (!vsi)
			continue;
		if (!vsi || vsi->type != type)
			continue;
		if (sxe2_vsi_enable_unlock(vsi))
			ret = -EIO;
	}
	mutex_unlock(&adapter->vsi_ctxt.lock);

	return ret;
}

struct sxe2_vsi_coalesce {
	u8 tx_valid;
	u8 rx_valid;
	u16 rate_limit;
	u16 tx_itr;
	u16 rx_itr;
	u16 tx_itr_mode;
	u16 rx_itr_mode;
};

STATIC void sxe2_vsi_coalesce_store(struct sxe2_vsi *vsi,
				    struct sxe2_vsi_coalesce *coalesce)
{
	s32 idx;
	struct sxe2_irq_data *irq_data;

	if (!vsi->irqs.irq_data)
		return;

	sxe2_for_each_vsi_irq(vsi, idx)
	{
		irq_data = vsi->irqs.irq_data[idx];
		coalesce[idx].tx_itr = irq_data->tx.itr_setting;
		coalesce[idx].rx_itr = irq_data->rx.itr_setting;
		coalesce[idx].rate_limit = irq_data->rate_limit;
		coalesce[idx].tx_itr_mode = irq_data->tx.itr_mode;
		coalesce[idx].rx_itr_mode = irq_data->rx.itr_mode;

		if (SXE2_IRQ_HAS_TXQ(irq_data))
			coalesce[idx].tx_valid = true;
		if (SXE2_IRQ_HAS_RXQ(irq_data))
			coalesce[idx].rx_valid = true;
	}
}

STATIC void sxe2_vsi_coalesce_set(struct sxe2_vsi *vsi,
				  struct sxe2_vsi_coalesce *coalesce,
				  u16 old_irq_cnt)
{
	s32 i;
	u16 default_coalesce_tx = coalesce[0].tx_itr;
	u16 default_coalesce_rx = coalesce[0].rx_itr;
	u16 default_tx_itr_mode = coalesce[0].tx_itr_mode;
	u16 default_rx_itr_mode = coalesce[0].rx_itr_mode;
	u16 default_rate_limit = coalesce[0].rate_limit;
	struct sxe2_irq_data *irq_data;
	struct sxe2_hw *hw = &vsi->adapter->hw;

	for (i = 0; i < old_irq_cnt && i < vsi->irqs.cnt; i++) {
		irq_data = vsi->irqs.irq_data[i];
		if (SXE2_IRQ_HAS_TXQ(irq_data) && coalesce[i].tx_valid) {
			irq_data->tx.itr_mode = coalesce[i].tx_itr_mode;
			irq_data->tx.itr_setting = coalesce[i].tx_itr;
			sxe2_itr_set(irq_data, &irq_data->tx, coalesce[i].tx_itr);
		} else if (SXE2_IRQ_HAS_TXQ(irq_data)) {
			irq_data->tx.itr_mode = default_tx_itr_mode;
			irq_data->tx.itr_setting = default_coalesce_tx;
			sxe2_itr_set(irq_data, &irq_data->tx, default_coalesce_tx);
		}
		if (SXE2_IRQ_HAS_RXQ(irq_data) && coalesce[i].rx_valid) {
			irq_data->rx.itr_mode = coalesce[i].rx_itr_mode;
			irq_data->rx.itr_setting = coalesce[i].rx_itr;
			sxe2_itr_set(irq_data, &irq_data->rx, coalesce[i].rx_itr);
		} else if (SXE2_IRQ_HAS_RXQ(irq_data)) {
			irq_data->rx.itr_mode = default_rx_itr_mode;
			irq_data->rx.itr_setting = default_coalesce_rx;
			sxe2_itr_set(irq_data, &irq_data->rx, default_coalesce_rx);
		}
		irq_data->rate_limit = coalesce[i].rate_limit;
		sxe2_hw_irq_rate_limit_set(hw, irq_data->idx_in_pf,
					   irq_data->rate_limit);
	}
	for (; i < vsi->irqs.cnt; i++) {
		irq_data = vsi->irqs.irq_data[i];

		irq_data->tx.itr_setting = default_coalesce_tx;
		sxe2_itr_set(irq_data, &irq_data->tx, default_coalesce_tx);

		irq_data->rx.itr_setting = default_coalesce_rx;
		sxe2_itr_set(irq_data, &irq_data->rx, default_coalesce_rx);

		irq_data->rate_limit = default_rate_limit;
		sxe2_hw_irq_rate_limit_set(hw, irq_data->idx_in_pf,
					   irq_data->rate_limit);
	}
}

#ifdef HAVE_XDP_SUPPORT
STATIC s32 sxe2_vsi_xdp_qs_stats_realloc(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	u16 req_txq = (u16)vsi->num_xdp_txq;
	struct sxe2_queue_stats **xdp_stats;
	struct sxe2_vsi_qs_stats *vsi_qs_stats;
	u16 i;

	vsi_qs_stats = &vsi->vsi_qs_stats;
	if (req_txq < vsi->xdp_rings.q_cnt) {
		for (i = req_txq; i < vsi->xdp_rings.q_cnt; i++) {
			kfree(vsi_qs_stats->xdp_stats[i]);
			WRITE_ONCE(vsi_qs_stats->xdp_stats[i], NULL);
		}
	}

	xdp_stats = vsi_qs_stats->xdp_stats;
#ifdef SXE2_TEST
	vsi_qs_stats->xdp_stats =
	  (struct sxe2_queue_stats **)
	    SXE2_REALLOC(vsi_qs_stats->xdp_stats, req_txq,
			 sizeof(*vsi_qs_stats->xdp_stats), GFP_KERNEL | __GFP_ZERO,
			 vsi->xdp_rings.q_cnt);
#else
	vsi_qs_stats->xdp_stats =
	  (struct sxe2_queue_stats **)
	    SXE2_REALLOC(vsi_qs_stats->xdp_stats, req_txq,
			 sizeof(*vsi_qs_stats->xdp_stats), GFP_KERNEL | __GFP_ZERO);
#endif
	if (!vsi_qs_stats->xdp_stats) {
		LOG_ERROR_BDF("alloc txqs stats failed, count: %d, size: %zu.\n",
			      vsi->xdp_rings.q_cnt,
			      sizeof(*vsi_qs_stats->xdp_stats));
		vsi_qs_stats->xdp_stats = xdp_stats;
		return -ENOMEM;
	}

	return 0;
}
#endif

s32 sxe2_vsi_recfg(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;

	ret = sxe2_vsi_hw_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi:%d hw cfg failed %d\n", vsi->id_in_pf, ret);
		goto l_end;
	}

	ret = sxe2_txsched_lan_vsi_cfg(vsi);
	if (ret)
		goto l_defcfg;

	ret = sxe2_vsi_rss_init(vsi);
	if (ret)
		goto l_defcfg;

	if (vsi->type == SXE2_VSI_T_PF) {
		ret = sxe2_rss_replay_hash_cfg(&vsi->adapter->rss_flow_ctxt,
					       vsi->id_in_pf);
		if (ret)
			goto l_defcfg;
	}

	(void)mutex_lock(&adapter->switch_ctxt.evb_mode_lock);
	if ((adapter->switch_ctxt.evb_mode == BRIDGE_MODE_VEB ||
	     vsi->type == SXE2_VSI_T_LB) &&
	    sxe2_vsi_loopback_control(adapter, vsi->idx_in_dev, true)) {
		(void)mutex_unlock(&adapter->switch_ctxt.evb_mode_lock);
		goto l_defcfg;
	}
	(void)mutex_unlock(&adapter->switch_ctxt.evb_mode_lock);

	if (SXE2_VSI_T_PF == vsi->type || SXE2_VSI_T_VF == vsi->type) {
		ret = sxe2_src_vsi_prune_control(adapter, vsi->idx_in_dev, true);
		if (ret)
			goto l_defcfg;
	}

	return ret;
l_defcfg:
	(void)sxe2_vsi_hw_decfg(adapter, vsi->idx_in_dev);

l_end:
	return ret;
}

s32 sxe2_vsi_rebuild(struct sxe2_vsi *vsi, bool init)
{
	s32 ret;
	u16 old_irq_cnt = vsi->irqs.cnt;

	if (!vsi->irqs.coalesce) {
		vsi->irqs.coalesce =
				kcalloc(old_irq_cnt, sizeof(*vsi->irqs.coalesce),
					GFP_KERNEL);
		if (!vsi->irqs.coalesce)
			return -ENOMEM;

		sxe2_vsi_coalesce_store(vsi, vsi->irqs.coalesce);
	}

	(void)sxe2_txsched_lan_vsi_rm(vsi);

	sxe2_vsi_irqs_deinit(vsi);

#ifdef HAVE_XDP_SUPPORT
	if (sxe2_xdp_is_enable(vsi) && vsi->type == SXE2_VSI_T_PF)
		(void)sxe2_destroy_xdp_rings(vsi, true);
#endif

	sxe2_vsi_queues_deinit(vsi);

	ret = sxe2_vsi_queues_init(vsi);
	if (ret)
		goto l_queue_init_failed;

	if (sxe2_vsi_qs_stats_init(vsi))
		goto l_queue_init_failed;

	ret = sxe2_vsi_irqs_init(vsi);
	if (ret)
		goto l_queue_init_failed;

	ret = sxe2_vsi_recfg(vsi);
	if (ret)
		goto l_queue_init_failed;

#ifdef HAVE_XDP_SUPPORT
	if (sxe2_xdp_is_enable(vsi) && vsi->type == SXE2_VSI_T_PF) {
		sxe2_xdp_queue_cnt_set(vsi, vsi->rxqs.q_cnt);

		(void)sxe2_vsi_xdp_qs_stats_realloc(vsi);
		ret = sxe2_prepare_xdp_rings(vsi, vsi->xdp_prog);
		if (ret)
			goto l_queue_init_failed;
	}
#endif

	sxe2_vsi_coalesce_set(vsi, vsi->irqs.coalesce, old_irq_cnt);
	kfree(vsi->irqs.coalesce);
	vsi->irqs.coalesce = NULL;

	return 0;

l_queue_init_failed:
	(void)sxe2_vsi_disable_unlock(vsi);

	return ret;
}

s32 sxe2_vsi_rebuild_by_type(struct sxe2_adapter *adapter, enum sxe2_vsi_type type,
			     bool init)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi;
	u16 i;

	mutex_lock(&adapter->vsi_ctxt.lock);
	sxe2_for_each_vsi(&adapter->vsi_ctxt, i)
	{
		vsi = adapter->vsi_ctxt.vsi[i];
		if (!vsi)
			continue;
		if (!vsi || vsi->type != type)
			continue;

		if (vsi->type == SXE2_VSI_T_PF) {
			ret = sxe2_switch_fltr_restore_prepare(adapter);
			if (ret) {
				LOG_DEV_ERR("adapter %d switch filter restore \t"
					    "prepare failed, ret %d\n",
					    adapter->pf_idx, ret);
				break;
			}
		}

		ret = sxe2_vsi_rebuild(vsi, init);
		if (ret)
			break;

		ret = sxe2_vsi_l2_fltr_restore(vsi);
		if (ret)
			break;

		LOG_DEBUG_BDF("pf_idx[%u] vsi_id_in_pf[%u] vsi_idx_in_dev[%u].\n",
			      adapter->pf_idx, vsi->id_in_pf, vsi->idx_in_dev);
	}
	mutex_unlock(&adapter->vsi_ctxt.lock);

	return ret;
}

struct sxe2_vsi *sxe2_macvlan_vsi_create(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi_cfg_params vsi_create = {};
	struct sxe2_vsi *vsi;

	vsi_create.type = SXE2_VSI_T_MACVLAN;

	vsi = sxe2_vsi_create_unlock(adapter, &vsi_create);
	if (!vsi)
		return NULL;

	return vsi;
}

void sxe2_vsi_id_in_dev_clear(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *vsi;
	u16 i;

	mutex_lock(&adapter->vsi_ctxt.lock);
	sxe2_for_each_vsi(&adapter->vsi_ctxt, i)
	{
		vsi = adapter->vsi_ctxt.vsi[i];
		if (!vsi)
			continue;

		vsi->idx_in_dev = SXE2_VSI_ID_INVALID;
	}
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

struct sxe2_addr_node *sxe2_mac_addr_find(struct sxe2_vsi *vsi, const u8 *macaddr)
{
	struct sxe2_addr_node *node = NULL;

	list_for_each_entry(node, &vsi->mac_filter.mac_addr_list, list) {
		if (ether_addr_equal(macaddr, node->mac_addr))
			return node;
	}
	return NULL;
}

int sxe2_mac_addr_add(struct sxe2_vsi *vsi, const u8 *addr,
		      enum sxe2_mac_owner owner)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_addr_node *node = NULL;
	struct sxe2_mac_filter *mac_filter = &vsi->mac_filter;
	struct sxe2_vsi *user_pf_vsi = NULL;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;

	mutex_lock(&switch_ctxt->mac_addr_lock);

	node = sxe2_mac_addr_find(vsi, addr);
	if (!node) {
		node = kzalloc(sizeof(*node), GFP_KERNEL);
		if (!node) {
			LOG_ERROR_BDF("create list node for mac:%pM failed.\n",
				      addr);
			ret = -ENOMEM;
			goto l_end;
		}

		user_pf_vsi = sxe2_vsi_get_by_type_unlock(adapter,
							  SXE2_VSI_T_DPDK_PF);
		if (user_pf_vsi && is_unicast_ether_addr(addr)) {
			if (!sxe2_mac_addr_find(user_pf_vsi, addr)) {
				ret = sxe2_mac_rule_add(vsi, addr);
				if (ret == -EEXIST) {
					LOG_WARN_BDF("mac filter exist, addr %pM\n",
						     addr);
					ret = 0;
				} else if (ret) {
					kfree(node);
					goto l_end;
				}
			}
		} else {
			ret = sxe2_mac_rule_add(vsi, addr);
			if (ret == -EEXIST) {
				LOG_WARN_BDF("mac filter exist, addr %pM\n", addr);
				ret = 0;
			} else if (ret) {
				kfree(node);
				goto l_end;
			}
		}

		ether_addr_copy(node->mac_addr, addr);
		list_add_tail(&node->list, &mac_filter->mac_addr_list);
	}

	set_bit((s32)owner, &node->usage);

l_end:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
	return ret;
}

int sxe2_mac_addr_del(struct sxe2_vsi *vsi, const u8 *addr,
		      enum sxe2_mac_owner owner)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_addr_node *node = NULL;
	s32 owner_nr = (s32)owner;
	struct sxe2_vsi *user_pf_vsi = NULL;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;

	mutex_lock(&switch_ctxt->mac_addr_lock);

	node = sxe2_mac_addr_find(vsi, addr);
	if (!node) {
		LOG_WARN_BDF("mac filter not exist, addr %pM\n", addr);
		goto l_end;
	}

	if (!test_bit(owner_nr, &node->usage)) {
		LOG_WARN_BDF("mac not belong to owner %d, addr %pM, usage %lx\n",
			     owner_nr, addr, node->usage);
		goto l_end;
	}
	clear_bit(owner_nr, &node->usage);

	if (node->usage)
		goto l_end;

	user_pf_vsi = sxe2_vsi_get_by_type_unlock(adapter, SXE2_VSI_T_DPDK_PF);
	if (user_pf_vsi && is_unicast_ether_addr(addr)) {
		if (!sxe2_mac_addr_find(user_pf_vsi, addr)) {
			ret = sxe2_mac_rule_del(adapter, vsi->idx_in_dev, addr);
			if (ret == -ENOENT) {
				LOG_WARN_BDF("mac filter not exist, addr %pM\n",
					     addr);
				ret = 0;
			} else if (ret) {
				LOG_ERROR_BDF("del mac %pM failed err:%d\n", addr,
					      ret);
				set_bit(owner_nr, &node->usage);
				goto l_end;
			}
		}
	} else {
		ret = sxe2_mac_rule_del(adapter, vsi->idx_in_dev, addr);
		if (ret == -ENOENT) {
			LOG_WARN_BDF("mac filter not exist, addr %pM\n", addr);
			ret = 0;
		} else if (ret) {
			LOG_ERROR_BDF("del mac %pM failed err:%d\n", addr, ret);
			set_bit(owner_nr, &node->usage);
			goto l_end;
		}
	}

	sxe2_switch_mac_node_del_and_free(node);

l_end:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
	return ret;
}

struct sxe2_vsi *sxe2_vsi_get_by_idx(struct sxe2_adapter *adapter, u16 idx_in_dev)
{
	struct sxe2_vsi *vsi = NULL;
	s32 i = 0;
	bool found = false;

	sxe2_for_each_vsi(&adapter->vsi_ctxt, i)
	{
		vsi = adapter->vsi_ctxt.vsi[i];
		if (!vsi)
			continue;
		if (vsi->idx_in_dev == idx_in_dev) {
			found = true;
			break;
		}
	}

	if (!found)
		vsi = NULL;

	return vsi;
}

struct sxe2_vsi *sxe2_vsi_get_by_type_unlock(struct sxe2_adapter *adapter,
					     enum sxe2_vsi_type target_type)
{
	struct sxe2_vsi *vsi;
	u16 i;

	lockdep_assert_held(&adapter->vsi_ctxt.lock);

	sxe2_for_each_vsi(&adapter->vsi_ctxt, i)
	{
		vsi = adapter->vsi_ctxt.vsi[i];

		if (!vsi)
			continue;

		if (vsi->type != target_type)
			continue;

		if (target_type == SXE2_VSI_T_VF ||
		    target_type == SXE2_VSI_T_DPDK_VF) {
			continue;
		}

		return vsi;
	}

	return NULL;
}

s32 sxe2_dpdk_vsi_create(struct sxe2_adapter *adapter,
			 struct sxe2_vsi_cfg_params *params,
			 struct sxe2_fwc_vsi_crud_resp *resp)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi;

	vsi = sxe2_vsi_create(adapter, params);
	if (!vsi) {
		LOG_ERROR_BDF("dpdk pf vsi create fail.\n");
		return -ENOMEM;
	}

	resp->vsi_id = vsi->idx_in_dev;

	LOG_INFO_BDF("dpdk pf vsi create success vsi_id_in_pf:%d \t"
		     "vsi_id_in_dev:%d.\n",
		     vsi->id_in_pf, vsi->idx_in_dev);

	return ret;
}

s32 sxe2_dpdk_vsi_destroy(struct sxe2_adapter *adapter,
			  struct sxe2_vsi_cfg_params *params)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, params->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", params->vsi_id);
		ret = -EINVAL;
		goto l_unlock;
	}

	(void)sxe2_user_l2_feature_clean(adapter, vsi->idx_in_dev);

	sxe2_vsi_destroy_unlock(vsi);
	LOG_INFO_BDF("dpdk vsi_in_dev:%d destroy done.\n", params->vsi_id);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

static s32 sxe2_dpdk_pfvsi_resource_release(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_type_unlock(adapter, SXE2_VSI_T_DPDK_PF);
	if (!vsi) {
		mutex_unlock(&adapter->vsi_ctxt.lock);
		LOG_ERROR_BDF("dpdk vsi null.\n");
		ret = -EINVAL;
		return ret;
	}

	if (sxe2_txqs_stop(vsi))
		LOG_DEV_ERR("vsi:%u txqs disable failed.\n", vsi->idx_in_dev);

	if (sxe2_rxqs_stop(vsi))
		LOG_DEV_ERR("vsi:%u rxqs disable failed.\n", vsi->idx_in_dev);

	sxe2_vsi_irqs_disable(vsi);

	LOG_INFO_BDF("dpdk vsi id_in_pf:%d id_in_dev:%d destroy done.\n",
		     vsi->id_in_pf, vsi->idx_in_dev);

	(void)sxe2_txsch_ucmd_subtree_del(adapter, vsi->idx_in_dev,
					  adapter->tx_sched_ctxt.user_root_teid,
					  true);

	(void)sxe2_user_l2_feature_clean(adapter, vsi->idx_in_dev);

	mutex_unlock(&adapter->vsi_ctxt.lock);

	sxe2_vsi_destroy(vsi);

	return ret;
}

static s32 sxe2_dpdk_repr_recover(struct sxe2_adapter *adapter)
{
	u16 idx;
	struct sxe2_vf_node *vf_node = NULL;
	s32 ret = 0;

	if (test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags)) {
		sxe2_for_each_vf(adapter, idx)
		{
			(void)mutex_lock(SXE2_VF_NODE_LOCK(adapter, idx));
			vf_node = sxe2_vf_node_get(adapter, idx);
			ret = sxe2_eswitch_ucmd_repr_cfg(vf_node, false);
			if (ret) {
				(void)mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
				break;
			}
			(void)mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
		}
	}
	return ret;
}

static s32 sxe2_dpdk_reprvsi_resource_release(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi;

	ret = sxe2_dpdk_repr_recover(adapter);
	if (ret)
		LOG_ERROR_BDF("dpdk reprvsi resource release failed.\n");

	mutex_lock(&adapter->vsi_ctxt.lock);

	vsi = sxe2_vsi_get_by_type_unlock(adapter, SXE2_VSI_T_DPDK_ESW);
	if (!vsi) {
		LOG_ERROR_BDF("dpdk vsi null.\n");
		mutex_unlock(&adapter->vsi_ctxt.lock);
		ret = -EINVAL;
		return ret;
	}
	if (sxe2_txqs_stop(vsi))
		LOG_DEV_ERR("vsi:%u txqs disable failed.\n", vsi->idx_in_dev);
	if (sxe2_rxqs_stop(vsi))
		LOG_DEV_ERR("vsi:%u rxqs disable failed.\n", vsi->idx_in_dev);

	sxe2_vsi_irqs_disable(vsi);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_dpdk_resource_release(void *pf_adapter, struct sxe2_obj *obj)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = pf_adapter;

	ret = sxe2_dpdk_pfvsi_resource_release(adapter);
	if (ret)
		LOG_ERROR_BDF("dpdk pfvsi resource release failed.\n");

	ret = sxe2_dpdk_reprvsi_resource_release(adapter);
	if (ret)
		LOG_ERROR_BDF("dpdk reprvsi resource release failed.\n");

	ret = sxe2_dpdk_ipsec_resource_release(adapter, obj);
	if (ret)
		LOG_ERROR_BDF("dpdk ipsec resource release failed.\n");

	ret = sxe2_dpdk_q_map_resource_release(adapter, obj);
	if (ret)
		LOG_ERROR_BDF("dpdk q_map resource release failed.\n");

	return ret;
}

s32 sxe2_user_vsi_info_get(struct sxe2_adapter *adapter, u16 vsi_id,
			   struct sxe2_fwc_func_caps *caps)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", vsi_id);
		ret = -EINVAL;
		goto l_end;
	}

	caps->tx_caps.cnt = vsi->txqs.q_cnt;
	if (vsi->type == SXE2_VSI_T_DPDK_ESW) {
		caps->tx_caps.base_idx = adapter->q_ctxt.txq_layout.dpdk_esw_offset;
		LOG_DEBUG_BDF("dpdk esw vsi queue_in_pf:%d\n",
			      caps->tx_caps.base_idx);
	} else {
		caps->tx_caps.base_idx = vsi->txqs.base_idx_in_feature;
		LOG_DEBUG_BDF("vsi queue_in_pf:%d\n", caps->tx_caps.base_idx);
	}

	caps->msix_caps.cnt = vsi->irqs.cnt;
	caps->msix_caps.base_idx = vsi->irqs.base_idx_in_pf;

l_end:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}
