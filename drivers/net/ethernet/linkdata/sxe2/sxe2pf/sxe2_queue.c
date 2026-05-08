// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_queue.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_common.h"

STATIC u16 sxe2_rxq_preallocate_num_cal(struct sxe2_adapter *adapter)
{
	u16 rxq_cnt = 0;
	struct sxe2_queue_layout *rxq_layout = &adapter->q_ctxt.rxq_layout;

	rxq_cnt += rxq_layout->lb + rxq_layout->ctrl + rxq_layout->lan +
		   rxq_layout->dpdk;

	return rxq_cnt;
}

STATIC u16 sxe2_txq_preallocate_num_cal(struct sxe2_adapter *adapter)
{
	u16 txq_cnt = 0;
	struct sxe2_queue_layout *txq_layout = &adapter->q_ctxt.txq_layout;

	txq_cnt += txq_layout->lb + txq_layout->ctrl + txq_layout->lan +
		   txq_layout->dpdk;

	return txq_cnt;
}

u16 sxe2_usable_txqs_cnt_get(struct sxe2_adapter *adapter)
{
	struct sxe2_queue_layout *q_layout = &adapter->q_ctxt.txq_layout;
	u16 size = adapter->q_ctxt.max_txq_cnt;
	unsigned long *map = q_layout->txq_map;
	struct mutex *lock = &adapter->q_ctxt.lock;
	u16 cnt = 0;
	unsigned long bit = sxe2_txq_preallocate_num_cal(adapter);

	mutex_lock(lock);
	for_each_clear_bit_from(bit, map, size) {
		cnt++;
	}
	mutex_unlock(lock);

	return cnt;
}

u16 sxe2_usable_rxqs_cnt_get(struct sxe2_adapter *adapter)
{
	struct sxe2_queue_layout *q_layout = &adapter->q_ctxt.rxq_layout;
	u16 size = adapter->q_ctxt.max_rxq_cnt;
	unsigned long *map = q_layout->rxq_map;
	struct mutex *lock = &adapter->q_ctxt.lock;
	u16 cnt = 0;
	unsigned long bit = sxe2_rxq_preallocate_num_cal(adapter);

	mutex_lock(lock);
	for_each_clear_bit_from(bit, map, size) {
		cnt++;
	}
	mutex_unlock(lock);

	return cnt;
}

STATIC s32 sxe2_qs_find_from_shared(struct sxe2_adapter *adapter, unsigned long *map,
				    u16 size, u16 start_idx, u16 cnt)
{
	s32 offset;

	offset = (s32)bitmap_find_next_zero_area(map, (s32)size, (s32)start_idx,
						 (s32)cnt, 0);
	if (offset >= (s32)size) {
		offset = -ENOMEM;
		LOG_ERROR_BDF("get %d qs from map(size %d) failed, ret=%d\n", cnt,
			      size, offset);
		goto l_end;
	}
	bitmap_set(map, (unsigned int)offset, (unsigned int)cnt);
l_end:
	return offset;
}

STATIC s32 sxe2_vsi_qs_offset_get(struct sxe2_vsi *vsi,
				  struct sxe2_queue_layout *q_layout,
				  unsigned long *map, u16 size, u16 cnt, u8 q_type)
{
	s32 offset;
	u8 vsi_type = vsi->type;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct mutex *lock = &adapter->q_ctxt.lock;
	u16 start_idx;
	u16 base_idx;

	if (q_type == SXE2_DATA_RQ)
		start_idx = sxe2_rxq_preallocate_num_cal(adapter);
	else
		start_idx = sxe2_txq_preallocate_num_cal(adapter);

	if (q_type == SXE2_DATA_XDP_TQ) {
		mutex_lock(lock);
		offset = sxe2_qs_find_from_shared(adapter, map, size, start_idx,
						  cnt);
		mutex_unlock(lock);
		goto l_end;
	}

	switch (vsi_type) {
	case SXE2_VSI_T_LB:
		offset = q_layout->lb_offset;
		break;
	case SXE2_VSI_T_PF:
		offset = q_layout->lan_offset;
		break;
	case SXE2_VSI_T_CTRL:
		offset = q_layout->ctrl_offset;
		break;
	case SXE2_VSI_T_ESW:
		offset = q_layout->esw_offset;
		break;
	case SXE2_VSI_T_MACVLAN:
		mutex_lock(lock);
		offset = (s32)sxe2_qs_find_from_shared(adapter, map, size, start_idx,
						       cnt);
		if (offset >= 0)
			q_layout->macvlan++;
		mutex_unlock(lock);
		break;
	case SXE2_VSI_T_VF:
	case SXE2_VSI_T_DPDK_VF:
		base_idx = (q_type == SXE2_DATA_TQ) ? vsi->txqs.base_idx_in_feature
						    : vsi->rxqs.base_idx_in_feature;
		offset = q_layout->sriov_offset +
			 adapter->vf_ctxt.q_cnt * (vsi->vf_node->vf_idx) + base_idx;
		break;
	case SXE2_VSI_T_DPDK_PF:
		offset = q_layout->dpdk_offset;
		break;
	case SXE2_VSI_T_DPDK_ESW:
		offset = q_layout->dpdk_esw_offset;
		break;
	default:
		offset = -1;
		break;
	}

l_end:
	return offset;
}

s32 sxe2_vsi_queues_get(struct sxe2_vsi *vsi, u8 q_type)
{
	s32 ret = 0;
	s32 offset;
	u16 i;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_queue_layout *q_layout = NULL;
	unsigned long *map;
	u16 size = 0;
	struct sxe2_vsi_queues *queues;
	u16 cnt = 0;

	switch (q_type) {
	case SXE2_DATA_TQ:
		size = adapter->q_ctxt.max_txq_cnt;
		queues = &vsi->txqs;
		cnt = queues->q_alloc;
		q_layout = &adapter->q_ctxt.txq_layout;
		map = q_layout->txq_map;
		break;
	case SXE2_DATA_RQ:
		size = adapter->q_ctxt.max_rxq_cnt;
		queues = &vsi->rxqs;
		cnt = queues->q_alloc;
		q_layout = &adapter->q_ctxt.rxq_layout;
		map = q_layout->rxq_map;
		break;
	case SXE2_DATA_XDP_TQ:
		size = adapter->q_ctxt.max_txq_cnt;
		queues = &vsi->xdp_rings;
		cnt = queues->q_alloc;
		q_layout = &adapter->q_ctxt.txq_layout;
		map = q_layout->txq_map;
		break;
	default:
		ret = -ENOMEM;
		goto l_end;
	}

	offset = sxe2_vsi_qs_offset_get(vsi, q_layout, map, size, cnt, q_type);
	if (offset < 0) {
		ret = -ENOMEM;
		LOG_DEV_ERR("vsi get %d qs failed.\n", cnt);
		goto l_end;
	}

	for (i = 0; i < cnt; i++)
		queues->q[i]->idx_in_pf = (u16)(i + offset);

l_end:
	return ret;
}

s32 sxe2_vsi_txrx_queues_get(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (vsi->rxqs.q_alloc > SXE2_VSI_TXRX_Q_MAX_CNT ||
	    vsi->txqs.q_alloc > SXE2_VSI_TXRX_Q_MAX_CNT) {
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe2_vsi_queues_get(vsi, SXE2_DATA_TQ);
	if (ret) {
		LOG_DEV_ERR("get txqs %d failed.\n", vsi->txqs.q_alloc);
		goto l_error;
	}

	ret = sxe2_vsi_queues_get(vsi, SXE2_DATA_RQ);
	if (ret) {
		LOG_DEV_ERR("get rxqs %d failed.\n", vsi->rxqs.q_alloc);
		goto l_error;
	}

	return ret;

l_error:
	sxe2_vsi_txrx_queues_put(vsi);
l_end:
	return ret;
}

STATIC void sxe2_vsi_queues_put(struct sxe2_vsi *vsi, u8 q_type)
{
	u16 i;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_queue_layout *q_layout = NULL;
	unsigned long *map = NULL;
	struct sxe2_vsi_queues *queues = NULL;
	struct mutex *lock = &adapter->q_ctxt.lock;

	switch (q_type) {
	case SXE2_DATA_TQ:
		queues = &vsi->txqs;
		q_layout = &adapter->q_ctxt.txq_layout;
		map = q_layout->txq_map;
		break;
	case SXE2_DATA_RQ:
		queues = &vsi->rxqs;
		q_layout = &adapter->q_ctxt.rxq_layout;
		map = q_layout->rxq_map;
		break;
	case SXE2_DATA_XDP_TQ:
		queues = &vsi->xdp_rings;
		q_layout = &adapter->q_ctxt.txq_layout;
		map = q_layout->txq_map;
		break;
	default:
		LOG_ERROR_BDF("invalid q_type %d.\n", q_type);
		return;
	}

	mutex_lock(lock);
	for (i = 0; i < queues->q_alloc; i++) {
		if (queues->q[i]->idx_in_pf != SXE2_Q_IDX_INVAL) {
			clear_bit(queues->q[i]->idx_in_pf, map);
			queues->q[i]->idx_in_pf = SXE2_Q_IDX_INVAL;
		}
	}

	if (vsi->type == SXE2_VSI_T_MACVLAN)
		q_layout->macvlan--;

	mutex_unlock(lock);
}

void sxe2_vsi_txrx_queues_put(struct sxe2_vsi *vsi)
{
	sxe2_vsi_queues_put(vsi, SXE2_DATA_TQ);

	sxe2_vsi_queues_put(vsi, SXE2_DATA_RQ);
}

STATIC void sxe2_safemode_q_layout_init(struct sxe2_adapter *adapter)
{
	struct sxe2_queue_layout *txq_layout = &adapter->q_ctxt.txq_layout;
	struct sxe2_queue_layout *rxq_layout = &adapter->q_ctxt.rxq_layout;
	u16 max_txq = adapter->q_ctxt.max_txq_cnt;
	u16 max_rxq = adapter->q_ctxt.max_rxq_cnt;

	txq_layout->lb = 0;
	txq_layout->lb_offset = 0;

	txq_layout->ctrl = 0;
	txq_layout->ctrl_offset = 0;

	txq_layout->lan = 1;
	txq_layout->lan_offset = 0;

	txq_layout->xdp = 0;
	txq_layout->xdp_offset = txq_layout->lan_offset + txq_layout->lan;

	txq_layout->macvlan = 0;
	txq_layout->macvlan_offset = txq_layout->xdp_offset + txq_layout->xdp;

	txq_layout->dpdk_esw = 0;
	txq_layout->dpdk_esw_offset = max_txq;

	txq_layout->esw = 0;
	txq_layout->esw_offset = max_txq;

	txq_layout->sriov = 0;
	txq_layout->sriov_offset = max_txq;

	rxq_layout->lb = 0;
	rxq_layout->lb_offset = 0;

	rxq_layout->ctrl = 0;
	rxq_layout->ctrl_offset = 0;

	rxq_layout->lan = 1;
	rxq_layout->lan_offset = 0;

	rxq_layout->xdp = 0;
	rxq_layout->xdp_offset = rxq_layout->lan_offset + rxq_layout->lan;

	rxq_layout->macvlan = 0;
	rxq_layout->macvlan_offset = rxq_layout->xdp_offset + rxq_layout->xdp;

	rxq_layout->dpdk_esw = 0;
	rxq_layout->dpdk_esw_offset = max_rxq;

	rxq_layout->esw = 0;
	rxq_layout->esw_offset = max_rxq;

	rxq_layout->sriov = 0;
	rxq_layout->sriov_offset = max_rxq;
}

STATIC void sxe2_q_layout_init(struct sxe2_adapter *adapter)
{
	struct sxe2_queue_layout *txq_layout = &adapter->q_ctxt.txq_layout;
	struct sxe2_queue_layout *rxq_layout = &adapter->q_ctxt.rxq_layout;
	u16 max_txq = adapter->q_ctxt.max_txq_cnt;
	u16 max_rxq = adapter->q_ctxt.max_rxq_cnt;

	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u32 local_cpu_cnt = sxe2_local_cpus_cnt_get(dev);
	u32 standard_cpu_cnt = sxe2_standardize_cpu_cnt(local_cpu_cnt);
	u32 mode = (u32)sxe2_com_mode_get(adapter);

	if (mode == SXE2_COM_MODULE_KERNEL) {
		txq_layout->lb = 1;
		txq_layout->lb_offset = 0;

		txq_layout->ctrl = 1;
		txq_layout->ctrl_offset = txq_layout->lb_offset + txq_layout->lb;

		txq_layout->lan_offset = txq_layout->ctrl_offset + txq_layout->ctrl;
		txq_layout->lan = (u16)min_t(u32, standard_cpu_cnt,
					     (u32)adapter->irq_ctxt.irq_layout.lan);
		if ((txq_layout->lan + txq_layout->lan_offset) > max_txq)
			txq_layout->lan = (u16)(max_txq - txq_layout->lan_offset);
		txq_layout->dpdk_offset = txq_layout->lan_offset + txq_layout->lan;
	} else if (mode == SXE2_COM_MODULE_DPDK) {
		txq_layout->dpdk = SXE2_DPDK_QUEUE_MAX_CNT;
		txq_layout->dpdk_offset = txq_layout->lan_offset + txq_layout->lan;
		if ((txq_layout->dpdk + txq_layout->dpdk_offset) > max_txq)
			txq_layout->dpdk = (u16)(max_txq - txq_layout->dpdk_offset);
	} else {
		txq_layout->lb = 1;
		txq_layout->lb_offset = 0;

		txq_layout->ctrl = 1;
		txq_layout->ctrl_offset = txq_layout->lb_offset + txq_layout->lb;

		txq_layout->lan_offset = txq_layout->ctrl_offset + txq_layout->ctrl;
		txq_layout->lan = (u16)min_t(u32, standard_cpu_cnt,
					     (u32)adapter->irq_ctxt.irq_layout.lan);
		if ((txq_layout->lan + txq_layout->lan_offset) > max_txq)
			txq_layout->lan = (u16)(max_txq - txq_layout->lan_offset);

		txq_layout->dpdk_offset = txq_layout->lan_offset + txq_layout->lan;
		txq_layout->dpdk = SXE2_DPDK_QUEUE_DFLT_CNT;
		if ((txq_layout->dpdk + txq_layout->dpdk_offset) > max_txq)
			txq_layout->dpdk = (u16)(max_txq - txq_layout->dpdk_offset);
	}

	txq_layout->xdp = 0;
	txq_layout->xdp_offset = txq_layout->dpdk_offset + txq_layout->dpdk;

	txq_layout->macvlan = 0;
	txq_layout->macvlan_offset = txq_layout->xdp_offset + txq_layout->xdp;

	txq_layout->dpdk_esw = 0;
	txq_layout->dpdk_esw_offset = max_txq;

	txq_layout->esw = 0;
	txq_layout->esw_offset = max_txq;

	txq_layout->sriov = 0;
	txq_layout->sriov_offset = max_txq;

	if (mode == SXE2_COM_MODULE_KERNEL) {
		rxq_layout->lb = 1;
		rxq_layout->lb_offset = 0;

		rxq_layout->ctrl = 1;
		rxq_layout->ctrl_offset = rxq_layout->lb_offset + rxq_layout->lb;

		rxq_layout->lan_offset = rxq_layout->ctrl_offset + rxq_layout->ctrl;
		rxq_layout->lan = (u16)min_t(u32, standard_cpu_cnt,
					     (u32)adapter->irq_ctxt.irq_layout.lan);
		if ((rxq_layout->lan + rxq_layout->lan_offset) > max_txq)
			rxq_layout->lan = (u16)(max_txq - rxq_layout->lan_offset);
		rxq_layout->dpdk_offset = rxq_layout->lan_offset + rxq_layout->lan;
	} else if (mode == SXE2_COM_MODULE_DPDK) {
		rxq_layout->dpdk = SXE2_DPDK_QUEUE_MAX_CNT;
		rxq_layout->dpdk_offset = rxq_layout->lan_offset + rxq_layout->lan;
		if ((rxq_layout->dpdk + rxq_layout->dpdk_offset) > max_txq)
			rxq_layout->dpdk = (u16)(max_txq - rxq_layout->dpdk_offset);
	} else {
		rxq_layout->lb = 1;
		rxq_layout->lb_offset = 0;

		rxq_layout->ctrl = 1;
		rxq_layout->ctrl_offset = rxq_layout->lb_offset + rxq_layout->lb;

		rxq_layout->lan_offset = rxq_layout->ctrl_offset + rxq_layout->ctrl;
		rxq_layout->lan = (u16)min_t(u32, standard_cpu_cnt,
					     (u32)adapter->irq_ctxt.irq_layout.lan);
		if ((rxq_layout->lan + rxq_layout->lan_offset) > max_txq)
			rxq_layout->lan = (u16)(max_txq - rxq_layout->lan_offset);

		rxq_layout->dpdk_offset = rxq_layout->lan_offset + rxq_layout->lan;
		rxq_layout->dpdk = SXE2_DPDK_QUEUE_DFLT_CNT;
		if ((rxq_layout->dpdk + rxq_layout->dpdk_offset) > max_txq)
			rxq_layout->dpdk = (u16)(max_txq - rxq_layout->dpdk_offset);
	}

	rxq_layout->xdp = 0;
	rxq_layout->xdp_offset = rxq_layout->dpdk_offset + rxq_layout->dpdk;

	rxq_layout->macvlan = 0;
	rxq_layout->macvlan_offset = rxq_layout->xdp_offset + rxq_layout->xdp;

	rxq_layout->dpdk_esw = 0;
	rxq_layout->dpdk_esw_offset = max_rxq;

	rxq_layout->esw = 0;
	rxq_layout->esw_offset = max_rxq;

	rxq_layout->sriov = 0;
	rxq_layout->sriov_offset = max_rxq;
}

void sxe2_queue_init(struct sxe2_adapter *adapter)
{
	if (sxe2_is_safe_mode(adapter))
		sxe2_safemode_q_layout_init(adapter);
	else
		sxe2_q_layout_init(adapter);
}

s32 sxe2_dpdk_abs_qid_get(struct sxe2_adapter *adapter,
			  struct sxe2_q_id_transe *params)
{
	struct sxe2_vsi *vsi;
	u16 base_idx;
	u16 max_cnt;
	s32 ret = 0;

	if (!adapter || !params) {
		ret = -EINVAL;
		LOG_ERROR_BDF("params invalid.\n");
		return ret;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, params->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("dpdk vsi_id:%d vsi null.\n", params->vsi_id);
		ret = -EINVAL;
		goto l_unlock;
	}

	if (params->is_tx) {
		max_cnt = vsi->txqs.q_cnt;
		base_idx = adapter->q_ctxt.txq_base_idx_in_dev;
	} else {
		max_cnt = vsi->rxqs.q_cnt;
		base_idx = adapter->q_ctxt.rxq_base_idx_in_dev;
	}

	if (params->q_id >= max_cnt) {
		LOG_ERROR_BDF("invalid queue_id:%d vsi queue cnt:% is_tx:%d\n",
			      params->q_id, max_cnt, params->is_tx);
		ret = -EINVAL;
		goto l_unlock;
	}

	if (params->is_tx)
		params->q_id_in_dev =
				vsi->txqs.q[params->q_id]->idx_in_pf + base_idx;
	else
		params->q_id_in_dev =
				vsi->rxqs.q[params->q_id]->idx_in_pf + base_idx;

	LOG_INFO_BDF("dpdk vsi_id:%d q_id_in_vsi:%d q_id_in_dev:%d is_tx:%d.\n",
		     params->vsi_id, params->q_id, params->q_id_in_dev,
		     params->is_tx);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}
