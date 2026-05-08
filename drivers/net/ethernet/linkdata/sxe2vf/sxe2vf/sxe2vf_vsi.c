// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_vsi.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>

#include "sxe2_log.h"
#include "sxe2vf_netdev.h"
#include "sxe2vf.h"
#include "sxe2vf_tx.h"
#include "sxe2vf_rx.h"
#include "sxe2vf_vsi.h"
#include "sxe2vf_rxft.h"

#ifdef SXE2VF_MAC_VLAN_CLEAR
void sxe2vf_adv_cfg_clear(struct sxe2vf_adapter *adapter)
{
	sxe2vf_l2_filter_clear(adapter);
}
#endif

void sxe2vf_adv_cfg_restore(struct sxe2vf_adapter *adapter)
{
	sxe2vf_l2_filter_rules_restore(adapter);

	(void)sxe2vf_fnav_rebuild(adapter);

	(void)sxe2vf_rss_rebuild(adapter);
}

static void sxe2vf_link_down(struct sxe2vf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	adapter->link_ctxt.link_up = false;
	LOG_INFO_BDF("tx carrier off link down.\n");
}

static s32 sxe2vf_txrx_queues_disable(struct sxe2vf_adapter *adapter)
{
	return sxe2vf_txrxq_dis_request(adapter, true);
}

STATIC s32 __sxe2vf_vsi_close(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	s32 ret = 0;

	sxe2vf_link_down(adapter);

	ret = sxe2vf_txrx_queues_disable(adapter);

	sxe2vf_queue_irq_disable(adapter);

	sxe2vf_tx_rings_clean(vsi);
	sxe2vf_rx_rings_clean(vsi);

	return ret;
}

s32 __sxe2vf_vsi_open(struct sxe2vf_vsi *vsi, bool is_change, bool need_up)
{
	s32 ret;
	struct sxe2vf_adapter *adapter = vsi->adapter;

	ret = sxe2vf_tx_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("open: tx config err, ret=%d\n", ret);
		return ret;
	}

	ret = sxe2vf_rx_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("open: rx config err, ret=%d\n", ret);
		(void)sxe2vf_txrxq_dis_request(adapter, false);
		goto l_tx_fail;
	}

	ret = sxe2vf_dev_mac_add(adapter);
	if (ret) {
		LOG_ERROR_BDF("vf dev mac add failed.(err:%d)\n", ret);
		goto l_rx_fail;
	}

	ret = sxe2vf_irq_cfg(vsi);
	if (ret)
		goto l_rx_fail;

	if (is_change) {
		(void)netif_set_real_num_rx_queues(adapter->netdev, vsi->rxqs.q_cnt);
		(void)netif_set_real_num_tx_queues(adapter->netdev, vsi->txqs.q_cnt);
	}

	clear_bit(SXE2VF_VSI_CLOSE, vsi->state);

	if (need_up)
		(void)sxe2vf_link_status_request(adapter);

	return 0;

l_rx_fail:
	(void)sxe2vf_txrxq_dis_request(adapter, false);
	sxe2vf_rx_rings_res_free(vsi);

l_tx_fail:
	sxe2vf_tx_rings_res_free(vsi);

	return ret;
}

s32 sxe2vf_vsi_open(struct sxe2vf_vsi *vsi)
{
	return __sxe2vf_vsi_open(vsi, true, true);
}

s32 sxe2vf_vsi_close(struct sxe2vf_vsi *vsi)
{
	s32 ret = 0;

	LOG_INFO("vsi:%u state:0x%lx.\n", vsi->vsi_id, *vsi->state);
	if (!test_and_set_bit(SXE2VF_VSI_CLOSE, vsi->state)) {
		ret = __sxe2vf_vsi_close(vsi);

		sxe2vf_vsi_irqs_free(vsi);

		sxe2vf_tx_rings_res_free(vsi);

		sxe2vf_rx_rings_res_free(vsi);
	}

	return ret;
}

s32 sxe2vf_vsi_disable(struct sxe2vf_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2vf_adapter *adapter = vsi->adapter;

	if (!test_and_set_bit(SXE2VF_VSI_DISABLE, vsi->state)) {
		ret = sxe2vf_vsi_close(vsi);
		if (ret)
			LOG_ERROR_BDF("vsi:%d close failed.(err:%d)\n", vsi->vsi_id,
				      ret);
	}

	return ret;
}

void sxe2vf_queues_depth_update(struct sxe2vf_vsi *vf_vsi)
{
	u16 i;

	sxe2vf_for_each_vsi_txq(vf_vsi, i)
	{
		vf_vsi->txqs.q[i]->depth = vf_vsi->txqs.depth;
	}

	sxe2vf_for_each_vsi_rxq(vf_vsi, i)
	{
		vf_vsi->rxqs.q[i]->depth = vf_vsi->rxqs.depth;
	}
}

s32 sxe2vf_vsi_reopen(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	s32 ret = 0;

	if (!test_bit(SXE2VF_VSI_CLOSE, vsi->state)) {
		ret = sxe2vf_vsi_close(vsi);
		if (ret) {
			LOG_ERROR_BDF("vsi:%u down fail.(err:%d).\n", vsi->vsi_id,
				      ret);
			goto l_out;
		}

		sxe2vf_queues_depth_update(vsi);

		ret = __sxe2vf_vsi_open(vsi, false, true);
		if (ret) {
			LOG_ERROR_BDF("vsi:%u up fail.(err:%d).\n", vsi->vsi_id,
				      ret);
			goto l_out;
		}

		LOG_INFO_BDF("vsi:%d down-up done.\n", vsi->vsi_id);
	}

l_out:
	return ret;
}

s32 sxe2vf_vsi_reopen_locked(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	s32 ret;

	mutex_lock(&adapter->vsi_ctxt.lock);
	ret = sxe2vf_vsi_reopen(vsi);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

void sxe2vf_vsi_qs_stats_deinit(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_vsi_qs_stats *vsi_qs_stat = &vsi->vsi_qs_stats;

	kfree(vsi_qs_stat->txqs_stats);
	vsi_qs_stat->txqs_stats = NULL;

	kfree(vsi_qs_stat->rxqs_stats);
	vsi_qs_stat->rxqs_stats = NULL;
}

s32 sxe2vf_vsi_qs_stats_init(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_vsi_qs_stats *vsi_qs_stats;
	struct sxe2vf_adapter *adapter = vsi->adapter;
	u16 i;

	vsi_qs_stats = &vsi->vsi_qs_stats;

	if (!vsi_qs_stats->txqs_stats) {
		vsi_qs_stats->txqs_stats = kcalloc(SXE2_VF_ETH_Q_NUM,
						   sizeof(*vsi_qs_stats->txqs_stats),
						   GFP_KERNEL);
		if (!vsi_qs_stats->txqs_stats) {
			LOG_ERROR_BDF("alloc txqs stats failed, count: %d, size: \t"
				      "%zu.\n",
				      SXE2_VF_ETH_Q_NUM,
				      sizeof(*vsi_qs_stats->txqs_stats));
			goto err_out;
		}

		for (i = 0; i < SXE2_VF_ETH_Q_NUM; i++)
			u64_stats_init(&vsi_qs_stats->txqs_stats[i].syncp);
	}

	if (!vsi_qs_stats->rxqs_stats) {
		vsi_qs_stats->rxqs_stats = kcalloc(SXE2_VF_ETH_Q_NUM,
						   sizeof(*vsi_qs_stats->rxqs_stats),
						   GFP_KERNEL);
		if (!vsi_qs_stats->rxqs_stats) {
			LOG_ERROR_BDF("alloc rxqs stats failed, count: %d, size: \t"
				      "%zu.\n",
				      SXE2_VF_ETH_Q_NUM,
				      sizeof(*vsi_qs_stats->rxqs_stats));
			goto err_out;
		}

		for (i = 0; i < SXE2_VF_ETH_Q_NUM; i++)
			u64_stats_init(&vsi_qs_stats->rxqs_stats[i].syncp);
	}

	sxe2vf_for_each_vsi_txq(vsi, i)
	{
		struct sxe2vf_queue *txq = vsi->txqs.q[i];

		txq->stats = &vsi_qs_stats->txqs_stats[i];
	}

	sxe2vf_for_each_vsi_rxq(vsi, i)
	{
		struct sxe2vf_queue *rxq = vsi->rxqs.q[i];

		rxq->stats = &vsi_qs_stats->rxqs_stats[i];
	}

	return 0;

err_out:
	sxe2vf_vsi_qs_stats_deinit(vsi);
	return -ENOMEM;
}

STATIC void sxe2vf_vsi_coalesce_store(struct sxe2vf_vsi *vsi,
				      struct sxe2vf_vsi_coalesce *coalesce)
{
	s32 idx;
	struct sxe2vf_irq_data *irq_data;

	if (!vsi->irqs.irq_data)
		return;

	sxe2vf_for_each_vsi_irq(vsi, idx)
	{
		irq_data = vsi->irqs.irq_data[idx];
		coalesce[idx].tx_itr = (u16)irq_data->tx.itr_setting;
		coalesce[idx].rx_itr = (u16)irq_data->rx.itr_setting;
		coalesce[idx].rate_limit = irq_data->rate_limit;
		coalesce[idx].tx_itr_mode = irq_data->tx.itr_mode;
		coalesce[idx].rx_itr_mode = irq_data->rx.itr_mode;

		if (SXE2VF_IRQ_HAS_TXQ(irq_data))
			coalesce[idx].tx_valid = true;
		if (SXE2VF_IRQ_HAS_RXQ(irq_data))
			coalesce[idx].rx_valid = true;
	}
}

STATIC void sxe2vf_vsi_coalesce_set(struct sxe2vf_vsi *vsi,
				    struct sxe2vf_vsi_coalesce *coalesce,
				    u16 old_irq_cnt)
{
	s32 i;
	u16 default_coalesce_tx = coalesce[0].tx_itr;
	u16 default_coalesce_rx = coalesce[0].rx_itr;
	u16 default_tx_itr_mode = coalesce[0].tx_itr_mode;
	u16 default_rx_itr_mode = coalesce[0].rx_itr_mode;
	struct sxe2vf_irq_data *irq_data;
	struct sxe2vf_adapter *adapter = vsi->adapter;
	struct sxe2vf_hw *hw = &adapter->hw;

	for (i = 0; i < old_irq_cnt && i < vsi->irqs.cnt; i++) {
		irq_data = vsi->irqs.irq_data[i];
		if (SXE2VF_IRQ_HAS_TXQ(irq_data) && coalesce[i].tx_valid) {
			irq_data->tx.itr_mode = coalesce[i].tx_itr_mode;
			irq_data->tx.itr_setting = coalesce[i].tx_itr;
			sxe2vf_hw_int_itr_set(hw, irq_data->tx.itr_idx, irq_data->irq_idx,
					      (irq_data->tx.itr_setting /
					       adapter->irq_ctxt.itr_gran) &
							SXE2VF_VF_INT_ITR_INTERVAL_MAX);
		} else if (SXE2VF_IRQ_HAS_TXQ(irq_data)) {
			irq_data->tx.itr_mode = default_tx_itr_mode;
			irq_data->tx.itr_setting = default_coalesce_tx;
			sxe2vf_hw_int_itr_set(hw, irq_data->tx.itr_idx, irq_data->irq_idx,
					      (irq_data->tx.itr_setting /
					       adapter->irq_ctxt.itr_gran) &
							SXE2VF_VF_INT_ITR_INTERVAL_MAX);
		}
		if (SXE2VF_IRQ_HAS_RXQ(irq_data) && coalesce[i].rx_valid) {
			irq_data->rx.itr_mode = coalesce[i].rx_itr_mode;
			irq_data->rx.itr_setting = coalesce[i].rx_itr;
			sxe2vf_hw_int_itr_set(hw, irq_data->rx.itr_idx, irq_data->irq_idx,
					      (irq_data->rx.itr_setting /
					       adapter->irq_ctxt.itr_gran) &
							SXE2VF_VF_INT_ITR_INTERVAL_MAX);
		} else if (SXE2VF_IRQ_HAS_RXQ(irq_data)) {
			irq_data->rx.itr_mode = default_rx_itr_mode;
			irq_data->rx.itr_setting = default_coalesce_rx;
			sxe2vf_hw_int_itr_set(hw, irq_data->rx.itr_idx, irq_data->irq_idx,
					      (irq_data->rx.itr_setting /
					       adapter->irq_ctxt.itr_gran) &
							SXE2VF_VF_INT_ITR_INTERVAL_MAX);
		}
	}
	for (; i < vsi->irqs.cnt; i++) {
		irq_data = vsi->irqs.irq_data[i];

		irq_data->tx.itr_setting = default_coalesce_tx;
		sxe2vf_hw_int_itr_set(hw, irq_data->tx.itr_idx, irq_data->irq_idx,
				      (irq_data->tx.itr_setting /
				       adapter->irq_ctxt.itr_gran) &
						SXE2VF_VF_INT_ITR_INTERVAL_MAX);

		irq_data->rx.itr_setting = default_coalesce_rx;
		sxe2vf_hw_int_itr_set(hw, irq_data->rx.itr_idx, irq_data->irq_idx,
				      (irq_data->rx.itr_setting /
				       adapter->irq_ctxt.itr_gran) &
						SXE2VF_VF_INT_ITR_INTERVAL_MAX);
	}
}

s32 sxe2vf_vsi_irq_cfg_record(struct sxe2vf_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2vf_adapter *adapter = vsi->adapter;

	if (!vsi->irqs.coalesce) {
		if (vsi->irqs.cnt == 0) {
			LOG_ERROR_BDF("vsi:%d irqs cnt invalid\n", vsi->vsi_id);
			ret = -EINVAL;
			goto l_out;
		}

		vsi->irqs.coalesce =
				kcalloc(vsi->irqs.cnt, sizeof(*vsi->irqs.coalesce),
					GFP_KERNEL);
		if (!vsi->irqs.coalesce) {
			ret = -ENOMEM;
			LOG_ERROR_BDF("vsi:%d irqs coalesce alloc failed\n",
				      vsi->vsi_id);
			goto l_out;
		}
		sxe2vf_vsi_coalesce_store(vsi, vsi->irqs.coalesce);
	}

l_out:
	return ret;
}

s32 sxe2vf_vsi_rebuild(struct sxe2vf_vsi *vsi)
{
	s32 ret;
	struct sxe2vf_adapter *adapter = vsi->adapter;
	u16 old_irq_cnt = vsi->irqs.cnt;

	ret = sxe2vf_vsi_irq_cfg_record(vsi);
	if (ret)
		return ret;

	(void)sxe2vf_vsi_irqs_decfg(vsi);
	sxe2vf_vsi_irqs_deinit(vsi);

	sxe2vf_vsi_queues_deinit(vsi);

	ret = sxe2vf_vsi_queues_init(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi:%u queues init failed during vsi \t"
			      "rebuild.(err:%d)\n",
			      vsi->vsi_id, ret);
		return ret;
	}

	if (sxe2vf_vsi_qs_stats_init(vsi)) {
		LOG_ERROR_BDF("vsi:%u qs stats init failed.(err:%d)\n", vsi->vsi_id,
			      ret);
		goto l_queues_deinit;
	}

	ret = sxe2vf_vsi_irqs_init(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi:%u irqs init failed during vsi \t"
			      "rebuild.(err:%d)\n",
			      vsi->vsi_id, ret);
		goto l_queues_deinit;
	}

	ret = sxe2vf_vsi_irqs_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi:%u irq cfg failed %d.\n", vsi->vsi_id, ret);
		goto l_irq_deinit;
	}

	sxe2vf_vsi_coalesce_set(vsi, vsi->irqs.coalesce, old_irq_cnt);
	kfree(vsi->irqs.coalesce);
	vsi->irqs.coalesce = NULL;

	return ret;

l_irq_deinit:
	sxe2vf_vsi_irqs_deinit(vsi);
l_queues_deinit:
	sxe2vf_vsi_queues_deinit(vsi);

	return ret;
}

s32 sxe2vf_dpdk_irq_cnt_get(void *pf_adapter)
{
	struct sxe2vf_adapter *adapter = pf_adapter;

	return adapter->irq_ctxt.dpdk_irq_cnt;
}

s32 sxe2vf_dpdk_irq_vector_idx_get(void *adapter, u16 irq_idx)
{
	struct sxe2vf_adapter *vf_adapter = adapter;
	u16 offset = vf_adapter->irq_ctxt.dpdk_offset + irq_idx;

	if (!vf_adapter->irq_ctxt.msix_entries)
		return -EINVAL;

	return (s32)vf_adapter->irq_ctxt.msix_entries[offset].vector;
}

s32 sxe2vf_dpdk_resource_release(void *pf_adapter, struct sxe2_obj *obj)
{
	s32 ret;
	struct sxe2vf_adapter *adapter = pf_adapter;
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_user_driver_release msg = {0};
	u16 vsi_id = adapter->vsi_ctxt.vsi_ids[SXE2VF_VSI_TYPE_DPDK];

	msg.func_id = obj->vf_id;
	msg.drv_id = obj->drv_id;

	(void)sxe2vf_user_l2_feature_clean(adapter, vsi_id);

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_USER_DRIVER_RELEASE, &msg,
					sizeof(msg), NULL, 0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("dpdk resource release failed.(err:%d)\n", ret);

	return ret;
}
