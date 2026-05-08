// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_irq.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_compat.h"
#include "sxe2vf.h"
#include "sxe2vf_irq.h"
#include "sxe2_log.h"
#include "sxe2vf_rx.h"
#include "sxe2vf_tx.h"
#include "sxe2vf_vsi.h"
#include "sxe2vf_mbx_channel.h"

int dpdk_irq_cnt = SXE2VF_DPDK_MSIX_MIN_CNT;
module_param(dpdk_irq_cnt, int, 0644);
MODULE_PARM_DESC(dpdk_irq_cnt, "dpdk vf irq cnt");

#define SXE2VF_DIM_DFLT_PROFILE_IDX 1

static const u16 tx_itr_profile[] = {
		2,
		8,
		40,
		128,
		256
};

static const u16 rx_itr_profile[] = {
		2,
		8,
		16,
		32,
		64
};

irqreturn_t sxe2vf_event_irq_handler(int irq, void *data)
{
	struct sxe2vf_adapter *adapter = (struct sxe2vf_adapter *)data;

	LOG_INFO_BDF("dev_name:%s event irq:%d triggered.\n", adapter->dev_name,
		     irq);

	sxe2vf_wkq_schedule(adapter, SXE2VF_WK_MBX, 0);

	return IRQ_HANDLED;
}

STATIC void sxe2vf_vsi_queues_free(struct sxe2vf_vsi *vsi)
{
	u16 i;

	if (vsi->rxqs.q) {
		sxe2vf_for_each_vsi_rxq(vsi, i)
		{
			if (vsi->rxqs.q[i]) {
				kfree_rcu(vsi->rxqs.q[i], rcu);
				WRITE_ONCE(vsi->rxqs.q[i], NULL);
			}
		}
		kfree(vsi->rxqs.q);
		vsi->rxqs.q = NULL;
	}

	if (vsi->txqs.q) {
		sxe2vf_for_each_vsi_txq(vsi, i)
		{
			if (vsi->txqs.q[i]) {
				kfree_rcu(vsi->txqs.q[i], rcu);
				WRITE_ONCE(vsi->txqs.q[i], NULL);
			}
		}
		kfree(vsi->txqs.q);
		vsi->txqs.q = NULL;
	}

	LOG_DEBUG("vsi:%pK tx/rx queues free.\n", vsi);
}

void sxe2vf_vsi_queues_deinit(struct sxe2vf_vsi *vsi)
{
	sxe2vf_vsi_queues_free(vsi);
}

STATIC s32 sxe2vf_vsi_queues_alloc(struct sxe2vf_vsi *vf_vsi)
{
	s32 ret = 0;
	struct sxe2vf_adapter *adapter = vf_vsi->adapter;
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	struct sxe2vf_queue *q;
	u16 i;

	vf_vsi->txqs.q = kcalloc(vf_vsi->txqs.q_cnt, sizeof(*vf_vsi->txqs.q),
				 GFP_KERNEL);
	if (!vf_vsi->txqs.q) {
		ret = -ENOMEM;
		LOG_DEV_ERR("alloc txqs failed, count: %d, size: %zu.\n",
			    vf_vsi->txqs.q_cnt, sizeof(*vf_vsi->txqs.q));
		goto l_failed;
	}

	vf_vsi->rxqs.q = kcalloc(vf_vsi->rxqs.q_cnt, sizeof(*vf_vsi->rxqs.q),
				 GFP_KERNEL);
	if (!vf_vsi->rxqs.q) {
		ret = -ENOMEM;
		LOG_DEV_ERR("alloc rxqs failed, count: %d, size: %zu.\n",
			    vf_vsi->rxqs.q_cnt, sizeof(*vf_vsi->rxqs.q));
		goto l_failed;
	}

	sxe2vf_for_each_vsi_txq(vf_vsi, i)
	{
		q = kzalloc(sizeof(*q), GFP_KERNEL);
		if (!q) {
			ret = -ENOMEM;
			LOG_DEV_ERR("txq size: %zu alloc failed.\n", sizeof(*q));
			goto l_failed;
		}
		q->vsi = vf_vsi;
		q->idx_in_vsi = i;
		q->dev = dev;
		q->netdev = vf_vsi->netdev;
		q->depth = vf_vsi->txqs.depth;
		u64_stats_init(&q->syncp);
		WRITE_ONCE(vf_vsi->txqs.q[i], q);
	}

	sxe2vf_for_each_vsi_rxq(vf_vsi, i)
	{
		q = kzalloc(sizeof(*q), GFP_KERNEL);
		if (!q) {
			ret = -ENOMEM;
			LOG_DEV_ERR("rxq size: %zu alloc failed.\n", sizeof(*q));
			goto l_failed;
		}
		q->vsi = vf_vsi;
		q->idx_in_vsi = i;
		q->dev = dev;
		q->depth = vf_vsi->rxqs.depth;
		q->netdev = vf_vsi->netdev;
		u64_stats_init(&q->syncp);
		WRITE_ONCE(vf_vsi->rxqs.q[i], q);
	}
	return ret;

l_failed:
	sxe2vf_vsi_queues_free(vf_vsi);
	return ret;
}

STATIC void sxe2vf_vsi_queues_num_set(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	u16 num_queues;

	if (adapter->q_ctxt.q_cnt_req)
		num_queues = adapter->q_ctxt.q_cnt_req;
	else
		num_queues = adapter->q_ctxt.eth_q_cnt;

	vsi->txqs.q_cnt = num_queues;
	vsi->rxqs.q_cnt = num_queues;
}

STATIC void sxe2vf_vsi_queues_cfg(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;

	vsi->txqs.depth = (u16)(vsi->txqs.depth ?: SXE2VF_DFLT_NUM_TX_DESC);
	vsi->rxqs.depth = (u16)(vsi->rxqs.depth ?: SXE2VF_DFLT_NUM_RX_DESC);

	LOG_INFO_BDF("vsi:%u queue_cnt:%u txq_depth:%u rxq_depth:%u.\n", vsi->vsi_id,
		     vsi->txqs.q_cnt, vsi->txqs.depth, vsi->rxqs.depth);
}

s32 sxe2vf_vsi_queues_init(struct sxe2vf_vsi *vf_vsi)
{
	sxe2vf_vsi_queues_num_set(vf_vsi);

	sxe2vf_vsi_queues_cfg(vf_vsi);

	return sxe2vf_vsi_queues_alloc(vf_vsi);
}

STATIC s32 sxe2vf_msix_entries_alloc(struct sxe2vf_adapter *adapter, u16 msix_cnt)
{
	s32 ret = 0;
	u16 i;

	adapter->irq_ctxt.msix_entries =
			kcalloc(msix_cnt, sizeof(struct msix_entry), GFP_KERNEL);
	if (!adapter->irq_ctxt.msix_entries) {
		ret = -ENOMEM;
		LOG_DEV_ERR("msi-x irq entry num:%u per size:%lu kcalloc failed, \t"
			    "ret=%d\n",
			    msix_cnt, sizeof(struct msix_entry), ret);
		goto l_end;
	}

	for (i = 0; i < msix_cnt; i++)
		adapter->irq_ctxt.msix_entries[i].entry = i;

l_end:
	return ret;
}

static void sxe2vf_msix_entries_free(struct sxe2vf_adapter *adapter)
{
	kfree(adapter->irq_ctxt.msix_entries);
	adapter->irq_ctxt.msix_entries = NULL;
}

STATIC s32 sxe2vf_msix_enable(struct sxe2vf_adapter *adapter, s32 min_msix,
			      s32 msix_cnt)
{
	s32 ret;

	ret = sxe2vf_msix_entries_alloc(adapter, (u16)msix_cnt);
	if (ret)
		return ret;

	ret = pci_enable_msix_range(adapter->pdev, adapter->irq_ctxt.msix_entries,
				    min_msix, msix_cnt);
	if (ret < 0) {
		LOG_ERROR_BDF("enable msix range[%d-%d] failed, ret=%d\n", min_msix,
			      msix_cnt, ret);
		goto l_ena_failed;
	}
	LOG_INFO_BDF("enable msix range[%d-%d] suc, ret=%d\n", min_msix, msix_cnt,
		     ret);
	return ret;

l_ena_failed:
	sxe2vf_msix_entries_free(adapter);
	return ret;
}

#define SXE2VF_RDMA_OTHER_IRQCNT 1

s32 sxe2vf_msix_init(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	s32 fact_cnt;
	u16 eth_fact = 0;
	u16 dpdk_fact = 0;
	u16 rdma_fact = 0;
	u16 left_cnt = (u16)(adapter->irq_ctxt.max_cnt - (u16)SXE2VF_EVENT_MSIX_CNT);
	u16 eth_expect = 0;
	u16 dpdk_expect = 0;
	u16 rdma_expect = 0;
	int mode = sxe2vf_com_mode_get(adapter);
	u16 msix_min = sxe2vf_irq_cnt_min_get(adapter);

	if (mode == SXE2_COM_MODULE_KERNEL) {
		left_cnt -= SXE2VF_RDMA_MSIX_MIN_CNT;
		eth_expect = (u16)(min3((u16)SXE2_VF_ETH_Q_NUM,
					(u16)(num_online_cpus()), left_cnt));
		rdma_expect = (u16)(adapter->irq_ctxt.max_cnt -
				    (u16)SXE2VF_EVENT_MSIX_CNT - eth_expect);
	} else if (mode == SXE2_COM_MODULE_DPDK) {
		dpdk_expect = (u16)(min((u16)(SXE2VF_DPDK_MSIX_MAX_CNT), left_cnt));
	} else {
		left_cnt -= (SXE2VF_DPDK_MSIX_MIN_CNT + SXE2VF_RDMA_MSIX_MIN_CNT);
		eth_expect = (u16)(min3((u16)SXE2_VF_ETH_Q_NUM,
					(u16)(num_online_cpus()), left_cnt));
		left_cnt = (u16)(adapter->irq_ctxt.max_cnt -
				 (u16)SXE2VF_EVENT_MSIX_CNT -
				 (u16)SXE2VF_DPDK_MSIX_MIN_CNT - eth_expect);
		rdma_expect = (u16)(min(((u16)num_online_cpus()), (left_cnt)));
		dpdk_expect = (u16)(adapter->irq_ctxt.max_cnt -
				    (u16)SXE2VF_EVENT_MSIX_CNT - eth_expect -
				    rdma_expect);
	}

	fact_cnt = sxe2vf_msix_enable(adapter, msix_min, adapter->irq_ctxt.max_cnt);
	if (fact_cnt < 0) {
		ret = -ENOSPC;
		LOG_INFO_BDF("cpu:%u q_max_cnt:%u irq_caps:%d eth_expect:%u \t"
			     "dpdk_expect:%u\t"
			     "rdma_expect:%u fact_cnt:%u msix enable failed \t"
			     "ret:%d\n",
			     num_online_cpus(), adapter->q_ctxt.max_cnt,
			     adapter->irq_ctxt.max_cnt, eth_expect, dpdk_expect,
			     rdma_expect, fact_cnt, ret);
		goto l_end;
	}

	adapter->irq_ctxt.msix_cnt = (u16)fact_cnt;

	if (fact_cnt < adapter->irq_ctxt.max_cnt) {
		fact_cnt -= SXE2VF_EVENT_MSIX_CNT;
		if (mode == SXE2_COM_MODULE_KERNEL) {
			left_cnt = (u16)(fact_cnt - (u16)SXE2VF_RDMA_MSIX_MIN_CNT);
			eth_fact = (u16)min_t(int, left_cnt, eth_expect);
			left_cnt = (u16)((u16)fact_cnt - eth_fact);
			rdma_fact = (u16)(min(left_cnt, rdma_expect));
		} else if (mode == SXE2_COM_MODULE_DPDK) {
			dpdk_fact = (u16)min_t(int, fact_cnt, dpdk_expect);
		} else {
			left_cnt = (u16)((u16)fact_cnt -
					 (u16)SXE2VF_RDMA_MSIX_MIN_CNT -
					 (u16)SXE2VF_DPDK_MSIX_MIN_CNT);
			eth_fact = (u16)min_t(int, left_cnt, eth_expect);
			left_cnt = (u16)(fact_cnt - (u16)SXE2VF_DPDK_MSIX_MIN_CNT -
					 eth_fact);
			rdma_fact = (u16)(min(left_cnt, rdma_expect));
			left_cnt = (u16)((u16)fact_cnt - (u16)eth_fact -
					 (u16)rdma_fact);
			dpdk_fact = (u16)(min(left_cnt, dpdk_expect));
		}
	} else {
		eth_fact = eth_expect;
		rdma_fact = rdma_expect;
		dpdk_fact = dpdk_expect;
	}
	adapter->aux_ctxt.num_msix = rdma_fact;
	adapter->irq_ctxt.rdma_irq_cnt = (u16)adapter->aux_ctxt.num_msix;
	adapter->irq_ctxt.dpdk_irq_cnt = dpdk_fact;
	adapter->irq_ctxt.eth_irq_cnt = eth_fact;

	adapter->irq_ctxt.eth_offset = SXE2VF_EVENT_MSIX_CNT;
	adapter->irq_ctxt.rdma_offset =
			adapter->irq_ctxt.eth_irq_cnt + adapter->irq_ctxt.eth_offset;
	adapter->irq_ctxt.dpdk_offset = adapter->irq_ctxt.rdma_irq_cnt +
					adapter->irq_ctxt.rdma_offset;

	LOG_INFO_BDF("cpu:%u q_max_cnt:%u irq_caps:%d eth_expect:%u dpdk_expect:%u \t"
		     "rdma_expect:%u\t"
		     "msix_cnt:%u eth_fact:%u dpdk_fact:%u rdma_fact:%u\t"
		     "eth offset:%d dpdk offset:%d rdma offset:%d mode:%d ret:%d\n",
		     num_online_cpus(), adapter->q_ctxt.max_cnt,
		     adapter->irq_ctxt.max_cnt, eth_expect, dpdk_expect, rdma_expect,
		     fact_cnt, eth_fact, dpdk_fact, rdma_fact,
		     adapter->irq_ctxt.eth_offset, adapter->irq_ctxt.dpdk_offset,
		     adapter->irq_ctxt.rdma_offset, mode, ret);

l_end:
	return ret;
}

s32 sxe2vf_queue_init(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	u16 eth_queue_cnt = 0;
	u16 dpdk_q_cnt = 0;
	int mode = sxe2vf_com_mode_get(adapter);

	if (mode == SXE2_COM_MODULE_KERNEL) {
		eth_queue_cnt = (u16)min3(adapter->q_ctxt.max_cnt,
					  (u16)SXE2_VF_ETH_Q_NUM,
					  adapter->irq_ctxt.eth_irq_cnt);
	} else if (mode == SXE2_COM_MODULE_DPDK) {
		dpdk_q_cnt = (u16)min_t(u16, adapter->q_ctxt.max_cnt,
					(u16)SXE2_VF_DPDK_Q_NUM);
	} else {
		eth_queue_cnt = (u16)min3((u16)(adapter->q_ctxt.max_cnt -
						SXE2VF_DPDK_QUEUE_CNT_MIN),
					  (u16)SXE2_VF_ETH_Q_NUM,
					  adapter->irq_ctxt.eth_irq_cnt);
		dpdk_q_cnt = (u16)min((u16)(adapter->q_ctxt.max_cnt - eth_queue_cnt),
				      (u16)SXE2_VF_DPDK_Q_NUM);
	}

	adapter->q_ctxt.eth_q_cnt = eth_queue_cnt;
	adapter->q_ctxt.eth_offset = 0;
	adapter->q_ctxt.dpdk_q_cnt = dpdk_q_cnt;
	adapter->q_ctxt.dpdk_offset =
			adapter->q_ctxt.eth_q_cnt + adapter->q_ctxt.eth_offset;

	LOG_INFO_BDF("eth irq cnt:%u eth_q_cnt:%u offset:%d dpdk_q_cnt:%u offset:%d \t"
		     "mode:%d\n",
		     adapter->irq_ctxt.eth_irq_cnt, adapter->q_ctxt.eth_q_cnt,
		     adapter->q_ctxt.eth_offset, adapter->q_ctxt.dpdk_q_cnt,
		     adapter->q_ctxt.dpdk_offset, mode);

	return ret;
}

void sxe2vf_queue_deinit(struct sxe2vf_adapter *adapter)
{
	adapter->q_ctxt.eth_q_cnt = 0;
	adapter->q_ctxt.dpdk_q_cnt = 0;
}

STATIC s32 sxe2vf_vsi_irq_data_alloc(struct sxe2vf_vsi *vsi, u16 idx)
{
	s32 ret = 0;
	struct sxe2vf_adapter *adapter = vsi->adapter;
	struct sxe2vf_irq_data *irq_data;

	irq_data = kzalloc(sizeof(*irq_data), GFP_KERNEL);
	if (!irq_data) {
		LOG_DEV_ERR("irq_data alloc failed.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	irq_data->vsi = vsi;
	irq_data->irq_idx = idx;

	vsi->irqs.irq_data[idx] = irq_data;

l_end:
	return ret;
}

STATIC void sxe2vf_vsi_irqs_data_free(struct sxe2vf_vsi *vsi)
{
	u16 i;

	if (vsi->irqs.irq_data) {
		sxe2vf_for_each_vsi_irq(vsi, i)
		{
			kfree(vsi->irqs.irq_data[i]);
			vsi->irqs.irq_data[i] = NULL;
		}
		kfree(vsi->irqs.irq_data);
		vsi->irqs.irq_data = NULL;
	}
}

STATIC s32 sxe2vf_vsi_irqs_data_alloc(struct sxe2vf_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2vf_adapter *adapter = vsi->adapter;
	u16 i;

	vsi->irqs.irq_data = kcalloc(vsi->irqs.cnt, sizeof(*vsi->irqs.irq_data),
				     GFP_KERNEL);
	if (!vsi->irqs.irq_data) {
		ret = -ENOMEM;
		LOG_DEV_ERR("alloc irq_data failed, count: %d, size: %zu.\n",
			    vsi->irqs.cnt, sizeof(*vsi->irqs.irq_data));
		goto l_end;
	}

	sxe2vf_for_each_vsi_irq(vsi, i)
	{
		ret = sxe2vf_vsi_irq_data_alloc(vsi, i);
		if (ret)
			goto l_failed;
	}

	return ret;

l_failed:
	sxe2vf_vsi_irqs_data_free(vsi);
l_end:
	return ret;
}

STATIC void sxe2vf_queue_add(struct sxe2vf_queue *queue, struct sxe2vf_list *head)
{
	queue->next = head->next;
	head->next = queue;
	head->cnt++;
}

STATIC void sxe2vf_map_txq_to_irq(struct sxe2vf_vsi *vsi, u16 cnt, u16 q_idx,
				  u16 irq_idx)
{
	struct sxe2vf_queue *queue;
	struct sxe2vf_irq_data *irq_data = vsi->irqs.irq_data[irq_idx];

	while (cnt) {
		queue = vsi->txqs.q[q_idx];
		queue->irq_data = irq_data;
		sxe2vf_queue_add(queue, &irq_data->tx.list);
		irq_data->q_bitmap |= (u32)BIT(q_idx);
		cnt--;
		q_idx++;
	}
}

STATIC void sxe2vf_map_rxq_to_irq(struct sxe2vf_vsi *vsi, u16 cnt, u16 q_idx,
				  u16 irq_idx)
{
	struct sxe2vf_queue *queue;
	struct sxe2vf_irq_data *irq_data = vsi->irqs.irq_data[irq_idx];

	while (cnt) {
		queue = vsi->rxqs.q[q_idx];
		queue->irq_data = irq_data;
		sxe2vf_queue_add(queue, &irq_data->rx.list);
		cnt--;
		q_idx++;
	}
}

STATIC void sxe2vf_vsi_queues_irqs_map(struct sxe2vf_vsi *vsi)
{
	u16 irq_cnt = vsi->irqs.cnt;
	u16 txq_remain = vsi->txqs.q_cnt;
	u16 rxq_remain = vsi->rxqs.q_cnt;
	u16 i;
	u16 txq_cnt, rxq_cnt, txq_idx = 0, rxq_idx = 0;

	sxe2vf_for_each_vsi_irq(vsi, i)
	{
		txq_cnt = (u16)DIV_ROUND_UP(txq_remain, irq_cnt - i);
		rxq_cnt = (u16)DIV_ROUND_UP(rxq_remain, irq_cnt - i);

		sxe2vf_map_txq_to_irq(vsi, txq_cnt, txq_idx, i);
		sxe2vf_map_rxq_to_irq(vsi, rxq_cnt, rxq_idx, i);

		txq_idx += txq_cnt;
		rxq_idx += rxq_cnt;
		txq_remain -= txq_cnt;
		rxq_remain -= rxq_cnt;
	}
}

STATIC void sxe2vf_vsi_queues_irqs_unmap(struct sxe2vf_vsi *vsi)
{
	u16 i;
	struct sxe2vf_queue *queue;
	struct sxe2vf_irq_data *irq_data;
	struct sxe2vf_adapter *adapter = vsi->adapter;

	sxe2vf_for_each_vsi_irq(vsi, i)
	{
		if (!vsi->irqs.irq_data)
			return;

		irq_data = vsi->irqs.irq_data[i];

		sxe2vf_for_each_queue(queue, irq_data->tx.list)
		{
			queue->irq_data = NULL;
			queue->next = NULL;
			irq_data->tx.list.cnt--;
		}

		sxe2vf_for_each_queue(queue, irq_data->rx.list)
		{
			queue->irq_data = NULL;
			queue->next = NULL;
			irq_data->rx.list.cnt--;
		}

		LOG_WARN_BDF("irq_cnt:%u i:%u state:0x%lx napi del.\n",
			     vsi->irqs.cnt, i, irq_data->napi.state);
	}
}

static void sxe2vf_vsi_irq_itr_cfg(struct sxe2vf_vsi *vsi, u16 idx)
{
	u16 itr_gran;
	struct sxe2vf_adapter *adapter = vsi->adapter;
	struct sxe2vf_hw *hw = &adapter->hw;
	struct sxe2vf_irq_data *irq_data = vsi->irqs.irq_data[idx];

	irq_data->tx.itr_idx = SXE2VF_TX_ITR_IDX;
	irq_data->tx.itr_setting = SXE2VF_TX_DFLT_ITR;

	irq_data->rx.itr_idx = SXE2VF_RX_ITR_IDX;
	irq_data->rx.itr_setting = SXE2VF_RX_DFLT_ITR;

	irq_data->tx.itr_mode = SXE2VF_ITR_DYNAMIC;
	irq_data->rx.itr_mode = SXE2VF_ITR_DYNAMIC;

	itr_gran = adapter->irq_ctxt.itr_gran;

	sxe2vf_hw_int_itr_set(hw, irq_data->tx.itr_idx, idx,
			      SXE2VF_VF_INT_ITR_INTERVAL_MAX &
					      (irq_data->tx.itr_setting / itr_gran));
	sxe2vf_hw_int_itr_set(hw, irq_data->rx.itr_idx, idx,
			      SXE2VF_VF_INT_ITR_INTERVAL_MAX &
					      (irq_data->rx.itr_setting / itr_gran));
}

static void sxe2vf_vsi_irq_itr_clear(struct sxe2vf_vsi *vsi, u16 idx)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	struct sxe2vf_hw *hw = &adapter->hw;
	struct sxe2vf_irq_data *irq_data = vsi->irqs.irq_data[idx];

	sxe2vf_hw_int_itr_set(hw, irq_data->tx.itr_idx, idx, 0);
	sxe2vf_hw_int_itr_set(hw, irq_data->rx.itr_idx, idx, 0);
}

s32 sxe2vf_vsi_irqs_decfg(struct sxe2vf_vsi *vsi)
{
	u16 i;
	struct sxe2vf_irq_data *irq_data;
	s32 ret;
	struct sxe2vf_adapter *adapter = vsi->adapter;

	if (vsi->irqs.cnt == 0) {
		LOG_ERROR_BDF("vsi:%u irq has been deinit.\n", vsi->vsi_id);
		return 0;
	}

	ret = sxe2vf_irq_map_clear(vsi);
	if (ret)
		LOG_ERROR_BDF("vsi:%u irq map clear failed.\n", vsi->vsi_id);

	sxe2vf_for_each_vsi_irq(vsi, i)
	{
		irq_data = vsi->irqs.irq_data[i];

		sxe2vf_vsi_irq_itr_clear(vsi, i);

		netif_napi_del(&irq_data->napi);
	}

	sxe2vf_vsi_queues_irqs_unmap(vsi);

	return ret;
}

s32 sxe2vf_vsi_irqs_cfg(struct sxe2vf_vsi *vsi)
{
	u16 i;
	struct sxe2vf_irq_data *irq_data;
	struct sxe2vf_adapter *adapter = vsi->adapter;
	s32 ret = 0;

	sxe2vf_vsi_queues_irqs_map(vsi);

	sxe2vf_for_each_vsi_irq(vsi, i)
	{
		irq_data = vsi->irqs.irq_data[i];

		sxe2vf_vsi_irq_itr_cfg(vsi, i);

		if (cpu_online(i))
			cpumask_set_cpu(i, &irq_data->affinity_mask);

		netif_napi_add(vsi->netdev, &irq_data->napi, sxe2vf_napi_poll,
			       NAPI_POLL_WEIGHT);
	}

	ret = sxe2vf_irq_map_setup(vsi);
	if (ret) {
		(void)sxe2vf_vsi_irqs_decfg(vsi);
		LOG_ERROR_BDF("vsi:%d irq map failed.\n", vsi->vsi_id);
	}

	return ret;
}

void sxe2vf_msix_deinit(struct sxe2vf_adapter *adapter)
{
	if (!adapter->irq_ctxt.msix_entries)
		return;

	pci_disable_msix(adapter->pdev);
	sxe2vf_msix_entries_free(adapter);

	adapter->irq_ctxt.eth_irq_cnt = 0;
	adapter->aux_ctxt.num_msix = 0;
	LOG_INFO_BDF("pci msix disabled msi_enable:%u.\n",
		     adapter->pdev->msix_enabled);
}

void sxe2vf_event_irq_enable(struct sxe2vf_adapter *adapter)
{
	clear_bit(SXE2VF_FLAG_EVENT_IRQ_DISABLED, adapter->flags);

	sxe2vf_hw_event_irq_enable(&adapter->hw);

	LOG_INFO_BDF("mbx event irq enabled.\n");
}

s32 sxe2vf_event_irq_request(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	struct msix_entry *msix_entries = adapter->irq_ctxt.msix_entries;

	(void)snprintf(adapter->irq_ctxt.event_int_name,
		       sizeof(adapter->irq_ctxt.event_int_name) - 1, "%s-%s:event",
		       dev_driver_string(dev), dev_name(dev));

	ret = request_irq(msix_entries[SXE2VF_EVENT_IRQ_IDX].vector,
			  sxe2vf_event_irq_handler, 0,
			  adapter->irq_ctxt.event_int_name, adapter);
	if (ret) {
		LOG_DEV_ERR("request_irq for %s failed, ret=%d\n",
			    adapter->irq_ctxt.event_int_name, ret);
		memset(adapter->irq_ctxt.event_int_name, 0,
		       sizeof(adapter->irq_ctxt.event_int_name));
		goto l_end;
	}

	LOG_INFO_BDF("mbx event irq:%s request irq.\n",
		     adapter->irq_ctxt.event_int_name);

l_end:
	return ret;
}

void sxe2vf_event_irq_disable(struct sxe2vf_adapter *adapter)
{
	struct msix_entry *msix_entries = adapter->irq_ctxt.msix_entries;

	set_bit(SXE2VF_FLAG_EVENT_IRQ_DISABLED, adapter->flags);

	if (msix_entries)
		synchronize_irq(msix_entries[SXE2VF_EVENT_IRQ_IDX].vector);

	sxe2vf_wkq_cancel(adapter, SXE2VF_WK_MBX);
	sxe2vf_wkq_cancel(adapter, SXE2VF_WK_NOTIFY_MSG);

	sxe2vf_notify_msg_list_clear(adapter);

	sxe2vf_hw_event_irq_disable(&adapter->hw);

	LOG_INFO_BDF("mbx event irq disabled.\n");
}

STATIC void sxe2vf_event_irq_free(struct sxe2vf_adapter *adapter)
{
	struct msix_entry *msix_entries = adapter->irq_ctxt.msix_entries;

	sxe2vf_event_irq_disable(adapter);

	if (strlen(adapter->irq_ctxt.event_int_name))
		free_irq(msix_entries[SXE2VF_EVENT_IRQ_IDX].vector, adapter);

	memset(adapter->irq_ctxt.event_int_name, 0,
	       sizeof(adapter->irq_ctxt.event_int_name));

	LOG_INFO_BDF("event irq freed.\n");
}

s32 sxe2vf_irq_init(struct sxe2vf_adapter *adapter)
{
	s32 ret;

	ret = sxe2vf_msix_init(adapter);
	if (ret)
		goto l_end;

	ret = sxe2vf_event_irq_request(adapter);
	if (ret)
		goto l_event_irq_failed;

	sxe2vf_event_irq_enable(adapter);

	return 0;

l_event_irq_failed:
	sxe2vf_msix_deinit(adapter);
l_end:
	return ret;
}

s32 sxe2vf_main_vsi_create(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;

	mutex_lock(&adapter->vsi_ctxt.lock);
	adapter->vsi_ctxt.vf_vsi = sxe2vf_vsi_create(adapter);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	if (!adapter->vsi_ctxt.vf_vsi)
		ret = -ENOMEM;

	return ret;
}

STATIC void sxe2vf_vsi_irqs_num_set(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	u16 q_cnt = (u16)max(vsi->txqs.q_cnt, vsi->rxqs.q_cnt);
	u16 q_irq_cnt = adapter->irq_ctxt.eth_irq_cnt;

	vsi->irqs.cnt = (u16)min(q_irq_cnt, q_cnt);

	LOG_INFO_BDF("vsi:%u txqs_cnt:%u rxqs_cnt:%u queue irq cnt:%u q_cnt:%u \t"
		     "q_irq_cnt:%u.\n",
		     vsi->vsi_id, vsi->txqs.q_cnt, vsi->rxqs.q_cnt, vsi->irqs.cnt,
		     q_cnt, q_irq_cnt);
}

STATIC void sxe2vf_vsi_irqs_num_clear(struct sxe2vf_vsi *vsi)
{
	vsi->irqs.cnt = 0;
}

s32 sxe2vf_vsi_irqs_init(struct sxe2vf_vsi *vsi)
{
	sxe2vf_vsi_irqs_num_set(vsi);

	return sxe2vf_vsi_irqs_data_alloc(vsi);
}

void sxe2vf_vsi_irqs_deinit(struct sxe2vf_vsi *vsi)
{
	sxe2vf_vsi_irqs_data_free(vsi);

	sxe2vf_vsi_irqs_num_clear(vsi);
}

void sxe2vf_irq_deinit(struct sxe2vf_adapter *adapter)
{
	sxe2vf_event_irq_free(adapter);

	sxe2vf_msix_deinit(adapter);
}

STATIC void sxe2vf_vsi_irqs_coalesce_deinit(struct sxe2vf_vsi *vsi)
{
	kfree(vsi->irqs.coalesce);
	vsi->irqs.coalesce = NULL;
}

STATIC void sxe2vf_napi_irq_enable(struct sxe2vf_hw *hw,
				   struct sxe2vf_irq_data *irq_data)
{
	u32 value = 0;

	if (irq_data->multiple_polling) {
		irq_data->multiple_polling = false;
		value = SXE2VF_DYN_CTL_INTENABLE |
			SXE2VF_DYN_CTL_CLEARPBA |
			SXE2VF_DYN_CTL_SWINT_TRIG |
			(SXE2VF_ITR_IDX_NONE
			 << SXE2VF_DYN_CTL_ITR_IDX_SHIFT);

		sxe2vf_hw_irq_dyn_ctl(hw, irq_data->irq_idx, value);
	} else {
		sxe2vf_hw_irq_enable(hw, irq_data->irq_idx);
	}
}

static void sxe2vf_net_dim(u16 event_ctr, u64 packets, u64 bytes, struct dim *dim)
{
	struct dim_sample dim_sample = {};

	dim_update_sample(event_ctr, packets, bytes, &dim_sample);
	dim_sample.comp_ctr = 0;

	if (ktime_ms_delta(dim_sample.time, dim->start_sample.time) >= 1000)
		dim->state = DIM_START_MEASURE;

	net_dim(dim, dim_sample);
}

STATIC void sxe2vf_dynamic_itr(struct sxe2vf_irq_data *irq_data)
{
	struct sxe2vf_q_container *tqc = &irq_data->tx;
	struct sxe2vf_q_container *rqc = &irq_data->rx;
	struct sxe2vf_queue *queue;

	if (SXE2VF_IS_ITR_DYNAMIC(tqc)) {
		u64 packets = 0, bytes = 0;

		sxe2vf_for_each_queue(queue, irq_data->tx.list)
		{
			packets += queue->stats->packets;
			bytes += queue->stats->bytes;
		}
		sxe2vf_net_dim(irq_data->event_ctr, packets, bytes,
			       &irq_data->tx.dim);
	}

	if (SXE2VF_IS_ITR_DYNAMIC(rqc)) {
		u64 packets = 0, bytes = 0;

		sxe2vf_for_each_queue(queue, irq_data->rx.list)
		{
			packets += queue->stats->packets;
			bytes += queue->stats->bytes;
		}
		sxe2vf_net_dim(irq_data->event_ctr, packets, bytes,
			       &irq_data->rx.dim);
	}
}

int sxe2vf_napi_poll(struct napi_struct *napi, int weight)
{
	struct sxe2vf_irq_data *irq_data =
			container_of(napi, struct sxe2vf_irq_data, napi);
	struct sxe2vf_queue *txq;
	struct sxe2vf_queue *rxq;
	int total_cleaned = 0;
	int budget_per_ring;
	bool complete = true;
	struct sxe2vf_adapter *adapter = irq_data->vsi->adapter;
	s32 clean;

	sxe2vf_for_each_queue(txq, irq_data->tx.list)
	{
		bool wd;

		wd = sxe2vf_txq_irq_clean(txq, weight);

		if (!wd)
			complete = false;
	}

	if (unlikely(weight <= 0))
		return weight;

	if (unlikely(irq_data->rx.list.cnt > 1))
		budget_per_ring = max_t(int, ((u32)weight / irq_data->rx.list.cnt),
					1);
	else
		budget_per_ring = weight;

	sxe2vf_trace(irq_rxclean_begin, irq_data, total_cleaned);
	sxe2vf_for_each_queue(rxq, irq_data->rx.list)
	{
		sxe2vf_trace(rxq_clean_begin, rxq);
		clean = sxe2vf_rxq_irq_clean(rxq, budget_per_ring);
		sxe2vf_trace(rxq_clean_end, rxq, clean);
		total_cleaned += clean;
		if (clean >= budget_per_ring)
			complete = false;
	}
	sxe2vf_trace(irq_rxclean_end, irq_data, total_cleaned);

	if (!complete) {
		irq_data->multiple_polling = true;
		return weight;
	}

	if (napi_complete_done(napi, total_cleaned)) {
		sxe2vf_dynamic_itr(irq_data);
		sxe2vf_napi_irq_enable(&adapter->hw, irq_data);
	}

	return min_t(int, total_cleaned, (weight - 1));
}

STATIC void sxe2vf_vsi_irq_disable(struct sxe2vf_vsi *vsi, u16 idx)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	struct sxe2vf_hw *hw = &adapter->hw;
	struct sxe2vf_irq_data *irq_data = vsi->irqs.irq_data[idx];

	synchronize_irq(adapter->irq_ctxt.msix_entries[irq_data->irq_idx].vector);

	if (irq_data->rx.list.next || irq_data->tx.list.next)
		napi_disable(&irq_data->napi);

	cancel_work_sync(&irq_data->tx.dim.work);
	cancel_work_sync(&irq_data->rx.dim.work);

	sxe2vf_hw_irq_disable(hw, irq_data->irq_idx);
}

STATIC void sxe2vf_vsi_irq_enable(struct sxe2vf_vsi *vsi, u16 idx)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	struct sxe2vf_hw *hw = &adapter->hw;
	struct sxe2vf_irq_data *irq_data = vsi->irqs.irq_data[idx];

	if (irq_data->rx.list.next || irq_data->tx.list.next)
		napi_enable(&irq_data->napi);

	sxe2vf_irq_itr_init(irq_data);

	sxe2vf_hw_irq_enable(hw, irq_data->irq_idx);

	sxe2vf_hw_irq_trigger(hw, irq_data->irq_idx);
}

STATIC inline void sxe2vf_itr_set(struct sxe2vf_irq_data *irq_data,
				  struct sxe2vf_q_container *qc, u16 itr)
{
	struct sxe2vf_hw *hw = &irq_data->vsi->adapter->hw;
	struct sxe2vf_adapter *adapter = irq_data->vsi->adapter;

	sxe2vf_hw_int_itr_set(hw, qc->itr_idx, irq_data->irq_idx,
			      (itr / adapter->irq_ctxt.itr_gran) &
					      SXE2VF_VF_INT_ITR_INTERVAL_MAX);
}

STATIC void sxe2vf_dim_work_tx(struct work_struct *work)
{
	struct sxe2vf_irq_data *irq_data;
	struct sxe2vf_q_container *qc;
	struct dim *dim;
	u16 itr;

	dim = container_of(work, struct dim, work);
	irq_data = (struct sxe2vf_irq_data *)dim->priv;
	qc = &irq_data->tx;

	WARN_ON(dim->profile_ix >= ARRAY_SIZE(tx_itr_profile));

	itr = tx_itr_profile[dim->profile_ix];

	sxe2vf_itr_set(irq_data, qc, itr);

	dim->state = DIM_START_MEASURE;
}

STATIC void sxe2vf_dim_work_rx(struct work_struct *work)
{
	struct sxe2vf_irq_data *irq_data;
	struct sxe2vf_q_container *qc;
	struct dim *dim;
	u16 itr;

	dim = container_of(work, struct dim, work);
	irq_data = (struct sxe2vf_irq_data *)dim->priv;
	qc = &irq_data->rx;

	WARN_ON(dim->profile_ix >= ARRAY_SIZE(rx_itr_profile));

	itr = rx_itr_profile[dim->profile_ix];

	sxe2vf_itr_set(irq_data, qc, itr);

	dim->state = DIM_START_MEASURE;
}

STATIC void sxe2vf_dim_init(struct sxe2vf_irq_data *irq_data)
{
	struct sxe2vf_q_container *qc;
	u16 itr;

	qc = &irq_data->tx;
	INIT_WORK(&qc->dim.work, sxe2vf_dim_work_tx);
	qc->dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
	qc->dim.profile_ix = SXE2VF_DIM_DFLT_PROFILE_IDX;
	qc->dim.priv = irq_data;

	itr = (u16)(SXE2VF_IS_ITR_DYNAMIC(qc) ? tx_itr_profile[qc->dim.profile_ix]
					      : qc->itr_setting);

	sxe2vf_itr_set(irq_data, qc, itr);

	qc = &irq_data->rx;
	INIT_WORK(&qc->dim.work, sxe2vf_dim_work_rx);
	qc->dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
	qc->dim.profile_ix = SXE2VF_DIM_DFLT_PROFILE_IDX;
	qc->dim.priv = irq_data;

	itr = (u16)(SXE2VF_IS_ITR_DYNAMIC(qc) ? rx_itr_profile[qc->dim.profile_ix]
					      : qc->itr_setting);
	sxe2vf_itr_set(irq_data, qc, itr);
}

void sxe2vf_irq_itr_init(struct sxe2vf_irq_data *irq_data)
{
	sxe2vf_dim_init(irq_data);
}

void sxe2vf_queue_irq_disable(struct sxe2vf_adapter *adapter)
{
	u16 i;
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;

	sxe2vf_for_each_vsi_irq(vsi, i)
	{
		sxe2vf_vsi_irq_disable(vsi, i);
	}

	LOG_DEBUG_BDF("queue irq disabled.\n");
}

void sxe2vf_queue_irq_enable(struct sxe2vf_vsi *vsi)
{
	u16 i;

	sxe2vf_for_each_vsi_irq(vsi, i)
	{
		sxe2vf_vsi_irq_enable(vsi, i);
	}
}

STATIC void sxe2vf_vsi_get_q_idx(struct sxe2vf_vsi *vsi, u16 irq_idx, u16 *txq,
				 u16 *rxq)
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

STATIC void sxe2vf_irq_affinity_notify(struct irq_affinity_notify *notify,
				       const cpumask_t *mask)
{
	struct sxe2vf_irq_data *irq_data = container_of(notify,
							struct sxe2vf_irq_data,
							affinity_notify);

	cpumask_copy(&irq_data->affinity_mask, mask);
}

STATIC void sxe2vf_irq_affinity_release(struct kref __always_unused *ref)
{
}

STATIC irqreturn_t sxe2vf_msix_ring_irq_handler(int __always_unused irq, void *data)
{
	struct sxe2vf_irq_data *irq_data = (struct sxe2vf_irq_data *)data;

	if (!SXE2VF_IRQ_HAS_TXQ(irq_data) && !SXE2VF_IRQ_HAS_RXQ(irq_data))
		goto l_end;

	irq_data->event_ctr++;
	napi_schedule_irqoff(&irq_data->napi);
l_end:
	return IRQ_HANDLED;
}

STATIC s32 sxe2vf_vsi_irq_request(struct sxe2vf_vsi *vsi, s8 *base_name, u16 idx)
{
	s32 ret = 0;
	struct sxe2vf_irq_data *irq_data;
	struct sxe2vf_adapter *adapter = vsi->adapter;
	u16 rx_idx, tx_idx;
	u32 irq_num;

	irq_data = vsi->irqs.irq_data[idx];
	irq_num = adapter->irq_ctxt.msix_entries[idx + SXE2VF_EVENT_MSIX_CNT].vector;

	sxe2vf_vsi_get_q_idx(vsi, idx, &tx_idx, &rx_idx);

	if (SXE2VF_IRQ_HAS_TXQ(irq_data) && SXE2VF_IRQ_HAS_RXQ(irq_data)) {
		if (irq_data->rx.list.cnt == 1)
			(void)snprintf(irq_data->name, sizeof(irq_data->name) - 1,
				       "%s-%s-%d", base_name, "TxRx", rx_idx);
		else
			(void)snprintf(irq_data->name, sizeof(irq_data->name) - 1,
				       "%s-%s-%d-%d", base_name, "TxRx", rx_idx,
				       rx_idx + irq_data->rx.list.cnt - 1);
	} else if (SXE2VF_IRQ_HAS_TXQ(irq_data)) {
		(void)snprintf(irq_data->name, sizeof(irq_data->name) - 1,
			       "%s-%s-%d", base_name, "Tx", tx_idx);
	} else if (SXE2VF_IRQ_HAS_RXQ(irq_data)) {
		(void)snprintf(irq_data->name, sizeof(irq_data->name) - 1,
			       "%s-%s-%d", base_name, "Rx", rx_idx);
	} else {
		LOG_WARN_BDF("irq[%u] bind no queues.\n", idx);
		goto l_end;
	}

	ret = request_irq(irq_num, sxe2vf_msix_ring_irq_handler, 0, irq_data->name,
			  irq_data);
	if (ret) {
		memset(irq_data->name, 0, sizeof(irq_data->name));
		LOG_DEV_ERR("irq_idx:%u vector:%u MSI-X request_irq failed err:%d\n",
			    idx, irq_num, ret);
		goto l_end;
	}

	irq_data->affinity_notify.notify = sxe2vf_irq_affinity_notify;
	irq_data->affinity_notify.release = sxe2vf_irq_affinity_release;
	ret = irq_set_affinity_notifier(irq_num, &irq_data->affinity_notify);
	if (ret) {
		LOG_DEV_ERR("irq_idx:%u vector:%u MSI-X set affinity notifier NOK, \t"
			    "ret:%d\n",
			    idx, irq_num, ret);
	}

	ret = irq_set_affinity_hint(irq_num, &irq_data->affinity_mask);
	if (ret) {
		LOG_DEV_ERR("irq_idx:%u vector:%u MSI-X set affinity hint NOK, \t"
			    "ret:%d\n",
			    idx, irq_num, ret);
	}

	LOG_INFO_BDF("irq_cnt:%u idx:%u vector:%u request irq len:%lu.\n",
		     vsi->irqs.cnt, idx, irq_num, strlen(irq_data->name));

l_end:
	return ret;
}

s32 sxe2vf_vsi_irqs_request(struct sxe2vf_vsi *vsi)
{
	s32 ret;
	s8 base_name[SXE2VF_IRQ_NAME_MAX_LEN];
	struct sxe2vf_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	u16 i;
	unsigned int irq_num;

	(void)snprintf(base_name, sizeof(base_name) - 1, "%s-%s",
		       dev_driver_string(dev), vsi->netdev->name);

	sxe2vf_for_each_vsi_irq(vsi, i)
	{
		ret = sxe2vf_vsi_irq_request(vsi, base_name, i);
		if (ret)
			goto l_end;
	}

	return 0;

l_end:
	while (i) {
		i--;
		irq_num = adapter->irq_ctxt.msix_entries[i + SXE2VF_EVENT_MSIX_CNT]
					  .vector;
		(void)irq_set_affinity_hint(irq_num, NULL);
		free_irq(irq_num, vsi->irqs.irq_data[i]);
		memset(vsi->irqs.irq_data[i]->name, 0,
		       sizeof(vsi->irqs.irq_data[i]->name));
	}
	return ret;
}

STATIC void sxe2vf_vsi_irq_free(struct sxe2vf_vsi *vsi, u16 idx)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	struct sxe2vf_irq_data *irq_data = vsi->irqs.irq_data[idx];
	u32 irq_num = adapter->irq_ctxt.msix_entries[idx + SXE2VF_EVENT_MSIX_CNT]
				      .vector;

	if (!strlen(irq_data->name)) {
		LOG_WARN_BDF("irq:%u not request.\n", irq_data->irq_idx);
		return;
	}

	(void)irq_set_affinity_notifier(irq_num, NULL);

	(void)irq_set_affinity_hint(irq_num, NULL);
	synchronize_irq(irq_num);
	free_irq(irq_num, irq_data);

	memset(irq_data->name, 0, sizeof(irq_data->name));

	LOG_INFO_BDF("irq_cnt:%u irq_idx:%u vector:%u freed.\n", vsi->irqs.cnt,
		     idx + SXE2VF_EVENT_MSIX_CNT, irq_num);
}

void sxe2vf_vsi_irqs_free(struct sxe2vf_vsi *vsi)
{
	u16 i;

	sxe2vf_for_each_vsi_irq(vsi, i)
	{
		sxe2vf_vsi_irq_free(vsi, i);
	}
}

s32 sxe2vf_irq_cfg(struct sxe2vf_vsi *vsi)
{
	s32 ret;

	ret = sxe2vf_vsi_irqs_request(vsi);
	if (ret)
		return ret;

	sxe2vf_queue_irq_enable(vsi);

	return ret;
}

STATIC void sxe2vf_vsi_deinit(struct sxe2vf_adapter *adapter)
{
	kfree(adapter->vsi_ctxt.vf_vsi);
	adapter->vsi_ctxt.vf_vsi = NULL;
}

static s32 __sxe2vf_vsi_hw_cfg(struct sxe2vf_adapter *adapter, bool is_clear)
{
	struct sxe2_vf_vsi_cfg vsi_cfg = {};
	s32 ret;
	struct sxe2vf_msg_params params = {0};

	vsi_cfg.txq_base_idx = cpu_to_le16(adapter->q_ctxt.eth_offset);
	vsi_cfg.txq_cnt = cpu_to_le16(adapter->q_ctxt.eth_q_cnt);
	vsi_cfg.rxq_base_idx = cpu_to_le16(adapter->q_ctxt.eth_offset);
	vsi_cfg.rxq_cnt = cpu_to_le16(adapter->q_ctxt.eth_q_cnt);
	vsi_cfg.irq_base_idx = cpu_to_le16(adapter->irq_ctxt.eth_offset);
	vsi_cfg.irq_cnt = cpu_to_le16(adapter->irq_ctxt.eth_irq_cnt);
	vsi_cfg.is_clear = is_clear;
	vsi_cfg.vsi_id = cpu_to_le16(adapter->vsi_ctxt.vsi_ids[SXE2VF_VSI_TYPE_ETH]);

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_VSI_CFG, &vsi_cfg, sizeof(vsi_cfg),
					NULL, 0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);

	LOG_INFO_BDF("vsi:%d cfg msg:0x%x ret:%d.\n", vsi_cfg.vsi_id,
		     SXE2_VF_VSI_CFG, ret);

	return ret;
}

s32 sxe2vf_vsi_hw_cfg(struct sxe2vf_adapter *adapter)
{
	return __sxe2vf_vsi_hw_cfg(adapter, false);
}

s32 sxe2vf_vsi_hw_decfg(struct sxe2vf_adapter *adapter)
{
	return __sxe2vf_vsi_hw_cfg(adapter, true);
}

void sxe2vf_vsi_destroy(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_vsi *vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = adapter->vsi_ctxt.vf_vsi;
	if (vsi) {
		(void)sxe2vf_vsi_close(vsi);
		(void)sxe2vf_vsi_irqs_decfg(vsi);
		(void)sxe2vf_vsi_hw_decfg(adapter);
		sxe2vf_vsi_irqs_deinit(vsi);
		sxe2vf_vsi_qs_stats_deinit(vsi);
		sxe2vf_vsi_queues_deinit(vsi);
		sxe2vf_vsi_irqs_coalesce_deinit(vsi);
	}
	sxe2vf_vsi_deinit(adapter);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	LOG_DEBUG_BDF("vsi destroyed.\n");
}

STATIC struct sxe2vf_vsi *sxe2vf_vsi_init(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_vsi *vsi = NULL;

	vsi = kzalloc(sizeof(*vsi), GFP_KERNEL);
	if (!vsi) {
		LOG_DEV_ERR("alloc vsi struct failed.\n");
		goto l_end;
	}

	vsi->adapter = adapter;
	vsi->netdev = adapter->netdev;
	vsi->vsi_id = adapter->vsi_ctxt.vsi_ids[SXE2VF_VSI_TYPE_ETH];

	set_bit(SXE2VF_VSI_CLOSE, vsi->state);
	adapter->vsi_ctxt.vf_vsi = vsi;

l_end:
	return vsi;
}

struct sxe2vf_vsi *sxe2vf_vsi_create(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_vsi *vsi;

	vsi = sxe2vf_vsi_init(adapter);
	if (!vsi)
		goto l_end;

	if (sxe2vf_vsi_queues_init(vsi) != 0)
		goto l_queue_init_failed;

	if (sxe2vf_vsi_qs_stats_init(vsi))
		goto l_qs_stats_init_failed;

	if (sxe2vf_vsi_irqs_init(vsi) != 0)
		goto l_irq_init_failed;

	if (sxe2vf_vsi_hw_cfg(adapter) != 0)
		goto l_vsi_cfg_failed;

	if (sxe2vf_vsi_irqs_cfg(vsi)) {
		LOG_ERROR_BDF("vsi:%u irq cfg failed.\n", vsi->vsi_id);
		goto l_irqs_cfg_failed;
	}

	return vsi;

l_irqs_cfg_failed:
	(void)sxe2vf_vsi_hw_decfg(adapter);
l_vsi_cfg_failed:
	sxe2vf_vsi_irqs_deinit(vsi);
l_irq_init_failed:
	sxe2vf_vsi_qs_stats_deinit(vsi);
l_qs_stats_init_failed:
	sxe2vf_vsi_queues_deinit(vsi);
l_queue_init_failed:
	sxe2vf_vsi_deinit(adapter);
l_end:
	return NULL;
}
