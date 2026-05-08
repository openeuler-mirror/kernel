/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_irq.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2VF_IRQ_H__
#define __SXE2VF_IRQ_H__

#include <linux/pci.h>
#ifdef NEED_COMPAT_DIM
#include "sxe2_compat_dim.h"
#else
#include <linux/dim.h>
#endif
#include <linux/cpumask.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>

#include "sxe2vf_regs.h"

#ifdef SXE2_TEST
#define STATIC
#else
#define STATIC static
#endif

struct sxe2vf_queue;
struct sxe2vf_adapter;

#define SXE2VF_EVENT_IRQ_IDX     0
#define SXE2VF_IRQ_NAME_MAX_LEN  (IFNAMSIZ + 16)
#define SXE2VF_LAN_MSIX_MIN_CNT  1
#define SXE2VF_EVENT_MSIX_CNT    1
#define SXE2VF_DPDK_MSIX_MIN_CNT 1
#define SXE2VF_RDMA_MSIX_MIN_CNT 1
#define SXE2VF_DPDK_MSIX_MAX_CNT 16

#define SXE2VF_IRQ_MAX_CNT (64 + SXE2VF_EVENT_MSIX_CNT)
#define SXE2VF_DFLT_NUM_RX_DESC 512
#define SXE2VF_DFLT_NUM_TX_DESC 512
#define SXE2VF_MAX_NUM_DESC 8160
#define SXE2VF_MIN_NUM_DESC                                                    \
	64
#define SXE2VF_DESC_ALIGN_32 32
#define SXE2VF_MIN_LRO_ITR 2
#define SXE2VF_VF_INT_ITR_INTERVAL_MAX 0xFFF

enum sxe2vf_itr_mode {
	SXE2VF_ITR_STATIC = 0,
	SXE2VF_ITR_DYNAMIC = 1,
};

#define SXE2VF_ITR_20K 50
#define SXE2VF_TX_ITR_IDX SXE2VF_ITR_IDX_1
#define SXE2VF_RX_ITR_IDX SXE2VF_ITR_IDX_0
#define SXE2VF_TX_DFLT_ITR SXE2VF_ITR_20K
#define SXE2VF_RX_DFLT_ITR SXE2VF_ITR_20K

#define sxe2_for_each_array_element(type, start, max_size)                        \
	for ((type) = (start); (type) < (max_size); (type)++) \

#define sxe2vf_for_txq_range(i, start, end)                                    \
	sxe2_for_each_array_element(i, (start), (end))

#define sxe2vf_for_rxq_range(i, start, end)                                    \
	sxe2_for_each_array_element(i, (start), (end))

#define SXE2VF_IRQ_HAS_TXQ(irq_data)                                           \
	((irq_data)->tx.list.next)
#define SXE2VF_IRQ_HAS_RXQ(irq_data)                                           \
	((irq_data)->rx.list.next)
#define SXE2VF_IS_ITR_DYNAMIC(qc)                                              \
	((qc)->itr_mode == SXE2VF_ITR_DYNAMIC)

struct sxe2vf_list {
	struct sxe2vf_queue *next;
	u16 cnt;
};

struct sxe2vf_q_container {
	struct sxe2vf_list list;
	struct dim dim;
	u16 itr_idx;
	u16 itr_setting;
	u16 itr_mode;
};

struct sxe2vf_irq_data {
	u16 irq_idx;
	u8 rate_limit;
	u8 q_cnt;
	u32 q_bitmap;
	u8 multiple_polling : 1;
	u8 pad : 7;
	u8 reserve[3];
	u16 event_ctr;
	struct sxe2vf_vsi *vsi;
	struct napi_struct napi;
	struct sxe2vf_q_container tx;
	struct sxe2vf_q_container rx;
	s8 name[SXE2VF_IRQ_NAME_MAX_LEN];
	cpumask_t affinity_mask;
	struct irq_affinity_notify affinity_notify;
};

struct sxe2vf_vsi_coalesce {
	u8 tx_valid;
	u8 rx_valid;
	u8 rate_limit;
	u16 tx_itr;
	u16 rx_itr;
	u16 tx_itr_mode;
	u16 rx_itr_mode;
};

struct sxe2vf_vsi_irqs {
	u16 cnt;
	struct sxe2vf_irq_data **irq_data;
	struct sxe2vf_vsi_coalesce
		*coalesce;
};

struct sxe2vf_irq_context {
	u16 max_cnt;
	struct msix_entry *msix_entries;
	s8 event_int_name[SXE2VF_IRQ_NAME_MAX_LEN];
	u16 eth_irq_cnt;
	u16 eth_offset;
	u16 dpdk_irq_cnt;
	u16 dpdk_offset;
	u16 rdma_irq_cnt;
	u16 rdma_offset;
	u16 msix_cnt;
	u16 itr_gran;
};

irqreturn_t sxe2vf_event_irq_handler(int irq, void *data);

void sxe2vf_queue_irq_deinit(struct sxe2vf_adapter *adapter);

int sxe2vf_napi_poll(struct napi_struct *napi, int weight);

s32 sxe2vf_irq_cfg(struct sxe2vf_vsi *vsi);

void sxe2vf_queue_irq_disable(struct sxe2vf_adapter *adapter);

s32 sxe2vf_vsi_irqs_configure(struct sxe2vf_vsi *vsi);

void sxe2vf_vsi_destroy(struct sxe2vf_adapter *adapter);

struct sxe2vf_vsi *sxe2vf_vsi_create(struct sxe2vf_adapter *adapter);

void sxe2vf_vsi_irqs_free(struct sxe2vf_vsi *vsi);

s32 sxe2vf_main_vsi_create(struct sxe2vf_adapter *adapter);

s32 sxe2vf_irq_init(struct sxe2vf_adapter *adapter);

void sxe2vf_irq_deinit(struct sxe2vf_adapter *adapter);

void sxe2vf_queue_irq_enable(struct sxe2vf_vsi *vsi);

void sxe2vf_event_irq_disable(struct sxe2vf_adapter *adapter);

void sxe2vf_event_irq_enable(struct sxe2vf_adapter *adapter);

void sxe2vf_vsi_queues_deinit(struct sxe2vf_vsi *vsi);

void sxe2vf_vsi_irqs_deinit(struct sxe2vf_vsi *vsi);

s32 sxe2vf_vsi_queues_init(struct sxe2vf_vsi *vf_vsi);

s32 sxe2vf_vsi_irqs_init(struct sxe2vf_vsi *vsi);

s32 sxe2vf_msix_init(struct sxe2vf_adapter *adapter);

void sxe2vf_msix_deinit(struct sxe2vf_adapter *adapter);

s32 sxe2vf_event_irq_request(struct sxe2vf_adapter *adapter);

s32 sxe2vf_vsi_irqs_request(struct sxe2vf_vsi *vsi);

void sxe2vf_irq_itr_init(struct sxe2vf_irq_data *irq_data);

s32 sxe2vf_queue_init(struct sxe2vf_adapter *adapter);

void sxe2vf_queue_deinit(struct sxe2vf_adapter *adapter);

s32 sxe2vf_vsi_irqs_decfg(struct sxe2vf_vsi *vsi);

s32 sxe2vf_vsi_irqs_cfg(struct sxe2vf_vsi *vsi);

s32 sxe2vf_vsi_hw_cfg(struct sxe2vf_adapter *adapter);

s32 sxe2vf_vsi_hw_decfg(struct sxe2vf_adapter *adapter);

#endif
