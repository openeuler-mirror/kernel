/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_irq.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_IRQ_H__
#define __SXE2_IRQ_H__

#include <linux/pci.h>
#ifdef NEED_COMPAT_DIM
#include "sxe2_compat_dim.h"
#else
#include <linux/dim.h>
#endif
#include <linux/cpumask.h>
#include <linux/interrupt.h>

#include "sxe2_queue.h"

struct sxe2_vsi;
struct sxe2_adapter;
struct sxe2_hw;

#define SXE2_IRQ_MAX_CNT (2048)

#define SXE2_LAN_MSIX_MIN_CNT (1)
#define SXE2_EVENT_MSIX_CNT   (1)

#define SXE2_MSIX_MIN_CNT                                                      \
	(SXE2_LAN_MSIX_MIN_CNT + SXE2_EVENT_MSIX_CNT)
#define SXE2_FNAV_MSIX_CNT 1
#define SXE2_RDMA_MSIX_MIN_CNT 2
#define SXE2_ESWITCH_MSIX_CNT 1
#define SXE2_RDMA_AEQ_MSIX_CNT 1
#define SXE2_LB_RXQ_MSIX_CNT 1

#define SXE2_DPDK_MSIX_MAX_CNT  256
#define SXE2_DPDK_MSIX_DFLT_CNT 64
#define SXE2_DPDK_MSIX_MIN_CNT  1
#define SXE2_DPDK_ESWITCH_MSIX_CNT SXE2_ESWITCH_MSIX_CNT

#define SXE2_NON_SAFEMODE_MIN_MSIX                                             \
	(SXE2_MSIX_MIN_CNT + SXE2_RDMA_MSIX_MIN_CNT                                \
	+ SXE2_FNAV_MSIX_CNT + SXE2_ESWITCH_MSIX_CNT + SXE2_LB_RXQ_MSIX_CNT)

#define SXE2_EVENT_IRQ_IDX 0

#define SXE2_ITR_8K 124
#define SXE2_ITR_20K 50
#define SXE2_ITR_MAX 8160

#define SXE2_TX_ITR_IDX SXE2_ITR_IDX_1
#define SXE2_RX_ITR_IDX SXE2_ITR_IDX_0
#define SXE2_TX_DFLT_ITR SXE2_ITR_20K
#define SXE2_RX_DFLT_ITR SXE2_ITR_20K

#define SXE2_IS_ITR_DYNAMIC(qc)                                                \
	((qc)->itr_mode == SXE2_ITR_DYNAMIC)

#define SXE2_IRQ_HAS_TXQ(irq_data)                                             \
	((irq_data)->tx.list.next)
#define SXE2_IRQ_HAS_RXQ(irq_data)                                             \
	((irq_data)->rx.list.next)

#define SXE2_INT_NAME_MAX_LEN (IFNAMSIZ + 16)

enum sxe2_itr_idx {
	SXE2_ITR_IDX_0 = 0,
	SXE2_ITR_IDX_1,
	SXE2_ITR_IDX_2,
	SXE2_ITR_IDX_NONE,
};

enum sxe2_itr_mode {
	SXE2_ITR_STATIC = 0,
	SXE2_ITR_DYNAMIC = 1,
};

struct sxe2_irq_layout {
	u16 event;
	u16 event_offset;

	u16 lb;
	u16 lb_offset;

	u16 fnav;
	u16 fnav_offset;

	u16 eswitch;
	u16 eswitch_offset;

	u16 lan;
	u16 lan_offset;

	u16 rdma;
	u16 rdma_offset;

	u16 dpdk;
	u16 dpdk_offset;

	u16 dpdk_eswitch;
	u16 dpdk_eswitch_offset;

	u16 macvlan;
	u16 macvlan_offset;

	u16 sriov;
	u16 sriov_offset;
};

struct sxe2_irq_context {
	u16 max_cnt;
	u16 avail_cnt;
	u16 fixed_cnt;
	u16 base_idx_in_dev;
	u16 rdma_base_idx;
	struct sxe2_irq_layout irq_layout;
	struct msix_entry *msix_entries;
	s8 event_int_name[SXE2_INT_NAME_MAX_LEN];
	u32 event_irq_cnt;

	/* in order to protect the data */
	struct mutex lock;
	DECLARE_BITMAP(map, SXE2_IRQ_MAX_CNT);
};

struct sxe2_q_container {
	struct sxe2_list list;
	struct dim dim;
	u16 itr_idx;
	u16 itr_setting;
	u16 itr_mode;
};

struct sxe2_irq_data {
	u16 idx_in_vsi;
	u16 idx_in_pf;
	u16 rate_limit;
	u8 multiple_polling : 1;
	u16 event_ctr;
	struct sxe2_vsi *vsi;
	struct napi_struct napi;
	struct sxe2_q_container tx;
	struct sxe2_q_container rx;
	s8 name[SXE2_INT_NAME_MAX_LEN];
	cpumask_t affinity_mask;
	struct irq_affinity_notify affinity_notify;
};

s32 sxe2_irq_init(struct sxe2_adapter *adapter);

void sxe2_irq_deinit(struct sxe2_adapter *adapter);

s32 sxe2_event_irq_request(struct sxe2_adapter *adapter);

void sxe2_event_irq_free(struct sxe2_adapter *adapter);

void sxe2_event_irq_enable(struct sxe2_adapter *adapter);

void sxe2_event_irq_disable(struct sxe2_adapter *adapter);

s32 sxe2_irq_offset_get(struct sxe2_adapter *adapter, u16 cnt, u8 vsi_type);

irqreturn_t sxe2_msix_ring_irq_handler(int __always_unused irq, void *data);

irqreturn_t sxe2_msix_ctrl_vsi_handler(int __always_unused irq, void *data);

irqreturn_t sxe2_msix_lb_rx_irq_handler(int __always_unused irq, void *data);

void sxe2_dynamic_itr(struct sxe2_irq_data *irq_data);

void sxe2_irq_rate_limit_init(struct sxe2_irq_data *irq_data);

void sxe2_dim_init(struct sxe2_irq_data *irq_data);

void sxe2_irq_itr_init(struct sxe2_irq_data *irq_data);

int sxe2_napi_poll(struct napi_struct *napi, int weight);

int sxe2_esw_napi_poll(struct napi_struct *napi, int weight);

void sxe2_trigger_soft_intr(struct sxe2_hw *hw, struct sxe2_irq_data *irq_data);

s32 sxe2_irq_resume(struct sxe2_adapter *adapter);

s32 sxe2_dpdk_irq_cnt_get(void       *adapter);

s32 sxe2_dpdk_irq_vector_idx_get(void *adapter, u16 irq_idx);

#endif
