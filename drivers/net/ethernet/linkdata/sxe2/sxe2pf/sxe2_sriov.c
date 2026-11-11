// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_sriov.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/errno.h>
#include <linux/hashtable.h>

#include "sxe2.h"
#include "sxe2_common.h"
#include "sxe2_queue.h"
#include "sxe2_mbx_msg.h"
#include "sxe2_log.h"
#include "sxe2_sriov.h"
#include "sxe2_tx.h"
#include "sxe2_rx.h"
#include "sxe2_netdev.h"
#include "sxe2_eswitch.h"
#include "sxe2_mbx_channel.h"
#include "sxe2_rss.h"
#include "sxe2_ipsec.h"
#include "sxe2_lag.h"
#include "sxe2_fnav.h"
#include "sxe2_drv_cmd.h"
#include "sxe2_vsi.h"
#include "sxe2_acl.h"

static void sxe2_sriov_clear_ceq_irq_map(struct sxe2_vf_node *vf, u16 ceq_idx)
{
	u16 glint_ceqctl_idx = ceq_idx;
	u32 reg_val;

	reg_val = SXE2_REG_READ(&vf->adapter->hw,
				SXE2_VF_GLINT_CEQCTL(glint_ceqctl_idx));
	SXE2_REG_WRITE(&vf->adapter->hw, SXE2_VF_GLINT_CEQCTL(glint_ceqctl_idx),
		       (reg_val & SXE2_VF_CEQ_CTRL_MASK));
}

static void sxe2_sriov_clear_aeq_irq_map(struct sxe2_vf_node *vf)
{
	SXE2_REG_WRITE(&vf->adapter->hw, SXE2_VF_VPINT_AEQCTL(vf->vf_idx), 0);
}

static void sxe2_sriov_clear_rdma_irq_map(struct sxe2_vf_node *vf,
					  struct aux_qv_info *qv_info)
{
	if (qv_info->ceq_idx != SXE2_RDMA_VCHNL_Q_INVALID_IDX)
		sxe2_sriov_clear_ceq_irq_map(vf, qv_info->ceq_idx);

	if (qv_info->aeq_idx != SXE2_RDMA_VCHNL_Q_INVALID_IDX)
		sxe2_sriov_clear_aeq_irq_map(vf);
}

static void sxe2_sriov_cfg_rdma_ceq_irq_map(struct sxe2_vf_node *vf,
					    struct aux_qv_info *qv_info)
{
	u32 regval = ((qv_info->v_idx + vf->irq_base_idx) &
		      SXE2_VF_GLINT_CEQCTL_MSIX_INDX_M) |
		     ((qv_info->itr_idx << SXE2_VF_GLINT_CEQCTL_ITR_INDX_S) &
		      SXE2_VF_GLINT_CEQCTL_ITR_INDX_M) |
		     SXE2_VF_GLINT_CEQCTL_CAUSE_ENA_M;

	SXE2_REG_WRITE(&vf->adapter->hw, SXE2_VF_GLINT_CEQCTL(qv_info->ceq_idx),
		       regval);
	LOG_DEBUG("map info v_idx(%d) irq_base(%d) ceq_idx(%d) value(%d)\t"
		  "itr_idx(%d)",
		  qv_info->v_idx, vf->irq_base_idx,
		  SXE2_VF_GLINT_CEQCTL(qv_info->ceq_idx), regval, qv_info->itr_idx);
}

static void sxe2_sriov_cfg_rdma_aeq_irq_map(struct sxe2_vf_node *vf,
					    struct aux_qv_info *qv_info)
{
	u32 regval = (qv_info->v_idx & SXE2_VF_PFINT_AEQCTL_MSIX_INDX_M) |
		     ((qv_info->itr_idx << SXE2_VF_VPINT_AEQCTL_ITR_INDX_S) &
		      SXE2_VF_VPINT_AEQCTL_ITR_INDX_M) |
		     SXE2_VF_VPINT_AEQCTL_CAUSE_ENA_M;

	SXE2_REG_WRITE(&vf->adapter->hw, SXE2_VF_VPINT_AEQCTL(vf->vf_idx), regval);
	LOG_DEBUG("map info v_idx(%d) vf_idx(%d) aeq_idx(%d) value(%d) itr_idx(%d)",
		  qv_info->v_idx, vf->vf_idx, SXE2_VF_VPINT_AEQCTL(vf->vf_idx),
		  regval, qv_info->itr_idx);
}

static void sxe2_sriov_cfg_rdma_irq_map(struct sxe2_vf_node *vf,
					struct aux_qv_info *qv_info)
{
	if (qv_info->ceq_idx != SXE2_RDMA_VCHNL_Q_INVALID_IDX)
		sxe2_sriov_cfg_rdma_ceq_irq_map(vf, qv_info);

	if (qv_info->aeq_idx != SXE2_RDMA_VCHNL_Q_INVALID_IDX)
		sxe2_sriov_cfg_rdma_aeq_irq_map(vf, qv_info);
}

static const struct sxe2_vf_ops sxe2_sriov_ops = {
		.reset_type = SXE2_RST_TYPE_VF_RESET,
		.clear_mbx_reg = NULL,
		.trigger_reset_register = NULL,
		.poll_reset_status = NULL,
		.clear_reset_trigger = NULL,
		.vsi_rebuild = NULL,
		.post_vsi_rebuild = NULL,
		.cfg_rdma_irq_map = sxe2_sriov_cfg_rdma_irq_map,
		.clear_rdma_irq_map = sxe2_sriov_clear_rdma_irq_map,
};

static s32 sxe2_vf_perm_check(struct sxe2_adapter *adapter, int num_vfs)
{
	if (!test_bit(SXE2_FLAG_SRIOV_CAPABLE, adapter->flags)) {
		LOG_DEV_ERR("sriov not support\n");
		return -EOPNOTSUPP;
	}

	if (sxe2_is_safe_mode(adapter)) {
		LOG_DEV_ERR("device in safe mode, cannot configure sriov\n");
		return -EOPNOTSUPP;
	}

	if (num_vfs > adapter->vf_ctxt.max_vfs) {
		LOG_DEV_ERR("enable %u vfs exceed device vf cap:%u.\n", num_vfs,
			    adapter->vf_ctxt.max_vfs);
		return -EOPNOTSUPP;
	}

	return 0;
}

bool sxe2_vf_is_exist(struct sxe2_adapter *adapter)
{
	return !!adapter->vf_ctxt.num_vfs;
}

bool sxe2_vf_is_trusted(struct sxe2_vf_node *vf)
{
	return vf->prop.trusted;
}

bool sxe2_vf_set_mac_is_allow(struct sxe2_vf_node *vf)
{
	if (vf->prop.mac_from_pf && !sxe2_vf_is_trusted(vf))
		return false;

	return true;
}

STATIC u16 sxe2_sriov_irqs_avail_nums_get(struct sxe2_adapter *adapter)
{
	unsigned long *map = adapter->irq_ctxt.map;
	u16 size = adapter->irq_ctxt.max_cnt;
	struct sxe2_irq_layout *irq_layout = &adapter->irq_ctxt.irq_layout;
	u16 start_idx = irq_layout->macvlan_offset;
	u16 zero_count = 0;
	u16 i;

	for (i = (u16)(size - 1); i >= start_idx; i--) {
		if (test_bit(i, map))
			break;
		zero_count++;

		if (i == 0)
			break;
	}

	return zero_count;
}

STATIC s32 sxe2_vf_irqs_num_set(struct sxe2_adapter *adapter, int num_vfs)
{
	u16 sriov;
	u16 per;
	u16 vf_irq_cnt;
	u16 i;
	struct sxe2_irq_context *irq_ctxt = &adapter->irq_ctxt;
	u16 max_msix = irq_ctxt->max_cnt;
	struct sxe2_irq_layout *irq_layout = &irq_ctxt->irq_layout;
	unsigned long *map = adapter->irq_ctxt.map;

	mutex_lock(&irq_ctxt->lock);

	sriov = sxe2_sriov_irqs_avail_nums_get(adapter);

	per = sriov / (u16)num_vfs;

	if (per < SXE2_VF_1Q_MSIX_NUM) {
		LOG_DEV_ERR("sriov irq:%u not enough to support %u vfs's \t"
			    "minimum msi-x interrupts:%u\n",
			    sriov, num_vfs, SXE2_VF_1Q_MSIX_NUM);
		mutex_unlock(&irq_ctxt->lock);
		return -ENOSPC;
	}

	if (per >= SXE2_VF_64Q_MSIX_NUM)
		vf_irq_cnt = SXE2_VF_64Q_MSIX_NUM;
	else
		vf_irq_cnt = per;

	irq_layout->sriov = (u16)(vf_irq_cnt * (u16)num_vfs);
	irq_layout->sriov_offset = (u16)(max_msix - irq_layout->sriov);
	adapter->vf_ctxt.irq_base = irq_layout->sriov_offset;
	bitmap_set(map, irq_layout->sriov_offset, irq_layout->sriov);

	for (i = 0; i < (u16)num_vfs; i++) {
		struct sxe2_vf_node *vf_node = SXE2_VF_NODE(adapter, i);

		vf_node->irq_cnt = vf_irq_cnt;
		vf_node->irq_base_idx = (u16)(irq_layout->sriov_offset +
					      i * vf_irq_cnt);
	}

	mutex_unlock(&irq_ctxt->lock);

	LOG_INFO_BDF("pf total irq cnt:%u used:%u\t"
		     "sriov:%u num_vfs:%d per vf irq cnt:%u\t"
		     "sriov irq base idx:%u\n",
		     irq_ctxt->max_cnt, irq_ctxt->avail_cnt + irq_layout->macvlan,
		     sriov, num_vfs, vf_irq_cnt, adapter->vf_ctxt.irq_base);

	return 0;
}

bool sxe2_vf_user_cfg_is_set(struct sxe2_adapter *adapter)
{
	u16 i;

	for (i = 0; i < SXE2_VF_NUM; i++) {
		if (SXE2_VF_USR_CFG(adapter, i)->configured)
			return true;
	}

	return false;
}

u16 sxe2_sriov_qs_avail_nums_get(struct sxe2_adapter *adapter, u8 q_type)
{
	unsigned long *map;
	u16 size;
	struct sxe2_queue_layout *q_layout = NULL;
	u16 start_idx;
	u16 zero_count = 0;
	u16 i;

	switch (q_type) {
	case SXE2_DATA_TQ:
		size = adapter->q_ctxt.max_txq_cnt;
		q_layout = &adapter->q_ctxt.txq_layout;
		map = q_layout->txq_map;
		start_idx = q_layout->macvlan_offset;
		break;
	case SXE2_DATA_RQ:
		size = adapter->q_ctxt.max_rxq_cnt;
		q_layout = &adapter->q_ctxt.rxq_layout;
		map = q_layout->rxq_map;
		start_idx = q_layout->macvlan_offset;
		break;
	default:
		zero_count = 0;
		goto l_end;
	}

	for (i = (u16)(size - 1); i >= start_idx; i--) {
		if (test_bit(i, map))
			break;

		zero_count++;

		if (i == 0)
			break;
	}

l_end:
	return zero_count;
}

static void sxe2_vf_eswitch_qs_occupy(struct sxe2_adapter *adapter, int num_vfs)
{
	struct sxe2_queue_layout *txq_layout = &adapter->q_ctxt.txq_layout;
	struct sxe2_queue_layout *rxq_layout = &adapter->q_ctxt.rxq_layout;

	if (!sxe2_eswitch_is_offload(adapter))
		return;

	txq_layout->esw = (u16)num_vfs;
	txq_layout->esw_offset =
			(u16)(txq_layout->sriov_offset - txq_layout->esw);
	txq_layout->dpdk_esw = (u16)num_vfs;
	txq_layout->dpdk_esw_offset =
			(u16)(txq_layout->sriov_offset - txq_layout->esw -
			      txq_layout->dpdk_esw);

	rxq_layout->esw = (u16)num_vfs;
	rxq_layout->esw_offset =
			(u16)(rxq_layout->sriov_offset - rxq_layout->esw);
	rxq_layout->dpdk_esw = (u16)num_vfs;
	rxq_layout->dpdk_esw_offset =
			(u16)(rxq_layout->sriov_offset - rxq_layout->esw -
			      rxq_layout->dpdk_esw);

	bitmap_set(txq_layout->txq_map, txq_layout->esw_offset,
		   txq_layout->esw);
	bitmap_set(rxq_layout->rxq_map, rxq_layout->esw_offset,
		   rxq_layout->esw);
	bitmap_set(txq_layout->txq_map, txq_layout->dpdk_esw_offset,
		   txq_layout->dpdk_esw);
	bitmap_set(rxq_layout->rxq_map, rxq_layout->dpdk_esw_offset,
		   rxq_layout->dpdk_esw);
}

static void sxe2_vf_idle_qs_get(struct sxe2_adapter *adapter, u16 num_vfs,
				u16 *txq_idle, u16 *rxq_idle)
{
	u16 eswitch_need = 0;

	if (sxe2_eswitch_is_offload(adapter))
		eswitch_need = (u16)(num_vfs * SXE2_VF_ESW_CNT);

	*txq_idle = sxe2_sriov_qs_avail_nums_get(adapter, SXE2_DATA_TQ);
	*rxq_idle = sxe2_sriov_qs_avail_nums_get(adapter, SXE2_DATA_RQ);
	*txq_idle = (*txq_idle > eswitch_need) ?
		    (u16)(*txq_idle - eswitch_need) : (u16)0;
	*rxq_idle = (*rxq_idle > eswitch_need) ?
		    (u16)(*rxq_idle - eswitch_need) : (u16)0;
}

static void sxe2_vf_sriov_window_set(struct sxe2_adapter *adapter, u16 q_total)
{
	struct sxe2_queue_layout *txq_layout = &adapter->q_ctxt.txq_layout;
	struct sxe2_queue_layout *rxq_layout = &adapter->q_ctxt.rxq_layout;

	txq_layout->sriov = q_total;
	txq_layout->sriov_offset =
		(u16)(adapter->q_ctxt.max_txq_cnt - q_total);
	rxq_layout->sriov = q_total;
	rxq_layout->sriov_offset =
		(u16)(adapter->q_ctxt.max_rxq_cnt - q_total);

	bitmap_set(txq_layout->txq_map, txq_layout->sriov_offset,
		   txq_layout->sriov);
	bitmap_set(rxq_layout->rxq_map, rxq_layout->sriov_offset,
		   rxq_layout->sriov);
}

static void sxe2_vf_nodes_qs_account(struct sxe2_adapter *adapter, u16 num_vfs,
				     u16 vf_q_cnt)
{
	struct sxe2_queue_layout *txq_layout = &adapter->q_ctxt.txq_layout;
	struct sxe2_queue_layout *rxq_layout = &adapter->q_ctxt.rxq_layout;
	u16 i;

	for (i = 0; i < num_vfs; i++) {
		struct sxe2_vf_node *vf_node = SXE2_VF_NODE(adapter, i);

		vf_node->q_cnt = vf_q_cnt;
		vf_node->rxq_base =
			(u16)(rxq_layout->sriov_offset + i * vf_q_cnt);
		vf_node->txq_base =
			(u16)(txq_layout->sriov_offset + i * vf_q_cnt);
	}
}

static bool sxe2_vf_queue_pool_check(struct sxe2_adapter *adapter,
				     u16 num_vfs, u32 need_q, u16 *avail)
{
	struct sxe2_queue_layout *txq_layout = &adapter->q_ctxt.txq_layout;
	struct sxe2_queue_layout *rxq_layout = &adapter->q_ctxt.rxq_layout;
	u32 eswitch_q = 0;
	u32 pool;
	s32 pool_rx;
	s32 pool_tx;

	if (sxe2_eswitch_is_offload(adapter))
		eswitch_q = (u32)num_vfs * SXE2_VF_ESW_CNT;

	pool_rx = (s32)adapter->q_ctxt.max_rxq_cnt -
		  rxq_layout->macvlan_offset - rxq_layout->macvlan;
	pool_tx = (s32)adapter->q_ctxt.max_txq_cnt -
		  txq_layout->macvlan_offset - txq_layout->macvlan;
	pool = (u32)min_t(s32, max(pool_rx, 0), max(pool_tx, 0));

	if (need_q + eswitch_q > pool) {
		LOG_DEV_ERR("need_q:%u eswitch:%u exceed avail pool:%u\n",
			    need_q, eswitch_q, pool);
		return false;
	}

	if (avail)
		*avail = (u16)(pool - eswitch_q);

	return true;
}

static s32 sxe2_vf_queue_user_cfg_res_check(struct sxe2_adapter *adapter,
					    int num_vfs, u16 *per_slot_q,
					    u16 *extra_q, u16 *esw_cov)
{
	u16 spare_q_total = adapter->vf_ctxt.large_q.spare_q;
	u16 occupied_q_cnt = adapter->vf_ctxt.large_q.occupied_q_cnt;
	u16 empty_slot_cnt = 0;
	u32 esw_q = 0;
	u32 spare_left;
	s32 pool_rx;
	s32 pool_tx;
	s32 pool;
	s32 budget;
	u16 i;
	u8 v;
	struct sxe2_vf_usr_cfg *usr_cfg;

	if ((u16)num_vfs > SXE2_VF_LARGE_Q_VF_NUM_MAX) {
		u16 max_cfg_id = adapter->vf_ctxt.large_q.max_vf_id;
		u16 q_max;

		for (i = 0; i <= max_cfg_id; i++) {
			usr_cfg = SXE2_VF_USR_CFG(adapter, i);
			for (v = 0; v < SXE2_PRODUCT_ID_NR; v++) {
				q_max = (v == SXE2_PRODUCT_ID_KERNEL) ?
					SXE2_VSI_LUT_MAX_QUEUE :
					SXE2_VF_LARGE_Q_DPDK_Q_MAX;
				if (usr_cfg->product[v].q_cfg > q_max) {
					LOG_WARN_BDF("vf:%u %s cfg q:%u > %u, not allowed when "
						     "num_vfs:%d exceeds %u\n",
						     i,
						     v == SXE2_PRODUCT_ID_KERNEL ?
						     "kernel" : "dpdk",
						     usr_cfg->product[v].q_cfg,
						     q_max, num_vfs,
						     SXE2_VF_LARGE_Q_VF_NUM_MAX);
					return -ENOSPC;
				}
			}
		}
	}

	for (i = 0; i < (u16)num_vfs; i++) {
		usr_cfg = SXE2_VF_USR_CFG(adapter, i);
		for (v = 0; v < SXE2_PRODUCT_ID_NR; v++) {
			if (!usr_cfg->product[v].q_cfg)
				empty_slot_cnt++;
		}
	}

	if (sxe2_eswitch_is_offload(adapter))
		esw_q = (u32)num_vfs * SXE2_VF_ESW_CNT;

	*esw_cov = (u16)min_t(u32, spare_q_total, esw_q);
	spare_left = spare_q_total - *esw_cov;

	pool_rx = (s32)adapter->q_ctxt.max_rxq_cnt -
		  adapter->q_ctxt.rxq_layout.macvlan_offset -
		  adapter->q_ctxt.rxq_layout.macvlan;
	pool_tx = (s32)adapter->q_ctxt.max_txq_cnt -
		  adapter->q_ctxt.txq_layout.macvlan_offset -
		  adapter->q_ctxt.txq_layout.macvlan;
	pool = min_t(s32, max(pool_rx, 0), max(pool_tx, 0));

	*per_slot_q = 0;
	*extra_q = 0;

	if ((s32)occupied_q_cnt + ((s32)esw_q - (s32)*esw_cov) > pool) {
		LOG_DEV_ERR("occupied:%u esw:%u spare_cover:%u exceed avail pool:%d\n",
			    occupied_q_cnt, esw_q, *esw_cov, pool);
		return -ENOSPC;
	}

	if (!empty_slot_cnt)
		return 0;

	*per_slot_q = min_t(u16, (u16)(spare_left / empty_slot_cnt),
			    SXE2_VSI_LUT_MAX_QUEUE);
	if (*per_slot_q >= SXE2_VF_QUEUE_CNT_MIN)
		return 0;

	budget = pool - (s32)occupied_q_cnt + (s32)(spare_q_total - esw_q);
	*per_slot_q = min_t(u16, (u16)((u32)max(budget, 0) / empty_slot_cnt),
			    SXE2_VSI_LUT_MAX_QUEUE);
	if (*per_slot_q < SXE2_VF_QUEUE_CNT_MIN) {
		LOG_DEV_ERR("num_vfs:%d empty slots:%u spare_q:%u esw_q:%u "
			    "budget:%d per_slot:%u not enough\n",
			    num_vfs, empty_slot_cnt, spare_q_total, esw_q,
			    budget, *per_slot_q);
		*per_slot_q = 0;
		return -ENOSPC;
	}

	*extra_q = (u16)((u32)*per_slot_q * empty_slot_cnt - spare_left);

	return 0;
}

static void sxe2_vf_usr_cfg_q_idx_set(struct sxe2_adapter *adapter,
				      int num_vfs, u16 per_slot_q, u16 extra_q,
				      u16 esw_cov)
{
	struct sxe2_queue_layout *txq_layout = &adapter->q_ctxt.txq_layout;
	struct sxe2_queue_layout *rxq_layout = &adapter->q_ctxt.rxq_layout;
	u16 max_txq_cnt = adapter->q_ctxt.max_txq_cnt;
	u16 max_rxq_cnt = adapter->q_ctxt.max_rxq_cnt;
	u16 rx_level = max_rxq_cnt;
	u16 tx_level = max_txq_cnt;
	u16 i;
	u8 v;
	struct sxe2_vf_usr_cfg *usr_cfg;
	struct sxe2_vf_node *vf_node;

	for (i = 0; i < (u16)num_vfs; i++) {
		u16 vf_q_total = 0;

		usr_cfg = SXE2_VF_USR_CFG(adapter, i);
		vf_node = SXE2_VF_NODE(adapter, i);
		for (v = 0; v < SXE2_PRODUCT_ID_NR; v++) {
			if (usr_cfg->product[v].q_cfg) {
				vf_q_total += usr_cfg->product[v].q_cfg;
			} else {
				vf_q_total += per_slot_q;
				usr_cfg->product[v].lut_id =
					SXE2_VF_GLOBAL_LUT_INVALID_ID;
				usr_cfg->product[v].lut_type = SXE2_RSS_VSI_LUT;
				usr_cfg->product[v].lut_size =
					SXE2_RSS_LUT_SIZE_64;
			}
		}

		rx_level -= vf_q_total;
		tx_level -= vf_q_total;
		vf_node->q_cnt = vf_q_total;
		vf_node->rxq_base = rx_level;
		vf_node->txq_base = tx_level;
	}

	rxq_layout->sriov_offset =
		(u16)(max_rxq_cnt - adapter->vf_ctxt.large_q.occupied_q_cnt -
		      extra_q + esw_cov);
	rxq_layout->sriov = adapter->vf_ctxt.large_q.occupied_q_cnt + extra_q -
			    esw_cov;
	txq_layout->sriov_offset =
		(u16)(max_txq_cnt - adapter->vf_ctxt.large_q.occupied_q_cnt -
		      extra_q + esw_cov);
	txq_layout->sriov = adapter->vf_ctxt.large_q.occupied_q_cnt + extra_q -
			    esw_cov;
	adapter->vf_ctxt.large_q.esw_cov = esw_cov;

	if (extra_q) {
		bitmap_set(rxq_layout->rxq_map, rxq_layout->sriov_offset,
			   extra_q);
		bitmap_set(txq_layout->txq_map, txq_layout->sriov_offset,
			   extra_q);
		adapter->vf_ctxt.large_q.extra_q_cnt = extra_q;
	}

	LOG_INFO_BDF("use user queue cfg, num_vfs:%d per_slot_q:%u occupied_q_cnt:%u\t"
		     "extra_q:%u esw_cov:%u used rxq:%u+%u txq:%u+%u\n",
		     num_vfs, per_slot_q, adapter->vf_ctxt.large_q.occupied_q_cnt,
		     extra_q, esw_cov,
		     rx_level, (u16)(max_rxq_cnt - rx_level),
		     tx_level, (u16)(max_txq_cnt - tx_level));
}

static s32 sxe2_vf_queues_user_cfg_apply(struct sxe2_adapter *adapter, int num_vfs)
{
	u16 per_slot_q;
	u16 extra_q;
	u16 esw_cov;
	s32 ret;

	ret = sxe2_vf_queue_user_cfg_res_check(adapter, num_vfs, &per_slot_q,
					       &extra_q, &esw_cov);
	if (ret)
		return ret;

	sxe2_vf_usr_cfg_q_idx_set(adapter, num_vfs, per_slot_q, extra_q,
				  esw_cov);

	sxe2_vf_eswitch_qs_occupy(adapter, num_vfs);

	return 0;
}

static void sxe2_vf_dpdk_luts_release(struct sxe2_adapter *adapter, u16 num_vfs)
{
	u16 i;

	for (i = 0; i < num_vfs; i++) {
		struct sxe2_vf_usr_cfg *usr_cfg = SXE2_VF_USR_CFG(adapter, i);

		if (usr_cfg->product[SXE2_PRODUCT_ID_DPDK].lut_id ==
		    SXE2_VF_GLOBAL_LUT_INVALID_ID)
			continue;

		sxe2_global_lut_put(adapter,
				    usr_cfg->product[SXE2_PRODUCT_ID_DPDK].lut_id);
		usr_cfg->product[SXE2_PRODUCT_ID_DPDK].lut_id =
			SXE2_VF_GLOBAL_LUT_INVALID_ID;
		usr_cfg->product[SXE2_PRODUCT_ID_DPDK].lut_type = SXE2_RSS_VSI_LUT;
		usr_cfg->product[SXE2_PRODUCT_ID_DPDK].lut_size =
			SXE2_RSS_LUT_SIZE_64;
	}
}

static bool sxe2_vf_dflt_large_q_lut_apply(struct sxe2_adapter *adapter,
					   int num_vfs, u16 *kernel_q)
{
	u8 lut_ids[SXE2_RSS_GLOBAL_LUT_NUM_MAX];
	u16 remain;
	u16 i;

	if (!sxe2_vf_queue_pool_check(adapter, (u16)num_vfs,
				      (u32)num_vfs * (SXE2_VF_DFLT_LARGE_Q_NUM +
						      SXE2_VF_QUEUE_CNT_MIN),
				      &remain))
		return false;

	if (!sxe2_global_lut_get_bulk(adapter, (u16)num_vfs, lut_ids)) {
		LOG_DEV_ERR("num_vfs:%d global lut not enough\n", num_vfs);
		return false;
	}

	for (i = 0; i < (u16)num_vfs; i++) {
		struct sxe2_vf_usr_cfg *usr_cfg = SXE2_VF_USR_CFG(adapter, i);

		usr_cfg->product[SXE2_PRODUCT_ID_DPDK].lut_id = lut_ids[i];
		usr_cfg->product[SXE2_PRODUCT_ID_DPDK].lut_type =
			SXE2_RSS_GLOBAL_LUT;
		usr_cfg->product[SXE2_PRODUCT_ID_DPDK].lut_size =
			SXE2_RSS_LUT_SIZE_512;
		usr_cfg->product[SXE2_PRODUCT_ID_KERNEL].lut_id =
			SXE2_VF_GLOBAL_LUT_INVALID_ID;
		usr_cfg->product[SXE2_PRODUCT_ID_KERNEL].lut_type =
			SXE2_RSS_VSI_LUT;
		usr_cfg->product[SXE2_PRODUCT_ID_KERNEL].lut_size =
			SXE2_RSS_LUT_SIZE_64;
	}

	*kernel_q = (u16)((remain - (u32)num_vfs * SXE2_VF_DFLT_LARGE_Q_NUM) /
			  (u16)num_vfs);
	*kernel_q = min_t(u16, *kernel_q, SXE2_VSI_LUT_MAX_QUEUE);

	return true;
}

static void sxe2_vf_dflt_large_q_idx_set(struct sxe2_adapter *adapter,
					 int num_vfs, u16 vf_q_cnt)
{
	sxe2_vf_sriov_window_set(adapter, (u16)(vf_q_cnt * (u16)num_vfs));
	sxe2_vf_nodes_qs_account(adapter, (u16)num_vfs, vf_q_cnt);
}

static bool sxe2_vf_queues_dflt_large_q_apply(struct sxe2_adapter *adapter,
					      int num_vfs)
{
	u16 kernel_q;
	u16 vf_q_cnt;

	if (!sxe2_vf_dflt_large_q_lut_apply(adapter, num_vfs, &kernel_q))
		return false;

	vf_q_cnt = SXE2_VF_DFLT_LARGE_Q_NUM + kernel_q;

	sxe2_vf_dflt_large_q_idx_set(adapter, num_vfs, vf_q_cnt);
	adapter->vf_ctxt.large_q.dflt_large_q_en = true;

	sxe2_vf_eswitch_qs_occupy(adapter, num_vfs);

	LOG_INFO_BDF("use default large q strategy, num_vfs:%d kernel_q:%u q_cnt:%u\t"
		     "sriov rxq:%u+%u txq:%u+%u\n",
		     num_vfs, kernel_q, vf_q_cnt,
		     adapter->q_ctxt.rxq_layout.sriov_offset,
		     adapter->q_ctxt.rxq_layout.sriov,
		     adapter->q_ctxt.txq_layout.sriov_offset,
		     adapter->q_ctxt.txq_layout.sriov);
	return true;
}

static s32 sxe2_vf_queue_dflt_res_check(struct sxe2_adapter *adapter,
					int num_vfs, u16 *vf_q_cnt)
{
	u16 txq_cnt;
	u16 rxq_cnt;
	u16 txq_idle;
	u16 rxq_idle;
	u16 per;

	sxe2_vf_idle_qs_get(adapter, (u16)num_vfs, &txq_idle, &rxq_idle);

	per = txq_idle / (u16)num_vfs;
	txq_cnt = per ? (u16)min_t(u16, per, (u16)SXE2_VF_QUEUE_CNT_DFLT_MAX) :
			0U;
	per = rxq_idle / (u16)num_vfs;
	rxq_cnt = per ? (u16)min_t(u16, per, (u16)SXE2_VF_QUEUE_CNT_DFLT_MAX) :
			0U;

	if (txq_cnt < SXE2_VF_QUEUE_CNT_MIN || rxq_cnt < SXE2_VF_QUEUE_CNT_MIN) {
		LOG_DEV_ERR("txq_idle:%u rxq_idle:%u not enough\t"
			    "to support %u vfs's minimum queue cnt:%u\n",
			    txq_idle, rxq_idle, num_vfs, SXE2_VF_QUEUE_CNT_MIN);
		return -ENOSPC;
	}
	*vf_q_cnt = (u16)min_t(u16, rxq_cnt, txq_cnt);

	LOG_INFO_BDF("num_vfs:%d txq_idle:%u rxq_idle:%u \t"
		     "txq_cnt:%u rxq_cnt:%u q_cnt:%u swt_mode:%u.\n",
		     num_vfs, txq_idle, rxq_idle, txq_cnt, rxq_cnt,
		     *vf_q_cnt, adapter->eswitch_ctxt.mode);

	return 0;
}

static void sxe2_vf_dflt_q_idx_set(struct sxe2_adapter *adapter,
				   int num_vfs, u16 vf_q_cnt)
{
	sxe2_vf_sriov_window_set(adapter, (u16)(vf_q_cnt * (u16)num_vfs));
	sxe2_vf_nodes_qs_account(adapter, (u16)num_vfs, vf_q_cnt);
}

static s32 sxe2_vf_queues_dflt_apply(struct sxe2_adapter *adapter, int num_vfs)
{
	u16 vf_q_cnt;
	s32 ret;

	ret = sxe2_vf_queue_dflt_res_check(adapter, num_vfs, &vf_q_cnt);
	if (ret)
		return ret;

	sxe2_vf_dflt_q_idx_set(adapter, num_vfs, vf_q_cnt);
	sxe2_vf_eswitch_qs_occupy(adapter, num_vfs);

	return 0;
}

static s32 sxe2_vf_queues_num_set(struct sxe2_adapter *adapter, int num_vfs)
{
	struct mutex *lock = &adapter->q_ctxt.lock;
	s32 ret = 0;

	mutex_lock(lock);

	if (sxe2_vf_user_cfg_is_set(adapter)) {
		ret = sxe2_vf_queues_user_cfg_apply(adapter, num_vfs);
	} else if (sxe2_vf_queues_dflt_large_q_apply(adapter, num_vfs)) {
		LOG_INFO_BDF("default large q strategy applied for %d vfs\n",
			     num_vfs);
	} else {
		ret = sxe2_vf_queues_dflt_apply(adapter, num_vfs);
	}

	mutex_unlock(lock);
	return ret;
}

static void sxe2_vf_eswitch_qs_release(struct sxe2_adapter *adapter)
{
	struct sxe2_queue_context *q_ctxt = &adapter->q_ctxt;
	struct sxe2_queue_layout *txq_layout = &q_ctxt->txq_layout;
	struct sxe2_queue_layout *rxq_layout = &q_ctxt->rxq_layout;
	u16 blk_overlap;

	if (!sxe2_eswitch_is_offload(adapter))
		return;

	blk_overlap = (u16)max_t(s32, 0,
				 ((s32)adapter->vf_ctxt.large_q.esw_cov -
				 (s32)adapter->vf_ctxt.large_q.extra_q_cnt));

	bitmap_clear(txq_layout->txq_map, txq_layout->dpdk_esw_offset,
		     (u16)(txq_layout->esw + txq_layout->dpdk_esw - blk_overlap));
	bitmap_clear(rxq_layout->rxq_map, rxq_layout->dpdk_esw_offset,
		     (u16)(rxq_layout->esw + rxq_layout->dpdk_esw - blk_overlap));

	txq_layout->esw = 0;
	txq_layout->esw_offset = q_ctxt->max_txq_cnt;
	txq_layout->dpdk_esw = 0;
	txq_layout->dpdk_esw_offset = q_ctxt->max_txq_cnt;

	rxq_layout->esw = 0;
	rxq_layout->esw_offset = q_ctxt->max_rxq_cnt;
	rxq_layout->dpdk_esw = 0;
	rxq_layout->dpdk_esw_offset = q_ctxt->max_rxq_cnt;

	adapter->vf_ctxt.large_q.esw_cov = 0;
}

static void sxe2_vf_irq_queues_num_clear(struct sxe2_adapter *adapter)
{
	struct sxe2_irq_context *irq_ctxt = &adapter->irq_ctxt;
	struct sxe2_irq_layout *irq_layout = &irq_ctxt->irq_layout;
	unsigned long *map = adapter->irq_ctxt.map;

	struct sxe2_queue_context *q_ctxt = &adapter->q_ctxt;
	struct sxe2_queue_layout *txq_layout = &q_ctxt->txq_layout;
	struct sxe2_queue_layout *rxq_layout = &q_ctxt->rxq_layout;

	mutex_lock(&irq_ctxt->lock);
	bitmap_clear(map, adapter->vf_ctxt.irq_base, irq_layout->sriov);
	irq_layout->sriov = 0;
	irq_layout->sriov_offset = irq_ctxt->max_cnt;
	mutex_unlock(&irq_ctxt->lock);

	if (sxe2_vf_user_cfg_is_set(adapter)) {
		mutex_lock(&q_ctxt->lock);
		if (adapter->vf_ctxt.large_q.extra_q_cnt) {
			bitmap_clear(txq_layout->txq_map,
				     q_ctxt->max_txq_cnt -
				     adapter->vf_ctxt.large_q.occupied_q_cnt -
				     adapter->vf_ctxt.large_q.extra_q_cnt,
				     adapter->vf_ctxt.large_q.extra_q_cnt);
			bitmap_clear(rxq_layout->rxq_map,
				     q_ctxt->max_rxq_cnt -
				     adapter->vf_ctxt.large_q.occupied_q_cnt -
				     adapter->vf_ctxt.large_q.extra_q_cnt,
				     adapter->vf_ctxt.large_q.extra_q_cnt);
			adapter->vf_ctxt.large_q.extra_q_cnt = 0;
		}
		txq_layout->sriov = 0;
		txq_layout->sriov_offset = q_ctxt->max_txq_cnt;
		rxq_layout->sriov = 0;
		rxq_layout->sriov_offset = q_ctxt->max_rxq_cnt;
		sxe2_vf_eswitch_qs_release(adapter);
		mutex_unlock(&q_ctxt->lock);

		adapter->vf_ctxt.irq_base = 0;
		return;
	}

	if (adapter->vf_ctxt.large_q.dflt_large_q_en) {
		sxe2_vf_dpdk_luts_release(adapter, SXE2_VF_NUM);
		adapter->vf_ctxt.large_q.dflt_large_q_en = false;
	}

	mutex_lock(&q_ctxt->lock);
	bitmap_clear(txq_layout->txq_map, txq_layout->sriov_offset,
		     txq_layout->sriov);
	txq_layout->sriov = 0;
	txq_layout->sriov_offset = q_ctxt->max_txq_cnt;

	bitmap_clear(rxq_layout->rxq_map, rxq_layout->sriov_offset,
		     rxq_layout->sriov);
	rxq_layout->sriov = 0;
	rxq_layout->sriov_offset = q_ctxt->max_rxq_cnt;

	sxe2_vf_eswitch_qs_release(adapter);
	mutex_unlock(&q_ctxt->lock);

	adapter->vf_ctxt.irq_base = 0;
}

static void sxe2_vf_node_free(struct sxe2_adapter *adapter, u16 vf_idx)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_vf_node_e *vf_node_e = SXE2_VF_NODE_E(adapter, vf_idx);

	BUG_ON(vf_idx >= adapter->vf_ctxt.max_vfs);

	mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));

	devm_kfree(dev, vf_node_e->vf_node);
	vf_node_e->vf_node = NULL;

	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
}

static void sxe2_vf_nodes_free(struct sxe2_adapter *adapter, u16 num_vfs)
{
	u16 vf_idx;

	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++)
		sxe2_vf_node_free(adapter, vf_idx);
}

static s32 sxe2_vf_node_alloc(struct sxe2_adapter *adapter, u16 num_vfs)
{
	struct sxe2_vf_node_e *vf_node_e;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u16 vf_idx;

	lockdep_assert_held(&adapter->vf_ctxt.vfs_lock);

	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		vf_node_e = SXE2_VF_NODE_E(adapter, vf_idx);
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));

		vf_node_e->vf_node = devm_kzalloc(dev,
						  sizeof(struct sxe2_vf_node),
						  GFP_KERNEL);
		if (!vf_node_e->vf_node) {
			LOG_DEV_ERR("vf node alloc failed num_vfs:%u vf_idx:%u\t"
				    "size:%zu\n",
				    num_vfs, vf_idx,
				    sizeof(struct sxe2_vf_node));
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
			goto l_free;
		}

		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	}

	return 0;

l_free:
	sxe2_vf_nodes_free(adapter, vf_idx);

	return -ENOMEM;
}

static void sxe2_vf_sw_res_deinit(struct sxe2_adapter *adapter)
{
	lockdep_assert_held(&adapter->vf_ctxt.vfs_lock);

	LOG_DEV_WARN("%u vf sw res deinit.\n", adapter->vf_ctxt.num_vfs);
	adapter->vf_ctxt.num_vfs = 0;
}

static s32 sxe2_vf_sw_res_init(struct sxe2_adapter *adapter, u32 num_vfs)
{
	struct sxe2_vf_node_e *vf_node_e;
	u16 vf_idx;

	lockdep_assert_held(&adapter->vf_ctxt.vfs_lock);

	adapter->vf_ctxt.adapter = adapter;

	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		vf_node_e = SXE2_VF_NODE_E(adapter, vf_idx);
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));

		set_bit(SXE2_VF_STATE_DIS, vf_node_e->vf_node->states);
		vf_node_e->vf_node->adapter = adapter;
		vf_node_e->vf_node->vf_idx = vf_idx;
		vf_node_e->vf_node->msg_table = sxe2_mbx_msg_table_get();
		vf_node_e->vf_node->vf_ops = &sxe2_sriov_ops;
		vf_node_e->vf_node->prop.spoofchk = true;
		vf_node_e->vf_node->vf_cfg_mode = SXE2_COM_MODULE_UNDEFINED;
		vf_node_e->vf_node->vf_run_mode = SXE2_COM_MODULE_UNDEFINED;

		mutex_init(&vf_node_e->vf_node->repr_cfg_lock);

		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	}

	adapter->vf_ctxt.num_vfs = (u16)num_vfs;

	return 0;
}

struct sxe2_vf_node *sxe2_vf_node_get(struct sxe2_adapter *adapter, u16 vf_id)
{
	struct sxe2_vf_node *vf_node = NULL;

	lockdep_assert_held(SXE2_VF_NODE_LOCK(adapter, vf_id));

	if (vf_id >= adapter->vf_ctxt.num_vfs) {
		LOG_ERROR_BDF("invalid vf_id:%u.\n", vf_id);
		goto l_out;
	}

	vf_node = SXE2_VF_NODE(adapter, vf_id);
	if (!vf_node)
		LOG_DEV_ERR("vf_id:%u node NULL.\n", vf_id);

l_out:
	return vf_node;
}

STATIC s32 sxe2_vf_vlan_init(struct sxe2_vf_node *vf_node, struct sxe2_vsi *vsi)
{
	s32 ret = 0;

	if (sxe2_port_vlan_is_exist(vf_node)) {
		ret = sxe2_vf_vsi_port_vlan_cfg(vf_node, vsi);
		if (ret)
			LOG_ERROR("vf:%u vsi %u port vlan cfg fail %d.\n",
				  vf_node->vf_idx, vsi->idx_in_dev, ret);
	} else {
		ret = sxe2_vsi_vlan_zero_add(vf_node->vsi);
		if (ret)
			LOG_ERROR("vf:%u vsi %u add vlan 0 fail %d.\n",
				  vf_node->vf_idx, vsi->idx_in_dev, ret);
	}

	return ret;
}

void sxe2_vf_mac_cnt_inc(struct sxe2_vf_node *vf_node, struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter;

	if (!vf_node || !vsi)
		return;

	adapter = vf_node->adapter;

	if (vsi->type == SXE2_VSI_T_DPDK_VF)
		vf_node->usr_mac_cnt++;

	vf_node->total_mac_cnt++;
	LOG_INFO_BDF("vf:%u mac add: total_cnt:%u dpdk_cnt:%u\n",
		     vf_node->vf_idx, vf_node->total_mac_cnt,
		     vf_node->usr_mac_cnt);
}

void sxe2_vf_vlan_cnt_inc(struct sxe2_vf_node *vf_node, struct sxe2_vsi *vsi, u16 vlan_id)
{
	struct sxe2_adapter *adapter;

	if (!vf_node || !vsi)
		return;

	adapter = vf_node->adapter;

	if (vlan_id == 0)
		return;

	if (vsi->type == SXE2_VSI_T_DPDK_VF)
		vf_node->vlan_info.usr_vlan_cnt++;

	vf_node->vlan_info.total_vlan_cnt++;

	LOG_INFO_BDF("vf:%u vlan add: total_cnt:%u dpdk_cnt:%u\n",
		     vf_node->vf_idx, vf_node->vlan_info.total_vlan_cnt,
		     vf_node->vlan_info.usr_vlan_cnt);
}

void sxe2_vf_mac_cnt_dec(struct sxe2_vf_node *vf_node, struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter;

	if (!vf_node || !vsi)
		return;

	adapter = vf_node->adapter;

	if (vsi->type == SXE2_VSI_T_DPDK_VF)
		vf_node->usr_mac_cnt--;

	vf_node->total_mac_cnt--;

	LOG_INFO_BDF("vf:%u mac del: total_cnt:%u dpdk_cnt:%u\n",
		     vf_node->vf_idx, vf_node->total_mac_cnt,
		     vf_node->usr_mac_cnt);
}

void sxe2_vf_vlan_cnt_dec(struct sxe2_vf_node *vf_node, struct sxe2_vsi *vsi, u16 vlan_id)
{
	struct sxe2_adapter *adapter;

	if (!vf_node || !vsi)
		return;

	adapter = vf_node->adapter;

	if (vlan_id == 0)
		return;

	if (vsi->type == SXE2_VSI_T_DPDK_VF)
		vf_node->vlan_info.usr_vlan_cnt--;

	vf_node->vlan_info.total_vlan_cnt--;
	LOG_INFO_BDF("vf:%u vlan del: total_cnt:%u dpdk_cnt:%u\n",
		     vf_node->vf_idx, vf_node->vlan_info.total_vlan_cnt,
		     vf_node->vlan_info.usr_vlan_cnt);
}

void sxe2_vf_mac_cnt_clr(struct sxe2_vf_node *vf_node, struct sxe2_vsi *vsi)
{
	if (!vf_node || !vsi)
		return;

	if (vsi->type == SXE2_VSI_T_DPDK_VF) {
		vf_node->total_mac_cnt -= vf_node->usr_mac_cnt;
		vf_node->usr_mac_cnt = 0;
	} else {
		vf_node->total_mac_cnt = vf_node->usr_mac_cnt;
	}
}

void sxe2_vf_vlan_cnt_clr(struct sxe2_vf_node *vf_node, struct sxe2_vsi *vsi)
{
	if (!vf_node || !vsi)
		return;

	if (vsi->type == SXE2_VSI_T_DPDK_VF) {
		vf_node->vlan_info.total_vlan_cnt -= vf_node->vlan_info.usr_vlan_cnt;
		vf_node->vlan_info.usr_vlan_cnt = 0;
	} else {
		vf_node->vlan_info.total_vlan_cnt = vf_node->vlan_info.usr_vlan_cnt;
	}
}

static s32 sxe2_vf_mac_init(struct sxe2_vf_node *vf_node, struct sxe2_vsi *vsi)
{
	s32 ret;
	u8 broadcast[ETH_ALEN];

	eth_broadcast_addr(broadcast);
	ret = sxe2_mac_rule_add(vsi, broadcast);
	if (ret) {
		LOG_ERROR("vf:%u vsi:%u broadcast mac addr add failed.(err:%d).\n",
			  vf_node->vf_idx, vsi->idx_in_dev, ret);
		return ret;
	}

	sxe2_vf_mac_cnt_inc(vf_node, vsi);

	return 0;
}

s32 sxe2_vf_id_check(struct sxe2_adapter *adapter, u16 vf_idx)
{
	if (vf_idx >= adapter->vf_ctxt.max_vfs) {
		LOG_DEV_ERR("invalid vf_idx:%u exceed max_vfs:%u.\n", vf_idx,
			    adapter->vf_ctxt.max_vfs);
		return -EINVAL;
	}

	return 0;
}

STATIC s32 sxe2_vf_vsi_id_alloc(struct sxe2_vf_node *vf_node)
{
	s32 ret = 0;
	struct sxe2_hw *hw = &vf_node->adapter->hw;
	struct sxe2_adapter *adapter = vf_node->adapter;
	u16 i;
	u16 idx_in_pf;

	for (i = 0; i < SXE2_VF_VSI_ID_NR; i++) {
		mutex_lock(&adapter->vsi_ctxt.lock);
		idx_in_pf = sxe2_vsi_get(&adapter->vsi_ctxt);
		mutex_unlock(&adapter->vsi_ctxt.lock);
		if (idx_in_pf == SXE2_INVAL_U16) {
			ret = -ENOSPC;
			LOG_DEV_ERR("No Free Vsis.\n");
			goto l_err;
		}
		vf_node->vsi_id[i] = idx_in_pf + adapter->vsi_ctxt.base_idx_in_dev;
		LOG_INFO_BDF("vf:%d vsi id_in_pf:%d type:%d id_in_dev:%d.\n",
			     vf_node->vf_idx, idx_in_pf, i, vf_node->vsi_id[i]);

		sxe2_hw_l2tag_accept(hw, vf_node->vsi_id[i]);
	}

	return ret;

l_err:
	while (i) {
		i--;
		idx_in_pf = (u16)(vf_node->vsi_id[i] -
				  adapter->vsi_ctxt.base_idx_in_dev);
		mutex_lock(&adapter->vsi_ctxt.lock);
		sxe2_vsi_put(&adapter->vsi_ctxt, idx_in_pf);
		mutex_unlock(&adapter->vsi_ctxt.lock);
	}
	return ret;
}

static void sxe2_vf_vsi_id_free(struct sxe2_vf_node *vf_node)
{
	struct sxe2_adapter *adapter = vf_node->adapter;
	u16 i;
	u16 idx_in_pf;

	for (i = 0; i < SXE2_VF_VSI_ID_NR; i++) {
		idx_in_pf = (u16)(vf_node->vsi_id[i] -
				  adapter->vsi_ctxt.base_idx_in_dev);
		mutex_lock(&adapter->vsi_ctxt.lock);
		sxe2_vsi_put(&adapter->vsi_ctxt, idx_in_pf);
		mutex_unlock(&adapter->vsi_ctxt.lock);
	}
}

static void sxe2_vf_irq_map(struct sxe2_vf_node *vf)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_hw_vf_irq vf_irq;

	vf_irq.first_in_pf = vf->irq_base_idx;
	vf_irq.last_in_pf = (vf_irq.first_in_pf + vf->irq_cnt) - 1U;

	vf_irq.first_in_dev = vf_irq.first_in_pf + adapter->irq_ctxt.base_idx_in_dev;
	vf_irq.last_in_dev = (vf_irq.first_in_dev + vf->irq_cnt) - 1U;

	vf_irq.vfid_in_pf = vf->vf_idx;
	vf_irq.vfid_in_dev = vf->vf_idx + adapter->vf_ctxt.vfid_base;

	vf_irq.pf_id = adapter->pf_idx;

	LOG_INFO_BDF("pf_id:%u vfid_in_pf:%u vfid_in_dev:%u irq cnt:%u\t"
		     "first_in_pf:%u last_in_pf:%u first_in_dev:%u\t"
		     "last_in_dev:%u.\n",
		     vf_irq.pf_id, vf_irq.vfid_in_pf, vf_irq.vfid_in_dev,
		     vf->irq_cnt, vf_irq.first_in_pf, vf_irq.last_in_pf,
		     vf_irq.first_in_dev, vf_irq.last_in_dev);

	sxe2_hw_vf_irq_cfg(&adapter->hw, &vf_irq);
}

static void sxe2_vf_queue_map(struct sxe2_vf_node *vf)
{
	struct sxe2_hw_vf_queue vf_queue;
	struct sxe2_adapter *adapter = vf->adapter;

	vf_queue.rxq_cnt = vf->q_cnt;
	vf_queue.rxq_first_in_pf = vf->rxq_base;
	vf_queue.txq_cnt = vf->q_cnt;
	vf_queue.txq_first_in_pf = vf->txq_base;
	vf_queue.vfid_in_pf = vf->vf_idx;

	LOG_INFO_BDF("vf:%u rxq cnt:%u rxq_first_idx:%u txq cnt:%u\t"
		     "txq_first_in_pf:%u.\n",
		     vf->vf_idx, vf_queue.rxq_cnt, vf_queue.rxq_first_in_pf,
		     vf_queue.txq_cnt, vf_queue.txq_first_in_pf);

	sxe2_hw_vf_queue_cfg(&adapter->hw, &vf_queue);
}

static void sxe2_vf_res_map(struct sxe2_vf_node *vf_node)
{
	sxe2_vf_irq_map(vf_node);
	sxe2_vf_queue_map(vf_node);
}

static void sxe2_vf_irq_unmap(struct sxe2_vf_node *vf)
{
	struct sxe2_adapter *adapter = vf->adapter;
	struct sxe2_hw_vf_irq vf_irq;

	vf_irq.first_in_pf = vf->irq_base_idx;
	vf_irq.last_in_pf = (vf_irq.first_in_pf + vf->irq_cnt) - 1U;

	vf_irq.first_in_dev = vf_irq.first_in_pf + adapter->irq_ctxt.base_idx_in_dev;
	vf_irq.last_in_dev = (vf_irq.first_in_dev + vf->irq_cnt) - 1U;

	vf_irq.vfid_in_pf = vf->vf_idx;
	vf_irq.vfid_in_dev = vf->vf_idx + adapter->vf_ctxt.vfid_base;

	vf_irq.pf_id = adapter->pf_idx;
	sxe2_hw_vf_irq_decfg(&adapter->hw, &vf_irq);
}

static void sxe2_vf_queue_unmap(struct sxe2_vf_node *vf)
{
	struct sxe2_hw_vf_queue vf_queue;
	struct sxe2_adapter *adapter = vf->adapter;

	vf_queue.vfid_in_pf = vf->vf_idx;
	sxe2_hw_vf_queue_decfg(&adapter->hw, &vf_queue);
}

static void sxe2_vf_res_unmap(struct sxe2_vf_node *vf_node)
{
	sxe2_vf_irq_unmap(vf_node);
	sxe2_vf_queue_unmap(vf_node);
}

void sxe2_vfs_active(struct sxe2_adapter *adapter)
{
	struct sxe2_vf_node *vf_node;
	u16 vf_idx;

	sxe2_for_each_vf(adapter, vf_idx)
	{
		vf_node = SXE2_VF_NODE(adapter, vf_idx);

		clear_bit(SXE2_VF_STATE_DIS, vf_node->states);

		sxe2_hw_vf_active(&adapter->hw, vf_node->vf_idx);
	}
}

static void sxe2_vfs_hw_deactive(struct sxe2_adapter *adapter)
{
	struct sxe2_vf_node *vf_node;
	u16 vf_idx;

	sxe2_for_each_vf(adapter, vf_idx)
	{
		vf_node = SXE2_VF_NODE(adapter, vf_idx);
		sxe2_hw_vf_deactive(&adapter->hw, vf_node->vf_idx);
	}
}

static s32 __sxe2_vf_vsi_destroy_by_id(struct sxe2_vf_node *vf_node,
				       u16 vsi_id_in_dev)
{
	struct sxe2_adapter *adapter = vf_node->adapter;
	struct sxe2_vsi *vsi = NULL;
	enum sxe2_vsi_type type;
	s32 ret;

	lockdep_assert_held(&adapter->vsi_ctxt.lock);

	vsi = sxe2_vf_vsi_get(vf_node, vsi_id_in_dev);
	if (!vsi) {
		ret = -EINVAL;
		LOG_WARN_BDF("vsi id:%d vsi not create yet.\n", vsi_id_in_dev);
		goto l_out;
	}

	type = vsi->type;
	sxe2_vsi_destroy_unlock(vsi);

	if (type == SXE2_VSI_T_DPDK_VF)
		vf_node->dpdk_vf_vsi = NULL;
	else
		vf_node->vsi = NULL;

	if (vf_node->repr)
		vf_node->repr->src_vsi = NULL;

	LOG_INFO_BDF("vf:%d vsi_id:%d vsi destroyed.\n", vf_node->vf_idx, vsi_id_in_dev);

l_out:
	return ret;
}

void sxe2_vf_vsi_destroy_by_id(struct sxe2_vf_node *vf_node, u16 vsi_id_in_dev)
{
	struct sxe2_adapter *adapter = vf_node->adapter;

	mutex_lock(&adapter->vsi_ctxt.lock);
	(void)__sxe2_vf_vsi_destroy_by_id(vf_node, vsi_id_in_dev);
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

STATIC void sxe2_vf_vsi_destroy(struct sxe2_vf_node *vf_node)
{
	struct sxe2_vsi *vsi = NULL;
	struct sxe2_adapter *adapter = vf_node->adapter;
	u16 i;
	u16 vsi_id;
	enum sxe2_vsi_type type;

	for (i = 0; i < SXE2_VF_VSI_ID_NR; i++) {
		mutex_lock(&adapter->vsi_ctxt.lock);
		vsi = sxe2_vf_vsi_get(vf_node, vf_node->vsi_id[i]);
		if (!vsi) {
			vsi_id = vf_node->vsi_id[i];
			sxe2_vsi_fltr_remove(vf_node->adapter, vsi_id);
			mutex_unlock(&adapter->vsi_ctxt.lock);
			continue;
		}

		type = vsi->type;
		sxe2_vsi_destroy_unlock(vsi);

		if (type == SXE2_VSI_T_DPDK_VF)
			vf_node->dpdk_vf_vsi = NULL;
		else
			vf_node->vsi = NULL;

		mutex_unlock(&adapter->vsi_ctxt.lock);
	}
}

s32 sxe2_vf_queue_range_set(struct sxe2_adapter *adapter)
{
	struct sxe2_fwc_vf_queue_info *req;
	u32 req_size;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u16 vf_cnt = adapter->vf_ctxt.num_vfs;
	s32 ret;
	u16 i;
	struct sxe2_cmd_params cmd = {};

	req_size = (u32)struct_size(req, queue_info, vf_cnt);
	req = devm_kzalloc(dev, req_size, GFP_KERNEL);
	if (!req) {
		LOG_ERROR_BDF("sched node add: alloc failed\n");
		ret = -ENOMEM;
		goto l_end;
	}

	req->pf_id = adapter->pf_idx;
	req->vf_cnt = vf_cnt;
	for (i = 0; i < vf_cnt; i++) {
		struct sxe2_vf_node *vf_node = SXE2_VF_NODE(adapter, i);

		req->queue_info[i].rxq_base = vf_node->rxq_base;
		req->queue_info[i].rxq_cnt = vf_node->q_cnt;
		req->queue_info[i].txq_base = vf_node->txq_base;
		req->queue_info[i].txq_cnt = vf_node->q_cnt;
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_VSI_VF_QUEUE_SET, req, req_size,
				  NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("vf queue set msg failed %d\n", ret);
		ret = -EIO;
	}

	devm_kfree(dev, req);
l_end:
	return ret;
}

static s32 sxe2_vf_queue_range_clear(struct sxe2_adapter *adapter)
{
	struct sxe2_fwc_vf_queue_info req = {};
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	req.pf_id = adapter->pf_idx;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_VSI_VF_QUEUE_CLEAR, &req,
				  sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("vf cnt:%d queue clear msg failed %d\n",
			      adapter->vf_ctxt.num_vfs, ret);
		ret = -EIO;
	}

	return ret;
}

static void sxe2_vf_hw_res_deinit(struct sxe2_adapter *adapter, bool is_disable)
{
	struct sxe2_vf_node *vf_node;
	u16 vf_idx;

	sxe2_mbx_channel_disable(adapter);

	(void)sxe2_vf_queue_range_clear(adapter);

	sxe2_for_each_vf(adapter, vf_idx)
	{
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		vf_node = sxe2_vf_node_get(adapter, vf_idx);
		if (is_disable)
			(void)sxe2_rdma_aux_send_vf_reset_event(adapter,
								vf_node->vf_idx);

		sxe2_vf_res_unmap(vf_node);

		sxe2_vf_vsi_destroy(vf_node);

		sxe2_vf_vsi_id_free(vf_node);

		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	}
}

static s32 sxe2_vf_hw_res_init(struct sxe2_adapter *adapter, int num_vfs)
{
	struct sxe2_vf_node_e *vf_node_e;
	u16 vf_idx;
	s32 ret = 0;
	u16 cnt = 0;
	u16 vf_id_in_dev = 0;

	lockdep_assert_held(&adapter->vf_ctxt.vfs_lock);

	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		vf_id_in_dev = vf_idx + adapter->vf_ctxt.vfid_base;
		if (sxe2_hw_vflr_cause_get(&adapter->hw, vf_id_in_dev))
			sxe2_hw_vflr_cause_clear(&adapter->hw, vf_id_in_dev);
	}

	ret = sxe2_mbx_channel_enable(adapter);
	if (ret) {
		ret = -EIO;
		goto l_fail;
	}

	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		vf_node_e = SXE2_VF_NODE_E(adapter, vf_idx);
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));

		ret = sxe2_vf_vsi_id_alloc(vf_node_e->vf_node);
		if (ret) {
			ret = -EIO;
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
			goto l_fail;
		}

		cnt++;

		sxe2_vf_res_map(vf_node_e->vf_node);

		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	}

	ret = sxe2_vf_queue_range_set(adapter);
	if (ret) {
		LOG_ERROR_BDF("vf queue range set failed %d\n", ret);
		goto l_fail;
	}

	return ret;

l_fail:
	for (vf_idx = 0; vf_idx < cnt; vf_idx++) {
		vf_node_e = SXE2_VF_NODE_E(adapter, vf_idx);
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));

		sxe2_vf_res_unmap(vf_node_e->vf_node);
		sxe2_vf_vsi_id_free(vf_node_e->vf_node);
		vf_node_e->vf_node->vsi = NULL;

		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	}
	sxe2_mbx_channel_disable(adapter);
	return ret;
}

s32 sxe2_vf_base_l2_filter_setup(struct sxe2_vf_node *vf_node, struct sxe2_vsi *vsi)
{
	s32 ret = 0;

	ret = sxe2_vf_vlan_init(vf_node, vsi);
	if (ret)
		return ret;

	ret = sxe2_vf_mac_init(vf_node, vsi);
	return ret;
}

STATIC s32 sxe2_sriov_enable(struct sxe2_adapter *adapter, int num_vfs)
{
	s32 ret;

	mutex_lock(&adapter->vf_ctxt.vfs_lock);

	if (test_bit(SXE2_FLAG_SRIOV_VFS_DISABLED, adapter->flags)) {
		ret = -EBUSY;
		LOG_WARN_BDF("during pf reset, try later.\n");
		goto l_unlock;
	}

	ret = sxe2_vf_node_alloc(adapter, (u16)num_vfs);
	if (ret)
		goto l_unlock;

	ret = sxe2_vf_irqs_num_set(adapter, num_vfs);
	if (ret)
		goto l_node_free;

	ret = sxe2_vf_queues_num_set(adapter, num_vfs);
	if (ret)
		goto l_clear_num;

	ret = sxe2_vf_sw_res_init(adapter, (u32)num_vfs);
	if (ret)
		goto l_clear_num;

	ret = sxe2_vf_hw_res_init(adapter, num_vfs);
	if (ret)
		goto l_sw_res_deinit;

	if (sxe2_eswitch_is_offload(adapter)) {
		ret = sxe2_eswitch_configure(adapter, true);
		if (ret)
			goto l_hw_res_deinit;
	}

	sxe2_vfs_active(adapter);

	mutex_unlock(&adapter->vf_ctxt.vfs_lock);
	return ret;

l_hw_res_deinit:
	sxe2_vf_hw_res_deinit(adapter, false);

l_sw_res_deinit:
	sxe2_vf_sw_res_deinit(adapter);

l_clear_num:
	sxe2_vf_irq_queues_num_clear(adapter);

l_node_free:
	sxe2_vf_nodes_free(adapter, (u16)num_vfs);

l_unlock:
	mutex_unlock(&adapter->vf_ctxt.vfs_lock);
	return ret;
}

STATIC s32 sxe2_sriov_disable(struct sxe2_adapter *adapter, bool is_stopped)
{
	struct sxe2_vf_context *vf_ctxt = &adapter->vf_ctxt;
	struct sxe2_vf_node *vf_node;
	u16 idx;
	u16 vfs_cnt;
	s32 ret = 0;

	mutex_lock(&vf_ctxt->vfs_lock);

	if (!is_stopped && test_bit(SXE2_FLAG_SRIOV_VFS_DISABLED, adapter->flags)) {
		ret = -EBUSY;
		LOG_WARN_BDF("during pf reset, try later.\n");
		goto l_unlock;
	}

	sxe2_for_each_vf(adapter, idx)
	{
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, idx));
		vf_node = sxe2_vf_node_get(adapter, idx);
		sxe2_vf_stop(vf_node);
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
		LOG_INFO_BDF("vf:%u stopped.\n", idx);
	}

	sxe2_vfs_hw_deactive(adapter);

	(void)sxe2_eswitch_configure(adapter, false);

	sxe2_rss_vf_sw_cfg_clear(adapter);

	sxe2_fnav_vf_cfg_clear(adapter);

	sxe2_vf_hw_res_deinit(adapter, true);

	sxe2_txsched_vf_tree_clean(adapter);

	vfs_cnt = vf_ctxt->num_vfs;
	sxe2_vf_sw_res_deinit(adapter);
	sxe2_vf_nodes_free(adapter, vfs_cnt);

	sxe2_vf_irq_queues_num_clear(adapter);

l_unlock:
	mutex_unlock(&vf_ctxt->vfs_lock);

	return ret;
}

STATIC s32 sxe2_vfs_enable(struct sxe2_adapter *adapter, int num_vfs)
{
	s32 ret;

	if (sxe2_eswitch_mode_read_lock(adapter)) {
		LOG_DEV_ERR("sxe2 enable %u vfs failed when eswitch modifying.\n", num_vfs);
		ret = -EBUSY;
		goto l_timeout_check;
	}

	ret = sxe2_sriov_enable(adapter, num_vfs);
	if (ret) {
		LOG_DEV_ERR("sxe2 enable %u vfs failed.ret:%d\n", num_vfs, ret);
		goto l_timeout_check;
	}

	ret = pci_enable_sriov(adapter->pdev, num_vfs);
	if (ret) {
		LOG_DEV_ERR("enable %u sriov failed.ret:%d\n", num_vfs, ret);
		(void)sxe2_sriov_disable(adapter, true);
		goto l_timeout_check;
	}

	if (sxe2_eswitch_is_offload(adapter)) {
		(void)sxe2_com_irq_notifier_call_chain(&adapter->com_ctxt,
						       SXE2_COM_SW_MODE_SWITCHDEV);
	} else {
		(void)sxe2_com_irq_notifier_call_chain(&adapter->com_ctxt,
						       SXE2_COM_SW_MODE_LEGACY);
	}

l_timeout_check:
	sxe2_eswitch_mode_read_unlock(adapter);
	return ret;
}

s32 sxe2_vfs_disable(struct sxe2_adapter *adapter, bool is_stopped)
{
	s32 ret = 0;

	if (sxe2_eswitch_mode_read_lock(adapter)) {
		ret = -EBUSY;
		goto l_timeout_check;
	}

	pci_disable_sriov(adapter->pdev);
	(void)sxe2_sriov_disable(adapter, is_stopped);

	(void)sxe2_com_irq_notifier_call_chain(&adapter->com_ctxt,
					       SXE2_COM_SW_MODE_LEGACY);

l_timeout_check:
	sxe2_eswitch_mode_read_unlock(adapter);
	return ret;
}

int sxe2_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct sxe2_adapter *adapter = pci_get_drvdata(pdev);
	int ret;

	ret = sxe2_vf_perm_check(adapter, num_vfs);
	if (ret)
		goto l_err;

	if (!num_vfs) {
		ret = sxe2_vfs_disable(adapter, true);
	} else {
		sxe2_lag_exit_bond(adapter);

		ret = sxe2_vfs_enable(adapter, num_vfs);

		sxe2_lag_exit_bond_done(adapter);
	}

	LOG_INFO_BDF("%s %d vfs done.(ret:%d).\n", num_vfs ? "create" : "remove",
		     num_vfs, ret);
	if (ret)
		goto l_err;

	return num_vfs;

l_err:
	return ret;
}

void sxe2_vf_init(struct sxe2_adapter *adapter)
{
	u16 i;

	mutex_init(&adapter->vf_ctxt.vfs_lock);

	for (i = 0; i < SXE2_VF_NUM; i++) {
		u8 v;

		mutex_init(&adapter->vf_ctxt.vf_node_e[i].vf_lock);
		for (v = 0; v < SXE2_PRODUCT_ID_NR; v++) {
			adapter->vf_ctxt.large_q.usr_cfg[i].product[v].lut_id =
				SXE2_VF_GLOBAL_LUT_INVALID_ID;
			adapter->vf_ctxt.large_q.usr_cfg[i].product[v].lut_type =
				SXE2_RSS_VSI_LUT;
			adapter->vf_ctxt.large_q.usr_cfg[i].product[v].lut_size =
				SXE2_RSS_LUT_SIZE_64;
		}
	}
}

void sxe2_vf_deinit(struct sxe2_adapter *adapter)
{
	u16 i;

	for (i = 0; i < SXE2_VF_NUM; i++)
		mutex_destroy(&adapter->vf_ctxt.vf_node_e[i].vf_lock);

	mutex_destroy(&adapter->vf_ctxt.vfs_lock);
}

static s32 sxe2_vf_port_vlan_check(struct sxe2_adapter *adapter, u16 vlan_id, u8 qos,
				   __be16 vlan_proto)
{
	if (vlan_id >= VLAN_N_VID || qos > SXE2_VLAN_QOS_MAX) {
		LOG_DEV_ERR("vlan id:%d QoS %d invalid\n", vlan_id, qos);
		return -EINVAL;
	}

	if (vlan_proto != ETH_P_8021Q && vlan_proto != ETH_P_8021AD) {
		LOG_DEV_ERR("vlan_proto:0x%x invalid\n", vlan_proto);
		return -EPROTONOSUPPORT;
	}

	return 0;
}

int sxe2_set_vf_port_vlan_inner(struct sxe2_adapter *adapter, int vf_idx,
				u16 vlan_id, u8 qos, u16 protocol,
				bool need_vf_reset)
{
	s32 ret;
	struct sxe2_vlan vlan;
	struct sxe2_vf_node *vf;

	ret = sxe2_vf_port_vlan_check(adapter, vlan_id, qos, protocol);
	if (ret)
		return ret;

	if (sxe2_eswitch_is_offload(adapter)) {
		LOG_DEV_ERR("vf vlan cannot be configured - switchdev is enabled\n");
		return -EOPNOTSUPP;
	}

	if (sxe2_vf_id_check(adapter, (u16)vf_idx)) {
		LOG_ERROR_BDF("invalid vf_id:%u.\n", vf_idx);
		return -EINVAL;
	}

	vlan = SXE2_VLAN(protocol, vlan_id, qos);
	mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	vf = sxe2_vf_node_get(adapter, (u16)vf_idx);
	if (!vf) {
		ret = -EINVAL;
		goto l_unlock;
	}

	if (!memcmp(&vf->vlan_info.port_vlan, &vlan, sizeof(vlan))) {
		LOG_INFO_BDF("vf:%u port vlan vlan_id:%u qos:%u protocol:0x%x existed.\n",
			     vf_idx, vlan_id, qos, protocol);
		goto l_unlock;
	}

	ret = sxe2_check_vf_ready_for_cfg(vf);
	if (ret) {
		LOG_ERROR_BDF("vf:%u pf flags:0x%lx vf states:0x%lx not ready.\n",
			      vf_idx, *adapter->flags, *vf->states);
		goto l_unlock;
	}

	memcpy(&vf->vlan_info.port_vlan, &vlan, sizeof(vlan));
	if (sxe2_port_vlan_is_exist(vf)) {
		vf->vlan_info.port_vlan_exsit = true;
		LOG_INFO_BDF("vf:%u port vlan vlan_id:%u qos:%u protocol:0x%x add.\n",
			     vf_idx, vlan_id, qos, protocol);
	} else {
		vf->vlan_info.port_vlan_exsit = false;
		LOG_INFO_BDF("vf:%u port vlan delete.\n", vf_idx);
	}

	if (need_vf_reset) {
		ret = sxe2_reset_vf(adapter, (u16)vf_idx, SXE2_VF_RESET_FLAG_NOTIFY);
		if (ret)
			LOG_ERROR_BDF("vf:%u set port vlan:0x%x failed.(err:%d)\n",
				      vf_idx, *(u32 *)&vlan, ret);
	}

l_unlock:
	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	return ret;
}

int sxe2_set_vf_port_vlan(struct net_device *netdev, int vf_idx, u16 vlan_id, u8 qos,
			  __be16 protocol)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	return sxe2_set_vf_port_vlan_inner(adapter, vf_idx, vlan_id, qos,
					   be16_to_cpu(protocol), true);
}

struct sxe2_vsi *sxe2_vf_vsi_get(struct sxe2_vf_node *vf_node, u16 vsi_id_in_dev)
{
	struct sxe2_vsi *vsi = NULL;
	struct sxe2_adapter *adapter = vf_node->adapter;

	lockdep_assert_held(SXE2_VF_NODE_LOCK(vf_node->adapter,
					      (u16)vf_node->vf_idx));

	if (vsi_id_in_dev == vf_node->vsi_id[SXE2_VF_VSI_ID_MASTER]) {
		vsi = (vf_node->vf_run_mode == SXE2_COM_MODULE_DPDK) ? vf_node->dpdk_vf_vsi :
									   vf_node->vsi;
	} else if (vsi_id_in_dev == vf_node->vsi_id[SXE2_VF_VSI_ID_SLAVE]) {
		vsi = (vf_node->vf_run_mode == SXE2_COM_MODULE_DPDK) ? NULL :
									   vf_node->dpdk_vf_vsi;
	} else {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", vsi_id_in_dev);
		goto l_out;
	}

	LOG_INFO_BDF("vf:%d vsi id:%d drv_run_mode:%u vsi:%p.\n",
		     vf_node->vf_idx, vsi_id_in_dev,
				 vf_node->vf_run_mode,
				 vsi);
l_out:
	return vsi;
}

s32 sxe2_vf_vsi_type_get(struct sxe2_vf_node *vf_node, u16 vsi_id_in_dev,
			 enum sxe2_vsi_type *type)
{
	struct sxe2_adapter *adapter = vf_node->adapter;
	s32 ret = 0;

	lockdep_assert_held(SXE2_VF_NODE_LOCK(vf_node->adapter,
					      (u16)vf_node->vf_idx));

	if (vsi_id_in_dev == vf_node->vsi_id[SXE2_VF_VSI_ID_MASTER]) {
		*type = (vf_node->vf_run_mode == SXE2_COM_MODULE_DPDK) ? SXE2_VSI_T_DPDK_VF :
										 SXE2_VSI_T_VF;
	} else if (vsi_id_in_dev == vf_node->vsi_id[SXE2_VF_VSI_ID_SLAVE]) {
		*type = SXE2_VSI_T_DPDK_VF;
	} else {
		ret = -EINVAL;
		LOG_ERROR_BDF("invalid vsi id:%d ret:%d.\n", vsi_id_in_dev, ret);
		goto l_out;
	}

	LOG_INFO_BDF("vf:%d vsi id:%d drv_run_mode:%u vsi type:%u.\n",
		     vf_node->vf_idx, vsi_id_in_dev,
				 vf_node->vf_run_mode,
				 *type);
l_out:
	return ret;
}

u16 sxe2_kernel_vf_vsi_id_get(struct sxe2_vf_node *vf_node)
{
	struct sxe2_adapter *adapter = vf_node->adapter;
	u16 vsi_id = SXE2_VSI_ID_INVALID;

	lockdep_assert_held(SXE2_VF_NODE_LOCK(vf_node->adapter,
					      (u16)vf_node->vf_idx));

	if (vf_node->vf_run_mode == SXE2_COM_MODULE_KERNEL ||
	    vf_node->vf_run_mode == SXE2_COM_MODULE_MIXED)
		vsi_id = vf_node->vsi_id[SXE2_VF_VSI_ID_MASTER];

	LOG_INFO_BDF("vf:%d drv_run_mode:%u kernel vf vsi_id:%u.\n",
		     vf_node->vf_idx, vf_node->vf_run_mode,
				 vsi_id);
	return vsi_id;
}

u16 sxe2_user_vf_vsi_id_get(struct sxe2_vf_node *vf_node)
{
	struct sxe2_adapter *adapter = vf_node->adapter;
	u16 vsi_id = SXE2_VSI_ID_INVALID;

	lockdep_assert_held(SXE2_VF_NODE_LOCK(vf_node->adapter,
					      (u16)vf_node->vf_idx));

	if (vf_node->vf_run_mode == SXE2_COM_MODULE_DPDK)
		vsi_id = vf_node->vsi_id[SXE2_VF_VSI_ID_MASTER];
	else if (vf_node->vf_run_mode == SXE2_COM_MODULE_KERNEL ||
		 vf_node->vf_run_mode == SXE2_COM_MODULE_MIXED)
		vsi_id = vf_node->vsi_id[SXE2_VF_VSI_ID_SLAVE];

	LOG_INFO_BDF("vf:%d drv_run_mode:%u user vf vsi_id:%u.\n",
		     vf_node->vf_idx, vf_node->vf_run_mode,
				 vsi_id);
	return vsi_id;
}

void sxe2_vf_queues_stop(struct sxe2_vf_node *vf_node)
{
	struct sxe2_vsi *vsi;
	struct sxe2_adapter *adapter = vf_node->adapter;
	u16 i;

	for (i = 0; i < SXE2_VF_VSI_ID_NR; i++) {
		vsi = sxe2_vf_vsi_get(vf_node, vf_node->vsi_id[i]);
		if (!vsi)
			continue;

		LOG_INFO_BDF("vsi:%u txqs disable start.\n", vsi->idx_in_dev);
		if (sxe2_txqs_stop(vsi))
			LOG_DEV_ERR("vsi:%u txqs disable failed.\n",
				    vsi->idx_in_dev);

		if (sxe2_rxqs_stop(vsi))
			LOG_DEV_ERR("vsi:%u rxqs disable failed.\n",
				    vsi->idx_in_dev);
	}
}

void sxe2_vf_adv_cfg_clear(struct sxe2_vf_node *vf_node, bool is_vfr_vflr)
{
	struct sxe2_adapter *adapter = vf_node->adapter;
	u16 vsi_id_in_dev;

	vsi_id_in_dev = sxe2_kernel_vf_vsi_id_get(vf_node);

	if (!is_vfr_vflr) {
		LOG_INFO_BDF("vsi %u pfr/pflr skip.\n", vsi_id_in_dev);
		return;
	}

	if (!test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags))
		sxe2_vsi_l2_fltr_remove(adapter, vsi_id_in_dev);
}

void sxe2_vf_trust_cfg_restore(struct sxe2_vf_node *vf_node)
{
	assign_bit(SXE2_VF_CAP_TRUSTED, vf_node->caps, vf_node->prop.trusted);
}

STATIC s32 sxe2_vf_mac_cfg_restore(struct sxe2_vf_node *vf_node)
{
	s32 ret = 0;
	u8 broadcast[ETH_ALEN];

	if (sxe2_eswitch_is_offload(vf_node->adapter)) {
		LOG_INFO("switchdev mode no need restore vf mac.\n");
		return ret;
	}
	if (!vf_node->vsi) {
		LOG_ERROR("vsi is null, vsi id:%d.\n",
			  sxe2_kernel_vf_vsi_id_get(vf_node));
		ret = -EINVAL;
		return ret;
	}

	eth_broadcast_addr(broadcast);
	ret = sxe2_mac_rule_add(vf_node->vsi, broadcast);
	if (ret) {
		LOG_ERROR("vf:%u broadcast mac addr add failed.(err:%d).\n",
			  vf_node->vf_idx, ret);
		return ret;
	}

	sxe2_vf_mac_cnt_inc(vf_node, vf_node->vsi);

	if (!is_zero_ether_addr(vf_node->mac_addr.addr)) {
		ret = sxe2_mac_rule_add(vf_node->vsi, vf_node->mac_addr.addr);
		if (ret) {
			LOG_ERROR("Failed to add MAC %pM for VF %d\n, error %d\n",
				  vf_node->mac_addr.addr, vf_node->vf_idx, ret);
			return ret;
		}
		ret = sxe2_mac_spoofchk_ext_rule_add(vf_node->adapter,
						     vf_node->vsi->idx_in_dev,
						     vf_node->mac_addr.addr);
		if (ret) {
			LOG_ERROR("Failed to add mac spoof ext rule %pM\t"
				  "for VF %d vsi %u\n, error %d\n",
				  vf_node->mac_addr.addr, vf_node->vsi->idx_in_dev,
				  vf_node->vf_idx, ret);
			(void)sxe2_mac_rule_del(vf_node->adapter,
						vf_node->vsi->idx_in_dev,
						vf_node->mac_addr.addr);
			return ret;
		}

		sxe2_vf_mac_cnt_inc(vf_node, vf_node->vsi);
	}

	return ret;
}

STATIC s32 sxe2_vf_port_vlan_recfg(struct sxe2_hw *hw, struct sxe2_vf_node *vf_node,
				   u16 vlan_info, u16 tpid)
{
	s32 ret = 0;

	if (!vf_node->vsi) {
		LOG_ERROR("vsi is null, vsi id:%d.\n",
			  sxe2_kernel_vf_vsi_id_get(vf_node));
		ret = -EINVAL;
		return ret;
	}

	(void)sxe2_hw_port_vlan_setup(hw, vf_node->vsi->idx_in_dev, vlan_info, tpid);
	return 0;
}

STATIC s32 sxe2_vf_vlan_cfg_restore(struct sxe2_vf_node *vf_node)
{
	s32 ret;
	struct sxe2_adapter *adapter = vf_node->adapter;
	struct sxe2_vlan *port_vlan;
	u16 vlan_info;
	struct sxe2_hw *hw = &adapter->hw;

	if (sxe2_eswitch_is_offload(vf_node->adapter)) {
		LOG_INFO("switchdev mode no need restore vf mac.\n");
		return 0;
	}

	if (!vf_node->vsi) {
		LOG_ERROR("vsi is null, vsi id:%d.\n",
			  sxe2_kernel_vf_vsi_id_get(vf_node));
		ret = -EINVAL;
		return ret;
	}

	if (sxe2_port_vlan_is_exist(vf_node)) {
		port_vlan = &vf_node->vlan_info.port_vlan;
		vlan_info = (u16)(port_vlan->prio << VLAN_PRIO_SHIFT) |
			    port_vlan->vid;
		ret = sxe2_vf_port_vlan_recfg(hw, vf_node, vlan_info,
					      port_vlan->tpid);
		if (ret) {
			LOG_ERROR_BDF("port vlan set failed, vsi[%u] tpid[0x%x],\t"
				      "vid[%d], prio[%d].\n",
				      vf_node->vsi->idx_in_dev, port_vlan->tpid,
				      port_vlan->vid, port_vlan->prio);
			goto l_err;
		}

		ret = sxe2_vlan_rule_add(vf_node->vsi, port_vlan);
		if (ret && ret != -EEXIST)
			goto l_rule_add_fail;

		ret = sxe2_vlan_filter_control(adapter, vf_node->vsi->idx_in_dev,
					       true);
		if (ret)
			goto l_vlan_filter_fail;

	} else {
		ret = sxe2_vsi_vlan_zero_add(vf_node->vsi);
		if (ret)
			goto l_err;
	}

	return 0;

l_vlan_filter_fail:
	(void)sxe2_vlan_rule_del(adapter, vf_node->vsi->idx_in_dev, port_vlan);
l_rule_add_fail:
	(void)sxe2_vf_port_vlan_recfg(hw, vf_node, 0, port_vlan->tpid);

l_err:
	return ret;
}

s32 sxe2_vf_vsi_port_vlan_cfg(struct sxe2_vf_node *vf_node, struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vf_node->adapter;
	struct sxe2_vlan *port_vlan;
	u16 vlan_info;
	struct sxe2_hw *hw = &adapter->hw;

	if (sxe2_eswitch_is_offload(vf_node->adapter)) {
		LOG_INFO("switchdev mode no need restore vf mac.\n");
		return 0;
	}

	port_vlan = &vf_node->vlan_info.port_vlan;
	vlan_info = (u16)(port_vlan->prio << VLAN_PRIO_SHIFT) | port_vlan->vid;

	(void)sxe2_hw_port_vlan_setup(hw, vsi->idx_in_dev, vlan_info,
				      port_vlan->tpid);

	ret = sxe2_vlan_rule_add(vsi, port_vlan);
	if (ret && ret != -EEXIST)
		goto l_rule_add_fail;

	ret = sxe2_vlan_filter_control(adapter, vsi->idx_in_dev, true);
	if (ret)
		goto l_vlan_filter_fail;

	return 0;

l_vlan_filter_fail:
	(void)sxe2_vlan_rule_del(adapter, vsi->idx_in_dev, port_vlan);
l_rule_add_fail:
	(void)sxe2_hw_port_vlan_setup(hw, vsi->idx_in_dev, 0, port_vlan->tpid);

	return ret;
}

s32 sxe2_vf_rate_cfg_restore(struct sxe2_vf_node *vf_node)
{
	s32 ret = 0;

	if (vf_node->prop.min_tx_rate) {
		ret = sxe2_txsched_vf_bw_lmt_cfg(vf_node->adapter, vf_node,
						 SXE2_NODE_RL_TYPE_CIR,
						 vf_node->prop.min_tx_rate * 1000);
		if (ret) {
			LOG_ERROR("vf:%u min rate:%u vsi:%u restore\t"
				  "failed.(err:%d)\n",
				  vf_node->vf_idx, vf_node->prop.min_tx_rate,
				  vf_node->vsi->idx_in_dev, ret);
		}
	}
	if (vf_node->prop.max_tx_rate) {
		ret = sxe2_txsched_vf_bw_lmt_cfg(vf_node->adapter, vf_node,
						 SXE2_NODE_RL_TYPE_EIR,
						 vf_node->prop.max_tx_rate * 1000);
		if (ret) {
			LOG_ERROR("vf:%u max rate:%u vsi:%u restore\t"
				  "failed.(err:%d)\n",
				  vf_node->vf_idx, vf_node->prop.max_tx_rate,
				  vf_node->vsi->idx_in_dev, ret);
		}
	}

	return ret;
}

STATIC s32 sxe2_vf_spoofchk_cfg_restore(struct sxe2_vf_node *vf_node)
{
	s32 ret;
	struct sxe2_adapter *adapter = vf_node->adapter;

	if (sxe2_eswitch_is_offload(adapter)) {
		LOG_DEBUG_BDF("switchdev mode no need restore spoofchk.\n");
		return 0;
	}

	if (!vf_node->vsi) {
		LOG_ERROR("vsi is null, vsi id:%d.\n",
			  sxe2_kernel_vf_vsi_id_get(vf_node));
		ret = -EINVAL;
		return ret;
	}

	ret = sxe2_vsi_spoofchk_control(vf_node->adapter, vf_node->vsi->idx_in_dev,
					vf_node->prop.spoofchk);
	if (ret) {
		LOG_DEV_ERR("vf:%u spoofchk:%u vsi:%u restore failed.(err:%d)\n",
			    vf_node->vf_idx, vf_node->prop.spoofchk,
			    vf_node->vsi->idx_in_dev, ret);
	}

	return ret;
}

STATIC s32 sxe2_vf_default_etype_cfg_restore(struct sxe2_vf_node *vf_node)
{
	s32 ret;
	struct sxe2_adapter *adapter = vf_node->adapter;

	if (sxe2_eswitch_is_offload(adapter)) {
		LOG_DEBUG_BDF("switchdev mode no need restore etype rule.\n");
		return 0;
	}

	if (!vf_node->vsi) {
		LOG_ERROR("vsi is null, vsi id:%d.\n",
			  sxe2_kernel_vf_vsi_id_get(vf_node));
		ret = -EINVAL;
		return ret;
	}

	ret = sxe2_etype_fltr_init(vf_node->vsi);
	if (ret) {
		LOG_DEV_ERR("vf:%u vsi:%u default_etype restore failed.(err:%d)\n",
			    vf_node->vf_idx, vf_node->vsi->idx_in_dev, ret);
	}

	return ret;
}

STATIC s32 sxe2_vf_src_prune_cfg_restore(struct sxe2_vf_node *vf_node)
{
	s32 ret;
	struct sxe2_adapter *adapter = vf_node->adapter;

	if (sxe2_eswitch_is_offload(adapter)) {
		LOG_DEBUG_BDF("switchdev mode no need restore etype rule.\n");
		return 0;
	}

	if (!vf_node->vsi) {
		LOG_ERROR("vsi is null, vsi id:%d.\n",
			  sxe2_kernel_vf_vsi_id_get(vf_node));
		ret = -EINVAL;
		return ret;
	}

	ret = sxe2_src_vsi_prune_control(adapter, vf_node->vsi->idx_in_dev, true);
	if (ret) {
		LOG_DEV_ERR("vf:%u vsi:%u src prune restore failed,\n"
			    "inverse action cfg error.(err:%d)\n",
			    vf_node->vf_idx, vf_node->vsi->idx_in_dev, ret);
		return ret;
	}

	ret = sxe2_srcvsi_rule_add(vf_node->vsi);
	if (ret) {
		LOG_DEV_ERR("vf:%u vsi:%u src prune restore failed.(err:%d)\n",
			    vf_node->vf_idx, vf_node->vsi->idx_in_dev, ret);
		return ret;
	}

	return ret;
}

STATIC void sxe2_vf_cfg_restore(struct sxe2_vf_node *vf_node)
{
	struct sxe2_adapter *adapter = vf_node->adapter;

	sxe2_vf_trust_cfg_restore(vf_node);

	if (sxe2_mac_spoofchk_rule_add(adapter, sxe2_kernel_vf_vsi_id_get(vf_node)))
		LOG_DEV_ERR("vf:%u vsi:%u mac spoofchk rule restore failed.\n",
			    vf_node->vf_idx, sxe2_kernel_vf_vsi_id_get(vf_node));

	if (sxe2_vf_mac_cfg_restore(vf_node))
		LOG_DEV_ERR("vf:%u mac configure restore failed.\n",
			    vf_node->vf_idx);

	if (sxe2_vf_vlan_cfg_restore(vf_node))
		LOG_DEV_ERR("vf:%u vlan configure restore failed.\n",
			    vf_node->vf_idx);

	if (sxe2_vf_rate_cfg_restore(vf_node))
		LOG_DEV_ERR("vf:%u rate configure restore failed.\n",
			    vf_node->vf_idx);

	if (sxe2_vf_spoofchk_cfg_restore(vf_node))
		LOG_DEV_ERR("vf:%u spoofchk configure restore failed.\n",
			    vf_node->vf_idx);

	if (sxe2_vf_default_etype_cfg_restore(vf_node))
		LOG_DEV_ERR("vf:%u default etype configure restore failed.\n",
			    vf_node->vf_idx);

	if (sxe2_vf_src_prune_cfg_restore(vf_node))
		LOG_DEV_ERR("vf:%u src prune configure restore failed.\n",
			    vf_node->vf_idx);
}

s32 sxe2_sriov_vsi_rebuild(struct sxe2_vsi *vsi, bool is_vfr_vflr)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	bool init = true;
	struct sxe2_hw *hw = &vsi->adapter->hw;

	mutex_lock(&adapter->vsi_ctxt.lock);

	if (is_vfr_vflr)
		init = false;

	ret = sxe2_vsi_rebuild(vsi, init);
	if (ret) {
		mutex_unlock(&adapter->vsi_ctxt.lock);
		LOG_ERROR_BDF("vsi[%u][%u] init:%u rebuild failed.(err:%d.)\n",
			      vsi->id_in_pf, init, vsi->idx_in_dev, ret);
		return ret;
	}

	if (vsi->type == SXE2_VSI_T_VF)
		sxe2_hw_l2tag_accept(hw, vsi->idx_in_dev);

	LOG_INFO_BDF("vsi[%u][%u] rebuild done.(err:%d.)\n", vsi->id_in_pf,
		     vsi->idx_in_dev, ret);

	clear_bit(SXE2_VSI_S_DISABLE, vsi->state);

	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_vf_rebuild(struct sxe2_vf_node *vf_node, bool is_vfr_vflr)
{
	s32 ret;
	struct sxe2_adapter *adapter = vf_node->adapter;

	ret = sxe2_sriov_vsi_rebuild(vf_node->vsi, is_vfr_vflr);
	if (ret) {
		LOG_ERROR_BDF("vf_idx:%u vsi rebuild failed.(err:%d)\n",
			      vf_node->vf_idx, ret);
		return ret;
	}

	sxe2_vf_cfg_restore(vf_node);

	memset(&vf_node->vlan_info.vlan_offload, 0,
	       sizeof(vf_node->vlan_info.vlan_offload));

	return ret;
}

u32 sxe_calc_all_vfs_min_tx_rate(struct sxe2_adapter *adapter)
{
	u16 idx;
	u16 vf_id_in_dev;
	u32 rate = 0;
	struct sxe2_vf_node *vf_node;

	sxe2_for_each_vf(adapter, idx)
	{
		vf_id_in_dev = idx + adapter->vf_ctxt.vfid_base;
		LOG_INFO_BDF("vf:%u vf_id_in_dev:%u get min rate.\n", idx,
			     vf_id_in_dev);

		mutex_lock(SXE2_VF_NODE_LOCK(adapter, idx));
		vf_node = sxe2_vf_node_get(adapter, idx);
		if (!vf_node) {
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
			continue;
		}

		if (sxe2_check_vf_ready_for_cfg(vf_node)) {
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
			continue;
		}

		rate += vf_node->prop.min_tx_rate;
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
	}

	return rate;
}

bool sxe2_min_tx_rate_oversubscribed(struct sxe2_adapter *adapter, s32 vf_idx,
				     int min_tx_rate)
{
	u32 all_vfs_min_tx_rate;
	u32 link_speed_mbps;
	u32 new_all_vfs_min_tx_rate;
	struct sxe2_vf_node *vf_node;

#if defined(SXE2_HARDWARE_ASIC)
	link_speed_mbps = adapter->link_ctxt.current_link_speed;
#else
	link_speed_mbps = SXE2_LINK_SPEED_10G;
#endif
	all_vfs_min_tx_rate = sxe_calc_all_vfs_min_tx_rate(adapter);

	mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	vf_node = sxe2_vf_node_get(adapter, (u16)vf_idx);
	if (!vf_node) {
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		return false;
	}

	new_all_vfs_min_tx_rate = all_vfs_min_tx_rate - vf_node->prop.min_tx_rate +
				  min_tx_rate;
	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));

	if (new_all_vfs_min_tx_rate > link_speed_mbps) {
		if (all_vfs_min_tx_rate > link_speed_mbps) {
			LOG_INFO_BDF("The sum of min_tx_rate for all VF's\n"
				     "is greater than the link speed\n");
			LOG_INFO_BDF("Set the min_tx_rate to 0 on the VF(s)\n"
				     "to resolve oversubscription\n");
		}

		LOG_ERROR_BDF("min_tx_rate of %d Mbps on VF %u\n"
			      "would cause oversubscription of %d Mbps\n"
			      "based on the current link speed %d Mbps\n",
			      min_tx_rate, vf_idx,
			      all_vfs_min_tx_rate + min_tx_rate - link_speed_mbps,
			      link_speed_mbps);

		return true;
	}

	return false;
}

u16 sxe2_vf_num_get(struct sxe2_adapter *adapter)
{
	return adapter->vf_ctxt.num_vfs;
}

void sxe2_ipsec_vf_sa_clear(struct sxe2_adapter *adapter, u32 vf_id)
{
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	u32 i;

	mutex_lock(&adapter->ipsec_ctxt.context_lock);

	for (i = 0; i < ipsec->max_rx_sa_cnt; i++) {
		if (!ipsec->rx_sa_table[i].used)
			continue;

		if (ipsec->rx_sa_table[i].is_vf &&
		    ipsec->rx_sa_table[i].vf_id == vf_id) {
			hash_del_rcu(&ipsec->rx_sa_table[i].hlist);
			sxe2_ipsec_rx_state_free(adapter, &ipsec->rx_sa_table[i]);
		}
	}

	for (i = 0; i < ipsec->max_tx_sa_cnt; i++) {
		if (!ipsec->tx_sa_table[i].used)
			continue;

		if (ipsec->tx_sa_table[i].is_vf &&
		    ipsec->tx_sa_table[i].vf_id == vf_id)
			sxe2_ipsec_tx_state_free(adapter, &ipsec->tx_sa_table[i]);
	}

	mutex_unlock(&adapter->ipsec_ctxt.context_lock);
}

void sxe2_vf_dpdk_cfg_clear(struct sxe2_vf_node *vf_node, bool is_vfr_vflr)
{
	struct sxe2_vsi *vsi;
	struct sxe2_vsi *eth_vsi;
	struct sxe2_adapter *adapter = vf_node->adapter;
	struct sxe2_obj obj;
	u16 vf_id_in_dev = 0;

	vsi = vf_node->dpdk_vf_vsi;
	eth_vsi = vf_node->vsi;
	if (!vsi) {
		LOG_WARN_BDF("vf:%d no dpdk.\n", vf_node->vf_idx);
		return;
	}

	if (is_vfr_vflr && vsi->txsched.node) {
		(void)sxe2_txsch_ucmd_subtree_del(adapter, vsi->idx_in_dev,
						  vsi->txsched.node->info.node_teid,
						  true);
	}

	if (eth_vsi)
		(void)sxe2_vf_vsi_mac_spoof_unsync(adapter, vsi, eth_vsi);

	sxe2_vf_mac_cnt_clr(vf_node, vsi);
	sxe2_vf_vlan_cnt_clr(vf_node, vsi);

	sxe2_vf_vsi_destroy_by_id(vf_node, vsi->idx_in_dev);

	vf_id_in_dev = vf_node->vf_idx + adapter->vf_ctxt.vfid_base;
	obj.vf_id = vf_id_in_dev;
	obj.valid = 1;
	obj.func_type = SXE2_VF;
	obj.drv_type = SXE2_DPDK_DRV;
	obj.drv_id = 0;
	(void)sxe2_dpdk_ipsec_resource_release(adapter, &obj);
}

STATIC s32 sxe2_vf_eth_cfg_clear(struct sxe2_vf_node *vf_node, bool is_vfr_vflr)
{
	struct sxe2_adapter *adapter = vf_node->adapter;
	s32 ret = 0;

	sxe2_vf_mac_cnt_clr(vf_node, vf_node->vsi);
	sxe2_vf_vlan_cnt_clr(vf_node, vf_node->vsi);

	sxe2_vf_res_map(vf_node);

	if (!vf_node->vsi) {
		LOG_WARN_BDF("vf:%d eth vsi not cfg yet.\n", vf_node->vf_idx);
		return 0;
	}

	(void)sxe2_acl_del_filter_by_vsi(vf_node->vsi);

	sxe2_vf_adv_cfg_clear(vf_node, is_vfr_vflr);

	sxe2_ipsec_vf_sa_clear(adapter, vf_node->vf_idx);

	if (vf_node->vf_ver.minor > SXE2_PF_VF_VERSION_MINOR_V1) {
		sxe2_vf_vsi_destroy_by_id(vf_node, vf_node->vsi->idx_in_dev);
		LOG_WARN_BDF("vf:%u version:%d.%d no need rebuild vsi.\n",
			     vf_node->vf_idx, vf_node->vf_ver.major, vf_node->vf_ver.minor);
		goto l_end;
	}

	sxe2_fnav_clean_by_vsi(vf_node->vsi, is_vfr_vflr);
	if (is_vfr_vflr)
		sxe2_rss_vsi_flow_clean_for_vf(vf_node->vsi);

	ret = sxe2_vf_rebuild(vf_node, is_vfr_vflr);
	if (ret) {
		LOG_ERROR_BDF("vf:%u vsi rebuild failed during reset.\n",
			      vf_node->vf_idx);
		goto l_end;
	}

	sxe2_vf_repr_rebuild(vf_node->vsi, is_vfr_vflr);

l_end:
	return ret;
}

s32 sxe2_vf_cfg_clear(struct sxe2_vf_node *vf_node, bool is_vfr_vflr)
{
	if (!test_bit(SXE2_VF_STATE_DIS, vf_node->states))
		return 0;

	sxe2_vf_dpdk_cfg_clear(vf_node, is_vfr_vflr);

	return  sxe2_vf_eth_cfg_clear(vf_node, is_vfr_vflr);
}

s32 sxe2_vf_reset_notify(struct sxe2_adapter *adapter, struct sxe2_vf_node *vf_node)
{
	struct sxe2_cmd_params params = {};

	if (!test_bit(SXE2_VF_STATE_ACTIVE, vf_node->states)) {
		LOG_INFO_BDF("vf:%u not activated, no send vf reset notify.\n",
			     vf_node->vf_idx);
		return 0;
	}

	sxe2_mbx_msg_params_fill(&params, SXE2_VF_RESET_NOTIFY, NULL, 0,
				 vf_node->vf_idx, true);
	return sxe2_mbx_msg_send(adapter, &params);
}

void sxe2_vfs_vsi_id_get(struct sxe2_adapter *adapter,
			 struct sxe2_drv_vsi_caps *repr_vf_id)
{
	struct sxe2_vf_node *vf_node;
	u16 num_vfs;
	u16 vf_idx = 0;

	num_vfs = sxe2_vf_num_get(adapter);
	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		vf_node = sxe2_vf_node_get(adapter, vf_idx);

		repr_vf_id[vf_idx].kernel_vsi_id = vf_node->vsi_id[SXE2_VF_VSI_ID_MASTER];
		repr_vf_id[vf_idx].dpdk_vsi_id = vf_node->vsi_id[SXE2_VF_VSI_ID_SLAVE];

		repr_vf_id[vf_idx].vsi_type = SXE2_VSI_T_VF;
		repr_vf_id[vf_idx].func_id = vf_idx;
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	}
}

s32 sxe2_vf_sw_vsi_id_get(struct sxe2_vf_node *vf_node,
			  enum sxe2_vsi_type type, u16 *sw_vsi_id)
{
	struct sxe2_adapter *adapter = vf_node->adapter;
	s32 ret = 0;
	u16 base = adapter->vsi_ctxt.base_idx_in_dev;
	u16 vsi_id = SXE2_VSI_ID_INVALID;

	lockdep_assert_held(SXE2_VF_NODE_LOCK(vf_node->adapter, (u16)vf_node->vf_idx));

	if (type == SXE2_VSI_T_VF)
		vsi_id = sxe2_kernel_vf_vsi_id_get(vf_node);
	else if (type == SXE2_VSI_T_DPDK_VF)
		vsi_id = sxe2_user_vf_vsi_id_get(vf_node);

	if (vsi_id == SXE2_VSI_ID_INVALID) {
		ret = -EINVAL;
		LOG_ERROR_BDF("vf:%u run mode:%d base:%u vsi_type:%u sw vsi id invalid ret:%d.\n",
			      vf_node->vf_idx, vf_node->vf_run_mode, base, type, ret);
		goto l_out;
	}

	*sw_vsi_id = vsi_id - base;

l_out:
	return ret;
}

