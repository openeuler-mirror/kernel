// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_debugfs.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/debugfs.h>
#include <linux/cpumask.h>
#include <linux/atomic.h>

#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_common.h"
#include "sxe2_debugfs.h"
#include "sxe2_switch.h"
#include "sxe2_txsched.h"
#include "sxe2_lldp.h"
#include "sxe2_rss.h"
#include "sxe2_fnav.h"
#include "sxe2_dfx.h"
#include "sxe2_dev_ctrl.h"
#include "sxe2_host_cli.h"
#include "sxe2_lag.h"
#include "sxe2_acl.h"
#include "sxe2_com_dma.h"
#include "sxe2_ethtool.h"
#include "sxe2_com_cdev.h"
#include "sxe2_sriov.h"
#include "sxe2_queue.h"
#include "sxe2_tx.h"

static struct dentry *sxe2_debugfs_root;

#ifdef SXE2_CFG_DEBUG
extern int g_pf_switch_stats;
#endif

static char *g_sxe2_com_mode_to_str[] = {
		[SXE2_COM_MODULE_KERNEL] = SXE2_COM_KERNEL_MODE_NAME,
		[SXE2_COM_MODULE_DPDK] = SXE2_COM_DPDK_MODE_NAME,
		[SXE2_COM_MODULE_RDMA] = SXE2_COM_RDMA_MODE_NAME,
		[SXE2_COM_MODULE_MIXED] = SXE2_COM_MIXED_MODE_NAME,
		[SXE2_COM_MODULE_UNDEFINED] = SXE2_COM_UNDEFINED_MODE_NAME,
};

STATIC void sxe2_info_dump(struct sxe2_adapter *adapter)
{
	LOG_DEV_INFO("\t adapter=%pK\n", adapter);
	LOG_DEV_INFO("\t adapter.dev_name=%s\n", adapter->dev_name);
	LOG_DEV_INFO("\t adapter.pf_idx=%d\n", adapter->pf_idx);
	LOG_DEV_INFO("\t adapter.port_idx=%d\n", adapter->port_idx);
	LOG_DEV_INFO("\t adapter mode:%d\n", sxe2_com_mode_get(adapter));
	LOG_DEV_INFO("\t adapter.irq_ctxt.max_cnt=%d\n", adapter->irq_ctxt.max_cnt);
	LOG_DEV_INFO("\t adapter.irq_ctxt.avail_cnt=%d\n",
		     adapter->irq_ctxt.avail_cnt);
	LOG_DEV_INFO("\t adapter.irq_ctxt.base_idx_in_dev=%d\n",
		     adapter->irq_ctxt.base_idx_in_dev);
	LOG_DEV_INFO("\t adapter.irq_ctxt.rdma_base_idx=%d\n",
		     adapter->irq_ctxt.rdma_base_idx);
	LOG_DEV_INFO("\t adapter.irq_ctxt.event_irq_cnt=%d\n",
		     adapter->irq_ctxt.event_irq_cnt);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.event=%d\n",
		     adapter->irq_ctxt.irq_layout.event);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.event_offset=%d\n",
		     adapter->irq_ctxt.irq_layout.event_offset);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.lb=%d\n",
		     adapter->irq_ctxt.irq_layout.lb);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.lb_offset=%d\n",
		     adapter->irq_ctxt.irq_layout.lb_offset);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.fnav=%d\n",
		     adapter->irq_ctxt.irq_layout.fnav);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.fnav_offset=%d\n",
		     adapter->irq_ctxt.irq_layout.fnav_offset);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.eswitch=%d\n",
		     adapter->irq_ctxt.irq_layout.eswitch);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.eswitch_offset=%d\n",
		     adapter->irq_ctxt.irq_layout.eswitch_offset);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.lan=%d\n",
		     adapter->irq_ctxt.irq_layout.lan);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.lan_offset=%d\n",
		     adapter->irq_ctxt.irq_layout.lan_offset);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.rdma_offset=%d\n",
		     adapter->irq_ctxt.irq_layout.rdma_offset);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.rdma=%d\n",
		     adapter->irq_ctxt.irq_layout.rdma);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.dpdk_offset=%d\n",
		     adapter->irq_ctxt.irq_layout.dpdk_offset);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.dpdk=%d\n",
		     adapter->irq_ctxt.irq_layout.dpdk);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.dpdk_eswitch=%d\n",
		     adapter->irq_ctxt.irq_layout.dpdk_eswitch);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.dpdk_eswitch_offset=%d\n",
		     adapter->irq_ctxt.irq_layout.dpdk_eswitch_offset);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.macvlan_offset=%d\n",
		     adapter->irq_ctxt.irq_layout.macvlan_offset);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.macvlan=%d\n",
		     adapter->irq_ctxt.irq_layout.macvlan);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.sriov=%d\n",
		     adapter->irq_ctxt.irq_layout.sriov);
	LOG_DEV_INFO("\t adapter.irq_ctxt.irq_layout.sriov_offset=%d\n",
		     adapter->irq_ctxt.irq_layout.sriov_offset);

	LOG_DEV_INFO("\t adapter.q_ctxt.max_txq_cnt=%d\n",
		     adapter->q_ctxt.max_txq_cnt);
	LOG_DEV_INFO("\t adapter.q_ctxt.max_rxq_cnt=%d\n",
		     adapter->q_ctxt.max_rxq_cnt);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_base_idx_in_dev=%d\n",
		     adapter->q_ctxt.txq_base_idx_in_dev);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_base_idx_in_dev=%d\n",
		     adapter->q_ctxt.rxq_base_idx_in_dev);

	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.lb=%d\n",
		     adapter->q_ctxt.txq_layout.lb);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.lb_offset=%d\n",
		     adapter->q_ctxt.txq_layout.lb_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.ctrl_offset=%d\n",
		     adapter->q_ctxt.txq_layout.ctrl_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.ctrl=%d\n",
		     adapter->q_ctxt.txq_layout.ctrl);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.lan=%d\n",
		     adapter->q_ctxt.txq_layout.lan);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.lan_offset=%d\n",
		     adapter->q_ctxt.txq_layout.lan_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.dpdk=%d\n",
		     adapter->q_ctxt.txq_layout.dpdk);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.dpdk_offset=%d\n",
		     adapter->q_ctxt.txq_layout.dpdk_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.xdp=%d\n",
		     adapter->q_ctxt.txq_layout.xdp);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.xdp_offset=%d\n",
		     adapter->q_ctxt.txq_layout.xdp_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.macvlan=%d\n",
		     adapter->q_ctxt.txq_layout.macvlan);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.macvlan_offset=%d\n",
		     adapter->q_ctxt.txq_layout.macvlan_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.sriov=%d\n",
		     adapter->q_ctxt.txq_layout.sriov);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.sriov_offset=%d\n",
		     adapter->q_ctxt.txq_layout.sriov_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.esw=%d\n",
		     adapter->q_ctxt.txq_layout.esw);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.esw_offset=%d\n",
		     adapter->q_ctxt.txq_layout.esw_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.dpdk_esw=%d\n",
		     adapter->q_ctxt.txq_layout.dpdk_esw);
	LOG_DEV_INFO("\t adapter.q_ctxt.txq_layout.dpdk_esw_offset=%d\n",
		     adapter->q_ctxt.txq_layout.dpdk_esw_offset);

	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.lb=%d\n",
		     adapter->q_ctxt.rxq_layout.lb);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.lb_offset=%d\n",
		     adapter->q_ctxt.rxq_layout.lb_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.ctrl_offset=%d\n",
		     adapter->q_ctxt.rxq_layout.ctrl_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.ctrl=%d\n",
		     adapter->q_ctxt.rxq_layout.ctrl);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.lan=%d\n",
		     adapter->q_ctxt.rxq_layout.lan);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.lan_offset=%d\n",
		     adapter->q_ctxt.rxq_layout.lan_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.dpdk=%d\n",
		     adapter->q_ctxt.rxq_layout.dpdk);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.dpdk_offset=%d\n",
		     adapter->q_ctxt.rxq_layout.dpdk_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.xdp=%d\n",
		     adapter->q_ctxt.rxq_layout.xdp);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.xdp_offset=%d\n",
		     adapter->q_ctxt.rxq_layout.xdp_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.macvlan=%d\n",
		     adapter->q_ctxt.rxq_layout.macvlan);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.macvlan_offset=%d\n",
		     adapter->q_ctxt.rxq_layout.macvlan_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.sriov=%d\n",
		     adapter->q_ctxt.rxq_layout.sriov);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.sriov_offset=%d\n",
		     adapter->q_ctxt.rxq_layout.sriov_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.esw=%d\n",
		     adapter->q_ctxt.rxq_layout.esw);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.esw_offset=%d\n",
		     adapter->q_ctxt.rxq_layout.esw_offset);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.dpdk_esw=%d\n",
		     adapter->q_ctxt.rxq_layout.dpdk_esw);
	LOG_DEV_INFO("\t adapter.q_ctxt.rxq_layout.dpdk_esw_offset=%d\n",
		     adapter->q_ctxt.rxq_layout.dpdk_esw_offset);

	LOG_DEV_INFO("\t adapter.vsi_ctxt.cnt=%d\n", adapter->vsi_ctxt.cnt);
	LOG_DEV_INFO("\t adapter.vsi_ctxt.max_cnt=%d\n", adapter->vsi_ctxt.max_cnt);
	LOG_DEV_INFO("\t adapter.vsi_ctxt.base_idx_in_dev=%d\n",
		     adapter->vsi_ctxt.base_idx_in_dev);
	LOG_DEV_INFO("\t adapter.dev_ctrl_ctxt.dev_state=%d\n",
		     adapter->dev_ctrl_ctxt.dev_state);
	LOG_DEV_INFO("\t adapter.dev_ctrl_ctxt.work_state=%lu\n",
		     adapter->dev_ctrl_ctxt.work_state);
	LOG_DEV_INFO("\t adapter.macvlan_ctxt.num_macvlan=%d\n",
		     adapter->macvlan_ctxt.num_macvlan);
	LOG_DEV_INFO("\t adapter.macvlan_ctxt.max_num_macvlan=%d\n",
		     adapter->macvlan_ctxt.max_num_macvlan);
}

STATIC void sxe2_vsi_dump(struct sxe2_vsi *vsi)
{
	u16 i;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct netdev_queue *ntxq = NULL;

	LOG_DEV_INFO("\t ----vsi[%d]----\n", vsi->idx_in_dev);
	LOG_DEV_INFO("\t vsi->is_from_pool=%d\n", vsi->is_from_pool);
	LOG_DEV_INFO("\t vsi->type=%d\n", vsi->type);
	LOG_DEV_INFO("\t vsi->id_in_pf=%d\n", vsi->id_in_pf);
	LOG_DEV_INFO("\t vsi->idx_in_dev=%d\n", vsi->idx_in_dev);
	LOG_DEV_INFO("\t vsi base id in dev=%d\n",
		     adapter->vsi_ctxt.base_idx_in_dev);
	LOG_DEV_INFO("\t vsi cnt=%d\n", adapter->vsi_ctxt.cnt);

	LOG_DEV_INFO("\t vsi->tc.tc_cnt=%d\n", vsi->tc.tc_cnt);
	LOG_DEV_INFO("\t vsi->tc.tc_map=%d\n", vsi->tc.tc_map);

	LOG_DEV_INFO("\t vsi->irqs.cnt=%d\n", vsi->irqs.cnt);
	LOG_DEV_INFO("\t vsi->irqs.base_idx_in_pf=%d\n", vsi->irqs.base_idx_in_pf);
	sxe2_for_each_vsi_irq(vsi, i)
	{
		LOG_DEV_INFO("\t ----vsi irq_data[%d]----\n",
			     vsi->irqs.irq_data[i]->idx_in_vsi);
		LOG_DEV_INFO("\t\t irq_data[%d]->name=%s\n", i,
			     vsi->irqs.irq_data[i]->name);
		LOG_DEV_INFO("\t\t irq_data[%d]->idx_in_pf=%d\n", i,
			     vsi->irqs.irq_data[i]->idx_in_pf);
		LOG_DEV_INFO("\t\t irq_data[%d]->rate_limit=%d\n", i,
			     vsi->irqs.irq_data[i]->rate_limit);
		LOG_DEV_INFO("\t\t irq_data[%d]->multiple_polling=%d\n", i,
			     vsi->irqs.irq_data[i]->multiple_polling);
		LOG_DEV_INFO("\t\t irq_data[%d]->event_ctr=%d\n", i,
			     vsi->irqs.irq_data[i]->event_ctr);
		LOG_DEV_INFO("\t\t irq_data[%d]->tx.itr_mode=%d\n", i,
			     vsi->irqs.irq_data[i]->tx.itr_mode);
		LOG_DEV_INFO("\t\t irq_data[%d]->tx.itr_idx=%d\n", i,
			     vsi->irqs.irq_data[i]->tx.itr_idx);
		LOG_DEV_INFO("\t\t irq_data[%d]->tx.itr_setting=%d\n", i,
			     vsi->irqs.irq_data[i]->tx.itr_setting);
		LOG_DEV_INFO("\t\t irq_data[%d]->rx.itr_mode=%d\n", i,
			     vsi->irqs.irq_data[i]->rx.itr_mode);
		LOG_DEV_INFO("\t\t irq_data[%d]->rx.itr_idx=%d\n", i,
			     vsi->irqs.irq_data[i]->rx.itr_idx);
		LOG_DEV_INFO("\t\t irq_data[%d]->rx.itr_setting=%d\n", i,
			     vsi->irqs.irq_data[i]->rx.itr_setting);
	}

	LOG_DEV_INFO("\t vsi->txqs.q_cnt=%d\n", vsi->txqs.q_cnt);
	LOG_DEV_INFO("\t vsi->txqs.depth=%d\n", vsi->txqs.depth);
	LOG_DEV_INFO("\t vsi->txqs.rx_buf_len=%d\n", vsi->txqs.rx_buf_len);
	LOG_DEV_INFO("\t vsi->txqs.max_frame=%d\n", vsi->txqs.max_frame);
	sxe2_for_each_vsi_txq(vsi, i)
	{
		LOG_DEV_INFO("\t ----vsi txq[%d]----\n", vsi->txqs.q[i]->idx_in_vsi);
		LOG_DEV_INFO("\t\t txq[%d]->idx_in_pf=%d\n", i,
			     vsi->txqs.q[i]->idx_in_pf);
		LOG_DEV_INFO("\t\t txq[%d]->depth=%d\n", i, vsi->txqs.q[i]->depth);
		LOG_DEV_INFO("\t\t txq[%d]->next_to_use=%d\n", i,
			     vsi->txqs.q[i]->next_to_use);
		LOG_DEV_INFO("\t\t txq[%d]->next_to_clean=%d\n", i,
			     vsi->txqs.q[i]->next_to_clean);
		if (vsi->txqs.q[i]->netdev) {
			ntxq = netdev_get_tx_queue(vsi->txqs.q[i]->netdev,
						   vsi->txqs.q[i]->idx_in_vsi);
			if (ntxq) {
				LOG_DEV_INFO("\t\t txq[%d] netdev st=%lu\t"
					     "(BIT: 0 - DRV_XOFF; 1 - STACK_XOFF;\t"
					     "2- FROZEN)\n",
					     i, ntxq->state);
#ifdef CONFIG_BQL
				LOG_DEV_INFO("\t\t txq[%d] dql adj_limit %u queued\t"
					     "%u\t"
					     "completed %u max_limit %u min_limit\t"
					     "%u.\n",
					     i, ntxq->dql.adj_limit,
					     ntxq->dql.num_queued,
					     ntxq->dql.num_completed,
					     ntxq->dql.max_limit,
					     ntxq->dql.min_limit);
#endif
			}
		}
	}

	LOG_DEV_INFO("\t vsi->rxqs.q_cnt=%d\n", vsi->rxqs.q_cnt);
	LOG_DEV_INFO("\t vsi->rxqs.depth=%d\n", vsi->rxqs.depth);
	LOG_DEV_INFO("\t vsi->rxqs.rx_buf_len=%d\n", vsi->rxqs.rx_buf_len);
	LOG_DEV_INFO("\t vsi->rxqs.max_frame=%d\n", vsi->rxqs.max_frame);
	sxe2_for_each_vsi_rxq(vsi, i)
	{
		LOG_DEV_INFO("\t ----vsi rxq[%d]----\n", vsi->rxqs.q[i]->idx_in_vsi);
		LOG_DEV_INFO("\t\t rxq[%d]->idx_in_pf=%d\n", i,
			     vsi->rxqs.q[i]->idx_in_pf);
		LOG_DEV_INFO("\t\t rxq[%d]->depth=%d\n", i, vsi->rxqs.q[i]->depth);
		LOG_DEV_INFO("\t\t rxq[%d]->next_to_use=%d\n", i,
			     vsi->rxqs.q[i]->next_to_use);
		LOG_DEV_INFO("\t\t rxq[%d]->next_to_clean=%d\n", i,
			     vsi->rxqs.q[i]->next_to_clean);
	}
}

STATIC void sxe2_vsis_dump(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *vsi;
	u16 i;

	mutex_lock(&adapter->vsi_ctxt.lock);
	sxe2_for_each_vsi(&adapter->vsi_ctxt, i)
	{
		vsi = adapter->vsi_ctxt.vsi[i];
		if (!vsi)
			continue;

		sxe2_vsi_dump(vsi);
	}
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

STATIC void sxe2_debugfs_cdev_show(struct sxe2_adapter *adapter)
{
	struct sxe2_cli_dev_mgr *cli_dev_mgr = sxe2_cdev_mgr_get();

	LOG_DEV_INFO("bitmap:%ld\n", cli_dev_mgr->map[0]);

	LOG_DEV_INFO("cdev mgr[0] id %d\n", cli_dev_mgr->cdev_mgr[0].id);
	LOG_DEV_INFO("cdev mgr[0] ref_count %d\n",
		     atomic_read(&cli_dev_mgr->cdev_mgr[0].ref_count));
	LOG_DEV_INFO("cdev mgr[0] adapter %p\n",
		     (void *)cli_dev_mgr->cdev_mgr[0].adapter);
	LOG_DEV_INFO("cdev mgr[0] status %d\n", cli_dev_mgr->cdev_mgr[0].status);
	LOG_DEV_INFO("cdev mgr[1] id %d\n", cli_dev_mgr->cdev_mgr[1].id);
	LOG_DEV_INFO("cdev mgr[1] ref_count %d\n",
		     atomic_read(&cli_dev_mgr->cdev_mgr[1].ref_count));
	LOG_DEV_INFO("cdev mgr[1] adapter %p\n",
		     (void *)cli_dev_mgr->cdev_mgr[1].adapter);
	LOG_DEV_INFO("cdev mgr[1] status %d\n", cli_dev_mgr->cdev_mgr[1].status);
	LOG_DEV_INFO("cdev mgr[2] id %d\n", cli_dev_mgr->cdev_mgr[2].id);
	LOG_DEV_INFO("cdev mgr[2] ref_count %d\n",
		     atomic_read(&cli_dev_mgr->cdev_mgr[2].ref_count));
	LOG_DEV_INFO("cdev mgr[2] adapter %p\n",
		     (void *)cli_dev_mgr->cdev_mgr[2].adapter);
	LOG_DEV_INFO("cdev mgr[2] status %d\n", cli_dev_mgr->cdev_mgr[2].status);
	LOG_DEV_INFO("cdev mgr[3] id %d\n", cli_dev_mgr->cdev_mgr[3].id);
	LOG_DEV_INFO("cdev mgr[3] ref_count %d\n",
		     atomic_read(&cli_dev_mgr->cdev_mgr[3].ref_count));
	LOG_DEV_INFO("cdev mgr[3] adapter %p\n",
		     (void *)cli_dev_mgr->cdev_mgr[3].adapter);
	LOG_DEV_INFO("cdev mgr[3] status %d\n", cli_dev_mgr->cdev_mgr[3].status);
}

STATIC void sxe2_pf_state_get(struct sxe2_adapter *adapter)
{
	enum sxe2_dev_state dev_state;
	enum sxe2_reset_type reset_type;

	sxe2_dev_state_get(adapter, &dev_state, &reset_type);
	if (dev_state == SXE2_DEVSTATE_RUNNING)
		LOG_DEV_INFO("pf ready\n");
	else
		LOG_DEV_INFO("pf unready\n");
}

STATIC void sxe2_pf_lag_dump(struct sxe2_adapter *adapter)
{
	struct sxe2_lag_context *lag = adapter->lag_ctxt;

	if (!lag) {
		LOG_DEV_INFO("No lag\n");
		return;
	}

	mutex_lock(&lag->lock);

	LOG_DEV_INFO("lag bond id %d.\n", lag->bond_id);
	LOG_DEV_INFO("lag bonded:%d mode:%d pf 0 \t"
		     "state: %d pf 1 state: %d ref_num: %d\n",
		     lag->bonded, lag->bond_mode, lag->state[SXE2_LAG_PF0],
		     lag->state[SXE2_LAG_PF0], lag->ref_num);

	LOG_DEV_INFO("lag serinum:%s\n", lag->serial_num);
	LOG_DEV_INFO("lag adapters[0] 0x%p pfid %d\n", lag->adapters[0],
		     lag->adapters[0] ? lag->adapters[0]->pf_idx : -1);
	LOG_DEV_INFO("lag adapters[1] 0x%p pfid %d\n", lag->adapters[1],
		     lag->adapters[1] ? lag->adapters[1]->pf_idx : -1);
	LOG_DEV_INFO("lag wk state %d mode %d event %d is_bonded %d\n",
		     lag->lag_wk.state, lag->lag_wk.bond_mode, lag->lag_wk.event,
		     lag->lag_wk.is_bonded);
	LOG_DEV_INFO("lag wk slave[0] st %d link %d\n",
		     lag->lag_wk.info[0].slave_state,
		     lag->lag_wk.info[0].slave_link);
	LOG_DEV_INFO("lag wk slave[1] st %d link %d\n",
		     lag->lag_wk.info[1].slave_state,
		     lag->lag_wk.info[1].slave_link);
	mutex_unlock(&lag->lock);
}

STATIC void sxe2_vf_nodes_show(struct sxe2_adapter *adapter)
{
	u16 vf_idx;
	struct sxe2_vf_node_e *vf_node_e;
	bool cfg_exists;
	u16 max_vf_id;

	LOG_DEV_INFO("\t vf node show start.\n");

	LOG_DEV_INFO("\t adapter.vf_ctxt.max_vfs=%d\n", adapter->vf_ctxt.max_vfs);
	LOG_DEV_INFO("\t adapter.vf_ctxt.num_vfs=%d\n", adapter->vf_ctxt.num_vfs);
	LOG_DEV_INFO("\t adapter.vf_ctxt.vfid_base=%d\n",
		     adapter->vf_ctxt.vfid_base);
	LOG_DEV_INFO("\t adapter.vf_ctxt.large_q.dflt_large_q_en=%d\n",
		     adapter->vf_ctxt.large_q.dflt_large_q_en);
	LOG_DEV_INFO("\t adapter.vf_ctxt.large_q.occupied_q_cnt=%d\n",
		     adapter->vf_ctxt.large_q.occupied_q_cnt);
	LOG_DEV_INFO("\t adapter.vf_ctxt.large_q.spare_q=%d\n",
		     adapter->vf_ctxt.large_q.spare_q);
	LOG_DEV_INFO("\t adapter.vf_ctxt.large_q.extra_q_cnt=%d\n",
		     adapter->vf_ctxt.large_q.extra_q_cnt);
	LOG_DEV_INFO("\t adapter.vf_ctxt.large_q.max_vf_id=%d\n",
		     adapter->vf_ctxt.large_q.max_vf_id);

	mutex_lock(&adapter->vf_ctxt.vfs_lock);

	for (vf_idx = 0; vf_idx < adapter->vf_ctxt.num_vfs; vf_idx++) {
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		vf_node_e = SXE2_VF_NODE_E(adapter, vf_idx);

		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d]\n", vf_idx);
		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].irq_base_idx=%d\n",
			     vf_idx, vf_node_e->vf_node->irq_base_idx);
		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].irq_cnt=%d\n",
			     vf_idx, vf_node_e->vf_node->irq_cnt);
		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].q_cnt=%d\n",
			     vf_idx, vf_node_e->vf_node->q_cnt);
		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].rxq_base=%d\n",
			     vf_idx, vf_node_e->vf_node->rxq_base);
		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].txq_base=%d\n",
			     vf_idx, vf_node_e->vf_node->txq_base);
		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].vf_idx=%d\n", vf_idx,
			     vf_node_e->vf_node->vf_idx);

		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].mac_from_pf=%d\n",
			     vf_idx, vf_node_e->vf_node->prop.mac_from_pf);
		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].trusted=%d\n", vf_idx,
			     vf_node_e->vf_node->prop.trusted);
		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].spoofchk=%d\n",
			     vf_idx, vf_node_e->vf_node->prop.spoofchk);
		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].link_forced=%d\n",
			     vf_idx, vf_node_e->vf_node->prop.link_forced);
		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].link_up=%d\n", vf_idx,
			     vf_node_e->vf_node->prop.link_up);
		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].min_tx_rate=%d\n",
			     vf_idx, vf_node_e->vf_node->prop.min_tx_rate);
		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].max_tx_rate=%d\n",
			     vf_idx, vf_node_e->vf_node->prop.max_tx_rate);
		LOG_DEV_INFO("\t vf:%d vf_cfg_mode=%d vf_run_mode:%d\n",
			     vf_idx, vf_node_e->vf_node->vf_cfg_mode,
			     vf_node_e->vf_node->vf_run_mode);
		LOG_DEV_INFO("\t vf:%d master vsi id=%d slave vsi id=%d\n",
			     vf_idx, vf_node_e->vf_node->vsi_id[SXE2_VF_VSI_ID_MASTER],
			     vf_node_e->vf_node->vsi_id[SXE2_VF_VSI_ID_SLAVE]);

		if (vf_node_e->vf_node->vsi)
			sxe2_vsi_dump(vf_node_e->vf_node->vsi);
		else if (vf_node_e->vf_node->dpdk_vf_vsi)
			sxe2_vsi_dump(vf_node_e->vf_node->dpdk_vf_vsi);
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	}

	cfg_exists = sxe2_vf_user_cfg_is_set(adapter);
	max_vf_id = adapter->vf_ctxt.large_q.max_vf_id;
	for (vf_idx = 0; cfg_exists && vf_idx <= max_vf_id; vf_idx++) {
		struct sxe2_vf_usr_cfg *usr_cfg = SXE2_VF_USR_CFG(adapter, vf_idx);

		LOG_DEV_INFO("\t adapter.vf_ctxt.large_q.usr_cfg[%d]: "
			     "kernel(q_cfg=%u lut_type=%u lut_id=%u) "
			     "dpdk(q_cfg=%u lut_type=%u lut_id=%u)\n",
			     vf_idx,
			     usr_cfg->product[SXE2_PRODUCT_ID_KERNEL].q_cfg,
			     usr_cfg->product[SXE2_PRODUCT_ID_KERNEL].lut_type,
			     usr_cfg->product[SXE2_PRODUCT_ID_KERNEL].lut_id,
			     usr_cfg->product[SXE2_PRODUCT_ID_DPDK].q_cfg,
			     usr_cfg->product[SXE2_PRODUCT_ID_DPDK].lut_type,
			     usr_cfg->product[SXE2_PRODUCT_ID_DPDK].lut_id);
	}
	mutex_unlock(&adapter->vf_ctxt.vfs_lock);

	LOG_DEV_INFO("\t vf node show end.\n");
}

#ifdef SXE2_CFG_DEBUG
STATIC void sxe2_switch_dfx_irq_enable(struct sxe2_adapter *adapter)
{
	(void)sxe2_switch_dfx_irq_setup(adapter, true);
}

STATIC void sxe2_switch_dfx_irq_disable(struct sxe2_adapter *adapter)
{
	(void)sxe2_switch_dfx_irq_setup(adapter, false);
}

STATIC void sxe2_fnav_hw_clear(struct sxe2_adapter *adapter)
{
	s32 ret = 0;

	ret = sxe2_fwc_fnav_hw_clear(adapter);
	if (ret)
		return;

	sxe2_fnav_flow_ctxt_clean(adapter);
}

STATIC void sxe2_fnav_hw_replay(struct sxe2_adapter *adapter)
{
	sxe2_fnav_rule_reply(adapter);
}

STATIC void sxe2_heart_close(struct sxe2_adapter *adapter)
{
	adapter->dev_ctrl_ctxt.heart_beat_ena = false;
	LOG_DEV_INFO("heart beat disable\n");
}

STATIC void sxe2_heart_open(struct sxe2_adapter *adapter)
{
	adapter->dev_ctrl_ctxt.heart_beat_ena = true;
	LOG_DEV_INFO("heart beat enable\n");
}

STATIC void sxe2_corer_trigger(struct sxe2_adapter *adapter)
{
	enum sxe2_dev_state curr_dev_state;
	enum sxe2_reset_type curr_reset_type;

	LOG_DEV_INFO("\t CORER trigger\n");
	sxe2_dev_state_get(adapter, &curr_dev_state, &curr_reset_type);
	if (curr_dev_state == SXE2_DEVSTATE_FAULT) {
		LOG_DEV_DEBUG("sxe2 nic fault.\n");
		return;
	} else if (curr_dev_state != SXE2_DEVSTATE_RUNNING) {
		LOG_DEV_DEBUG("reset already in progress.\n");
		return;
	}
	(void)sxe2_reset_async(adapter, SXE2_RESET_CORER);
}

STATIC void sxe2_pfr_trigger(struct sxe2_adapter *adapter)
{
	enum sxe2_dev_state curr_dev_state;
	enum sxe2_reset_type curr_reset_type;

	LOG_DEV_INFO("\t PFR trigger\n");

	sxe2_dev_state_get(adapter, &curr_dev_state, &curr_reset_type);
	if (curr_dev_state == SXE2_DEVSTATE_FAULT) {
		LOG_DEV_DEBUG("sxe2 nic fault.\n");
		return;
	} else if (curr_dev_state != SXE2_DEVSTATE_RUNNING) {
		LOG_DEV_DEBUG("reset already in progress.\n");
		return;
	}
	(void)sxe2_reset_async(adapter, SXE2_RESET_PFR);
}

void sxe2_etype_rx_rule_add(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *vsi;

	LOG_DEV_INFO("\t rx etype rule add\n");
	vsi = adapter->vsi_ctxt.main_vsi;
	(void)sxe2_rx_etype_rule_add(vsi, ETH_P_LLDP);
}

void sxe2_etype_rx_rule_del(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *vsi;

	LOG_DEV_INFO("\t rx etype rule del\n");
	vsi = adapter->vsi_ctxt.main_vsi;
	(void)sxe2_rx_etype_rule_del(adapter, vsi->idx_in_dev, ETH_P_LLDP);
}

STATIC void sxe2_dcb_info_show(struct sxe2_adapter *adapter)
{
	struct sxe2_dcbx_cfg *new_cfg = &adapter->dcb_ctxt.desired_dcbx_cfg;
	struct sxe2_dcbx_cfg *local_cfg = &adapter->dcb_ctxt.local_dcbx_cfg;
	u32 i;

	LOG_INFO_BDF("local pfc cfg, cap=%u, enable=%u,\n"
		     "mbc=%u, willing=%u\n",
		     local_cfg->pfc.cap, local_cfg->pfc.enable, local_cfg->pfc.mbc,
		     local_cfg->pfc.willing);

	LOG_INFO_BDF("local ets cfg, willing=%d, cbs=%d, maxtcs=%d\n"
		     "prio[0]=%d, tcbw[0]=%d, tsa_tbl[0]=%d\n"
		     "prio[1]=%d, tcbw[1]=%d, tsa_tbl[1]=%d\n"
		     "prio[2]=%d, tcbw[2]=%d, tsa_tbl[2]=%d\n"
		     "prio[3]=%d, tcbw[3]=%d, tsa_tbl[3]=%d\n"
		     "prio[4]=%d, tcbw[4]=%d, tsa_tbl[4]=%d\n"
		     "prio[5]=%d, tcbw[5]=%d, tsa_tbl[5]=%d\n"
		     "prio[6]=%d, tcbw[6]=%d, tsa_tbl[6]=%d\n"
		     "prio[7]=%d, tcbw[7]=%d, tsa_tbl[7]=%d\n",
		     local_cfg->ets.willing, local_cfg->ets.cbs,
		     local_cfg->ets.maxtcs, local_cfg->ets.prio_tbl[0],
		     local_cfg->ets.tcbw_tbl[0], local_cfg->ets.tsa_tbl[0],
		     local_cfg->ets.prio_tbl[1], local_cfg->ets.tcbw_tbl[1],
		     local_cfg->ets.tsa_tbl[1], local_cfg->ets.prio_tbl[2],
		     local_cfg->ets.tcbw_tbl[2], local_cfg->ets.tsa_tbl[2],
		     local_cfg->ets.prio_tbl[3], local_cfg->ets.tcbw_tbl[3],
		     local_cfg->ets.tsa_tbl[3], local_cfg->ets.prio_tbl[4],
		     local_cfg->ets.tcbw_tbl[4], local_cfg->ets.tsa_tbl[4],
		     local_cfg->ets.prio_tbl[5], local_cfg->ets.tcbw_tbl[5],
		     local_cfg->ets.tsa_tbl[5], local_cfg->ets.prio_tbl[6],
		     local_cfg->ets.tcbw_tbl[6], local_cfg->ets.tsa_tbl[6],
		     local_cfg->ets.prio_tbl[7], local_cfg->ets.tcbw_tbl[7],
		     local_cfg->ets.tsa_tbl[7]);

	for (i = 0; i < SXE2_DSCP_MAX_NUM; i++) {
		LOG_INFO_BDF("local app cfg, qos_mode %d dscp=%d, en=%d\n", i,
			     local_cfg->qos_mode,
			     test_bit((int)i, local_cfg->dscp_mapped));
	}
	for (i = 0; i < local_cfg->numapps; i++)
		LOG_INFO_BDF("local app cfg, dscp=%d, up=%d\n",
			     local_cfg->app[i].prot_id, local_cfg->app[i].prio);

	LOG_INFO_BDF("desired pfc cfg, cap=%u, enable=%u,\n"
		     "mbc=%u, willing=%u\n",
		     new_cfg->pfc.cap, new_cfg->pfc.enable, new_cfg->pfc.mbc,
		     new_cfg->pfc.willing);

	LOG_INFO_BDF("desired ets cfg, willing=%d, cbs=%d, maxtcs=%d\n"
		     "prio[0]=%d, tcbw[0]=%d, tsa_tbl[0]=%d\n"
		     "prio[1]=%d, tcbw[1]=%d, tsa_tbl[1]=%d\n"
		     "prio[2]=%d, tcbw[2]=%d, tsa_tbl[2]=%d\n"
		     "prio[3]=%d, tcbw[3]=%d, tsa_tbl[3]=%d\n"
		     "prio[4]=%d, tcbw[4]=%d, tsa_tbl[4]=%d\n"
		     "prio[5]=%d, tcbw[5]=%d, tsa_tbl[5]=%d\n"
		     "prio[6]=%d, tcbw[6]=%d, tsa_tbl[6]=%d\n"
		     "prio[7]=%d, tcbw[7]=%d, tsa_tbl[7]=%d\n",
		     new_cfg->ets.willing, new_cfg->ets.cbs, new_cfg->ets.maxtcs,
		     new_cfg->ets.prio_tbl[0], new_cfg->ets.tcbw_tbl[0],
		     new_cfg->ets.tsa_tbl[0], new_cfg->ets.prio_tbl[1],
		     new_cfg->ets.tcbw_tbl[1], new_cfg->ets.tsa_tbl[1],
		     new_cfg->ets.prio_tbl[2], new_cfg->ets.tcbw_tbl[2],
		     new_cfg->ets.tsa_tbl[2], new_cfg->ets.prio_tbl[3],
		     new_cfg->ets.tcbw_tbl[3], new_cfg->ets.tsa_tbl[3],
		     new_cfg->ets.prio_tbl[4], new_cfg->ets.tcbw_tbl[4],
		     new_cfg->ets.tsa_tbl[4], new_cfg->ets.prio_tbl[5],
		     new_cfg->ets.tcbw_tbl[5], new_cfg->ets.tsa_tbl[5],
		     new_cfg->ets.prio_tbl[6], new_cfg->ets.tcbw_tbl[6],
		     new_cfg->ets.tsa_tbl[6], new_cfg->ets.prio_tbl[7],
		     new_cfg->ets.tcbw_tbl[7], new_cfg->ets.tsa_tbl[7]);

	for (i = 0; i < SXE2_DSCP_MAX_NUM; i++) {
		LOG_INFO_BDF("desired app cfg, qos_mode %d dscp=%d, en=%d\n", i,
			     new_cfg->qos_mode,
			     test_bit((int)i, new_cfg->dscp_mapped));
	}
	for (i = 0; i < new_cfg->numapps; i++)
		LOG_INFO_BDF("desired app cfg, dscp=%d, up=%d\n",
			     new_cfg->app[i].prot_id, new_cfg->app[i].prio);
}

STATIC void sxe2_datapath_log_close(struct sxe2_adapter *adapter)
{
	clear_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags);
	LOG_DEV_INFO("datapath log disable\n");
}

STATIC void sxe2_datapath_log_open(struct sxe2_adapter *adapter)
{
	set_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags);
	LOG_DEV_INFO("datapath log enable\n");
}
#endif

STATIC void sxe2_spoof_stats_debugfs_dump(struct sxe2_adapter *adapter)
{
	struct sxe2_pf_hw_stats *stats = &adapter->pf_stats.pf_hw_stats;

	mutex_lock(&adapter->vsi_ctxt.lock);
	sxe2_stats_update(adapter);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	sxe2_repr_vf_vsis_stats_acculate_update(adapter);

	LOG_DEV_INFO("%llu mac spoof packets detected.\n", stats->spoof_mac_packets);
	LOG_DEV_INFO("%llu vlan spoof packets detected.\n",
		     stats->spoof_vlan_packets);
}

STATIC void sxe2_nic_type_dump(struct sxe2_adapter *adapter)
{
	struct sxe2_hw *hw = &adapter->hw;

	if (hw->is_pop_type)
		LOG_DEV_INFO("nic is pop\n");
	else
		LOG_DEV_INFO("nic is sig\n");
}

STATIC void sxe2_fw_optical_waring_info_show(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};
	struct optical_warning_info opt_waring_info = {};

	memset(&opt_waring_info, 0, sizeof(struct optical_warning_info));
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_GET_VENDOR_INFO_CHECK_WARNING, NULL,
				  0, &opt_waring_info,
				  sizeof(struct optical_warning_info));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_DEV_ERR("get fw optical vendor info cmd failed, ret=%d\n", ret);
		return;
	}

	LOG_DEV_INFO("optical vendor pn: %s\n", opt_waring_info.vendor_pn);
	LOG_DEV_INFO("optical vendor name: %s\n", opt_waring_info.vendor);
	if (opt_waring_info.is_warning) {
		LOG_DEV_WARN("an unsupport optical module type was detected\n");
		LOG_DEV_WARN("refer to the sxe2 ethernet adapters and devices usr \t"
			     "guide for a list of supported modules\n");
	} else {
		LOG_DEV_WARN("a supported optical module type was detected\n");
	}
}

STATIC void sxe2_acl_trace_trigger(struct sxe2_adapter *adapter)
{
	s32 ret = 0;

	ret = sxe2_fwc_acl_trace_trigger(adapter);
	if (ret)
		LOG_DEV_ERR("sxe2_fwc_acl_trace_trigger failed, ret=%d\n", ret);
}

STATIC void sxe2_acl_trace_recorder(struct sxe2_adapter *adapter)
{
	s32 ret = 0;

	ret = sxe2_fwc_acl_trace_recorder(adapter);
	if (ret)
		LOG_DEV_ERR("sxe2_fwc_acl_trace_recorder failed, ret=%d\n", ret);
}

STATIC void sxe2_acl_dfx_dump(struct sxe2_adapter *adapter)
{
	s32 ret = 0;

	ret = sxe2_fwc_acl_dfx_get(adapter);
	if (ret)
		LOG_DEV_ERR("sxe2_fwc_acl_dfx_get failed, ret=%d\n", ret);
}

STATIC void sxe2_com_info(struct sxe2_adapter *adapter)
{
	sxe2_com_info_print(&adapter->com_ctxt);
}

#ifdef SXE2_CFG_DEBUG
STATIC void sxe2_monitor_stats_close(struct sxe2_adapter *adapter)
{
	g_pf_switch_stats = 0;
}

STATIC void sxe2_monitor_stats_open(struct sxe2_adapter *adapter)
{
	g_pf_switch_stats = 1;
}

STATIC void sxe2_ntxq_stack_set(struct sxe2_adapter *adapter,
				const struct sxe2_debugfs_arg_val *argv)
{
	bool on = false;
	u16 queue = 0;
	struct sxe2_queue *txq = NULL;
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;
	struct netdev_queue *ntxq = NULL;

	queue = argv[0].num;
	on = argv[1].on;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		LOG_DEV_ERR("dev busy, please wait a moment.\n");
		goto l_end;
	}

	txq = sxe2_tx_queue_get(vsi, queue);
	if (!txq) {
		LOG_DEV_ERR("get txq failed.\n");
		goto l_end;
	}

	ntxq = sxe2_netdev_txq_get(txq);
	if (on) {
		clear_bit(__QUEUE_STATE_STACK_XOFF, &ntxq->state);
		LOG_DEV_INFO("set netdev txq %u stack on.\n", queue);
	} else {
		set_bit(__QUEUE_STATE_STACK_XOFF, &ntxq->state);
		LOG_DEV_INFO("set netdev txq %u stack off.\n", queue);
	}

l_end:
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

STATIC void sxe2_ntxq_drv_set(struct sxe2_adapter *adapter,
			      const struct sxe2_debugfs_arg_val *argv)
{
	bool on = false;
	u16 queue = 0;
	struct sxe2_queue *txq = NULL;
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;
	struct netdev_queue *ntxq = NULL;

	queue = argv[0].num;
	on = argv[1].on;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		LOG_DEV_ERR("dev busy, please wait a moment.\n");
		goto l_end;
	}

	if (!netif_carrier_ok(vsi->netdev)) {
		LOG_DEV_ERR("netdev not carrier on.\n");
		goto l_end;
	}

	txq = sxe2_tx_queue_get(vsi, queue);
	if (!txq) {
		LOG_DEV_ERR("get txq %d failed.\n", queue);
		goto l_end;
	}

	ntxq = sxe2_netdev_txq_get(txq);
	if (on) {
		netif_tx_start_queue(ntxq);
		LOG_DEV_INFO("set netdev txq %u drv on.\n", queue);
	} else {
		netif_tx_stop_queue(ntxq);
		LOG_DEV_INFO("set netdev txq %u drv off.\n", queue);
	}

l_end:
	mutex_unlock(&adapter->vsi_ctxt.lock);
}
#endif

STATIC void sxe2_debugfs_fnav_algo_set(struct sxe2_adapter *adapter,
				       const struct sxe2_debugfs_arg_val *argv)
{
	long mode = argv[0].num;
	s32 ret;

	if (mode < 0 || mode > SXE2_FNAV_ALGO_MODE_MAX) {
		LOG_DEV_ERR("fnav algo mode %ld out of range [0, %d].\n",
			    mode, SXE2_FNAV_ALGO_MODE_MAX);
		return;
	}

	ret = sxe2_fwc_fnav_algo_set(adapter, (u8)mode);
	if (ret) {
		LOG_DEV_ERR("fnav algo set mode %ld failed, ret=%d.\n",
			    mode, ret);
	} else {
		LOG_DEV_INFO("fnav algo set mode %ld success.\n", mode);
	}
}

STATIC void sxe2_debugfs_switch_algo_set(struct sxe2_adapter *adapter,
					 const struct sxe2_debugfs_arg_val *argv)
{
	long mode = argv[0].num;
	s32 ret;

	if (mode < 0 || mode > SXE2_SWITCH_ALGO_MODE_MAX) {
		LOG_DEV_ERR("switch algo mode %ld out of range [0, %d].\n",
			    mode, SXE2_SWITCH_ALGO_MODE_MAX);
		return;
	}

	ret = sxe2_fwc_switch_algo_set(adapter, (u8)mode);
	if (ret) {
		LOG_DEV_ERR("switch algo set mode %ld failed, ret=%d.\n",
			    mode, ret);
	} else {
		LOG_DEV_INFO("switch algo set mode %ld success.\n", mode);
	}
}

static struct sxe2_debugfs_command command[] = {
		{"info dump", sxe2_info_dump},
		{"vsi dump", sxe2_vsis_dump},
		{"switch trigger rx", sxe2_fwc_switch_trace_rx_trigger},
		{"switch trigger tx", sxe2_fwc_switch_trace_tx_trigger},
		{"switch recorder", sxe2_fwc_switch_trace_recorder},
		{"switch rule dump", sxe2_switch_rule_hw_dump},
		{"switch recipe get", sxe2_switch_recipe_dump},
		{"switch profile recipe map", sxe2_switch_profile_recipemap_dump},
		{"switch share id", sxe2_switch_share_id_dump},
		{"switch profile fv dump", sxe2_switch_profile_fv_dump},
		{"txsched tree dump", sxe2_txsched_tree_dump},
		{"rss trigger", sxe2_fwc_rss_trace_trigger},
		{"rss recorder", sxe2_fwc_rss_trace_recorder},
		{"rss xlt2 dump", sxe2_rss_xlt2_dump},
		{"rss vsig dump", sxe2_rss_vsig_dump},
		{"rss prof dump", sxe2_rss_prof_dump},
		{"rss mask dump", sxe2_rss_mask_dump},
		{"fnav hw sts", sxe2_fwc_fnav_hw_sts},
		{"fnav xlt2 dump", sxe2_fnav_xlt2_dump},
		{"fnav vsig dump", sxe2_fnav_vsig_dump},
		{"fnav prof dump", sxe2_fnav_prof_dump},
		{"fnav mask dump", sxe2_fnav_mask_dump},
		{"fnav stats dump", sxe2_fnav_stats_dump},
#ifdef CONFIG_RFS_ACCEL
		{"arfs stats dump", sxe2_arfs_stats_dump},
#endif
		{"rxft ppe info", sxe2_fwc_rxft_ppe_info},
		{"ppe dfx", sxe2_fwc_ppe_dfx_show},
		{"lldp fw stats", sxe2_lldp_fw_stats},
		{"lldp remote mibs dump", sxe2_lldp_remote_mibs_dump},
		{"cdev show", sxe2_debugfs_cdev_show},
		{"pf state", sxe2_pf_state_get},
		{"lag dump", sxe2_pf_lag_dump},
		{"vf node show", sxe2_vf_nodes_show},
		{"nic type", sxe2_nic_type_dump},

		{"optical_info", sxe2_fw_optical_waring_info_show},
		{"com info", sxe2_com_info},

		{"acl trigger", sxe2_acl_trace_trigger},
		{"acl recorder", sxe2_acl_trace_recorder},
		{"acl dfx", sxe2_acl_dfx_dump},

#ifdef SXE2_CFG_DEBUG
		{"switch dfx irq enable", sxe2_switch_dfx_irq_enable},
		{"switch dfx irq disable", sxe2_switch_dfx_irq_disable},
		{"fnav trigger", sxe2_fwc_fnav_trace_trigger},
		{"fnav recorder", sxe2_fwc_fnav_trace_recorder},
		{"fnav hw clear", sxe2_fnav_hw_clear},
		{"fnav hw replay", sxe2_fnav_hw_replay},
		{"heart close", sxe2_heart_close},
		{"heart open", sxe2_heart_open},
		{"corer trigger", sxe2_corer_trigger},
		{"pfr trigger", sxe2_pfr_trigger},
		{"rx etype rule add", sxe2_etype_rx_rule_add},
		{"rx etype rule del", sxe2_etype_rx_rule_del},
		{"dcbx agent on", sxe2_lldp_dcbx_agent_on},
		{"dcbx agent off", sxe2_lldp_dcbx_agent_off},
		{"dcbx agent status", sxe2_lldp_dcbx_agent_is_on},
		{"dcb show", sxe2_dcb_info_show},
		{"datapath log close", sxe2_datapath_log_close},
		{"datapath log open", sxe2_datapath_log_open},
		{"stats close", sxe2_monitor_stats_close},
		{"stats open", sxe2_monitor_stats_open},
#endif
		{"spoof stats", sxe2_spoof_stats_debugfs_dump},
		{"sdf open", sxe2_sdf_open_test},
		{"sdf close", sxe2_sdf_close_test},
		{"", NULL},

};

static struct sxe2_debugfs_command_arg command_arg[] = {
#ifdef SXE2_CFG_DEBUG
	{"txq drv flag set", 2, {SXE2_DEBUGFS_ARG_NUM, SXE2_DEBUGFS_ARG_ONOFF}, sxe2_ntxq_drv_set},
	{"txq stack flag set", 2, {SXE2_DEBUGFS_ARG_NUM, SXE2_DEBUGFS_ARG_ONOFF},
		sxe2_ntxq_stack_set},
#endif
	{"fnav algo set", 1, {SXE2_DEBUGFS_ARG_NUM}, sxe2_debugfs_fnav_algo_set},
	{"switch algo set", 1, {SXE2_DEBUGFS_ARG_NUM}, sxe2_debugfs_switch_algo_set},
	{"", 0, {0}, NULL},
};

static const char *sxe2_debugfs_arg_type_str(enum sxe2_debugfs_arg_type type)
{
	switch (type) {
	case SXE2_DEBUGFS_ARG_NUM:
		return "num";
	case SXE2_DEBUGFS_ARG_STR:
		return "str";
	case SXE2_DEBUGFS_ARG_ONOFF:
		return "on|off";
	default:
		return "unknown";
	}
}

STATIC s32 sxe2_debugfs_args_parse(struct sxe2_adapter *adapter,
				   const struct sxe2_debugfs_command_arg *cmd,
				   char *args, struct sxe2_debugfs_arg_val *argv)
{
	u32 n = 0;
	char *tok;
	s32 ret;

	while ((tok = strsep(&args, " ")) != NULL) {
		if (*tok == '\0')
			continue;

		if (n >= cmd->argc) {
			LOG_DEV_ERR("command '%s' needs %u args, got more\n",
				    cmd->string, cmd->argc);
			return -EINVAL;
		}

		switch (cmd->argt[n]) {
		case SXE2_DEBUGFS_ARG_NUM:
			ret = kstrtol(tok, 10, &argv[n].num);
			if (ret) {
				LOG_DEV_ERR("arg %u '%s' is not a decimal number\n",
					    n + 1, tok);
				return -EINVAL;
			}
			break;
		case SXE2_DEBUGFS_ARG_STR:
			if (strlen(tok) > SXE2_DEBUGFS_STR_MAX_LEN) {
				LOG_DEV_ERR("arg %u string too long (max %d)\n",
					    n + 1, SXE2_DEBUGFS_STR_MAX_LEN);
				return -EINVAL;
			}
			argv[n].str = tok;
			break;
		case SXE2_DEBUGFS_ARG_ONOFF:
			if (strlen(tok) > SXE2_DEBUGFS_ONOFF_MAX_LEN) {
				LOG_DEV_ERR("arg %u string too long (max %d)\n",
					    n + 1, SXE2_DEBUGFS_ONOFF_MAX_LEN);
				return -EINVAL;
			}

			if (strncmp(tok, "on", 2) == 0) {
				argv[n].on = true;
			} else if (strncmp(tok, "off", 3) == 0) {
				argv[n].on = false;
			} else {
				LOG_DEV_ERR("arg %u string is not on or off\n", n + 1);
				return -EINVAL;
			}

			break;
		default:
			return -EINVAL;
		}

		n++;
	}

	if (n != cmd->argc) {
		LOG_DEV_ERR("command '%s' needs %u args, got %u\n",
			    cmd->string, cmd->argc, n);
		return -EINVAL;
	}

	return 0;
}

static s32 sxe2_debugfs_command_match(struct sxe2_adapter *adapter, s8 *cmd_buf,
				      size_t size)
{
	u32 i;
	size_t verb_len;
	char *args;
	struct sxe2_debugfs_arg_val argv[SXE2_DEBUGFS_ARG_MAX] = {};

	for (i = 0; strlen(command[i].string) != 0; i++) {
		if (!strcmp(cmd_buf, command[i].string)) {
			command[i].debugfs_cb(adapter);
			goto l_end;
		}
	}

	for (i = 0; strlen(command_arg[i].string) != 0; i++) {
		verb_len = strlen(command_arg[i].string);
		if (strncmp(cmd_buf, command_arg[i].string, verb_len) == 0 &&
		    (cmd_buf[verb_len] == '\0' || cmd_buf[verb_len] == ' ')) {
			args = (char *)cmd_buf + verb_len;
			while (*args == ' ')
				args++;

			if (sxe2_debugfs_args_parse(adapter, &command_arg[i],
						    args, argv))
				return -EINVAL;

			command_arg[i].debugfs_cb(adapter, argv);
			goto l_end;
		}
	}

	return -EINVAL;

l_end:
	return 0;
}

static void sxe2_debugfs_command_help_info(struct sxe2_adapter *adapter)
{
	u32 i, j;
	char usage[80];
	int len;

	LOG_DEV_INFO("available commands:\n");

	for (i = 0; strlen(command[i].string) != 0; i++)
		LOG_DEV_INFO("\t %s\n", command[i].string);

	for (i = 0; strlen(command_arg[i].string) != 0; i++) {
		len = scnprintf(usage, sizeof(usage), "%s", command_arg[i].string);
		for (j = 0; j < command_arg[i].argc && j < SXE2_DEBUGFS_ARG_MAX; j++)
			len += scnprintf(usage + len, sizeof(usage) - len,
					 " <%s>",
					 sxe2_debugfs_arg_type_str(command_arg[i].argt[j]));
		LOG_DEV_INFO("\t %s\n", usage);
	}
}

STATIC ssize_t sxe2_debugfs_command_write(struct file *file, const char __user *buf,
					  size_t count, loff_t *ppos)
{
	ssize_t ret;
	s8 *cmd_buf, *cmd_buf_tmp;
	struct sxe2_adapter *adapter = file->private_data;

	if (*ppos != 0) {
		LOG_DEV_ERR(" don't allow partial writes\n, *ppos!=NULL");
		return -EINVAL;
	}

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);

	cmd_buf[count] = '\0';
	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}
	ret = (ssize_t)count;

	if (sxe2_debugfs_command_match(adapter, cmd_buf, count)) {
		LOG_DEV_INFO("unknown or invalid command '%s'\n", cmd_buf);
		sxe2_debugfs_command_help_info(adapter);
		ret = -EINVAL;
	}

	kfree(cmd_buf);
	return ret;
}

static const struct file_operations sxe2_debugfs_command_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = sxe2_debugfs_command_write,
};

void sxe2_debugfs_create_common_file(struct sxe2_adapter *adapter)
{
#if defined(CONFIG_DEBUG_FS) || defined(PCLINT)
	if (IS_ERR(debugfs_create_file("command", 0600, adapter->sxe2_debugfs_pf,
				       adapter, &sxe2_debugfs_command_fops))) {
		LOG_DEV_ERR("debugfs file create failed\n");
	}

	return;
#endif
}

static char *sxe2_com_mode_to_str(enum sxe2_com_module com_mode)
{
	if (com_mode >= ARRAY_SIZE(g_sxe2_com_mode_to_str))
		return "unknown";

	return g_sxe2_com_mode_to_str[com_mode];
}

static s32 sxe2_com_str_to_mode(char *cmd_buf, enum sxe2_com_module *new_mode)
{
	s32 ret;
	u32 i;

	for (i = 0; i < SXE2_COM_MODULE_INVAL; i++) {
		if (!strcmp(cmd_buf, g_sxe2_com_mode_to_str[i])) {
			*new_mode = (enum sxe2_com_module)i;
			ret = 0;
			goto end;
		}
	}

	ret = -EINVAL;

end:
	return ret;
}

STATIC ssize_t sxe2_debugfs_drv_mode_read(struct file *file, char __user *buf,
					  size_t count, loff_t *ppos)
{
	struct sxe2_adapter *adapter = file->private_data;
	struct sxe2_fwc_drv_mode_resp resp = {};
	char tmp_buf[SXE2_COM_MODE_NAME_SIZE];
	ssize_t len = 0;
	s32 ret = 0;

	len = snprintf(tmp_buf, SXE2_COM_MODE_NAME_SIZE, "current mode:%s\n",
		       sxe2_com_mode_to_str(adapter->drv_mode));
	ret = __sxe2_drv_mode_get(adapter, &resp, sizeof(resp));
	len += snprintf(tmp_buf + len, SXE2_COM_MODE_NAME_SIZE - len,
			"configured mode:%s \t",
			ret ? "get failed" : sxe2_com_mode_to_str(resp.drv_mode));
	len += snprintf(tmp_buf + len, SXE2_COM_MODE_NAME_SIZE - len, "\n");

	return simple_read_from_buffer(buf, count, ppos, &tmp_buf, len);
}

STATIC bool sxe2_drv_mode_check(char *cmd_buf)
{
	if ((!strcmp(cmd_buf, SXE2_COM_KERNEL_MODE_NAME)) ||
	    (!strcmp(cmd_buf, SXE2_COM_MIXED_MODE_NAME)) ||
	    (!strcmp(cmd_buf, SXE2_COM_UNDEFINED_MODE_NAME)))
		return true;

	return false;
}

STATIC s32 sxe2_debugfs_drv_mode_set(struct sxe2_adapter *adapter, char *cmd_buf)
{
	s32 ret = 0;
	enum sxe2_com_module new_mode = SXE2_COM_MODULE_INVAL;

	if (sxe2_drv_mode_check(cmd_buf)) {
		ret = sxe2_com_str_to_mode(cmd_buf, &new_mode);
		if (ret) {
			LOG_ERROR_BDF("drv mode buf error.\n");
			goto end;
		}

		ret = sxe2_drv_mode_set(adapter, new_mode);
		if (ret) {
			LOG_ERROR_BDF("drv mode configuration failed.\n");
			goto end;
		}

		LOG_DEV_INFO("current mode:%s configured mode: %s\n",
			     g_sxe2_com_mode_to_str[adapter->drv_mode],
			     g_sxe2_com_mode_to_str[new_mode]);
	} else {
		LOG_DEV_INFO("unknown or invalid drv mode '%s'\n", cmd_buf);
		LOG_DEV_INFO("supported drv mode: %s、%s.\n",
			     SXE2_COM_KERNEL_MODE_NAME, SXE2_COM_MIXED_MODE_NAME);
		ret = -EINVAL;
	}

end:
	return ret;
}

STATIC ssize_t sxe2_debugfs_drv_mode_write(struct file *file, const char __user *buf,
					   size_t count, loff_t *ppos)
{
	ssize_t ret, tmp_ret;
	s8 *cmd_buf, *cmd_buf_tmp;
	struct sxe2_adapter *adapter = file->private_data;

	if (*ppos != 0) {
		LOG_DEV_ERR("don't allow partial writes.\n, *ppos!=NULL");
		return -EINVAL;
	}

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);

	cmd_buf[count] = '\0';
	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	ret = (ssize_t)count;

	tmp_ret = (ssize_t)sxe2_debugfs_drv_mode_set(adapter, cmd_buf);
	if (tmp_ret)
		ret = tmp_ret;

	kfree(cmd_buf);
	return ret;
}

static const struct file_operations sxe2_debugfs_drv_mode_fops = {
		.owner = THIS_MODULE,
		.open = simple_open,
		.read = sxe2_debugfs_drv_mode_read,
		.write = sxe2_debugfs_drv_mode_write,
};

#define SXE2_VF_CFG_LINE_BUF_LEN	64
#define SXE2_VF_CFG_HDR_BUF_LEN		64
STATIC ssize_t sxe2_debugfs_vf_config_read(struct file *file, char __user *buf,
					   size_t count, loff_t *ppos)
{
	struct sxe2_adapter *adapter = file->private_data;
	ssize_t ret;
	ssize_t len = 0;
	u32 buf_size;
	char *tmp_buf;
	bool cfg_exists;
	u16 max_vf_id;
	u16 i;

	buf_size = (u32)adapter->vf_ctxt.max_vfs * SXE2_VF_CFG_LINE_BUF_LEN +
		   SXE2_VF_CFG_HDR_BUF_LEN;
	tmp_buf = kzalloc(buf_size, GFP_KERNEL);
	if (!tmp_buf)
		return -ENOMEM;

	len += scnprintf(tmp_buf + len, buf_size - len,
			 "vf queue config (kernel_q,dpdk_q; empty means no user cfg):\n");

	mutex_lock(&adapter->vf_ctxt.vfs_lock);
	cfg_exists = sxe2_vf_user_cfg_is_set(adapter);
	max_vf_id = adapter->vf_ctxt.large_q.max_vf_id;
	for (i = 0; cfg_exists && i <= max_vf_id; i++) {
		u16 kernel_cfg = SXE2_VF_USR_CFG(adapter, i)->product[SXE2_PRODUCT_ID_KERNEL].q_cfg;
		u16 dpdk_cfg = SXE2_VF_USR_CFG(adapter, i)->product[SXE2_PRODUCT_ID_DPDK].q_cfg;
		char kernel_str[10] = "Unset";
		char dpdk_str[10] = "Unset";
		char vf_str[8];

		if (!kernel_cfg && !dpdk_cfg)
			continue;
		if (kernel_cfg)
			(void)scnprintf(kernel_str, sizeof(kernel_str), "%u", kernel_cfg);
		if (dpdk_cfg)
			(void)scnprintf(dpdk_str, sizeof(dpdk_str), "%u", dpdk_cfg);
		(void)scnprintf(vf_str, sizeof(vf_str), "vf%u:", i);

		len += scnprintf(tmp_buf + len, buf_size - len,
				 "%-5s kernel_q_cfg:%-5s dpdk_q_cfg:%s\n",
				 vf_str, kernel_str, dpdk_str);
	}
	mutex_unlock(&adapter->vf_ctxt.vfs_lock);

	ret = simple_read_from_buffer(buf, count, ppos, tmp_buf, len);
	kfree(tmp_buf);

	return ret;
}

struct sxe2_usr_input_ctxt {
	u16 *kernel_usr_q;
	u16 *dpdk_usr_q;
	unsigned long *listed_vf_bmap;
	u16 max_vf_id;
	u16 large_q_cfg;
	u16 explicit_queues;
	u16 unconfigured_slots;
	u16 per_slot;
};

static struct sxe2_usr_input_ctxt *sxe2_vf_config_ctx_alloc(void)
{
	struct sxe2_usr_input_ctxt *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->kernel_usr_q = kcalloc(SXE2_VF_NUM, sizeof(*ctx->kernel_usr_q), GFP_KERNEL);
	ctx->dpdk_usr_q = kcalloc(SXE2_VF_NUM, sizeof(*ctx->dpdk_usr_q), GFP_KERNEL);
	ctx->listed_vf_bmap = bitmap_zalloc(SXE2_VF_NUM, GFP_KERNEL);
	if (!ctx->kernel_usr_q || !ctx->dpdk_usr_q || !ctx->listed_vf_bmap) {
		bitmap_free(ctx->listed_vf_bmap);
		kfree(ctx->dpdk_usr_q);
		kfree(ctx->kernel_usr_q);
		kfree(ctx);
		return NULL;
	}

	return ctx;
}

static void sxe2_vf_config_ctx_free(struct sxe2_usr_input_ctxt *ctx)
{
	if (!ctx)
		return;

	bitmap_free(ctx->listed_vf_bmap);
	kfree(ctx->dpdk_usr_q);
	kfree(ctx->kernel_usr_q);
	kfree(ctx);
}

static s32 sxe2_vf_config_vf_range_parse(struct sxe2_adapter *adapter,
					 char *vf_str, u16 *vf_start, u16 *vf_end)
{
	if (strchr(vf_str, '-')) {
		if (sscanf(vf_str, "%hu-%hu", vf_start, vf_end) != 2) {
			LOG_DEV_ERR("invalid vf range: %s\n", vf_str);
			return -EINVAL;
		}
	} else {
		if (kstrtou16(vf_str, 10, vf_start)) {
			LOG_DEV_ERR("invalid vf id: %s\n", vf_str);
			return -EINVAL;
		}
		*vf_end = *vf_start;
	}

	return 0;
}

static s32 sxe2_vf_config_queue_num_parse(struct sxe2_adapter *adapter,
					  char *q_str, u16 *kernel_q, u16 *dpdk_q)
{
	char *kq, *dq;
	int err;

	*kernel_q = 0;
	*dpdk_q = 0;
	if (!strchr(q_str, ',')) {
		LOG_DEV_ERR("queue config must be kernel,dpdk form: %s\n", q_str);
		return -EINVAL;
	}

	kq = strsep(&q_str, ",");
	dq = q_str;
	if (*kq) {
		err = kstrtou16(kq, 10, kernel_q);
		if (err) {
			LOG_DEV_ERR("invalid kernel queue: %s\n", kq);
			return -EINVAL;
		}
		if (!*kernel_q) {
			LOG_DEV_ERR("kernel queue 0 invalid, leave empty for default\n");
			return -EINVAL;
		}
	}
	if (*dq) {
		err = kstrtou16(dq, 10, dpdk_q);
		if (err) {
			LOG_DEV_ERR("invalid dpdk queue: %s\n", dq);
			return -EINVAL;
		}
		if (!*dpdk_q) {
			LOG_DEV_ERR("dpdk queue 0 invalid, leave empty for default\n");
			return -EINVAL;
		}
	}

	if (!*kernel_q && !*dpdk_q) {
		LOG_DEV_ERR("kernel and dpdk queue both empty\n");
		return -EINVAL;
	}

	return 0;
}

static s32 sxe2_vf_config_input_parse(struct sxe2_adapter *adapter,
				      char *cmd_buf,
				      struct sxe2_usr_input_ctxt *ctx)
{
	char *token, *cur = cmd_buf;
	char *vf_str, *q_str;
	u16 vf_start = 0, vf_end = 0, vf_id;
	u16 kernel_q, dpdk_q;

	while ((token = strsep(&cur, ";")) != NULL) {
		if (!*token)
			continue;

		vf_str = strsep(&token, ":");
		q_str = token;
		if (!vf_str || !q_str) {
			LOG_DEV_ERR("invalid format, expected {vf_id}:{kernel_q},{dpdk_q}\n");
			return -EINVAL;
		}

		if (sxe2_vf_config_vf_range_parse(adapter, vf_str, &vf_start, &vf_end))
			return -EINVAL;

		if (vf_start > vf_end || vf_end >= adapter->vf_ctxt.max_vfs) {
			LOG_DEV_ERR("vf range %u-%u invalid, max vfs capability %u\n",
				    vf_start, vf_end, adapter->vf_ctxt.max_vfs);
			return -EINVAL;
		}

		if (sxe2_vf_config_queue_num_parse(adapter, q_str, &kernel_q, &dpdk_q))
			return -EINVAL;

		if (kernel_q > SXE2_VF_KERNEL_Q_CFG_MAX ||
		    dpdk_q > SXE2_VF_DPDK_Q_NUM) {
			LOG_DEV_ERR("queue num too large, kernel_q:%u(max:%u) dpdk_q:%u(max:%u)\n",
				    kernel_q, SXE2_VF_KERNEL_Q_CFG_MAX,
				    dpdk_q, SXE2_VF_DPDK_Q_NUM);
			return -EINVAL;
		}

		if (vf_end > ctx->max_vf_id)
			ctx->max_vf_id = vf_end;
		for (vf_id = vf_start; vf_id <= vf_end; vf_id++) {
			if (test_and_set_bit(vf_id, ctx->listed_vf_bmap)) {
				LOG_DEV_ERR("vf %u duplicate or overlapped config\n", vf_id);
				return -EINVAL;
			}

			if (vf_id >= SXE2_VF_LARGE_Q_VF_NUM_MAX &&
			    (kernel_q > SXE2_VSI_LUT_MAX_QUEUE ||
			     dpdk_q > SXE2_VF_LARGE_Q_DPDK_Q_MAX)) {
				LOG_DEV_ERR("vf %u not allowed kernel_q > %u or dpdk_q > %u when "
					    "vf num exceeds %u, kernel_q:%u dpdk_q:%u\n",
					    vf_id, SXE2_VSI_LUT_MAX_QUEUE,
					    SXE2_VF_LARGE_Q_DPDK_Q_MAX,
					    SXE2_VF_LARGE_Q_VF_NUM_MAX,
					    kernel_q, dpdk_q);
				return -EINVAL;
			}

			ctx->kernel_usr_q[vf_id] = kernel_q;
			ctx->dpdk_usr_q[vf_id] = dpdk_q;

			if (kernel_q > SXE2_VSI_LUT_MAX_QUEUE)
				ctx->large_q_cfg++;
			if (dpdk_q > SXE2_VSI_LUT_MAX_QUEUE)
				ctx->large_q_cfg++;

			if (kernel_q > 0)
				ctx->explicit_queues += kernel_q;
			else
				ctx->unconfigured_slots++;

			if (dpdk_q > 0)
				ctx->explicit_queues += dpdk_q;
			else
				ctx->unconfigured_slots++;
		}
	}

	if (!bitmap_weight(ctx->listed_vf_bmap, SXE2_VF_NUM)) {
		LOG_DEV_ERR("no valid vf config entry\n");
		return -EINVAL;
	}

	for (vf_id = 0; vf_id <= ctx->max_vf_id; vf_id++) {
		if (!test_bit(vf_id, ctx->listed_vf_bmap))
			ctx->unconfigured_slots += SXE2_PRODUCT_ID_NR;
	}

	return 0;
}

static void sxe2_vf_config_lut_release(struct sxe2_adapter *adapter,
				       struct sxe2_usr_input_ctxt *ctx)
{
	struct sxe2_vf_usr_cfg *usr_cfg;
	u16 i;
	u8 v;

	for (i = 0; i <= ctx->max_vf_id; i++) {
		usr_cfg = SXE2_VF_USR_CFG(adapter, i);

		for (v = 0; v < SXE2_PRODUCT_ID_NR; v++)
			sxe2_global_lut_put(adapter,
					    usr_cfg->product[v].lut_id);

		memset(usr_cfg, 0, sizeof(*usr_cfg));
		for (v = 0; v < SXE2_PRODUCT_ID_NR; v++) {
			usr_cfg->product[v].lut_id =
				SXE2_VF_GLOBAL_LUT_INVALID_ID;
			usr_cfg->product[v].lut_type = SXE2_RSS_VSI_LUT;
			usr_cfg->product[v].lut_size = SXE2_RSS_LUT_SIZE_64;
		}
	}
}

static s32 sxe2_vf_config_lut_apply(struct sxe2_adapter *adapter,
				    struct sxe2_usr_input_ctxt *ctx)
{
	struct sxe2_vf_usr_cfg *usr_cfg;
	u8 lut_ids[SXE2_RSS_GLOBAL_LUT_NUM_MAX];
	u16 lut_idx = 0;
	u16 vf_id;
	u8 v;

	if (ctx->large_q_cfg &&
	    !sxe2_global_lut_get_bulk(adapter, ctx->large_q_cfg, lut_ids)) {
		LOG_DEV_ERR("need %u global lut, but not enough available\n",
			    ctx->large_q_cfg);
		return -EINVAL;
	}

	for (vf_id = 0; vf_id <= ctx->max_vf_id; vf_id++) {
		usr_cfg = SXE2_VF_USR_CFG(adapter, vf_id);

		if (!test_bit(vf_id, ctx->listed_vf_bmap)) {
			for (v = 0; v < SXE2_PRODUCT_ID_NR; v++) {
				usr_cfg->product[v].q_cfg = 0;
				usr_cfg->product[v].lut_id =
					SXE2_VF_GLOBAL_LUT_INVALID_ID;
				usr_cfg->product[v].lut_type = SXE2_RSS_VSI_LUT;
				usr_cfg->product[v].lut_size =
					SXE2_RSS_LUT_SIZE_64;
			}
			continue;
		}

		for (v = 0; v < SXE2_PRODUCT_ID_NR; v++) {
			u16 q = (v == SXE2_PRODUCT_ID_KERNEL) ? ctx->kernel_usr_q[vf_id] :
							     ctx->dpdk_usr_q[vf_id];

			usr_cfg->product[v].q_cfg = q;

			if (q > SXE2_VSI_LUT_MAX_QUEUE) {
				usr_cfg->product[v].lut_id = lut_ids[lut_idx++];
				usr_cfg->product[v].lut_type = SXE2_RSS_GLOBAL_LUT;
				usr_cfg->product[v].lut_size =
					SXE2_RSS_LUT_SIZE_512;
			} else {
				usr_cfg->product[v].lut_id =
					SXE2_VF_GLOBAL_LUT_INVALID_ID;
				usr_cfg->product[v].lut_type = SXE2_RSS_VSI_LUT;
				usr_cfg->product[v].lut_size =
					SXE2_RSS_LUT_SIZE_64;
			}
		}
		usr_cfg->configured = true;
	}

	return 0;
}

static s32 sxe2_vf_config_queue_apply(struct sxe2_adapter *adapter,
				      struct sxe2_usr_input_ctxt *ctx)
{
	u16 txq_idle, rxq_idle;
	u16 total_avail;
	u16 occupied_q_total;
	s32 ret = 0;

	mutex_lock(&adapter->q_ctxt.lock);

	txq_idle = sxe2_sriov_qs_avail_nums_get(adapter, SXE2_DATA_TQ);
	rxq_idle = sxe2_sriov_qs_avail_nums_get(adapter, SXE2_DATA_RQ);
	total_avail = min_t(u16, txq_idle, rxq_idle);

	if (ctx->explicit_queues > total_avail) {
		LOG_DEV_ERR("explicit queues %u exceed available %u\n",
			    ctx->explicit_queues, total_avail);
		ret = -ENOSPC;
		goto l_unlock;
	}

	if (ctx->unconfigured_slots > 0) {
		ctx->per_slot = (unsigned int)(total_avail - ctx->explicit_queues) /
				ctx->unconfigured_slots;
		if (ctx->per_slot < SXE2_VF_QUEUE_CNT_MIN) {
			LOG_DEV_ERR("queue resource not enough, per_slot:%u min:%u\n",
				    ctx->per_slot, SXE2_VF_QUEUE_CNT_MIN);
			ret = -ENOSPC;
			goto l_unlock;
		}
		ctx->per_slot = min_t(u16, ctx->per_slot, SXE2_VSI_LUT_MAX_QUEUE);
	}

	occupied_q_total = ctx->explicit_queues +
		      ctx->unconfigured_slots * ctx->per_slot;
	bitmap_set(adapter->q_ctxt.rxq_layout.rxq_map,
		   adapter->q_ctxt.max_rxq_cnt - occupied_q_total, occupied_q_total);
	bitmap_set(adapter->q_ctxt.txq_layout.txq_map,
		   adapter->q_ctxt.max_txq_cnt - occupied_q_total, occupied_q_total);

	adapter->vf_ctxt.large_q.occupied_q_cnt = occupied_q_total;
	adapter->vf_ctxt.large_q.spare_q = ctx->unconfigured_slots * ctx->per_slot;
	adapter->vf_ctxt.large_q.max_vf_id = ctx->max_vf_id;

l_unlock:
	mutex_unlock(&adapter->q_ctxt.lock);
	return ret;
}

STATIC s32 sxe2_debugfs_vf_config(struct sxe2_adapter *adapter, char *cmd_buf)
{
	struct sxe2_usr_input_ctxt *ctx;
	s32 ret;

	ctx = sxe2_vf_config_ctx_alloc();
	if (!ctx)
		return -ENOMEM;

	mutex_lock(&adapter->vf_ctxt.vfs_lock);

	if (sxe2_vf_user_cfg_is_set(adapter)) {
		LOG_DEV_ERR("vf queue config already exists, please echo clear first.\n");
		ret = -EBUSY;
		goto l_unlock;
	}

	if (adapter->vf_ctxt.num_vfs > 0) {
		LOG_DEV_ERR("vfs exist, please echo 0 to sriov_numvfs first.\n");
		ret = -EBUSY;
		goto l_unlock;
	}

	ret = sxe2_vf_config_input_parse(adapter, cmd_buf, ctx);
	if (ret)
		goto l_unlock;

	ret = sxe2_vf_config_lut_apply(adapter, ctx);
	if (ret)
		goto l_lut_release;

	ret = sxe2_vf_config_queue_apply(adapter, ctx);
	if (ret)
		goto l_lut_release;

	LOG_INFO_BDF("vf queue config saved, need %u global lut\n",
		     ctx->large_q_cfg);
	goto l_unlock;

l_lut_release:
	sxe2_vf_config_lut_release(adapter, ctx);

l_unlock:
	mutex_unlock(&adapter->vf_ctxt.vfs_lock);
	sxe2_vf_config_ctx_free(ctx);
	return ret;
}

static s32 sxe2_debugfs_vf_config_clear(struct sxe2_adapter *adapter)
{
	struct sxe2_vf_usr_cfg *usr_cfg;
	u16 occupied_q_total;
	u16 i;
	u8 v;

	mutex_lock(&adapter->vf_ctxt.vfs_lock);

	if (adapter->vf_ctxt.num_vfs > 0) {
		LOG_DEV_ERR("vfs exist, please echo 0 to sriov_numvfs first.\n");
		mutex_unlock(&adapter->vf_ctxt.vfs_lock);
		return -EBUSY;
	}

	occupied_q_total = adapter->vf_ctxt.large_q.occupied_q_cnt;

	if (occupied_q_total) {
		mutex_lock(&adapter->q_ctxt.lock);
		bitmap_clear(adapter->q_ctxt.rxq_layout.rxq_map,
			     adapter->q_ctxt.max_rxq_cnt - occupied_q_total,
			     occupied_q_total);
		bitmap_clear(adapter->q_ctxt.txq_layout.txq_map,
			     adapter->q_ctxt.max_txq_cnt - occupied_q_total,
			     occupied_q_total);
		adapter->q_ctxt.txq_layout.sriov = 0;
		adapter->q_ctxt.txq_layout.sriov_offset =
			adapter->q_ctxt.max_txq_cnt;
		adapter->q_ctxt.rxq_layout.sriov = 0;
		adapter->q_ctxt.rxq_layout.sriov_offset =
			adapter->q_ctxt.max_rxq_cnt;
		mutex_unlock(&adapter->q_ctxt.lock);
	}

	for (i = 0; i < SXE2_VF_NUM; i++) {
		usr_cfg = SXE2_VF_USR_CFG(adapter, i);

		for (v = 0; v < SXE2_PRODUCT_ID_NR; v++)
			sxe2_global_lut_put(adapter,
					    usr_cfg->product[v].lut_id);

		memset(usr_cfg, 0, sizeof(*usr_cfg));
		for (v = 0; v < SXE2_PRODUCT_ID_NR; v++) {
			usr_cfg->product[v].lut_id =
				SXE2_VF_GLOBAL_LUT_INVALID_ID;
			usr_cfg->product[v].lut_type = SXE2_RSS_VSI_LUT;
			usr_cfg->product[v].lut_size = SXE2_RSS_LUT_SIZE_64;
		}
	}
	adapter->vf_ctxt.large_q.occupied_q_cnt = 0;
	adapter->vf_ctxt.large_q.spare_q = 0;
	adapter->vf_ctxt.large_q.extra_q_cnt = 0;
	adapter->vf_ctxt.large_q.max_vf_id = 0;
	mutex_unlock(&adapter->vf_ctxt.vfs_lock);

	return 0;
}

STATIC ssize_t sxe2_debugfs_vf_config_write(struct file *file,
					    const char __user *buf,
					    size_t count, loff_t *ppos)
{
	struct sxe2_adapter *adapter = file->private_data;
	char *cmd_buf;
	ssize_t ret;

	cmd_buf = kzalloc(count + 1, GFP_KERNEL);
	if (!cmd_buf)
		return -ENOMEM;

	if (copy_from_user(cmd_buf, buf, count)) {
		kfree(cmd_buf);
		return -EFAULT;
	}

	cmd_buf[count] = '\0';

	if (count > 0 && cmd_buf[count - 1] == '\n')
		cmd_buf[count - 1] = '\0';

	if (!strcmp(cmd_buf, "clear")) {
		ret = sxe2_debugfs_vf_config_clear(adapter);
		if (!ret) {
			LOG_INFO_BDF("vf queue config cleared.\n");
			ret = count;
		}
	} else {
		ret = sxe2_debugfs_vf_config(adapter, cmd_buf);
		if (!ret)
			ret = count;
	}

	kfree(cmd_buf);
	return ret;
}

static const struct file_operations sxe2_debugfs_vf_config_fops = {
		.owner = THIS_MODULE,
		.open = simple_open,
		.read = sxe2_debugfs_vf_config_read,
		.write = sxe2_debugfs_vf_config_write,
};

static void sxe2_debugfs_create_vf_config_file(struct sxe2_adapter *adapter)
{
#if defined(CONFIG_DEBUG_FS) || defined(PCLINT)
	if (IS_ERR(debugfs_create_file("vf_config", 0600, adapter->sxe2_debugfs_pf,
				       adapter, &sxe2_debugfs_vf_config_fops))) {
		LOG_DEV_ERR("debugfs vf_config file create failed\n");
	}
#endif
}

void sxe2_debugfs_create_drv_mode_file(struct sxe2_adapter *adapter)
{
#if defined(CONFIG_DEBUG_FS) || defined(PCLINT)
	if (IS_ERR(debugfs_create_file("drv_mode", 0600, adapter->sxe2_debugfs_pf,
				       adapter, &sxe2_debugfs_drv_mode_fops))) {
		LOG_DEV_ERR("debugfs file create failed\n");
	}

	return;
#endif
}

void sxe2_debugfs_pf_init(struct sxe2_adapter *adapter)
{
#if defined(CONFIG_DEBUG_FS) || defined(PCLINT)
	const char *name = pci_name(adapter->pdev);

	adapter->sxe2_debugfs_pf = debugfs_create_dir(name, sxe2_debugfs_root);
	if (IS_ERR(adapter->sxe2_debugfs_pf)) {
		LOG_ERROR("init of pf debugfs failed\n");
		goto l_end;
	}

	sxe2_debugfs_create_common_file(adapter);
	sxe2_debugfs_create_drv_mode_file(adapter);
	sxe2_debugfs_create_vf_config_file(adapter);

l_end:
	return;
#endif
}

void sxe2_debugfs_pf_exit(struct sxe2_adapter *adapter)
{
#if defined(CONFIG_DEBUG_FS) || defined(PCLINT)
	debugfs_remove_recursive(adapter->sxe2_debugfs_pf);
	adapter->sxe2_debugfs_pf = NULL;
#endif
}

void sxe2_debugfs_init(void)
{
	sxe2_debugfs_root = debugfs_create_dir(SXE2_DRV_NAME, NULL);
	if (IS_ERR(sxe2_debugfs_root))
		LOG_ERROR_D("init of debugfs failed.\n");
	else
		LOG_INFO_D("init of debugfs success.\n");
}

void sxe2_debugfs_exit(void)
{
	debugfs_remove_recursive(sxe2_debugfs_root);
	sxe2_debugfs_root = NULL;
}
