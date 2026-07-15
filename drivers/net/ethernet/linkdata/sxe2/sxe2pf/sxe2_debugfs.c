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
#include <linux/cpu_rmap.h>
#include <linux/cpumask.h>
#include <linux/atomic.h>

#include "sxe2.h"
#include "sxe2_log.h"
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

	LOG_DEV_INFO("\t vf node show start.\n");

	LOG_DEV_INFO("\t adapter.vf_ctxt.irq_cnt=%d\n", adapter->vf_ctxt.irq_cnt);
	LOG_DEV_INFO("\t adapter.vf_ctxt.max_vfs=%d\n", adapter->vf_ctxt.max_vfs);
	LOG_DEV_INFO("\t adapter.vf_ctxt.num_vfs=%d\n", adapter->vf_ctxt.num_vfs);
	LOG_DEV_INFO("\t adapter.vf_ctxt.q_cnt=%d\n", adapter->vf_ctxt.q_cnt);
	LOG_DEV_INFO("\t adapter.vf_ctxt.vfid_base=%d\n",
		     adapter->vf_ctxt.vfid_base);

	mutex_lock(&adapter->vf_ctxt.vfs_lock);

	for (vf_idx = 0; vf_idx < adapter->vf_ctxt.num_vfs; vf_idx++) {
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		vf_node_e = SXE2_VF_NODE_E(adapter, vf_idx);

		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d]\n", vf_idx);
		LOG_DEV_INFO("\t adapter.vf_ctxt.vf_node_e[%d].irq_base_idx=%d\n",
			     vf_idx, vf_node_e->vf_node->irq_base_idx);
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

		if (vf_node_e->vf_node->vsi)
			sxe2_vsi_dump(vf_node_e->vf_node->vsi);
		else if (vf_node_e->vf_node->dpdk_vf_vsi)
			sxe2_vsi_dump(vf_node_e->vf_node->dpdk_vf_vsi);
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
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
	s32 ret = 0;

	ret = sxe2_fnav_rule_reply(adapter);
	if (ret)
		LOG_DEV_ERR("fnav rule failed, ret:%d\n", ret);
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
		LOG_DEV_ERR("get fw optical vendor info cmd fail, ret=%d\n", ret);
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
#endif

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
		{"", NULL},
};

static s32 sxe2_debugfs_command_match(struct sxe2_adapter *adapter, s8 *cmd_buf,
				      size_t size)
{
	u32 i;

	for (i = 0; strlen(command[i].string) != 0; i++) {
		if (!strcmp(cmd_buf, command[i].string)) {
			command[i].debugfs_cb(adapter);
			goto l_end;
		}
	}

	return -EINVAL;

l_end:
	return 0;
}

static void sxe2_debugfs_command_help_info(struct sxe2_adapter *adapter)
{
	u32 i;

	LOG_DEV_INFO("available commands:\n");

	for (i = 0; strlen(command[i].string) != 0; i++)
		LOG_DEV_INFO("\t %s\n", command[i].string);
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
			LOG_ERROR_BDF("drv mode configurate failed.\n");
			goto end;
		}

		LOG_DEV_INFO("current mode:%s configured mode: %s\n",
			     g_sxe2_com_mode_to_str[adapter->drv_mode],
			     g_sxe2_com_mode_to_str[new_mode]);
	} else {
		LOG_DEV_INFO("unknown or invalid command '%s'\n", cmd_buf);
		LOG_DEV_INFO("supported commands: %s、%s.\n",
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
		LOG_DEV_ERR("dont't allow partial writes.\n, *ppos!=NULL");
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
