// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include <linux/module.h>
#include "mcevf.h"
#include "mcevf_irq.h"
#include "mcevf_lib.h"
#include "mcevf_base.h"
#include "mcevf_netdev.h"
#include "mcevf_fltr.h"
#include "mcevf_virtchnl.h"
#include "mcevf_version.h"
#include <linux/inetdevice.h>

/* Device IDs */
#ifndef PCI_VENDOR_ID_MUCSE
#define PCI_VENDOR_ID_MUCSE 0x8848
#endif /* PCI_VENDOR_ID_MUCSE */

#define PCI_DEVICE_ID_N20 0x8503
#define PCI_DEVICE_ID_B850 0x850a

/* bar number */
#define MCEVF_NIC_BAR_N20 4
#define MCEVF_RDMA_BAR_N20 2

MODULE_AUTHOR("Mucse Corporation, <mucse@mucse.com>");
MODULE_DESCRIPTION("Mucse(R) 1/10/25/40/100 Gigabit PCI Express Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

static int debug = -1;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "netif level (0=none,...,16=all)");

static struct pci_device_id mcevf_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MUCSE, PCI_DEVICE_ID_N20),
	  .driver_data = board_n20 },
	{ PCI_DEVICE(PCI_VENDOR_ID_MUCSE, PCI_DEVICE_ID_B850),
	  .driver_data = board_n20 },
	/* required last entry */
	{ 0 }
};
MODULE_DEVICE_TABLE(pci, mcevf_pci_tbl);

static unsigned int tun_inner;
module_param(tun_inner, uint, 0000);
MODULE_PARM_DESC(tun_inner,
		 "parse tunnel packet by inner layer(0: outer layer, 1: inner layer, default: 0)");

static unsigned int probe_with_aux;
module_param(probe_with_aux, uint, 0000);
MODULE_PARM_DESC(probe_with_aux,
		 "probe aux for mrdma(0: no, 1: yes, default: 0)");

struct workqueue_struct *mcevf_wq;

/**
 * mcevf_hw_to_dev - Get device pointer from the hardware structure
 * @hw: pointer to the device HW structure
 *
 * Used to access the device pointer from compilation units which can't easily
 * include the definition of struct mcevf_pf without leading to circular header
 * dependencies.
 */
struct device *mcevf_hw_to_dev(struct mcevf_hw *hw)
{
	struct mcevf_pf *pf = container_of(hw, struct mcevf_pf, hw);

	return &pf->pdev->dev;
}

/**
 * mcevf_service_task_schedule - schedule the service task to wake up
 * @pf: board private structure
 *
 * If not already scheduled, this puts the task into the work queue.
 */
void mcevf_service_task_schedule(struct mcevf_pf *pf)
{
	if (!test_bit(MCEVF_SERVICE_DIS, pf->state) &&
	    !test_and_set_bit(MCEVF_SERVICE_SCHED, pf->state) &&
	    !test_bit(MCEVF_NEEDS_RESTART, pf->state))
		queue_work(mcevf_wq, &pf->serv_task);
}

/**
 * mcevf_service_task_complete - finish up the service task
 * @pf: board private structure
 */
static void mcevf_service_task_complete(struct mcevf_pf *pf)
{
	/* force memory (pf->state) to sync before next service task */
	smp_mb__before_atomic();
	clear_bit(MCEVF_SERVICE_SCHED, pf->state);
}

/**
 * mcevf_service_task_stop - stop service task and cancel works
 * @pf: board private structure
 *
 * Return 0 if the MCEVF_SERVICE_DIS bit was not already set,
 * 1 otherwise.
 */
static int mcevf_service_task_stop(struct mcevf_pf *pf)
{
	int ret;

	ret = test_and_set_bit(MCEVF_SERVICE_DIS, pf->state);

	if (pf->serv_tmr.function) {
		pf->serv_tmr_ticks = 0;
		del_timer_sync(&pf->serv_tmr);
	}

	if (pf->serv_task.func)
		cancel_work_sync(&pf->serv_task);

	clear_bit(MCEVF_SERVICE_SCHED, pf->state);
	return ret;
}

/**
 * mcevf_handle_drop_intr - timer callback to handle tx drop interrupts
 * @pf: pointer to struct pf
 */
static void mcevf_handle_drop_intr(struct mcevf_pf *pf)
{
	struct mcevf_vsi *vsi = mcevf_get_main_vsi(pf);
	struct mcevf_hw *hw = &pf->hw;
	int i;

	if (!pf->drop_intr_timer_en)
		return;
	if (test_bit(MCEVF_SHUTTING_DOWN, pf->state) ||
	    test_bit(MCEVF_VSI_DOWN, vsi->state))
		return;
	mcevf_for_each_q_vector(vsi, i) {
		struct mcevf_q_vector *q_vector = vsi->q_vectors[i];
		struct mcevf_ring *tx_ring;

		if (!q_vector)
			continue;
		/* If ticks have not changed, check whether the software ring has
		 * been cleaned and used to determine whether Tx interrupts dropped.
		 */
		if (q_vector->ticks == q_vector->old_ticks) {
			mcevf_rc_for_each_ring(tx_ring, q_vector->tx) {
				if (!tx_ring)
					continue;
				if (tx_ring->next_to_clean !=
				    tx_ring->next_to_use) {
					hw->ops->set_txring_trig_intr(tx_ring);
					tx_ring->ring_stats->tx_stats
						.period_intr_drop++;
				}
			}
		} else {
			q_vector->old_ticks = q_vector->ticks;
		}
	}
}

/**
 * mcevf_service_timer - timer callback to schedule service task
 * @t: pointer to timer_list
 */
static void mcevf_service_timer(struct timer_list *t)
{
	struct mcevf_pf *pf = from_timer(pf, t, serv_tmr);

	mcevf_handle_drop_intr(pf);
	mod_timer(&pf->serv_tmr, round_jiffies(pf->serv_tmr_period + jiffies));

	if (pf->serv_tmr_ticks % pf->serv_tmr_max_cnt == 0)
		mcevf_service_task_schedule(pf);
	pf->serv_tmr_ticks++;
}

/**
 * mcevf_vsi_fltr_changed - check if filter state changed
 * @vsi: VSI to be checked
 *
 * returns true if filter state has changed, false otherwise.
 */
static bool mcevf_vsi_fltr_changed(struct mcevf_vsi *vsi)
{
	return test_bit(MCEVF_VSI_UMAC_FLTR_CHANGED, vsi->state) ||
	       test_bit(MCEVF_VSI_MMAC_FLTR_CHANGED, vsi->state);
}

/**
 * mcevf_vsi_sync_fltr - Update the VSI filter list to the HW
 * @vsi: ptr to the VSI
 *
 * Push any outstanding VSI filter changes through the AdminQ.
 */
static int mcevf_vsi_sync_fltr(struct mcevf_vsi *vsi)
{
	struct net_device *netdev = vsi->netdev;
	struct mcevf_pf *pf = vsi->back;
	struct mcevf_hw *hw = &pf->hw;

	if (!vsi->netdev)
		return -EINVAL;

	vsi->changed_flags = vsi->current_netdev_flags ^ vsi->netdev->flags;
	vsi->current_netdev_flags = vsi->netdev->flags;

	if (mcevf_vsi_fltr_changed(vsi)) {
		clear_bit(MCEVF_VSI_UMAC_FLTR_CHANGED, vsi->state);
		clear_bit(MCEVF_VSI_MMAC_FLTR_CHANGED, vsi->state);

		/* grab the netdev's addr_list_lock */
		netif_addr_lock_bh(netdev);
		__dev_uc_sync(netdev, mcevf_add_uc_filter, mcevf_del_uc_filter);
		__dev_mc_sync(netdev, mcevf_add_mc_filter, mcevf_del_mc_filter);
		/* our temp lists are populated. release lock */
		netif_addr_unlock_bh(netdev);
	}

	if (vsi->changed_flags & IFF_ALLMULTI) {
		if (vsi->current_netdev_flags & IFF_ALLMULTI)
			hw->ops->set_mc_promisc(hw, true);
		else
			hw->ops->set_mc_promisc(hw, false);
	}

	if (vsi->changed_flags & IFF_PROMISC) {
		if (vsi->current_netdev_flags & IFF_PROMISC) {
			hw->ops->set_uc_promisc(hw, true);
			hw->ops->set_mc_promisc(hw, true);
			hw->ops->set_vlan_promisc(hw, true);
		} else {
			if (vsi->current_netdev_flags & IFF_ALLMULTI)
				hw->ops->set_mc_promisc(hw, true);
			else
				hw->ops->set_mc_promisc(hw, false);
			hw->ops->set_uc_promisc(hw, false);
			hw->ops->set_vlan_promisc(hw, false);
		}
	}
	return 0;
}

/**
 * mcevf_sync_fltr_subtask - Sync the VSI filter list with HW
 * @pf: board private structure
 */
static void mcevf_sync_fltr_subtask(struct mcevf_pf *pf)
{
	int v;

	if (!pf || !(test_bit(MCEVF_FLAG_FLTR_SYNC, pf->flags)))
		return;

	clear_bit(MCEVF_FLAG_FLTR_SYNC, pf->flags);

	mcevf_for_each_vsi(pf, v) {
		if (pf->vsi[v] && mcevf_vsi_fltr_changed(pf->vsi[v]) &&
		    mcevf_vsi_sync_fltr(pf->vsi[v])) {
			/* come back and try again later */
			set_bit(MCEVF_FLAG_FLTR_SYNC, pf->flags);
			break;
		}
	}
}

/**
 * mcevf_sync_vlan_subtask - Sync the VSI filter list with HW
 * @pf: board private structure
 */
static void mcevf_sync_vlan_subtask(struct mcevf_pf *pf)
{
	struct mcevf_hw *hw = &pf->hw;
	struct net_device *netdev = mcevf_hw_to_netdev(hw);

	if (!pf || !(test_bit(MCEVF_FLAG_PF_UPDATE_VLAN, pf->flags)))
		return;

	clear_bit(MCEVF_FLAG_PF_UPDATE_VLAN, pf->flags);
	mcevf_mbx_handle_pf_vlan(hw, pf->vf_vlan);
	hw->ops->set_vlan_strip(hw, netdev->features);
}

static void mcevf_sync_fcs_subtask(struct mcevf_pf *pf)
{
	struct mcevf_vsi *vsi;
	struct net_device *netdev;

	if (!pf || !test_and_clear_bit(MCEVF_FLAG_PF_UPDATE_FCS, pf->flags))
		return;

	vsi = mcevf_get_main_vsi(pf);
	if (!vsi || !vsi->netdev)
		return;

	netdev = vsi->netdev;
	rtnl_lock();
	if (test_bit(MCEVF_FLAG_NETDEV_STATE_FCS_ENA, pf->flags))
		netdev->features |= NETIF_F_RXFCS;
	else
		netdev->features &= ~NETIF_F_RXFCS;
	rtnl_unlock();
}

static void mcevf_pf_reset_subtask(struct mcevf_pf *pf)
{
	struct mcevf_hw *hw;
	struct net_device *netdev;
	struct mcevf_netdev_priv *np;
	struct mcevf_vsi *vsi;
	int ret = 0;

	if (!pf || !mcevf_pf_flags_reset_get(pf) ||
	    !test_bit(MCEVF_FLAG_VF_NDO_OPENED, pf->flags))
		return;

	hw = &pf->hw;
	netdev = mcevf_hw_to_netdev(hw);
	np = netdev_priv(netdev);
	vsi = np->vsi;

	if (test_bit(MCEVF_FLAG_FORCE_CLOSE, pf->flags) &&
	    !test_bit(MCEVF_VSI_DOWN, vsi->state)) {
		rtnl_lock();
		mcevf_vsi_close(vsi);
		rtnl_unlock();
		hw->reset_done = true;
		mcevf_mbx_set_vf_stat(&hw->pf_mbx);
	}
	clear_bit(MCEVF_FLAG_FORCE_CLOSE, pf->flags);

	if (test_bit(MCEVF_FLAG_FORCE_OPEN, pf->flags) &&
	    test_bit(MCEVF_VSI_DOWN, vsi->state)) {
		ret = mcevf_reset_hw(hw, true);
		if (ret) {
			set_bit(MCEVF_FLAG_FORCE_OPEN, pf->flags);
			netdev_warn(netdev,
				    "%s force open later because of reset hw failed!\n",
				__func__);
			return;
		}

		rtnl_lock();
		mcevf_vsi_open(vsi);
		rtnl_unlock();
		clear_bit(MCEVF_FLAG_FORCE_OPEN, pf->flags);
	} else {
		clear_bit(MCEVF_FLAG_FORCE_OPEN, pf->flags);
	}

	set_bit(MCEVF_FLAG_PF_UPDATE_LINK, pf->flags);
}

#define MCEVF_MAX_SPEED_STRLEN 13

static void mcevf_print_link_message(struct mcevf_pf *pf)
{
	struct mcevf_hw *hw = &pf->hw;
	struct mcevf_port_info *pi = hw->port_info;
	struct net_device *netdev = pf->vsi[0]->netdev;
	int link_speed_mbps;
	char speed[MCEVF_MAX_SPEED_STRLEN + 1];

	if (!pi->link_up) {
		if (netif_msg_link(pf))
			netdev_info(netdev, "NIC Link is Down\n");
		return;
	}

	switch (pi->link_speed) {
	case SPEED_100000:
		fallthrough;
	case SPEED_40000:
		fallthrough;
	case SPEED_25000:
		fallthrough;
	case SPEED_10000:
		fallthrough;
	case SPEED_1000:
		fallthrough;
	case SPEED_100:
		link_speed_mbps = pi->link_speed;
		break;
	default:
		link_speed_mbps = SPEED_UNKNOWN;
		break;
	}

	if (link_speed_mbps > SPEED_1000) {
		/* convert to Gbps inline */
		snprintf(speed, MCEVF_MAX_SPEED_STRLEN, "%d %s",
			 link_speed_mbps / 1000, "Gbps");
	} else if (link_speed_mbps == SPEED_UNKNOWN) {
		snprintf(speed, MCEVF_MAX_SPEED_STRLEN, "%s", "Unknown Mbps");
	} else {
		snprintf(speed, MCEVF_MAX_SPEED_STRLEN, "%d %s",
			 link_speed_mbps, "Mbps");
	}
	if (netif_msg_link(pf))
		netdev_info(netdev, "NIC Link is Up Speed is %s Full Duplex\n",
			    speed);
}

static void mcevf_watchdog_subtask(struct mcevf_pf *pf)
{
	struct mcevf_hw *hw = &pf->hw;
	struct mcevf_port_info *pi = hw->port_info;
	struct mcevf_vsi *vsi = mcevf_get_main_vsi(pf);
	struct net_device *netdev = vsi->netdev;

	if (test_bit(MCEVF_VSI_DOWN, vsi->state))
		return;

	if (!pf || !test_bit(MCEVF_FLAG_PF_UPDATE_LINK, pf->flags))
		return;

	clear_bit(MCEVF_FLAG_PF_UPDATE_LINK, pf->flags);
	if (pi->link_up) {
		if (netif_carrier_ok(netdev))
			return;
		netif_tx_lock(netdev);
		netif_tx_start_all_queues(netdev);
		netif_carrier_on(netdev);
		netif_tx_unlock(netdev);
	} else {
		if (!netif_carrier_ok(netdev))
			return;
		netif_tx_lock(netdev);
		netif_tx_stop_all_queues(netdev);
		netif_carrier_off(netdev);
		netif_tx_unlock(netdev);
	}
	mcevf_print_link_message(pf);
}

static void __maybe_unused mcevf_monitor_msix_vector(struct mcevf_pf *pf)
{
	struct mcevf_hw *hw = &pf->hw;
	u32 val, i;
	struct mcevf_vsi *vsi = pf->vsi[0];
	struct mcevf_q_vector *q_vector;
	int base = vsi->base_vector;
	u32 base_off = hw->vector_offset;
	int v_idx;
	struct mcevf_ring *ring;

	if (test_bit(MCEVF_VSI_DOWN, vsi->state))
		return;

	mcevf_for_each_q_vector(vsi, i) {
		q_vector = vsi->q_vectors[i];
		v_idx = q_vector->v_idx + base;
		val = rd32(hw, base_off + 0xc + 0x10 * v_idx);
		if (val & BIT(0)) {
			dev_info(mcevf_pf_to_dev(pf),
				 "vidx:%d val:0x%x irq mask detected!\n", v_idx,
				 val);
			wr32(hw, base_off + 0xc + 0x10 * v_idx, val & ~BIT(0));
			mcevf_rc_for_each_ring(ring, q_vector->tx)
				hw->ops->set_txring_trig_intr(ring);
		}
	}
}

/**
 * mcevf_service_task - manage and run subtasks
 * @work: pointer to work_struct contained by the PF struct
 */
static void mcevf_service_task(struct work_struct *work)
{
	struct mcevf_pf *pf = container_of(work, struct mcevf_pf, serv_task);
	unsigned long start_time = jiffies;

	if (test_bit(MCEVF_REMOVED, pf->state))
		return;

	mcevf_sync_fltr_subtask(pf);
	mcevf_sync_vlan_subtask(pf);
	mcevf_sync_fcs_subtask(pf);
	mcevf_pf_reset_subtask(pf);
	mcevf_watchdog_subtask(pf);
	// mcevf_monitor_msix_vector(pf);
	// mcevf_virtchnl_completion(pf, false);
	/* Clear MCEVF_SERVICE_SCHED flag to allow scheduling next event */
	mcevf_service_task_complete(pf);

	/* If the tasks have taken longer than one service timer period
	 * or there is more work to be done, reset the service timer to
	 * schedule the service task now.
	 */
	if (!test_bit(MCEVF_REMOVED, pf->state)) {
		if (time_after(jiffies, (start_time + pf->serv_tmr_period)))
			mod_timer(&pf->serv_tmr, jiffies);
	}
}

/**
 * mcevf_get_avail_q_count - Get count of queues in use
 * @pf_qmap: bitmap to get queue use count from
 * @lock: pointer to a mutex that protects access to pf_qmap
 * @size: size of the bitmap
 */
static u16 mcevf_get_avail_q_count(unsigned long *pf_qmap, struct mutex *lock,
				   u16 size)
{
	unsigned long bit;
	u16 count = 0;

	mutex_lock(lock);
	for_each_clear_bit(bit, pf_qmap, size)
		count++;
	mutex_unlock(lock);

	return count;
}

/**
 * mcevf_get_avail_txq_count - Get count of Tx queues in use
 * @pf: pointer to an mcevf_pf instance
 */
u16 mcevf_get_avail_txq_count(struct mcevf_pf *pf)
{
	return mcevf_get_avail_q_count(pf->avail_txqs, &pf->avail_q_mutex,
				       pf->max_pf_txqs);
}

/**
 * mcevf_get_avail_rxq_count - Get count of Rx queues in use
 * @pf: pointer to an mcevf_pf instance
 */
u16 mcevf_get_avail_rxq_count(struct mcevf_pf *pf)
{
	return mcevf_get_avail_q_count(pf->avail_rxqs, &pf->avail_q_mutex,
				       pf->max_pf_rxqs);
}

static inline struct mcevf_pf *mcevf_allocate_pf(struct device *dev)
{
	return devm_kzalloc(dev, sizeof(struct mcevf_pf), GFP_KERNEL);
}

/**
 * mcevf_vsi_recfg_qs - Change the number of queues on a VSI
 * @vsi: VSI being changed
 * @new_rx: new number of Rx queues
 * @new_tx: new number of Tx queues
 * @force: force the reconfiguration even if new counts are zero
 *
 * Only change the number of queues if new_tx, or new_rx is non-0.
 *
 * Returns 0 on success.
 */
int mcevf_vsi_recfg_qs(struct mcevf_vsi *vsi, int new_rx, int new_tx,
		       bool force)
{
	struct mcevf_pf *pf = vsi->back;
	int err = 0;

	if (!force && !new_rx && !new_tx)
		return -EINVAL;

	if (force || new_tx)
		vsi->req_txq = (u16)new_tx;
	if (force || new_rx)
		vsi->req_rxq = (u16)new_rx;

	/* set for the next time the netdev is started */
	if (!netif_running(vsi->netdev)) {
		mcevf_vsi_rebuild(vsi);
		dev_info(mcevf_pf_to_dev(pf),
			 "Link is down, queue count change happens when link is brought up\n");
		goto done;
	}
	mcevf_vsi_close(vsi);
	mcevf_vsi_rebuild(vsi);
	err = mcevf_vsi_open(vsi);
done:
	return err;
}

int mcevf_reset_hw(struct mcevf_hw *hw, bool set_mac)
{
	int ret = 0;

	ret = hw->ops->reset_hw(hw);
	if (ret)
		return ret;
	hw->ops->init_hw(hw);
	hw->ops->get_queues(hw);

	if (set_mac && is_valid_ether_addr(hw->mac.addr)) {
		struct net_device *netdev = mcevf_hw_to_netdev(hw);

		eth_hw_addr_set(netdev, hw->mac.addr);
		ether_addr_copy(netdev->perm_addr, hw->mac.addr);
	}

	return ret;
}

static void mcevf_get_msix_vector(struct mcevf_hw *hw)
{
	struct pci_dev *dev = hw->pdev;
	u32 table_offset;

	pci_read_config_dword(dev, dev->msix_cap + PCI_MSIX_TABLE,
			      &table_offset);
	//hw->msix_vector_bar = (u8)(table_offset & PCI_MSIX_TABLE_BIR);
	hw->vector_offset = table_offset & PCI_MSIX_TABLE_OFFSET;
}

int mcevf_init_hw(struct mcevf_hw *hw)
{
	struct device *dev = hw->dev;
	int err = 0;
	int bar_id = 0;

	if (!hw->port_info)
		hw->port_info = devm_kzalloc(mcevf_hw_to_dev(hw),
					     sizeof(*hw->port_info),
					     GFP_KERNEL);
	if (!hw->port_info)
		return -ENOMEM;

	switch (hw->hw_type) {
	case board_n20:
		bar_id = MCEVF_NIC_BAR_N20;
		hw->eth_bar_base = ioremap(pci_resource_start(hw->pdev, bar_id),
					   pci_resource_len(hw->pdev, bar_id));
		hw->eth_bar_phy = pci_resource_start(hw->pdev, bar_id);
		if (!(hw->eth_bar_base)) {
			dev_err(dev, "pcim_iomap bar%u failed!\n", bar_id);
			err = -EIO;
			goto err_ioremap_eth;
		}
		dev_info(dev, "BAR%u PA:%016llx,SIZE:%08llu, VA=0x%016llx",
			 bar_id, pci_resource_start(hw->pdev, bar_id),
			 pci_resource_len(hw->pdev, bar_id),
			 (uint64_t)(hw->eth_bar_base));

		err = mcevf_get_n20_caps(hw);
		if (err) {
			dev_err(dev, "get n20 capabilities failed!");
			goto err_hw_type;
		}
		mcevf_get_msix_vector(hw);
		/* if has rdma on */
		if (hw->rdma_state) {
#define RDMA_OFFSET (0x40000)
			hw->rdma_bar_base = hw->eth_bar_base + RDMA_OFFSET;
			hw->rdma_bar_phy = hw->eth_bar_phy + RDMA_OFFSET;
		}
		break;
	default:
		dev_err(dev, "Sorry this device not supported!");
		err = -EINVAL;
		goto err_hw_type;
	}

	return err;

err_hw_type:
	//if (hw->rdma_bar_base)
	//	iounmap(hw->rdma_bar_base);
	hw->rdma_bar_base = NULL;
	//err_ioremap_rdma:
	if (hw->eth_bar_base)
		iounmap(hw->eth_bar_base);
	hw->eth_bar_base = NULL;
err_ioremap_eth:
	if (hw->port_info) {
		devm_kfree(dev, hw->port_info);
		hw->port_info = NULL;
	}
	return err;
}

static void mcevf_set_pf_caps(struct mcevf_pf *pf)
{
	struct mcevf_hw_func_caps *func_caps = &pf->hw.func_caps;

	clear_bit(MCEVF_FLAG_RSS_ENA, pf->flags);
	if (func_caps->common_cap.rss_table_size)
		set_bit(MCEVF_FLAG_RSS_ENA, pf->flags);

	pf->max_pf_txqs = func_caps->common_cap.num_txq;
	pf->max_pf_rxqs = func_caps->common_cap.num_rxq;
	pf->mbox_irq_base = func_caps->common_cap.mbox_irq_base;
	pf->num_mbox_irqs = func_caps->common_cap.num_mbox_irqs;
	pf->qvec_irq_base = func_caps->common_cap.qvec_irq_base;
	pf->rdma_irq_base = func_caps->common_cap.rdma_irq_base;
	pf->num_rdma_irqs = func_caps->common_cap.num_rdma_irqs;
	pf->num_msix_cnt = func_caps->common_cap.max_irq_cnts;
	pf->vlan_strip_cnt = func_caps->common_cap.vlan_strip_cnt;
	pf->drop_intr_timer_en = func_caps->common_cap.drop_intr_timer_en;
	pf->cline_size = cache_line_size();
}

static int mcevf_init_dcb(struct mcevf_pf *pf)
{
	struct mcevf_dcb *dcb = NULL;

	dcb = devm_kzalloc(mcevf_pf_to_dev(pf), sizeof(*pf->dcb), GFP_KERNEL);
	if (!dcb)
		return -ENOMEM;

	clear_bit(MCEVF_DSCP_EN, dcb->flags);
	clear_bit(MCEVF_ETS_EN, dcb->flags);
	clear_bit(MCEVF_DCB_EN, dcb->flags);
	clear_bit(MCEVF_PFC_EN, dcb->flags);

	//mce_dcb_tc_default(&(dcb->cur_tccfg));
	//mce_dcb_tc_default(&(dcb->new_tccfg));
	//mce_dcb_ets_default(&(dcb->cur_etscfg));
	//mce_dcb_ets_default(&(dcb->new_etscfg));
	//mce_dcb_pfc_default(&(dcb->cur_pfccfg));
	//mce_dcb_pfc_default(&(dcb->new_pfccfg));

	memset(dcb->vlan_to_q, 0xff, MCEVF_MAX_VLAN);
	dcb->back = pf;
	pf->dcb = dcb;

	mutex_init(&dcb->dcb_mutex);

	return 0;
}

static void mcevf_deinit_dcb(struct mcevf_pf *pf)
{
	struct mcevf_dcb *dcb = pf->dcb;

	if (dcb) {
		mutex_destroy(&dcb->dcb_mutex);
		devm_kfree(mcevf_pf_to_dev(pf), dcb);
		pf->dcb = NULL;
	}
}

static int mcevf_init_pf(struct mcevf_pf *pf)
{
	struct mcevf_hw *hw = &pf->hw;

	mcevf_set_pf_caps(pf);

	mutex_init(&pf->sw_mutex);
	mutex_init(&pf->adev_mutex);

	mutex_init(&hw->fdir_fltr_lock);
	INIT_LIST_HEAD(&hw->fdir_list_head);

	/* setup service timer and periodic service task */
	timer_setup(&pf->serv_tmr, mcevf_service_timer, 0);
	if (pf->drop_intr_timer_en) {
		pf->serv_tmr_max_cnt = __MCEVF_SERV_TIMER_PERIODS_CNT;
		pf->serv_tmr_period = __MCEVF_SERV_TIMER_PERIODS_UNIT;
	} else {
		pf->serv_tmr_max_cnt = 1;
		pf->serv_tmr_period = __MCEVF_SERV_TIMER_PERIODS_UNIT *
				      __MCEVF_SERV_TIMER_PERIODS_CNT;
	}
	INIT_WORK(&pf->serv_task, mcevf_service_task);
	clear_bit(MCEVF_SERVICE_SCHED, pf->state);
	set_bit(MCEVF_FLAG_SW_DIM_ENA, pf->flags);

	mutex_init(&pf->avail_q_mutex);
	pf->avail_txqs = bitmap_zalloc(pf->max_pf_txqs, GFP_KERNEL);
	if (!pf->avail_txqs)
		return -ENOMEM;

	pf->avail_rxqs = bitmap_zalloc(pf->max_pf_rxqs, GFP_KERNEL);
	if (!pf->avail_rxqs) {
		devm_kfree(mcevf_pf_to_dev(pf), pf->avail_txqs);
		pf->avail_txqs = NULL;
		return -ENOMEM;
	}
	/* setup tunnel inner layer */
	if (pf->tun_inner)
		set_bit(MCEVF_FLAG_TUNNEL_INNER_ENA, pf->flags);
	hw->ops->set_tun_select_inner(hw, pf->tun_inner);

	return 0;
}

/**
 * mcevf_pf_vsi_setup - Set up a PF VSI
 * @pf: board private structure
 *
 * Returns pointer to the successfully allocated VSI software struct
 * on success, otherwise returns NULL on failure.
 */
static struct mcevf_vsi *mcevf_pf_vsi_setup(struct mcevf_pf *pf)
{
	return mcevf_vsi_setup(pf);
}

/**
 * mcevf_setup_pf_sw - Setup the HW switch on startup or after reset
 * @pf: board private structure
 *
 * Returns 0 on success, negative value on failure
 */
static int mcevf_setup_pf_sw(struct mcevf_pf *pf)
{
	struct mcevf_vsi *vsi;
	int status = 0;

	vsi = mcevf_pf_vsi_setup(pf);
	if (!vsi) {
		dev_err(&pf->pdev->dev, "pf vsi setup failed!\n");
		return -ENOMEM;
	}

	status = mcevf_cfg_netdev(vsi);
	if (status) {
		dev_err(&pf->pdev->dev, "cfg netdev failed!\n");
		goto unroll_vsi_setup;
	}

	/* netdev has to be configured before setting frame size */
	mcevf_vsi_cfg_frame_size(vsi);

	/* registering the NAPI handler requires both the queues and
	 * netdev to be created, which are done in mcevf_pf_vsi_setup()
	 * and mcevf_cfg_netdev() respectively
	 */
	mcevf_napi_add(vsi);

	return status;

unroll_vsi_setup:
	mcevf_vsi_release(vsi);

	return status;
}

/**
 * mcevf_misc_intr - misc interrupt handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
static irqreturn_t mcevf_misc_intr(int __always_unused irq, void *data)
{
	struct mcevf_pf *pf = data;

	mcevf_mbx_clean_all_incoming_req(&pf->hw, mcevf_mbx_pf_event_req_isr,
					 mcevf_mbx_pf_req_isr);
	// none_work:
	return IRQ_WAKE_THREAD;
}

/**
 * mcevf_misc_intr_thread_fn - misc interrupt thread function
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
static irqreturn_t mcevf_misc_intr_thread_fn(int __always_unused irq,
					     void *data)
{
	// struct mcevf_pf *pf = data;
	// struct mcevf_hw *hw;

	// hw = &pf->hw;

	return IRQ_HANDLED;
}

/**
 * mcevf_req_irq_msix_misc - Setup the misc vector to handle non queue events
 * @pf: board private structure
 *
 * This sets up the handler for MSIX 0, which is used to manage the
 * non-queue interrupts, e.g. AdminQ and errors. This is not used
 * when in MSI or Legacy interrupt mode.
 */
static int mcevf_req_irq_msix_misc(struct mcevf_pf *pf)
{
	int err = 0;
	struct device *dev = mcevf_pf_to_dev(pf);
	struct mcevf_hw *hw = &pf->hw;

	err = mcevf_get_irq_res(pf, pf->irq_tracker, pf->num_mbox_irqs,
				pf->mbox_irq_base);
	if (err) {
		dev_err(dev, "No irq rem for mbox\n");
		return err;
	}

	if (!pf->int_name[0])
		snprintf(pf->int_name, sizeof(pf->int_name) - 1, "%s-%s:misc",
			 dev_driver_string(dev), dev_name(dev));
	err = devm_request_threaded_irq(dev,
					mcevf_get_irq_num(pf, pf->mbox_irq_base), mcevf_misc_intr,
		mcevf_misc_intr_thread_fn, 0, pf->int_name, pf);
	if (err) {
		dev_err(dev, "devm_request_threaded_irq for %s failed",
			pf->int_name);
		mcevf_free_irq_res(pf->irq_tracker, pf->num_mbox_irqs,
				   pf->mbox_irq_base);
		return err;
	}
	// hw->mbx.ops->configure(hw, pf->mbox_irq_base, true);
	mcevf_mbx_vector_set(&hw->pf_mbx, pf->mbox_irq_base, true);

	return 0;
}

static void mcevf_notify_pf_probe_info(struct mcevf_hw *hw)
{
	struct mcevf_pf *pf = container_of(hw, struct mcevf_pf, hw);
	struct mcevf_vsi *vsi = mcevf_get_main_vsi(pf);

	hw->virtchnl.ops->set_init_done(hw, true);
	/* default vsi num_txq == num_rxq */
	hw->virtchnl.ops->notify_ring_cnt(hw, vsi->num_txq);
}

/**
 * mcevf_inetaddr_event - IPv4 address notifier callback
 * @nb: notifier block
 * @event: event type (NETDEV_UP, NETDEV_DOWN)
 * @ptr: pointer to event data (struct in_ifaddr)
 *
 * Handles IPv4 address changes and notifies PF via mailbox.
 * When a conflict is detected, an error is logged but the IP is NOT deleted.
 *
 * NOTE: This callback is called with rtnl_lock held.
 */
static int mcevf_inetaddr_event(struct notifier_block *nb, unsigned long event,
				void *ptr)
{
	struct mcevf_pf *pf = container_of(nb, struct mcevf_pf, nb);
	struct mcevf_hw *hw = &pf->hw;
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *netdev;
	struct mcevf_vsi *vsi;
	__be32 ipv4_addr;
	int err;

	/* Safety check - ifa or ifa_dev might be NULL during some events */
	if (!ifa || !ifa->ifa_dev)
		return NOTIFY_DONE;

	netdev = ifa->ifa_dev->dev;
	if (!netdev)
		return NOTIFY_DONE;

	/* Only care about our own network device */
	vsi = mcevf_get_main_vsi(pf);
	if (!vsi || !vsi->netdev || netdev != vsi->netdev)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
		/* Send IP address to PF */
		ipv4_addr = ifa->ifa_local;
		if (hw->virtchnl.ops->set_ipv4_addr) {
			err = hw->virtchnl.ops->set_ipv4_addr(hw, ipv4_addr);
			if (err) {
				netdev_err(netdev,
					   "IPv4 address %pI4 conflicts with another VF in the same VLAN - configuration rejected (err:%d)\n",
					&ipv4_addr, err);
				/* Do NOT delete the IP address - just report the conflict */
				return NOTIFY_DONE;
			}
		}
		break;
	case NETDEV_DOWN:
		/* Clear IP address in PF */
		if (hw->virtchnl.ops->set_ipv4_addr)
			hw->virtchnl.ops->set_ipv4_addr(hw, 0);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

/**
 * mcevf_register_notifier - Register for IPv4 address changes
 * @pf: board private structure
 */
static void mcevf_register_notifier(struct mcevf_pf *pf)
{
	pf->nb.notifier_call = mcevf_inetaddr_event;
	register_inetaddr_notifier(&pf->nb);
}

/**
 * mcevf_unregister_notifier - Unregister IPv4 address notifier
 * @pf: board private structure
 */
static void mcevf_unregister_notifier(struct mcevf_pf *pf)
{
	unregister_inetaddr_notifier(&pf->nb);
}

/**
 * mcevf_probe - Device initialization routine
 * @pdev: PCI device information struct
 * @id: entry in mcevf_pci_tbl
 *
 * Returns 0 on success, negative on failure
 */
static int mcevf_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct mcevf_pf *pf = NULL;
	struct mcevf_hw *hw = NULL;
	int err = 0;

	dev_info(dev, DRIVER_NAME " PCI probe");

	err = pci_enable_device(pdev);
	if (err)
		return err;

	pf = mcevf_allocate_pf(dev);
	if (!pf) {
		err = -ENOMEM;
		goto err_regions;
	}

	/* set up for high or low DMA */
	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (err) {
		err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(dev, "DMA configuration failed: 0x%x\n", err);
			goto err_regions;
		}
	}

	pci_enable_pcie_error_reporting(pdev);
	pci_set_master(pdev);

	pf->pdev = pdev;
	pci_set_drvdata(pdev, pf);
	set_bit(MCEVF_DOWN, pf->state);

	hw = &pf->hw;

	pci_save_state(pdev);

	hw->back = pf;
	hw->dev = dev;
	hw->pdev = pdev;
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);
	hw->subsystem_vendor_id = pdev->subsystem_vendor;
	hw->subsystem_device_id = pdev->subsystem_device;
	hw->bus.bus_num = pdev->bus->number;
	hw->bus.device = PCI_SLOT(pdev->devfn);
	hw->bus.func = PCI_FUNC(pdev->devfn);
	hw->hw_type = id->driver_data;
	pf->msg_enable = netif_msg_init(debug, MCEVF_DFLT_NETIF_M);

	err = pci_request_mem_regions(pdev, dev_driver_string(dev));
	if (err) {
		dev_err(dev, "pci_request_selected_regions failed 0x%x\n", err);
		goto err_regions;
	}

	pci_save_state(pdev);

	err = mcevf_init_dcb(pf);
	if (err) {
		dev_err(dev, "mcevf_init_dcb failed: %d", err);
		goto err_init_hw;
	}
	err = mcevf_init_hw(hw);
	if (err) {
		dev_err(dev, "mcevf_init_hw failed: %d", err);
		goto err_init_hw;
	}
	dev_info(dev, "get vfnum is: %d\n", _vfnum(hw->vfnum));

	/* setup tunnel inner layer */
	pf->tun_inner = tun_inner;
	err = mcevf_init_pf(pf);
	if (err) {
		dev_err(dev, "mcevf_init_hw failed: %d", err);
		goto err_init_pf;
	}

	pf->num_alloc_vsi = hw->func_caps.guar_num_vsi;
	if (!pf->num_alloc_vsi) {
		err = -EIO;
		goto err_init_pf;
	}

	pf->vsi = devm_kcalloc(dev, pf->num_alloc_vsi, sizeof(*pf->vsi),
			       GFP_KERNEL);
	if (!pf->vsi) {
		err = -ENOMEM;
		goto err_init_pf;
	}

	pf->vsi_stats = devm_kcalloc(dev, pf->num_alloc_vsi,
				     sizeof(*pf->vsi_stats), GFP_KERNEL);

	if (!pf->vsi_stats) {
		err = -ENOMEM;
		goto err_init_vsi_stats;
	}

	err = mcevf_init_interrupt_scheme(pf);
	if (err) {
		dev_err(dev, "mcevf_init_interrupt_scheme failed: %d", err);
		err = -EIO;
		goto err_init_interrupt_scheme;
	}

	err = mcevf_setup_pf_sw(pf);
	if (err) {
		dev_err(dev, "probe failed due to setup PF switch");
		goto err_setup_pf_sw;
	}
	/* In case of MSIX we are going to setup the misc vector right here
	 * to handle admin queue events etc. In case of legacy and MSI
	 * the misc functionality and queue processing is combined in
	 * the same vector and that gets setup at open.
	 */
	err = mcevf_req_irq_msix_misc(pf);
	if (err) {
		dev_err(dev, "setup of misc vector failed: %d", err);
		goto err_setup_pf_sw;
	}
	/* ready to go, so clear down state bit */
	clear_bit(MCEVF_DOWN, pf->state);
	clear_bit(MCEVF_SERVICE_DIS, pf->state);

	/* since everything is good, start the service timer */
	mod_timer(&pf->serv_tmr, round_jiffies(jiffies + pf->serv_tmr_period));

	err = mcevf_register_netdev(pf);
	if (err) {
		dev_err(dev, "failed to register netdev!\n");
		goto err_netdev_reg;
	}
	if (hw->rdma_state && probe_with_aux) {
		err = mcevf_plug_aux_devs(pf, "mrdma_roce");
		if (err) {
			//NOTE: ETH function can still be used without RDMA
			dev_err(dev, "failed to register auxdev!\n");
		}
	}

	if (mcevf_sysfs_init(pf))
		dev_err(dev, "failed to init sysfs!\n");
	mcevf_notify_pf_probe_info(hw);
	mcevf_register_notifier(pf);
	return 0;

err_netdev_reg:
	mcevf_vsi_release_all(pf);
err_setup_pf_sw:
	set_bit(MCEVF_DOWN, pf->state);
	mcevf_clear_interrupt_scheme(pf);
err_init_interrupt_scheme:
	devm_kfree(dev, pf->vsi_stats);
	pf->vsi_stats = NULL;
err_init_vsi_stats:
	devm_kfree(dev, pf->vsi);
	pf->vsi = NULL;
err_init_pf:
err_init_hw:
	mcevf_deinit_dcb(pf);
	pci_clear_master(pdev);
	pci_release_mem_regions(pdev);
err_regions:
	pci_disable_device(pdev);
	return err;
}

/**
 * mcevf_deinit_pf - Unrolls initialziations done by mcevf_init_pf
 * @pf: board private structure to initialize
 */
static void mcevf_deinit_pf(struct mcevf_pf *pf)
{
	mcevf_service_task_stop(pf);
	mutex_destroy(&pf->sw_mutex);
	mutex_destroy(&pf->adev_mutex);
	mutex_destroy(&pf->hw.fdir_fltr_lock);
	mutex_destroy(&pf->avail_q_mutex);

	if (pf->avail_txqs) {
		bitmap_free(pf->avail_txqs);
		pf->avail_txqs = NULL;
	}

	if (pf->avail_rxqs) {
		bitmap_free(pf->avail_rxqs);
		pf->avail_rxqs = NULL;
	}
}

/**
 * mcevf_unmap_all_hw_addr - Release device register memory maps
 * @pf: pointer to the PF structure
 *
 * Release all PCI memory maps and regions.
 */
static void mcevf_unmap_all_hw_addr(struct mcevf_pf *pf)
{
	struct mcevf_hw *hw = &pf->hw;
	struct pci_dev *pdev = pf->pdev;

	if (hw->eth_bar_base)
		iounmap(hw->eth_bar_base);
	hw->eth_bar_base = NULL;
	//if (hw->rdma_bar_base)
	//	iounmap(hw->rdma_bar_base);
	hw->rdma_bar_base = NULL;
	pci_clear_master(pdev);
	pci_release_mem_regions(pdev);
}

/**
 * mcevf_deinit_hw - Release device register memory maps
 * @pf: pointer to the PF structure
 *
 */
static void mcevf_deinit_hw(struct mcevf_pf *pf)
{
	struct mcevf_hw *hw = &pf->hw;

	// hw->ops->reset_hw(hw);

	if (hw->port_info) {
		devm_kfree(mcevf_hw_to_dev(hw), hw->port_info);
		hw->port_info = NULL;
	}

	mcevf_unmap_all_hw_addr(pf);
}

/**
 * mcevf_free_irq_msix_misc - Unroll misc vector setup
 * @pf: board private structure
 */
static void mcevf_free_irq_msix_misc(struct mcevf_pf *pf)
{
	int irq_num = mcevf_get_irq_num(pf, pf->mbox_irq_base);

	synchronize_irq(irq_num);
	devm_free_irq(mcevf_pf_to_dev(pf), irq_num, pf);

	mcevf_free_irq_res(pf->irq_tracker, pf->num_mbox_irqs,
			   pf->mbox_irq_base);
}

static void mcevf_remove_mbx_irq(struct mcevf_pf *pf)
{
	struct mcevf_hw *hw = &pf->hw;

	hw->virtchnl.ops->set_init_done(hw, false);
	mcevf_mbx_vector_set(&hw->pf_mbx, pf->mbox_irq_base, false);
}

/**
 * mcevf_remove - Device removal routine
 * @pdev: PCI device information struct
 */
static void mcevf_remove(struct pci_dev *pdev)
{
	struct mcevf_pf *pf = pci_get_drvdata(pdev);
	struct mcevf_hw *hw = &pf->hw;
	int i = 0;

	if (!pf)
		return;
	/* get pf removed flags */

	set_bit(MCEVF_REMOVED, pf->state);
	mcevf_sysfs_exit(pf);
	set_bit(MCEVF_SHUTTING_DOWN, pf->state);
	mcevf_unregister_notifier(pf);
	if (hw->rdma_state && probe_with_aux)
		mcevf_unplug_aux_devs(pf);
	mcevf_remove_mbx_irq(pf);
	mcevf_free_irq_msix_misc(pf);

	mcevf_vsi_release_all(pf);

	mcevf_for_each_vsi(pf, i) {
		if (!pf->vsi[i])
			continue;
		mcevf_vsi_free_q_vectors(pf->vsi[i]);
	}

	devm_kfree(&pdev->dev, pf->vsi_stats);
	pf->vsi_stats = NULL;

	mcevf_deinit_pf(pf);
	mcevf_deinit_dcb(pf);
	mcevf_clear_interrupt_scheme(pf);
	mcevf_deinit_hw(pf);
	pci_wait_for_pending_transaction(pdev);
	pci_disable_pcie_error_reporting(pdev);
	pci_disable_device(pdev);

	dev_info(&pdev->dev, DRIVER_NAME " PCI remove");
}

/**
 * mcevf_shutdown - Shutdown the device in preparation for a reboot
 * @pdev: pci device structure
 **/
static void mcevf_shutdown(struct pci_dev *pdev)
{
	mcevf_remove(pdev);

	if (system_state == SYSTEM_POWER_OFF)
		pci_set_power_state(pdev, PCI_D3hot);
}

static struct pci_driver mcevf_driver = {
	.name = DRIVER_NAME,
	.id_table = mcevf_pci_tbl,
	.probe = mcevf_probe,
	.remove = mcevf_remove,
	.shutdown = mcevf_shutdown,
};

static int __init mcevf_init_module(void)
{
	int status;

	mcevf_wq = alloc_workqueue("%s", 0, 0, KBUILD_MODNAME);
	if (!mcevf_wq) {
		pr_err("Failed to create workqueue\n");
		return -ENOMEM;
	}

	status = pci_register_driver(&mcevf_driver);
	if (status) {
		pr_err("failed to register PCI driver, err %d\n", status);
		destroy_workqueue(mcevf_wq);
	}

	return status;
}

static void __exit mcevf_exit_module(void)
{
	pci_unregister_driver(&mcevf_driver);
	destroy_workqueue(mcevf_wq);
	pr_info("module unloaded\n");
}

module_init(mcevf_init_module);
module_exit(mcevf_exit_module);
