// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include <linux/module.h>
#include <linux/inetdevice.h>
#include <linux/namei.h>
#include <linux/bitmap.h>
#include <linux/if_macvlan.h>
#include "mce.h"
#include "mce_irq.h"
#include "mce_lib.h"
#include "mce_base.h"
#include "mce_netdev.h"
#include "mce_fltr.h"
#include "mce_fdir.h"
#include "mce_sriov.h"
#include "mce_fwchnl.h"
#include "mce_virtchnl.h"
#include "mce_devlink.h"
#include "mce_dcb.h"
#include "mce_version.h"
#include "mce_npu.h"
#include "mce_ptp.h"

/* Device IDs */
#define PCI_DEVICE_ID_N20_25G 0x8500
#define PCI_DEVICE_ID_N20_100G 0x8501
#define PCI_DEVICE_ID_N20_40G 0x8502
#define PCI_DEVICE_ID_B850_25G 0x8507
#define PCI_DEVICE_ID_B850_100G 0x8508
#define PCI_DEVICE_ID_B850_40G 0x8509

#define MCE_NPU_BAR_N20 0
/* bar number */
#define MCE_NIC_BAR_N20 4
#define MCE_RDMA_BAR_N20 2

static unsigned int mce_major;
static struct class *mce_class;
static DECLARE_BITMAP(cdev_bitmap, MAX_MCE_DEVICES);

MODULE_AUTHOR("Mucse Corporation, <mucse@mucse.com>");
MODULE_DESCRIPTION("Mucse(R) N20/B850 25/40/100 Gigabit PCI Express Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

static int clk_tube = 1;
module_param(clk_tube, int, 0444);
MODULE_PARM_DESC(clk_tube, "0:default clk 1:max clk");

static int debug = -1;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "netif level (0=none,...,16=all)");

static int pcie_irq_mode = MCE_PCIE_IRQ_MODE_NONE;
module_param(pcie_irq_mode, int, 0644);
MODULE_PARM_DESC(pcie_irq_mode,
		 "pcie interrupt mode (1:msix, 2:msi, 3:legacy, default:1)");

static char *add_ibdev_script = "/opt/mucse/mrdma/mrdma_add_ibdev.sh";
module_param(add_ibdev_script, charp, 0644);
MODULE_PARM_DESC(add_ibdev_script, "script to run after mrdma add ibdev, default=/opt/mucse/mrdma/mrdma_add_ibdev.sh");

static char *remove_ibdev_script = "/opt/mucse/mrdma/mrdma_remove_ibdev.sh";
module_param(remove_ibdev_script, charp, 0644);
MODULE_PARM_DESC(remove_ibdev_script, "script to run after mrdma remove ibdev, default=/opt/mucse/mrdma/mrdma_remove_ibdev.sh");

static unsigned int tun_inner;
module_param(tun_inner, uint, 0444);
MODULE_PARM_DESC(tun_inner, "parse tunnel packet by inner layer"
			    "(0: outer layer, 1: inner layer, default: 0)");

static unsigned int fdir_mode;
module_param(fdir_mode, uint, 0444);
MODULE_PARM_DESC(fdir_mode,
		 "fdir mode(0:exact no macvlan, 1:sign no macvlan, "
		 "2:exact only macvlan, 3:sign only macvlan, default: 0)");

bool mce_arfs_enable;
module_param_named(arfs, mce_arfs_enable, bool, 0444);
MODULE_PARM_DESC(arfs, "enable accelerated RFS using FDIR (default: 0)");

bool mce_rx_page_pool_en;
module_param_named(rx_page_pool, mce_rx_page_pool_en, bool, 0644);
MODULE_PARM_DESC(rx_page_pool,
		 "enable page_pool based RX buffer management (default: 0)");

static struct pci_device_id mce_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MUCSE, PCI_DEVICE_ID_N20_25G),
	  .driver_data = board_n20 }, /* n20 */
	{ PCI_DEVICE(PCI_VENDOR_ID_MUCSE, PCI_DEVICE_ID_N20_100G),
	  .driver_data = board_n20 },
	{ PCI_DEVICE(PCI_VENDOR_ID_MUCSE, PCI_DEVICE_ID_N20_40G),
	  .driver_data = board_n20 },
	{ PCI_DEVICE(PCI_VENDOR_ID_MUCSE, PCI_DEVICE_ID_B850_25G),
	  .driver_data = board_n20 }, /* n20 */
	{ PCI_DEVICE(PCI_VENDOR_ID_MUCSE, PCI_DEVICE_ID_B850_100G),
	  .driver_data = board_n20 },
	{ PCI_DEVICE(PCI_VENDOR_ID_MUCSE, PCI_DEVICE_ID_B850_40G),
	  .driver_data = board_n20 },
	/* required last entry */
	{}
};
MODULE_DEVICE_TABLE(pci, mce_pci_tbl);

static struct workqueue_struct *mce_wq;
static bool mce_pcie_support_mrdma(struct mce_pf *pf);
static void mce_free_irq_msix_misc(struct mce_pf *pf);
static int mce_req_irq_msix_misc(struct mce_pf *pf);

/**
 * mce_service_task_schedule - schedule the service task to wake up
 * @pf: board private structure
 *
 * If not already scheduled, this puts the task into the work queue.
 */
void mce_service_task_schedule(struct mce_pf *pf)
{
	if (!test_bit(MCE_SERVICE_DIS, pf->state) &&
	    !test_and_set_bit(MCE_SERVICE_SCHED, pf->state) &&
	    !test_bit(MCE_NEEDS_RESTART, pf->state))
		queue_work(mce_wq, &pf->serv_task);
}

/**
 * mce_service_task_complete - finish up the service task
 * @pf: board private structure
 */
static void mce_service_task_complete(struct mce_pf *pf)
{
	/* force memory (pf->state) to sync before next service task */
	smp_mb__before_atomic();
	clear_bit(MCE_SERVICE_SCHED, pf->state);
}

/**
 * mce_service_task_stop - stop service task and cancel works
 * @pf: board private structure
 *
 * Return: 0 if the MCE_SERVICE_DIS bit was not already set,
 * 1 otherwise.
 */
static int mce_service_task_stop(struct mce_pf *pf)
{
	int ret;

	ret = test_and_set_bit(MCE_SERVICE_DIS, pf->state);

	if (pf->serv_tmr.function) {
		pf->serv_tmr_ticks = 0;
		del_timer_sync(&pf->serv_tmr);
	}

	if (pf->serv_task.func)
		cancel_work_sync(&pf->serv_task);
#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
	if (pf->tx_hwtstamp_work.work.func)
		cancel_delayed_work_sync(&pf->tx_hwtstamp_work);
#endif

	clear_bit(MCE_SERVICE_SCHED, pf->state);
	return ret;
}

#define MCE_PCIE_POST_MASTER_WAIT_MS 20

static void mce_handle_pcie_soc_fatal(struct mce_pf *pf)
{
#define __PCIE_FATAL_TIMEOUT_MS 30
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	u32 val, timeout = __PCIE_FATAL_TIMEOUT_MS;
	struct mce_hw *hw = &pf->hw;
	u16 vid = 0xffff;

	/* need this to rebuild the PCIe bdf for ep */
	pci_write_config_word(pf->pdev, PCI_VENDOR_ID, PCI_VENDOR_ID_MUCSE);

	if (test_bit(MCE_VSI_DOWN, vsi->state) ||
	    test_bit(MCE_FLAG_PF_RESET_ENA, pf->flags))
		return;

	pci_read_config_word(pf->pdev, PCI_VENDOR_ID, &vid);
	if (vid != PCI_VENDOR_ID_MUCSE)
		return;

	while (timeout) {
		val = raw_rd32(hw->eth_bar_base + 0x33000 +
			       MCE_SOC_PCIE_RESTORE_CNT_REG);
		if (val != (u32)-1)
			break;
		timeout--;
		udelay(5000); /* busy-wait: called from timer softirq, cannot sleep */
	}

	if (timeout < __PCIE_FATAL_TIMEOUT_MS) {
		if (timeout == 0) {
			dev_info(mce_pf_to_dev(pf),
				 "PCIe fatal error not recovered,  return!\n");
			return;
		}

		dev_info(mce_pf_to_dev(pf),
			 "PCIe fatal error detected by SoC, val:0x%x prev:0x%x timeout: %d\n",
			val, pf->pcie_restore_cnt, timeout);
	}

	if (pf->pcie_restore_cnt != val && val != (u32)-1) {
		struct net_device *netdev = vsi->netdev;

		/* Defer if netdev is in a transitional state (e.g. linkwatch
		 * pending from a prior reset's mce_vsi_open).  Do not touch
		 * pcie_restore_cnt / MCE_FLAG_PF_RESET_ENA here so the next
		 * timer tick will retry -- the PCIe restore must happen once
		 * the netdev state is stable.
		 */
		if (!netif_running(netdev) ||
		    test_bit(__LINK_STATE_LINKWATCH_PENDING, &netdev->state)) {
			dev_info(mce_pf_to_dev(pf),
				 "PCIe restore defer, cnt:0x%x(0x%x) netdev busy(running:%d lw:%d)\n",
				val, pf->pcie_restore_cnt,
				netif_running(netdev),
				!!test_bit(__LINK_STATE_LINKWATCH_PENDING,
					   &netdev->state));
			return;
		}

		dev_info(mce_pf_to_dev(pf),
			 "PCIe restore over, cnt:0x%x(0x%x), pf reset now\n",
			 val, pf->pcie_restore_cnt);
		pf->pcie_restore_cnt = val;

		/* pci_restore_state() rewrites the full PCIe config space
		 * so the Root Port can rebuild its ACS context.  It also
		 * restores the saved COMMAND which has Bus Master = 1.
		 * Explicitly clear Master - firmware only set Memory Space
		 * after retraining.  Master is enabled at the very end of
		 * mce_pf_reset_subtask() when everything is ready.
		 */
		pci_clear_master(pf->pdev);
		pci_save_state(pf->pdev);
		pci_restore_state(pf->pdev);
		set_bit(MCE_FLAG_PF_RESET_ENA, pf->flags);
	}
}

static void __maybe_unused mce_monitor_msix_vector(struct mce_pf *pf)
{
	struct mce_vsi *vsi = pf->vsi[0];
	struct mce_q_vector *q_vector;
	struct mce_hw *hw = &pf->hw;
	u32 base_off = hw->vector_offset;
	int base = vsi->base_vector;
	struct mce_ring *ring;
	u32 val, i;
	int v_idx;

	if (test_bit(MCE_VSI_DOWN, vsi->state))
		return;

	mce_for_each_q_vector(vsi, i) {
		q_vector = vsi->q_vectors[i];
		v_idx = q_vector->v_idx + base;
		val = vector_rd(hw, base_off + 0xc + 0x10 * v_idx);
		if (val & BIT(0)) {
			dev_info(mce_pf_to_dev(pf),
				 "vidx:%d val:0x%x irq mask detected!\n", v_idx,
				 val);
			vector_wr(hw, base_off + 0xc + 0x10 * v_idx,
				  val & ~BIT(0));
			mce_rc_for_each_ring(ring, q_vector->tx)
				hw->ops->set_txring_trig_intr(ring);
		}
	}
}

/**
 * mce_handle_drop_intr - timer callback to handle tx drop interrupts
 * @pf: pointer to struct pf
 */
static void mce_handle_drop_intr(struct mce_pf *pf)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_hw *hw = &pf->hw;
	int i;

	if (!pf->drop_intr_timer_en)
		return;

	if (test_bit(MCE_VSI_DOWN, vsi->state))
		return;
	if (test_bit(MCE_SERVICE_DIS, pf->state))
		return;
	mce_for_each_q_vector(vsi, i) {
		struct mce_q_vector *q_vector = vsi->q_vectors[i];
		struct mce_ring *tx_ring;

		if (!q_vector)
			continue;

		/* If ticks do not change, check whether the software ring is
		 * cleaned and used to judge if TX interrupts were dropped.
		 */
		if (q_vector->ticks == q_vector->old_ticks) {
			mce_rc_for_each_ring(tx_ring, q_vector->tx) {
				if (!tx_ring)
					return;
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
 * mce_service_timer - timer callback to schedule service task
 * @t: pointer to timer_list
 */
static void mce_service_timer(struct timer_list *t)
{
	struct mce_pf *pf = from_timer(pf, t, serv_tmr);

	mce_handle_drop_intr(pf);
	mce_handle_pcie_soc_fatal(pf);
	if (pf->serv_tmr_ticks % pf->serv_tmr_max_cnt == 0)
		mce_service_task_schedule(pf);
	pf->serv_tmr_ticks++;
	if (test_bit(MCE_SERVICE_DIS, pf->state))
		return;
	mod_timer(&pf->serv_tmr, round_jiffies(pf->serv_tmr_period + jiffies));
}

/**
 * mce_vsi_fltr_changed - check if filter state changed
 * @vsi: VSI to be checked
 *
 * returns true if filter state has changed, false otherwise.
 * Returns: The result of the operation.
 */
static bool mce_vsi_fltr_changed(struct mce_vsi *vsi)
{
	return test_bit(MCE_VSI_UMAC_FLTR_CHANGED, vsi->state) ||
	       test_bit(MCE_VSI_MMAC_FLTR_CHANGED, vsi->state);
}

/**
 * mce_vsi_sync_fltr - Update the VSI filter list to the HW
 * @vsi: ptr to the VSI
 *
 * Push any outstanding VSI filter changes through the AdminQ.
 * Returns: The result of the operation.
 */
static int mce_vsi_sync_fltr(struct mce_vsi *vsi)
{
	struct net_device *netdev = vsi->netdev;
	struct mce_pf *pf = vsi->back;
	struct mce_hw *hw = &pf->hw;
	u32 changed_flags = 0;

	if (!vsi->netdev)
		return -EINVAL;
	changed_flags = vsi->current_netdev_flags ^ vsi->netdev->flags;
	vsi->current_netdev_flags = vsi->netdev->flags;

	if (mce_vsi_fltr_changed(vsi)) {
		clear_bit(MCE_VSI_UMAC_FLTR_CHANGED, vsi->state);
		clear_bit(MCE_VSI_MMAC_FLTR_CHANGED, vsi->state);
		/* grab the netdev's addr_list_lock */
		netif_addr_lock_bh(netdev);
		__dev_uc_sync(netdev, mce_add_uc_filter, mce_del_uc_filter);
		__dev_mc_sync(netdev, mce_add_mc_filter, mce_del_mc_filter);
		/* our temp lists are populated. release lock */
		netif_addr_unlock_bh(netdev);
	}

	mce_sync_mac_uc_hash_list(hw);
	mce_sync_mac_mc_hash_list(hw);
	/* check for changes in promiscuous modes */
	if (changed_flags & IFF_ALLMULTI) {
		if (vsi->current_netdev_flags & IFF_ALLMULTI)
			hw->ops->set_mc_promisc(hw, true);
		else
			hw->ops->set_mc_promisc(hw, false);
	}

	if (changed_flags & IFF_PROMISC) {
		if (vsi->current_netdev_flags & IFF_PROMISC) {
			hw->ops->set_rx_promisc(hw, true);
			/* we should set mc promisc too */
			hw->ops->set_mc_promisc(hw, true);
			hw->vf.ops->set_vf_set_vlan_promisc(hw, PFINFO_IDX,
							    true);
		} else {
			hw->ops->set_rx_promisc(hw, false);
			/* maybe in mc promisc */
			if (vsi->current_netdev_flags & IFF_PROMISC)
				hw->ops->set_mc_promisc(hw, true);
			else
				hw->ops->set_mc_promisc(hw, false);

			if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
				hw->vf.ops->set_vf_set_vlan_promisc(hw, PFINFO_IDX, false);
			else
				hw->vf.ops->set_vf_set_vlan_promisc(hw, PFINFO_IDX, true);
		}
	}

	return 0;
}

/**
 * mce_sync_fltr_subtask - Sync the VSI filter list with HW
 * @pf: board private structure
 */
static void mce_sync_fltr_subtask(struct mce_pf *pf)
{
	int v;

	if (!pf || !(test_bit(MCE_FLAG_FLTR_SYNC, pf->flags)))
		return;

	clear_bit(MCE_FLAG_FLTR_SYNC, pf->flags);

	mce_for_each_vsi(pf, v) {
		if (pf->vsi[v] && mce_vsi_fltr_changed(pf->vsi[v]) &&
		    mce_vsi_sync_fltr(pf->vsi[v])) {
			/* come back and try again later */
			set_bit(MCE_FLAG_FLTR_SYNC, pf->flags);
			break;
		}
	}
}

static void mce_process_vflr_event(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	int i = 0, vfid;
	u32 val = 0;
	int j;

	if (!test_and_clear_bit(MCE_FLAG_MISC_IRQ_FLR_PENDING, pf->flags))
		return;
	for (i = MCE_MISC_IRQ_FLR_NONE; i < MCE_MISC_IRQ_FLR_MAX; i++) {
		val = i;
		hw->ops->get_misc_irq_st(hw, MCE_MAC_MISC_IRQ_FLR, &val);

		if (!val)
			continue;

		for (j = 0; j < 32; j++) {
			if (!(val & BIT(j)))
				continue;
			vfid = i * 32 + j;
			mce_vf_handle_flr_intr(hw, vfid);
		}
		hw->ops->clear_misc_irq_evt(hw, MCE_MAC_MISC_IRQ_FLR, i, val);
	}
}

static int mrdma_run_script(char *script, struct mce_pf *pf, char *queue)
{
	struct pci_dev *pdev = pf->pdev;
	char *envp[1] = { NULL };
	struct inode *inode;
	char bdf_str[32];
	char *argv[4] = { script, bdf_str, queue, NULL };
	struct path path;
	int ret;

	if (test_bit(MCE_REMOVED, pf->state))
		return -ESHUTDOWN;

	sprintf(bdf_str, "%04x:%02x:%02x.%d",
		pci_domain_nr(pdev->bus),
		pdev->bus->number,
		PCI_SLOT(pdev->devfn),
		PCI_FUNC(pdev->devfn));

	/* Use kern_path instead of filp_open to check the script
	 * before calling call_usermodehelper.  filp_open allocates a
	 * struct file which on KyLin 4.19 kernels triggers LSM
	 * security_file_alloc/free hooks; those hooks corrupt the LSM
	 * security blob slab (value 0x0000040000000000), which later
	 * crashes security_prepare_creds during fork().
	 */
	ret = kern_path(script, LOOKUP_FOLLOW, &path);
	if (ret)
		return ret;

	inode = d_inode(path.dentry);
	if (!inode || !S_ISREG(inode->i_mode)) {
		path_put(&path);
		return -ENOENT;
	}
	if (!(inode->i_mode & 0100)) {
		path_put(&path);
		return -EACCES;
	}
	path_put(&path);

	ret = call_usermodehelper(script, argv, envp, UMH_WAIT_PROC);
	if (ret < 0)
		pr_err("run script:%s bdf:%s failed ret=%d\n", script, bdf_str, ret);

	return ret;
}

static void mce_sync_mrdma_subtask(struct mce_pf *pf)
{
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
	struct net_device *netdev = mce_get_main_net_dev(pf);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_hw *hw = &pf->hw;
	bool mrdma_true = false;
	char queue[10];
	int i;

	if (test_bit(MCE_REMOVED, pf->state))
		return;

	sprintf(queue, "%d ", vsi->num_txq_real);

	/* only call script port not down */
	if (!test_bit(MCE_VSI_DOWN, vsi->state) && (!test_bit(MCE_FLAG_SRIOV_DOING, pf->flags))) {
		if (pf->m_status_req != pf->m_status || pf->force) {
			set_bit(MCE_FLAG_RDMA_SCRIPT_DOING, pf->flags);
			/* for next use */
			pf->m_status_req = pf->m_status;
			/* first call mtu setup */
			if (pf->m_status == MRDMA_INSMOD) {
				/* if mrdma insmod, check valid mtu */
				if (pf->valid_mtu > NORMAL_MTU) {
					/* mtu 9600 */
					netdev_info(netdev,
						    "mtu limit %d with mrdma\n", NORMAL_MTU);
					rtnl_lock();
					set_bit(MCE_VSI_HOLD_VALID_MTU, vsi->state);
					netdev->netdev_ops->ndo_change_mtu(netdev, NORMAL_MTU);
					clear_bit(MCE_VSI_HOLD_VALID_MTU, vsi->state);
					rtnl_unlock();
				}
			} else {
				/* if mrdm rmmod, try to recover before mtu */
				if (pf->valid_mtu != netdev->mtu) {
					netdev_info(netdev, "recover mtu to %d without mrdma",
						    pf->valid_mtu);
					rtnl_lock();
					netdev->netdev_ops->ndo_change_mtu(netdev, pf->valid_mtu);
					rtnl_unlock();
				}
			}
			if (pf->m_status_req == MRDMA_INSMOD)
				mrdma_run_script(add_ibdev_script, pf, queue);
			else
				mrdma_run_script(remove_ibdev_script, pf,
						 queue);
			clear_bit(MCE_FLAG_RDMA_SCRIPT_DOING, pf->flags);
		}
		if (!test_and_clear_bit(MCE_FLAG_MRDMA_CHANGED, pf->flags))
			return;

		if (pf->m_status == MRDMA_INSMOD) {
			mrdma_true = true;
			mce_for_each_vsi(pf, i) {
				if (!pf->vsi[i])
					continue;
				pf->vsi[i]->valid_prio &= 0x7f;
			}
			dev_info(mce_pf_to_dev(pf), "mrdma insmode\n");
		} else {
			/* if mrdma removed, nic use all prio */
			mce_for_each_vsi(pf, i) {
				if (!pf->vsi[i])
					continue;
				pf->vsi[i]->valid_prio = 0xff;
			}
			/* rdma use null valid_prio */
			/* should echo again */
			if (cdev_info)
				cdev_info->valid_prio = 0;
		}
		/* echo valid_prio to all vfs */
		mce_reset_vf(netdev);

		if (hw->ops->update_rdma_status)
			hw->ops->update_rdma_status(hw, mrdma_true);
	}
}

static void mce_process_aux_op_subtask(struct mce_pf *pf)
{
	enum mce_aux_op op;

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags) ||
	    test_bit(MCE_FLAG_SRIOV_DOING, pf->flags))
		return;

	if (!test_and_clear_bit(MCE_FLAG_AUX_OP_PENDING, pf->flags))
		return;

	op = pf->aux_op_pending;
	pf->aux_op_pending = MCE_AUX_OP_NONE;

	if (test_bit(MCE_REMOVED, pf->state))
		return;

	if (!mce_pcie_support_mrdma(pf))
		return;

	switch (op) {
	case MCE_AUX_OP_UNPLUG:
		if (!pf->bond_linked) {
			dev_warn(mce_pf_to_dev(pf),
				 "aux unplug pending but not linked to bond, skip\n");
			return;
		}
		dev_info(mce_pf_to_dev(pf),
			 "executing deferred aux unplug (bond: %s)\n",
			pf->bond_upper ? netdev_name(pf->bond_upper) : "NULL");
		mce_unplug_aux_dev(pf);
		break;

	case MCE_AUX_OP_PLUG:
		if (pf->bond_linked) {
			dev_warn(mce_pf_to_dev(pf),
				 "aux plug pending but still linked to bond, skip\n");
			return;
		}
		dev_info(mce_pf_to_dev(pf), "executing deferred aux plug\n");
		mce_plug_aux_dev(pf);
		break;

	default:
		break;
	}
}

void mce_reset_prev_stats(struct mce_pf *pf)
{
	struct mce_hw_stats *prev_stats = &pf->prev_stats;
	/* reset pf pri-stats when reset hw */
	memset(prev_stats, 0, sizeof(struct mce_hw_stats));
}

void mce_reset_hw(struct mce_hw *hw)
{
#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	bool restore_ptp = pf->flags2 & MCE_FLAG2_PTP_ENABLED;
#endif

	/* all regs will cleared when reset hw */
	hw->ops->reset_hw(hw);
	hw->ops->init_hw(hw);
	/* Initialize PTP hardware when PTP misc IRQ support is present. */
	if (hw->func_caps.common_cap.mac_misc_irq & BIT(MCE_MAC_MISC_IRQ_PTP))
		hw->ops->set_init_ptp(hw);
#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
	if (restore_ptp && mce_ptp_restore(pf))
		dev_warn(hw->dev, "failed to restore PTP after reset\n");
#endif
	hw->vf.ops->set_vf_rebase_ring_base(hw);
}

static void mce_vlan_restore_fltr(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	bool sriov_on = !!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags);
	struct mce_vlan_list_entry *vlan_entry = NULL;
	u16 vid;

	list_for_each_entry(vlan_entry, &hw->vlan_list_head, vlan_node) {
		vid = vlan_entry->vid;
		if (sriov_on)
			mce_vf_setup_flr_vlan(pf, PFINFO_IDX, vid);
		else
			hw->ops->add_vlan_filter(hw, vid);
	}
}

static void mce_mac_restore_fltr(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);

	spin_lock_bh(&hw->mac_hash_lock);
	bitmap_fill(hw->uc_hash_bm, MCE_FILTER_HASH_TB_SIZE);
	bitmap_fill(hw->mc_hash_bm, MCE_FILTER_HASH_TB_SIZE);
	set_bit(MCE_FLAG_PF_UC_HASH_SYNC_ENA, pf->flags);
	set_bit(MCE_FLAG_PF_MC_HASH_SYNC_ENA, pf->flags);
	spin_unlock_bh(&hw->mac_hash_lock);
}

static void mce_udp_tunnel_restore_fltr(struct mce_hw *hw)
{
	hw->ops->restore_udp_tnl(hw, TNL_VXLAN);
	hw->ops->restore_udp_tnl(hw, TNL_GENEVE);
	hw->ops->restore_udp_tnl(hw, TNL_VXLAN_GPE);
}

void mce_restore_hw(struct mce_hw *hw)
{
	/* fdir fltr restore */
	mce_fdir_del_fltrs(hw, false);
	mce_fdir_restore_fltr(hw);
	/* vlan fltr restore */
	mce_vlan_restore_fltr(hw);
	/* uc/mc fltr restore */
	mce_mac_restore_fltr(hw);
	/* pf macvlan fltr restore */
	mce_restore_pf_macvlan_fltr(hw);
	/* tcpsync fltr restore */
	/* udp tunnel fltr restore */
	mce_udp_tunnel_restore_fltr(hw);
}

static int mce_reset_pf(struct mce_pf *pf)
{
	return 0;
}

static void mce_pf_reset_subtask(struct mce_pf *pf)
{
	struct mce_netdev_priv *np;
	struct net_device *netdev;
	struct mce_vsi *vsi;
	struct mce_hw *hw;
	int ret;

	if (!pf || !(test_bit(MCE_FLAG_PF_RESET_ENA, pf->flags)))
		return;

	netdev = pf->vsi[0]->netdev;
	np = netdev_priv(netdev);
	vsi = np->vsi;
	hw = &pf->hw;

	mce_free_irq_msix_misc(pf);
	mce_notify_fw_ifup_down(pf, false);
	mce_vf_force_close_and_wait_done(pf);
	rtnl_lock();
	mce_vsi_close(vsi);
	rtnl_unlock();
	mce_reset_hw(hw);
	mce_reset_prev_stats(pf);
	mce_restore_hw(hw);
	mce_reset_pf(pf);
	ret = mce_reinit_pcie_msix(pf);
	if (ret)
		netdev_err(netdev, "reinit PCIe MSI-X failed: %d\n", ret);
	ret = mce_req_irq_msix_misc(pf);
	if (ret)
		netdev_err(netdev, "request misc MSI-X irq failed: %d\n", ret);
	rtnl_lock();
	mce_vsi_rebuild(vsi);
	rtnl_unlock();
	/* need keep this */
	pci_set_master(pf->pdev);
	msleep(MCE_PCIE_POST_MASTER_WAIT_MS);
	rtnl_lock();
	mce_vsi_open(vsi);
	rtnl_unlock();

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		mce_sriov_deinit_hw(pf);
		mce_sriov_init_hw(pf);
	}
	mce_notify_fw_ifup_down(pf, true);
	mce_vf_force_open_and_no_wait(pf);
	/* sync restore counter to avoid false second reset from
	 * mce_handle_pcie_soc_fatal timer callback, which would
	 * race with the linkwatch_event just scheduled by mce_vsi_open
	 */
	clear_bit(MCE_FLAG_PF_RESET_ENA, pf->flags);
	netdev_info(netdev, "mce pf reset subtask done!\n");
}

static void __maybe_unused mce_print_link_message(struct mce_pf *pf)
{
	struct net_device *netdev = pf->vsi[0]->netdev;
	struct mce_hw *hw = &pf->hw;
	struct mce_port_info *pi = hw->port_info;
	const char *speed;
	const char *fc;

	if (!pi->link_up) {
		if (netif_msg_link(pf))
			netdev_info(netdev, "NIC Link is Down\n");
		return;
	}

	switch (pi->link_speed) {
	case SPEED_10:
		speed = "10 Mbps";
		break;
	case SPEED_100:
		speed = "100 Mbps";
		break;
	case SPEED_1000:
		speed = "1 Gbps";
		break;
	case SPEED_10000:
		speed = "10 Gbps";
		break;
	case SPEED_25000:
		speed = "25 Gbps";
		break;
	case SPEED_40000:
		speed = "40 Gbps";
		break;
	case SPEED_50000:
		speed = "50 Gbps";
		break;
	case SPEED_100000:
		speed = "100 Gbps";
		break;
	default:
		speed = "Unknown ";
		break;
	}
	switch (pf->fc.current_mode) {
	case MCE_FC_FULL:
		fc = "Rx/Tx";
		break;
	case MCE_FC_TX_PAUSE:
		fc = "Tx";
		break;
	case MCE_FC_RX_PAUSE:
		fc = "Rx";
		break;
	case MCE_FC_NONE:
		fc = "None";
		break;
	default:
		fc = "Unknown ";
		break;
	}

	if (netif_msg_link(pf))
		netdev_info(netdev,
			    "NIC Link is up %s Full Duplex, Flow Control: %s\n",
			    speed, fc);
}

static void mce_link_state_subtask(struct mce_pf *pf)
{
	struct mce_vsi *vsi = pf->vsi[0];
	struct net_device *netdev = vsi->netdev;
	struct mce_hw *hw = &pf->hw;
	struct mce_port_info *pi = hw->port_info;

	if (test_bit(MCE_VSI_DOWN, vsi->state)) {
		if (test_and_clear_bit(MCE_FLAG_PF_FORCE_VF_LINK_DOWN,
				       pf->flags)) {
			pi->link_up = false;
			goto force_link_down;
		}
		return;
	}

	if (!test_bit(MCE_FLAG_PF_UPDATE_LINK, pf->flags))
		return;

	clear_bit(MCE_FLAG_PF_UPDATE_LINK, pf->flags);
	mce_get_port_phy_ability(hw);
	/* update pf stat reg: linkup bit */
	hw->ops->update_pf_stat(hw);
	pi->link_up = hw->fw_stat.stat0.linkup;
	pi->link_speed = speed_unzip(hw->fw_stat.stat0.s_speed);
	if (pi->link_up) {
		if (netif_carrier_ok(netdev))
			return;
		netif_carrier_on(netdev);
		netif_tx_wake_all_queues(netdev);
		mce_vsi_start_hw_transmit(vsi);
	} else {
		if (!netif_carrier_ok(netdev))
			return;
		netif_carrier_off(netdev);
		netif_tx_stop_all_queues(netdev);
		mce_vsi_close_hw_transmit(vsi);
	}
force_link_down:
	hw->ops->update_pf_stat(hw);
	mce_print_link_message(pf);
	mce_vf_notify_link_state(pf);
}

#ifdef CONFIG_DCB
static void mce_recover_ets_task(struct mce_pf *pf)
{
	struct net_device *netdev = pf->vsi[0]->netdev;
	const struct dcbnl_rtnl_ops *dcbnl_ops = netdev->dcbnl_ops;
	struct mce_dcb *dcb = pf->dcb;
	struct mce_hw *hw = &pf->hw;
	bool tool_flags;

	if (test_bit(MCE_VSI_DOWN, pf->vsi[0]->state))
		return;

	if (!test_bit(MCE_ETS_EN, dcb->flags))
		return;

	if (hw->qos.link_speed_old == hw->qos.link_speed)
		return;

	/* it must link speed changed, setup ets again */
	rtnl_lock();
	clear_bit(MCE_ETS_EN, pf->dcb->flags);
	mce_dcb_ets_default(&dcb->cur_etscfg);
	mce_dcb_ets_default(&dcb->new_etscfg);
	mce_dcb_update_hwetscfg(pf->dcb);
	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags)) {
		tool_flags = true;
		clear_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
	}

	dcbnl_ops->ieee_setets(netdev, &dcb->ets_os);
	set_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
	rtnl_unlock();

	if (tool_flags)
		set_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
}
#else
static inline void mce_recover_ets_task(struct mce_pf *pf)
{
}
#endif

/**
 * mce_service_task - manage and run subtasks
 * @work: pointer to work_struct contained by the PF struct
 */
static void mce_service_task(struct work_struct *work)
{
	struct mce_pf *pf = container_of(work, struct mce_pf, serv_task);
	unsigned long start_time = jiffies;

	mce_sync_fltr_subtask(pf);
	mce_process_vflr_event(pf);
	mce_process_aux_op_subtask(pf);
	mce_sync_mrdma_subtask(pf);
	mce_pf_reset_subtask(pf);
	mce_link_state_subtask(pf);
	mce_recover_ets_task(pf);
	mce_sync_arfs_fltrs(pf);
	/* Clear MCE_SERVICE_SCHED flag to allow scheduling next event */
	mce_service_task_complete(pf);

	/* If the tasks have taken longer than one service timer period
	 * or there is more work to be done, reset the service timer to
	 * schedule the service task now.
	 */
	if (!test_bit(MCE_REMOVED, pf->state)) {
		if (time_after(jiffies, (start_time + pf->serv_tmr_period)))
			mod_timer(&pf->serv_tmr, jiffies);
	}
}

int mce_get_msix_vector(struct mce_hw *hw)
{
	struct pci_dev *dev = hw->pdev;
	u32 table_offset;
	int err;

	if (!dev->msix_cap) {
		dev_err(&dev->dev, "MSI-X capability is missing\n");
		return -ENODEV;
	}

	err = pci_read_config_dword(dev, dev->msix_cap + PCI_MSIX_TABLE,
				    &table_offset);
	if (err || table_offset == (u32)-1) {
		dev_err(&dev->dev, "failed to read MSI-X table: err=%d val=0x%x\n",
			err, table_offset);
		return err ? err : -EIO;
	}

	hw->msix_vector_bar = (u8)(table_offset & PCI_MSIX_TABLE_BIR);
	hw->vector_offset = table_offset & PCI_MSIX_TABLE_OFFSET;
	return 0;
}

static void mce_get_port_speed_list(struct mce_hw *hw,
				    struct mce_phy_ability *ability)
{
	struct mce_port_info *pi = hw->port_info;
	u32 force_speed;

	pi->adv_speed_list = 0;
	pi->sup_speed_list = 0;

	if (ability->is_sgmii) {
		pi->sup_speed_list |= MCE_FW_LINK_SPEED_1000MB;
	} else {
		if (hw->max_speed >= 100000) {
			/* qsfp28 */
			pi->sup_speed_list |= MCE_FW_LINK_SPEED_100GB;
		}

		if (hw->max_speed >= 40000) {
			/* qsfp28 */
			pi->sup_speed_list |= MCE_FW_LINK_SPEED_40GB;
			pi->sup_speed_list |= MCE_FW_LINK_SPEED_25GB;
			pi->sup_speed_list |= MCE_FW_LINK_SPEED_10GB;
			pi->sup_speed_list |= MCE_FW_LINK_SPEED_1000MB;
		} else {
			/* sfp28 */
			pi->sup_speed_list |= MCE_FW_LINK_SPEED_25GB;
			pi->sup_speed_list |= MCE_FW_LINK_SPEED_10GB;
			pi->sup_speed_list |= MCE_FW_LINK_SPEED_1000MB;
		}

		if (hw->max_speed == 40000)
			pi->sup_speed_list &= ~MCE_FW_LINK_SPEED_25GB;
	}

	force_speed = ability->force_speed_by_user;
	if (force_speed) {
		switch (force_speed) {
		case MCE_FORCE_1G:
			pi->adv_speed_list |= MCE_FW_LINK_SPEED_1000MB;
			break;
		case MCE_FORCE_10G:
			pi->adv_speed_list |= MCE_FW_LINK_SPEED_10GB;
			break;
		case MCE_FORCE_25G:
			pi->adv_speed_list |= MCE_FW_LINK_SPEED_25GB;
			break;
		case MCE_FORCE_40G:
			pi->adv_speed_list |= MCE_FW_LINK_SPEED_40GB;
			break;
		case MCE_FORCE_100G:
			pi->adv_speed_list |= MCE_FW_LINK_SPEED_100GB;
			break;
		}
	} else {
		if (!ability->sfp_c0_c1_valid) {
			pi->adv_speed_list = MCE_FW_LINK_SPEED_UNKNOWN;
			return;
		}

		if (ability->speed_1g)
			pi->adv_speed_list |= MCE_FW_LINK_SPEED_1000MB;
		if (ability->speed_10g)
			pi->adv_speed_list |= MCE_FW_LINK_SPEED_10GB;
		if (ability->speed_25g)
			pi->adv_speed_list |= MCE_FW_LINK_SPEED_25GB;
		if (ability->speed_40g)
			pi->adv_speed_list |= MCE_FW_LINK_SPEED_40GB;
		if (ability->speed_100g)
			pi->adv_speed_list |= MCE_FW_LINK_SPEED_100GB;
	}
}

static void mce_get_port_media_type(struct mce_hw *hw,
				    struct mce_phy_ability *ability)
{
	struct mce_port_info *pi = hw->port_info;

	pi->media_type = 0;
	if (ability->is_backplane) {
		pi->media_type = MCE_MEDIA_BACKPLANE;
	} else if (ability->is_sgmii) {
		pi->media_type = MCE_MEDIA_BASET;
	} else {
		if (ability->sfp_c0_c1_valid) {
			if (ability->acc)
				pi->media_type = MCE_MEDIA_COPPER;
			else if (ability->dac)
				pi->media_type = MCE_MEDIA_DA;
			else if (ability->sfp_rj45_or_t)
				pi->media_type = MCE_MEDIA_BASET;
			else
				pi->media_type = MCE_MEDIA_FIBER;
		} else {
			pi->media_type = MCE_MEDIA_UNKNOWN;
		}
	}
}

static void mce_get_port_module_type_by_fiber(struct mce_hw *hw,
					      struct mce_phy_ability *ability,
					      bool is_sup, u16 speed_list,
					      u32 *module_type)
{
	struct mce_port_info *pi = hw->port_info;
	bool fiber_40_100g;
	bool card_40_100g;

	fiber_40_100g = !!(speed_list &
			   (MCE_FW_LINK_SPEED_40GB | MCE_FW_LINK_SPEED_100GB));
	card_40_100g = !!(hw->max_speed >= 40000);

	if (!ability || ability->is_sgmii)
		return;

	/* backplane */
	if (ability->is_backplane) {
		if (card_40_100g)
			*module_type |= BIT(MCE_MODULE_KR4);
		else
			*module_type |= BIT(MCE_MODULE_KR);
		return;
	}

	/* if support link capability, all module support */
	if (is_sup) {
		if (card_40_100g) {
			*module_type |= BIT(MCE_MODULE_CR4);
			*module_type |= BIT(MCE_MODULE_CR);
			*module_type |= BIT(MCE_MODULE_SR4);
			*module_type |= BIT(MCE_MODULE_SR);
			*module_type |= BIT(MCE_MODULE_LR4_ER4);
			*module_type |= BIT(MCE_MODULE_LR_ER);
			*module_type |= BIT(MCE_MODULE_1G_X);
			*module_type |= BIT(MCE_MODULE_1G_T);
			*module_type |= BIT(MCE_MODULE_BASET);
		} else {
			*module_type |= BIT(MCE_MODULE_CR);
			*module_type |= BIT(MCE_MODULE_SR);
			*module_type |= BIT(MCE_MODULE_LR_ER);
			*module_type |= BIT(MCE_MODULE_1G_X);
			*module_type |= BIT(MCE_MODULE_1G_T);
			*module_type |= BIT(MCE_MODULE_BASET);
		}
		return;
	}

	if (pi->media_type == MCE_MEDIA_BASET) {
		*module_type |= BIT(MCE_MODULE_BASET);
		return;
	}

	/* 40/100G card with 40/100G fiber */
	if (card_40_100g && fiber_40_100g) {
		/* 40G/100G */
		if (speed_list & MCE_FW_LINK_SPEED_40GB ||
		    speed_list & MCE_FW_LINK_SPEED_100GB) {
			switch (ability->c0) {
			case QSFP_C_CR4:
				*module_type |= BIT(MCE_MODULE_CR4);
				break;
			case QSFP_C_SR4:
				*module_type |= BIT(MCE_MODULE_SR4);
				break;
			case QSFP_C_LR4:
			case QSFP_C_PSM4:
			case QSFP_C_ER4:
			case QSFP_C_CWDM4:
			case QSFP_C_CLR4:
			case QSFP_C_SWDM4:
				*module_type |= BIT(MCE_MODULE_LR4_ER4);
				break;
			default:
				break;
			}
		}

		/* 10G */
		if (speed_list & MCE_FW_LINK_SPEED_10GB) {
			switch (ability->c0_10g) {
			case QSFP_C_10G_SR:
				*module_type |= BIT(MCE_MODULE_SR);
				break;
			case QSFP_C_10G_LR:
			case QSFP_C_10G_LRM:
				*module_type |= BIT(MCE_MODULE_LR_ER);
				break;
			default:
				break;
			}
		}

		/* 1G */
		if (speed_list & MCE_FW_LINK_SPEED_10GB) {
			switch (ability->c0_1g) {
			case QSFP_C_1G_SX:
			case QSFP_C_1G_LX:
			case QSFP_C_1G_CX:
				*module_type |= BIT(MCE_MODULE_1G_X);
				break;
			default:
				break;
			}
		}
		return;
	}

	/* 25G card or 40/100G card with 1/10/25G fiber */
	/* 10G/25G */
	if (speed_list & MCE_FW_LINK_SPEED_10GB ||
	    speed_list & MCE_FW_LINK_SPEED_25GB) {
		switch (ability->c1) {
		case SFP_C_CR:
			*module_type |= BIT(MCE_MODULE_CR);
			break;
		case SFP_C_SR:
			*module_type |= BIT(MCE_MODULE_SR);
			break;
		case SFP_C_LR:
		case SFP_C_LRM:
		case SFP_C_ER:
			*module_type |= BIT(MCE_MODULE_LR_ER);
			break;
		case SFP_C_KR:
			*module_type |= BIT(MCE_MODULE_KR);
			break;
		default:
			if (pi->media_type == MCE_MEDIA_DA)
				*module_type |= BIT(MCE_MODULE_CR);
			/* unknown fiber */
			if (pi->media_type == MCE_MEDIA_FIBER)
				*module_type |= BIT(MCE_MODULE_SR);
			break;
		}
	}

	/* 1G */
	if (speed_list & MCE_FW_LINK_SPEED_1000MB) {
		switch (ability->c1_1g) {
		case SFP_C_1G_SX:
		case SFP_C_1G_LX:
		case SFP_C_1G_CX:
			*module_type |= BIT(MCE_MODULE_1G_X);
			break;
		default:
			if (pi->media_type == MCE_MEDIA_DA)
				*module_type |= BIT(MCE_MODULE_1G_T);
			/* unknown fiber */
			if (pi->media_type == MCE_MEDIA_FIBER)
				*module_type |= BIT(MCE_MODULE_1G_X);
			break;
		}
	}
}

static void mce_get_port_module_type_by_sgmii(struct mce_hw *hw,
					      struct mce_phy_ability *ability,
					      bool is_sup, u16 speed_list,
					      u32 *module_type)
{
	if (!ability || !ability->is_sgmii)
		return;
	if (is_sup) {
		*module_type |= BIT(MCE_MODULE_1G_T);
		return;
	}
	*module_type |= BIT(MCE_MODULE_1G_T);
}

void mce_get_port_phy_ability(struct mce_hw *hw)
{
	struct mce_phy_ability *adv = NULL, *sup = NULL;
	struct mce_port_info *pi = hw->port_info;
	u32 *module_type;
	u16 speed_list;
	bool autoneg;
	u32 parse_v;

	hw->ops->update_fw_stat(hw);
	parse_v = hw->fw_stat.stat2.v;
	adv = (struct mce_phy_ability *)&parse_v;
	/* support speed */
	mce_get_port_speed_list(hw, adv);

	/* media type */
	mce_get_port_media_type(hw, adv);

	/* get advised module type */
	pi->adv_module_type = 0;
	speed_list = pi->adv_speed_list;
	module_type = &pi->adv_module_type;
	mce_get_port_module_type_by_fiber(hw, adv, false, speed_list,
					  module_type);
	mce_get_port_module_type_by_sgmii(hw, adv, false, speed_list,
					  module_type);

	/* get support module type */
	speed_list = pi->sup_speed_list;
	pi->sup_module_type = 0;
	module_type = &pi->sup_module_type;
	sup = adv;
	mce_get_port_module_type_by_fiber(hw, sup, true, speed_list,
					  module_type);
	mce_get_port_module_type_by_sgmii(hw, sup, true, speed_list,
					  module_type);

	autoneg = adv->is_backplane ? !!hw->fw_stat.stat0.autoneg :
					 !adv->force_speed_by_user;
	if (adv->force_speed_by_user) {
		pi->adv_module_type = pi->sup_module_type;
	} else if (autoneg || !hw->fw_stat.stat0.linkup) {
		pi->adv_speed_list = pi->sup_speed_list;
		pi->adv_module_type = pi->sup_module_type;
	}

	hw_logd(LOG_LINK_INFO,
		"%s phy ability original value:%x, disable 40/100G card 25G and below:%d max_speed:%d\n",
		__func__, parse_v,
		READ_ONCE(hw->disable_40_100g_card_25g_and_below),
		hw->max_speed);
	hw_logd(LOG_LINK_INFO,
		"%s media_type:0x%x sup_speed_list:0x%x sup_module_type:0x%x\n",
		__func__, pi->media_type, pi->sup_speed_list,
		pi->sup_module_type);
	hw_logd(LOG_LINK_INFO,
		"%s media_type:0x%x adv_speed_list:0x%x adv_module_type:0x%x\n",
		__func__, pi->media_type, pi->adv_speed_list,
		pi->adv_module_type);
}

static int mce_init_hw(struct mce_hw *hw)
{
	struct tuple4_policy *tp_list;
	struct device *dev = hw->dev;
	bool is_32bit_bar = false;
	int err = 0;
	int i;

	if ((pci_resource_flags(hw->pdev, 0) & PCI_BASE_ADDRESS_MEM_TYPE_32) ||
	    (pci_resource_flags(hw->pdev, 2) & PCI_BASE_ADDRESS_MEM_TYPE_32)) {
		is_32bit_bar = true;
	}

	if (is_32bit_bar) {
		hw->bar_3th_sz = pci_resource_len(hw->pdev, 2);
		hw->bar_3th_phy = pci_resource_start(hw->pdev, 2);
		hw->bar_2th_sz = pci_resource_len(hw->pdev, 1);
		hw->bar_2th_phy = pci_resource_start(hw->pdev, 1);
		hw->bar_1th_sz = pci_resource_len(hw->pdev, 0);
		hw->bar_1th_phy = pci_resource_start(hw->pdev, 0);
		hw->bar_3th = pcim_iomap(hw->pdev, 2, 0);
		hw->bar_2th = pcim_iomap(hw->pdev, 1, 0);
		hw->bar_1th = pcim_iomap(hw->pdev, 0, 0);
	} else {
		hw->bar_3th_sz = pci_resource_len(hw->pdev, 4);
		hw->bar_3th_phy = pci_resource_start(hw->pdev, 4);
		hw->bar_2th_sz = pci_resource_len(hw->pdev, 2);
		hw->bar_2th_phy = pci_resource_start(hw->pdev, 2);
		hw->bar_1th_sz = pci_resource_len(hw->pdev, 0);
		hw->bar_1th_phy = pci_resource_start(hw->pdev, 0);
		hw->bar_3th = pcim_iomap(hw->pdev, 4, 0);
		hw->bar_2th = pcim_iomap(hw->pdev, 2, 0);
		hw->bar_1th = pcim_iomap(hw->pdev, 0, 0);
	}

	switch (hw->hw_type) {
	case board_n20:
		hw->eth_bar_base = hw->bar_3th;
		if (!hw->eth_bar_base) {
			dev_err(dev, "pcim_iomap bar4 failed!\n");
			err = -EIO;
			goto err_ioremap_eth;
		}
		if (hw->bar_3th_sz >= 2 * 1024 * 1024) {
			hw->rdma_bar_base =
				hw->eth_bar_base + (1 * 1024 * 1024);
			hw->rdma_bar_phy = hw->bar_3th_phy + (1 * 1024 * 1024);
			dev_info(dev, "RDMA: ETH(bar4) PA:%pa\n",
				 &hw->rdma_bar_phy);
		}

		hw->axi_mode = AXI_NO_FORCE;
		/* 25G card, insmod params force fw axi mhz */
		if (hw->device_id == PCI_DEVICE_ID_N20_25G && clk_tube == 1)
			hw->axi_mode = AXI_333_MHZ;
		if (mce_get_n20_caps(hw) < 0) {
			dev_err(dev, "Failed to mce_get_n20_caps\n");
			err = -EIO;
			goto err_hw_type;
		}

		err = mce_get_msix_vector(hw);
		if (err)
			goto err_hw_type;
		hw->vector_bar_base = hw->eth_bar_base;

		if (hw->bar_1th_sz >= (8 * 1024 * 1024) &&
		    hw->func_caps.common_cap.npu_capable) {
			hw->npu_bar_base = hw->bar_1th;
			if (!hw->npu_bar_base) {
				dev_err(dev, "pcim_iomap bar0 failed!\n");
				err = -EIO;
				goto err_ioremap_npu;
			}
			if (hw->func_caps.common_cap.npu_capable)
				hw->func_caps.common_cap.npu_en = true;
		}
		if (!hw->vector_bar_base) {
			dev_err(dev, "no vector_bar_base!\n");
			err = -EIO;
			goto err_ioremap_npu;
		}
		break;
	default:
		dev_err(dev, "device not supported!");
		err = -EINVAL;
		goto err_hw_type;
	}

	if (!hw->port_info) {
		hw->port_info =
			devm_kzalloc(dev, sizeof(*hw->port_info), GFP_KERNEL);
		if (!hw->port_info) {
			err = -ENOMEM;
			goto err_hw_type;
		}
	}
	mce_reset_hw(hw);

	mutex_init(&hw->fdir_fltr_lock);
	INIT_LIST_HEAD(&hw->fdir_list_head);
	INIT_LIST_HEAD(&hw->vlan_list_head);

	hash_init(hw->uc_hash_tb);
	hash_init(hw->mc_hash_tb);
	spin_lock_init(&hw->mac_hash_lock);

	mutex_init(&hw->tnl_lock);
	memset(&hw->tnl, 0x0, sizeof(hw->tnl));

	INIT_LIST_HEAD(&hw->tuple4_policy.l);

	tp_list = kcalloc(MCE_VEB_MAX_VF_MACVLAN_NUMS,
			  sizeof(struct tuple4_policy), GFP_KERNEL);
	hw->tuple4_policy_list = tp_list;
	if (!hw->tuple4_policy_list) {
		err = -ENOMEM;
		goto err_free_port_info;
	}

	for (i = 0; i < MCE_VEB_MAX_VF_MACVLAN_NUMS; i++) {
		tp_list->free = true;
		tp_list->entry = i;
		list_add(&tp_list->l, &hw->tuple4_policy.l);
		tp_list++;
	}

#define SP_TIMEOUT_DEFAULT 1000
	hw->sp_timeout = SP_TIMEOUT_DEFAULT;

	/* init custom tunnel packets dport */
	for (i = 0; i < MCE_TUNNEL_MAX_ENTRIES; i++) {
		hw->tnl[TNL_VXLAN].tbl[i].default_port = 4789;
		hw->tnl[TNL_VXLAN_GPE].tbl[i].default_port = 4790;
		hw->tnl[TNL_GENEVE].tbl[i].default_port = 6081;
	}

	hw->disable_40_100g_card_25g_and_below =
		MCE_DISABLE_40_100G_CARD_25G_AND_BELOW_DEFAULT;

	return err;
err_free_port_info:
	devm_kfree(dev, hw->port_info);
err_hw_type:
	hw->npu_bar_base = NULL;
err_ioremap_npu:
	hw->rdma_bar_base = NULL;
	hw->eth_bar_base = NULL;
err_ioremap_eth:
	return err;
}

static bool mce_need_dis_irq_affinity(struct mce_pf __always_unused *pf)
{
	return false;
}

void mce_set_pf_caps(struct mce_pf *pf)
{
	struct mce_hw_func_caps *func_caps = &pf->hw.func_caps;
	struct mce_hw_common_caps *common_cap = &func_caps->common_cap;

	clear_bit(MCE_FLAG_SRIOV_CAPABLE, pf->flags);
	if (common_cap->sr_iov) {
		set_bit(MCE_FLAG_SRIOV_CAPABLE, pf->flags);
		set_bit(MCE_FLAG_ESWITCH_CAPABLE, pf->flags);
	}

	if (pcie_irq_mode == MCE_PCIE_IRQ_MODE_NONE)
		pf->pcie_irq_mode = MCE_PCIE_IRQ_MODE_MSIX;
	else
		pf->pcie_irq_mode = pcie_irq_mode;
	pf->bridge_mode = BRIDGE_MODE_VEB;

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		pf->max_pf_txqs = common_cap->vf_num_txq;
		pf->max_pf_rxqs = common_cap->vf_num_rxq;
	} else {
		pf->max_pf_txqs = common_cap->num_txq;
		pf->max_pf_rxqs = common_cap->num_rxq;
	}
	pf->num_msix_cnt = common_cap->max_irq_cnts;
	pf->max_vfs = common_cap->max_vfs;
	pf->mbox_irq_base = common_cap->mbox_irq_base;
	pf->num_mbox_irqs = common_cap->num_mbox_irqs;
	pf->num_rdma_irqs = common_cap->num_rdma_irqs;
	if (pf->pcie_irq_mode == MCE_PCIE_IRQ_MODE_MSIX) {
		pf->qvec_irq_base = common_cap->qvec_irq_base;
	} else {
		/* no pcie msix mode, we only support 1 pcie vector */
		pf->qvec_irq_base = 0;
	}
	pf->vlan_strip_cnt = common_cap->vlan_strip_cnt;
	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		pf->num_max_tc = 1;
	else
		pf->num_max_tc = common_cap->max_tc;

	pf->num_q_for_tc = common_cap->queue_for_tc;
	pf->mac_misc_irq = common_cap->mac_misc_irq;
	pf->mac_misc_irq_retry = common_cap->mac_misc_irq_retry;
	pf->npu_capable = common_cap->npu_capable;
	pf->npu_en = common_cap->npu_en;
	pf->num_alloc_vsi = func_caps->guar_num_vsi;

	if (common_cap->pcie_irq_capable & BIT(MCE_PCIE_IRQ_MODE_MSIX))
		set_bit(MCE_FLAG_IRQ_MSIX_CAPABLE, pf->flags);
	if (common_cap->pcie_irq_capable & BIT(MCE_PCIE_IRQ_MODE_MSI))
		set_bit(MCE_FLAG_IRQ_MSI_CAPABLE, pf->flags);
	if (common_cap->pcie_irq_capable & BIT(MCE_FLAG_IRQ_LEGACY_CAPABLE))
		set_bit(MCE_FLAG_IRQ_LEGACY_CAPABLE, pf->flags);

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		pf->rss_tb_size = common_cap->vf_rss_tb_size;
	else
		pf->rss_tb_size = common_cap->pf_rss_tb_size;
	pf->xmit_check_intr_drop = common_cap->xmit_check_intr_drop;
	pf->poll_check_intr_drop = common_cap->poll_check_intr_drop;

	pf->d_txqueue.permit = true;
	pf->drop_intr_timer_en = func_caps->common_cap.drop_intr_timer_en;
	pf->cline_size = cache_line_size();
	pf->dis_irq_affinity = mce_need_dis_irq_affinity(pf);
}

static int mce_init_devlink(struct mce_pf *pf)
{
	int err;

	mce_devlink_register(pf);
	err = mce_devlink_register_params(pf);

	if (err)
		return err;

	return 0;
}

static void mce_deinit_devlink(struct mce_pf *pf)
{
	mce_devlink_unregister(pf);
	mce_devlink_unregister_params(pf);
}

static int mce_pf_init_dcb(struct mce_pf *pf)
{
	struct mce_dcb *dcb = NULL;

	dcb = devm_kzalloc(mce_pf_to_dev(pf), sizeof(*pf->dcb), GFP_KERNEL);
	if (!dcb)
		return -ENOMEM;

	clear_bit(MCE_DSCP_EN, dcb->flags);
	clear_bit(MCE_ETS_EN, dcb->flags);
	clear_bit(MCE_DCB_EN, dcb->flags);
	clear_bit(MCE_PFC_EN, dcb->flags);
	set_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
	set_bit(MCE_FLAG_PF_DCB_TOOLS, pf->flags);
	set_bit(MCE_FLAG_PFC_RR_MODE, pf->flags);

	mce_dcb_tc_default(&dcb->cur_tccfg);
	mce_dcb_tc_default(&dcb->new_tccfg);
	mce_dcb_ets_default(&dcb->cur_etscfg);
	mce_dcb_ets_default(&dcb->new_etscfg);
	mce_dcb_pfc_default(&dcb->cur_pfccfg);
	mce_dcb_pfc_default(&dcb->backup_pfccfg);
	mce_dcb_pfc_default(&dcb->new_pfccfg);

	memset(dcb->vlan_to_q, 0xff, MCE_MAX_VLAN);
	dcb->back = pf;
	pf->dcb = dcb;

	mutex_init(&dcb->dcb_mutex);

	return 0;
}

static void mce_pf_deinit_dcb(struct mce_pf *pf)
{
	struct mce_dcb *dcb = pf->dcb;

	if (dcb) {
		mutex_destroy(&dcb->dcb_mutex);
		devm_kfree(mce_pf_to_dev(pf), dcb);
		pf->dcb = NULL;
	}
}

static bool mce_pcie_support_mrdma(struct mce_pf *pf)
{
	return pf->hw.rdma_bar_base &&
	       pf->pcie_irq_mode == MCE_PCIE_IRQ_MODE_MSIX;
}

static int mcepf_inetaddr_event(struct notifier_block *nb, unsigned long event,
				void *ptr)
{
	struct mce_pf *pf = container_of(nb, struct mce_pf, inet_nb);
	struct mce_hw *hw = &pf->hw;
	struct in_ifaddr *ifa = ptr;
	struct net_device *netdev;
	struct mce_vsi *vsi;
	int ovf;

	/* Safety check - ifa or ifa_dev might be NULL during some events */
	if (!ifa || !ifa->ifa_dev)
		return NOTIFY_DONE;

	netdev = ifa->ifa_dev->dev;
	if (!netdev)
		return NOTIFY_DONE;

	/* Only care about our own network device */
	vsi = mce_get_main_vsi(pf);
	if (!vsi || !vsi->netdev || netdev != vsi->netdev)
		return NOTIFY_DONE;

	if (test_bit(MCE_REMOVED, pf->state))
		return NOTIFY_OK;

	switch (event) {
	case NETDEV_UP:
		pf->ipv4_addr = ifa->ifa_address;

		if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
			return NOTIFY_OK;

		mce_pf_to_vf(pf)->vfinfo[PFINFO_IDX].vf_ipv4_addr =
			pf->ipv4_addr;
		/* Check for IP address conflict within the same VLAN */
		ovf = mce_vc_check_ipv4_conflict_with_vf(pf, PFINFO_IDX,
							 pf->ipv4_addr);
		if (ovf >= 0) {
			dev_err(mce_pf_to_dev(pf),
				"PF IPv4 address %pI4 conflicts with VF %d in VLAN %d\n",
				&pf->ipv4_addr, ovf,
				mce_pf_to_vf(pf)->vfinfo[ovf].pf_vlan);
		}
		break;
	case NETDEV_DOWN:
		pf->ipv4_addr = 0;

		if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
			return NOTIFY_OK;

		mce_pf_to_vf(pf)->vfinfo[PFINFO_IDX].vf_ipv4_addr =
			pf->ipv4_addr;
		break;
	}

	return NOTIFY_OK;
}

static int mcepf_netdev_event(struct notifier_block *this, unsigned long event,
			      void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct vlan_dev_priv *vlan = NULL;
	struct mce_netdev_priv *np;
	struct mce_pf *pf = NULL;
	u16 vid = 0;

	if (is_vlan_dev(netdev)) {
		vlan = vlan_dev_priv(netdev);
		if (!netif_is_mce(vlan->real_dev))
			return NOTIFY_OK;
		np = netdev_priv(vlan->real_dev);
		if (np && np->vsi && np->vsi->back)
			pf = np->vsi->back;
	} else {
		if (!netif_is_mce(netdev))
			return NOTIFY_OK;
		np = netdev_priv(netdev);
		if (np && np->vsi && np->vsi->back)
			pf = np->vsi->back;
	}
	if (!pf)
		return NOTIFY_OK;

	if (test_bit(MCE_REMOVED, pf->state))
		return NOTIFY_OK;

	switch (event) {
	case NETDEV_CHANGENAME: {
#ifdef CONFIG_DEBUG_FS
		mce_debugfs_eth_link_rename(pf, netdev_name(netdev));
#endif
		break;
	}
	case NETDEV_REGISTER: {
		if (is_vlan_dev(netdev)) {
			vid = vlan_dev_vlan_id(netdev);
			__set_bit(vid, pf->nb_vlan_bitmap);
		}
		break;
	}
	case NETDEV_UNREGISTER: {
		if (is_vlan_dev(netdev)) {
			vid = vlan_dev_vlan_id(netdev);
			__clear_bit(vid, pf->nb_vlan_bitmap);
		}
		break;
	}
	case NETDEV_DOWN:
	case NETDEV_UP:
	case NETDEV_CHANGEMTU:
	case NETDEV_CHANGEADDR:
	case NETDEV_GOING_DOWN:
	case NETDEV_CHANGE:
	default:
		break;
	}
	return NOTIFY_OK;
}

static int mce_init_pf(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	int err = 0;

	mce_set_pf_caps(pf);

	mutex_init(&pf->sw_mutex);
	mutex_init(&pf->adev_mutex);
	bitmap_zero(pf->nb_vlan_bitmap, VLAN_N_VID);
	bitmap_zero(pf->vlan_bitmap, VLAN_N_VID);

	/* Initialize bond membership state */
	pf->bond_upper = NULL;
	pf->bond_linked = false;

	/* Initialize async aux operation state */
	pf->aux_op_pending = MCE_AUX_OP_NONE;
	pf->aux_op_upper = NULL;

#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
	INIT_DELAYED_WORK(&pf->tx_hwtstamp_work, mce_tx_hwtstamp_work);
	pf->tx_timeout_factor = 10; /* 10s for ptp timeout */
#endif

	/* setup service timer and periodic service task */
	timer_setup(&pf->serv_tmr, mce_service_timer, 0);
	if (pf->drop_intr_timer_en) {
		pf->serv_tmr_max_cnt = __MCE_SERV_TIMER_PERIODS_CNT;
		pf->serv_tmr_period = __MCE_SERV_TIMER_PERIODS_UNIT;
	} else {
		pf->serv_tmr_max_cnt = 1;
		pf->serv_tmr_period = __MCE_SERV_TIMER_PERIODS_UNIT *
				      __MCE_SERV_TIMER_PERIODS_CNT;
	}
	INIT_WORK(&pf->serv_task, mce_service_task);
	clear_bit(MCE_SERVICE_SCHED, pf->state);
	set_bit(MCE_FLAG_SW_DIM_ENA, pf->flags);
	set_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags);
	clear_bit(MCE_FLAG_PF_ANTISPOOF, pf->flags);

	memset(&pf->fc, 0x0, sizeof(struct mce_flow_control));

	err = mce_pf_init_dcb(pf);
	if (err) {
		dev_err(mce_pf_to_dev(pf), "init dcb failed\n");
		return err;
	}
	mce_realloc_and_fill_pfinfo(pf, false);
	/* setup tunnel inner layer */
	if (pf->tun_inner) {
		set_bit(TNL_INNER_EN, hw->l2_fltr_flags);
		set_bit(MCE_FLAG_TUNNEL_INNER_ENA, pf->flags);
	}
	hw->ops->set_tun_select_inner(hw, pf->tun_inner);

	set_bit(MCE_FLAG_DDP_EXTRA_ENA, pf->flags);
	hw->ops->set_ddp_extra_en(hw, true);
	pf->pcie_restore_cnt = raw_rd32(hw->eth_bar_base + 0x33000 +
					MCE_SOC_PCIE_RESTORE_CNT_REG);
	return 0;
}

/**
 * mce_deinit_pf - Unrolls initialziations done by mce_init_pf
 * @pf: board private structure to initialize
 */
static void mce_deinit_pf(struct mce_pf *pf)
{
	mutex_destroy(&pf->sw_mutex);
	mutex_destroy(&pf->adev_mutex);

	mce_pf_deinit_dcb(pf);
}

/**
 * mce_pf_vsi_setup - Set up a PF VSI
 * @pf: board private structure
 *
 * Returns: pointer to the successfully allocated VSI software struct
 * on success, otherwise returns NULL on failure.
 */
static struct mce_vsi *mce_pf_vsi_setup(struct mce_pf *pf)
{
	return mce_vsi_setup(pf, MCE_VSI_PF);
}

static void mce_setup_fc_status(struct mce_pf *pf)
{
	struct mce_flow_control *fc = &pf->fc;

	fc->req_mode = MCE_FC_FULL;
}

static void mce_setup_default_vport(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;

	pf->default_vport = hw->func_caps.common_cap.max_vfs;
}

/**
 * mce_setup_pf_sw - Setup the HW switch on startup or after reset
 * @pf: board private structure
 *
 * Returns: 0 on success, negative value on failure
 */
static int mce_setup_pf_sw(struct mce_pf *pf)
{
	struct mce_vsi *vsi;
	int status = 0;

	vsi = mce_pf_vsi_setup(pf);
	if (!vsi) {
		dev_err(&pf->pdev->dev, "pf vsi setup failed!\n");
		return -ENOMEM;
	}

	mce_setup_fc_status(pf);
	status = mce_cfg_netdev(vsi);
	if (status) {
		dev_err(&pf->pdev->dev, "cfg netdev failed!\n");
		goto unroll_vsi_setup;
	}
	mce_setup_default_vport(pf);
	/* registering the NAPI handler requires both the queues and
	 * netdev to be created, which are done in mce_pf_vsi_setup()
	 * and mce_cfg_netdev() respectively
	 */
	mce_napi_add(vsi);

	return status;

unroll_vsi_setup:
	mce_vsi_release(vsi);

	return status;
}

static void mce_mailbox_incoming_event_irq_handler(struct mce_mbx_info *mbx,
						   int event_id)
{
	/* event request */
	if (mbx->is_vf_mbx) { /* VF2PF */
		mce_mbx_vf_event_req_isr(mbx, event_id);
	} else { /* FW2PF */
		mce_mbx_fw_event_req_isr(mbx, event_id);
	}
}

static void mce_mailbox_incoming_req_irq_handler(struct mce_mbx_info *mbx,
						 struct mbx_req *req)
{
	/* req with data */
	if (mbx->is_vf_mbx) { /* VF2PF */
		mce_mbx_vf_req_isr(mbx, req);
	} else { /* FW2PF */
		mce_mbx_fw_req_isr(mbx, req);
	}
}

/**
 * mce_misc_intr - misc interrupt handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 * Returns: The result of the operation.
 */
irqreturn_t mce_misc_intr(int __always_unused irq, void *data)
{
	bool misc_irq_pending = false;
	struct mce_pf *pf = data;
	struct mce_hw *hw = &pf->hw;
	int type_idx = 0;

	pf_logd(LOG_MISC_IRQ, "%s: %s irq:%d\n", __func__, pf->int_name, irq);

	mce_mbx_clean_all_incoming_req(&pf->hw,
				       mce_mailbox_incoming_event_irq_handler,
					mce_mailbox_incoming_req_irq_handler);

	mce_for_each_misc_irq(type_idx) {
		if (mce_get_misc_irq_evt(hw, type_idx)) {
			misc_irq_pending = true;
			mce_pre_handle_misc_irq(hw, type_idx);
		}
	}
	if (misc_irq_pending)
		mce_service_task_schedule(pf);
	return IRQ_WAKE_THREAD;
}

/**
 * mce_misc_intr_thread_fn - misc interrupt thread function
 * @irq: interrupt number
 * @data: pointer to a q_vector
 * Returns: The result of the operation.
 */
static irqreturn_t mce_misc_intr_thread_fn(int __always_unused irq, void *data)
{
	return IRQ_HANDLED;
}

/**
 * mce_req_irq_msix_misc - Setup the misc vector to handle non queue events
 * @pf: board private structure
 *
 * This sets up the handler for MSIX 0, which is used to manage the
 * non-queue interrupts, e.g. AdminQ and errors. This is not used
 * when in MSI or Legacy interrupt mode.
 * Returns: The result of the operation.
 */
static int mce_req_irq_msix_misc(struct mce_pf *pf)
{
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_hw *hw = &pf->hw;
	int err = 0, nr_vec;

	if (pf->pcie_irq_mode != MCE_PCIE_IRQ_MODE_MSIX) {
		pf->mbox_irq_base = MCE_MBOX_IRQ_NO_MSIX_BASE;
		goto misc_share_ring_irq;
	}

	err = mce_get_irq_res(pf, pf->irq_tracker, pf->num_mbox_irqs,
			      pf->mbox_irq_base);
	if (err) {
		dev_err(dev, "No irq rem for mbox\n");
		return err;
	}
	nr_vec = pf->mbox_irq_base;
	if (!pf->int_name[0])
		snprintf(pf->int_name, sizeof(pf->int_name) - 1, "%s-%s:misc",
			 dev_driver_string(dev), dev_name(dev));

	err = devm_request_threaded_irq(dev,
					mce_get_irq_num(pf, pf->mbox_irq_base),
					mce_misc_intr, mce_misc_intr_thread_fn,
					0, pf->int_name, pf);
	if (err) {
		dev_err(dev, "devm_request_threaded_irq for %s failed",
			pf->int_name);
		mce_free_irq_res(pf->irq_tracker, pf->num_mbox_irqs,
				 pf->mbox_irq_base);
		goto out;
	}

	/* TODO: must test other irq in mis/legacy mode */
	mce_setup_misc_irq(hw, true, nr_vec);
misc_share_ring_irq:
	mce_mbx_vector_set(&hw->fw_mbx, pf->mbox_irq_base, true);
out:
	return err;
}

static int create_cdev(struct mce_pf *pf)
{
	struct pci_dev *pdev = pf->pdev;
	int idx;
	int rv;

	spin_lock_init(&pf->spinlock_cdev);
	mutex_init(&pf->cdev_dma_lock);
	mutex_init(&pf->cdev_lock);
	init_waitqueue_head(&pf->cdev_wait);
	INIT_LIST_HEAD(&pf->filp_list);

	idx = pf->bd_number * 2 + pf->nr_pf;
	if (idx >= MAX_MCE_DEVICES) {
		dev_err(&pdev->dev, "cdev index %d exceeds MAX_MCE_DEVICES\n",
			idx);
		return -ENODEV;
	}
	if (test_and_set_bit(idx, cdev_bitmap)) {
		dev_err(&pdev->dev,
			"cdev index %d already in use (bd=%d nr_pf=%d)\n",
			idx, pf->bd_number, pf->nr_pf);
		return -EBUSY;
	}
	pf->index = idx;

	cdev_init(&pf->cdev, &mce_fops);
	pf->cdev.owner = THIS_MODULE;
	rv = cdev_add(&pf->cdev, MKDEV(mce_major, pf->index), 1);
	if (rv) {
		dev_err(&pdev->dev, "cdev_add() failed %d\n", rv);
		kobject_put(&pf->cdev.kobj);
		clear_bit(pf->index, cdev_bitmap);
		return -ENODEV;
	}
	if (IS_ERR(device_create(mce_class, NULL, MKDEV(mce_major, pf->index),
				 NULL, "%s", pf->name))) {
		dev_err(&pdev->dev, "device_create(mce%u) failed\n", pf->index);
		cdev_del(&pf->cdev);
		clear_bit(pf->index, cdev_bitmap);
		return -ENODEV;
	}

	return 0;
}

static int destroy_cdev(struct mce_pf *pf)
{
	spin_lock(&pf->spinlock_cdev);
	pf->open_inhibit = 1;
	spin_unlock(&pf->spinlock_cdev);
	device_destroy(mce_class, MKDEV(mce_major, MINOR(pf->cdev.dev)));
	cdev_del(&pf->cdev);
	clear_bit(pf->index, cdev_bitmap);

	wait_event(pf->cdev_wait, !READ_ONCE(pf->open_count));
	mutex_lock(&pf->cdev_dma_lock);
	if (pf->cdev_dma_buf) {
		dma_free_coherent(&pf->pdev->dev, pf->cdev_dma_size,
				  pf->cdev_dma_buf, pf->cdev_dma_phy);
		pf->cdev_dma_buf = NULL;
		pf->cdev_dma_size = 0;
	}
	mutex_unlock(&pf->cdev_dma_lock);
	mutex_destroy(&pf->cdev_dma_lock);
	mutex_destroy(&pf->cdev_lock);

	return 0;
}

struct card_bus {
	int domain;
	long bus_number;
	u8 slot;
};

static int mce_get_card_number(struct pci_dev *pdev)
{
	int i;

	static struct card_bus cards[64];
	static int card_idx;

	for (i = 0; i < card_idx; i++) {
		if (cards[i].domain == pci_domain_nr(pdev->bus) &&
		    cards[i].bus_number == pdev->bus->number &&
		    cards[i].slot == PCI_SLOT(pdev->devfn)) {
			return i + 1;
		}
	}
	cards[card_idx].domain = pci_domain_nr(pdev->bus);
	cards[card_idx].bus_number = pdev->bus->number;
	cards[card_idx].slot = PCI_SLOT(pdev->devfn);
	card_idx++;

	return card_idx;
}

/**
 * mce_free_irq_msix_misc - Unroll misc vector setup
 * @pf: board private structure
 */
static void mce_free_irq_msix_misc(struct mce_pf *pf)
{
	int irq_num = mce_get_irq_num(pf, pf->mbox_irq_base);
	struct mce_hw *hw = &pf->hw;

	if (pf->pcie_irq_mode != MCE_PCIE_IRQ_MODE_MSIX) {
		pf->mbox_irq_base = MCE_MBOX_IRQ_NO_MSIX_BASE;
		goto misc_share_ring_irq;
	}
	synchronize_irq(irq_num);
	devm_free_irq(mce_pf_to_dev(pf), irq_num, pf);

	mce_free_irq_res(pf->irq_tracker, pf->num_mbox_irqs, pf->mbox_irq_base);
	mce_setup_misc_irq(hw, false, 0);
misc_share_ring_irq:
	mce_mbx_vector_set(&hw->fw_mbx, pf->mbox_irq_base, false);
}

/**
 * mce_probe - Device initialization routine
 * @pdev: PCI device information struct
 * @id: pci device id
 *
 * Returns: 0 on success, negative on failure
 */
static int mce_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct mce_pf *pf = NULL;
	struct mce_hw *hw = NULL;
	int err = 0;

	if (pdev->is_virtfn) {
		dev_err(dev, "can't probe a virtual function\n");
		return -EINVAL;
	}

	dev_info(dev, DRIVER_NAME " PCI probe version:%s", DRV_VERSION);
	dev_info(dev, DRIVER_NAME " %s", GIT_COMMIT);

	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	pf = mce_allocate_pf(dev);
	if (!pf)
		return -ENOMEM;
	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (err) {
		err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(dev, "DMA MASK 32 failed: 0x%x\n", err);
			return err;
		}
	}

	pci_set_master(pdev);

	pf->pdev = pdev;
	pci_set_drvdata(pdev, pf);
	set_bit(MCE_DOWN, pf->state);

	hw = &pf->hw;
	pdev->dev_flags |= PCI_DEV_FLAGS_NO_D3;
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
	pf->bd_number = mce_get_card_number(pdev);

	pf->msg_enable = netif_msg_init(debug, MCE_DFLT_NETIF_M);
	err = pci_request_mem_regions(pdev, dev_driver_string(dev));
	if (err) {
		dev_err(dev, "pci_request_selected_regions failed 0x%x\n", err);
		goto err_regions;
	}

	pci_save_state(pdev);

	err = mce_init_hw(hw);
	if (err) {
		dev_err(dev, "mce_init_hw failed: %d", err);
		goto err_init_hw;
	}

	snprintf(pf->name, sizeof(pf->name), "mcepf%d%d", pf->bd_number,
		 pf->nr_pf);

	pf->tun_inner = tun_inner;
	err = mce_init_pf(pf);
	if (err) {
		dev_err(dev, "mce_init_hw failed: %d", err);
		goto err_init_pf;
	}

	err = mce_init_devlink(pf);
	if (err)
		goto err_init_pf;

	hw->ops->set_fd_fltr_guar(hw);
	if (!pf->num_alloc_vsi)
		pf->num_alloc_vsi = 1;
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

	err = mce_init_interrupt_scheme(pf);
	if (err) {
		dev_err(dev, "mce_init_interrupt_scheme failed: %d", err);
		err = -EIO;
		goto err_init_interrupt_scheme;
	}

	err = mce_setup_pf_sw(pf);
	if (err) {
		dev_err(dev, "probe failed due to setup PF switch");
		goto err_setup_pf_sw;
	}

	/* In case of MSIX we are going to setup the misc vector right here
	 * to handle admin queue events etc. In case of legacy and MSI
	 * the misc functionality and queue processing is combined in
	 * the same vector and that gets setup at open.
	 */
	err = mce_req_irq_msix_misc(pf);
	if (err) {
		dev_err(dev, "setup of misc vector failed: %d", err);
		goto err_setup_pf_sw;
	}

	/* ready to go, so clear down state bit */
	clear_bit(MCE_DOWN, pf->state);
	clear_bit(MCE_SERVICE_DIS, pf->state);

	/* Register event notifiers BEFORE registering netdev to avoid missing events */
	pf->nb.notifier_call = mcepf_netdev_event;
	err = register_netdevice_notifier(&pf->nb);
	if (err) {
		dev_err(dev, "failed to register netdevice notifier: %d\n", err);
		goto err_register_notifier;
	}

	pf->inet_nb.notifier_call = mcepf_inetaddr_event;
	err = register_inetaddr_notifier(&pf->inet_nb);
	if (err) {
		dev_err(dev, "failed to register inetaddr notifier: %d\n", err);
		goto err_register_inet_notifier;
	}

	hw->ops->update_fw_stat(hw);
	hw->ops->update_pf_stat(hw);
	hw->vf.ops->set_vf_default_vport(hw, pf->default_vport);
	mce_get_port_phy_ability(hw);
	err = mce_register_netdev(pf);
	if (err) {
		dev_err(dev, "failed to register netdev!\n");
		goto err_netdev_reg;
	}

	if (mce_pcie_support_mrdma(pf)) {
		err = mce_plug_aux_dev(pf);
		if (err)
			dev_err(dev, "failed to register auxdev!\n");
	}

#if IS_ENABLED(CONFIG_SYSFS)
	if (mce_sysfs_init(pf))
		dev_err(dev, "failed to init sysfs!\n");
#endif
	if (create_cdev(pf))
		goto err_init_cdev;

	mce_debugfs_pf_init(pf);
	mod_timer(&pf->serv_tmr, round_jiffies(jiffies + pf->serv_tmr_period));
	return 0;
err_init_cdev:
	if (mce_pcie_support_mrdma(pf))
		mce_unplug_aux_dev(pf);
	mce_vsi_release_all(pf);
err_netdev_reg:
	/* Both notifiers are registered at this point, clean them up in reverse order */
	unregister_inetaddr_notifier(&pf->inet_nb);
	unregister_netdevice_notifier(&pf->nb);
	goto err_register_notifier;
err_register_inet_notifier:
	/* Only netdevice notifier is registered, clean it up */
	unregister_netdevice_notifier(&pf->nb);
err_register_notifier:
	mce_free_irq_msix_misc(pf);
err_setup_pf_sw:
	set_bit(MCE_DOWN, pf->state);
	mce_clear_interrupt_scheme(pf);
err_init_interrupt_scheme:
	devm_kfree(dev, pf->vsi_stats);
	pf->vsi_stats = NULL;
err_init_vsi_stats:
	mce_deinit_devlink(pf);
	devm_kfree(dev, pf->vsi);
	pf->vsi = NULL;
err_init_pf:
	mce_deinit_pf(pf);
err_init_hw:
	pci_clear_master(pdev);
	pci_release_mem_regions(pdev);
err_regions:
	pci_disable_device(pdev);
	return err;
}

/**
 * mce_unmap_all_hw_addr - Release device register memory maps
 * @pf: pointer to the PF structure
 *
 * Release all PCI memory maps and regions.
 */
static void mce_unmap_all_hw_addr(struct mce_pf *pf)
{
	struct pci_dev *pdev = pf->pdev;
	struct mce_hw *hw = &pf->hw;

	hw->eth_bar_base = NULL;
	hw->rdma_bar_base = NULL;
	hw->npu_bar_base = NULL;
	pci_clear_master(pdev);
	pci_release_mem_regions(pdev);
}

static void mce_release_mac_fltr(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;

	mce_clear_mac_hash_list(hw, MCE_MAC_ADDR_UC);
	mce_clear_mac_hash_list(hw, MCE_MAC_ADDR_MC);
}

/**
 * mce_deinit_hw - Release device register memory maps
 * @pf: pointer to the PF structure
 *
 */
static void mce_deinit_hw(struct mce_pf *pf)
{
	struct mce_vlan_list_entry *vlan_l, *v_tmp;
	struct mce_fdir_fltr *f_rule, *f_tmp;
	struct mce_hw *hw = &pf->hw;
	struct list_head *pos, *q;

	/* free tuple4_policy list */
	list_for_each_safe(pos, q, &hw->tuple4_policy.l)
		list_del(pos);
	kfree(hw->tuple4_policy_list);

	mutex_lock(&hw->fdir_fltr_lock);
	list_for_each_entry_safe(f_rule, f_tmp, &hw->fdir_list_head,
				 fltr_node) {
		list_del(&f_rule->fltr_node);
		devm_kfree(hw->dev, f_rule);
	}
	mutex_unlock(&hw->fdir_fltr_lock);

	mce_release_mac_fltr(pf);

	list_for_each_entry_safe(vlan_l, v_tmp, &hw->vlan_list_head,
				 vlan_node) {
		list_del(&vlan_l->vlan_node);
		devm_kfree(hw->dev, vlan_l);
	}

	mutex_destroy(&hw->fdir_fltr_lock);

	mutex_destroy(&hw->tnl_lock);

	if (hw->port_info) {
		devm_kfree(hw->dev, hw->port_info);
		hw->port_info = NULL;
	}

	hw->ops->reset_hw(hw);

	mce_unmap_all_hw_addr(pf);
}

/**
 * mce_remove - Device removal routine
 * @pdev: PCI device information struct
 */
static void mce_remove(struct pci_dev *pdev)
{
	struct mce_pf *pf = pci_get_drvdata(pdev);

	mutex_lock(&pf->cdev_lock);
	set_bit(MCE_REMOVED, pf->state);
	mutex_unlock(&pf->cdev_lock);
	unregister_netdevice_notifier(&pf->nb);
	unregister_inetaddr_notifier(&pf->inet_nb);

	mce_mbx_link_state_change_notify_en(&pf->hw, false);
	mce_mbx_sfp_plug_notify_en(&pf->hw, false);
	mce_mbx_drv_send_uninstall_notify_fw(&pf->hw);

	mce_free_irq_msix_misc(pf);

#ifdef CONFIG_PCI_IOV
	mce_broadcast_event_to_vf(pf, EVT_PF_DRV_REMOVE, 1000);
	set_bit(MCE_FLAG_SRIOV_DOING, pf->flags);
	mce_disable_sriov(pf);
	clear_bit(MCE_FLAG_SRIOV_DOING, pf->flags);
#endif
	pf->hw.ops->update_pf_stat(&pf->hw);
	mce_service_task_stop(pf);
#if IS_ENABLED(CONFIG_SYSFS)
	mce_sysfs_exit(pf);
#endif

	clear_bit(MCE_FLAG_MRDMA_CHANGED, pf->flags);
	clear_bit(MCE_FLAG_AUX_OP_PENDING, pf->flags);
	if (mce_pcie_support_mrdma(pf))
		mce_unplug_aux_dev(pf);

	mce_debugfs_pf_exit(pf);

	/* Clear bond membership state */
	pf->bond_upper = NULL;
	pf->bond_linked = false;
	pf->aux_op_pending = MCE_AUX_OP_NONE;
	pf->aux_op_upper = NULL;

	mce_deinit_devlink(pf);
	mce_vsi_release_all(pf);

	devm_kfree(&pdev->dev, pf->vsi_stats);
	pf->vsi_stats = NULL;
	mce_deinit_pf(pf);
	destroy_cdev(pf);
	mce_clear_interrupt_scheme(pf);
	mce_deinit_hw(pf);
	pci_wait_for_pending_transaction(pdev);
	pci_disable_device(pdev);

	dev_info(&pdev->dev, DRIVER_NAME " PCI remove");
}

/**
 * mce_shutdown - Shutdown the device in preparation for a reboot
 * @pdev: pci device structure
 **/
static void mce_shutdown(struct pci_dev *pdev)
{
	mce_remove(pdev);

	if (system_state == SYSTEM_POWER_OFF)
		pci_set_power_state(pdev, PCI_D3hot);
}

static struct pci_driver mce_driver = {
	.name = DRIVER_NAME,
	.id_table = mce_pci_tbl,
	.probe = mce_probe,
	.remove = mce_remove,
	/* .err_handler = &mce_err_handler, */
	.shutdown = mce_shutdown,
};

static int __init mce_init_module(void)
{
	int status;
	dev_t dev;

	/* init for chr dev */
	bitmap_zero(cdev_bitmap, MAX_MCE_DEVICES);
	status = alloc_chrdev_region(&dev, 0, MAX_MCE_DEVICES, DRIVER_NAME);
	if (status) {
		pr_err("Failed to alloc_chrdev_region()\n");
		return status;
	}

	mce_major = MAJOR(dev);
	mce_class = class_create(THIS_MODULE, DRIVER_NAME);

	if (IS_ERR(mce_class)) {
		pr_err("mce class_create() failed\n");
		status = PTR_ERR(mce_class);
		goto unregister_chrdev;
	}

	mce_wq = alloc_workqueue("%s", 0, 0, KBUILD_MODNAME);
	if (!mce_wq) {
		pr_err("Failed to create workqueue\n");
		status = -ENOMEM;
		goto class_destroy;
	}

	mce_debugfs_init();

	status = pci_register_driver(&mce_driver);
	if (status) {
		pr_err("failed to register PCI driver, err %d\n", status);
		destroy_workqueue(mce_wq);
		mce_debugfs_exit();
		goto class_destroy;
	}

	return status;
class_destroy:
	class_destroy(mce_class);
unregister_chrdev:
	unregister_chrdev_region(dev, MAX_MCE_DEVICES);
	return status;
}

static void __exit mce_exit_module(void)
{
	pci_unregister_driver(&mce_driver);
	destroy_workqueue(mce_wq);
	mce_debugfs_exit();
	/* remove cdev */
	if (mce_class) {
		class_destroy(mce_class);
		unregister_chrdev_region(MKDEV(mce_major, 0), MAX_MCE_DEVICES);
	}
	pr_info("module unloaded\n");
}

module_init(mce_init_module);
module_exit(mce_exit_module);
