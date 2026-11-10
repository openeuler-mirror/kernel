// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nsevf.h"
#include "nsevf_helper.h"
#include "nsevf_prototype.h"
#include "nsevf_msgbox.h"
/* All nsevf tracepoints are defined by the include below, which must
 * be included exactly once across the whole kernel with
 * CREATE_TRACE_POINTS defined
 */
#define CREATE_TRACE_POINTS
#include "nsevf_trace.h"
#include "nsevf_idc.h"
#include "nsevf_fdir.h"

static int nsevf_setup_all_tx_resources(struct nsevf_adapter *adapter);
static int nsevf_setup_all_rx_resources(struct nsevf_adapter *adapter);
static int nsevf_setup_all_txcq_resources(struct nsevf_adapter *adapter);
static int nsevf_close(struct net_device *netdev);
static void nsevf_init_get_resources(struct nsevf_adapter *adapter);
static void nsevf_handle_hw_reset(struct nsevf_adapter *adapter);

char nsevf_driver_name[] = "nsevf";
static const char nsevf_driver_string[] =
	"WangXun(R) Ethernet Connection AM Series Linux VF Driver";

#define DRV_VERSION_MAJOR (1)
#define DRV_VERSION_MINOR (0)
#define DRV_VERSION_BUILD (2)
#define DRV_VERSION "1.0.2oe"
const char nsevf_driver_version[] = DRV_VERSION;
static const char nsevf_copyright[] =
	"Copyright (c) 2018 -2021 Beijing WangXun Technology Co., Ltd";

static int debug = -1;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug,
		 "netif level (0=none,...,16=all), hw debug_mask (0x8XXXXXXX)");

unsigned int nse_aq_cmd_check_dd = 1;
module_param(nse_aq_cmd_check_dd, uint, 0644);
MODULE_PARM_DESC(nse_aq_cmd_check_dd,
		 "check DD flag in write-back descriptor, instead of HEAD (default: 1)");

unsigned int nse_aq_cmd_wait_method;
module_param(nse_aq_cmd_wait_method, uint, 0644);
MODULE_PARM_DESC(nse_aq_cmd_wait_method,
		 "AQM poll method (default 0 for sleep, 1 for delay)");

unsigned int nse_timeout_scale = 1;
module_param(nse_timeout_scale, uint, 0644);
MODULE_PARM_DESC(nse_timeout_scale,
		 "scale for various timeout (including aq, reset, etc) (default: 1)");

static unsigned int nse_aq_verbose;
module_param(nse_aq_verbose, uint, 0644);
MODULE_PARM_DESC(nse_aq_verbose,
		 "print more verbose log when doing aq_cmd (default: 0)");

static unsigned int nse_conf_verbose;
module_param(nse_conf_verbose, uint, 0644);
MODULE_PARM_DESC(nse_conf_verbose,
		 "print more verbose log when doing configuration (default: 0)");

unsigned int nse_lan_tx_no_bql;
module_param(nse_lan_tx_no_bql, uint, 0644);
MODULE_PARM_DESC(nse_lan_tx_no_bql,
		 "Do not call BQL logic (default: 0)");

unsigned int nsevf_lan_tx_rs_optimize = 1;
module_param(nsevf_lan_tx_rs_optimize, uint, 0644);
MODULE_PARM_DESC(nsevf_lan_tx_rs_optimize,
		 "TX RS writeback optimize (default: 1)");

unsigned int nsevf_lan_min_itr_no_intrl;

unsigned int nsevf_lan_no_xmit;
module_param(nsevf_lan_no_xmit, uint, 0644);
MODULE_PARM_DESC(nsevf_lan_no_xmit, "for VF LAN test, don't TX (default: 0)");

unsigned int nsevf_lan_tx_select_q_dport;
module_param(nsevf_lan_tx_select_q_dport, uint, 0644);
MODULE_PARM_DESC(nsevf_lan_tx_select_q_dport,
		 "Select TXQ based on TCP/UDP dport (default: 0)");

unsigned int nsevf_lan_tx_select_q_default;
module_param(nsevf_lan_tx_select_q_default, uint, 0644);
MODULE_PARM_DESC(nsevf_lan_tx_select_q_default,
		 "Select TXQ default for non-TCP,UDP,ICMP packet (default: 0)");

unsigned int nsevf_fdir_ena = 1;
module_param(nsevf_fdir_ena, uint, 0644);
MODULE_PARM_DESC(nsevf_fdir_ena,
		 "Enable VF-FDir, including all its logic (default: 1)");

unsigned int nsevf_use_msgbox;
module_param(nsevf_use_msgbox, uint, 0644);
MODULE_PARM_DESC(nsevf_use_msgbox,
		 "Use PV msgbox instead of mailboxq for  (default: 0)");

unsigned int nsevf_lan_tx_use_cq;
module_param(nsevf_lan_tx_use_cq, uint, 0644);
MODULE_PARM_DESC(nsevf_lan_tx_use_cq,
		 "try to request PF driver to grant LAN CompletionQ to handle TX-done release (default: 0)");

unsigned int nsevf_polling_mod;
module_param(nsevf_polling_mod, uint, 0644);
MODULE_PARM_DESC(nsevf_polling_mod,
		 "vf pmd (0:napi, non-0: pmd (default napi)");

static unsigned int nsevf_lan_rx_ena_rsc;
module_param(nsevf_lan_rx_ena_rsc, uint, 0644);
MODULE_PARM_DESC(nsevf_lan_rx_ena_rsc,
		 "try to request PF driver to enable RSC for VF (default: 0)");

static unsigned int nsevf_max_lanirq_num;
module_param(nsevf_max_lanirq_num, uint, 0644);
MODULE_PARM_DESC(nsevf_max_lanirq_num,
		 "limit irqvec used by VF LAN-RXQ/TXQ, leaving more for VF-RDMA (default: 0)");

/* nsevf_pci_tbl - PCI Device ID Table
 *
 * Wildcard entries (PCI_ANY_ID) should come last
 * Last entry must be all 0s
 *
 * { Vendor ID, Device ID, SubVendor ID, SubDevice ID,
 *   Class, Class Mask, private data (not used) }
 */
static const struct pci_device_id nsevf_pci_tbl[] = {
	{ PCI_VDEVICE(TRUSTNETIC, NSEVF_DEV_ID_VF_AMBER_FPGA), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSEVF_DEV_ID_VF_AMBER_FDBTACRX), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSEVF_DEV_ID_VF_AMBER_FDBTACXX), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSEVF_DEV_ID_VF_AMBER_FDATACRX), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSEVF_DEV_ID_VF_AMBER_FDATAIRX), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSEVF_DEV_ID_VF_AMBER_FQATACRX), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSEVF_DEV_ID_VF_AMBER_DQATACXX), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSEVF_DEV_ID_VF_MS), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSEVF_DEV_ID_VDEV), 0 },
	/* required last entry */
	{
		0,
	}
};

MODULE_DEVICE_TABLE(pci, nsevf_pci_tbl);

MODULE_AUTHOR("Beijing WangXun Technology Co., Ltd, <linux.nic@trustnetic.com>");
MODULE_DESCRIPTION("WangXun(R) Ethernet Connection AM Series Linux VF Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

static const struct net_device_ops nsevf_netdev_ops;

unsigned int nsevf_wq_low_interval = 2;
unsigned int nsevf_wq_low_mid_interval = 5;
unsigned int nsevf_wq_mid_interval = 30;
unsigned int nsevf_wq_mid_high_interval = 100;
unsigned int nsevf_wq_high_interval = 1000;

int nsevf_status_to_errno(enum nsevf_status status)
{
	switch (status) {
	case NSEVF_SUCCESS:
		return 0;
	case NSEVF_ERR_PARAM:
	case NSEVF_ERR_MAC_TYPE:
	case NSEVF_ERR_INVALID_MAC_ADDR:
	case NSEVF_ERR_INVALID_LINK_SETTINGS:
	case NSEVF_ERR_INVALID_PD_ID:
	case NSEVF_ERR_INVALID_QP_ID:
	case NSEVF_ERR_INVALID_CQ_ID:
	case NSEVF_ERR_INVALID_CEQ_ID:
	case NSEVF_ERR_INVALID_AEQ_ID:
	case NSEVF_ERR_INVALID_SIZE:
	case NSEVF_ERR_INVALID_ARP_INDEX:
	case NSEVF_ERR_INVALID_FPM_FUNC_ID:
	case NSEVF_ERR_QP_INVALID_MSG_SIZE:
	case NSEVF_ERR_INVALID_FRAG_COUNT:
	case NSEVF_ERR_INVALID_ALIGNMENT:
	case NSEVF_ERR_INVALID_PUSH_PAGE_INDEX:
	case NSEVF_ERR_INVALID_IMM_DATA_SIZE:
	case NSEVF_ERR_INVALID_VF_ID:
	case NSEVF_ERR_INVALID_HMCFN_ID:
	case NSEVF_ERR_INVALID_PBLE_INDEX:
	case NSEVF_ERR_INVALID_SD_INDEX:
	case NSEVF_ERR_INVALID_PAGE_DESC_INDEX:
	case NSEVF_ERR_INVALID_SD_TYPE:
	case NSEVF_ERR_INVALID_HMC_OBJ_INDEX:
	case NSEVF_ERR_INVALID_HMC_OBJ_COUNT:
	case NSEVF_ERR_INVALID_SRQ_ARM_LIMIT:
	case NSEVF_ERR_INVAL_SIZE:
	case NSEVF_ERR_ADMIN_QUEUE_EMPTY:
		return -EINVAL;
	case NSEVF_ERR_NVM:
	case NSEVF_ERR_NVM_CHECKSUM:
	case NSEVF_ERR_PHY:
	case NSEVF_ERR_CONFIG:
	case NSEVF_ERR_UNKNOWN_PHY:
	case NSEVF_ERR_LINK_SETUP:
	case NSEVF_ERR_ADAPTER_STOPPED:
	case NSEVF_ERR_PRIMARY_REQUESTS_PENDING:
	case NSEVF_ERR_AUTONEG_NOT_COMPLETE:
	case NSEVF_ERR_RESET_FAILED:
	case NSEVF_ERR_BAD_PTR:
	case NSEVF_ERR_SWFW_SYNC:
	case NSEVF_ERR_QP_TOOMANY_WRS_POSTED:
	case NSEVF_ERR_QUEUE_EMPTY:
	case NSEVF_ERR_FLUSHED_QUEUE:
	case NSEVF_ERR_OPCODE_MISMATCH:
	case NSEVF_ERR_CQP_COMPL_ERROR:
	case NSEVF_ERR_BACKING_PAGE_ERROR:
	case NSEVF_ERR_NO_PBLCHUNKS_AVAILABLE:
	case NSEVF_ERR_MEMCPY_FAILED:
	case NSEVF_ERR_SRQ_ENABLED:
	case NSEVF_ERR_ADMIN_QUEUE_ERROR:
	case NSEVF_ERR_ADMIN_QUEUE_FULL:
	case NSEVF_ERR_BAD_IWARP_CQE:
	case NSEVF_ERR_NVM_BLANK_MODE:
	case NSEVF_ERR_PE_DOORBELL_NOT_ENABLED:
	case NSEVF_ERR_DIAG_TEST_FAILED:
	case NSEVF_ERR_FIRMWARE_API_VERSION:
	case NSEVF_ERR_ADMIN_QUEUE_CRITICAL_ERROR:
		return -EIO;
	case NSEVF_ERR_DEVICE_NOT_SUPPORTED:
		return -ENODEV;
	case NSEVF_ERR_NO_AVAILABLE_VSI:
	case NSEVF_ERR_RING_FULL:
		return -ENOSPC;
	case NSEVF_ERR_NO_MEMORY:
		return -ENOMEM;
	case NSEVF_ERR_TIMEOUT:
	case NSEVF_ERR_ADMIN_QUEUE_TIMEOUT:
		return -ETIMEDOUT;
	case NSEVF_ERR_NOT_IMPLEMENTED:
	case NSEVF_NOT_SUPPORTED:
		return -EOPNOTSUPP;
	case NSEVF_ERR_ADMIN_QUEUE_NO_WORK:
		return -EALREADY;
	case NSEVF_ERR_NOT_READY:
		return -EBUSY;
	case NSEVF_ERR_BUF_TOO_SHORT:
		return -EMSGSIZE;
	}

	return -EIO;
}

int virtchnl_status_to_errno(enum virtchnl_status_code v_status)
{
	switch (v_status) {
	case VIRTCHNL_STATUS_SUCCESS:
		return 0;
	case VIRTCHNL_STATUS_ERR_PARAM:
	case VIRTCHNL_STATUS_ERR_INVALID_VF_ID:
		return -EINVAL;
	case VIRTCHNL_STATUS_ERR_NO_MEMORY:
		return -ENOMEM;
	case VIRTCHNL_STATUS_ERR_TIMEOUT:
		return -ETIMEDOUT;
	case VIRTCHNL_STATUS_ERR_OPCODE_MISMATCH:
	case VIRTCHNL_STATUS_ERR_CQP_COMPL_ERROR:
	case VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR:
		return -EIO;
	case VIRTCHNL_STATUS_ERR_NOT_SUPPORTED:
		return -EOPNOTSUPP;
	}

	return -EIO;
}

/**
 * nsevf_pdev_to_adapter - go from pci_dev to adapter
 * @pdev: pci_dev pointer
 */
struct nsevf_adapter *nsevf_pdev_to_adapter(struct pci_dev *pdev)
{
	return netdev_priv(pci_get_drvdata(pdev));
}

/**
 * nsevf_allocate_dma_mem_d - OS specific memory alloc for shared code
 * @hw:   pointer to the HW structure
 * @mem:  ptr to mem struct to fill out
 * @mtype: unused parameter for documenting memory type of dma
 * @size: size of memory requested
 * @alignment: what to align the allocation to
 **/
enum nsevf_status
nsevf_allocate_dma_mem_d(struct nsevf_hw *hw, struct nsevf_dma_mem *mem,
			 __always_unused enum nsevf_memory_type mtype, u64 size,
			 u32 alignment)
{
	struct nsevf_adapter *nf = (struct nsevf_adapter *)hw->back;

	if (!mem)
		return NSEVF_ERR_PARAM;

	mem->size = ALIGN(size, alignment);
	mem->va = dma_alloc_coherent(&nf->pdev->dev, mem->size, &mem->pa,
				     GFP_KERNEL);
	if (!mem->va)
		return NSEVF_ERR_NO_MEMORY;

	return NSEVF_SUCCESS;
}

/**
 * nsevf_free_dma_mem_d - OS specific memory free for shared code
 * @hw:   pointer to the HW structure
 * @mem:  ptr to mem struct to free
 **/
enum nsevf_status nsevf_free_dma_mem_d(struct nsevf_hw *hw,
				       struct nsevf_dma_mem *mem)
{
	struct nsevf_adapter *nf = (struct nsevf_adapter *)hw->back;

	if (!mem || !mem->va)
		return NSEVF_ERR_PARAM;

	dma_free_coherent(&nf->pdev->dev, mem->size, mem->va, mem->pa);
	mem->va = NULL;
	mem->pa = 0;
	mem->size = 0;

	return NSEVF_SUCCESS;
}

/**
 * nsevf_allocate_virt_mem_d - OS specific memory alloc for shared code
 * @hw:   pointer to the HW structure
 * @mem:  ptr to mem struct to fill out
 * @size: size of memory requested
 **/
enum nsevf_status nsevf_allocate_virt_mem_d(struct nsevf_hw *hw,
					    struct nsevf_virt_mem *mem,
					    u32 size)
{
	if (!mem)
		return NSEVF_ERR_PARAM;

	mem->size = size;
	mem->va = kzalloc(size, GFP_KERNEL);

	if (!mem->va)
		return NSEVF_ERR_NO_MEMORY;

	return NSEVF_SUCCESS;
}

/**
 * nsevf_free_virt_mem_d - OS specific memory free for shared code
 * @hw:   pointer to the HW structure
 * @mem:  ptr to mem struct to free
 **/
enum nsevf_status nsevf_free_virt_mem_d(struct nsevf_hw *hw,
					struct nsevf_virt_mem *mem)
{
	if (!mem)
		return NSEVF_ERR_PARAM;

	/* it's ok to kfree a NULL pointer */
	kfree(mem->va);
	mem->va = NULL;
	mem->size = 0;

	return NSEVF_SUCCESS;
}

/**
 * nsevf_is_reset_in_progress - Check if a reset is in progress
 * @adapter: board private structure
 */
bool nsevf_is_reset_in_progress(struct nsevf_adapter *adapter)
{
	if (adapter->state == __NSEVF_RESETTING)
		return true;

	if (adapter->flags &
	    (NSEVF_FLAG_RESET_PENDING | NSEVF_FLAG_RESET_NEEDED |
	     NSEVF_FLAG_RESET_DETECTED))
		return true;

	if (adapter->in_os_reset)
		return true;

	return false;
}

/**
 * nsevf_is_remove_in_progress - Check if a nsevf_remove() is in progress
 * @adapter: board private structure
 */
bool nsevf_is_remove_in_progress(struct nsevf_adapter *adapter)
{
	return test_bit(__NSEVF_IN_REMOVE_TASK, &adapter->crit_section);
}

void nsevf_schedule_reset(struct nsevf_adapter *adapter, u64 flags)
{
	struct nsevf_hw *hw = &adapter->hw;
	unsigned long delay = 0;

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s] flags=%lX, adapter->flags=%lX\n",
		    __func__, (unsigned long)flags,
		    (unsigned long)adapter->flags);

	if (nsevf_is_remove_in_progress(adapter)) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s] not actually schedule_reset(), because in remove\n",
			__func__);
		return;
	}

	if (adapter->flags &
	    (NSEVF_FLAG_RESET_PENDING | NSEVF_FLAG_RESET_NEEDED)) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s] already in reset, still schedule watchdog_task (intentionally longer delay)\n",
			__func__);

		delay = nsevf_wq_low_mid_interval; //5 jiffies
	} else {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s] schedule watchdog_task (delay=0)\n",
			    __func__);

		adapter->flags |= (flags | NSEVF_FLAG_RESET_NEEDED);
	}

	mod_delayed_work(adapter->wq, &adapter->watchdog_task, delay);
}

void nsevf_schedule_aq_request(struct nsevf_adapter *adapter, u64 flags)
{
	adapter->aq_required |= flags;
	mod_delayed_work(adapter->wq, &adapter->watchdog_task, 0);
}

/**
 * nsevf_misc_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/
static void nsevf_misc_irq_disable(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;

	if (!adapter->msix_entries)
		return;

	wr32(hw, INT_DYN_CTLN0(hw),
	     (NSEVF_REG_INT_DYN_CTLN_INTMSK_VLD_M |
	      NSEVF_REG_INT_DYN_CTLN_INTMSK_M));

	nsevf_flush(hw);

	synchronize_irq(adapter->msix_entries[0].vector);
}

/**
 * nsevf_misc_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 * @config: whether to configure the interrupt registers
 **/
static void nsevf_misc_irq_enable(struct nsevf_adapter *adapter, bool config)
{
	struct nsevf_hw *hw = &adapter->hw;
	u32 regval;

	/* set INTMSK_VLD = 1, INTMSK=0, unmask it */
	wr32(hw, INT_DYN_CTLN0(hw),
	     (NSEVF_REG_INT_DYN_CTLN_CLEARPBA_M |
	      NSEVF_REG_INT_DYN_CTLN_INTMSK_VLD_M));

	if (config) {
		if (hw->device_id == NSEVF_DEV_ID_VDEV) {
			/* todo - SIOV VDEV */
		} else {
			if (nsevf_use_msgbox) {
				/* here, lli = 0, MSIX_IDX is implicitly 0 */
				wr32(hw, NSEVF_REG_P2V_UPINT,
				     NSEVF_REG_P2V_UPINT_VLD_M);
			} else {
				regval = rd32(hw, NSEVF_REG_MBX_CTL);

				regval &= ~(NSEVF_REG_MBX_CTL_MSIX_IDX_M);
				regval |=
					NSEVF_REG_MBX_CTL_CAUSE_EN_M; /* CAUSE_EN = 1 */

				wr32(hw, NSEVF_REG_MBX_CTL, regval);
			}
		}
	}

	nsevf_flush(hw);
}

/**
 * nsevf_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/
static void nsevf_irq_disable(struct nsevf_adapter *adapter)
{
	int i;
	struct nsevf_hw *hw = &adapter->hw;

	if (!adapter->msix_entries)
		return;

	for (i = 1; i < adapter->num_msix_vectors; i++) {
		wr32(hw, INT_DYN_CTLN(hw, i),
		     (NSEVF_REG_INT_DYN_CTLN_INTMSK_VLD_M |
		      NSEVF_REG_INT_DYN_CTLN_INTMSK_M));
		synchronize_irq(adapter->msix_entries[i].vector);
	}
	nsevf_flush(hw);
}

/**
 * nsevf_irq_enable_queues - Enable interrupt for specified queues
 * @adapter: board private structure
 * @mask: bitmap of queues to enable
 **/
void nsevf_irq_enable_queues(struct nsevf_adapter *adapter, u32 mask)
{
	struct nsevf_hw *hw = &adapter->hw;
	int i;

	for (i = 1; i < adapter->num_msix_vectors; i++) {
		if (mask & BIT(i - 1)) {
			wr32(hw, INT_DYN_CTLN(hw, i),
			     NSEVF_REG_INT_DYN_CTLN_INTMSK_VLD_M); /* INTMSK_VLD = 1, INTMSK = 0 */
		}
	}
}

/**
 * nsevf_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 * @flush: boolean value whether to run rd32()
 **/
void nsevf_irq_enable(struct nsevf_adapter *adapter, bool flush)
{
	struct nsevf_hw *hw = &adapter->hw;

	nsevf_misc_irq_enable(adapter, true);
	nsevf_irq_enable_queues(adapter, ~0);

	if (flush)
		nsevf_flush(hw);
}

/**
 * nsevf_msix_aq - Interrupt handler for vector 0
 * @irq: interrupt number
 * @data: pointer to netdev
 **/
static irqreturn_t nsevf_msix_aq(int irq, void *data)
{
	struct net_device *netdev = data;
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	/* schedule work on the private workqueue */
	queue_work(adapter->wq, &adapter->adminq_task);

	return IRQ_HANDLED;
}

/**
 * nsevf_msix_clean_rings - MSIX mode Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 **/
static irqreturn_t nsevf_msix_clean_rings(int irq, void *data)
{
	struct nsevf_q_vector *q_vector = data;

	if (!q_vector->tx.ring && !q_vector->rx.ring)
		return IRQ_HANDLED;

	q_vector->total_events++;

	q_vector->dbg_stats.hardirq_total_cnt++;

	napi_schedule_irqoff(&q_vector->napi);

	return IRQ_HANDLED;
}

/**
 * nsevf_map_vector_to_rxq - associate irqs with rx queues
 * @adapter: board private structure
 * @v_idx: interrupt number
 * @r_idx: queue number
 **/
static void nsevf_map_vector_to_rxq(struct nsevf_adapter *adapter, int v_idx,
				    int r_idx)
{
	struct nsevf_q_vector *q_vector = &adapter->q_vectors[v_idx];
	struct nsevf_ring *rx_ring = &adapter->rx_rings[r_idx];

	rx_ring->q_vector = q_vector;
	rx_ring->next = q_vector->rx.ring;
	rx_ring->vsi = &adapter->vsi;
	q_vector->rx.ring = rx_ring;
	q_vector->rx.count++;
	q_vector->ring_mask |= BIT(r_idx);
}

static void nsevf_cfg_xps_tx_ring(struct nsevf_ring *ring)
{
	if (!ring->q_vector || !ring->netdev)
		return;

	if (test_and_set_bit(NSEVF_TX_XPS_INIT_DONE, ring->xps_state))
		return;

	netif_set_xps_queue(ring->netdev, &ring->q_vector->affinity_mask,
			    ring->queue_index);
}

/**
 * nsevf_map_vector_to_txq - associate irqs with tx queues
 * @adapter: board private structure
 * @v_idx: interrupt number
 * @t_idx: queue number
 **/
static void nsevf_map_vector_to_txq(struct nsevf_adapter *adapter, int v_idx,
				    int t_idx)
{
	struct nsevf_q_vector *q_vector = &adapter->q_vectors[v_idx];
	struct nsevf_ring *tx_ring = &adapter->tx_rings[t_idx];

	tx_ring->q_vector = q_vector;
	tx_ring->next = q_vector->tx.ring;
	tx_ring->vsi = &adapter->vsi;
	q_vector->tx.ring = tx_ring;
	q_vector->tx.count++;
	q_vector->num_ringpairs++;

	nsevf_cfg_xps_tx_ring(tx_ring);
}

static void nsevf_map_txcq_rings_to_vectors(struct nsevf_adapter *adapter)
{
	struct nsevf_q_vector *qvec = NULL;
	struct nsevf_txcq_ring *cq_ring = NULL;
	int q_vectors = adapter->num_msix_vectors - NONQ_VECS;
	int i;

	if (!adapter->sw_conf.lan_tx_use_cq)
		return;

	if (q_vectors > adapter->vf_res->lan_txcq_num)
		q_vectors = adapter->vf_res->lan_txcq_num;

	if (adapter->vf_res->max_lan_vectors &&
	    q_vectors > adapter->vf_res->max_lan_vectors) {
		q_vectors = adapter->vf_res->max_lan_vectors;
	}

	for (i = 0; i < q_vectors; i++) {
		qvec = &adapter->q_vectors[i];
		cq_ring = &adapter->txcq_rings[i];

		cq_ring->q_vector = qvec;

		qvec->txcq = cq_ring;
	}
}

/**
 * nsevf_map_rings_to_vectors - Maps descriptor rings to vectors
 * @adapter: board private structure to initialize
 *
 * This function maps descriptor rings to the queue-specific vectors
 * we were allotted through the MSI-X enabling code.  Ideally, we'd have
 * one vector per ring/queue, but on a constrained vector budget, we
 * group the rings as "efficiently" as possible.  You would add new
 * mapping configurations in here.
 **/
static void nsevf_map_rings_to_vectors(struct nsevf_adapter *adapter)
{
	int rings_remaining = adapter->num_active_queues;
	int ridx = 0, vidx = 0;
	int q_vectors;
	int rings_per_v;

	q_vectors = adapter->num_msix_vectors - NONQ_VECS;

	if (adapter->vf_res->max_lan_vectors &&
	    q_vectors > adapter->vf_res->max_lan_vectors)
		q_vectors = adapter->vf_res->max_lan_vectors;

	/* only map to those irqvector with CQ */
	if (adapter->sw_conf.lan_tx_use_cq) {
		if (q_vectors > adapter->vf_res->lan_txcq_num)
			q_vectors = adapter->vf_res->lan_txcq_num;
	}

	rings_per_v = DIV_ROUND_UP(rings_remaining, q_vectors);

	for (; ridx < rings_remaining; ridx++) {
		if (ridx && (ridx % rings_per_v) == 0)
			vidx++;

		/* In the case where we have more queues than vectors, continue
		 * round-robin on vectors until all queues are mapped.
		 */
		if (vidx >= q_vectors)
			vidx = 0;

		nsevf_map_vector_to_rxq(adapter, vidx, ridx);
		nsevf_map_vector_to_txq(adapter, vidx, ridx);
	}

	nsevf_map_txcq_rings_to_vectors(adapter);

	adapter->aq_required |= NSEVF_FLAG_AQ_MAP_VECTORS;
}

/**
 * nsevf_irq_affinity_notify - Callback for affinity changes
 * @notify: context as to what irq was changed
 * @mask: the new affinity mask
 *
 * This is a callback function used by the irq_set_affinity_notifier function
 * so that we may register to receive changes to the irq affinity masks.
 **/
static void nsevf_irq_affinity_notify(struct irq_affinity_notify *notify,
				      const cpumask_t *mask)
{
	struct nsevf_q_vector *q_vector =
		container_of(notify, struct nsevf_q_vector, affinity_notify);

	cpumask_copy(&q_vector->affinity_mask, mask);
}

/**
 * nsevf_irq_affinity_release - Callback for affinity notifier release
 * @ref: internal core kernel usage
 *
 * This is a callback function used by the irq_set_affinity_notifier function
 * to inform the current notification subscriber that they will no longer
 * receive notifications.
 **/
static void nsevf_irq_affinity_release(struct kref *ref)
{
}

/**
 * nsevf_request_traffic_irqs - Initialize MSI-X interrupts
 * @adapter: board private structure
 * @basename: device basename
 *
 * Allocates MSI-X vectors for tx and rx handling, and requests
 * interrupts from the kernel.
 **/
static int nsevf_request_traffic_irqs(struct nsevf_adapter *adapter,
				      char *basename)
{
	unsigned int vector, q_vectors;
	unsigned int rx_int_idx = 0, tx_int_idx = 0;
	int irq_num, err;

	nsevf_irq_disable(adapter);
	/* Decrement for Other and TCP Timer vectors */
	q_vectors = adapter->num_msix_vectors - NONQ_VECS;

	for (vector = 0; vector < q_vectors; vector++) {
		struct nsevf_q_vector *q_vector = &adapter->q_vectors[vector];

		irq_num = adapter->msix_entries[vector + NONQ_VECS].vector;

		if (q_vector->tx.ring && q_vector->rx.ring) {
			if (q_vector->rx.count == 1) {
				snprintf(q_vector->name, sizeof(q_vector->name),
					 "nsevf-%s-TxRx-%u", basename,
					 rx_int_idx++);
				tx_int_idx++;
			} else {
				snprintf(q_vector->name, sizeof(q_vector->name),
					 "nsevf-%s-TxRx-%u-%u", basename,
					 rx_int_idx,
					 (rx_int_idx + q_vector->rx.count - 1));
				rx_int_idx = rx_int_idx + q_vector->rx.count;
				tx_int_idx = rx_int_idx;
			}

		} else if (q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name),
				 "nsevf-%s-Rx-%u", basename, rx_int_idx++);
		} else if (q_vector->tx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name),
				 "nsevf-%s-Tx-%u", basename, tx_int_idx++);
		} else {
			/* skip this unused q_vector */
			continue;
		}
		err = request_irq(irq_num, nsevf_msix_clean_rings, 0,
				  q_vector->name, q_vector);
		if (err) {
			dev_info(&adapter->pdev->dev,
				 "Request_irq failed, error: %d\n", err);
			goto free_queue_irqs;
		}
		/* register for affinity change notifications */
		q_vector->affinity_notify.notify = nsevf_irq_affinity_notify;
		q_vector->affinity_notify.release = nsevf_irq_affinity_release;
		irq_set_affinity_notifier(irq_num, &q_vector->affinity_notify);

		/* assign the mask for this irq */
		irq_set_affinity_hint(irq_num, &q_vector->affinity_mask);
	}

	return 0;

free_queue_irqs:
	while (vector) {
		vector--;
		irq_num = adapter->msix_entries[vector + NONQ_VECS].vector;
		irq_set_affinity_notifier(irq_num, NULL);
		free_irq(irq_num, &adapter->q_vectors[vector]);
	}
	return err;
}

/**
 * nsevf_request_misc_irq - Initialize MSI-X interrupts
 * @adapter: board private structure
 *
 * Allocates MSI-X vector 0 and requests interrupts from the kernel. This
 * vector is only for the admin queue, and stays active even when the netdev
 * is closed.
 **/
static int nsevf_request_misc_irq(struct nsevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int err;

	if (nsevf_lan_min_itr_no_intrl)
		(void)nsevf_set_itr_interval(&adapter->hw, 0,
					     NSE_ITR_INTERVAL_MIN_USEC);
	else
		(void)nsevf_set_itr_interval(&adapter->hw, 0,
					     NSE_ITR_INTERVAL_20K);

	snprintf(adapter->misc_vector_name,
		 sizeof(adapter->misc_vector_name) - 1, "nsevf-%s:mbx",
		 dev_name(&adapter->pdev->dev));
	err = request_irq(adapter->msix_entries[0].vector, &nsevf_msix_aq, 0,
			  adapter->misc_vector_name, netdev);
	if (err) {
		dev_err(&adapter->pdev->dev, "request_irq for %s failed: %d\n",
			adapter->misc_vector_name, err);
		free_irq(adapter->msix_entries[0].vector, netdev);
	}
	return err;
}

/**
 * nsevf_free_traffic_irqs - Free MSI-X interrupts
 * @adapter: board private structure
 *
 * Frees all MSI-X vectors other than 0.
 **/
static void nsevf_free_traffic_irqs(struct nsevf_adapter *adapter)
{
	int vector, irq_num, q_vectors;

	if (!adapter->msix_entries)
		return;

	q_vectors = adapter->num_msix_vectors - NONQ_VECS;

	for (vector = 0; vector < q_vectors; vector++) {
		irq_num = adapter->msix_entries[vector + NONQ_VECS].vector;
		irq_set_affinity_notifier(irq_num, NULL);
		free_irq(irq_num, &adapter->q_vectors[vector]);
	}
}

/**
 * nsevf_free_misc_irq - Free MSI-X miscellaneous vector
 * @adapter: board private structure
 *
 * Frees MSI-X vector 0.
 **/
static void nsevf_free_misc_irq(struct nsevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	if (!adapter->msix_entries)
		return;

	free_irq(adapter->msix_entries[0].vector, netdev);
}

/**
 * nsevf_configure_tx - Configure Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
static void nsevf_configure_tx(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;
	int i;

	for (i = 0; i < adapter->num_active_queues; i++)
		adapter->tx_rings[i].tail = hw->hw_addr + QTX_TAIL(hw, i);
}

/**
 * nsevf_select_rx_desc_format - Select Rx descriptor format
 * @adapter: adapter private structure
 *
 * Select what Rx descriptor format based on availability and enabled
 * features.
 *
 * Returns the desired RXDID to select for a given Rx queue, as defined by
 * enum virtchnl_rxdid_format.
 */
static u8 nsevf_select_rx_desc_format(struct nsevf_adapter *adapter)
{
	return NSE_RXDID_FLEX_NIC;
}

/**
 * nsevf_configure_rx - Configure Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
static void nsevf_configure_rx(struct nsevf_adapter *adapter)
{
	unsigned int rx_buf_len = NSEVF_RXBUFFER_2048;
	struct nsevf_hw *hw = &adapter->hw;
	int i;

	adapter->rxdid = nsevf_select_rx_desc_format(adapter);

	/* Legacy Rx will always default to a 2048 buffer size. */
#if (PAGE_SIZE < 8192)
	if (!(adapter->flags & NSEVF_FLAG_LEGACY_RX)) {
		struct net_device *netdev = adapter->netdev;

		/* For jumbo frames on systems with 4K pages we have to use
		 * an order 1 page, so we might as well increase the size
		 * of our Rx buffer to make better use of the available space
		 */
		rx_buf_len = NSEVF_RXBUFFER_3072;

		/* We use a 1536 buffer size for configurations with
		 * standard Ethernet mtu.  On x86 this gives us enough room
		 * for shared info and 192 bytes of padding.
		 */
		if (!NSEVF_2K_TOO_SMALL_WITH_PADDING &&
		    netdev->mtu <= ETH_DATA_LEN)
			rx_buf_len = NSEVF_RXBUFFER_1536 - NET_IP_ALIGN;
	}
#endif

	for (i = 0; i < adapter->num_active_queues; i++) {
		adapter->rx_rings[i].tail = hw->hw_addr + QRX_TAIL(hw, i);
		adapter->rx_rings[i].rx_buf_len = rx_buf_len;
		adapter->rx_rings[i].rxdid = adapter->rxdid;

		if (adapter->flags & NSEVF_FLAG_LEGACY_RX)
			clear_ring_build_skb_enabled(&adapter->rx_rings[i]);
		else
			set_ring_build_skb_enabled(&adapter->rx_rings[i]);
	}
}

/**
 * nsevf_find_vlan - Search filter list for specific vlan filter
 * @adapter: board private structure
 * @vlan: vlan tag
 *
 * Returns ptr to the filter object or NULL. Must be called while holding the
 * mac_vlan_list_lock.
 **/
static struct nsevf_vlan_filter *nsevf_find_vlan(struct nsevf_adapter *adapter,
						 struct nsevf_vlan vlan)
{
	struct nsevf_vlan_filter *f;

	list_for_each_entry(f, &adapter->vlan_filter_list, list) {
		if (f->vlan.vid == vlan.vid && f->vlan.tpid == vlan.tpid)
			return f;
	}

	return NULL;
}

/**
 * nsevf_add_vlan - Add a vlan filter to the list
 * @adapter: board private structure
 * @vlan: VLAN tag
 *
 * Returns ptr to the filter object or NULL when no memory available.
 **/
static struct nsevf_vlan_filter *nsevf_add_vlan(struct nsevf_adapter *adapter,
						struct nsevf_vlan vlan)
{
	struct nsevf_vlan_filter *f = NULL;

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	f = nsevf_find_vlan(adapter, vlan);
	if (!f) {
		f = kzalloc(sizeof(*f), GFP_ATOMIC);
		if (!f)
			goto clearout;

		f->vlan = vlan;

		list_add_tail(&f->list, &adapter->vlan_filter_list);
		f->add = true;

		nsevf_schedule_aq_request(adapter,
					  NSEVF_FLAG_AQ_ADD_VLAN_FILTER);
	}

clearout:
	spin_unlock_bh(&adapter->mac_vlan_list_lock);
	return f;
}

/**
 * nsevf_del_vlan - Remove a vlan filter from the list
 * @adapter: board private structure
 * @vlan: VLAN tag
 **/
static void nsevf_del_vlan(struct nsevf_adapter *adapter,
			   struct nsevf_vlan vlan)
{
	struct nsevf_vlan_filter *f;

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	f = nsevf_find_vlan(adapter, vlan);
	if (f) {
		f->remove = true;

		nsevf_schedule_aq_request(adapter,
					  NSEVF_FLAG_AQ_DEL_VLAN_FILTER);
	}

	spin_unlock_bh(&adapter->mac_vlan_list_lock);
}

void nsevf_dump_vlan_filters(struct nsevf_adapter *adapter)
{
	struct device *dev = nsevf_adapter_to_dev(adapter);
	struct nsevf_vlan_filter *f = NULL;
	unsigned int cnt = 0;

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	list_for_each_entry(f, &adapter->vlan_filter_list, list) {
		dev_info(dev, "vlan-filter #%d\n", cnt);
		dev_info(dev, "\t vid=%d\n", f->vlan.vid);
		dev_info(dev, "\t is_new_vlan=%d\n", f->is_new_vlan);
		dev_info(dev, "\t remove=%d\n", f->remove);
		dev_info(dev, "\t add=%d\n", f->add);

		cnt++;
	}

	spin_unlock_bh(&adapter->mac_vlan_list_lock);

	dev_info(dev, "current cnt of VF vlan-filter: %d\n", cnt);
}

/**
 * nsevf_restore_filters
 * @adapter: board private structure
 *
 * Restore existing non MAC filters when VF netdev comes back up
 **/
static void nsevf_restore_filters(struct nsevf_adapter *adapter)
{
	u16 vid;

	for_each_set_bit(vid, adapter->vsi.active_cvlans, VLAN_N_VID)
		nsevf_add_vlan(adapter, NSEVF_VLAN(vid, ETH_P_8021Q));

	for_each_set_bit(vid, adapter->vsi.active_svlans, VLAN_N_VID)
		nsevf_add_vlan(adapter, NSEVF_VLAN(vid, ETH_P_8021AD));
}

/**
 * nsevf_get_num_vlans_added - get number of VLANs added
 * @adapter: board private structure
 */
u16 nsevf_get_num_vlans_added(struct nsevf_adapter *adapter)
{
	return bitmap_weight(adapter->vsi.active_cvlans, VLAN_N_VID) +
	       bitmap_weight(adapter->vsi.active_svlans, VLAN_N_VID);
}

/**
 * nsevf_get_max_vlans_allowed - get maximum VLANs allowed for this VF
 * @adapter: board private structure
 *
 * This depends on the negotiated VLAN capability.
 * for VIRTCHNL_VF_OFFLOAD_VLAN_V2, use the maximum allowed sent from the PF.
 **/
static u16 nsevf_get_max_vlans_allowed(struct nsevf_adapter *adapter)
{
	if (VLAN_V2_ALLOWED(adapter))
		return adapter->vlan_v2_caps.filtering.max_filters;

	return 0;
}

/**
 * nsevf_max_vlans_added - check if maximum VLANs allowed already exist
 * @adapter: board private structure
 **/
static bool nsevf_max_vlans_added(struct nsevf_adapter *adapter)
{
	if (nsevf_get_num_vlans_added(adapter) <
	    nsevf_get_max_vlans_allowed(adapter))
		return false;

	return true;
}

/**
 * nsevf_vlan_rx_add_vid - Add a VLAN filter to a device
 * @netdev: network device struct
 * @proto: unused protocol data
 * @vid: VLAN tag
 **/
static int nsevf_vlan_rx_add_vid(struct net_device *netdev,
				 __always_unused __be16 proto, u16 vid)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	u16 local_vlan_proto = be16_to_cpu(proto);

	if (!(vid & VLAN_VID_MASK)) {
		netdev_err(netdev, "not allow add VF VLAN ID=0\n");
		return -EIO;
	}

	if (!VLAN_FILTERING_ALLOWED(adapter))
		return -EIO;

	if (nsevf_max_vlans_added(adapter)) {
		netdev_err(netdev,
			   "Max allowed VLAN filters %u. Remove existing VLANs or disable filtering via Ethtool if supported.\n",
			nsevf_get_max_vlans_allowed(adapter));
		return -EIO;
	}

	if (!nsevf_add_vlan(adapter, NSEVF_VLAN(vid, local_vlan_proto)))
		return -ENOMEM;

	return 0;
}

/**
 * nsevf_vlan_rx_kill_vid - Remove a VLAN filter from a device
 * @netdev: network device struct
 * @proto: unused protocol data
 * @vid: VLAN tag
 **/
static int nsevf_vlan_rx_kill_vid(struct net_device *netdev,
				  __always_unused __be16 proto, u16 vid)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	u16 local_vlan_proto = be16_to_cpu(proto);

	nsevf_del_vlan(adapter, NSEVF_VLAN(vid, local_vlan_proto));
	if (local_vlan_proto == ETH_P_8021Q)
		clear_bit(vid, adapter->vsi.active_cvlans);
	else
		clear_bit(vid, adapter->vsi.active_svlans);

	return 0;
}

/**
 * nsevf_find_filter - Search filter list for specific mac filter
 * @adapter: board private structure
 * @macaddr: the MAC address
 *
 * Returns ptr to the filter object or NULL. Must be called while holding the
 * mac_vlan_list_lock.
 **/
static struct nsevf_mac_filter *nsevf_find_filter(struct nsevf_adapter *adapter,
						  const u8 *macaddr)
{
	struct nsevf_mac_filter *f;

	if (!macaddr)
		return NULL;

	list_for_each_entry(f, &adapter->mac_filter_list, list) {
		if (ether_addr_equal(macaddr, f->macaddr))
			return f;
	}
	return NULL;
}

/**
 * nsevf_add_filter - Add a mac filter to the filter list
 * @adapter: board private structure
 * @macaddr: the MAC address
 *
 * Returns ptr to the filter object or NULL when no memory available.
 **/
static struct nsevf_mac_filter *nsevf_add_filter(struct nsevf_adapter *adapter,
						 const u8 *macaddr)
{
	struct nsevf_mac_filter *f;

	if (!macaddr)
		return NULL;

	f = nsevf_find_filter(adapter, macaddr);
	if (!f) {
		f = kzalloc(sizeof(*f), GFP_ATOMIC);
		if (!f)
			return f;

		ether_addr_copy(f->macaddr, macaddr);

		list_add_tail(&f->list, &adapter->mac_filter_list);
		f->add = true;
		f->add_handled = false;
		f->is_new_mac = true;
		f->is_primary = ether_addr_equal(macaddr, adapter->hw.mac.addr);
		adapter->aq_required |= NSEVF_FLAG_AQ_ADD_MAC_FILTER;
	} else {
		f->remove = false;
	}

	return f;
}

/**
 * nsevf_replace_primary_mac - Replace current primary address
 * @adapter: board private structure
 * @new_mac: new mac address to be applied
 *
 * Replace current dev_addr and send request to PF for removal of previous
 * primary mac address filter and addition of new primary mac filter.
 * Return 0 for success, -ENOMEM for failure.
 *
 * Do not call this with mac_vlan_list_lock!
 **/
int nsevf_replace_primary_mac(struct nsevf_adapter *adapter, const u8 *new_mac)
{
	struct nsevf_hw *hw = &adapter->hw;
	struct nsevf_mac_filter *new_f;
	struct nsevf_mac_filter *old_f;
	int ret = 0;

	if (ether_addr_equal(new_mac, hw->mac.addr))
		goto out;

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	new_f = nsevf_add_filter(adapter, new_mac);
	if (!new_f) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	old_f = nsevf_find_filter(adapter, hw->mac.addr);
	if (old_f) {
		old_f->is_primary = false;
		old_f->remove = true;
		adapter->aq_required |= NSEVF_FLAG_AQ_DEL_MAC_FILTER;
	}

	/* Always send the request to add if changing primary MAC
	 * even if filter is already present on the list
	 */
	new_f->is_primary = true;
	new_f->add = true;
	adapter->aq_required |= NSEVF_FLAG_AQ_ADD_MAC_FILTER;
	ether_addr_copy(hw->mac.addr, new_mac);

	/* schedule the watchdog task to immediately process the request */
	nsevf_schedule_aq_request(adapter, NSEVF_FLAG_AQ_ADD_MAC_FILTER);

	ret = 0;

out_unlock:
	spin_unlock_bh(&adapter->mac_vlan_list_lock);

out:
	return ret;
}

/**
 * nsevf_is_mac_set_handled - wait for a response to set MAC from PF
 * @netdev: network interface device structure
 * @macaddr: MAC address to set
 *
 * Returns true on success, false on failure
 **/
static bool nsevf_is_mac_set_handled(struct net_device *netdev,
				     const u8 *macaddr)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	struct nsevf_mac_filter *f;
	bool ret = false;

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	f = nsevf_find_filter(adapter, macaddr);

	if (!f || (!f->add && f->add_handled))
		ret = true;

	spin_unlock_bh(&adapter->mac_vlan_list_lock);

	return ret;
}

void nsevf_dump_mac_filters(struct nsevf_adapter *adapter)
{
	struct device *dev = nsevf_adapter_to_dev(adapter);
	struct nsevf_mac_filter *f;
	unsigned int cnt = 0;

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	list_for_each_entry(f, &adapter->mac_filter_list, list) {
		dev_info(dev, "mac-filter #%d\n", cnt);
		dev_info(dev, "\t macaddr=%pM\n", f->macaddr);
		dev_info(dev, "\t is_new_mac=%d\n", f->is_new_mac);
		dev_info(dev, "\t remove=%d\n", f->remove);
		dev_info(dev, "\t add=%d\n", f->add);
		dev_info(dev, "\t is_primary=%d\n", f->is_primary);
		dev_info(dev, "\t add_handled=%d\n", f->add_handled);

		cnt++;
	}

	spin_unlock_bh(&adapter->mac_vlan_list_lock);

	dev_info(dev, "current cnt of VF mac-filter: %d\n", cnt);
}

/**
 * nsevf_set_mac - NDO callback to set port mac address
 * @netdev: network interface device structure
 * @p: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 **/
static int nsevf_set_mac(struct net_device *netdev, void *p)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	struct nsevf_hw *hw = &adapter->hw;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	struct sockaddr *addr = p;
	unsigned int timeout;
	int ret;

	nsevf_debug(hw, NSEVF_DBG_SW,
		    "[%s]: requested mac_addr=%pM, current mac_addr=%pM, adapter->flags=%X\n",
		__func__, addr->sa_data, adapter->hw.mac.addr, adapter->flags);

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	ret = nsevf_replace_primary_mac(adapter, addr->sa_data);

	if (ret) {
		dev_err(dev, "[%s, %d] fail: replace_primary_mac(), ret=%d\n",
			__func__, __LINE__, ret);
		return ret;
	}

	/* If this is an initial set mac during VF spawn do not wait */
	if (adapter->flags & NSEVF_FLAG_INITIAL_MAC_SET) {
		adapter->flags &= ~NSEVF_FLAG_INITIAL_MAC_SET;
		return 0;
	}

	timeout = (msecs_to_jiffies(2500) * nse_timeout_scale);

	nsevf_debug(hw, NSEVF_DBG_SW, "[%s, %d]: gonna wait for (timeout=%d)\n",
		    __func__, __LINE__, timeout);

	ret =
		wait_event_interruptible_timeout(adapter->vc_waitqueue,
						 nsevf_is_mac_set_handled(netdev, addr->sa_data),
			timeout);

	/* If ret < 0 then it means wait was interrupted.
	 * If ret == 0 then it means we got a timeout.
	 * If ret > 0 it means we got response for set MAC from PF,
	 * check if netdev MAC was updated to requested MAC,
	 * if yes then set MAC succeeded otherwise it failed return -EACCES
	 */
	if (ret < 0) {
		dev_err(dev, "[%s, %d] wait_event interrupted, ret=%d\n",
			__func__, __LINE__, ret);
		return ret;
	}

	if (ret == 0) {
		dev_err(dev, "[%s, %d] wait_event timeout\n", __func__,
			__LINE__);
		return -EAGAIN;
	}

	if (ret > 0 && !ether_addr_equal(netdev->dev_addr, addr->sa_data)) {
		dev_err(dev,
			"[%s, %d] not equal: netdev->dev_addr (%pM), addr->sa_data (%pM)\n",
			__func__, __LINE__, netdev->dev_addr, addr->sa_data);
		return -EACCES;
	}

	return 0;
}

/**
 * nsevf_addr_sync - Callback for dev_(mc|uc)_sync to add address
 * @netdev: the netdevice
 * @addr: address to add
 *
 * Called by __dev_(mc|uc)_sync when an address needs to be added. We call
 * __dev_(uc|mc)_sync from .set_rx_mode and guarantee to hold the hash lock.
 */
static int nsevf_addr_sync(struct net_device *netdev, const u8 *addr)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	if (nsevf_add_filter(adapter, addr))
		return 0;
	else
		return -ENOMEM;
}

/**
 * nsevf_addr_unsync - Callback for dev_(mc|uc)_sync to remove address
 * @netdev: the netdevice
 * @addr: address to add
 *
 * Called by __dev_(mc|uc)_sync when an address needs to be removed. We call
 * __dev_(uc|mc)_sync from .set_rx_mode and guarantee to hold the hash lock.
 */
static int nsevf_addr_unsync(struct net_device *netdev, const u8 *addr)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	struct nsevf_mac_filter *f;

	/* Under some circumstances, we might receive a request to delete
	 * our own device address from our uc list. Because we store the
	 * device address in the VSI's MAC/VLAN filter list, we need to ignore
	 * such requests and not delete our device address from this list.
	 */
	if (ether_addr_equal(addr, netdev->dev_addr))
		return 0;

	f = nsevf_find_filter(adapter, addr);
	if (f) {
		f->remove = true;
		adapter->aq_required |= NSEVF_FLAG_AQ_DEL_MAC_FILTER;
	}

	return 0;
}

/**
 * nsevf_promiscuous_mode_changed - check if promiscuous mode bits changed
 * @adapter: device specific adapter
 */
bool nsevf_promiscuous_mode_changed(struct nsevf_adapter *adapter)
{
	return (adapter->current_netdev_promisc_flags ^
		adapter->netdev->flags) &
	       (IFF_PROMISC | IFF_ALLMULTI);
}

/**
 * nsevf_set_rx_mode - NDO callback to set the netdev filters
 * @netdev: network interface device structure
 **/
static void nsevf_set_rx_mode(struct net_device *netdev)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	__dev_uc_sync(netdev, nsevf_addr_sync, nsevf_addr_unsync);
	__dev_mc_sync(netdev, nsevf_addr_sync, nsevf_addr_unsync);

	spin_unlock_bh(&adapter->mac_vlan_list_lock);

	spin_lock_bh(&adapter->current_netdev_promisc_flags_lock);

	if (nsevf_promiscuous_mode_changed(adapter))
		adapter->aq_required |= NSEVF_FLAG_AQ_CONFIGURE_PROMISC_MODE;
	spin_unlock_bh(&adapter->current_netdev_promisc_flags_lock);
}

/* in unit of us --- when set to HW, translate into 2us unit. */
const struct nse_dim nse_dim_profile[] = {
	{4},
	{32},
	{64},
	{128},
	{192}
};

static void nse_dim_work(struct work_struct *work)
{
	struct dim *dim = container_of(work, struct dim, work);
	struct nsevf_q_vector *q_vector = (struct nsevf_q_vector *)dim->priv;
	u8 profile_ix = READ_ONCE(dim->profile_ix);
	u32 itr;

	if (!ITR_IS_DYNAMIC(q_vector))
		return;

	if (profile_ix >= ARRAY_SIZE(nse_dim_profile)) {
		profile_ix = NSE_DIM_DEFAULT_PROFILE_IX;
		WRITE_ONCE(dim->profile_ix, profile_ix);
	}

	/* look up the values in our local table */
	itr = nse_dim_profile[dim->profile_ix].itr;

	if (ITR_IS_DYNAMIC(q_vector)) {
		WRITE_ONCE(q_vector->dyn_itr_val, (itr >> NSE_ITR_GRAN_S));
		WRITE_ONCE(q_vector->dyn_itr_refresh, true);
	} else {
		WRITE_ONCE(q_vector->dyn_itr_refresh, false);
	}
}

/**
 * nsevf_init_moderation - set up interrupt moderation
 * @q_vector: the vector containing rings to be configured
 *
 * Set up interrupt moderation registers, with the intent to do the right thing
 * when called from reset or from probe, and whether or not dynamic moderation
 * is enabled or not. Take special care to write all the registers in both
 * dynamic moderation mode or not in order to make sure hardware is in a known
 * state.
 */
static void nsevf_init_moderation(struct nsevf_q_vector *q_vector)
{
	INIT_WORK(&q_vector->dim.work, nse_dim_work);
	q_vector->dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
	q_vector->dim.profile_ix = NSE_DIM_DEFAULT_PROFILE_IX;
	q_vector->dim.priv = q_vector;

	q_vector->dyn_itr_refresh = false;

	/* set the initial ITR to match the above */
	(void)nsevf_write_itr(q_vector,
		ITR_IS_DYNAMIC(q_vector) ?
			nse_dim_profile[q_vector->dim.profile_ix].itr :
			q_vector->itr_setting);

	nsevf_set_q_vector_intrl(q_vector);
}

/**
 * nsevf_napi_enable_all - enable NAPI on all queue vectors
 * @adapter: board private structure
 **/
static void nsevf_napi_enable_all(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;
	struct nsevf_q_vector *q_vector;
	int q_vectors = adapter->num_msix_vectors - NONQ_VECS;
	int q_idx;

	mutex_lock(&adapter->misc_mutex);

	nsevf_debug(hw, NSEVF_DBG_LAN, "[%s] napi_enabled = %d\n", __func__,
		    adapter->napi_enabled);

	for (q_idx = 0; q_idx < q_vectors; q_idx++) {
		struct napi_struct *napi;

		q_vector = &adapter->q_vectors[q_idx];

		nsevf_init_moderation(q_vector);

		napi = &q_vector->napi;
		napi_enable(napi);
	}

	adapter->napi_enabled = true;

	mutex_unlock(&adapter->misc_mutex);
}

/**
 * nsevf_napi_disable_all - disable NAPI on all queue vectors
 * @adapter: board private structure
 **/
static void nsevf_napi_disable_all(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;
	int q_vectors = adapter->num_msix_vectors - NONQ_VECS;
	struct nsevf_q_vector *q_vector;
	int q_idx;

	mutex_lock(&adapter->misc_mutex);

	nsevf_debug(hw, NSEVF_DBG_LAN, "[%s] napi_enabled = %d\n", __func__,
		    adapter->napi_enabled);

	if (!adapter->napi_enabled)
		goto out;

	for (q_idx = 0; q_idx < q_vectors; q_idx++) {
		q_vector = &adapter->q_vectors[q_idx];
		napi_disable(&q_vector->napi);

		cancel_work_sync(&q_vector->dim.work);
	}

	adapter->napi_enabled = false;

out:
	mutex_unlock(&adapter->misc_mutex);
}

/**
 * nsevf_configure - set up transmit and receive data structures
 * @adapter: board private structure
 **/
static void nsevf_configure(struct nsevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int i;

	nsevf_set_rx_mode(netdev);

	nsevf_configure_tx(adapter);
	nsevf_configure_rx(adapter);
	adapter->aq_required |= NSEVF_FLAG_AQ_CONFIGURE_QUEUES;

	for (i = 0; i < adapter->num_active_queues; i++) {
		struct nsevf_ring *ring = &adapter->rx_rings[i];

		nsevf_alloc_rx_buffers(ring, NSEVF_DESC_UNUSED(ring));
	}
}

/**
 * nsevf_enable_adapter - Finish the last steps of bringing up a connection
 * @adapter: board private structure
 *
 * Expects to be called while holding the __NSEVF_IN_CRITICAL_TASK bit lock.
 **/
static void nsevf_enable_adapter(struct nsevf_adapter *adapter)
{
	nsevf_change_state(adapter, __NSEVF_RUNNING);
	clear_bit(__NSEVF_VSI_DOWN, adapter->vsi.state);

	if (!nsevf_polling_mod)
		nsevf_napi_enable_all(adapter);

	adapter->aq_required |= NSEVF_FLAG_AQ_ENABLE_QUEUES;

	nsevf_reset_stats(adapter);
}

/**
 * nsevf_up_complete - placeholder function for nsevf_enable_adapter
 * @adapter: board private structure
 *
 * Expects to be called while holding the __NSEVF_IN_CRITICAL_TASK bit lock.
 **/
void nsevf_up_complete(struct nsevf_adapter *adapter)
{
	nsevf_enable_adapter(adapter);

	nsevf_schedule_aq_request(adapter, NSEVF_FLAG_AQ_ENABLE_QUEUES);

	if (nsevf_polling_mod)
		mod_timer(&adapter->vf_polling_tmr,
			  round_jiffies(jiffies + HZ));
}

/**
 * nsevf_down - Shutdown the connection processing
 * @adapter: board private structure
 *
 * Expects to be called while holding the __NSEVF_IN_CRITICAL_TASK bit lock.
 **/
void nsevf_down(struct nsevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct nsevf_vlan_filter *vlf;
	struct nsevf_mac_filter *f;

	if (adapter->state <= __NSEVF_DOWN_PENDING)
		return;

	if (nsevf_polling_mod) {
		del_timer_sync(&adapter->vf_polling_tmr);
		msleep(100);
	}

	nsevf_reset_stats(adapter);

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);
	adapter->link_up = false;
	nsevf_irq_disable(adapter);
	if (!nsevf_polling_mod)
		nsevf_napi_disable_all(adapter);

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	/* clear the sync flag on all filters */
	__dev_uc_unsync(adapter->netdev, NULL);
	__dev_mc_unsync(adapter->netdev, NULL);

	/* remove all MAC filters */
	list_for_each_entry(f, &adapter->mac_filter_list, list) {
		f->remove = true;
	}

	/* remove all VLAN filters */
	list_for_each_entry(vlf, &adapter->vlan_filter_list, list) {
		vlf->remove = true;
	}

	spin_unlock_bh(&adapter->mac_vlan_list_lock);

	if (!(adapter->flags & NSEVF_FLAG_PF_COMMS_FAILED) &&
	    adapter->state != __NSEVF_RESETTING) {
		/* cancel any current operation */
		adapter->current_op = VIRTCHNL_OP_UNKNOWN;
		/* Schedule operations to close down the HW. Don't wait
		 * here for this to complete. The watchdog is still running
		 * and it will take care of this.
		 */
		adapter->aq_required |= NSEVF_FLAG_AQ_DEL_MAC_FILTER;
		adapter->aq_required |= NSEVF_FLAG_AQ_DEL_VLAN_FILTER;
		adapter->aq_required |= NSEVF_FLAG_AQ_DISABLE_QUEUES;
		/* In case the queue configure or enable operations are still
		 * pending from when the interface was opened, make sure
		 * they're canceled here.
		 */
		adapter->aq_required &= ~NSEVF_FLAG_AQ_ENABLE_QUEUES;
		adapter->aq_required &= ~NSEVF_FLAG_AQ_CONFIGURE_QUEUES;
	}

	nsevf_schedule_aq_request(adapter, NSEVF_FLAG_AQ_DISABLE_QUEUES);
}

/**
 * nsevf_acquire_msix_vectors - Setup the MSIX capability
 * @adapter: board private structure
 * @vectors: number of vectors to request
 *
 * Work with the OS to set up the MSIX vectors needed.
 *
 * Returns 0 on success, negative on failure
 **/
static int nsevf_acquire_msix_vectors(struct nsevf_adapter *adapter,
				      int vectors)
{
	int v_actual;

	/* We'll want at least 3 (vector_threshold):
	 * 0) Other (Admin Queue and link, mostly)
	 * 1) TxQ[0] Cleanup
	 * 2) RxQ[0] Cleanup
	 *
	 * The more we get, the more we will assign to Tx/Rx Cleanup
	 * for the separate queues...where Rx Cleanup >= Tx Cleanup.
	 * Right now, we simply care about how many we'll get; we'll
	 * set them up later while requesting irq's.
	 */
	v_actual = pci_enable_msix_range(adapter->pdev, adapter->msix_entries,
					 MIN_MSIX_COUNT, vectors);
	if (v_actual < 0) {
		dev_err(&adapter->pdev->dev,
			"Unable to allocate MSI-X interrupts: %d\n", v_actual);
		kfree(adapter->msix_entries);
		adapter->msix_entries = NULL;
		return v_actual;
	}

	adapter->num_msix_vectors =
		min_t(int, v_actual, adapter->num_active_queues + NONQ_VECS);

	if (adapter->vf_res->max_lan_vectors &&
	    (adapter->vf_res->max_lan_vectors <
	     (adapter->num_msix_vectors - NONQ_VECS)))
		adapter->num_msix_vectors =
			adapter->vf_res->max_lan_vectors + NONQ_VECS;

	if (nsevf_max_lanirq_num &&
	    (nsevf_max_lanirq_num < (adapter->num_msix_vectors - NONQ_VECS)))
		adapter->num_msix_vectors = nsevf_max_lanirq_num + NONQ_VECS;

	if (RDMA_ALLOWED(adapter))
#define NSEVF_RDMA_NUM_OTHER_VECS 1
		adapter->rdma.num_msix =
			min_t(int, v_actual - adapter->num_msix_vectors,
			      num_online_cpus() + NSEVF_RDMA_NUM_OTHER_VECS);

	return 0;
}

/**
 * nsevf_free_queues - Free memory for all rings
 * @adapter: board private structure to initialize
 *
 * Free all of the memory associated with queue pairs.
 **/
static void nsevf_free_queues(struct nsevf_adapter *adapter)
{
	if (!adapter->vsi_res)
		return;
	adapter->num_active_queues = 0;
	kfree(adapter->tx_rings);
	adapter->tx_rings = NULL;
	kfree(adapter->rx_rings);
	adapter->rx_rings = NULL;

	kfree(adapter->txcq_rings);
	adapter->txcq_rings = NULL;
}

/**
 * nsevf_set_queue_vlan_tag_loc - set location for VLAN tag offload
 * @adapter: board private structure
 *
 * Based on negotiated capabilities, the VLAN tag needs to be inserted and/or
 * stripped in certain descriptor fields. Instead of checking the offload
 * capability bits in the hot path, cache the location the ring specific
 * flags.
 */
void nsevf_set_queue_vlan_tag_loc(struct nsevf_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_active_queues; i++) {
		struct nsevf_ring *tx_ring = &adapter->tx_rings[i];
		struct nsevf_ring *rx_ring = &adapter->rx_rings[i];

		/* prevent multiple L2TAG bits being set after VFR */
		tx_ring->flags &= ~(NSEVF_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1 |
				    NSEVF_TXR_FLAGS_VLAN_TAG_LOC_L2TAG2);
		rx_ring->flags &= ~(NSEVF_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1 |
				    NSEVF_RXR_FLAGS_VLAN_TAG_LOC_L2TAG2_2ND);

		if (VLAN_V2_ALLOWED(adapter)) {
			struct virtchnl_vlan_supported_caps *stripping_support;
			struct virtchnl_vlan_supported_caps *insertion_support;

			stripping_support = &adapter->vlan_v2_caps.offloads
						     .stripping_support;
			insertion_support = &adapter->vlan_v2_caps.offloads
						     .insertion_support;

			if (stripping_support->outer) {
				if (stripping_support->outer &
				    VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1)
					rx_ring->flags |=
						NSEVF_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1;
				else if (stripping_support->outer &
					 VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2_2ND)
					rx_ring->flags |=
						NSEVF_RXR_FLAGS_VLAN_TAG_LOC_L2TAG2_2ND;
			} else if (stripping_support->inner) {
				if (stripping_support->inner &
				    VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1)
					rx_ring->flags |=
						NSEVF_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1;
				else if (stripping_support->inner &
					 VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2_2ND)
					rx_ring->flags |=
						NSEVF_RXR_FLAGS_VLAN_TAG_LOC_L2TAG2_2ND;
			}

			if (insertion_support->outer) {
				if (insertion_support->outer &
				    VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1)
					tx_ring->flags |=
						NSEVF_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1;
				else if (insertion_support->outer &
					 VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2)
					tx_ring->flags |=
						NSEVF_TXR_FLAGS_VLAN_TAG_LOC_L2TAG2;
			} else if (insertion_support->inner) {
				if (insertion_support->inner &
				    VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1)
					tx_ring->flags |=
						NSEVF_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1;
				else if (insertion_support->inner &
					 VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2)
					tx_ring->flags |=
						NSEVF_TXR_FLAGS_VLAN_TAG_LOC_L2TAG2;
			}
		}
	}
}

/**
 * nsevf_alloc_queues - Allocate memory for all rings
 * @adapter: board private structure to initialize
 *
 * We allocate one ring per queue at run-time since we don't know the
 * number of queues at compile-time.  The polling_netdev array is
 * intended for Multiqueue, but should work fine with a single queue.
 **/
static int nsevf_alloc_queues(struct nsevf_adapter *adapter)
{
	int i, num_active_queues;

	/* If we're in reset reallocating queues we don't actually know yet for
	 * certain the PF gave us the number of queues we asked for but we'll
	 * assume it did.  Once basic reset is finished we'll confirm once we
	 * start negotiating config with PF.
	 */
	if (adapter->num_req_queues)
		num_active_queues = adapter->num_req_queues;
	else
		num_active_queues = min_t(int,
					  adapter->vsi_res->num_queue_pairs,
					  (int)(num_online_cpus()));

	adapter->tx_rings = kcalloc(num_active_queues,
				    sizeof(struct nsevf_ring), GFP_KERNEL);
	if (!adapter->tx_rings)
		goto err_out;
	adapter->rx_rings = kcalloc(num_active_queues,
				    sizeof(struct nsevf_ring), GFP_KERNEL);
	if (!adapter->rx_rings)
		goto err_out;

	for (i = 0; i < num_active_queues; i++) {
		struct nsevf_ring *tx_ring;
		struct nsevf_ring *rx_ring;

		tx_ring = &adapter->tx_rings[i];

		tx_ring->queue_index = i;
		tx_ring->adapter = adapter;
		tx_ring->netdev = adapter->netdev;
		tx_ring->dev = &adapter->pdev->dev;
		tx_ring->count = adapter->tx_desc_count;

		if (adapter->flags & NSEVF_FLAG_BYPASS_SWITCH)
			tx_ring->flags |= NSEVF_TXR_FLAGS_BYPASS_SWITCH;

		rx_ring = &adapter->rx_rings[i];

		rx_ring->queue_index = i;
		rx_ring->adapter = adapter;
		rx_ring->netdev = adapter->netdev;
		rx_ring->dev = &adapter->pdev->dev;
		rx_ring->count = adapter->rx_desc_count;
	}

	adapter->num_active_queues = num_active_queues;

	nsevf_set_queue_vlan_tag_loc(adapter);

	if (adapter->sw_conf.lan_tx_use_cq) {
		adapter->txcq_rings = kcalloc(adapter->vf_res->lan_txcq_num,
					      sizeof(struct nsevf_txcq_ring),
					      GFP_KERNEL);
		if (!adapter->txcq_rings)
			goto err_out;

		for (i = 0; i < adapter->vf_res->lan_txcq_num; i++) {
			struct nsevf_txcq_ring *cq_ring;

			cq_ring = &adapter->txcq_rings[i];

			cq_ring->queue_index = i;
			cq_ring->adapter = adapter;
			cq_ring->netdev = adapter->netdev;
			cq_ring->dev = &adapter->pdev->dev;
			cq_ring->count = adapter->txcq_desc_count;

			cq_ring->cq_abs_id =
				adapter->vf_res->lan_txcq_base_abs_id + i;
		}
	}

	return 0;

err_out:
	nsevf_free_queues(adapter);
	return -ENOMEM;
}

void nsevf_update_sw_stats(struct nsevf_adapter *adapter)
{
	struct nsevf_vsi_sw_stats *cur_ss, *prev_ss, *new_ss;
	struct nsevf_ring *ring;
	unsigned int start;
	int i;

	cur_ss = &adapter->sw_stats;
	prev_ss = &adapter->sw_stats_prev;
	new_ss = &adapter->sw_stats_new;

	if (!adapter->num_active_queues || !adapter->tx_rings ||
	    !adapter->rx_rings)
		return;

	memset(new_ss, 0, sizeof(*new_ss));

	for (i = 0; i < adapter->num_active_queues; i++) {
		ring = &adapter->tx_rings[i];

		do {
			start = u64_stats_fetch_begin(&ring->syncp);

			new_ss->tx_pkts += ring->stats.packets;
			new_ss->tx_bytes += ring->stats.bytes;

			new_ss->tx_busy += ring->tx_stats.tx_busy;
			new_ss->tx_linearize += ring->tx_stats.tx_linearize;
			new_ss->tx_restart += ring->tx_stats.restart_queue;

		} while (u64_stats_fetch_retry(&ring->syncp, start));

		ring = &adapter->rx_rings[i];

		do {
			start = u64_stats_fetch_begin(&ring->syncp);

			new_ss->rx_pkts += ring->stats.packets;
			new_ss->rx_bytes += ring->stats.bytes;

			new_ss->rx_csum_good += ring->rx_stats.rx_csum_good;
			new_ss->rx_csum_bad += ring->rx_stats.rx_csum_bad;

			new_ss->fdir_match +=
				ring->rx_stats.qsrc_cnt[NSE_RXD_QSRC_FD];
			new_ss->fdir_miss +=
				ring->rx_stats.qsrc_cnt[NSE_RXD_QSRC_RSS];

			new_ss->rx_buf_failed +=
				ring->rx_stats.alloc_buff_failed;
			new_ss->rx_page_failed +=
				ring->rx_stats.alloc_page_failed;
			new_ss->page_reuse_count +=
				ring->rx_stats.page_reuse_count;

		} while (u64_stats_fetch_retry(&ring->syncp, start));
	}

	nsevf_stat_update64(new_ss->rx_pkts, adapter->sw_stats_prev_loaded,
			    &prev_ss->rx_pkts, &cur_ss->rx_pkts);
	nsevf_stat_update64(new_ss->rx_bytes, adapter->sw_stats_prev_loaded,
			    &prev_ss->rx_bytes, &cur_ss->rx_bytes);
	nsevf_stat_update64(new_ss->tx_pkts, adapter->sw_stats_prev_loaded,
			    &prev_ss->tx_pkts, &cur_ss->tx_pkts);
	nsevf_stat_update64(new_ss->tx_bytes, adapter->sw_stats_prev_loaded,
			    &prev_ss->tx_bytes, &cur_ss->tx_bytes);
	nsevf_stat_update64(new_ss->tx_linearize, adapter->sw_stats_prev_loaded,
			    &prev_ss->tx_linearize, &cur_ss->tx_linearize);
	nsevf_stat_update64(new_ss->tx_restart, adapter->sw_stats_prev_loaded,
			    &prev_ss->tx_restart, &cur_ss->tx_restart);
	nsevf_stat_update64(new_ss->tx_busy, adapter->sw_stats_prev_loaded,
			    &prev_ss->tx_busy, &cur_ss->tx_busy);
	nsevf_stat_update64(new_ss->rx_csum_good, adapter->sw_stats_prev_loaded,
			    &prev_ss->rx_csum_good, &cur_ss->rx_csum_good);
	nsevf_stat_update64(new_ss->rx_csum_bad, adapter->sw_stats_prev_loaded,
			    &prev_ss->rx_csum_bad, &cur_ss->rx_csum_bad);
	nsevf_stat_update64(new_ss->fdir_match, adapter->sw_stats_prev_loaded,
			    &prev_ss->fdir_match, &cur_ss->fdir_match);
	nsevf_stat_update64(new_ss->fdir_miss, adapter->sw_stats_prev_loaded,
			    &prev_ss->fdir_miss, &cur_ss->fdir_miss);
	nsevf_stat_update64(new_ss->rx_buf_failed,
			    adapter->sw_stats_prev_loaded,
			    &prev_ss->rx_buf_failed, &cur_ss->rx_buf_failed);
	nsevf_stat_update64(new_ss->rx_page_failed,
			    adapter->sw_stats_prev_loaded,
			    &prev_ss->rx_page_failed, &cur_ss->rx_page_failed);
	nsevf_stat_update64(new_ss->page_reuse_count,
			    adapter->sw_stats_prev_loaded,
			    &prev_ss->page_reuse_count,
			    &cur_ss->page_reuse_count);

	adapter->sw_stats_prev_loaded = true;
}

void nsevf_sync_net_stats(struct nsevf_adapter *adapter)
{
	struct net_device_stats *ns = &adapter->net_stats;
	struct nsevf_vsi_sw_stats *ss = &adapter->sw_stats;
	struct nsevf_vsi_hw_stats *hs = &adapter->hw_stats;

	/* some from SW stats, some from HW stats */

	ns->rx_packets = ss->rx_pkts;
	ns->rx_bytes = ss->rx_bytes;

	ns->tx_packets = ss->tx_pkts;
	ns->tx_bytes = ss->tx_bytes;

	ns->rx_errors = hs->rx_dpkt;
	ns->tx_errors = hs->tx_dptc;
	ns->rx_dropped = hs->rx_dpkt;
	ns->tx_dropped = hs->tx_dptc;
}

void nsevf_reset_stats(struct nsevf_adapter *adapter)
{
	struct nsevf_ring *ring;
	struct nsevf_txcq_ring *cq_ring;
	int i;

	memset(&adapter->hw_stats, 0, sizeof(adapter->hw_stats));

	memset(&adapter->sw_stats_prev, 0, sizeof(adapter->sw_stats_prev));
	memset(&adapter->sw_stats_new, 0, sizeof(adapter->sw_stats_new));
	adapter->sw_stats_prev_loaded = false;

	for (i = 0; i < adapter->num_active_queues; i++) {
		if (adapter->tx_rings) {
			ring = &adapter->tx_rings[i];
			memset(&ring->stats, 0, sizeof(ring->stats));
			memset(&ring->tx_stats, 0, sizeof(ring->tx_stats));
		}

		if (adapter->rx_rings) {
			ring = &adapter->rx_rings[i];
			memset(&ring->stats, 0, sizeof(ring->stats));
			memset(&ring->rx_stats, 0, sizeof(ring->rx_stats));
		}
	}

	if (adapter->sw_conf.lan_tx_use_cq && adapter->txcq_rings) {
		nsevf_for_each_txcq(adapter, i) {
			cq_ring = &adapter->txcq_rings[i];
			memset(&cq_ring->stats, 0, sizeof(cq_ring->stats));
		}
	}
}

/**
 * nsevf_set_interrupt_capability - set MSI-X or FAIL if not supported
 * @adapter: board private structure to initialize
 *
 * Attempt to configure the interrupts using the best available
 * capabilities of the hardware and the kernel.
 **/
static int nsevf_set_interrupt_capability(struct nsevf_adapter *adapter)
{
	int vector, v_budget;
	int pairs = 0;
	int err = 0;

	if (!adapter->vsi_res) {
		err = -EIO;
		goto out;
	}
	pairs = adapter->num_active_queues;

	/* It's easy to be greedy for MSI-X vectors, but it really doesn't do
	 * us much good if we have more vectors than CPUs. However, we already
	 * limit the total number of queues by the number of CPUs so we do not
	 * need any further limiting here.
	 */
	if (RDMA_ALLOWED(adapter)) {
		/* add MSI-X wanted by RDMA */
		int max_needed = min_t(int,
				       pairs + NONQ_VECS + num_online_cpus() +
					       NSEVF_RDMA_NUM_OTHER_VECS,
				       (int)adapter->vf_res->max_vectors);

		v_budget = max_t(int, pairs + NONQ_VECS, max_needed);
	} else {
		v_budget = min_t(int, pairs + NONQ_VECS,
				 (int)adapter->vf_res->max_vectors);
	}

	adapter->msix_entries =
		kcalloc(v_budget, sizeof(struct msix_entry), GFP_KERNEL);
	if (!adapter->msix_entries) {
		err = -ENOMEM;
		goto out;
	}

	for (vector = 0; vector < v_budget; vector++)
		adapter->msix_entries[vector].entry = vector;

	err = nsevf_acquire_msix_vectors(adapter, v_budget);
out:
	netif_set_real_num_rx_queues(adapter->netdev, pairs);
	netif_set_real_num_tx_queues(adapter->netdev, pairs);
	return err;
}

/**
 * nsevf_alloc_q_vectors - Allocate memory for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * We allocate one q_vector per queue interrupt.  If allocation fails we
 * return -ENOMEM.
 **/
static int nsevf_alloc_q_vectors(struct nsevf_adapter *adapter)
{
	int q_idx = 0, num_q_vectors;
	struct nsevf_q_vector *q_vector;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	int best_local_cpu_id;

	num_q_vectors = adapter->num_msix_vectors - NONQ_VECS;
	adapter->q_vectors =
		kcalloc(num_q_vectors, sizeof(*q_vector), GFP_KERNEL);
	if (!adapter->q_vectors)
		return -ENOMEM;
	for (q_idx = 0; q_idx < num_q_vectors; q_idx++) {
		q_vector = &adapter->q_vectors[q_idx];
		q_vector->adapter = adapter;
		q_vector->vsi = &adapter->vsi;
		q_vector->v_idx = q_idx;

		q_vector->reg_idx = q_idx + NONQ_VECS;

		if (nsevf_lan_min_itr_no_intrl) {
			q_vector->itr_setting = NSE_ITR_INTERVAL_MIN_USEC;
			q_vector->itr_mode = ITR_STATIC;
		} else {
			q_vector->itr_setting = NSE_ITR_INTERVAL_DEFAULT;
			q_vector->itr_mode = ITR_DYNAMIC;
		}

		q_vector->intrl = NSE_INTRL_INTERVAL_NO_USEC;

		best_local_cpu_id = cpumask_local_spread(q_vector->v_idx, dev_to_node(dev));
		if (cpu_online(best_local_cpu_id)) {
			cpumask_set_cpu(best_local_cpu_id, &q_vector->affinity_mask);
			cpumask_set_cpu(best_local_cpu_id, &q_vector->best_affinity_mask);
			q_vector->best_local_cpu_id = best_local_cpu_id;
		} else {
			cpumask_copy(&q_vector->affinity_mask, cpu_possible_mask);
			q_vector->best_local_cpu_id = -1;
		}
		netif_napi_add(adapter->netdev, &q_vector->napi,
			       nsevf_napi_poll);
	}

	return 0;
}

/**
 * nsevf_free_q_vectors - Free memory allocated for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * This function frees the memory allocated to the q_vectors.  In addition if
 * NAPI is enabled it will delete any references to the NAPI struct prior
 * to freeing the q_vector.
 **/
static void nsevf_free_q_vectors(struct nsevf_adapter *adapter)
{
	int q_idx, num_q_vectors;
	int napi_vectors;

	if (!adapter->q_vectors)
		return;

	num_q_vectors = adapter->num_msix_vectors - NONQ_VECS;
	napi_vectors = adapter->num_active_queues;

	for (q_idx = 0; q_idx < num_q_vectors; q_idx++) {
		struct nsevf_q_vector *q_vector = &adapter->q_vectors[q_idx];

		if (q_idx < napi_vectors)
			netif_napi_del(&q_vector->napi);
	}
	kfree(adapter->q_vectors);
	adapter->q_vectors = NULL;
}

/**
 * nsevf_reset_interrupt_capability - Reset MSIX setup
 * @adapter: board private structure
 *
 **/
void nsevf_reset_interrupt_capability(struct nsevf_adapter *adapter)
{
	if (!adapter->msix_entries)
		return;

	pci_disable_msix(adapter->pdev);
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
}

/**
 * nsevf_init_interrupt_scheme - Determine if MSIX is supported and init
 * @adapter: board private structure to initialize
 *
 **/
int nsevf_init_interrupt_scheme(struct nsevf_adapter *adapter)
{
	int err;

	err = nsevf_alloc_queues(adapter);
	if (err) {
		dev_err(&adapter->pdev->dev,
			"Unable to allocate memory for queues\n");
		goto err_alloc_queues;
	}

	rtnl_lock();
	err = nsevf_set_interrupt_capability(adapter);
	rtnl_unlock();
	if (err) {
		dev_err(&adapter->pdev->dev,
			"Unable to setup interrupt capabilities\n");
		goto err_set_interrupt;
	}

	err = nsevf_alloc_q_vectors(adapter);
	if (err) {
		dev_err(&adapter->pdev->dev,
			"Unable to allocate memory for queue vectors\n");
		goto err_alloc_q_vectors;
	}

	dev_info(&adapter->pdev->dev, "Multiqueue %s: Queue pair count = %u",
		 (adapter->num_active_queues > 1) ? "Enabled" : "Disabled",
		 adapter->num_active_queues);

	return 0;
err_alloc_q_vectors:
	nsevf_reset_interrupt_capability(adapter);
err_set_interrupt:
	nsevf_free_queues(adapter);
err_alloc_queues:
	return err;
}

/**
 * nsevf_reinit_interrupt_scheme - Reallocate queues and vectors
 * @adapter: board private structure
 *
 * Returns 0 on success, negative on failure
 **/
static int nsevf_reinit_interrupt_scheme(struct nsevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int err;

	if (!test_bit(__NSEVF_VSI_DOWN, adapter->vsi.state))
		nsevf_free_traffic_irqs(adapter);
	nsevf_free_misc_irq(adapter);
	nsevf_reset_interrupt_capability(adapter);
	nsevf_free_q_vectors(adapter);
	nsevf_free_queues(adapter);

	err = nsevf_init_interrupt_scheme(adapter);
	if (err)
		goto err;

	netif_tx_stop_all_queues(netdev);

	err = nsevf_request_misc_irq(adapter);
	if (err)
		goto err;

	set_bit(__NSEVF_VSI_DOWN, adapter->vsi.state);

	nsevf_map_rings_to_vectors(adapter);
err:
	return err;
}

/**
 * nsevf_config_rss - Configure RSS keys and lut
 * @adapter: board private structure
 * @flags: RSS configuration flags
 *
 * Returns 0 on success, negative on failure
 **/
int nsevf_config_rss(struct nsevf_adapter *adapter, unsigned int flags)
{
	struct nsevf_hw *hw = &adapter->hw;

	nsevf_debug(hw, NSEVF_DBG_LAN, "[%s] flags = 0x%X\n", __func__, flags);

	if (RSS_PF(adapter)) {
		if (flags & NSEVF_CONFIG_RSS_FLAG_ALG)
			adapter->aq_required |= NSEVF_FLAG_AQ_SET_RSS_ALG;

		if (flags & NSEVF_CONFIG_RSS_FLAG_KEY)
			adapter->aq_required |= NSEVF_FLAG_AQ_SET_RSS_KEY;

		if (flags & NSEVF_CONFIG_RSS_FLAG_LUT)
			adapter->aq_required |= NSEVF_FLAG_AQ_SET_RSS_LUT;

		return 0;
	}

	dev_err(&adapter->pdev->dev,
		"[%s, %d] MUST need PF driver give us VIRTCHNL_VF_OFFLOAD_RSS_PF\n",
		__func__, __LINE__);
	return -EIO;
}

/**
 * nsevf_fill_rss_lut_dflt - Fill the lut with default values
 * @adapter: board private structure
 **/
static void nsevf_fill_rss_lut_dflt(struct nsevf_adapter *adapter)
{
	u16 i;

	for (i = 0; i < adapter->rss_lut_size; i++)
		adapter->rss_lut[i] = i % adapter->num_active_queues;
}

static void nsevf_fill_rss_lut_all_zero(struct nsevf_adapter *adapter)
{
	u16 i;

	for (i = 0; i < adapter->rss_lut_size; i++)
		adapter->rss_lut[i] = 0;
}

/**
 * nsevf_init_rss - Prepare for RSS
 * @adapter: board private structure
 * @in_init: whether RSS is being initialized during device setup
 *
 * Return 0 on success, negative on failure
 **/
static int nsevf_init_rss(struct nsevf_adapter *adapter, bool in_init)
{
	struct nsevf_hw *hw = &adapter->hw;

	nsevf_debug(hw, NSEVF_DBG_LAN, "[%s] in_init=%d\n", __func__, in_init);

	if (in_init) {
		nsevf_fill_rss_lut_dflt(adapter);
		netdev_rss_key_fill((void *)adapter->rss_key,
				    adapter->rss_key_size);
	}

	return nsevf_config_rss(adapter, NSEVF_CONFIG_RSS_FLAG_ALL);
}

/**
 * nsevf_free_rss - Free memory used by RSS structs
 * @adapter: board private structure
 **/
static void nsevf_free_rss(struct nsevf_adapter *adapter)
{
	kfree(adapter->rss_key);

	adapter->rss_key = NULL;

	kfree(adapter->rss_lut);

	adapter->rss_lut = NULL;
}

/**
 * nsevf_set_vlan_offload_features - set VLAN offload configuration
 * @adapter: board private structure
 * @prev_features: previous features used for comparison
 * @features: updated features used for configuration
 *
 * Set the aq_required bit(s) based on the requested features passed in to
 * configure VLAN stripping and/or VLAN insertion if supported. Also, schedule
 * the watchdog if any changes are requested to expedite the request via
 * virtchnl.
 */
void nsevf_set_vlan_offload_features(struct nsevf_adapter *adapter,
				     netdev_features_t prev_features,
				     netdev_features_t features)
{
	bool enable_stripping = true, enable_insertion = true;
	u16 vlan_ethertype = 0;
	u64 aq_required = 0;

	/* keep cases separate because one ethertype for offloads can be
	 * disabled at the same time as another is disabled, so check for an
	 * enabled ethertype first, then check for disabled. Default to
	 * ETH_P_8021Q so an ethertype is specified if disabling insertion and
	 * stripping.
	 */
	if (features & (NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX))
		vlan_ethertype = ETH_P_8021AD;
	else if (features & (NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX))
		vlan_ethertype = ETH_P_8021Q;
	else if (prev_features &
		 (NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX))
		vlan_ethertype = ETH_P_8021AD;
	else if (prev_features &
		 (NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX))
		vlan_ethertype = ETH_P_8021Q;
	else
		vlan_ethertype = ETH_P_8021Q;

	if (!(features & (NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_CTAG_RX)))
		enable_stripping = false;
	if (!(features & (NETIF_F_HW_VLAN_STAG_TX | NETIF_F_HW_VLAN_CTAG_TX)))
		enable_insertion = false;

	if (VLAN_V2_ALLOWED(adapter)) {
		switch (vlan_ethertype) {
		case ETH_P_8021Q:
			if (enable_stripping)
				aq_required |=
					NSEVF_FLAG_AQ_ENABLE_CTAG_VLAN_STRIPPING;
			else
				aq_required |=
					NSEVF_FLAG_AQ_DISABLE_CTAG_VLAN_STRIPPING;

			if (enable_insertion)
				aq_required |=
					NSEVF_FLAG_AQ_ENABLE_CTAG_VLAN_INSERTION;
			else
				aq_required |=
					NSEVF_FLAG_AQ_DISABLE_CTAG_VLAN_INSERTION;
			break;
		case ETH_P_8021AD:
			if (enable_stripping)
				aq_required |=
					NSEVF_FLAG_AQ_ENABLE_STAG_VLAN_STRIPPING;
			else
				aq_required |=
					NSEVF_FLAG_AQ_DISABLE_STAG_VLAN_STRIPPING;

			if (enable_insertion)
				aq_required |=
					NSEVF_FLAG_AQ_ENABLE_STAG_VLAN_INSERTION;
			else
				aq_required |=
					NSEVF_FLAG_AQ_DISABLE_STAG_VLAN_INSERTION;
			break;
		}
	}

	if (aq_required)
		nsevf_schedule_aq_request(adapter, aq_required);
}

/**
 * nsevf_get_netdev_vlan_hw_features - get NETDEV VLAN features
 * @adapter: board private structure
 *
 * Depending on whether VIRTCHNL_VF_OFFLOAD_VLAN_V2
 * were negotiated determine the VLAN features that can be toggled on and off.
 **/
static netdev_features_t
nsevf_get_netdev_vlan_hw_features(struct nsevf_adapter *adapter)
{
	netdev_features_t hw_features = 0;

	if (!adapter->vf_res || !adapter->vf_res->vf_cap_flags)
		return hw_features;

	/* Enable VLAN features if supported */
	if (VLAN_V2_ALLOWED(adapter)) {
		struct virtchnl_vlan_caps *vlan_v2_caps =
			&adapter->vlan_v2_caps;
		struct virtchnl_vlan_supported_caps *stripping_support =
			&vlan_v2_caps->offloads.stripping_support;
		struct virtchnl_vlan_supported_caps *insertion_support =
			&vlan_v2_caps->offloads.insertion_support;

		if (stripping_support->outer != VIRTCHNL_VLAN_UNSUPPORTED &&
		    stripping_support->outer & VIRTCHNL_VLAN_TOGGLE) {
			if (stripping_support->outer &
			    VIRTCHNL_VLAN_ETHERTYPE_8100)
				hw_features |= NSEVF_NETIF_F_HW_VLAN_CTAG_RX;
			if (stripping_support->outer &
			    VIRTCHNL_VLAN_ETHERTYPE_88A8)
				hw_features |= NETIF_F_HW_VLAN_STAG_RX;
		} else if (stripping_support->inner !=
				   VIRTCHNL_VLAN_UNSUPPORTED &&
			   stripping_support->inner & VIRTCHNL_VLAN_TOGGLE) {
			if (stripping_support->inner &
			    VIRTCHNL_VLAN_ETHERTYPE_8100)
				hw_features |= NSEVF_NETIF_F_HW_VLAN_CTAG_RX;
		}

		if (insertion_support->outer != VIRTCHNL_VLAN_UNSUPPORTED &&
		    insertion_support->outer & VIRTCHNL_VLAN_TOGGLE) {
			if (insertion_support->outer &
			    VIRTCHNL_VLAN_ETHERTYPE_8100)
				hw_features |= NSEVF_NETIF_F_HW_VLAN_CTAG_TX;
			if (insertion_support->outer &
			    VIRTCHNL_VLAN_ETHERTYPE_88A8)
				hw_features |= NETIF_F_HW_VLAN_STAG_TX;
		} else if (insertion_support->inner &&
			   insertion_support->inner & VIRTCHNL_VLAN_TOGGLE) {
			if (insertion_support->inner &
			    VIRTCHNL_VLAN_ETHERTYPE_8100)
				hw_features |= NSEVF_NETIF_F_HW_VLAN_CTAG_TX;
		}
	}

	return hw_features;
}

/**
 * nsevf_get_netdev_vlan_features - get the enabled NETDEV VLAN fetures
 * @adapter: board private structure
 *
 * Depending on whether VIRTCHNL_VF_OFFLOAD_VLAN_V2
 * were negotiated determine the VLAN features that are enabled by default.
 **/
static netdev_features_t
nsevf_get_netdev_vlan_features(struct nsevf_adapter *adapter)
{
	netdev_features_t features = 0;

	if (!adapter->vf_res || !adapter->vf_res->vf_cap_flags)
		return features;

	if (VLAN_V2_ALLOWED(adapter)) {
		struct virtchnl_vlan_caps *vlan_v2_caps =
			&adapter->vlan_v2_caps;
		struct virtchnl_vlan_supported_caps *filtering_support =
			&vlan_v2_caps->filtering.filtering_support;
		struct virtchnl_vlan_supported_caps *stripping_support =
			&vlan_v2_caps->offloads.stripping_support;
		struct virtchnl_vlan_supported_caps *insertion_support =
			&vlan_v2_caps->offloads.insertion_support;
		u32 ethertype_init;

		/* give priority to outer stripping and don't support both outer
		 * and inner stripping
		 */
		ethertype_init = vlan_v2_caps->offloads.ethertype_init;
		if (stripping_support->outer != VIRTCHNL_VLAN_UNSUPPORTED) {
			if (stripping_support->outer &
				    VIRTCHNL_VLAN_ETHERTYPE_8100 &&
			    ethertype_init & VIRTCHNL_VLAN_ETHERTYPE_8100)
				features |= NSEVF_NETIF_F_HW_VLAN_CTAG_RX;
			else if (stripping_support->outer &
					 VIRTCHNL_VLAN_ETHERTYPE_88A8 &&
				 ethertype_init & VIRTCHNL_VLAN_ETHERTYPE_88A8)
				features |= NETIF_F_HW_VLAN_STAG_RX;
		} else if (stripping_support->inner !=
			   VIRTCHNL_VLAN_UNSUPPORTED) {
			if (stripping_support->inner &
				    VIRTCHNL_VLAN_ETHERTYPE_8100 &&
			    ethertype_init & VIRTCHNL_VLAN_ETHERTYPE_8100)
				features |= NSEVF_NETIF_F_HW_VLAN_CTAG_RX;
		}

		/* give priority to outer insertion and don't support both outer
		 * and inner insertion
		 */
		if (insertion_support->outer != VIRTCHNL_VLAN_UNSUPPORTED) {
			if (insertion_support->outer &
				    VIRTCHNL_VLAN_ETHERTYPE_8100 &&
			    ethertype_init & VIRTCHNL_VLAN_ETHERTYPE_8100)
				features |= NSEVF_NETIF_F_HW_VLAN_CTAG_TX;
			else if (insertion_support->outer &
					 VIRTCHNL_VLAN_ETHERTYPE_88A8 &&
				 ethertype_init & VIRTCHNL_VLAN_ETHERTYPE_88A8)
				features |= NETIF_F_HW_VLAN_STAG_TX;
		} else if (insertion_support->inner !=
			   VIRTCHNL_VLAN_UNSUPPORTED) {
			if (insertion_support->inner &
				    VIRTCHNL_VLAN_ETHERTYPE_8100 &&
			    ethertype_init & VIRTCHNL_VLAN_ETHERTYPE_8100)
				features |= NSEVF_NETIF_F_HW_VLAN_CTAG_TX;
		}

		/* give priority to outer filtering and don't bother if both
		 * outer and inner filtering are enabled
		 */
		ethertype_init = vlan_v2_caps->filtering.ethertype_init;
		if (filtering_support->outer != VIRTCHNL_VLAN_UNSUPPORTED) {
			if (filtering_support->outer &
				    VIRTCHNL_VLAN_ETHERTYPE_8100 &&
			    ethertype_init & VIRTCHNL_VLAN_ETHERTYPE_8100)
				features |= NSEVF_NETIF_F_HW_VLAN_CTAG_FILTER;
			if (filtering_support->outer &
				    VIRTCHNL_VLAN_ETHERTYPE_88A8 &&
			    ethertype_init & VIRTCHNL_VLAN_ETHERTYPE_88A8)
				features |= NETIF_F_HW_VLAN_STAG_FILTER;
		} else if (filtering_support->inner !=
			   VIRTCHNL_VLAN_UNSUPPORTED) {
			if (filtering_support->inner &
				    VIRTCHNL_VLAN_ETHERTYPE_8100 &&
			    ethertype_init & VIRTCHNL_VLAN_ETHERTYPE_8100)
				features |= NSEVF_NETIF_F_HW_VLAN_CTAG_FILTER;
			if (filtering_support->inner &
				    VIRTCHNL_VLAN_ETHERTYPE_88A8 &&
			    ethertype_init & VIRTCHNL_VLAN_ETHERTYPE_88A8)
				features |= NETIF_F_HW_VLAN_STAG_FILTER;
		}
	}

	return features;
}

/**
 * nsevf_check_reset_complete - check that VF reset is complete
 * @hw: pointer to hw struct
 * @check_frtrig: whether to check the VF reset trigger
 * @check_arqbal: whether to check the receive queue base address
 *
 * Returns 0 if device is ready to use, or -EBUSY if it's in reset.
 **/
int nsevf_check_reset_complete(struct nsevf_hw *hw, bool check_frtrig,
			       bool check_arqbal)
{
	u32 reg = 0;
	unsigned int i;
	unsigned int wait_timeout;

	wait_timeout =
		(NSEVF_RESET_WAIT_COMPLETE_TIMEOUT_BASE * nse_timeout_scale);

	nsevf_debug(hw, NSEVF_DBG_SYS,
		    "[%s] - enter: check_frtrig=%d, check_arqbal=%d, wait_timeout=%d\n",
		__func__, check_frtrig, check_arqbal, wait_timeout);

	if (!check_frtrig && !check_arqbal) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s] what are you checking ? check_frtrig and check_arqbal are all FALSE\n",
			__func__);
		return 0;
	}

	if (!check_frtrig)
		goto skip_check_frtrig;

	for (i = 0; i < wait_timeout; i++) {
		reg = rd32(hw, NSEVF_REG_CTL);
		if (reg & NSEVF_REG_CTL_FRTRIG_STATUS_M) {
			msleep(NSEVF_RESET_WAIT_TICK);
		} else {
			nsevf_debug(hw, NSEVF_DBG_SYS,
				    "[%s] see VF FRTRIG = 0, wait times=%d\n",
				    __func__, i);

			break;
		}
	}

	if (i >= wait_timeout) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s] timeout wait for VF FRTRIG = 0, reg_ctl=0x%X\n",
			__func__, reg);

		goto out_not_complete;
	}

skip_check_frtrig:

	if (!check_arqbal)
		goto out_complete;

	for (i = 0; i < wait_timeout; i++) {
		reg = rd32(hw, MBX_ARQBAL(hw));
		if (reg != NSE_REG_VMBX_ARQBAL_MAGIC_PF_INIT) {
			msleep(NSEVF_RESET_WAIT_TICK);
		} else {
			nsevf_debug(hw, NSEVF_DBG_SYS,
				    "[%s] see ARQBAL = 0x%X (init_magic) set by PF drv, wait times=%d\n",
				__func__, NSE_REG_VMBX_ARQBAL_MAGIC_PF_INIT, i);
			break;
		}
	}

	if (i >= wait_timeout) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s] timeout wait for ARQBAL = 0x%X (init_magic) set by PF drv, reg_mbx_arqbal=0x%X\n",
			__func__, NSE_REG_VMBX_ARQBAL_MAGIC_PF_INIT, reg);

		goto out_not_complete;
	}

out_complete:
	nsevf_debug(hw, NSEVF_DBG_SYS,
		    "[%s] - exit: VF reset PF/FW-cleanup complete in time\n",
		    __func__);
	return 0;

out_not_complete:

	nsevf_debug(hw, NSEVF_DBG_SYS,
		    "[%s] - exit: VF reset PF/FW-cleanup NOT complete in time\n",
		__func__);

	return -EBUSY;
}

/**
 * nsevf_process_config - Process the config information we got from the PF
 * @adapter: board private structure
 *
 * Verify that we have a valid config struct, and set up our netdev features
 * and our VSI struct.
 **/
int nsevf_process_config(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;
	struct virtchnl_vf_resource *vfres = adapter->vf_res;
	netdev_features_t hw_vlan_features, vlan_features;
	struct net_device *netdev = adapter->netdev;
	netdev_features_t hw_enc_features;
	netdev_features_t hw_features;

	hw_enc_features = NETIF_F_SG | NETIF_F_HW_CSUM |
			  NETIF_F_HIGHDMA | NETIF_F_SOFT_FEATURES |
			  NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_SCTP_CRC |
			  NETIF_F_RXHASH | NETIF_F_RXCSUM;

	/* advertise to stack only if offloads for encapsulated packets is
	 * supported
	 */
	if (vfres->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_ENCAP) {
		hw_enc_features |= NETIF_F_GSO_UDP_TUNNEL |
				   NETIF_F_GSO_GRE |
				   NETIF_F_GSO_GRE_CSUM |
				   NETIF_F_GSO_IPXIP4 |
				   NETIF_F_GSO_IPXIP6 |
				   NETIF_F_GSO_UDP_TUNNEL_CSUM |
				   NETIF_F_GSO_PARTIAL;

		if (!(vfres->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM))
			netdev->gso_partial_features |=
				NETIF_F_GSO_UDP_TUNNEL_CSUM;

		netdev->gso_partial_features |= NETIF_F_GSO_GRE_CSUM;
		netdev->hw_enc_features |= NETIF_F_TSO_MANGLEID;
		netdev->hw_enc_features |= hw_enc_features;
	}

	/* record features VLANs can make use of */
	netdev->vlan_features |= hw_enc_features | NETIF_F_TSO_MANGLEID;
	/* Write features and hw_features separately to avoid polluting
	 * with, or dropping, features that are set when we registered.
	 */
	hw_features = hw_enc_features;

	/* get HW VLAN features that can be toggled */
	hw_vlan_features = nsevf_get_netdev_vlan_hw_features(adapter);

	hw_features |= NETIF_F_GSO_UDP_L4;

	netdev->hw_enc_features |=
		(hw_vlan_features &
		 (NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX));

	if (!(vfres->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_LSO)) {
		hw_features &= ~NETIF_F_GSO_MASK;

		netdev->vlan_features &= ~NETIF_F_GSO_MASK;
		netdev->hw_enc_features &= ~NETIF_F_GSO_MASK;
		netdev->gso_partial_features &= ~NETIF_F_GSO_MASK;
	}

	if (adapter->sw_conf.lan_rx_ena_rsc)
		hw_features |= NETIF_F_LRO;

	if ((vfres->vf_cap_flags & VIRTCHNL_VF_CAP_FDIR) &&
	    hw->utilq_initialized)
		hw_features |= NETIF_F_NTUPLE;

	netdev->hw_features |= hw_features | hw_vlan_features;

	/* get VLAN features that cannot be toggled */
	vlan_features = nsevf_get_netdev_vlan_features(adapter);

	netdev->features |= hw_features | vlan_features;

	netdev->priv_flags |= IFF_UNICAST_FLT;
	/* Do not turn on offloads when they are requested to be turned off.
	 * TSO needs minimum 576 bytes to work correctly.
	 */
	if (netdev->wanted_features) {
		if (!(netdev->wanted_features & NETIF_F_TSO) ||
		    netdev->mtu < 576)
			netdev->features &= ~NETIF_F_TSO;
		if (!(netdev->wanted_features & NETIF_F_TSO6) ||
		    netdev->mtu < 576)
			netdev->features &= ~NETIF_F_TSO6;
		if (!(netdev->wanted_features & NETIF_F_TSO_ECN))
			netdev->features &= ~NETIF_F_TSO_ECN;
		if (!(netdev->wanted_features & NETIF_F_GRO))
			netdev->features &= ~NETIF_F_GRO;
		if (!(netdev->wanted_features & NETIF_F_GSO))
			netdev->features &= ~NETIF_F_GSO;
	}

	return 0;
}

static void nsevf_get_itr_intrl_gran(struct nsevf_hw *hw)
{
	hw->itr_gran = NSE_ITR_GRAN_FIXED;
	hw->intrl_gran = NSE_INTRL_GRAN_FIXED;
}

/**
 * nsevf_startup - first step of driver startup
 * @adapter: board private structure
 *
 * Function process __NSEVF_STARTUP driver state.
 * When success the state is changed to __NSEVF_INIT_VERSION_CHECK
 * when fails the state is changed to __NSEVF_INIT_FAILED
 **/
static void nsevf_startup(struct nsevf_adapter *adapter)
{
	struct pci_dev *pdev = adapter->pdev;
	struct nsevf_hw *hw = &adapter->hw;
	enum nsevf_status status;
	int ret;

	WARN_ON(adapter->state != __NSEVF_STARTUP);

	/* driver loaded, probe complete */
	adapter->flags &= ~NSEVF_FLAG_PF_COMMS_FAILED;
	adapter->flags &= ~NSEVF_FLAG_RESET_PENDING;
	status = nsevf_set_mac_type(hw);
	if (status) {
		dev_err(&pdev->dev, "Failed to set MAC type (%d)\n", status);
		goto err;
	}

	ret = nsevf_check_reset_complete(hw, true, false);
	if (ret) {
		dev_err(&pdev->dev, "Device is still in reset (%d), retrying\n",
			ret);
		goto err;
	}

	nsevf_get_itr_intrl_gran(hw);

	hw->mailboxq.num_arq_entries = NSEVF_AQ_LEN;
	hw->mailboxq.num_asq_entries = NSEVF_AQ_LEN;
	hw->mailboxq.arq_buf_size = NSEVF_MAX_AQ_BUF_SIZE;
	hw->mailboxq.asq_buf_size = NSEVF_MAX_AQ_BUF_SIZE;

	status = nsevf_init_mailboxq(hw);
	if (status) {
		dev_err(&pdev->dev, "Failed to init Admin Queue (%d)\n",
			status);
		goto err;
	}
	ret = nsevf_send_api_ver(adapter);
	if (ret) {
		dev_err(&pdev->dev, "Unable to send to PF (%d)\n", ret);
		nsevf_shutdown_mailboxq(hw);
		goto err;
	}
	nsevf_change_state(adapter, __NSEVF_INIT_VERSION_CHECK);
	return;
err:
	nsevf_change_state(adapter, __NSEVF_INIT_FAILED);
}

/**
 * nsevf_init_version_check - second step of driver startup
 * @adapter: board private structure
 *
 * Function process __NSEVF_INIT_VERSION_CHECK driver state.
 * When success the state is changed to __NSEVF_INIT_GET_RESOURCES
 * when fails the state is changed to __NSEVF_INIT_FAILED
 **/
static void nsevf_init_version_check(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;
	struct pci_dev *pdev = adapter->pdev;
	int ret;

	WARN_ON(adapter->state != __NSEVF_INIT_VERSION_CHECK);

	if (!nsevf_asq_done(hw, &hw->mailboxq, NULL)) {
		dev_err(&pdev->dev, "Admin queue command never completed\n");
		nsevf_shutdown_mailboxq(hw);
		nsevf_change_state(adapter, __NSEVF_STARTUP);
		goto err;
	}

	/* aq msg sent, awaiting reply */
	ret = nsevf_verify_api_ver(adapter);
	if (ret) {
		if (ret == -EALREADY)
			ret = nsevf_send_api_ver(adapter);
		else
			dev_err(&pdev->dev,
				"Unsupported PF API version %d.%d, expected %d.%d\n",
				adapter->pf_version.major,
				adapter->pf_version.minor,
				VIRTCHNL_VERSION_MAJOR, VIRTCHNL_VERSION_MINOR);
		goto err;
	}
	ret = nsevf_send_vf_config_msg(adapter);
	if (ret) {
		dev_err(&pdev->dev, "Unable to send config request (%d)\n",
			ret);
		goto err;
	}
	nsevf_change_state(adapter, __NSEVF_INIT_GET_RESOURCES);
	return;
err:
	nsevf_change_state(adapter, __NSEVF_INIT_FAILED);
}

/**
 * nsevf_parse_vf_resource_msg - parse response from VIRTCHNL_OP_GET_VF_RESOURCES
 * @adapter: board private structure
 */
int nsevf_parse_vf_resource_msg(struct nsevf_adapter *adapter)
{
	struct nsevf_vsi *vsi = &adapter->vsi;

	if (adapter->vf_res->vsi_res.vsi_type == VIRTCHNL_VSI_SRIOV) {
		adapter->vsi_res = &adapter->vf_res->vsi_res;
	} else {
		adapter->vsi_res = NULL;

		dev_err(&adapter->pdev->dev, "No LAN VSI found\n");
		return -ENODEV;
	}

	adapter->num_req_queues = 0;
	adapter->vsi.vsi_abs_id = adapter->vsi_res->vsi_abs_id;
	adapter->vsi.vsi_rel_id = adapter->vsi_res->vsi_rel_id;

	adapter->vsi.back = adapter;
	adapter->vsi.base_vector = NONQ_VECS;
	vsi->netdev = adapter->netdev;
	vsi->qs_handle = adapter->vsi_res->qset_handle;
	if (adapter->vf_res->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_RSS_PF) {
		adapter->rss_key_size = adapter->vf_res->rss_key_size;
		adapter->rss_lut_size = adapter->vf_res->rss_lut_size;
		adapter->rss_ctl_alg = adapter->vf_res->rss_ctl_alg;
		adapter->rss_hash_alg = adapter->vf_res->rss_hash_alg;
	} else {
		dev_err(&adapter->pdev->dev,
			"[%s, %d] MUST need PF driver give us VIRTCHNL_VF_OFFLOAD_RSS_PF\n",
			__func__, __LINE__);
		return -ENODEV;
	}

	return 0;
}

/**
 * nsevf_init_get_resources - third step of driver startup
 * @adapter: board private structure
 *
 * Function process __NSEVF_INIT_GET_RESOURCES driver state and
 * finishes driver initialization procedure.
 * When success the state is changed to __NSEVF_DOWN
 * when fails the state is changed to __NSEVF_INIT_FAILED
 **/
static void nsevf_init_get_resources(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;
	struct pci_dev *pdev = adapter->pdev;
	int ret;

	WARN_ON(adapter->state != __NSEVF_INIT_GET_RESOURCES);
	/* aq msg sent, awaiting reply */
	if (!adapter->vf_res) {
		adapter->vf_res = kzalloc(sizeof(*adapter->vf_res),
					  GFP_KERNEL);
		if (!adapter->vf_res)
			goto err;
	}
	ret = nsevf_get_vf_config(adapter);
	if (ret == -EALREADY) {
		ret = nsevf_send_vf_config_msg(adapter);
		goto err;
	} else if (ret == -EINVAL) {
		/* We only get -EINVAL if the device is in a very bad
		 * state or if we've been disabled for previous bad
		 * behavior. Either way, we're done now.
		 */
		nsevf_shutdown_mailboxq(hw);
		dev_err(&pdev->dev,
			"Unable to get VF config due to PF error condition, not retrying\n");
		return;
	}
	if (ret) {
		dev_err(&pdev->dev, "Unable to get VF config (%d)\n", ret);
		goto err_alloc;
	}

	ret = nsevf_parse_vf_resource_msg(adapter);
	if (ret) {
		dev_err(&pdev->dev,
			"Failed to parse VF resource message from PF (%d)\n",
			ret);
		goto err_alloc;
	}

	/* Some features require additional messages to negotiate extended
	 * capabilities. These are processed in sequence by the
	 * __NSEVF_INIT_EXTENDED_CAPS driver state.
	 */
	adapter->extended_caps = NSEVF_EXTENDED_CAPS;

	nsevf_change_state(adapter, __NSEVF_INIT_EXTENDED_CAPS);
	return;

err_alloc:
	kfree(adapter->vf_res);
	adapter->vf_res = NULL;
err:
	nsevf_change_state(adapter, __NSEVF_INIT_FAILED);
}

/**
 * nsevf_init_send_offload_vlan_v2_caps - part of initializing VLAN V2 caps
 * @adapter: board private structure
 *
 * Function processes send of the extended VLAN V2 capability message to the
 * PF. Must clear NSEVF_EXTENDED_CAP_RECV_VLAN_V2 if the message is not sent,
 * e.g. due to PF not negotiating VIRTCHNL_VF_OFFLOAD_VLAN_V2.
 */
static void nsevf_init_send_offload_vlan_v2_caps(struct nsevf_adapter *adapter)
{
	int ret;

	WARN_ON(!(adapter->extended_caps & NSEVF_EXTENDED_CAP_SEND_VLAN_V2));

	ret = nsevf_send_vf_offload_vlan_v2_msg(adapter);
	if (ret && ret == -EOPNOTSUPP) {
		/* PF does not support VIRTCHNL_VF_OFFLOAD_V2. In this case,
		 * we did not send the capability exchange message and do not
		 * expect a response.
		 */
		adapter->extended_caps &= ~NSEVF_EXTENDED_CAP_RECV_VLAN_V2;
	}

	/* We sent the message, so move on to the next step */
	adapter->extended_caps &= ~NSEVF_EXTENDED_CAP_SEND_VLAN_V2;
}

/**
 * nsevf_init_recv_offload_vlan_v2_caps - part of initializing VLAN V2 caps
 * @adapter: board private structure
 *
 * Function processes receipt of the extended VLAN V2 capability message from
 * the PF.
 **/
static void nsevf_init_recv_offload_vlan_v2_caps(struct nsevf_adapter *adapter)
{
	int ret;

	WARN_ON(!(adapter->extended_caps & NSEVF_EXTENDED_CAP_RECV_VLAN_V2));

	memset(&adapter->vlan_v2_caps, 0, sizeof(adapter->vlan_v2_caps));

	ret = nsevf_get_vf_vlan_v2_caps(adapter);
	if (ret)
		goto err;

	/* We've processed receipt of the VLAN V2 caps message */
	adapter->extended_caps &= ~NSEVF_EXTENDED_CAP_RECV_VLAN_V2;
	return;
err:
	/* We didn't receive a reply. Make sure we try sending again when
	 * __NSEVF_INIT_FAILED attempts to recover.
	 */
	adapter->extended_caps |= NSEVF_EXTENDED_CAP_SEND_VLAN_V2;
	nsevf_change_state(adapter, __NSEVF_INIT_FAILED);
}

/**
 * nsevf_init_send_supported_rxdids - part of querying for supported RXDID formats
 * @adapter: board private structure
 *
 * Function processes send of the request for supported RXDIDs to the PF.
 * Must clear NSEVF_EXTENDED_CAP_RECV_RXDID if the message is not sent, e.g.
 * due to the PF not negotiating VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC.
 */
static void nsevf_init_send_supported_rxdids(struct nsevf_adapter *adapter)
{
	int ret;

	WARN_ON(!(adapter->extended_caps & NSEVF_EXTENDED_CAP_SEND_RXDID));

	ret = nsevf_send_vf_supported_rxdids_msg(adapter);
	if (ret && ret == -EOPNOTSUPP) {
		/* PF does not support VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC. In this
		 * case, we did not send the capability exchange message and
		 * do not expect a response.
		 */
		adapter->extended_caps &= ~NSEVF_EXTENDED_CAP_RECV_RXDID;
	}

	/* We sent the message, so move on to the next step */
	adapter->extended_caps &= ~NSEVF_EXTENDED_CAP_SEND_RXDID;
}

/**
 * nsevf_init_recv_supported_rxdids - part of querying for supported RXDID formats
 * @adapter: board private structure
 *
 * Function processes receipt of the supported RXDIDs message from the PF.
 **/
static void nsevf_init_recv_supported_rxdids(struct nsevf_adapter *adapter)
{
	int ret;

	WARN_ON(!(adapter->extended_caps & NSEVF_EXTENDED_CAP_RECV_RXDID));

	memset(&adapter->supported_rxdids, 0,
	       sizeof(adapter->supported_rxdids));

	ret = nsevf_get_vf_supported_rxdids(adapter);
	if (ret)
		goto err;

	/* We've processed the PF response to the VIRTCHNL_OP_GET_SUPPORTED_RXDIDS
	 * message we sent previously.
	 */
	adapter->extended_caps &= ~NSEVF_EXTENDED_CAP_RECV_RXDID;
	return;
err:
	/* We didn't receive a reply. Make sure we try sending again when
	 * __NSEVF_INIT_FAILED attempts to recover.
	 */
	adapter->extended_caps |= NSEVF_EXTENDED_CAP_SEND_RXDID;
	nsevf_change_state(adapter, __NSEVF_INIT_FAILED);
}

/**
 * nsevf_init_process_extended_caps - Part of driver startup
 * @adapter: board private structure
 *
 * Function processes __NSEVF_INIT_EXTENDED_CAPS driver state. This state
 * handles negotiating capabilities for features which require an additional
 * message.
 *
 * Once all extended capabilities exchanges are finished, the driver will
 * transition into __NSEVF_INIT_CONFIG_ADAPTER.
 */
static void nsevf_init_process_extended_caps(struct nsevf_adapter *adapter)
{
	WARN_ON(adapter->state != __NSEVF_INIT_EXTENDED_CAPS);

	/* Process capability exchange for VLAN V2 */
	if (adapter->extended_caps & NSEVF_EXTENDED_CAP_SEND_VLAN_V2) {
		nsevf_init_send_offload_vlan_v2_caps(adapter);
		return;
	} else if (adapter->extended_caps & NSEVF_EXTENDED_CAP_RECV_VLAN_V2) {
		nsevf_init_recv_offload_vlan_v2_caps(adapter);
		return;
	}

	/* Process capability exchange for RXDID formats */
	if (adapter->extended_caps & NSEVF_EXTENDED_CAP_SEND_RXDID) {
		nsevf_init_send_supported_rxdids(adapter);
		return;
	} else if (adapter->extended_caps & NSEVF_EXTENDED_CAP_RECV_RXDID) {
		nsevf_init_recv_supported_rxdids(adapter);
		return;
	}

	/* When we reach here, no further extended capabilities exchanges are
	 * necessary, so we finally transition into __NSEVF_INIT_CONFIG_ADAPTER
	 */
	nsevf_change_state(adapter, __NSEVF_INIT_CONFIG_ADAPTER);
}

/**
 * nsevf_init_config_adapter - last part of driver startup
 * @adapter: board private structure
 *
 * After all the supported capabilities are negotiated, then the
 * __NSEVF_INIT_CONFIG_ADAPTER state will finish driver initialization.
 */
static void nsevf_init_config_adapter(struct nsevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	int ret;

	WARN_ON(adapter->state != __NSEVF_INIT_CONFIG_ADAPTER);

	nsevf_fdir_init(adapter);

	if (nsevf_process_config(adapter))
		goto err;

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	adapter->flags |= NSEVF_FLAG_RX_CSUM_ENABLED;

	netdev->netdev_ops = &nsevf_netdev_ops;
	nsevf_set_ethtool_ops(netdev);
	netdev->watchdog_timeo = 5 * HZ;

	/* MTU range: 68 - 9710 */
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = adapter->vf_res->max_mtu;

	if (!is_valid_ether_addr(adapter->hw.mac.addr)) {
		dev_info(&pdev->dev, "Invalid MAC address %pM, using random\n",
			 adapter->hw.mac.addr);
		eth_hw_addr_random(netdev);
		ether_addr_copy(adapter->hw.mac.addr, netdev->dev_addr);
	} else {
		eth_hw_addr_set(netdev, adapter->hw.mac.addr);
		ether_addr_copy(netdev->perm_addr, adapter->hw.mac.addr);
	}

	adapter->flags |= NSEVF_FLAG_INITIAL_MAC_SET;

	if (adapter->vf_res->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_WB_ON_ITR)
		adapter->flags |= NSEVF_FLAG_WB_ON_ITR_CAPABLE;

	if (adapter->vf_res->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_BYPASS_SWITCH)
		adapter->flags |= NSEVF_FLAG_BYPASS_SWITCH;

	adapter->tx_desc_count = NSEVF_DEFAULT_TXD;
	adapter->rx_desc_count = NSEVF_DEFAULT_RXD;
	adapter->txcq_desc_count = NSE_DFLT_NUM_CQ_DESC;

	ret = nsevf_init_interrupt_scheme(adapter);
	if (ret)
		goto err_sw_init;

	nsevf_map_rings_to_vectors(adapter);

	ret = nsevf_request_misc_irq(adapter);
	if (ret)
		goto err_sw_init;

	netif_carrier_off(netdev);
	adapter->link_up = false;

	if (!adapter->netdev_registered) {
		ret = register_netdev(netdev);
		if (ret)
			goto err_register;
	}

	adapter->netdev_registered = true;

	nsevf_idc_init(adapter);

	netif_tx_stop_all_queues(netdev);

	dev_info(&pdev->dev, "MAC address: %pM\n", adapter->hw.mac.addr);
	if (netdev->features & NETIF_F_GRO)
		dev_info(&pdev->dev, "GRO is enabled\n");

	nsevf_change_state(adapter, __NSEVF_DOWN);
	set_bit(__NSEVF_VSI_DOWN, adapter->vsi.state);

	nsevf_misc_irq_enable(adapter, true);
	wake_up(&adapter->down_waitqueue);

	adapter->rss_key = kzalloc(adapter->rss_key_size, GFP_KERNEL);
	adapter->rss_lut =
		kcalloc(adapter->rss_lut_size, sizeof(u16), GFP_KERNEL);
	if (!adapter->rss_key || !adapter->rss_lut)
		goto err_mem;

	(void)nsevf_init_rss(adapter, true);

	if (VLAN_V2_ALLOWED(adapter))
		/* request initial VLAN offload settings */
		nsevf_set_vlan_offload_features(adapter, 0, netdev->features);

	if (adapter->flags & NSEVF_FLAG_RESET_FAILED_DEV_UP)
		nsevf_change_state(adapter, __NSEVF_STATE_UP_AFTER_RESET);

	return;
err_mem:
	nsevf_free_rss(adapter);
err_register:
	nsevf_free_misc_irq(adapter);
err_sw_init:
	nsevf_reset_interrupt_capability(adapter);
err:
	nsevf_fdir_deinit(adapter, false);

	nsevf_change_state(adapter, __NSEVF_INIT_FAILED);
}

/**
 * nsevf_process_aq_command - process aq_required flags
 * and sends aq command
 * @adapter: pointer to nsevf adapter structure
 *
 * Returns 0 on success
 * Returns error code if no command was sent
 * or error code if the command failed.
 **/
static int nsevf_process_aq_command(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;

	if (adapter->aq_required)
		nsevf_debug(hw, NSEVF_DBG_AQM_MSG, "[%s] aq_required=%lX\n",
			    __func__, (unsigned long)adapter->aq_required);

	if (adapter->aq_required & NSEVF_FLAG_AQ_GET_CONFIG) //done
		return nsevf_send_vf_config_msg(adapter);
	if (adapter->aq_required &
	    NSEVF_FLAG_AQ_GET_OFFLOAD_VLAN_V2_CAPS) //done
		return nsevf_send_vf_offload_vlan_v2_msg(adapter);
	if (adapter->aq_required & NSEVF_FLAG_AQ_GET_SUPPORTED_RXDIDS) //done
		return nsevf_send_vf_supported_rxdids_msg(adapter);
	if (adapter->aq_required & NSEVF_FLAG_AQ_DISABLE_QUEUES) { //done
		nsevf_disable_queues(adapter);
		return 0;
	}
	if (adapter->aq_required & NSEVF_FLAG_AQ_MAP_VECTORS) { //done
		nsevf_map_queues(adapter);
		return 0;
	}
	if (adapter->aq_required & NSEVF_FLAG_AQ_ADD_MAC_FILTER) { //done
		nsevf_add_ether_addrs(adapter);
		return 0;
	}
	if (adapter->aq_required & NSEVF_FLAG_AQ_ADD_VLAN_FILTER) { //done
		nsevf_add_vlans(adapter);
		return 0;
	}
	if (adapter->aq_required & NSEVF_FLAG_AQ_DEL_MAC_FILTER) { //done
		nsevf_del_ether_addrs(adapter);
		return 0;
	}
	if (adapter->aq_required & NSEVF_FLAG_AQ_DEL_VLAN_FILTER) { //done
		nsevf_del_vlans(adapter);
		return 0;
	}

	if (adapter->aq_required & NSEVF_FLAG_AQ_SET_RSS_ALG) { //done
		nsevf_set_rss_alg(adapter);
		return 0;
	}
	if (adapter->aq_required & NSEVF_FLAG_AQ_SET_RSS_KEY) { //done
		nsevf_set_rss_key(adapter);
		return 0;
	}
	if (adapter->aq_required & NSEVF_FLAG_AQ_SET_RSS_LUT) { //done
		nsevf_set_rss_lut(adapter);
		return 0;
	}

	if (adapter->aq_required & NSEVF_FLAG_AQ_SET_FDIR_INPUT_MASK) { //done
		nsevf_set_fdir_input_mask(adapter);
		return 0;
	}

	if (adapter->aq_required & NSEVF_FLAG_AQ_CONFIGURE_QUEUES) { //done
		nsevf_configure_queues(adapter);
		return 0;
	}
	if (adapter->aq_required & NSEVF_FLAG_AQ_ENABLE_QUEUES) { //done
		nsevf_enable_queues(adapter);
		return 0;
	}

	if (adapter->aq_required &
	    NSEVF_FLAG_AQ_CONFIGURE_PROMISC_MODE) { //done
		nsevf_set_promiscuous(adapter);
		return 0;
	}

	if (adapter->aq_required &
	    NSEVF_FLAG_AQ_DISABLE_CTAG_VLAN_STRIPPING) { //done
		nsevf_disable_vlan_stripping_v2(adapter, ETH_P_8021Q);
		return 0;
	}
	if (adapter->aq_required &
	    NSEVF_FLAG_AQ_DISABLE_STAG_VLAN_STRIPPING) { //done
		nsevf_disable_vlan_stripping_v2(adapter, ETH_P_8021AD);
		return 0;
	}
	if (adapter->aq_required &
	    NSEVF_FLAG_AQ_ENABLE_CTAG_VLAN_STRIPPING) { //done
		nsevf_enable_vlan_stripping_v2(adapter, ETH_P_8021Q);
		return 0;
	}
	if (adapter->aq_required &
	    NSEVF_FLAG_AQ_ENABLE_STAG_VLAN_STRIPPING) { //done
		nsevf_enable_vlan_stripping_v2(adapter, ETH_P_8021AD);
		return 0;
	}
	if (adapter->aq_required &
	    NSEVF_FLAG_AQ_DISABLE_CTAG_VLAN_INSERTION) { //done
		nsevf_disable_vlan_insertion_v2(adapter, ETH_P_8021Q);
		return 0;
	}
	if (adapter->aq_required &
	    NSEVF_FLAG_AQ_DISABLE_STAG_VLAN_INSERTION) { //done
		nsevf_disable_vlan_insertion_v2(adapter, ETH_P_8021AD);
		return 0;
	}
	if (adapter->aq_required &
	    NSEVF_FLAG_AQ_ENABLE_CTAG_VLAN_INSERTION) { //done
		nsevf_enable_vlan_insertion_v2(adapter, ETH_P_8021Q);
		return 0;
	}
	if (adapter->aq_required &
	    NSEVF_FLAG_AQ_ENABLE_STAG_VLAN_INSERTION) { //done
		nsevf_enable_vlan_insertion_v2(adapter, ETH_P_8021AD);
		return 0;
	}
	if (adapter->aq_required & NSEVF_FLAG_AQ_MSG_QUEUE_PENDING) {
		nsevf_send_vc_msg(adapter);
		return 0;
	}

	/* since only one operation is processed at a time, always keep stats
	 * requests at the lowest priority so all other operations get processed
	 * first
	 */
	if (adapter->aq_required & NSEVF_FLAG_AQ_REQUEST_STATS) {
		nsevf_request_stats(adapter);
		return 0;
	}

	return -EAGAIN;
}

/**
 * nsevf_send_reset_request - prepare driver and send reset request
 * @adapter: pointer to nsevf_adapter
 *
 * During reset we need to shut down and reinitialize the admin queue
 * before we can use it to communicate with the PF again. We also clear
 * and reinit the rings because that context is lost as well.
 **/
static void nsevf_send_reset_request(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;

	nsevf_misc_irq_disable(adapter);
	adapter->flags &= ~NSEVF_FLAG_QUEUES_ENABLED;

	/* Restart the AQ here. If we have been reset but didn't
	 * detect it, or if the PF had to reinit, our AQ will be hosed.
	 */
	nsevf_shutdown_mailboxq(hw);
	nsevf_init_mailboxq(hw);

	nsevf_misc_irq_enable(adapter, true);

	if (!nsevf_request_reset(adapter))
		adapter->flags |= NSEVF_FLAG_RESET_PENDING;
}

/**
 * nsevf_set_flags_reset_detected - set flags for handling reset
 * @adapter: pointer to nsevf_adapter
 *
 * Set NSEVF_FLAG_RESET_DETECTED flag to handle
 * reset without sending reset request to PF in nsevf_watchdog_task() via
 * nsevf_send_reset_request().
 **/
static void nsevf_set_flags_reset_detected(struct nsevf_adapter *adapter)
{
	adapter->flags &= ~NSEVF_FLAG_QUEUES_ENABLED;
	adapter->flags |= NSEVF_FLAG_RESET_DETECTED;
}

/* forward-declare */
static void nsevf_disable_vf(struct nsevf_adapter *adapter);
static enum nsevf_status
nsevf_setup_vf(struct nsevf_adapter *adapter,
	       void (*cleanup)(struct nsevf_adapter *));

static void nsevf_polling_timer(struct timer_list *t)
{
	struct nsevf_adapter *adapter = from_timer(adapter, t, vf_polling_tmr);
	unsigned long next_event_offset = HZ / 1000;
	int q_idx;
	int budget;

	mod_timer(&adapter->vf_polling_tmr,
		  round_jiffies(next_event_offset + jiffies));

	if ((adapter->state == __NSEVF_RESETTING ||
	     adapter->state == __NSEVF_DOWN)) {
		return;
	}

	nsevf_for_each_q_vector(adapter, q_idx) {
		struct nsevf_q_vector *q_vector = &adapter->q_vectors[q_idx];

		if (!q_vector)
			return;

		do {
			budget = nsevf_polling(q_vector, 64);
			//printk("-----polling one time----\n");
		} while (budget == 64);
	}
}

/**
 * nsevf_watchdog_task - Periodic call-back task
 * @work: pointer to work_struct
 **/
static void nsevf_watchdog_task(struct work_struct *work)
{
	struct nsevf_adapter *adapter =
		container_of(work, struct nsevf_adapter, watchdog_task.work);
	struct nsevf_hw *hw = &adapter->hw;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	u32 reg_val;

	/* If the driver is in the process of being removed then don't run or
	 * reschedule the watchdog task.
	 */
	if (nsevf_is_remove_in_progress(adapter))
		return;

	if (adapter->flags & NSEVF_FLAG_UPDATE_NETDEV_FEATURES) {
		if (rtnl_trylock()) {
			netdev_update_features(adapter->netdev);
			rtnl_unlock();
			adapter->flags &= ~NSEVF_FLAG_UPDATE_NETDEV_FEATURES;
		}
	}

	if (test_and_set_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section))
		goto restart_watchdog;

	if (adapter->flags & NSEVF_FLAG_PF_COMMS_FAILED)
		nsevf_change_state(adapter, __NSEVF_COMM_FAILED);

	/* NSEVF_FLAG_RESET_NEEDED is set in nsevf_schedule_reset() */
	if (adapter->flags & NSEVF_FLAG_RESET_NEEDED &&
	    adapter->state != __NSEVF_RESETTING) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s, %d] RESET_NEEDED, change state to RESETTING\n",
			__func__, __LINE__);

		adapter->flags &= ~NSEVF_FLAG_RESET_NEEDED;
		nsevf_change_state(adapter, __NSEVF_RESETTING);
		adapter->aq_required = 0;
		adapter->current_op = VIRTCHNL_OP_UNKNOWN;
	}

	switch (adapter->state) {
	case __NSEVF_STARTUP: //done
		nsevf_startup(adapter);
		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);
		queue_delayed_work(adapter->wq, &adapter->watchdog_task,
				   msecs_to_jiffies(adapter->wq_mid_interval));
		return;
	case __NSEVF_INIT_VERSION_CHECK: //done
		nsevf_init_version_check(adapter);
		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);
		queue_delayed_work(adapter->wq, &adapter->watchdog_task,
				   msecs_to_jiffies(adapter->wq_mid_interval));
		return;
	case __NSEVF_INIT_GET_RESOURCES: //done
		nsevf_init_get_resources(adapter);
		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);
		queue_delayed_work(adapter->wq, &adapter->watchdog_task,
				   msecs_to_jiffies(adapter->wq_mid_interval));
		return;
	case __NSEVF_INIT_EXTENDED_CAPS: //done
		nsevf_init_process_extended_caps(adapter);
		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);
		queue_delayed_work(adapter->wq, &adapter->watchdog_task,
				   msecs_to_jiffies(adapter->wq_mid_interval));
		return;
	case __NSEVF_INIT_CONFIG_ADAPTER: //done
		nsevf_init_config_adapter(adapter);
		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);
		queue_delayed_work(adapter->wq, &adapter->watchdog_task,
				   msecs_to_jiffies(adapter->wq_low_interval));
		return;
	case __NSEVF_STATE_UP_AFTER_RESET: //done
		/* If reset failed and driver is reconfiguring adapter after
		 * it, then reenable the VF and attach device back.
		 */
		if (nsevf_setup_vf(adapter, nsevf_disable_vf)) {
			clear_bit(__NSEVF_IN_CRITICAL_TASK,
				  &adapter->crit_section);
			queue_delayed_work(adapter->wq, &adapter->watchdog_task,
					   msecs_to_jiffies(adapter->wq_low_interval));
			return;
		}
		/* nsevf_enable_adapter() will switch device back
		 * to __NSEVF_RUNNING
		 */
		nsevf_enable_adapter(adapter);
		netif_device_attach(adapter->netdev);
		adapter->flags &= ~NSEVF_FLAG_RESET_FAILED_DEV_UP;
		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);

		queue_delayed_work(adapter->wq, &adapter->watchdog_task,
				   msecs_to_jiffies(adapter->wq_low_interval));
		return;
	case __NSEVF_INIT_FAILED: //done
		/* If a reset was triggered during the initialization state
		 * machine, then we have no way to communicate with the PF.
		 * Instead of going into the last state and coming back to this
		 * state over and over again due to failed communication just
		 * force the __NSEVF_COMM_FAILED state to check if the reset has
		 * completed, which gets back to the __NSEVF_STARTUP state as
		 * quickly as possible.
		 */
		if (nsevf_is_reset(hw)) {
			dev_info(dev,
				 "adapter reset during state machine startup\n");
			adapter->flags |= NSEVF_FLAG_PF_COMMS_FAILED;
			nsevf_shutdown_mailboxq(hw);
			clear_bit(__NSEVF_IN_CRITICAL_TASK,
				  &adapter->crit_section);
			queue_delayed_work(adapter->wq, &adapter->watchdog_task,
					   (5 * HZ));
			return;
		}

		if (++adapter->aq_wait_count > NSEVF_AQ_MAX_ERR) {
			dev_err(dev,
				"Failed to communicate with PF; waiting before retry\n");
			adapter->flags |= NSEVF_FLAG_PF_COMMS_FAILED;
			nsevf_shutdown_mailboxq(hw);
			clear_bit(__NSEVF_IN_CRITICAL_TASK,
				  &adapter->crit_section);
			queue_delayed_work(adapter->wq, &adapter->watchdog_task,
					   (5 * HZ));
			return;
		}

		/* Try again from failed step */
		nsevf_change_state(adapter, adapter->last_state);
		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);
		queue_delayed_work(adapter->wq, &adapter->watchdog_task, HZ);
		return;
	case __NSEVF_COMM_FAILED: { //done
		unsigned int delay = adapter->wq_high_interval;

		reg_val = rd32(hw, NSEVF_REG_CTL);
		if (!(reg_val & NSEVF_REG_CTL_FRTRIG_STATUS_M)) {
			/* A chance for redemption! */
			dev_info(dev,
				 "Hardware came out of reset. Attempting reinit.\n");
			/* When init_task contacts the PF and
			 * gets everything set up again, it'll restart the
			 * watchdog for us. Down, boy. Sit. Stay. Woof.
			 */
			nsevf_change_state(adapter, __NSEVF_STARTUP);
			adapter->flags &= ~NSEVF_FLAG_PF_COMMS_FAILED;
			/* Get VF up and running ASAP */
			delay = 0;
		}
		adapter->aq_required = 0;
		adapter->current_op = VIRTCHNL_OP_UNKNOWN;
		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);
		queue_delayed_work(adapter->wq, &adapter->watchdog_task,
				   msecs_to_jiffies(delay));
		return;
	}
	case __NSEVF_RESETTING:

		if (adapter->netdev && adapter->netdev_registered) {
			netif_carrier_off(adapter->netdev);
			netif_tx_stop_all_queues(adapter->netdev);
			adapter->link_up = false;
		}

		/* Proceed with handling reset if NSEVF_FLAG_RESET_PENDING has
		 * been set in either nsevf_send_reset_request() or
		 * nsevf_set_flags_reset_detected().
		 */
		if (!(adapter->flags & NSEVF_FLAG_RESET_PENDING)) {
			nsevf_debug(hw, NSEVF_DBG_SYS,
				    "[%s] state = __RESETTING, block #1 handling, send vch-req(VFR) to PF driver\n",
				__func__);

			nsevf_send_reset_request(adapter);
		} else {
			nsevf_debug(hw, NSEVF_DBG_SYS,
				    "[%s] state = __RESETTING, block #2 handling, handle possible VF reset\n",
				__func__);

			nsevf_handle_hw_reset(adapter);
		}

		if (adapter->flags & NSEVF_FLAG_RESET_FAILED_DEV_UP) {
			/* detach device, since nothing will be set up on adapter
			 * after nsevf_disable_vf call. driver does not need to detach
			 * device, if it was not running before, since everything will
			 * be set up with ndo_open.
			 */
			netif_device_detach(adapter->netdev);
		}

		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);
		queue_delayed_work(adapter->wq, &adapter->watchdog_task,
				   msecs_to_jiffies(adapter->wq_low_interval));
		return;
	case __NSEVF_DOWN: //done
	case __NSEVF_DOWN_PENDING: //done
	case __NSEVF_TESTING: //done
	case __NSEVF_RUNNING: //done
		if (adapter->current_op) {
			if (!nsevf_asq_done(hw, &hw->mailboxq, NULL)) {
				dev_dbg(dev, "Admin queue timeout\n");
				nsevf_send_api_ver(adapter);
			}
		} else {
			int ret = nsevf_process_aq_command(adapter);

			/* An error will be returned if no commands were
			 * processed; use this opportunity to update stats
			 * if the error isn't -ENOTSUPP
			 */
			if (ret && ret != -EOPNOTSUPP &&
			    adapter->state == __NSEVF_RUNNING &&
			    time_after(jiffies,
				       adapter->hw_stats_last_update_time +
					       adapter->hw_stats_update_period))
				nsevf_request_stats(adapter);
		}
		if (adapter->state == __NSEVF_RUNNING)
			nsevf_detect_recover_hung(&adapter->vsi);

		break;
	case __NSEVF_REMOVE: //done
		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);
		return;
	default:
		break;
	}

	/* check for hw reset */
	if (nsevf_is_reset(hw)) {
		dev_err(dev,
			"[%s, %d] VF reset detected in state = %d (%s), last_state = %d (%s)\n",
			__func__, __LINE__, adapter->state,
			nsevf_state_str(adapter->state), adapter->last_state,
			nsevf_state_str(adapter->last_state));

		nsevf_set_flags_reset_detected(adapter);
		adapter->aq_required = 0;
		adapter->current_op = VIRTCHNL_OP_UNKNOWN;

		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);

		nsevf_schedule_reset(adapter, (NSEVF_FLAG_RESET_NEEDED |
					       NSEVF_FLAG_RESET_PENDING));

		return;
	}

	clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);
restart_watchdog:
	queue_work(adapter->wq, &adapter->adminq_task);

	if (adapter->aq_required)
		queue_delayed_work(adapter->wq, &adapter->watchdog_task,
				   msecs_to_jiffies(nsevf_wq_mid_interval));
	else
		queue_delayed_work(adapter->wq, &adapter->watchdog_task,
				   HZ * 2);
}

/**
 * nsevf_adminq_task - worker thread to clean the admin queue
 * @work: pointer to work_struct containing our data
 **/
static void nsevf_adminq_task(struct work_struct *work)
{
	struct nsevf_adapter *adapter =
		container_of(work, struct nsevf_adapter, adminq_task);
	struct nsevf_hw *hw = &adapter->hw;
	struct nsevf_arq_event_info event;
	enum virtchnl_status_code v_ret;
	enum virtchnl_ops v_op;
	enum nsevf_status ret;
	u32 val, oldval;
	u16 pending;
	struct nse_aqc_mbx_cmd_buff_hdr *v_hdr = NULL;

	/* If the driver is in the process of being removed then return
	 * immediately and don't re-enable the Admin Queue interrupt.
	 */
	if (nsevf_is_remove_in_progress(adapter))
		return;

	if (adapter->flags & NSEVF_FLAG_PF_COMMS_FAILED)
		goto out;

	event.buf_len = NSEVF_MAX_AQ_BUF_SIZE;
	event.msg_buf = kzalloc(event.buf_len, GFP_KERNEL);
	if (!event.msg_buf)
		goto out;

	do {
		pending = 0;

		ret = nsevf_clean_arq_element(hw, &hw->mailboxq, &event,
					      &pending);
		if (ret)
			break;

		if (event.msg_len < sizeof(struct nse_aqc_mbx_cmd_buff_hdr))
			continue;

		event.vch_msg_content =
			event.msg_buf + sizeof(struct nse_aqc_mbx_cmd_buff_hdr);
		event.vch_msg_len =
			event.msg_len - sizeof(struct nse_aqc_mbx_cmd_buff_hdr);

		v_hdr = (struct nse_aqc_mbx_cmd_buff_hdr *)event.msg_buf;

		v_op = (enum virtchnl_ops)le32_to_cpu(v_hdr->cookie_high);
		v_ret = (enum virtchnl_status_code)le32_to_cpu(v_hdr->cookie_low);

		if (ret || !v_op)
			break; /* No event to process or error cleaning ARQ */

		while (test_and_set_bit(__NSEVF_IN_CRITICAL_TASK,
					&adapter->crit_section))
			usleep_range(500, 1000);

		if (nsevf_is_reset_in_progress(adapter) ||
		    adapter->flags & NSEVF_FLAG_RESET_FAILED_DEV_UP) {
			clear_bit(__NSEVF_IN_CRITICAL_TASK,
				  &adapter->crit_section);
			goto freedom;
		}

		nsevf_virtchnl_completion(adapter, v_op, v_ret,
					  event.vch_msg_content,
					  event.vch_msg_len);

		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);

		if (pending != 0)
			memset(event.msg_buf, 0, NSEVF_MAX_AQ_BUF_SIZE);

	} while (pending);

	if ((adapter->flags &
	     (NSEVF_FLAG_RESET_PENDING | NSEVF_FLAG_RESET_NEEDED)) ||
	    adapter->state == __NSEVF_RESETTING)
		goto freedom;

	/* check for error indications */
	val = rd32(hw, hw->mailboxq.arq.len);

	/* device in reset */
	if (nsevf_is_regval_reset_magic(val))
		goto freedom;

	oldval = val;
	if (val & NSEVF_REG_MBX_ARQLEN_VFE_M) {
		dev_info(&adapter->pdev->dev, "ARQ VF Error detected\n");
		val &= ~NSEVF_REG_MBX_ARQLEN_VFE_M;
	}
	if (val & NSEVF_REG_MBX_ARQLEN_OVFL_M) {
		dev_info(&adapter->pdev->dev, "ARQ Overflow Error detected\n");
		val &= ~NSEVF_REG_MBX_ARQLEN_OVFL_M;
	}
	if (val & NSEVF_REG_MBX_ARQLEN_CRIT_M) {
		dev_info(&adapter->pdev->dev, "ARQ Critical Error detected\n");
		val &= ~NSEVF_REG_MBX_ARQLEN_CRIT_M;
	}
	if (oldval != val)
		wr32(hw, hw->mailboxq.arq.len, val);

	val = rd32(hw, hw->mailboxq.asq.len);
	oldval = val;
	if (val & NSEVF_REG_MBX_ATQLEN_VFE_M) {
		dev_info(&adapter->pdev->dev, "ASQ VF Error detected\n");
		val &= ~NSEVF_REG_MBX_ATQLEN_VFE_M;
	}
	if (val & NSEVF_REG_MBX_ATQLEN_OVFL_M) {
		dev_info(&adapter->pdev->dev, "ASQ Overflow Error detected\n");
		val &= ~NSEVF_REG_MBX_ATQLEN_OVFL_M;
	}
	if (val & NSEVF_REG_MBX_ATQLEN_CRIT_M) {
		dev_info(&adapter->pdev->dev, "ASQ Critical Error detected\n");
		val &= ~NSEVF_REG_MBX_ATQLEN_CRIT_M;
	}
	if (oldval != val)
		wr32(hw, hw->mailboxq.asq.len, val);

freedom:
	kfree(event.msg_buf);
out:
	/* re-enable Admin queue interrupt cause */
	nsevf_misc_irq_enable(adapter, false);
}

/* msgbox version of nsevf_adminq_task() */
static void nsevf_msgbox_task(struct work_struct *work)
{
	struct nsevf_adapter *adapter =
		container_of(work, struct nsevf_adapter, adminq_task);
	struct nsevf_hw *hw = &adapter->hw;
	struct nsevf_arq_event_info event;
	enum virtchnl_status_code v_ret;
	enum virtchnl_ops v_op;
	enum nsevf_status ret;
	u32 val;
	u16 pending;
	struct nse_aqc_mbx_cmd_buff_hdr *v_hdr = NULL;

	/* If the driver is in the process of being removed then return
	 * immediately and don't re-enable the Admin Queue interrupt.
	 */
	if (nsevf_is_remove_in_progress(adapter))
		return;

	if (adapter->flags & NSEVF_FLAG_PF_COMMS_FAILED)
		goto out;

	event.buf_len = NSEVF_MAX_AQ_BUF_SIZE;
	event.msg_buf = kzalloc(event.buf_len, GFP_KERNEL);
	if (!event.msg_buf)
		goto out;

	do {
		pending = 0;

		/* try see msgbox P2V if anything incomes */
		ret = nsevf_msgbox_p2v_clean_rx(hw, &event, &pending);
		if (ret)
			break;

		if (event.msg_len < sizeof(struct nse_aqc_mbx_cmd_buff_hdr))
			continue;

		event.vch_msg_content =
			event.msg_buf + sizeof(struct nse_aqc_mbx_cmd_buff_hdr);
		event.vch_msg_len =
			event.msg_len - sizeof(struct nse_aqc_mbx_cmd_buff_hdr);

		v_hdr = (struct nse_aqc_mbx_cmd_buff_hdr *)event.msg_buf;

		v_op = (enum virtchnl_ops)le32_to_cpu(v_hdr->cookie_high);
		v_ret = (enum virtchnl_status_code)le32_to_cpu(v_hdr->cookie_low);

		if (ret || !v_op)
			break; /* No event to process or error cleaning ARQ */

		while (test_and_set_bit(__NSEVF_IN_CRITICAL_TASK,
					&adapter->crit_section))
			usleep_range(500, 1000);

		if (nsevf_is_reset_in_progress(adapter) ||
		    adapter->flags & NSEVF_FLAG_RESET_FAILED_DEV_UP) {
			clear_bit(__NSEVF_IN_CRITICAL_TASK,
				  &adapter->crit_section);
			goto freedom;
		}

		nsevf_virtchnl_completion(adapter, v_op, v_ret,
					  event.vch_msg_content,
					  event.vch_msg_len);

		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);

		if (pending != 0)
			memset(event.msg_buf, 0, NSEVF_MAX_AQ_BUF_SIZE);

	} while (pending);

	if ((adapter->flags &
	     (NSEVF_FLAG_RESET_PENDING | NSEVF_FLAG_RESET_NEEDED)) ||
	    adapter->state == __NSEVF_RESETTING)
		goto freedom;

	/* check for error indications */
	val = rd32(hw, hw->mailboxq.arq.len);
	if (nsevf_is_regval_reset_magic(val) ||
	    nsevf_is_reset(hw)) /* device in reset */
		goto freedom;

freedom:
	kfree(event.msg_buf);
out:
	/* re-enable Admin queue interrupt cause */
	nsevf_misc_irq_enable(adapter, false);
}

/**
 * nsevf_free_all_tx_resources - Free Tx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all transmit software resources
 **/
void nsevf_free_all_tx_resources(struct nsevf_adapter *adapter)
{
	int i;

	if (!adapter->tx_rings)
		return;

	for (i = 0; i < adapter->num_active_queues; i++)
		if (adapter->tx_rings[i].desc)
			nsevf_free_tx_resources(&adapter->tx_rings[i]);
}

/**
 * nsevf_setup_all_tx_resources - allocate all queues Tx resources
 * @adapter: board private structure
 *
 * If this function returns with an error, then it's possible one or
 * more of the rings is populated (while the rest are not).  It is the
 * callers duty to clean those orphaned rings.
 *
 * Return 0 on success, negative on failure
 **/
int nsevf_setup_all_tx_resources(struct nsevf_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_active_queues; i++) {
		adapter->tx_rings[i].count = adapter->tx_desc_count;
		err = nsevf_setup_tx_descriptors(&adapter->tx_rings[i]);
		if (!err)
			continue;
		dev_err(&adapter->pdev->dev,
			"Allocation for Tx Queue %u failed\n", i);
		break;
	}

	return err;
}

/**
 * nsevf_setup_all_rx_resources - allocate all queues Rx resources
 * @adapter: board private structure
 *
 * If this function returns with an error, then it's possible one or
 * more of the rings is populated (while the rest are not).  It is the
 * callers duty to clean those orphaned rings.
 *
 * Return 0 on success, negative on failure
 **/
int nsevf_setup_all_rx_resources(struct nsevf_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_active_queues; i++) {
		adapter->rx_rings[i].count = adapter->rx_desc_count;
		err = nsevf_setup_rx_descriptors(&adapter->rx_rings[i]);
		if (!err)
			continue;
		dev_err(&adapter->pdev->dev,
			"Allocation for Rx Queue %u failed\n", i);
		break;
	}
	return err;
}

static int nsevf_setup_all_txcq_resources(struct nsevf_adapter *adapter)
{
	int i, err = 0;

	if (!adapter->sw_conf.lan_tx_use_cq)
		return 0;

	for (i = 0; i < adapter->vf_res->lan_txcq_num; i++) {
		adapter->txcq_rings[i].count = adapter->txcq_desc_count;
		err = nsevf_setup_txcq_descriptors(&adapter->txcq_rings[i]);
		if (!err)
			continue;
		dev_err(&adapter->pdev->dev,
			"Allocation for Rx Queue %u failed\n", i);
		break;
	}
	return err;
}

/**
 * nsevf_free_all_rx_resources - Free Rx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all receive software resources
 **/
void nsevf_free_all_rx_resources(struct nsevf_adapter *adapter)
{
	int i;

	if (!adapter->rx_rings)
		return;

	for (i = 0; i < adapter->num_active_queues; i++)
		if (adapter->rx_rings[i].desc)
			nsevf_free_rx_resources(&adapter->rx_rings[i]);
}

void nsevf_free_all_txcq_resources(struct nsevf_adapter *adapter)
{
	int i;

	if (!adapter->txcq_rings)
		return;

	for (i = 0; i < adapter->vf_res->lan_txcq_num; i++)
		if (adapter->txcq_rings[i].desc)
			nsevf_free_txcq_resources(&adapter->txcq_rings[i]);
}

/**
 * nsevf_disable_vf - disable a VF that failed to reset
 * @adapter: private adapter structure
 *
 * Helper function to shut down the VF when a reset never finishes.
 **/
void nsevf_disable_vf(struct nsevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct nsevf_mac_filter *f, *ftmp;
	struct nsevf_vlan_filter *fv, *fvtmp;

	adapter->flags |= NSEVF_FLAG_PF_COMMS_FAILED;

	/* We don't use netif_running() because it may be true prior to
	 * ndo_open() returning, so we can't assume it means all our open
	 * tasks have finished, since we're not holding the rtnl_lock here.
	 */
	if (!test_bit(__NSEVF_VSI_DOWN, adapter->vsi.state)) {
		set_bit(__NSEVF_VSI_DOWN, adapter->vsi.state);
		netif_carrier_off(netdev);
		netif_tx_disable(netdev);
		adapter->link_up = false;
		nsevf_irq_disable(adapter);
		//if (!nsevf_polling_mod)
		nsevf_napi_disable_all(adapter);
		nsevf_free_traffic_irqs(adapter);
		nsevf_free_all_tx_resources(adapter);
		nsevf_free_all_rx_resources(adapter);
		nsevf_free_all_txcq_resources(adapter);
	}

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	/* Delete all of the filters */
	list_for_each_entry_safe(f, ftmp, &adapter->mac_filter_list, list) {
		list_del(&f->list);
		kfree(f);
	}

	list_for_each_entry_safe(fv, fvtmp, &adapter->vlan_filter_list, list) {
		list_del(&fv->list);
		kfree(fv);
	}

	spin_unlock_bh(&adapter->mac_vlan_list_lock);

	nsevf_free_misc_irq(adapter);
	nsevf_reset_interrupt_capability(adapter);
	nsevf_free_q_vectors(adapter);
	nsevf_free_queues(adapter);
	memset(adapter->vf_res, 0, sizeof(struct virtchnl_vf_resource));
	nsevf_shutdown_mailboxq(&adapter->hw);
	adapter->flags &= ~NSEVF_FLAG_RESET_PENDING;
	nsevf_change_state(adapter, __NSEVF_DOWN);
	wake_up(&adapter->down_waitqueue);
}

/**
 * nsevf_setup_vf - setup VF resources
 * @adapter: private adapter structure
 * @cleanup: function to call, if error happened during setup
 *
 * Setup all VF resources required to run traffic
 **/
static enum nsevf_status nsevf_setup_vf(struct nsevf_adapter *adapter,
					void (*cleanup)(struct nsevf_adapter *))
{
	int err;

	/* allocate transmit descriptors */
	err = nsevf_setup_all_tx_resources(adapter);
	if (err)
		goto err_setup_tx;

	/* allocate receive descriptors */
	err = nsevf_setup_all_rx_resources(adapter);
	if (err)
		goto err_setup_rx;

	err = nsevf_setup_all_txcq_resources(adapter);
	if (err)
		goto err_setup_txcq;

	/* clear any pending interrupts, may auto mask */
	err = nsevf_request_traffic_irqs(adapter, adapter->netdev->name);
	if (err)
		goto err_req_irq;

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	nsevf_add_filter(adapter, adapter->hw.mac.addr);

	spin_unlock_bh(&adapter->mac_vlan_list_lock);

	/* Restore VLAN and Cloud filters that were removed with IFF_DOWN */
	nsevf_restore_filters(adapter);

	nsevf_configure(adapter);

	return 0;
err_req_irq:
	cleanup(adapter);
	nsevf_free_traffic_irqs(adapter);
err_setup_txcq:
	nsevf_free_all_txcq_resources(adapter);
err_setup_rx:
	nsevf_free_all_rx_resources(adapter);
err_setup_tx:
	nsevf_free_all_tx_resources(adapter);
	return NSEVF_ERR_CONFIG;
}

/**
 * nsevf_is_reset_detected - check if reset has been detected
 * @adapter: pointer to nsevf_adapter
 *
 * NSEVF_FLAG_RESET_DETECTED is set if a HW reset is detected in
 * nsevf_watchdog_task() and cleared here, else poll for reset.
 */
static bool nsevf_is_reset_detected(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;
	unsigned int i;
	unsigned int detect_timeout;
	bool ret = false;

	if (adapter->flags & NSEVF_FLAG_RESET_DETECTED) {
		adapter->flags &= ~NSEVF_FLAG_RESET_DETECTED;
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s] see FLAG_RESET_DETECTED is set\n", __func__);
		ret = true;
		goto out;
	}

	detect_timeout =
		(NSEVF_RESET_WAIT_DETECT_TIMEOUT_BASE * nse_timeout_scale);

	nsevf_debug(hw, NSEVF_DBG_SYS,
		    "[%s] check is_reset(), detect_timeout=%d\n", __func__,
		    detect_timeout);

	/* poll until we see the reset actually happen */
	for (i = 0; i < detect_timeout; i++) {
		if (nsevf_is_reset(hw)) {
			nsevf_debug(hw, NSEVF_DBG_SYS,
				    "[%s] is_reset() get TRUE, wait %d times\n",
				    __func__, i);
			ret = true;
			goto out;
		}

		msleep(NSEVF_RESET_WAIT_TICK);
	}

out:
	nsevf_debug(hw, NSEVF_DBG_SYS,
		    "[%s] %s detect VF reset at this round\n", __func__,
		    ret ? "We" : "We don't");

	return ret;
}

/**
 * nsevf_handle_hw_reset - Handle hardware reset
 * @adapter: pointer to nsevf_adapter
 *
 * During reset we need to shut down and reinitialize the admin queue
 * before we can use it to communicate with the PF again. We also clear
 * and reinit the rings because that context is lost as well.
 *
 * This function is called in the __IAVF_RESETTING driver state. If a reset
 * is detected and completes, the driver state changed to __IAVF_RUNNING or
 * __IAVF_DOWN, else driver state will remain in __IAVF_RESETTING.
 *
 * The function is called with the IAVF_FLAG_RESET_PENDING flag set and it is
 * cleared when a reset is detected and completes.
 **/
void nsevf_handle_hw_reset(struct nsevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct nsevf_hw *hw = &adapter->hw;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	enum nsevf_status status;
	int err;
	bool running;

	pci_set_master(adapter->pdev);

	if (!nsevf_is_reset_detected(adapter)) {
		/* Driver state remains __IAVF_RESETTING and flags are not
		 * cleared, so nsevf_watchdog_task() will call again.
		 */
		dev_info(dev,
			 "[%s, %d]: Never saw reset, goto watchdog_task next round\n",
			__func__, __LINE__);
		return;
	}

	/* wait until the reset is complete and the PF is responding to us */

	err = nsevf_check_reset_complete(hw, true, true);

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] pci_restore_msi_state()\n",
		    __func__, __LINE__);

	pci_restore_msi_state(adapter->pdev);

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] idc_deinit() - BEGIN\n",
		    __func__, __LINE__);

	nsevf_idc_deinit(adapter, 1);

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] idc_deinit() - DONE\n",
		    __func__, __LINE__);

	nsevf_fdir_deinit(adapter, true);

	if (err) {
		dev_err(dev, "[%s, %d] Reset never finished\n", __func__,
			__LINE__);
		nsevf_disable_vf(adapter);
		return;
	}

	nsevf_debug(hw, NSEVF_DBG_SYS,
		    "[%s, %d] VF driver SW-cleanup - BEGIN\n", __func__,
		    __LINE__);

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] \t SW-cleanup - irq_disable\n",
		    __func__, __LINE__);

	nsevf_misc_irq_disable(adapter);
	nsevf_irq_disable(adapter);

	/* We don't use netif_running() because it may be true prior to
	 * ndo_open() returning, so we can't assume it means all our open
	 * tasks have finished, since we're not holding the rtnl_lock here.
	 */
	running = (adapter->last_state == __NSEVF_RUNNING);

	if (running) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s, %d] \t SW-cleanup - running - carrier_off\n",
			    __func__, __LINE__);

		netif_carrier_off(netdev);

		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s, %d] \t SW-cleanup - running - tx_stop_all_queues\n",
			__func__, __LINE__);

		netif_tx_stop_all_queues(netdev);

		adapter->link_up = false;

		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s, %d] \t SW-cleanup - running - napi_disable_all\n",
			__func__, __LINE__);

		//		if (!nsevf_polling_mod)
		nsevf_napi_disable_all(adapter);
	}

	adapter->flags &= ~NSEVF_FLAG_RESET_PENDING;

	/* free the Tx/Rx rings and descriptors, might be better to just
	 * re-use them sometime in the future
	 */
	nsevf_free_all_rx_resources(adapter);
	nsevf_free_all_tx_resources(adapter);
	nsevf_free_all_txcq_resources(adapter);

	/* Set the queues_disabled flag when VF is going through reset
	 * to avoid a race condition especially for ADQ i.e. when a VF ADQ is
	 * configured, PF resets the VF to allocate ADQ resources. When this
	 * happens there's a possibility to hit a condition where VF is in
	 * running state but the queues haven't been enabled yet. So wait for
	 * virtchnl success message for enable queues and then unset this flag.
	 * Don't allow the link to come back up until that happens.
	 */
	adapter->flags |= NSEVF_FLAG_QUEUES_DISABLED;

	/* kill and reinit the admin queue */
	nsevf_shutdown_mailboxq(hw);

	nsevf_debug(hw, NSEVF_DBG_SYS,
		    "[%s, %d] VF driver SW-rebuild - BEGIN\n", __func__,
		    __LINE__);

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;
	status = nsevf_init_mailboxq(hw);
	if (status) {
		dev_info(dev, "[%s, %d] FAIL init_adminq: status=%d\n",
			 __func__, __LINE__, status);
		goto reset_err;
	}
	adapter->aq_required = 0;

	if ((adapter->flags & NSEVF_FLAG_REINIT_MSIX_NEEDED) ||
	    (adapter->flags & NSEVF_FLAG_REINIT_ITR_NEEDED)) {
		err = nsevf_reinit_interrupt_scheme(adapter);
		if (err) {
			dev_info(dev,
				 "[%s, %d] FAIL reinit_interrupt_scheme: err=%d\n",
				__func__, __LINE__, err);
			goto reset_err;
		}
	}

	err = nsevf_init_rss(adapter, false);
	if (err) {
		dev_info(dev, "[%s, %d] FAIL init_rss: err=%d\n", __func__,
			 __LINE__, err);
		goto reset_err;
	}

	adapter->aq_required |= NSEVF_FLAG_AQ_GET_CONFIG;
	adapter->aq_required |= NSEVF_FLAG_AQ_MAP_VECTORS;

	/* Certain capabilities require an extended negotiation process using
	 * extra messages that must be processed after getting the VF
	 * configuration. The related checks such as VLAN_V2_ALLOWED() are not
	 * reliable here, since the configuration has not yet been negotiated.
	 *
	 * Always set these flags, since them related VIRTCHNL messages won't
	 * be sent until after VIRTCHNL_OP_GET_VF_RESOURCES.
	 */
	adapter->aq_required |= NSEVF_FLAG_AQ_EXTENDED_CAPS;

	nsevf_misc_irq_enable(adapter, true);

	bitmap_clear(adapter->vsi.active_cvlans, 0, VLAN_N_VID);
	bitmap_clear(adapter->vsi.active_svlans, 0, VLAN_N_VID);

	/* We were running when the reset started, so we need to restore some
	 * state here.
	 */
	if (running) {
		/* allocate transmit descriptors */
		err = nsevf_setup_all_tx_resources(adapter);
		if (err)
			goto reset_err;

		/* allocate receive descriptors */
		err = nsevf_setup_all_rx_resources(adapter);
		if (err)
			goto reset_err;

		err = nsevf_setup_all_txcq_resources(adapter);
		if (err)
			goto reset_err;

		if ((adapter->flags & NSEVF_FLAG_REINIT_MSIX_NEEDED) ||
		    (adapter->flags & NSEVF_FLAG_REINIT_ITR_NEEDED)) {
			err = nsevf_request_traffic_irqs(adapter, netdev->name);
			if (err)
				goto reset_err;

			adapter->flags &= ~NSEVF_FLAG_REINIT_MSIX_NEEDED;
		}

		nsevf_configure(adapter);

		/* nsevf_up_complete() will switch device back
		 * to __NSEVF_RUNNING
		 */
		nsevf_up_complete(adapter);
	} else {
		nsevf_change_state(adapter, __NSEVF_DOWN);
		wake_up(&adapter->down_waitqueue);
		wake_up(&adapter->reset_waitqueue);
	}

	adapter->flags &= ~NSEVF_FLAG_REINIT_ITR_NEEDED;

	nsevf_idc_init(adapter);

	nsevf_fdir_rebuild(adapter);

	adapter->external_reset_type = 0;

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] VF driver SW-rebuild - DONE\n",
		    __func__, __LINE__);

	return;

reset_err:
	if (running) {
		set_bit(__NSEVF_VSI_DOWN, adapter->vsi.state);
		nsevf_free_traffic_irqs(adapter);
		adapter->flags |= NSEVF_FLAG_RESET_FAILED_DEV_UP;
	}
	nsevf_disable_vf(adapter);
	dev_info(dev, "[%s, %d] Reset task did not complete, VF disabled\n",
		 __func__, __LINE__);
	dev_err(dev, "[%s, %d] failed to allocate resources during reinit\n",
		__func__, __LINE__);
}

/**
 * nsevf_open - Called when a network interface is made active
 * @netdev: network interface device structure
 *
 * Returns 0 on success, negative value on failure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the watchdog is started,
 * and the stack is notified that the interface is ready.
 **/
static int nsevf_open(struct net_device *netdev)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	int err = 0;

	if (adapter->state == __NSEVF_RUNNING &&
	    !test_bit(__NSEVF_VSI_DOWN, adapter->vsi.state)) {
		dev_dbg(&adapter->pdev->dev, "VF is already open.\n");
		return err;
	}

	if (adapter->state != __NSEVF_DOWN) {
		err = -EBUSY;
		return err;
	}

	while (test_and_set_bit(__NSEVF_IN_CRITICAL_TASK,
				&adapter->crit_section))
		usleep_range(500, 1000);

	if (adapter->flags & NSEVF_FLAG_PF_COMMS_FAILED) {
		dev_err(&adapter->pdev->dev,
			"Unable to open device due to PF driver failure.\n");
		err = -EIO;
		goto unlock;
	}

	err = nsevf_setup_vf(adapter, nsevf_down);
	if (err)
		goto unlock;

	nsevf_up_complete(adapter);

	if (!nsevf_polling_mod)
		nsevf_irq_enable(adapter, true);

	clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);

	return 0;

unlock:
	clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);

	return err;
}

/**
 * nsevf_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the drivers control, but
 * needs to be disabled. All IRQs except vector 0 (reserved for admin queue)
 * are freed, along with all transmit and receive resources.
 **/
static int nsevf_close(struct net_device *netdev)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	unsigned int timeout;
	int status;

	while (test_and_set_bit(__NSEVF_IN_CRITICAL_TASK,
				&adapter->crit_section))
		usleep_range(500, 1000);

	if (adapter->state <= __NSEVF_DOWN_PENDING) {
		clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);
		return 0;
	}

	set_bit(__NSEVF_VSI_DOWN, adapter->vsi.state);

	nsevf_down(adapter);
	nsevf_change_state(adapter, __NSEVF_DOWN_PENDING);
	nsevf_free_traffic_irqs(adapter);

	clear_bit(__NSEVF_IN_CRITICAL_TASK, &adapter->crit_section);

	/* If we're closing the interface as part of driver removal then don't
	 * wait. The VF resources will be reinitialized when the hardware is
	 * reset.
	 */
	if (nsevf_is_remove_in_progress(adapter))
		return 0;

	/* We explicitly don't free resources here because the hardware is
	 * still active and can DMA into memory. Resources are cleared in
	 * nsevf_virtchnl_completion() after we get confirmation from the PF
	 * driver that the rings have been stopped.
	 *
	 * Also, we wait for state to transition to __NSEVF_DOWN before
	 * returning. State change occurs in nsevf_virtchnl_completion() after
	 * VF resources are released (which occurs after PF driver processes and
	 * responds to admin queue commands).
	 */

	timeout = (msecs_to_jiffies(500) * nse_timeout_scale);

	status = wait_event_timeout(adapter->down_waitqueue,
				    adapter->state == __NSEVF_DOWN, timeout);
	if (!status)
		netdev_info(netdev, "Device resources not yet released\n");
	return 0;
}

static u16 nsevf_select_queue(struct net_device *netdev, struct sk_buff *skb,
			      struct net_device *sb_dev)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	u16 dport;

	if (nsevf_lan_tx_select_q_dport && !sb_dev &&
	    adapter->num_active_queues > 1) {
		void *l4h = NULL, *l3h = NULL, *vh = NULL;
		u16 l3_proto;
		u8 l4_proto;
		struct iphdr *iph = NULL;
		struct ipv6hdr *ip6h = NULL;
		struct tcphdr *tcph = NULL;

		nsevf_locate_final_l3_l4_hdr(skb, &l4h, &l3h, &vh, &l3_proto,
					     &l4_proto);

		if (l3_proto == ETH_P_IP && l4h && l3h) {
			iph = (struct iphdr *)l3h;

			if (l4_proto == IPPROTO_TCP ||
			    l4_proto == IPPROTO_UDP) {
				tcph = (struct tcphdr *)l4h;
				dport = be16_to_cpu(tcph->dest);

				if (dport >= 10000) {
					dport -= 10000;
					return dport %
					       adapter->num_active_queues;
				} else {
					return dport %
					       adapter->num_active_queues;
				}
			} else if (l4_proto == IPPROTO_ICMP) {
				return iph->tos % adapter->num_active_queues;
			} else {
				return nsevf_lan_tx_select_q_default %
				       adapter->num_active_queues;
			}
		} else if (l3_proto == ETH_P_IPV6 && l4h && l3h) {
			ip6h = (struct ipv6hdr *)l3h;

			if (l4_proto == IPPROTO_TCP ||
			    l4_proto == IPPROTO_UDP) {
				tcph = (struct tcphdr *)l4h;
				dport = be16_to_cpu(tcph->dest);

				if (dport >= 10000) {
					dport -= 10000;
					return dport %
					       adapter->num_active_queues;
				} else {
					return dport %
					       adapter->num_active_queues;
				}
			} else if (l4_proto == IPPROTO_ICMPV6) {
				return ip6h->priority %
				       adapter->num_active_queues;
			} else {
				return nsevf_lan_tx_select_q_default %
				       adapter->num_active_queues;
			}
		} else {
			return nsevf_lan_tx_select_q_default %
			       adapter->num_active_queues;
		}
	}

	return netdev_pick_tx(netdev, skb, sb_dev);
}

/**
 * nsevf_get_stats - Get System Network Statistics
 * @netdev: network interface device structure
 *
 * Returns the address of the device statistics structure.
 * The statistics are actually updated from the watchdog task.
 **/
static struct net_device_stats *nsevf_get_stats(struct net_device *netdev)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	nsevf_update_sw_stats(adapter);

	nsevf_sync_net_stats(adapter);

	/* only return the current stats */
	return &adapter->net_stats;
}

/**
 * nsevf_change_mtu - Change the Maximum Transfer Unit
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 **/
static int nsevf_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	int max_frame = new_mtu + NSEVF_PACKET_HDR_PAD;
	int ret = 0;

	if (new_mtu < 68 || max_frame > NSEVF_MAX_RXBUFFER)
		return -EINVAL;

	netdev_info(netdev, "changing MTU from %d to %d\n", netdev->mtu,
		    new_mtu);
	netdev->mtu = new_mtu;

	nsevf_schedule_reset(adapter, NSEVF_FLAG_RESET_NEEDED);

	return ret;
}

#ifdef CONFIG_RFS_ACCEL
static int nsevf_rx_flow_steer(struct net_device *netdev,
			       const struct sk_buff *skb, u16 rxq_idx,
			       u32 flow_id)
{
	return -EOPNOTSUPP;
}
#endif

/**
 * nsevf_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 * @txqueue: stuck queue
 **/
static void nsevf_tx_timeout(struct net_device *netdev,
			     __always_unused unsigned int txqueue)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	adapter->tx_timeout_count++;
	nsevf_schedule_reset(adapter, NSEVF_FLAG_RESET_NEEDED);
}

#define NSEVF_NETDEV_VLAN_FEATURE_ALLOWED(requested, allowed, feature_bit) \
	(!(((requested) & (feature_bit)) && !((allowed) & (feature_bit))))

/**
 * nsevf_fix_netdev_vlan_features - fix NETDEV VLAN features based on support
 * @adapter: board private structure
 * @requested_features: stack requested NETDEV features
 **/
static netdev_features_t
nsevf_fix_netdev_vlan_features(struct nsevf_adapter *adapter,
			       netdev_features_t requested_features)
{
	netdev_features_t allowed_features;

	allowed_features = nsevf_get_netdev_vlan_hw_features(adapter) |
			   nsevf_get_netdev_vlan_features(adapter);

	if (!NSEVF_NETDEV_VLAN_FEATURE_ALLOWED(requested_features,
					       allowed_features,
					       NSEVF_NETIF_F_HW_VLAN_CTAG_TX))
		requested_features &= ~NSEVF_NETIF_F_HW_VLAN_CTAG_TX;

	if (!NSEVF_NETDEV_VLAN_FEATURE_ALLOWED(requested_features,
					       allowed_features,
					       NSEVF_NETIF_F_HW_VLAN_CTAG_RX))
		requested_features &= ~NSEVF_NETIF_F_HW_VLAN_CTAG_RX;

	if (!NSEVF_NETDEV_VLAN_FEATURE_ALLOWED(requested_features,
					       allowed_features,
					       NETIF_F_HW_VLAN_STAG_TX))
		requested_features &= ~NETIF_F_HW_VLAN_STAG_TX;
	if (!NSEVF_NETDEV_VLAN_FEATURE_ALLOWED(requested_features,
					       allowed_features,
					       NETIF_F_HW_VLAN_STAG_RX))
		requested_features &= ~NETIF_F_HW_VLAN_STAG_RX;

	if (!NSEVF_NETDEV_VLAN_FEATURE_ALLOWED(requested_features, allowed_features,
					       NSEVF_NETIF_F_HW_VLAN_CTAG_FILTER))
		requested_features &= ~NSEVF_NETIF_F_HW_VLAN_CTAG_FILTER;

	if (!NSEVF_NETDEV_VLAN_FEATURE_ALLOWED(requested_features,
					       allowed_features,
					       NETIF_F_HW_VLAN_STAG_FILTER))
		requested_features &= ~NETIF_F_HW_VLAN_STAG_FILTER;
	if ((requested_features &
	     (NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX)) &&
	    (requested_features &
	     (NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX)) &&
	    adapter->vlan_v2_caps.offloads.ethertype_match ==
		    VIRTCHNL_ETHERTYPE_STRIPPING_MATCHES_INSERTION) {
		netdev_warn(adapter->netdev,
			    "cannot support CTAG and STAG VLAN stripping and/or insertion simultaneously since CTAG and STAG offloads are mutually exclusive, clearing STAG offload settings\n");
		requested_features &=
			~(NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX);
	}

	return requested_features;
}

/**
 * nsevf_fix_strip_features - fix NETDEV strip features based on functionality
 * @adapter: board private structure
 * @requested_features: stack requested NETDEV features
 *
 * Returns fixed-up features bits
 **/
static netdev_features_t
nsevf_fix_strip_features(struct nsevf_adapter *adapter,
			 netdev_features_t requested_features)
{
	return requested_features;
}

/**
 * nsevf_fix_features - fix up the netdev feature bits
 * @netdev: our net device
 * @features: desired feature bits
 *
 * Returns fixed-up features bits
 **/
static netdev_features_t nsevf_fix_features(struct net_device *netdev,
					    netdev_features_t features)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);

	features = nsevf_fix_netdev_vlan_features(adapter, features);

	return nsevf_fix_strip_features(adapter, features);
}

#define NETIF_VLAN_OFFLOAD_FEATURES                          \
	(NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX | \
	 NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX)

/**
 * nsevf_set_features - set the netdev feature flags
 * @netdev: ptr to the netdev being adjusted
 * @features: the feature set that the stack is suggesting
 * Note: expects to be called while under rtnl_lock()
 **/
static int nsevf_set_features(struct net_device *netdev,
			      netdev_features_t features)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	struct device *dev = nsevf_adapter_to_dev(adapter);
	netdev_features_t changed;

	changed = features ^ netdev->features;

	/* trigger update on any VLAN feature change */
	if ((netdev->features & NETIF_VLAN_OFFLOAD_FEATURES) ^
	    (features & NETIF_VLAN_OFFLOAD_FEATURES))
		nsevf_set_vlan_offload_features(adapter, netdev->features,
						features);

	if (changed & NETIF_F_RXHASH) {
		if (features & NETIF_F_RXHASH) /* enable */
			nsevf_fill_rss_lut_dflt(adapter);
		else /* disable */
			nsevf_fill_rss_lut_all_zero(adapter);

		(void)nsevf_config_rss(adapter, NSEVF_CONFIG_RSS_FLAG_LUT);
	}

	if (changed & NETIF_F_NTUPLE) {
		if (features & NETIF_F_NTUPLE) {
			dev_info(dev, "NETIF_F_NTUPLE: off->on\n");
		} else {
			dev_info(dev, "NETIF_F_NTUPLE: on->off\n");
			nsevf_del_ethool_ntuple_all(adapter, false);
		}
	}

	if (changed & NETIF_F_LRO) {
		if (nsevf_lan_rx_ena_rsc) {
			if (features & NETIF_F_LRO)
				adapter->sw_conf.lan_rx_ena_rsc = 1;
			else
				adapter->sw_conf.lan_rx_ena_rsc = 0;

			nsevf_schedule_reset(adapter, NSEVF_FLAG_RESET_NEEDED);

			dev_info(nsevf_adapter_to_dev(adapter),
				 "Request change LRO at runtime, schedule VFR\n");
		}
	}

	return 0;
}

/**
 * nsevf_features_check - Validate encapsulated packet conforms to limits
 * @skb: skb buffer
 * @netdev: This port's netdev
 * @features: Offload features that the stack believes apply
 */
static netdev_features_t nsevf_features_check(struct sk_buff *skb,
					      struct net_device *netdev,
					      netdev_features_t features)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	bool gso = skb_is_gso(skb);
	size_t len;

	/* No point in doing any of this if neither checksum nor GSO are
	 * being requested for this frame. We can rule out both by just
	 * checking for CHECKSUM_PARTIAL
	 */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	/* refuse encap checksum and TSO */
	if (skb->encapsulation &&
	    !(adapter->vf_res->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_ENCAP))
		goto out_rm_features;

	/* We cannot support GSO if the MSS is going to be less than
	 * 64 bytes. If it is then we need to drop support for GSO.
	 */
	if (gso && (skb_shinfo(skb)->gso_size < NSE_TXD_CTX_MSS_MIN))
		features &= ~NETIF_F_GSO_MASK;

	/* We cannot support GSO if the MSS is too large,
	 * If it is then we need to drop support for GSO.
	 */
	if (gso && (skb_shinfo(skb)->gso_size > NSE_TXD_CTX_MSS_MAX))
		features &= ~NETIF_F_GSO_MASK;

	if (!(adapter->vf_res->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_LSO))
		features &= ~NETIF_F_GSO_MASK;

	len = skb_network_offset(skb);
	if (len > NSE_TXD_CTX_MACLEN_MAX_IN_BYTE || len & 0x1)
		goto out_rm_features;

	len = skb_network_header_len(skb);
	if (len > NSE_TXD_IPLEN_MAX_IN_BYTE || len & 0x3)
		goto out_rm_features;

	if (skb->encapsulation) {
		/* this must work for VXLAN frames AND IPIP/SIT frames, and in
		 * the case of IPIP frames, the transport header pointer is
		 * after the inner header! So check to make sure that this
		 * is a GRE or UDP_TUNNEL frame before doing that math.
		 */
		if (gso && (skb_shinfo(skb)->gso_type &
			    (SKB_GSO_GRE | SKB_GSO_UDP_TUNNEL))) {
			len = skb_inner_network_header(skb) -
			      skb_transport_header(skb);
			if (len > NSE_TXD_L4LEN_MAX_IN_BYTE || len & 0x1)
				goto out_rm_features;
		}

		len = skb_inner_network_header_len(skb);
		if (len > NSE_TXD_IPLEN_MAX_IN_BYTE || len & 0x3)
			goto out_rm_features;
	}

	return features;
out_rm_features:
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}

static const struct net_device_ops nsevf_netdev_ops = {
	.ndo_open = nsevf_open, //done
	.ndo_stop = nsevf_close, //done
	.ndo_start_xmit = nsevf_xmit_frame, //done
	.ndo_select_queue = nsevf_select_queue, //done
	.ndo_get_stats = nsevf_get_stats, //done
	.ndo_set_rx_mode = nsevf_set_rx_mode, //done
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_mac_address = nsevf_set_mac, //done
	.ndo_do_ioctl = NULL, //done
	.ndo_change_mtu = nsevf_change_mtu, //done
#ifdef CONFIG_RFS_ACCEL
	.ndo_rx_flow_steer = nsevf_rx_flow_steer,
#endif
	.ndo_tx_timeout = nsevf_tx_timeout, //done
	.ndo_vlan_rx_add_vid = nsevf_vlan_rx_add_vid, //done
	.ndo_vlan_rx_kill_vid = nsevf_vlan_rx_kill_vid, //done

	.ndo_features_check = nsevf_features_check, //done
	.ndo_fix_features = nsevf_fix_features, //done
	.ndo_set_features = nsevf_set_features, //done
};

/**
 * nsevf_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in nsevf_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * nsevf_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int nsevf_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct net_device *netdev = NULL;
	struct nsevf_adapter *adapter = NULL;
	struct nsevf_hw *hw = NULL;
	static unsigned int probed_id;
	int err;

	err = pci_enable_device(pdev);
	if (err)
		return err;

	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev, "DMA configuration failed: 0x%x\n",
				err);
			goto err_dma;
		}
	}

	err = pci_request_regions(pdev, nsevf_driver_name);
	if (err) {
		dev_err(&pdev->dev,
			"pci_request_regions failed 0x%x\n", err);
		goto err_pci_reg;
	}

	pci_set_master(pdev);

	netdev = alloc_etherdev_mq(sizeof(struct nsevf_adapter),
				   NSEVF_MAX_REQ_QUEUES);
	if (!netdev) {
		err = -ENOMEM;
		goto err_alloc_etherdev;
	}

	SET_NETDEV_DEV(netdev, &pdev->dev);

	pci_set_drvdata(pdev, netdev);
	adapter = netdev_priv(netdev);

	adapter->netdev = netdev;
	adapter->pdev = pdev;

	hw = &adapter->hw;
	hw->back = adapter;

	adapter->wq = alloc_ordered_workqueue("%s", 0, nsevf_driver_name);
	if (!adapter->wq) {
		err = -ENOMEM;
		goto err_alloc_wq;
	}

	adapter->probed_id = probed_id++;

	adapter->sw_conf.lan_rx_ena_rsc = nsevf_lan_rx_ena_rsc;

	adapter->debug_lan_no_xmit = nsevf_lan_no_xmit;

	adapter->wq_low_interval = (nsevf_wq_low_interval * nse_timeout_scale);
	adapter->wq_low_mid_interval =
		(nsevf_wq_low_mid_interval * nse_timeout_scale);
	adapter->wq_mid_interval = (nsevf_wq_mid_interval * nse_timeout_scale);
	adapter->wq_mid_high_interval =
		(nsevf_wq_mid_high_interval * nse_timeout_scale);
	adapter->wq_high_interval =
		(nsevf_wq_high_interval * nse_timeout_scale);

	adapter->hw_stats_update_period = (3600 * HZ);

	adapter->msg_enable = (1 << DEFAULT_DEBUG_LEVEL_SHIFT) - 1;

	if (debug < -1)
		hw->debug_mask = debug;

	if (nse_conf_verbose)
		hw->debug_mask |=
			(NSEVF_DBG_SYS | NSEVF_DBG_LAN | NSEVF_DBG_AQM_MSG |
			 NSEVF_DBG_RCF | NSEVF_DBG_SW | NSEVF_DBG_RDMA |
			 NSEVF_DBG_LMAC_PHY);

	if (nse_aq_verbose)
		hw->debug_mask |= NSEVF_DBG_AQM_MSG;

	mutex_init(&adapter->misc_mutex);
	adapter->in_os_reset = false;
	adapter->napi_enabled = false;
	adapter->sw_shutdown_mq_imm = false;

	nsevf_change_state(adapter, __NSEVF_STARTUP);

	/* Call save state here because it relies on the adapter struct. */
	pci_save_state(pdev);

	err = nsevf_msgbox_init(adapter);
	if (err)
		goto err_msgbox_init;

	hw->hw_addr =
		ioremap(pci_resource_start(pdev, 0), pci_resource_len(pdev, 0));
	if (!hw->hw_addr) {
		err = -EIO;
		goto err_ioremap;
	}
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);
	hw->subsystem_vendor_id = pdev->subsystem_vendor;
	hw->subsystem_device_id = pdev->subsystem_device;
	hw->bus.device = PCI_SLOT(pdev->devfn);
	hw->bus.func = PCI_FUNC(pdev->devfn);
	hw->bus.bus_id = pdev->bus->number;

	nsevf_set_vf_virtio_mode(hw, false);

	/* set up the spinlocks for the AQ, do this only once in probe
	 * and destroy them only once in remove
	 */
	nsevf_init_spinlock_d(&hw->mailboxq.asq_spinlock);
	nsevf_init_spinlock_d(&hw->mailboxq.arq_spinlock);

	spin_lock_init(&adapter->mac_vlan_list_lock);
	spin_lock_init(&adapter->current_netdev_promisc_flags_lock);
	mutex_init(&adapter->vc_msg_queue.lock);

	INIT_LIST_HEAD(&adapter->mac_filter_list);
	INIT_LIST_HEAD(&adapter->vlan_filter_list);
	INIT_LIST_HEAD(&adapter->vc_msg_queue.msgs);

	init_waitqueue_head(&adapter->rdma.vc_op_waitqueue);
	INIT_DELAYED_WORK(&adapter->rdma.init_task, nsevf_idc_init_task);
	adapter->rdma.back = adapter;

	/* Setup the wait queue for indicating transition to down status */
	init_waitqueue_head(&adapter->down_waitqueue);

	/* Setup the wait queue for indicating transition to running state */
	init_waitqueue_head(&adapter->reset_waitqueue);

	/* Setup the wait queue for indicating virtchannel events */
	init_waitqueue_head(&adapter->vc_waitqueue);

	nsevf_fdir_pre_init(adapter);

	nsevf_debugfs_vf_init(adapter);

	hw->aq_cmd_background_task_cmd_type = 0;
	INIT_WORK(&hw->aq_cmd_background_task, nsevf_aq_cmd_background_task);

	if (nsevf_use_msgbox)
		INIT_WORK(&adapter->adminq_task, nsevf_msgbox_task);
	else
		INIT_WORK(&adapter->adminq_task, nsevf_adminq_task);

	nsevf_debug(hw, NSEVF_DBG_SYS,
		    "[%s] DONE, schedule watchdog_task(state=__NSEVF_STARTUP) for further init\n",
		__func__);

	INIT_DELAYED_WORK(&adapter->watchdog_task, nsevf_watchdog_task);
	queue_delayed_work(adapter->wq, &adapter->watchdog_task,
			   msecs_to_jiffies(5 * (pdev->devfn & 0x07)));

	if (nsevf_polling_mod)
		timer_setup(&adapter->vf_polling_tmr, nsevf_polling_timer, 0);

	return 0;

err_ioremap:
	nsevf_msgbox_exit(adapter);
err_msgbox_init:
	destroy_workqueue(adapter->wq);
err_alloc_wq:
	free_netdev(netdev);
err_alloc_etherdev:
	pci_release_regions(pdev);
err_pci_reg:
err_dma:
	pci_disable_device(pdev);
	return err;
}

#ifdef CONFIG_PM
/**
 * nsevf_suspend_adapter - Suspends the adapter
 * @adapter: nsevf adapter struct
 *
 * Implements the suspend of nsevf adapter.
 **/
static void nsevf_suspend_adapter(struct nsevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	rtnl_lock();
	netif_device_detach(netdev);

	if (netif_running(netdev)) {
		nsevf_close(netdev);

		adapter->flags |= NSEVF_FLAG_SUSPEND_RUNNING;
	}

	rtnl_unlock();
	nsevf_free_misc_irq(adapter);
	nsevf_reset_interrupt_capability(adapter);
}

/**
 * nsevf_resume_adapter - Resumes the adapter
 * @adapter: nsevf adapter struct
 *
 * Implements the resume of nsevf adapter.
 **/
static int nsevf_resume_adapter(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;
	u32 err;

	/* If we were suspended in running state it means
	 * the adapter should be in down state so we can
	 * open it here. If it is not in down state that means
	 * it is being reset and we have to wait for the reset to finish.
	 */
	while (adapter->flags & NSEVF_FLAG_SUSPEND_RUNNING &&
	       adapter->state != __NSEVF_RUNNING &&
	       adapter->state != __NSEVF_DOWN)
		usleep_range(50, 100);

	nsevf_set_vf_virtio_mode(hw, false);

	rtnl_lock();
	err = nsevf_set_interrupt_capability(adapter);
	if (err) {
		rtnl_unlock();
		dev_err(&adapter->pdev->dev,
			"Cannot enable MSI-X interrupts.\n");
		return err;
	}

	err = nsevf_request_misc_irq(adapter);
	if (err) {
		rtnl_unlock();
		dev_err(&adapter->pdev->dev, "Cannot get interrupt vector.\n");
		return err;
	}

	if (adapter->flags & NSEVF_FLAG_SUSPEND_RUNNING) {
		err = nsevf_open(adapter->netdev);

		adapter->flags &= ~NSEVF_FLAG_SUSPEND_RUNNING;
	}

	netif_device_attach(adapter->netdev);
	rtnl_unlock();

	return err;
}

/**
 * nsevf_suspend - Power management suspend routine
 * @dev_d: device information struct
 *
 * Called when the system (VM) is entering sleep/suspend.
 **/
static int nsevf_suspend(struct device *dev_d)
{
	struct net_device *netdev = (struct net_device *)dev_get_drvdata(dev_d);

	nsevf_suspend_adapter(netdev_priv(netdev));

	return 0;
}

/**
 * nsevf_resume - Power management resume routine
 * @dev_d: device information struct
 *
 * Called when the system (VM) is resumed from sleep/suspend.
 **/
static int nsevf_resume(struct device *dev_d)
{
	struct pci_dev *pdev = to_pci_dev(dev_d);

	pci_set_master(pdev);

	return nsevf_resume_adapter(nsevf_pdev_to_adapter(pdev));
}

#endif /* CONFIG_PM */

/**
 * nsevf_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * nsevf_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 **/
static void nsevf_remove(struct pci_dev *pdev)
{
	struct nsevf_adapter *adapter = nsevf_pdev_to_adapter(pdev);
	enum nsevf_state_t prev_state = adapter->last_state;
	struct net_device *netdev = adapter->netdev;
	struct nsevf_vlan_filter *vlf, *vlftmp;
	struct nsevf_mac_filter *f, *ftmp;
	struct nsevf_hw *hw = &adapter->hw;
	int ret;

	/* Don't proceed with remove if netdev is already freed */
	if (!netdev)
		return;

	/* Indicate we are in remove and not to run/schedule any driver tasks */
	if (test_and_set_bit(__NSEVF_IN_REMOVE_TASK, &adapter->crit_section))
		return;

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s] Removing device\n", __func__);

	nsevf_debugfs_vf_exit(adapter);

	cancel_work_sync(&hw->aq_cmd_background_task);

	cancel_work_sync(&adapter->adminq_task);
	cancel_delayed_work_sync(&adapter->watchdog_task);

	nsevf_misc_irq_disable(adapter);

	nsevf_fdir_deinit(adapter, false);

	nsevf_debug(hw, NSEVF_DBG_RDMA, "[%s, %d] idc_deinit() - BEGIN\n",
		    __func__, __LINE__);

	nsevf_idc_deinit(adapter, 0);

	nsevf_debug(hw, NSEVF_DBG_RDMA, "[%s, %d] idc_deinit() - DONE\n",
		    __func__, __LINE__);

	if (adapter->netdev_registered) {
		nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] unreg_netdev()\n",
			    __func__, __LINE__);

		/* This will call nsevf_close if the device was open previously.
		 * The Admin Queue and watchdog tasks have already been shut
		 * down at this point so the driver will rely on
		 * nsevf_request_reset below to disable the queues and handle
		 * any other Admin Queue-based cleanup normally done as part of
		 * nsevf_close.
		 */
		unregister_netdev(netdev);
		adapter->netdev_registered = false;
	}

	/* Shut down all the garbage mashers on the detention level */
	nsevf_change_state(adapter, __NSEVF_REMOVE);
	adapter->aq_required = 0;
	adapter->flags &= ~NSEVF_FLAG_REINIT_ITR_NEEDED;

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] request_reset()\n", __func__,
		    __LINE__);

	(void)nsevf_request_reset(adapter);
	msleep(100);
	/* If the FW isn't responding, kick it once, but only once. */
	if (!nsevf_asq_done(hw, &hw->mailboxq, NULL)) {
		(void)nsevf_request_reset(adapter);
		msleep(100);
	}

	ret = nsevf_check_reset_complete(hw, false, true);
	if (ret) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s, %d] PF driver not respond to our request_reset() in time, have to trigger ourself\n",
			__func__, __LINE__);

		nsevf_force_reset_trig(hw);
	}

	nsevf_misc_irq_disable(adapter);

	/* no bother stop them again, like 4.11.1 */
	cancel_delayed_work_sync(&adapter->watchdog_task);
	cancel_work_sync(&adapter->adminq_task);

	nsevf_debug(hw, NSEVF_DBG_SYS,
		    "[%s, %d] about to free LAN-Q TX/RX resources\n", __func__,
		    __LINE__);

	nsevf_free_all_tx_resources(adapter);
	nsevf_free_all_rx_resources(adapter);
	nsevf_free_all_txcq_resources(adapter);

	nsevf_free_misc_irq(adapter);

	/* In case we enter nsevf_remove from erroneous state, free traffic irqs
	 * here, so as to not cause a kernel crash, when calling
	 * nsevf_reset_interrupt_capability.
	 */
	if ((adapter->last_state == __NSEVF_RESETTING &&
	     prev_state != __NSEVF_DOWN) ||
	    (adapter->last_state == __NSEVF_RUNNING &&
	     !(netdev->flags & IFF_UP)))
		nsevf_free_traffic_irqs(adapter);

	nsevf_reset_interrupt_capability(adapter);
	nsevf_free_q_vectors(adapter);
	nsevf_free_rss(adapter);

	if (hw->mailboxq.asq.count)
		nsevf_shutdown_mailboxq(hw);

	/* destroy the locks only once, here */
	nsevf_destroy_spinlock_d(&hw->mailboxq.arq_spinlock);
	nsevf_destroy_spinlock_d(&hw->mailboxq.asq_spinlock);
	mutex_destroy(&adapter->vc_msg_queue.lock);

	iounmap(hw->hw_addr);
	pci_release_regions(pdev);

	nsevf_free_queues(adapter);
	kfree(adapter->vf_res);
	adapter->vf_res = NULL;

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	/* If we got removed before an up/down sequence, we've got a filter
	 * hanging out there that we need to get rid of.
	 */
	list_for_each_entry_safe(f, ftmp, &adapter->mac_filter_list, list) {
		list_del(&f->list);
		kfree(f);
	}
	list_for_each_entry_safe(vlf, vlftmp, &adapter->vlan_filter_list,
				 list) {
		list_del(&vlf->list);
		kfree(vlf);
	}

	spin_unlock_bh(&adapter->mac_vlan_list_lock);

	nsevf_msgbox_exit(adapter);

	mutex_destroy(&adapter->misc_mutex);

	destroy_workqueue(adapter->wq);

	pci_set_drvdata(pdev, NULL);

	free_netdev(netdev);

	pci_disable_device(pdev);

	dev_info(&pdev->dev, "[%s] DONE remove\n", __func__);
}

/**
 * nsevf_shutdown - Shutdown the device in preparation for a reboot
 * @pdev: pci device structure
 **/
static void nsevf_shutdown(struct pci_dev *pdev)
{
	nsevf_remove(pdev);

	if (system_state == SYSTEM_POWER_OFF)
		pci_set_power_state(pdev, PCI_D3hot);
}

#if defined(CONFIG_PM) && !defined(USE_LEGACY_PM_SUPPORT)
static SIMPLE_DEV_PM_OPS(nsevf_pm_ops, nsevf_suspend, nsevf_resume);
#endif /* CONFIG_PM && !USE_LEGACY_PM_SUPPORT && !NSEVF_TDD */

static void nsevf_pci_err_reset_prepare(struct pci_dev *pdev)
{
	struct nsevf_adapter *adapter = nsevf_pdev_to_adapter(pdev);
	struct nsevf_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	unsigned int wait_timeout;
	int req_rst_rdma_fail = 0;
	bool running;

	mutex_lock(&adapter->misc_mutex);
	adapter->about_os_reset = true;
	mutex_unlock(&adapter->misc_mutex);

	if (RDMA_ALLOWED(adapter)) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s, %d] do a VF-RDMA cleanup\n", __func__,
			    __LINE__);

		req_rst_rdma_fail = nsevf_request_reset_rdma(adapter);

		nsevf_debug(hw, NSEVF_DBG_RDMA,
			    "[%s, %d] request_reset_rdma() returns %d\n",
			    __func__, __LINE__, req_rst_rdma_fail);

		if (!req_rst_rdma_fail) {
			wait_timeout = (NSEVF_RESET_WAIT_DETECT_TIMEOUT_BASE *
					nse_timeout_scale);

			nsevf_debug(hw, NSEVF_DBG_RDMA,
				    "[%s, %d] wait(%d) for a while\n", __func__,
				    __LINE__, wait_timeout);

			msleep(wait_timeout);
		}
	}

	mutex_lock(&adapter->misc_mutex);
	adapter->in_os_reset = true;
	adapter->sw_shutdown_mq_imm = true;
	mutex_unlock(&adapter->misc_mutex);

	/* doing some pre-work in nsevf_handle_hw_reset(), but not too much
	 *
	 * util:
	 *		nsevf_free_all_rx_resources(adapter)
	 *		nsevf_free_all_tx_resources(adapter)
	 *
	 *		nsevf_shutdown_mailboxq(hw);
	 *
	 * that is, not free any DMA resources.
	 */

	nsevf_misc_irq_disable(adapter);
	nsevf_irq_disable(adapter);

	running = (adapter->state == __NSEVF_RUNNING);

	if (running) {
		netif_carrier_off(netdev);
		netif_tx_stop_all_queues(netdev);
		adapter->link_up = false;
		//	if (!nsevf_polling_mod)
		nsevf_napi_disable_all(adapter);
	}

	cancel_delayed_work_sync(&adapter->watchdog_task);

	mdelay((100 * nse_timeout_scale));

	//	pci_clear_master(pdev);
}

static void nsevf_pci_err_reset_done(struct pci_dev *pdev)
{
	struct nsevf_adapter *adapter = nsevf_pdev_to_adapter(pdev);

	mutex_lock(&adapter->misc_mutex);
	adapter->about_os_reset = false;
	adapter->in_os_reset = false;
	mutex_unlock(&adapter->misc_mutex);

	mdelay((100 * nse_timeout_scale));

	//	pci_set_master(pdev);

	/* just like receive and handle vch-event: VIRTCHNL_EVENT_RESET_IMPENDING */
	nsevf_schedule_reset(adapter, (NSEVF_FLAG_RESET_NEEDED |
				       NSEVF_FLAG_RESET_PENDING));
}

static pci_ers_result_t nsevf_pci_err_detected(struct pci_dev *pdev,
					       pci_channel_state_t err)
{
	struct nsevf_adapter *adapter = nsevf_pdev_to_adapter(pdev);
	struct nsevf_hw *hw = &adapter->hw;

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s] - enter: pci_channel_state=%d\n",
		    __func__, (unsigned int)err);

	nsevf_pci_err_reset_prepare(pdev);

	return PCI_ERS_RESULT_NEED_RESET;
}

static pci_ers_result_t nsevf_pci_err_slot_reset(struct pci_dev *pdev)
{
	struct nsevf_adapter *adapter = nsevf_pdev_to_adapter(pdev);
	struct nsevf_hw *hw = &adapter->hw;
	int err;
	pci_ers_result_t result;

	err = pci_enable_device_mem(pdev);
	if (err) {
		dev_err(&pdev->dev,
			"[%s] Cannot re-enable PCI device after reset\n",
			__func__);
		result = PCI_ERS_RESULT_DISCONNECT;
	} else {
		pci_set_master(pdev);
		pci_restore_state(pdev);
		pci_save_state(pdev);
		pci_wake_from_d3(pdev, false);

		result = PCI_ERS_RESULT_RECOVERED;
	}

	err = pci_aer_clear_nonfatal_status(pdev);
	if (err)
		dev_info(&pdev->dev, "fail: pci_aer_clear_nonfatal_status()\n");

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s] - exit: result=%d\n", __func__,
		    (unsigned int)result);

	return result;
}

static void nsevf_pci_err_resume(struct pci_dev *pdev)
{
	nsevf_pci_err_reset_done(pdev);
}

static const struct pci_error_handlers nsevf_pci_err_handler = {
	.reset_prepare = nsevf_pci_err_reset_prepare,
	.reset_done = nsevf_pci_err_reset_done,
	.error_detected = nsevf_pci_err_detected,
	.slot_reset = nsevf_pci_err_slot_reset,
	.resume = nsevf_pci_err_resume
};

static struct pci_driver nsevf_driver = {
	.name = nsevf_driver_name,
	.id_table = nsevf_pci_tbl,
	.probe = nsevf_probe,
	.remove = nsevf_remove,
#ifdef CONFIG_PM
	.driver.pm = &nsevf_pm_ops,
#endif /* CONFIG_PM */
	.shutdown = nsevf_shutdown,
	.err_handler = &nsevf_pci_err_handler,
};

static void nsevf_module_params_fix(void)
{
#ifndef CONFIG_X86
	nse_lan_tx_no_bql = 1;
#endif

	if (!nse_timeout_scale)
		nse_timeout_scale = 1;
}

/**
 * nsevf_init_module - Driver Registration Routine
 *
 * nsevf_init_module is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 **/
static int __init nsevf_init_module(void)
{
	int ret;

	pr_info("nsevf: %s - version %s\n", nsevf_driver_string,
		nsevf_driver_version);

	pr_info("%s\n", nsevf_copyright);

	nsevf_module_params_fix();

	nsevf_debugfs_init();

	ret = pci_register_driver(&nsevf_driver);
	if (ret) {
		pr_err("%s: Failed to register PCI driver, err %d\n",
		       nsevf_driver_name, ret);

		nsevf_debugfs_exit();
	}

	if (nsevf_use_msgbox) {
		nsevf_wq_low_mid_interval = 2;
		nsevf_wq_mid_interval = 3;
	}

	return ret;
}

module_init(nsevf_init_module);

/**
 * nsevf_exit_module - Driver Exit Cleanup Routine
 *
 * nsevf_exit_module is called just before the driver is removed
 * from memory.
 **/
static void __exit nsevf_exit_module(void)
{
	pci_unregister_driver(&nsevf_driver);

	nsevf_debugfs_exit();
}

module_exit(nsevf_exit_module);
