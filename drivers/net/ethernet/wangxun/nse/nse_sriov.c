// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_vf_lib_private.h"
#include "nse_base.h"
#include "nse_lib.h"
#include "nse_fltr.h"
#include "nse_dcb_lib.h"
#include "nse_eswitch.h"
#include "nse_virtchnl_allowlist.h"
#include "nse_tc_lib.h"

#include <linux/pci.h>

static void nse_unplan_vf_res(struct nse_pf *pf);	/* forward declaration */

/**
 * nse_free_vf_entries - Free all VF entries from the hash table
 * @pf: pointer to the PF structure
 *
 * Iterate over the VF hash table, removing and releasing all VF entries.
 * Called during VF teardown or as cleanup during failed VF initialization.
 */
static void nse_free_vf_entries(struct nse_pf *pf)
{
	struct nse_vfs *vfs = &pf->vfs;
	struct hlist_node *tmp;
	struct nse_vf *vf;
	unsigned int bkt;

	/* Remove all VFs from the hash table and release their main
	 * reference. Once all references to the VF are dropped, nse_put_vf()
	 * will call nse_sriov_free_vf which will remove the VF memory.
	 */
	lockdep_assert_held(&vfs->table_lock);

	hash_for_each_safe(vfs->table, bkt, tmp, vf, entry) {
		hash_del_rcu(&vf->entry);
		nse_put_vf(vf);
	}
}

/**
 * nse_free_vf_res - Free a VF's resources
 * @vf: pointer to the VF info
 */
static void nse_free_vf_res(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	int i, last_vector_idx;

	/* First, disable VF's configuration API to prevent OS from
	 * accessing the VF's VSI after it's freed or invalidated.
	 */
	clear_bit(NSE_VF_STATE_INIT, vf->vf_states);

	/* free VSI and disconnect it from the parent uplink */
	if (vf->lan_vsi_idx != NSE_NO_VSI) {
		nse_vf_vsi_release(vf);
		vf->num_mac = 0;
	}

	last_vector_idx = vf->first_vector_idx + pf->vfs.num_msix_per - 1;

	/* clear VF MDD event information */
	memset(&vf->mdd_tx_events, 0, sizeof(vf->mdd_tx_events));
	memset(&vf->mdd_rx_events, 0, sizeof(vf->mdd_rx_events));

	/* Disable interrupts so that VF starts in a known state */
	for (i = vf->first_vector_idx; i <= last_vector_idx; i++) {
		wr32(&pf->hw, NSE_REG_INT_DYN_CTLN(i),
			(NSE_REG_INT_DYN_CTLN_CLEARPBA_M |
			 NSE_REG_INT_DYN_CTLN_INTMSK_VLD_M | NSE_REG_INT_DYN_CTLN_INTMSK_M));
		nse_flush(&pf->hw);
	}
	/* reset some of the state variables keeping track of the resources */
	clear_bit(NSE_VF_STATE_MC_PROMISC, vf->vf_states);
	clear_bit(NSE_VF_STATE_UC_PROMISC, vf->vf_states);
}

/**
 * nse_dis_vf_mappings
 * @vf: pointer to the VF structure
 */
void nse_dis_vf_mappings(struct nse_vf *vf)
{
}

/**
 * nse_sriov_free_msix_res - Reset/free any used MSIX resources
 * @pf: pointer to the PF structure
 *
 * Since no MSIX entries are taken from the pf->irq_tracker then just clear
 * the pf->sriov_base_vector.
 *
 * Returns 0 on success, and -EINVAL on error.
 */
static int nse_sriov_free_msix_res(struct nse_pf *pf)
{
	struct nse_res_tracker *res;

	if (!pf)
		return -EINVAL;

	res = pf->irq_tracker_self_region;
	if (!res)
		return -EINVAL;

	/* give back irq_tracker resources used */
	WARN_ON(pf->sriov_base_vector < res->num_entries);

	pf->sriov_base_vector = 0;

	return 0;
}

/**
 * nse_dis_vf_qs - Disable the VF queues
 * @vf: pointer to the VF structure
 */
void nse_dis_vf_qs(struct nse_vf *vf, bool lan_stopped)
{
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);

	nse_debug(hw, NSE_DBG_SYS, "[%s] VF (rel_id=%d, abs_id=%d), vsi(rel_id=%d, abs_id=%d)\n",
								__func__,
								vf->vf_id, nse_abs_vf_id(hw,
											 vf->vf_id),
								vf->vf_vsi_rel_id,
									vf->vf_vsi_abs_id);
	if (WARN_ON(!vsi))
		return;

	nse_vsi_stop_lan_tx_rings(vsi, lan_stopped);
	nse_vsi_stop_all_rx_rings(vsi, lan_stopped);

	nse_vsi_stop_lan_txcq_rings(vsi);

	nse_set_vf_state_qs_dis(vf);
}

/**
 * nse_is_sriov_enable - whether pf's sriov is enable or not
 * @pf: pointer to the PF structure
 */
bool nse_is_sriov_enabled(struct nse_pf *pf)
{
	return test_bit(NSE_FLAG_SRIOV_ENA, pf->flags);
}

/**
 * nse_free_vfs - Free all VFs
 * @pf: pointer to the PF structure
 */
void nse_free_vfs(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vfs *vfs = &pf->vfs;
	struct nse_hw *hw = &pf->hw;
	struct nse_vf *vf;
	unsigned int bkt;

	if (!nse_has_vfs(pf))
		return;

	nse_debug(hw, NSE_DBG_SYS, "[%s] - enter\n", __func__);

	while (test_and_set_bit(NSE_VF_DIS, pf->state))
		usleep_range(1000, 2000);

	nse_debug(hw, NSE_DBG_SYS, "[%s, %d] DONE setting VF_DIS in pf->state\n",
		  __func__, __LINE__);

	/* Disable IOV before freeing resources. This lets any VF drivers
	 * running in the host get themselves cleaned up before we yank
	 * the carpet out from underneath their feet.
	 */
	if (!pci_vfs_assigned(pf->pdev)) {
		pf->force_reset_vf = true;

		pci_disable_sriov(pf->pdev);

		pf->force_reset_vf = false;
	} else
		dev_warn(dev, "VFs are assigned - not disabling SR-IOV\n");

	mutex_lock(&vfs->table_lock);

	nse_eswitch_release(pf);

	nse_destroy_vfs_sysfs(pf);

	nse_for_each_vf(pf, bkt, vf) {
		mutex_lock(&vf->cfg_lock);

		nse_dis_vf_qs(vf, false);

		if (test_bit(NSE_VF_STATE_INIT, vf->vf_states)) {
			u16 abs_vf_id = nse_abs_vf_id(hw, vf->vf_id);
			struct iidc_core_dev_info *rcdi;

			/* disable VF qp mappings and set VF disable state */
			nse_dis_vf_mappings(vf);
			set_bit(NSE_VF_STATE_DIS, vf->vf_states);
			rcdi = nse_find_cdev_info_by_id(pf, IIDC_RDMA_ID);
			nse_send_vf_reset_to_aux(pf, rcdi, abs_vf_id);
			nse_free_vf_res(vf);
		}

		mutex_unlock(&vf->cfg_lock);
	}

	if (nse_sriov_free_msix_res(pf))
		dev_warn(dev, "WARN: some inproper condition when free MSIX resources used by SR-IOV\n");

	vfs->num_qps_per = 0;
	nse_free_vf_entries(pf);

	nse_unplan_vf_res(pf);

	mutex_unlock(&vfs->table_lock);

	clear_bit(NSE_VF_DIS, pf->state);
	clear_bit(NSE_FLAG_SRIOV_ENA, pf->flags);

	vfs->num_enabled = 0;

	nse_debug(hw, NSE_DBG_SYS, "[%s] - exit\n", __func__);
}

/**
 * nse_vf_vsi_setup - Set up a VF VSI
 * @vf: VF to setup VSI for
 *
 * Returns pointer to the successfully allocated VSI struct on success,
 * otherwise returns NULL on failure.
 */
static struct nse_vsi *nse_vf_vsi_setup(struct nse_vf *vf)
{
	struct nse_port_info *pi = nse_vf_get_port_info(vf);
	struct nse_pf *pf = vf->pf;
	struct nse_vsi *vsi;

	vsi = nse_vsi_setup(pf, pi, NSE_VSI_VF, vf, 0);

	if (!vsi) {
		dev_err(nse_pf_to_dev(pf), "Failed to create VF VSI\n");
		nse_vf_invalidate_vsi(vf);
		return NULL;
	}

	vf->lan_vsi_idx = vsi->idx;
	vf->vf_vsi_abs_id = vsi->vsi_abs_num;
	vf->vf_vsi_rel_id = vsi->vsi_rel_num;

	nse_debugfs_vf_init(vf);

	return vsi;
}

/**
 * nse_calc_vf_first_vector_idx - Calculate MSIX vector index in the PF space
 * @pf: pointer to PF structure
 * @vf: pointer to VF that the first MSIX vector index is being calculated for
 *
 * This returns the first MSIX vector index in PF space that is used by this VF.
 * This index is used when accessing PF relative registers such as
 * GLINT_VECT2FUNC and GLINT_DYN_CTL.
 * This will always be the OICR index in the AVF driver so any functionality
 * using vf->first_vector_idx for queue configuration will have to increment by
 * 1 to avoid meddling with the OICR index.
 */
static int nse_calc_vf_first_vector_idx(struct nse_pf *pf, struct nse_vf *vf)
{
	return pf->sriov_base_vector + vf->vf_id * pf->vfs.num_msix_per;
}

/**
 * nse_ena_vf_msix_mappings - enable VF MSIX mappings in hardware
 * @vf: VF to enable MSIX mappings for
 *
 * Some of the registers need to be indexed/configured using hardware global
 * device values and other registers need 0-based values, which represent PF
 * based values.
 */
static void nse_ena_vf_msix_mappings(struct nse_vf *vf)
{
	u32 reg;
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;

	if (WARN_ON(!vsi))
		return;

	reg = rd32(hw, NSE_REG_VMBX_CTL(vsi->vsi_rel_num));

	reg &= ~(NSE_REG_VMBX_CTL_PF_IDX_M);

	reg |= ((u32)hw->pcore_pf_id << NSE_REG_VMBX_CTL_PF_IDX_S) & NSE_REG_VMBX_CTL_PF_IDX_M;

	/* when first start SRIOV, the setting is: MSIX_IDX = 0 (VF misc-irq-vector), CAUSE_EN = 0
	 * later VF driver itself would set CAUSE_EN = 1
	 */
	wr32(hw, NSE_REG_VMBX_CTL(vsi->vsi_rel_num), reg);
}

/**
 * nse_ena_vf_q_mappings - enable Rx/Tx queue mappings for a VF
 * @vf: VF to enable the mappings for
 * @max_txq: max Tx queues allowed on the VF's VSI
 * @max_rxq: max Rx queues allowed on the VF's VSI
 */
static void nse_ena_vf_q_mappings(struct nse_vf *vf, u16 max_txq, u16 max_rxq)
{
}

/**
 * nse_ena_vf_mappings - enable VF MSIX and queue mapping
 * @vf: pointer to the VF structure
 */
static void nse_ena_vf_mappings(struct nse_vf *vf)
{
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);
	u16 max_txq, max_rxq;

	if (WARN_ON(!vsi))
		return;

	nse_ena_vf_msix_mappings(vf);

	max_txq = vsi->alloc_txq;
	max_rxq = vsi->alloc_rxq;

	nse_ena_vf_q_mappings(vf, max_txq, max_rxq);
}

/**
 * nse_calc_vf_reg_idx - Calculate the VF's register index in the PF space
 * @vf: VF to calculate the register index for
 * @q_vector: a q_vector associated to the VF
 * @tc: Traffic class number for VF ADQ
 */
int nse_calc_vf_reg_idx(struct nse_vf *vf, struct nse_q_vector *q_vector,
			u8 __maybe_unused tc)
{
	struct nse_pf *pf;
	u32 reg_idx;

	if (!vf || !q_vector)
		return -EINVAL;

	pf = vf->pf;

	/* always add one to account for the OICR being the first MSIX */
	reg_idx = pf->sriov_base_vector + pf->vfs.num_msix_per * vf->vf_id +
		  q_vector->v_idx + 1;

	return reg_idx;
}

static int nse_sriov_set_msix_res(struct nse_pf *pf, u16 num_msix_needed)
{
	u16 total_vectors = pf->irq_space_size;
	/* used by PF itself (including reserved for PE) */
	int vectors_used = pf->irq_tracker_self_region->num_entries;
	int sriov_base_vector;

	if (nse_sriov_vf_res_alloc_from_tail) {
		sriov_base_vector = total_vectors - num_msix_needed;

		/* make sure we only grab irq_tracker entries from the list end and
		 * that we have enough available MSIX vectors
		 */
		if (sriov_base_vector < vectors_used)
			return -EINVAL;

	} else {
		sriov_base_vector = vectors_used;

		if ((total_vectors - sriov_base_vector) < num_msix_needed)
			return -EINVAL;
	}

	pf->sriov_base_vector = sriov_base_vector;

	return 0;
}

/**
 * nse_set_per_vf_res - check if vectors and queues are available
 * @pf: pointer to the PF structure
 * @num_vfs: the number of SR-IOV VFs being configured
 *
 * First, determine HW interrupts from common pool. If we allocate fewer VFs, we
 * get more vectors and can enable more queues per VF. Note that this does not
 * grab any vectors from the SW pool already allocated. Also note, that all
 * vector counts include one for each VF's miscellaneous interrupt vector
 * (i.e. OICR).
 *
 * Minimum VFs - 2 vectors, 1 queue pair
 * Small VFs - 5 vectors, 4 queue pairs
 * Medium VFs - 17 vectors, 16 queue pairs
 *
 *
 * Second, determine number of queue pairs per VF by starting with a pre-defined
 * maximum each VF supports. If this is not possible, then we adjust based on
 * queue pairs available on the device.
 *
 *
 * Lastly, set queue and MSI-X VF variables tracked by the PF so it can be used
 * by each VF during VF initialization and reset.
 */
static int nse_set_per_vf_res(struct nse_pf *pf, u16 num_vfs)
{
	u16 num_msix_per_vf, num_txq, num_rxq, num_txcq, avail_qs;
	int msix_avail_per_vf, msix_avail_for_sriov;
	u16 txcq_reserved_for_switchdev = 0;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	lockdep_assert_held(&pf->vfs.table_lock);

	if (!num_vfs)
		return -EINVAL;

	/* determine MSI-X resources per VF */

	msix_avail_for_sriov = pf->irq_space_size -	pf->irq_tracker_self_region->num_entries;

	msix_avail_per_vf = msix_avail_for_sriov / num_vfs;

	if (msix_avail_per_vf >= NSE_NUM_VF_MSIX_MAX) {
		num_msix_per_vf = NSE_NUM_VF_MSIX_MAX;
	} else if (msix_avail_per_vf >= NSE_NUM_VF_MSIX_LARGE) {
		num_msix_per_vf = NSE_NUM_VF_MSIX_LARGE;
	} else if (msix_avail_per_vf >= NSE_NUM_VF_MSIX_MED) {
		num_msix_per_vf = NSE_NUM_VF_MSIX_MED;
	} else if (msix_avail_per_vf >= NSE_NUM_VF_MSIX_MED_SMALL) {
		num_msix_per_vf = NSE_NUM_VF_MSIX_MED_SMALL;
	} else if (msix_avail_per_vf >= NSE_NUM_VF_MSIX_SMALL) {
		num_msix_per_vf = NSE_NUM_VF_MSIX_SMALL;
	} else if (msix_avail_per_vf >= NSE_NUM_VF_MSIX_MULTIQ_MIN) {
		num_msix_per_vf = NSE_NUM_VF_MSIX_MULTIQ_MIN;
	} else if (msix_avail_per_vf >= NSE_MIN_INTR_PER_VF) {
		num_msix_per_vf = NSE_MIN_INTR_PER_VF;
	} else {
		dev_err(dev, "Only %d MSI-X interrupts available for SR-IOV. Not enough to support minimum of %d MSI-X interrupts per VF for %d VFs\n",
			msix_avail_for_sriov, NSE_MIN_INTR_PER_VF,
			num_vfs);
		return -ENOSPC;
	}

	num_txq = min_t(u16, num_msix_per_vf - NSE_NONQ_VECS_VF,
			NSE_MAX_DFLT_QS_PER_VF);
	avail_qs = nse_get_avail_txq_count_max_contig(pf) / num_vfs;
	if (!avail_qs)
		num_txq = 0;
	else if (num_txq > avail_qs)
		num_txq = rounddown_pow_of_two(avail_qs);

	num_rxq = min_t(u16, num_msix_per_vf - NSE_NONQ_VECS_VF,
			NSE_MAX_DFLT_QS_PER_VF);
	avail_qs = nse_get_avail_rxq_count_max_contig(pf) / num_vfs;
	if (!avail_qs)
		num_rxq = 0;
	else if (num_rxq > avail_qs)
		num_rxq = rounddown_pow_of_two(avail_qs);

	if (num_txq < NSE_MIN_QS_PER_VF || num_rxq < NSE_MIN_QS_PER_VF) {
		dev_err(dev, "Not enough queues to support minimum of %d queue pairs per VF for %d VFs\n",
			NSE_MIN_QS_PER_VF, num_vfs);
		return -ENOSPC;
	}

	/* only allow equal Tx/Rx queue count (i.e. queue pairs) */
	pf->vfs.num_qps_per = min_t(int, num_txq, num_rxq);

	pf->vfs.num_qps_per = rounddown_pow_of_two(pf->vfs.num_qps_per);

	if (nse_vf_vsi_max_lanq_num &&
		pf->vfs.num_qps_per > nse_vf_vsi_max_lanq_num) {
		pf->vfs.num_qps_per = nse_vf_vsi_max_lanq_num;
	}

	pf->vfs.num_msix_per = num_msix_per_vf;

	if (pf->sw_conf.lan_tx_use_cq_for_vf) {		//also VF vsi->sw_conf.lan_tx_use_cq

		/*  we need to reserve some CQ for switchdev-ctl-VSI, same computation as in
		 * nse_vsi_set_num_qs()
		 */
		if (nse_is_eswitch_mode_switchdev(pf)) {
			txcq_reserved_for_switchdev = (num_vfs + 7) / 8;
			if (!txcq_reserved_for_switchdev)
				txcq_reserved_for_switchdev = 1;

			if (nse_get_avail_txcq_count_max_contig(pf) <=
			    txcq_reserved_for_switchdev) {
				dev_err(dev,
		"Not enough completion queues to support %d VFs in switchdev mode\n", num_vfs);
				return -ENOSPC;
			}
		}

		/* ideally, same number as TXQ, which is max (num_msix_per - 1) */
		num_txcq = pf->vfs.num_qps_per;
		avail_qs = (nse_get_avail_txcq_count_max_contig(pf) -
			    txcq_reserved_for_switchdev) / num_vfs;

		if (!avail_qs)
			num_txcq = 0;
		else if (num_txcq > avail_qs)
			num_txcq = avail_qs;

		if (!num_txcq) {
			dev_err(dev,
				"Not enough txcqs to support minimum of 1 txcq per VF for %d VFs\n",
				num_vfs);
			return -ENOSPC;
		}

		if (num_txcq > (pf->vfs.num_msix_per - NSE_NONQ_VECS_VF))	/* no need more */
			num_txcq = (pf->vfs.num_msix_per - NSE_NONQ_VECS_VF);

		if (nse_vf_vsi_max_lanirq_num && nse_vf_vsi_max_lanirq_num < num_txcq) {
			pf->vfs.max_lan_msix_per = nse_vf_vsi_max_lanirq_num;
			num_txcq = nse_vf_vsi_max_lanirq_num;	/* no need more */

		} else {
			pf->vfs.max_lan_msix_per = num_txcq;
		}

		pf->vfs.num_txcq_per = num_txcq;

	} else {
		pf->vfs.num_txcq_per = 0;

		if (nse_vf_vsi_max_lanirq_num &&
		    nse_vf_vsi_max_lanirq_num < (pf->vfs.num_msix_per - NSE_NONQ_VECS_VF))
			pf->vfs.max_lan_msix_per = nse_vf_vsi_max_lanirq_num;
		else
			pf->vfs.max_lan_msix_per = 0;
	}

	err = nse_sriov_set_msix_res(pf, num_msix_per_vf * num_vfs);
	if (err) {
		dev_err(dev, "Unable to set MSI-X resources for %d VFs, err %d\n",
			num_vfs, err);
		return err;
	}

	dev_info(dev, "Enabling %d VFs with %d vectors and %d queues per VF\n",
		 num_vfs, pf->vfs.num_msix_per, pf->vfs.num_qps_per);

	return 0;
}

static int nse_plan_vf_res(struct nse_pf *pf, u16 num_vfs)
{
	int ret = -ENOSPC;
	enum nse_status status;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vfs *vfs = &pf->vfs;
	int free_res_cnt = 0, need_res_cnt = 0, idx = 0;

	if (pf->sriov_res_planned) {
		dev_err(dev, "SRIOV - VF resource plan already made ?\n");
		return ret;
	}

	/* acquire all mutex first */
	mutex_lock(&pf->vsi_tracker_mutex);
	mutex_lock(&pf->lan_rxq_tracker_mutex);
	mutex_lock(&pf->lan_txq_tracker_mutex);
	mutex_lock(&pf->lan_txcq_tracker_mutex);

	/* VF VSI plan.
	 */
	need_res_cnt = num_vfs;

	free_res_cnt = nse_get_free_res_count_max_contig(pf->vsi_tracker);

	if (free_res_cnt < need_res_cnt) {
		dev_err(dev, "SRIOV - VF VSI plan fails - 1: free_res_cnt = %d, need_res_cnt = %d\n",
						free_res_cnt, need_res_cnt);
		goto out;
	}

	if (nse_sriov_vf_res_alloc_from_tail)
		idx = nse_get_res_backward(pf, pf->vsi_tracker, need_res_cnt,
					   NSE_RES_VSI_ID_VF_BASE);
	else
		idx = nse_get_res(pf, pf->vsi_tracker, need_res_cnt, NSE_RES_VSI_ID_VF_BASE);

	if (idx < 0) {
		dev_err(dev, "SRIOV - VF VSI plan fails - 2: free_res_cnt = %d, need_res_cnt = %d\n",
						free_res_cnt, need_res_cnt);
		goto out;
	}

	vfs->vf_vsialloc_firstvsi = idx;

	/* VF rxq plan.
	 */
	need_res_cnt = num_vfs * vfs->num_qps_per;

	free_res_cnt = nse_get_free_res_count_max_contig(pf->lan_rxq_tracker);

	if (free_res_cnt < need_res_cnt) {
		dev_err(dev, "SRIOV - VF rxq plan fails - 1: free_res_cnt = %d, need_res_cnt = %d\n",
						free_res_cnt, need_res_cnt);
		goto unroll_vsi_plan;
	}

	if (nse_sriov_vf_res_alloc_from_tail)
		idx = nse_get_res_backward(pf, pf->lan_rxq_tracker, need_res_cnt,
					   NSE_RES_LAN_RXQ_ID_VF_BASE);
	else
		idx = nse_get_res(pf, pf->lan_rxq_tracker, need_res_cnt,
				  NSE_RES_LAN_RXQ_ID_VF_BASE);

	if (idx < 0) {
		dev_err(dev, "SRIOV - VF rxq plan fails - 2: free_res_cnt = %d, need_res_cnt = %d\n",
						free_res_cnt, need_res_cnt);
		goto unroll_vsi_plan;
	}

	vfs->vf_rx_qbase_firstq = idx;
	vfs->vf_rx_qbase_numq = vfs->num_qps_per;

	/* VF txq plan.
	 */
	need_res_cnt = num_vfs * vfs->num_qps_per;

	free_res_cnt = nse_get_free_res_count_max_contig(pf->lan_txq_tracker);

	if (free_res_cnt < need_res_cnt) {
		dev_err(dev, "SRIOV - VF txq plan fails - 1: free_res_cnt = %d, need_res_cnt = %d\n",
						free_res_cnt, need_res_cnt);
		goto unroll_rxq_plan;
	}

	if (nse_sriov_vf_res_alloc_from_tail)
		idx = nse_get_res_backward(pf, pf->lan_txq_tracker, need_res_cnt,
					   NSE_RES_LAN_TXQ_ID_VF_BASE);
	else
		idx = nse_get_res(pf, pf->lan_txq_tracker, need_res_cnt,
				  NSE_RES_LAN_TXQ_ID_VF_BASE);

	if (idx < 0) {
		dev_err(dev, "SRIOV - VF txq plan fails - 2: free_res_cnt = %d, need_res_cnt = %d\n",
						free_res_cnt, need_res_cnt);
		goto unroll_rxq_plan;
	}

	vfs->vf_tx_qbase_firstq = idx;
	vfs->vf_tx_qbase_numq = vfs->num_qps_per;

	/* VF txcq plan.
	 */
	if (pf->sw_conf.lan_tx_use_cq_for_vf) {
		need_res_cnt = num_vfs * vfs->num_txcq_per;

		free_res_cnt = nse_get_free_res_count_max_contig(pf->lan_txcq_tracker);

		if (free_res_cnt < need_res_cnt) {
			dev_err(dev, "SRIOV - VF txcq plan fails - 1: free_res_cnt = %d, need_res_cnt = %d\n",
							free_res_cnt, need_res_cnt);
			goto unroll_txq_plan;
		}

		if (nse_sriov_vf_res_alloc_from_tail)
			idx = nse_get_res_backward(pf, pf->lan_txcq_tracker, need_res_cnt,
						   NSE_RES_LAN_TXCQ_ID_VF_BASE);
		else
			idx = nse_get_res(pf, pf->lan_txcq_tracker, need_res_cnt,
					  NSE_RES_LAN_TXCQ_ID_VF_BASE);

		if (idx < 0) {
			dev_err(dev, "SRIOV - VF txcq plan fails - 2: free_res_cnt = %d, need_res_cnt = %d\n",
							free_res_cnt, need_res_cnt);
			goto unroll_txq_plan;
		}

		vfs->vf_txcq_qbase_firstq = idx;
	}

	/* VF irq plan - no need, because nse_set_per_vf_res() already did the plan.
	 */
	vfs->vfint_alloc_first = pf->sriov_base_vector;
	vfs->vfint_alloc_vecnum = vfs->num_msix_per;

	/* send adminq-cmd
	 */
	status = nse_aq_set_sriov_res(&pf->hw);
	if (status) {
		dev_err(dev, "SRIOV - aq_set_sriov_res() fails, status = %d\n",
						status);
		ret = -EIO;
		goto unroll_txcq_plan;
	}

	pf->sriov_res_planned = true;
	pf->nonvf_vsi_region_size = vfs->vf_vsialloc_firstvsi;

	ret = 0;

	goto out;	/* Success, need goto out to unlock mutex */

unroll_txcq_plan:
	if (pf->sw_conf.lan_tx_use_cq_for_vf)
		(void)nse_free_res(pf->lan_txcq_tracker, vfs->vf_txcq_qbase_firstq,
				   NSE_RES_LAN_TXCQ_ID_VF_BASE);

unroll_txq_plan:
	(void)nse_free_res(pf->lan_txq_tracker, vfs->vf_tx_qbase_firstq,
			   NSE_RES_LAN_TXQ_ID_VF_BASE);

unroll_rxq_plan:
	(void)nse_free_res(pf->lan_rxq_tracker, vfs->vf_rx_qbase_firstq,
			   NSE_RES_LAN_RXQ_ID_VF_BASE);

unroll_vsi_plan:
	(void)nse_free_res(pf->vsi_tracker, vfs->vf_vsialloc_firstvsi, NSE_RES_VSI_ID_VF_BASE);

out:
	mutex_unlock(&pf->lan_txcq_tracker_mutex);
	mutex_unlock(&pf->lan_txq_tracker_mutex);
	mutex_unlock(&pf->lan_rxq_tracker_mutex);
	mutex_unlock(&pf->vsi_tracker_mutex);

	return ret;
}

static void nse_unplan_vf_res(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_vfs *vfs = &pf->vfs;

	nse_debug(hw, NSE_DBG_SYS, "[%s] sriov_res_planned=%d\n",
		  __func__, pf->sriov_res_planned);

	if (!pf->sriov_res_planned)
		return;

	(void)nse_aq_unset_sriov_res(&pf->hw);

	mutex_lock(&pf->vsi_tracker_mutex);
	mutex_lock(&pf->lan_rxq_tracker_mutex);
	mutex_lock(&pf->lan_txq_tracker_mutex);
	mutex_lock(&pf->lan_txcq_tracker_mutex);

	if (pf->sw_conf.lan_tx_use_cq_for_vf)
		(void)nse_free_res(pf->lan_txcq_tracker, vfs->vf_txcq_qbase_firstq,
				   NSE_RES_LAN_TXCQ_ID_VF_BASE);

	(void)nse_free_res(pf->lan_txq_tracker, vfs->vf_tx_qbase_firstq,
			   NSE_RES_LAN_TXQ_ID_VF_BASE);
	(void)nse_free_res(pf->lan_rxq_tracker, vfs->vf_rx_qbase_firstq,
			   NSE_RES_LAN_RXQ_ID_VF_BASE);
	(void)nse_free_res(pf->vsi_tracker, vfs->vf_vsialloc_firstvsi, NSE_RES_VSI_ID_VF_BASE);

	mutex_unlock(&pf->lan_txcq_tracker_mutex);
	mutex_unlock(&pf->lan_txq_tracker_mutex);
	mutex_unlock(&pf->lan_rxq_tracker_mutex);
	mutex_unlock(&pf->vsi_tracker_mutex);

	pf->sriov_res_planned = false;
	pf->nonvf_vsi_region_size = pf->vsi_space_size;
}

/**
 * nse_init_vf_vsi_res - initialize/setup VF VSI resources
 * @vf: VF to initialize/setup the VSI for
 *
 * This function creates a VSI for the VF, adds a VLAN 0 filter, and sets up the
 * VF VSI's broadcast filter and is only used during initial VF creation.
 */
static int nse_init_vf_vsi_res(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	struct nse_vsi *vsi;
	int err;

	vf->first_vector_idx = nse_calc_vf_first_vector_idx(pf, vf);

	vsi = nse_vf_vsi_setup(vf);
	if (!vsi)
		return -ENOMEM;

	err = nse_vf_init_host_cfg(vf, vsi);
	if (err)
		goto release_vsi;

	return 0;

release_vsi:
	nse_vf_vsi_release(vf);
	return err;
}

/* simple rollback for nse_start_vfs() */
static void nse_start_vfs_rollback(struct nse_pf *pf)
{
	unsigned int bkt;
	struct nse_vf *vf;

	lockdep_assert_held(&pf->vfs.table_lock);

	nse_for_each_vf(pf, bkt, vf) {
		mutex_lock(&vf->cfg_lock);

		if (test_bit(NSE_VF_STATE_INIT, vf->vf_states)) {
			nse_dis_vf_mappings(vf);
			set_bit(NSE_VF_STATE_DIS, vf->vf_states);

			nse_free_vf_res(vf);	/* mainly for nse_vf_vsi_release(vf) inside */
		}

		mutex_unlock(&vf->cfg_lock);
	}

	nse_unplan_vf_res(pf);
}

/**
 * nse_start_vfs - start VFs so they are ready to be used by SR-IOV
 * @pf: PF the VFs are associated with
 */
static int nse_start_vfs(struct nse_pf *pf, u16 num_vfs)
{
	struct nse_hw *hw = &pf->hw;
	unsigned int bkt, it_cnt;
	struct nse_vf *vf;
	int retval;

	nse_debug(hw, NSE_DBG_SYS, "[%s] - enter: num_vfs=%d\n", __func__, num_vfs);

	lockdep_assert_held(&pf->vfs.table_lock);

	retval = nse_plan_vf_res(pf, num_vfs);
	if (retval) {
		dev_err(nse_pf_to_dev(pf), "[%s] FAIL: plan_vf_res(), ret=%d\n",
			__func__, retval);
		goto out;
	}

	it_cnt = 0;
	nse_for_each_vf(pf, bkt, vf) {
		retval = nse_init_vf_vsi_res(vf);
		if (retval) {
			nse_dev_err_errno(nse_pf_to_dev(pf), retval,
					  "Failed to initialize VSI resources for VF %d",
					  vf->vf_id);
			goto teardown;
		}

		vf->vf_ops->clear_reset_trigger(vf);

		set_bit(NSE_VF_STATE_INIT, vf->vf_states);
		nse_ena_vf_mappings(vf);

		it_cnt++;
	}

	nse_flush(hw);

	nse_debug(hw, NSE_DBG_SYS, "[%s] exit: ret=0\n", __func__);

	return 0;

teardown:
	nse_for_each_vf(pf, bkt, vf) {
		if (it_cnt == 0)
			break;

		nse_dis_vf_mappings(vf);
		nse_vf_vsi_release(vf);
		it_cnt--;
	}

	nse_unplan_vf_res(pf);

out:
	nse_debug(hw, NSE_DBG_SYS, "[%s] exit: ret=%d\n", __func__, retval);

	return retval;
}

/**
 * nse_sriov_free_vf - Free VF memory after all references are dropped
 * @vf: pointer to VF to free
 *
 * Called by nse_put_vf through nse_release_vf once the last reference to a VF
 * structure has been dropped.
 */
static void nse_sriov_free_vf(struct nse_vf *vf)
{
	mutex_destroy(&vf->cfg_lock);

	kfree_rcu(vf, rcu);
}

/**
 * nse_sriov_clear_mbx_register - clears SRIOV VF's mailbox registers
 * @vf: the vf to configure
 */
static void nse_sriov_clear_mbx_register(struct nse_vf *vf)
{
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;

	if (WARN_ON(!vsi))
		return;

	nse_debug(hw, NSE_DBG_SYS, "[%s]: VF (abs_id=%d, vf_id in PF=%d), VSI(abs_id=%d, rel_id=%d)\n",
								__func__,
								nse_abs_vf_id(&pf->hw, vf->vf_id),
									vf->vf_id, vsi->vsi_abs_num,
									vsi->vsi_rel_num);

	nse_shutdown_vsi_mbxq(&pf->hw, vsi->vsi_rel_num);

	nse_shutdown_vsi_utilq(&pf->hw, vsi->vsi_rel_num);

	if (vf->use_pv_msgbox)
		wr32(hw, NSE_REG_VMBX_ARQBAL(vsi->vsi_rel_num), NSE_REG_VALUE_RESET_MAGIC_1);
}

/**
 * nse_sriov_trigger_reset_register - trigger VF reset for SRIOV VF
 * @vf: pointer to VF structure
 * @is_vflr: true if reset occurred due to VFLR
 *
 * Trigger and cleanup after a VF reset for a SR-IOV VF.
 */
static void nse_sriov_trigger_reset_register(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_SYS, "[%s] VF (rel_id=%d, abs_id=%d), vsi(rel_id=%d, abs_id=%d)\n",
								__func__,
								vf->vf_id, nse_abs_vf_id(hw,
											 vf->vf_id),
								vf->vf_vsi_rel_id,
									vf->vf_vsi_abs_id);

	wr32(hw, NSE_REG_VFRTRIG(vf->vf_id), NSE_REG_VFRTRIG_TRIG_M);
}

/**
 * nse_sriov_poll_reset_status - poll SRIOV VF reset status
 * @vf: pointer to VF structure
 *
 * Returns true when reset is successful, else returns false
 */
static bool nse_sriov_poll_reset_status(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	unsigned int i;
	unsigned int vf_reset_wait_timeout;
	u32 reg;

	vf_reset_wait_timeout = (NSE_VF_RESET_WAIT_TIMEOUT_BASE * nse_timeout_scale);

	nse_debug(hw, NSE_DBG_SYS, "[%s] VF (rel_id=%d, abs_id=%d), vf_reset_wait_timeout=%d\n",
								__func__,
								vf->vf_id, nse_abs_vf_id(hw,
											 vf->vf_id),
									vf_reset_wait_timeout);

	for (i = 0; i < vf_reset_wait_timeout; i++) {
		reg = rd32(&pf->hw, NSE_REG_VFRTRIG(vf->vf_id));
		if (!(reg & NSE_REG_VFRTRIG_TRIG_M)) {
			nse_debug(hw, NSE_DBG_SYS, "[%s] poll VFRTRIG cleared, reg_vfrtrig=0x%X, poll times=%d\n",
										__func__,
											reg, i);

			return true;
		}

		/* only sleep if the reset is not done */
		msleep(NSE_RESET_WAIT_TICK);
	}

	nse_debug(hw, NSE_DBG_SYS, "[%s] poll VFRTRIG timeout, reg_vfrtrig=0x%X\n",
		  __func__, reg);

	return false;
}

/**
 * nse_sriov_clear_reset_trigger - enable VF to access hardware
 * @vf: VF to enabled hardware access for
 */
static void nse_sriov_clear_reset_trigger(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);
	u32 reg = 0;

	nse_debug(hw, NSE_DBG_SYS, "[%s] VF (rel_id=%d, abs_id=%d)\n",
								__func__,
		  vf->vf_id, nse_abs_vf_id(hw, vf->vf_id));

	reg = rd32(hw, NSE_REG_VFRTRIG(vf->vf_id));

	nse_debug(hw, NSE_DBG_SYS, "\t current VFRTRIG is 0x%X\n", reg);

	wr32(hw, NSE_REG_VFRTRIG(vf->vf_id), 0);

	if (vsi) {
		nse_debug(hw, NSE_DBG_SYS, "[%s] set vmbx arqbal to magic_pf_init (0x%X)\n",
			  __func__, NSE_REG_VMBX_ARQBAL_MAGIC_PF_INIT);

		wr32(hw, NSE_REG_VMBX_ARQBAL(vsi->vsi_rel_num), NSE_REG_VMBX_ARQBAL_MAGIC_PF_INIT);

		reg = rd32(hw, NSE_REG_VMBX_ARQBAL(vsi->vsi_rel_num));

		nse_debug(hw, NSE_DBG_SYS, "\t readback = (0x%X)\n", reg);
	}
}

/**
 * nse_sriov_create_vsi - Create a new VSI for a VF
 * @vf: VF to create the VSI for
 *
 * This is called by nse_vf_recreate_vsi to create the new VSI after the old
 * VSI has been released.
 */
static int nse_sriov_reinit_vsi(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);

	nse_debug(hw, NSE_DBG_SYS, "[%s] VF (rel_id=%d, abs_id=%d), vsi(rel_id=%d, abs_id=%d)\n",
								__func__,
								vf->vf_id, nse_abs_vf_id(hw,
											 vf->vf_id),
								vf->vf_vsi_rel_id,
									vf->vf_vsi_abs_id);
	if (!vsi)
		return -ENOENT;

	return nse_vsi_init(vsi, false);
}

/**
 * nse_sriov_post_vsi_rebuild - tasks to do after the VF's VSI have been rebuilt
 * @vf: VF to perform tasks on
 */
static void nse_sriov_post_vsi_rebuild(struct nse_vf *vf)
{
	nse_ena_vf_mappings(vf);
}

static struct nse_q_vector *nse_sriov_get_q_vector(struct nse_vf *vf,
						   struct nse_vsi *vsi,
						   u16 vector_id)
{
	if (!vsi || !vsi->q_vectors)
		return NULL;

	/* Subtract non queue vector from vector_id passed by VF
	 * to get actual number of VSI queue vector array index
	 */
	return vsi->q_vectors[vector_id - NSE_NONQ_VECS_VF];
}

/**
 * nse_sriov_clear_ceq_irq_map - clear the CEQ IRQ mapping
 * @vf: VF used to clear the mapping
 * @ceq_idx: VF relative (0-based) CEQ index
 */
static void nse_sriov_clear_ceq_irq_map(struct nse_vf *vf, u16 ceq_idx)
{
/*  @xzhao @renjunlin - todo-1: VF-RDMA: nse_sriov_clear_ceq_irq_map(): Amber PF BAR0 does not have
 * register: GLINT_CEQCTL, need think how to set it.
 */
}

/**
 * nse_sriov_clear_aeq_irq_map - clear the AEQ IRQ mapping
 * @vf: VF used to clear the mapping
 */
static void nse_sriov_clear_aeq_irq_map(struct nse_vf *vf)
{
/*  @xzhao @renjunlin - todo-1: VF-RDMA: nse_sriov_clear_aeq_irq_map(): Amber PF BAR0 does not have
 * register: VPINT_AEQCTL, need think how to set it.
 */
}

/**
 * nse_sriov_clear_rdma_irq_map - clear the RDMA IRQ mapping
 * @vf: VF used to clear the mapping
 *
 * Clear any RDMA IRQ mapping that a VF might have requested. Since the number
 * of CEQ indices are never greater than the num_msix_per_vf just clear all CEQ
 * indices that are possibly associated to this VF. Also clear the AEQ for this
 * VF. Doing it this way prevents the need to cache the configuration received
 * on VIRTCHNL_OP_CONFIG_RMDA_IRQ_MAP since VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP is
 * designed to clear the entire RDMA IRQ mapping configuration.
 */
static void nse_sriov_clear_rdma_irq_map(struct nse_vf *vf)
{
	u16 i;

	for (i = 0; i < vf->pf->vfs.num_msix_per; i++)
		nse_sriov_clear_ceq_irq_map(vf, i);

	nse_sriov_clear_aeq_irq_map(vf);
}

/**
 * nse_sriov_cfg_rdma_ceq_irq_map - configure the CEQ IRQ mapping
 * @vf: VF structure associated to the VF that requested the mapping
 * @qv_info: RDMA queue vector mapping information
 *
 * Configure the CEQ index for the passed in VF. This will result in the CEQ
 * being able to generate interrupts
 */
static void
nse_sriov_cfg_rdma_ceq_irq_map(struct nse_vf *vf,
			       struct virtchnl_rdma_qv_info *qv_info)
{
/*  @xzhao @renjunlin - todo-1: VF-RDMA: nse_sriov_cfg_rdma_ceq_irq_map(): Amber PF BAR0 does not
 * have register: GLINT_CEQCTL, need think how to set it.
 */
}

/**
 * nse_sriov_cfg_rdma_aeq_irq_map - configure the AEQ IRQ mapping
 * @vf: VF structure associated to the VF that requested the mapping
 * @qv_info: RDMA queue vector mapping information
 *
 * Configure the AEQ for the passed in VF. This will result in the AEQ being
 * able to generate interrupts
 */
static void
nse_sriov_cfg_rdma_aeq_irq_map(struct nse_vf *vf,
			       struct virtchnl_rdma_qv_info *qv_info)
{
/*  @xzhao @renjunlin - todo-1: VF-RDMA: nse_sriov_cfg_rdma_aeq_irq_map(): Amber PF BAR0 does not
 * have register: VPINT_AEQCTL, need think how to set it.
 */
}

/**
 * nse_sriov_cfg_rdma_irq_map - Configure RDMA IRQ mappings
 * @vf: VF structure associated to the VF that requested the mapping
 * @qv_info: RDMA queue vector mapping information
 *
 * Configure the AEQ and CEQ IRQ mappings for an SRIOV VF.
 */
static void
nse_sriov_cfg_rdma_irq_map(struct nse_vf *vf,
			   struct virtchnl_rdma_qv_info *qv_info)
{
	if (qv_info->ceq_idx != VIRTCHNL_RDMA_INVALID_QUEUE_IDX)
		nse_sriov_cfg_rdma_ceq_irq_map(vf, qv_info);

	if (qv_info->aeq_idx != VIRTCHNL_RDMA_INVALID_QUEUE_IDX)
		nse_sriov_cfg_rdma_aeq_irq_map(vf, qv_info);
}

static const struct nse_vf_ops nse_sriov_vf_ops = {
	.free = nse_sriov_free_vf,
	.clear_mbx_register = nse_sriov_clear_mbx_register,
	.trigger_reset_register = nse_sriov_trigger_reset_register,
	.poll_reset_status = nse_sriov_poll_reset_status,
	.clear_reset_trigger = nse_sriov_clear_reset_trigger,
	.irq_close = NULL,
	.reinit_vsi = nse_sriov_reinit_vsi,
	.post_vsi_rebuild = nse_sriov_post_vsi_rebuild,
	.get_q_vector = nse_sriov_get_q_vector,
	.cfg_rdma_irq_map = nse_sriov_cfg_rdma_irq_map,
	.clear_rdma_irq_map = nse_sriov_clear_rdma_irq_map,
};

/**
 * nse_create_vf_entries - Allocate and insert VF entries
 * @pf: pointer to the PF structure
 * @num_vfs: the number of VFs to allocate
 *
 * Allocate new VF entries and insert them into the hash table. Set some
 * basic default fields for initializing the new VFs.
 *
 * After this function exits, the hash table will have num_vfs entries
 * inserted.
 *
 * Returns 0 on success or an integer error code on failure.
 */
static int nse_create_vf_entries(struct nse_pf *pf, u16 num_vfs)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vfs *vfs = &pf->vfs;
	struct nse_vf *vf;
	u16 vf_id;
	int err;

	lockdep_assert_held(&vfs->table_lock);

	for (vf_id = 0; vf_id < num_vfs; vf_id++) {
		vf = kzalloc(sizeof(*vf), GFP_KERNEL);
		if (!vf) {
			err = -ENOMEM;
			goto err_free_entries;
		}
		kref_init(&vf->refcnt);

		vf->pf = pf;
		vf->vf_id = vf_id;

		/* set sriov vf ops for VFs created during SRIOV flow */
		vf->vf_ops = &nse_sriov_vf_ops;

		vf->lan_vsi_idx = NSE_NO_VSI;
		vf->vf_vsi_abs_id = NSE_NO_VSI;
		vf->vf_vsi_rel_id = NSE_NO_VSI;

		err = nse_initialize_vf_entry(vf);
		if (err) {
			dev_err(dev, "Failed to initialize the VF entry for SRIOV VF\n");
			goto err_free_entries;
		}

		vf->vf_sw_id = pf->first_sw;

		hash_add_rcu(vfs->table, &vf->entry, vf_id);
	}
	return 0;

err_free_entries:
	nse_free_vf_entries(pf);
	return err;
}

/**
 * nse_ena_vfs - enable VFs so they are ready to be used
 * @pf: pointer to the PF structure
 * @num_vfs: number of VFs to enable
 */
static int nse_ena_vfs(struct nse_pf *pf, u16 num_vfs)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	int ret;

	nse_debug(hw, NSE_DBG_SYS, "[%s] - enter: num_vfs=%d\n", __func__, num_vfs);

	/* Disable global interrupt 0 so we don't try to handle the VFLR. */
	wr32(hw, NSE_REG_INT_DYN_CTLN(pf->misc_irq_idx),
	     (NSE_REG_INT_DYN_CTLN_INTMSK_VLD_M | NSE_REG_INT_DYN_CTLN_INTMSK_M));
	set_bit(NSE_OICR_INTR_DIS, pf->state);
	nse_flush(hw);

	mutex_lock(&pf->vfs.table_lock);

	ret = nse_set_per_vf_res(pf, num_vfs);
	if (ret) {
		dev_err(dev, "Not enough resources for %d VFs, err %d. Try with fewer number of VFs\n",
			num_vfs, ret);
		goto err_unroll_intr;
	}

	ret = nse_create_vf_entries(pf, num_vfs);
	if (ret) {
		dev_err(dev, "Failed to allocate VF entries for %d VFs\n",
			num_vfs);
		goto err_unroll_per_vf_res;
	}

	ret = nse_start_vfs(pf, num_vfs);
	if (ret) {
		dev_err(dev, "Failed to start %d VFs, err %d\n", num_vfs, ret);
		ret = -EAGAIN;
		goto err_unroll_vf_entries;
	}

	ret = nse_create_vfs_sysfs(pf, num_vfs);
	if (ret) {
		dev_err(dev, "Failed to create vfs sysfs, err %d\n", ret);
		goto err_unroll_start_vfs;
	}

	ret = nse_eswitch_configure(pf);
	if (ret) {
		dev_err(dev, "Failed to configure eswitch, err %d\n", ret);
		goto err_unroll_vf_sysfs;
	}

	nse_debug(hw, NSE_DBG_SYS, "[%s] about to call pci_enable_sriov()\n", __func__);

	ret = pci_enable_sriov(pf->pdev, num_vfs);
	if (ret) {
		dev_err(dev, "FAIL: enable_sriov(num_vfs = %d)\n", num_vfs);
		goto err_unroll_eswitch;
	}

	clear_bit(NSE_VF_DIS, pf->state);

	nse_debug(hw, NSE_DBG_SYS, "[%s] DONE successful\n", __func__);

	/* rearm global interrupts */
	if (test_and_clear_bit(NSE_OICR_INTR_DIS, pf->state))
		nse_irq_dynamic_ena(hw, NULL, NULL);

	mutex_unlock(&pf->vfs.table_lock);

	nse_debug(hw, NSE_DBG_SYS, "[%s] - exit: ret=0\n", __func__);

	return 0;

err_unroll_eswitch:
	nse_eswitch_release(pf);

err_unroll_vf_sysfs:
	nse_destroy_vfs_sysfs(pf);

err_unroll_start_vfs:
	nse_start_vfs_rollback(pf);

err_unroll_vf_entries:
	nse_free_vf_entries(pf);

err_unroll_per_vf_res:

	/* rollback: nse_set_per_vf_res() -> nse_sriov_set_msix_res() */
	nse_sriov_free_msix_res(pf);

err_unroll_intr:

	mutex_unlock(&pf->vfs.table_lock);

	/* rearm interrupts here */
	nse_irq_dynamic_ena(hw, NULL, NULL);
	clear_bit(NSE_OICR_INTR_DIS, pf->state);

	nse_debug(hw, NSE_DBG_SYS, "[%s] - exit: ret=%d\n", __func__, ret);

	return ret;
}

/**
 * nse_pci_sriov_ena - Enable or change number of VFs
 * @pf: pointer to the PF structure
 * @num_vfs: number of VFs to allocate
 *
 * Returns 0 on success and negative on failure
 */
static int nse_pci_sriov_ena(struct nse_pf *pf, int num_vfs)
{
	int pre_existing_vfs = pci_num_vf(pf->pdev);
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	if (pre_existing_vfs && pre_existing_vfs != num_vfs)
		nse_free_vfs(pf);
	else if (pre_existing_vfs && pre_existing_vfs == num_vfs)
		return 0;

	if (num_vfs > pf->vfs.num_supported) {
		dev_err(dev, "Can't enable %d VFs, max VFs supported is %d\n",
			num_vfs, pf->vfs.num_supported);
		return -EOPNOTSUPP;
	}

	if (nse_is_pf_in_active_lag(pf)) {
		dev_err(dev, "Can't enable VFs because pf is in hw lag\n");
		return -EOPNOTSUPP;
	}

	dev_info(dev, "Enabling %d VFs\n", num_vfs);
	err = nse_ena_vfs(pf, num_vfs);
	if (err) {
		dev_err(dev, "FAIL: ena_vfs(), err=%d\n", err);
		nse_dev_err_errno(dev, err, "Failed to enable SR-IOV");
		return err;
	}

	set_bit(NSE_FLAG_SRIOV_ENA, pf->flags);

	pf->vfs.num_enabled = num_vfs;

	return 0;
}

/**
 * nse_check_sriov_allowed - check if SR-IOV is allowed based on various checks
 * @pf: PF to enabled SR-IOV on
 */
static int nse_check_sriov_allowed(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);

	if (!test_bit(NSE_FLAG_SRIOV_CAPABLE, pf->flags)) {
		dev_err(dev, "This device is not capable of SR-IOV\n");
		return -EOPNOTSUPP;
	}

	if (!nse_pf_state_is_nominal(pf)) {
		dev_err(dev, "Cannot enable SR-IOV, device not ready\n");
		return -EBUSY;
	}

	return 0;
}

/**
 * nse_sriov_configure - Enable or change number of VFs via sysfs
 * @pdev: pointer to a pci_dev structure
 * @num_vfs: number of VFs to allocate or 0 to free VFs
 *
 * This function is called when the user updates the number of VFs in sysfs. On
 * success return whatever num_vfs was set to by the caller. Return negative on
 * failure.
 */
int nse_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct nse_pf *pf = pci_get_drvdata(pdev);
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	err = nse_check_sriov_allowed(pf);
	if (err)
		return err;

	if (!num_vfs) {
		if (!pci_vfs_assigned(pdev)) {
			nse_free_vfs(pf);

			return 0;
		}

		dev_err(dev, "can't free VFs because some are assigned to VMs.\n");
		return -EBUSY;
	}

	err = nse_pci_sriov_ena(pf, num_vfs);
	if (err)
		return err;

	return num_vfs;
}

#define NSE_VF_ID_OFFSET 4

void nse_process_vflr_event(struct nse_pf *pf, struct nse_rq_event_info *event)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_vf *vf;
	unsigned int bkt;
	struct nse_aqc_vflr_event *vflr_evt = (struct nse_aqc_vflr_event *)event->msg_buf;
	u32 vf_offset;
	u32 reg_idx, bit_idx;
	int i = 0;

	if (!nse_has_vfs(pf)) {
		nse_debug(hw, NSE_DBG_SRIOV, "[%s] SRIOV VFs not enabled, skip\n", __func__);
		return;
	}

	nse_debug(hw, NSE_DBG_SRIOV, "[%s] vflr_evt content: pcore_id=%d, bitmap=\n",
								__func__, vflr_evt->pcore_id);
	for (i = 0; i < 8; i++)
		nse_debug(hw, NSE_DBG_SRIOV, "\t [%d]=%X\n", i, le32_to_cpu(vflr_evt->vf_flr[i]));

	if (vflr_evt->pcore_id != hw->pcore_id) {
		nse_debug(hw, NSE_DBG_SRIOV, "[%s] my->pcore_id=%d, this evt is NOT for me\n",
								__func__, hw->pcore_id);
		return;
	}

	mutex_lock(&pf->vfs.table_lock);

	nse_for_each_vf(pf, bkt, vf) {
		vf_offset = nse_abs_vf_id(hw, vf->vf_id);
		if (vf_offset < NSE_VF_ID_OFFSET) {
			nse_debug(hw, NSE_DBG_SRIOV, "[%s] bad vf_abs_id=%d, rel_id=%d, func_caps.first_vf=%d\n",
				  __func__, vf_offset, vf->vf_id, hw->func_caps.first_vf);
			continue;
		}

		vf_offset -= NSE_VF_ID_OFFSET;

		reg_idx = vf_offset / 32;
		bit_idx = vf_offset % 32;

		if (le32_to_cpu(vflr_evt->vf_flr[reg_idx]) & BIT(bit_idx)) {
			nse_debug(hw, NSE_DBG_SRIOV, "[%s]: VF (abs_id=%d, rel_id=%d) happen VFLR (evt bitmap[%d][bit=%d]=1), handle it\n",
				  __func__, nse_abs_vf_id(hw, vf->vf_id),
					  vf->vf_id, reg_idx, bit_idx);

			nse_reset_vf(vf, NSE_VF_RESET_VFLR | NSE_VF_RESET_LOCK);
		}
	}

	mutex_unlock(&pf->vfs.table_lock);
}

void nse_process_vflr_event_mini(struct nse_pf *pf, struct nse_rq_event_info *event)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_vf *vf;
	unsigned int bkt;
	struct nse_aqc_vflr_event_mini *evt = (struct nse_aqc_vflr_event_mini *)event->msg_buf;
	u32 vf_abs_id;

	nse_debug(hw, NSE_DBG_SRIOV, "[%s] vflr_evt_mini content: pcore_id=%d, pcore_pf_id=%d, vf_abs_id=%d\n",
								__func__, evt->pcore_id,
									evt->pcore_pf_id,
									evt->vf_abs_id);

	if (evt->pcore_id != hw->pcore_id ||
		evt->pcore_pf_id != hw->pcore_pf_id) {
		nse_debug(hw, NSE_DBG_SRIOV, "[%s] bad: (evt->pcore_id=%d, my=%d) or (evt->pcore_pf_id=%d, my=%d)\n",
									__func__, evt->pcore_id,
										hw->pcore_id,
										evt->pcore_pf_id,
										hw->pcore_pf_id);
		return;
	}

	if (!nse_has_vfs(pf)) {
		nse_debug(hw, NSE_DBG_SRIOV, "[%s] SRIOV VFs not enabled, skip\n", __func__);
		return;
	}

	mutex_lock(&pf->vfs.table_lock);

	nse_for_each_vf(pf, bkt, vf) {
		vf_abs_id = nse_abs_vf_id(hw, vf->vf_id);
		if (vf_abs_id < NSE_VF_ID_OFFSET) {
			nse_debug(hw, NSE_DBG_SRIOV, "[%s] BAD vf_abs_id=%d, rel_id=%d, func_caps.first_vf=%d\n",
				  __func__, vf_abs_id, vf->vf_id, hw->func_caps.first_vf);
			continue;
		}

		if (evt->vf_abs_id == vf_abs_id) {
			nse_debug(hw, NSE_DBG_SRIOV, "[%s]: VF (abs_id=%d, rel_id=%d) happen VFLR, handle it\n",
				  __func__, vf_abs_id, vf->vf_id);

			nse_reset_vf(vf, NSE_VF_RESET_VFLR | NSE_VF_RESET_LOCK);

			break;
		}
	}

	mutex_unlock(&pf->vfs.table_lock);
}

/**
 * nse_vf_lan_overflow_event - handle LAN overflow event for a VF
 * @pf: PF that the LAN overflow event happened on
 * @event: structure holding the event information for the LAN overflow event
 *
 * Determine if the LAN overflow event was caused by a VF queue. If it was not
 * caused by a VF, do nothing. If a VF caused this LAN overflow event trigger a
 * reset on the offending VF.
 */
void
nse_vf_lan_overflow_event(struct nse_pf *pf, struct nse_rq_event_info *event)
{
}

/**
 * nse_set_vf_spoofchk
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @ena: flag to enable or disable feature
 *
 * Enable or disable VF spoof checking
 */
int nse_set_vf_spoofchk(struct net_device *netdev, int vf_id, bool ena)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_pf *pf = np->vsi->back;
	struct nse_vsi *vf_vsi;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vf *vf;
	int ret;

	if (nse_is_eswitch_mode_switchdev(pf)) {
		dev_info(dev, "not allow set_vf_spoofchk in switchdev mode\n");
		return -EOPNOTSUPP;
	}

	vf = nse_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	ret = nse_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	vf_vsi = nse_get_vf_vsi(vf);
	if (!vf_vsi) {
		netdev_err(netdev, "VSI %d for VF %d is null\n",
			   vf->lan_vsi_idx, vf->vf_id);
		ret = -EINVAL;
		goto out_put_vf;
	}

	if (vf_vsi->type != NSE_VSI_VF) {
		netdev_err(netdev, "Type %d of VSI (abs_num=%d) for VF %d is no NSE_VSI_VF\n",
			   vf_vsi->type, vf_vsi->vsi_abs_num, vf->vf_id);
		ret = -ENODEV;
		goto out_put_vf;
	}

	if (ena == vf->spoofchk) {
		dev_dbg(dev, "VF spoofchk already %s\n", ena ? "ON" : "OFF");
		ret = 0;
		goto out_put_vf;
	}

	ret = nse_vsi_apply_spoofchk(vf_vsi, ena);
	if (ret)
		nse_dev_err_errno(dev, ret,
				  "Failed to set spoofchk %s for VF %d VSI (abs_num=%d)",
				  ena ? "ON" : "OFF", vf->vf_id,
				  vf_vsi->vsi_abs_num);
	else
		vf->spoofchk = ena;

out_put_vf:
	nse_put_vf(vf);
	return ret;
}

/**
 * nse_get_vf_cfg
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @ivi: VF configuration structure
 *
 * return VF configuration
 */
int
nse_get_vf_cfg(struct net_device *netdev, int vf_id, struct ifla_vf_info *ivi)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct nse_vf *vf;
	int ret;

	vf = nse_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	ret = nse_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	ivi->vf = vf_id;
	ether_addr_copy(ivi->mac, vf->hw_lan_addr.addr);

	/* VF configuration for VLAN and applicable QoS */
	ivi->vlan = nse_vf_get_port_vlan_id(vf);
	ivi->qos = nse_vf_get_port_vlan_prio(vf);
#ifdef IFLA_VF_VLAN_INFO_MAX
	if (nse_vf_is_port_vlan_ena(vf))
		ivi->vlan_proto = cpu_to_be16(nse_vf_get_port_vlan_tpid(vf));
#endif /* IFLA_VF_VLAN_INFO_MAX */

	ivi->trusted = vf->trusted;
	ivi->spoofchk = vf->spoofchk;
	if (!vf->link_forced)
		ivi->linkstate = IFLA_VF_LINK_STATE_AUTO;
	else if (vf->link_up)
		ivi->linkstate = IFLA_VF_LINK_STATE_ENABLE;
	else
		ivi->linkstate = IFLA_VF_LINK_STATE_DISABLE;
	ivi->max_tx_rate = vf->max_tx_rate;
	ivi->min_tx_rate = vf->min_tx_rate;

out_put_vf:
	nse_put_vf(vf);
	return ret;
}

/**
 * nse_set_vf_mac
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @mac: MAC address
 *
 * program VF MAC address
 */
int nse_set_vf_mac(struct net_device *netdev, int vf_id, u8 *mac)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct nse_vf *vf;
	int ret;

	if (is_multicast_ether_addr(mac)) {
		netdev_err(netdev, "%pM not a valid unicast address\n", mac);
		return -EINVAL;
	}

	vf = nse_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	/* nothing left to do, unicast MAC already set */
	if (ether_addr_equal(vf->dev_lan_addr.addr, mac) &&
	    ether_addr_equal(vf->hw_lan_addr.addr, mac)) {
		ret = 0;
		goto out_put_vf;
	}

	ret = nse_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	mutex_lock(&vf->cfg_lock);

	/* VF is notified of its new MAC via the PF's response to the
	 * VIRTCHNL_OP_GET_VF_RESOURCES message after the VF has been reset
	 */
	ether_addr_copy(vf->dev_lan_addr.addr, mac);
	ether_addr_copy(vf->hw_lan_addr.addr, mac);
	if (is_zero_ether_addr(mac)) {
		/* VF will send VIRTCHNL_OP_ADD_ETH_ADDR message with its MAC */
		vf->pf_set_mac = false;
		netdev_info(netdev, "Removing MAC on VF %d. VF driver will be reinitialized\n",
			    vf->vf_id);
	} else {
		/* PF will add MAC rule for the VF */
		vf->pf_set_mac = true;
		netdev_info(netdev, "Setting MAC %pM on VF %d. VF driver will be reinitialized\n",
			    mac, vf_id);
	}

	nse_reset_vf(vf, NSE_VF_RESET_NOTIFY);
	mutex_unlock(&vf->cfg_lock);

out_put_vf:
	nse_put_vf(vf);
	return ret;
}

/**
 * nse_set_vf_trust
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @trusted: Boolean value to enable/disable trusted VF
 *
 * Enable or disable a given VF as trusted
 */
int nse_set_vf_trust(struct net_device *netdev, int vf_id, bool trusted)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vf *vf;
	int ret;

	vf = nse_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	if (nse_is_eswitch_mode_switchdev(pf)) {
		dev_info(dev, "Trusted VF is forbidden in switchdev mode\n");
		return -EOPNOTSUPP;
	}

	ret = nse_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	/* Check if already trusted */
	if (trusted == vf->trusted) {
		ret = 0;
		goto out_put_vf;
	}

	mutex_lock(&vf->cfg_lock);

	vf->trusted = trusted;

	nse_reset_vf(vf, NSE_VF_RESET_NOTIFY);

	dev_info(nse_pf_to_dev(pf), "VF %u is now %strusted\n",
		 vf_id, trusted ? "" : "un");

	mutex_unlock(&vf->cfg_lock);

out_put_vf:
	nse_put_vf(vf);
	return ret;
}

/**
 * nse_set_vf_link_state
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @link_state: required link state
 *
 * Set VF's link state, irrespective of physical link state status
 */
int nse_set_vf_link_state(struct net_device *netdev, int vf_id, int link_state)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vf *vf;
	int ret;

	if (nse_is_eswitch_mode_switchdev(pf)) {
		dev_info(dev, "not allow set_vf_link_state in switchdev mode\n");
		return -EOPNOTSUPP;
	}

	vf = nse_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	ret = nse_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	switch (link_state) {
	case IFLA_VF_LINK_STATE_AUTO:
		vf->link_forced = false;
		break;
	case IFLA_VF_LINK_STATE_ENABLE:
		vf->link_forced = true;
		vf->link_up = true;
		break;
	case IFLA_VF_LINK_STATE_DISABLE:
		vf->link_forced = true;
		vf->link_up = false;
		break;
	default:
		ret = -EINVAL;
		goto out_put_vf;
	}

	if (vf->repr) {
		struct net_device *pr_netdev = vf->repr->netdev;
		unsigned int flags = pr_netdev->flags;

		flags = vf->link_up ? flags | IFF_UP : flags & ~IFF_UP;
		dev_change_flags(pr_netdev, flags, NULL);
	}

	nse_vc_notify_vf_link_state(vf, true);

out_put_vf:
	nse_put_vf(vf);
	return ret;
}

/**
 * nse_calc_all_vfs_min_tx_rate - calculate cumulative min Tx rate on all VFs
 * @pf: PF associated with VFs
 */
static unsigned int nse_calc_all_vfs_min_tx_rate(struct nse_pf *pf)
{
	struct nse_vf *vf;
	unsigned int bkt;
	unsigned int rate = 0;

	rcu_read_lock();
	nse_for_each_vf_rcu(pf, bkt, vf)
		rate += vf->min_tx_rate;
	rcu_read_unlock();

	return rate;
}

/**
 * nse_min_tx_rate_oversubscribed - check if min Tx rate causes oversubscription
 * @vf: VF trying to configure min_tx_rate
 * @min_tx_rate: min Tx rate in Mbps
 *
 * Check if the min_tx_rate being passed in will cause oversubscription of total
 * min_tx_rate based on the current link speed and all other VFs configured
 * min_tx_rate
 *
 * Return true if the passed min_tx_rate would cause oversubscription, else
 * return false
 */
static bool
nse_min_tx_rate_oversubscribed(struct nse_vf *vf, int min_tx_rate)
{
	struct nse_pf *pf = vf->pf;
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);
	unsigned int all_vfs_min_tx_rate;
	unsigned int link_speed_mbps;

	if (WARN_ON(!vsi))
		return false;

	link_speed_mbps = nse_get_link_speed_mbps(&pf->hw);
	all_vfs_min_tx_rate = nse_calc_all_vfs_min_tx_rate(pf);

	/* this VF's previous rate is being overwritten */
	all_vfs_min_tx_rate -= vf->min_tx_rate;

	if (all_vfs_min_tx_rate + min_tx_rate > link_speed_mbps) {
		dev_err(nse_pf_to_dev(vf->pf), "min_tx_rate of %d Mbps on VF %u would cause oversubscription of %d Mbps based on the current link speed %d Mbps\n",
			min_tx_rate, vf->vf_id,
			all_vfs_min_tx_rate + min_tx_rate - link_speed_mbps,
			link_speed_mbps);
		return true;
	}

	return false;
}

/**
 * nse_set_vf_bw - set min/max VF bandwidth
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @min_tx_rate: Minimum Tx rate in Mbps
 * @max_tx_rate: Maximum Tx rate in Mbps
 */
int
nse_set_vf_bw(struct net_device *netdev, int vf_id, int min_tx_rate,
	      int max_tx_rate)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct nse_vsi *vsi;
	struct device *dev;
	struct nse_vf *vf;
	int ret;

	dev = nse_pf_to_dev(pf);

	vf = nse_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	ret = nse_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		ret = -EINVAL;
		goto out_put_vf;
	}

	/* when max_tx_rate is zero that means no max Tx rate limiting, so only
	 * check if max_tx_rate is non-zero
	 */
	if (max_tx_rate && min_tx_rate > max_tx_rate) {
		dev_err(dev, "Cannot set min Tx rate %d Mbps greater than max Tx rate %d Mbps\n",
			min_tx_rate, max_tx_rate);
		ret = -EINVAL;
		goto out_put_vf;
	}

	if (min_tx_rate && nse_is_dcb_active(pf)) {
		dev_err(dev, "DCB on PF is currently enabled. VF min Tx rate limiting not allowed on this PF.\n");
		ret = -EOPNOTSUPP;
		goto out_put_vf;
	}

	if (nse_min_tx_rate_oversubscribed(vf, min_tx_rate)) {
		ret = -EINVAL;
		goto out_put_vf;
	}

	if (vf->min_tx_rate != (unsigned int)min_tx_rate) {
		ret = nse_set_min_bw_limit(vsi, min_tx_rate * 1000);
		if (ret) {
			dev_err(dev, "Unable to set min-tx-rate for VF %d\n",
				vf->vf_id);
			goto out_put_vf;
		}

		vf->min_tx_rate = min_tx_rate;
	}

	if (vf->max_tx_rate != (unsigned int)max_tx_rate) {
		ret = nse_set_max_bw_limit(vsi, max_tx_rate * 1000);
		if (ret) {
			dev_err(dev, "Unable to set max-tx-rate for VF %d\n",
				vf->vf_id);
			goto out_put_vf;
		}

		vf->max_tx_rate = max_tx_rate;
	}

out_put_vf:
	nse_put_vf(vf);
	return ret;
}

/**
 * nse_get_vf_stats - populate some stats for the VF
 * @netdev: the netdev of the PF
 * @vf_id: the host OS identifier (0-255)
 * @vf_stats: pointer to the OS memory to be initialized
 */
int nse_get_vf_stats(struct net_device *netdev, int vf_id,
		     struct ifla_vf_stats *vf_stats)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct nse_vsi_hw_stats *stats;
	struct nse_vsi *vsi;
	struct nse_vf *vf;
	int ret;

	vf = nse_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	ret = nse_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		ret = -EINVAL;
		goto out_put_vf;
	}

	nse_update_vsi_hw_stats(vsi);
	stats = &vsi->hw_stats;

	memset(vf_stats, 0, sizeof(*vf_stats));

	vf_stats->rx_packets = stats->rx_gpkt;
	vf_stats->tx_packets = stats->tx_gptc;
	vf_stats->rx_bytes   = stats->rx_goct;
	vf_stats->tx_bytes   = stats->tx_gotc;
	vf_stats->broadcast  = stats->rx_bpkt;
	vf_stats->multicast  = stats->rx_mpkt;
	vf_stats->rx_dropped = stats->rx_dpkt;
	vf_stats->tx_dropped = stats->tx_dptc;

out_put_vf:
	nse_put_vf(vf);
	return ret;
}

/**
 * nse_is_supported_port_vlan_proto - make sure the vlan_proto is supported
 * @hw: hardware structure used to check the VLAN mode
 * @vlan_proto: VLAN TPID being checked
 *
 * If the device is configured in Double VLAN Mode (DVM), then both ETH_P_8021Q
 * and ETH_P_8021AD are supported. If the device is configured in Single VLAN
 * Mode (SVM), then only ETH_P_8021Q is supported.
 */
static bool
nse_is_supported_port_vlan_proto(struct nse_hw *hw, u16 vlan_proto)
{
	if (vlan_proto == hw->stag_ethertype)	/* 88A8 or 8100 */
		return true;
	else
		return false;
}

#ifdef IFLA_VF_VLAN_INFO_MAX
/**
 * nse_set_vf_port_vlan
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @vlan_id: VLAN ID being set
 * @qos: priority setting
 * @vlan_proto: VLAN protocol
 *
 * program VF Port VLAN ID and/or QoS
 */
int
nse_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id, u8 qos,
		     __be16 vlan_proto)
#else
int
nse_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id, u8 qos)
#endif /* IFLA_VF_VLAN_INFO_MAX */
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
#ifdef IFLA_VF_VLAN_INFO_MAX
	u16 local_vlan_proto = ntohs(vlan_proto);
#else
	u16 local_vlan_proto = ETH_P_8021Q;
#endif
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vf *vf;
	int ret;

	if (!nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_TDM_SUPPORT_PVID)) {
		dev_err(dev, "[%s] BAD: this mac_type does not support port-based VLAN\n",
			__func__);
		return -EOPNOTSUPP;
	}

	if (nse_is_eswitch_mode_switchdev(pf)) {
		if (!vlan_id)
			return 0;

		dev_info(dev, "not allow set_vf_port_vlan in switchdev mode\n");
		return -EOPNOTSUPP;
	}

	if (vlan_id >= VLAN_N_VID || qos > 7) {
		dev_err(dev, "Invalid Port VLAN parameters for VF %d, ID %d, QoS %d\n",
			vf_id, vlan_id, qos);
		return -EINVAL;
	}

	if (!nse_is_supported_port_vlan_proto(&pf->hw, local_vlan_proto)) {
		dev_err(dev, "VF VLAN protocol 0x%04x is not supported\n",
			local_vlan_proto);
		return -EPROTONOSUPPORT;
	}

	vf = nse_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	ret = nse_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	if (nse_vf_get_port_vlan_prio(vf) == qos &&
	    nse_vf_get_port_vlan_tpid(vf) == local_vlan_proto &&
	    nse_vf_get_port_vlan_id(vf) == vlan_id) {
		/* duplicate request, so just return success */
		dev_info(dev, "Duplicate port VLAN %u, QoS %u, TPID 0x%04x request\n",
			vlan_id, qos, local_vlan_proto);
		ret = 0;
		goto out_put_vf;
	}

	mutex_lock(&vf->cfg_lock);

	vf->port_vlan_info =
		NSE_VLAN(local_vlan_proto, vlan_id, qos, NSE_FWD_TO_VSI);
	if (nse_vf_is_port_vlan_ena(vf))
		dev_info(dev, "Setting VLAN %u, QoS %u, TPID 0x%04x on VF %d\n",
			 vlan_id, qos, local_vlan_proto, vf_id);
	else
		dev_info(dev, "Clearing port VLAN on VF %d\n", vf_id);

	nse_reset_vf(vf, NSE_VF_RESET_NOTIFY);
	mutex_unlock(&vf->cfg_lock);

out_put_vf:
	nse_put_vf(vf);
	return ret;
}

/**
 * nse_restore_all_vfs_msi_state - restore VF MSI state after PF FLR
 * @pdev: pointer to a pci_dev structure
 *
 * Called when recovering from a PF FLR to restore interrupt capability to
 * the VFs.
 */
void nse_restore_all_vfs_msi_state(struct pci_dev *pdev)
{
	u16 vf_id;
	int pos;

	if (!pci_num_vf(pdev))
		return;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (pos) {
		struct pci_dev *vfdev;

		pci_read_config_word(pdev, pos + PCI_SRIOV_VF_DID,
				     &vf_id);
		vfdev = pci_get_device(pdev->vendor, vf_id, NULL);
		while (vfdev) {
			if (vfdev->is_virtfn && vfdev->physfn == pdev)
				pci_restore_msi_state(vfdev);
			vfdev = pci_get_device(pdev->vendor, vf_id,
					       vfdev);
		}
	}
}

/**
 * nse_get_vf_port_info - populate the iidc_vf_port_info structure
 * @pf: ptr to the struct ice_pf
 * @vf_id: VF ID used to populate the iidc_vf_port_info
 * @vf_port_info: structure to populate with the VF's port information
 */
int nse_get_vf_port_info(struct nse_pf *pf, u16 vf_id,
			 struct iidc_vf_port_info *vf_port_info)
{
	struct nse_vf *vf;

	vf = nse_get_vf_by_id(pf, vf_id);
	if (!vf) {
		dev_err(nse_pf_to_dev(pf), "Invalid VF ID %u\n", vf_id);
		return -EINVAL;
	}

	/* don't allow query if VF and/or PF are in reset */
	if (nse_is_vf_disabled(vf)) {
		nse_put_vf(vf);
		return -EAGAIN;
	}

	vf_port_info->vf_id = vf->vf_id;
	vf_port_info->vsi_abs_id = vf->vf_vsi_abs_id;
	if (nse_vf_is_port_vlan_ena(vf)) {
		vf_port_info->port_vlan_id = nse_vf_get_port_vlan_id(vf);
		vf_port_info->port_vlan_tpid = nse_vf_get_port_vlan_tpid(vf);
	}

	nse_put_vf(vf);
	return 0;
}

