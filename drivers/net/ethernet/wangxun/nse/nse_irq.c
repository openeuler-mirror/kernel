// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_lib.h"
#include "nse_irq.h"

static int nse_alloc_and_fill_msix_entries(struct nse_pf *pf, int nvec)
{
	int i;

	if (nse_no_irq)
		return 0;

	pf->msix_entries = kcalloc(nvec, sizeof(*pf->msix_entries),
				   GFP_KERNEL);
	if (!pf->msix_entries)
		return -ENOMEM;

	for (i = 0; i < nvec; i++) {
		pf->msix_entries[i].entry = i;
		pf->msix_entries[i].vector = nse_get_irq_num(pf, i);
	}

	return 0;
}

static void nse_dis_msix(struct nse_pf *pf)
{
	if (nse_no_irq)
		return;

	pci_free_irq_vectors(pf->pdev);
}

static int nse_ena_msix(struct nse_pf *pf, int nvec)
{
	if (nvec > pf->irq_space_size)
		nvec = pf->irq_space_size;

	if (nse_no_irq)
		return nvec;

	return pci_alloc_irq_vectors(pf->pdev, NSE_MIN_MSIX, nvec,
				     PCI_IRQ_MSIX);
}

static void nse_adj_vec_clear(int *src, int size)
{
	int i;

	for (i = 0; i < size; i++)
		src[i] = 0;
}

static void nse_adj_vec_sum(int *dst, int *src, int size)
{
	int i;

	for (i = 0; i < size; i++)
		dst[i] += src[i];
}

/**
 * nse_ena_msix_range - request a range of MSI-X vectors from the OS
 * @pf: board private structure
 *
 * The driver tries to enable best-case scenario MSI-X vectors. If that doesn't
 * succeed than adjust to irqs number returned by kernel.
 *
 * The fall-back logic is described below with each [#] represented needed irqs
 * number for the step. If any of the steps is lower than received number, then
 * return the number of MSI-X. If any of the steps is greater, then check next
 * one. If received value is lower than irqs value in last step return error.
 *
 * Step [0]: Enable the best-case scenario MSI-X vectors.
 *
 * Step [1]: Enable MSI-X vectors with eswitch support disabled
 *
 * Step [2]: Enable MSI-X vectors with the number of vectors reserved for
 * MACVLAN and Scalable IOV support reduced by a factor of 2.
 *
 * Step [3]: Enable MSI-X vectors with the number of vectors reserved for
 * MACVLAN and Scalable IOV support reduced by a factor of 4.
 *
 * Step [4]: Enable MSI-X vectors with MACVLAN and Scalable IOV support
 * disabled.
 *
 * Step [5]: Enable MSI-X vectors with the number of pf->num_lan_msix reduced
 * by a factor of 2 from the previous step (i.e. num_online_cpus() / 2).
 * Also, with the number of pf->num_rdma_msix reduced by a factor of ~2 from the
 * previous step (i.e. num_online_cpus() / 2 + NSE_RDMA_NUM_AEQ_MSIX).
 *
 * Step [6]: Same as step [3], except reduce both by a factor of 4.
 *
 * Step [7]: Enable the bare-minimum MSI-X vectors.
 *
 * Each feature has separate table with needed irqs in each step. Sum of these
 * tables is tracked in adj_vec to show needed irqs in each step. Separate
 * tables are later use to set correct number of irqs for each feature based on
 * choosed step.
 */
static int nse_ena_msix_range(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);

#define NSE_ADJ_VEC_STEPS 8
#define NSE_ADJ_VEC_WORST_CASE 0
#define NSE_ADJ_VEC_BEST_CASE (NSE_ADJ_VEC_STEPS - 1)
	int num_cpus = num_online_cpus();
	int rdma_adj_vec[NSE_ADJ_VEC_STEPS] = { 0 };
	int lan_adj_vec[NSE_ADJ_VEC_STEPS] = { 0 };
	int adj_vec[NSE_ADJ_VEC_STEPS] = {
		NSE_OICR_MSIX, NSE_OICR_MSIX, NSE_OICR_MSIX,
		NSE_OICR_MSIX, NSE_OICR_MSIX, NSE_OICR_MSIX,
		NSE_OICR_MSIX, NSE_OICR_MSIX,
	};
	int macvlan_adj_vec[NSE_ADJ_VEC_STEPS] = { 0 };
	int eswitch_adj_vec[NSE_ADJ_VEC_STEPS] = { 0 };
	int adj_step = NSE_ADJ_VEC_BEST_CASE;
	int err = -ENOSPC;
	int v_actual, i;
	int val;
	int needed = 0;

	needed += NSE_OICR_MSIX;

	if (hw->is_only_lan_in_chan)
		val = num_cpus;
	else
		val = num_cpus / 4;		/* for 4x10G, 4x25G*/

	lan_adj_vec[0] = NSE_MIN_LAN_MSIX;
	lan_adj_vec[1] = max_t(int, val / 4, NSE_MIN_LAN_MSIX);
	lan_adj_vec[2] = max_t(int, val / 2, NSE_MIN_LAN_MSIX);
	lan_adj_vec[3] = max_t(int, val, NSE_MIN_LAN_MSIX);
	lan_adj_vec[4] = lan_adj_vec[3];
	lan_adj_vec[5] = lan_adj_vec[3];
	lan_adj_vec[6] = lan_adj_vec[3];
	lan_adj_vec[7] = lan_adj_vec[3];

	for (i = 0; i < NSE_ADJ_VEC_STEPS; i++) {
		if (nse_main_vsi_max_lanirq_num && lan_adj_vec[i] > nse_main_vsi_max_lanirq_num)
			lan_adj_vec[i] = nse_main_vsi_max_lanirq_num;
	}

	needed += lan_adj_vec[NSE_ADJ_VEC_BEST_CASE];
	nse_adj_vec_sum(adj_vec, lan_adj_vec, NSE_ADJ_VEC_STEPS);

	if (test_bit(NSE_FLAG_ESWITCH_CAPABLE, pf->flags)) {
		/* align to nse_vsi_set_num_qs() -> case NSE_VSI_SWITCHDEV_CTRL: */
		if (hw->func_caps.vf_space_valid && hw->func_caps.vf_num)
			val = ((int)hw->func_caps.vf_num + 7) / 8;
		else
			val = 0;

		eswitch_adj_vec[NSE_ADJ_VEC_BEST_CASE] = val;

		needed += eswitch_adj_vec[NSE_ADJ_VEC_BEST_CASE];
		nse_adj_vec_sum(adj_vec, eswitch_adj_vec, NSE_ADJ_VEC_STEPS);
	} else {
		nse_adj_vec_clear(eswitch_adj_vec, NSE_ADJ_VEC_STEPS);
	}

	i = pf->sw_conf.max_macvlans;	/* 64 for asic, 16 for fpga */

	if (hw->hw_conf.hw_platform == NSE_HW_PLATFORM_FPGA) {
		macvlan_adj_vec[0] = 0;
		macvlan_adj_vec[1] = (i * NSE_DFLT_VEC_VMDQ_VSI) / 4;	/* 4 */
		macvlan_adj_vec[2] = (i * NSE_DFLT_VEC_VMDQ_VSI) / 2;	/* 8 */
		macvlan_adj_vec[3] = (i * NSE_DFLT_VEC_VMDQ_VSI);
		macvlan_adj_vec[4] = (i * NSE_DFLT_VEC_VMDQ_VSI);
		macvlan_adj_vec[5] = (i * NSE_DFLT_VEC_VMDQ_VSI);
		macvlan_adj_vec[6] = (i * NSE_DFLT_VEC_VMDQ_VSI);
		macvlan_adj_vec[7] = (i * NSE_DFLT_VEC_VMDQ_VSI);
	} else {	/* FPGA */
		macvlan_adj_vec[0] = 0;
		macvlan_adj_vec[1] = (i * NSE_DFLT_VEC_VMDQ_VSI) / 32;
		macvlan_adj_vec[2] = (i * NSE_DFLT_VEC_VMDQ_VSI) / 16;
		macvlan_adj_vec[3] = (i * NSE_DFLT_VEC_VMDQ_VSI) / 8;
		macvlan_adj_vec[4] = (i * NSE_DFLT_VEC_VMDQ_VSI) / 4;
		macvlan_adj_vec[5] = (i * NSE_DFLT_VEC_VMDQ_VSI) / 2;
		macvlan_adj_vec[6] = (i * NSE_DFLT_VEC_VMDQ_VSI);
		macvlan_adj_vec[7] = (i * NSE_DFLT_VEC_VMDQ_VSI);
	}

	if (test_bit(NSE_FLAG_VMDQ_ENA, pf->flags)) {
		needed += macvlan_adj_vec[NSE_ADJ_VEC_BEST_CASE];
		nse_adj_vec_sum(adj_vec, macvlan_adj_vec, NSE_ADJ_VEC_STEPS);
	} else {
		nse_adj_vec_clear(macvlan_adj_vec, NSE_ADJ_VEC_STEPS);
	}

	if (hw->hw_conf.hw_platform == NSE_HW_PLATFORM_FPGA) {
		rdma_adj_vec[0] = NSE_MIN_RDMA_MSIX;

		rdma_adj_vec[1] = num_cpus / 4 > NSE_MIN_RDMA_MSIX ?
							num_cpus / 4 + NSE_RDMA_NUM_AEQ_MSIX :
							NSE_MIN_RDMA_MSIX,

		rdma_adj_vec[2] = rdma_adj_vec[1];
		rdma_adj_vec[3] = rdma_adj_vec[1];
		rdma_adj_vec[4] = rdma_adj_vec[1];
		rdma_adj_vec[5] = rdma_adj_vec[1];
		rdma_adj_vec[6] = rdma_adj_vec[1];
		rdma_adj_vec[7] = rdma_adj_vec[1];
	} else {	/* FPGA */

		if (hw->is_only_lan_in_chan)
			val = num_cpus;
		else
			val = num_cpus / 4;		/* for 4x10G, 4x25G*/

		rdma_adj_vec[0] = NSE_MIN_RDMA_MSIX;

		rdma_adj_vec[1] = val / 4 > NSE_MIN_RDMA_MSIX ?
							val / 4 + NSE_RDMA_NUM_AEQ_MSIX :
							NSE_MIN_RDMA_MSIX;

		rdma_adj_vec[2] = val / 2 > NSE_MIN_RDMA_MSIX ?
							val / 2 + NSE_RDMA_NUM_AEQ_MSIX :
							NSE_MIN_RDMA_MSIX;

		rdma_adj_vec[3] = val > NSE_MIN_RDMA_MSIX ?
							val + NSE_RDMA_NUM_AEQ_MSIX :
								NSE_MIN_RDMA_MSIX;

		rdma_adj_vec[4] = rdma_adj_vec[3];

		rdma_adj_vec[5] = rdma_adj_vec[3];

		rdma_adj_vec[6] = rdma_adj_vec[3];

		rdma_adj_vec[7] = rdma_adj_vec[3];
	}

	if (nse_chk_rdma_cap(pf)) {
		needed += rdma_adj_vec[NSE_ADJ_VEC_BEST_CASE];
		nse_adj_vec_sum(adj_vec, rdma_adj_vec, NSE_ADJ_VEC_STEPS);
	} else {
		nse_adj_vec_clear(rdma_adj_vec, NSE_ADJ_VEC_STEPS);
	}

	v_actual = nse_ena_msix(pf, needed);

	nse_debug(hw, NSE_DBG_SYS, "nse_ena_msix(needed = %d) return: v_actual=%d\n",
					needed, v_actual);

	if (v_actual < 0) {
		err = v_actual;
		goto err_out;
	} else if (v_actual < adj_vec[NSE_ADJ_VEC_WORST_CASE]) {
		dev_err(dev, "BAD: in %s: v_actual = %d, < , adj_vect[NSE_ADJ_VEC_WORST_CASE] = %d\n",
						__func__, v_actual,
							adj_vec[NSE_ADJ_VEC_WORST_CASE]);

		nse_dis_msix(pf);
		goto err_out;
	}

	for (i = NSE_ADJ_VEC_WORST_CASE + 1; i < NSE_ADJ_VEC_STEPS; i++) {
		if (v_actual < adj_vec[i]) {
			adj_step = i - 1;
			break;
		}
	}

	pf->num_lan_msix = lan_adj_vec[adj_step];
	pf->num_rdma_msix = rdma_adj_vec[adj_step];
	if (test_bit(NSE_FLAG_ESWITCH_CAPABLE, pf->flags) &&
	    !eswitch_adj_vec[adj_step]) {
		dev_warn(dev, "Not enough MSI-X for eswitch support, disabling feature\n");
		clear_bit(NSE_FLAG_ESWITCH_CAPABLE, pf->flags);
	}
	if (test_bit(NSE_FLAG_VMDQ_ENA, pf->flags) &&
	    !macvlan_adj_vec[adj_step]) {
		dev_warn(dev, "Not enough MSI-X for hardware MACVLAN support, disabling feature\n");
		clear_bit(NSE_FLAG_VMDQ_ENA, pf->flags);
	}

	return v_actual;

err_out:
	dev_err(dev, "Failed to enable MSI-X vectors\n");
	return  err;
}

/**
 * nse_init_interrupt_scheme - Determine proper interrupt scheme
 * @pf: board private structure to initialize
 */
int nse_init_interrupt_scheme(struct nse_pf *pf)
{
	int vectors;

	vectors = nse_ena_msix_range(pf);
	if (vectors < 0)
		return vectors;

	/* pf->msix_entries is used in idc and needs to be filled on kernel
	 * with new irq alloc API
	 */
	if (nse_alloc_and_fill_msix_entries(pf, vectors)) {
		nse_dis_msix(pf);
		return -ENOMEM;
	}
	/* set up vector assignment tracking */
	pf->irq_tracker_self_region =
		devm_kzalloc(nse_pf_to_dev(pf),
			     struct_size(pf->irq_tracker_self_region, list, vectors),
			     GFP_KERNEL);
	if (!pf->irq_tracker_self_region) {
		nse_dis_msix(pf);
		return -ENOMEM;
	}

	/* populate SW interrupts pool with number of OS granted IRQs. */
	pf->num_avail_sw_msix = (u16)vectors;
	pf->irq_tracker_self_region->num_entries = (u16)vectors;
	pf->irq_tracker_self_region->end = (u16)vectors;

	nse_debug(&pf->hw, NSE_DBG_SYS, "[%s]: pf->num_avail_sw_msix = %d\n",
					__func__, pf->num_avail_sw_msix);

	return 0;
}

/**
 * nse_clear_interrupt_scheme - Undo things done by nse_init_interrupt_scheme
 * @pf: board private structure
 */
void nse_clear_interrupt_scheme(struct nse_pf *pf)
{
	kfree(pf->msix_entries);

	pf->msix_entries = NULL;

	nse_dis_msix(pf);

	if (pf->irq_tracker_self_region) {
		devm_kfree(nse_pf_to_dev(pf), pf->irq_tracker_self_region);
		pf->irq_tracker_self_region = NULL;
	}
}

/**
 * nse_get_irq_num - get system irq number based on index from driver
 * @pf: board private structure
 * @idx: driver irq index
 */
int nse_get_irq_num(struct nse_pf *pf, int idx)
{
	if (nse_no_irq)
		return -EINVAL;

	return pci_irq_vector(pf->pdev, idx);
}

int nse_set_itr_interval(struct nse_hw *hw, u16 irq, u32 interval_in_us)
{
	enum nse_status status;

	irq += hw->func_caps.first_irq;	/* get abs irq ID. also pf->irq_space_start = first_irq */

	if (interval_in_us > NSE_ITR_INTERVAL_MAX_USEC)
		return -ERANGE;

	/* translate into 2us ( NSE_ITR_GRAN_FIXED ) unit */
	interval_in_us = ITR_REG_ALIGN(interval_in_us) >> NSE_ITR_GRAN_S;

	status = nse_aq_set_itr_interval(hw, irq, interval_in_us);
	if (status)
		return -EIO;

	return 0;
}

int nse_set_intrl_interval(struct nse_hw *hw, u16 irq, u32 interval_in_us)
{
	enum nse_status status;

	irq += hw->func_caps.first_irq;	/* get abs irq ID. also pf->irq_space_start = first_irq */

	if (interval_in_us &&
		(interval_in_us < NSE_INTRL_INTERVAL_MIN_USEC ||
		interval_in_us > NSE_INTRL_INTERVAL_MAX_USEC))
		return -ERANGE;

#define NSE_INTRL_ENA	BIT(6)

	if (interval_in_us) {
		interval_in_us >>= 2;	/* translate into 4us (NSE_INTRL_GRAN_FIXED) unit */
		interval_in_us |= NSE_INTRL_ENA;
	}

	status = nse_aq_set_intrl_interval(hw, irq, interval_in_us);
	if (status)
		return -EIO;

	return 0;
}

