/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_AEQ_H
#define NBL_IB_AEQ_H

#include "main.h"
#include "mem.h"

/*CQP AEQ*/
#define NBL_CQP_AEQ_STATE GENMASK_ULL(47, 46)
#define NBL_CQP_AEQ_PM GENMASK_ULL(45, 44)
#define NBL_CQP_AEQ_SIZE GENMASK_ULL(43, 39)
#define NBL_CQP_AEQ_MSIX_INDEX_H11 GENMASK_ULL(10, 0)
#define NBL_CQP_AEQ_MSIX_INDEX_L5 GENMASK_ULL(63, 59)
#define NBL_CQP_AEQ_BASE_ADDR GENMASK_ULL(51, 0)
#define NBL_CQP_AEQ_FIR_PAGE_ADDR GENMASK_ULL(51, 0)
#define NBL_CQP_AEQ_SEC_PAGE_ADDR GENMASK_ULL(51, 0)

struct query_qpc_work {
	struct work_struct work;
	struct nbl_pci_f *rf;
	__u32 qpn;
};

struct query_cqc_work {
	struct work_struct work;
	struct nbl_pci_f *rf;
	__u32 cqn;
};

enum nbl_aeq_stat {
	NBL_AEQ_STAT_INVALID = 0,
	NBL_AEQ_STAT_VALID = 1,
	NBL_AEQ_STAT_OVERFLOW = 2,
	NBL_AEQ_STAT_RSV,
};

struct nbl_aeqc_t {
	u64 msix_num_h11:11;
	u64 aeq_ci:17;
	u64 aeq_ci_phase:1;
	u64 aeq_pi:17;
	u64 aeq_pi_phase:1;
	u64 rsv3:8;
	u64 aeq_size:5;
	u64 aeq_pm:2;
	u64 state:2;

	u64 aeq_pd_start_ba:52;
	u64 rsv2:7;
	u64 msix_num_l5:5;

	u64 aeq_cur_pdpa:52;
	u64 aeq_cur_pdpa_vld:1;
	u64 rsv1:11;

	u64 aeq_nxt_pdpa:52;
	u64 aeq_nxt_pdpa_vld:1;
	u64 rsv0:11;
};
/**
 * AEQ init info struct
 */
struct nbl_aeq_init_info {
	u64 aeq_elem_pa; /* physical address of firt page or firt level page*/
	struct nbl_sc_dev *dev;
	u32 *aeqe_base; /* virtual address from RDMA alloc */
	u32 elem_cnt; /* actual numbers of aeq entry */
	u32 msix_idx; /* Interrupt number for AEQ */
	u32 aeq_pg_num;
	bool pa_continuous; /* Assign physical addresses continuously or not */
};

static inline void nbl_sc_update_aeq_ci(struct nbl_sc_dev *dev,
					struct nbl_sc_aeq *sc_aeq)
{
	u64 val = (sc_aeq->polarity ^ 1) << NBL_CEAQ_NOTIFY_CI_PHASH_BIT |
		(sc_aeq->aeq_ring.tail & NBL_CEAQ_NOTIFY_CI_MASK);

	if (dev->has_high_temp_alarm)
		return;

	write64_reg(val, dev->hw_regs[NBL_AEQ_CI]);
}

void nbl_dump_aeqe(struct nbl_pci_f *rf, int index);
int nbl_query_aeq(struct nbl_pci_f *rf);
int nbl_create_aeq(struct nbl_pci_f *rf);
int nbl_cfg_aeq_vector(struct nbl_pci_f *rf);
int nbl_setup_aeq(struct nbl_pci_f *rf);
void nbl_destroy_aeq(struct nbl_pci_f *rf);
#endif /* NBL_IB_AEQ_H */
