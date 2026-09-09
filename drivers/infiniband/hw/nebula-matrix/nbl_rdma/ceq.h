/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_CEQ_H
#define NBL_IB_CEQ_H

#define NBL_CEQ_2M_PAGE_NUM 0x1
#define NBL_CEQ_CQP_ADDR_SHIFT 0xC
/* CEQE format */
#define NBL_CEQE_VALID BIT_ULL(63)
#define NBL_CEQE_CQN GENMASK_ULL(55, 32)
#define NBL_CEQE_CQCTX GENMASK_ULL(63, 0)

/*CQP CEQ*/
#define NBL_CQP_CEQ_STATE GENMASK_ULL(47, 46)
#define NBL_CQP_CEQ_PM GENMASK_ULL(45, 44)
#define NBL_CQP_CEQ_ID BIT_ULL(38)
#define NBL_CQP_CEQ_SIZE GENMASK_ULL(43, 39)
#define NBL_CQP_CEQ_MSIX_INDEX_H11 GENMASK_ULL(10, 0)
#define NBL_CQP_CEQ_MSIX_INDEX_L5 GENMASK_ULL(63, 59)
#define NBL_CQP_BASE_ADDR GENMASK_ULL(51, 0)
#define NBL_CQP_CEQ_FIR_PAGE_ADDR GENMASK_ULL(51, 0)
#define NBL_CQP_CEQ_SEC_PAGE_ADDR GENMASK_ULL(51, 0)

enum nbl_ceq_stat {
	NBL_CEQ_STAT_INVALID = 0,
	NBL_CEQ_STAT_VALID = 1,
	NBL_CEQ_STAT_OVERFLOW = 2,
	NBL_CEQ_STAT_RSV,
};

struct nbl_ceqc_t {
	u64 msix_num_h11:11;
	u64 ceq_ci:17;
	u64 ceq_ci_phase:1;
	u64 ceq_pi:17;
	u64 ceq_pi_phase:1;
	u64 rsv3:8;
	u64 ceq_size:5;
	u64 ceq_pm:2;
	u64 state:2;

	u64 ceq_pd_start_ba:52;
	u64 rsv2:7;
	u64 msix_num_l5:5;

	u64 ceq_cur_pdpa:52;
	u64 ceq_cur_pdpa_vld:1;
	u64 rsv1:11;

	u64 ceq_nxt_pdpa:52;
	u64 ceq_nxt_pdpa_vld:1;
	u64 rsv0:11;
};

static inline void nbl_sc_update_ceq_ci(struct nbl_sc_dev *dev,
					struct nbl_sc_ceq *sc_ceq)
{
	u64 val = (sc_ceq->polarity ^ 1) << NBL_CEAQ_NOTIFY_CI_PHASH_BIT |
			(sc_ceq->ceq_ring.tail & NBL_CEAQ_NOTIFY_CI_MASK);

	if (dev->has_high_temp_alarm)
		return;

	if (sc_ceq->ceq_id)
		write64_reg(val, dev->hw_regs[NBL_CEQ1_CI]);
	else
		write64_reg(val, dev->hw_regs[NBL_CEQ0_CI]);
}

void nbl_dump_ceqe(struct nbl_pci_f *rf, int ceq_id, int index);
int nbl_query_ceq(struct nbl_pci_f *rf);
void nbl_destroy_irq(struct nbl_pci_f *rf, struct nbl_msix_vector *msix_vec,
		     void *dev_id);
void nbl_del_ceqs(struct nbl_pci_f *rf);
enum nbl_status_code nbl_setup_ceqs(struct nbl_pci_f *rf);

#endif /* NBL_IB_CEQ_H */
