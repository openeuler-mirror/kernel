/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_CQ_H
#define NBL_IB_CQ_H

#define NBL_MAX_CQ_PERIOD 255
#define NBL_MAX_CQ_COUNT 255
#define NBL_START_CQ_PERIOD 1
#define NBL_START_CQ_MAXCNT 1

#define NBL_CQ_SW_SEL_CNT_MAX 0x03

#define NBL_QP_FLUSH_COMPLETE_CHK_DELAY_MS 50
#define NBL_SQ_COMPL_GEN (0x01)
#define NBL_RQ_COMPL_GEN (0x02)

#define NBL_CQ_SHADOW_TH_BOUNDARY 256
#define NBL_CQ_SHADOW_TH_LOW 128
#define NBL_CQ_SHADOW_TH_GAP 4
#define NBL_CQ_CTX_SIZE 64 /* CQC size, bytes*/
#define NBL_CQ_SHADOW_OFFST 56 /* CQ shadow offset from cqc */
#define NBL_CQ_SHADOW_SIZE 8 /* CQ shadow size, 8B */

/* cq arm control */
#define NBL_ARM_RD_FIFO_PERIOD 1024 /* read fifo every 1024 arm */
#define NBL_CQ_ARM_FIFO_QUARTER 512
#define NBL_CQ_ARM_FIFO_FULL 2045
#define NBL_CQ_ARM_FUN_NUM 63 /* actually 63 fun run rdma */
/*
 * CQ ARM fifo full is 2045, maybe 63 pf/vf may arm cq at same
 * time, so here we use 2045 - 63 = 1982 as software arm cq fifo
 * full limit for more safe.
 */
#define NBL_CQ_ARM_FIFO_THRESHOLD                                  \
	(NBL_CQ_ARM_FIFO_FULL - NBL_CQ_ARM_FUN_NUM)
#define NBL_ARM_FREE_LIMIT(_fcnt)                                  \
	((NBL_CQ_ARM_FIFO_THRESHOLD - (_fcnt)) / NBL_CQ_ARM_FUN_NUM)

enum nbl_cq_swwc_stat {
	SWWC_N_NTF_N_TIMER, /* no   notify and no  timer */
	SWWC_N_NTF_Y_TIMER, /* no   notify and mod timer */
	SWWC_Y_NTF_N_TIMER, /* send notify and no  timer */
};

enum nbl_cq_stat {
	NBL_CQ_STAT_INVALID = 0,
	NBL_CQ_STAT_VALID = 1,
	NBL_CQ_STAT_OVERFLOW = 2,
	NBL_CQ_STAT_RSV,
};

enum nbl_cq_cqc_ref {
	NBL_CQ_CQC_REF_SUB = 0,
	NBL_CQ_CQC_REF_ADD = 1,
};

struct nbl_create_cq_resp {
	u32 cq_id;
	u32 cq_size;
};

struct nbl_ib_create_cq {
	__aligned_u64 buf_addr;
};

static inline void nbl_cq_hold(struct nbl_cq *nblcq)
{
	refcount_inc(&nblcq->refcnt);
}

static inline void nbl_cq_put(struct nbl_cq *nblcq)
{
	if (refcount_dec_and_test(&nblcq->refcnt))
		complete(&nblcq->free_cq);
}

int nbl_ib_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
			struct ib_udata *udata);

int nbl_ib_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata);

int nbl_ib_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *entry);
int nbl_ib_v1_req_notify_cq(struct ib_cq *ibcq,
			 enum ib_cq_notify_flags notify_flags);
int nbl_ib_v2_req_notify_cq(struct ib_cq *ibcq,
			 enum ib_cq_notify_flags notify_flags);
int nbl_ib_modify_cq(struct ib_cq *cq, u16 cq_count, u16 cq_period);
int nbl_add_cqc_ref(struct nbl_cq *cq);
int nbl_dec_cqc_ref(struct nbl_cq *cq);
void nbl_clean_cqes(struct nbl_sc_dev *sc_dev, struct nbl_cq *nblcq, u32 qpn);
void nbl_generate_wc(struct nbl_cq *nblcq, struct nbl_ib_wc *soft_wc);
int nbl_ib_resize_cq(struct ib_cq *ibcq, int entries, struct ib_udata *udata);
int nbl_cqp_v2_cq_create_cmd(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq);
int nbl_cqp_v2_cq_destroy_cmd(struct nbl_pci_f *rf, struct nbl_sc_cq *cq);
int nbl_cqp_v2_cq_cqc_ref_add(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq);
int nbl_cqp_v2_cq_cqc_ref_sub(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq);
int nbl_cqp_cq_resize_cmd(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq,
				struct nbl_modify_cq_info *info);
void nbl_flush_dworker(struct work_struct *work);
void nbl_sc_cq_init(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq);
int nbl_create_cq_kernel_shadow(struct nbl_pci_f *rf,
			struct nbl_cq *cq, struct nbl_hmc_obj_sd_info *cq_sd_info);
#endif /* NBL_IB_CQ_H */
