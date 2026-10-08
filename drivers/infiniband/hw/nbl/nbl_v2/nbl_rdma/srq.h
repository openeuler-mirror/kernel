/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */

/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_SRQ_H
#define NBL_IB_SRQ_H

#include <linux/kernel.h>
#include <rdma/ib_verbs.h>
#include "main.h"
#include "pd.h"
#include "alloc.h"
#include "mem.h"
#include "qp.h"
#include "defs.h"

#define SRQ_BIGGEST_WQE_SIZE (1 << 9)
#define MIN_WR_SGE 2
#define MAX_SRQ_SUBQ_SIZE (1 << 21)
#define RQ_CTRL_SEG_BYTES 32
#define RQ_DATA_SEG_BYTES 16
#define NBL_WQE_QUANTA_SIZE 64
#define NBL_WQE_FIRST_QUANTA_SGE_NUM 2
#define NBL_SRQ_MAX_SEQ 0xF
#define SRQ_NXT_QUEUE_NUM_MASK 0b11

/* fill wqe */
#define RQ_WQE_DATA_VALID_SHIFT 31
#define RQ_DMA_MAX_LEN ((1UL << 31) - 1)
#define RQ_CTRL_SEG_DS_5_4_MASK 0b110000
#define RQ_CTRL_SEG_DS_5_4_SHIFT 4
#define RQ_CTRL_SEG_DS_3_0_MASK 0b1111
#define RQ_DATA_SEG_WQE_VLD_DMA_LEN_SIZE 4
#define RQ_DATA_SEG_LOCAL_ADDR_SIZE 8
#define RQ_DATA_SEG_LKEY_SIZE 4

/* RQ WQE CTRL SEG */
#define RQ_WQE_VLD FIELD_LOC(0, 31, 31)
#define RQ_WQE_IDX_PHASE FIELD_LOC(0, 23, 23)
#define RQ_WQE_IDX FIELD_LOC(0, 22, 8)
#define RQ_WQE_DS_H FIELD_LOC(0, 7, 6)
#define RQ_WQE_OPCODE FIELD_LOC(0, 5, 0)
#define RQ_WQE_QPN FIELD_LOC(4, 31, 8)
#define RQ_WQE_DS_L FIELD_LOC(4, 7, 4)
#define RQ_WQE_TS FIELD_LOC(4, 3, 0)
#define RQ_WQE_PAYLOAD_LEN FIELD_LOC(8, 31, 0)

#define SRQ_CQP_PDPA_SHIFT 12
#define SRQ_CQP_SRQC_BA_SHIFT 6

/****SRQ CQP****/
/*00-07h*/
#define SRQ_CQP_CQN FIELD_LOC(0, 47, 24) /* xrc only */
#define SRQ_CQP_SRQN FIELD_LOC(0, 23, 0)
/*08-0Fh*/
#define SRQ_CQP_SRQC_UPLOAD_ADDR FIELD_LOC(8, 63, 0)
#define SRQ_CQP_SRQ_CUR_PDPA_VLD FIELD_LOC(8, 52, 52)
#define SRQ_CQP_SRQ_CUR_PDPA FIELD_LOC(8, 51, 0)
/*10-17h*/
#define SRQ_CQP_SRQ_NXT_PDPA_VLD FIELD_LOC(16, 52, 52)
#define SRQ_CQP_SRQ_NXT_PDPA FIELD_LOC(16, 51, 0)
/*18-1Fh*/
#define SRQ_CQP_SRQ_CUR_ID FIELD_LOC(24, 63, 53)
#define SRQ_CQP_CUR_SRQE_VLD FIELD_LOC(24, 52, 52)
#define SRQ_CQP_SRQ_CUR_BA FIELD_LOC(24, 51, 0)
/*20-27h*/
#define SRQ_CQP_LIMIT_ARM FIELD_LOC(32, 31, 31)
#define SRQ_CQP_LIMIT_RTH FIELD_LOC(32, 30, 16)
#define SRQ_CQP_SRQWQE_SIZE FIELD_LOC(32, 13, 10)
#define SRQ_CQP_SRQ_PI_RTH FIELD_LOC(32, 9, 8)
#define SRQ_CQP_SRQ_PM FIELD_LOC(32, 7, 6)
#define SRQ_CQP_SRQ_SIZE FIELD_LOC(32, 5, 2)
#define SRQ_CQP_STATE FIELD_LOC(32, 1, 0)
/*28-2Fh*/
#define SRQ_CQP_HW_SRQ_CI_RTH FIELD_LOC(40, 60, 58)
#define SRQ_CQP_SRQC_BA FIELD_LOC(40, 57, 0)
/*30-37h*/
#define SRQ_CQP_SW_SEQ_NUM FIELD_LOC(48, 51, 48)
#define SRQ_CQP_XR_DOMAIN FIELD_LOC(48, 47, 24) /* xrc only */
#define SRQ_CQP_PD FIELD_LOC(48, 23, 0)

/* SRQC define */
#define NBL_SRQC_SIZE 0x40
/* general */
#define NBL_SRQ_SHADOW_OFFST 48

/* fields 18-1FH */
#define SRQC_LIMIT_RTH GENMASK_ULL(30, 16)
/* Shadow 48B-63B */
#define NBL_SRQ_SHDW_HW_CI GENMASK_ULL(38, 24)
#define NBL_SRQ_SHDW_HW_CI_PHASE BIT_ULL(39)
#define NBL_SRQ_SHDW_NXT_QUEUE_NUM GENMASK_ULL(21, 20)
#define NBL_SRQ_SHDW_SW_SEQ_NUM GENMASK_ULL(19, 16)
#define NBL_SRQ_SHDW_SRQ_NXT_ID GENMASK_ULL(15, 8)
#define NBL_SRQ_SHDW_SW_SRQ_PI_PHASE_COPY BIT_ULL(7)
#define NBL_SRQ_SHDW_NXT_SRQE_VLD BIT_ULL(6)
#define NBL_SRQ_SHDW_SRQ_NXT_PM GENMASK_ULL(5, 4)
#define NBL_SRQ_SHDW_SRQ_NXT_BA_SHIFT 12
#define NBL_SRQ_SHDW_SRQ_NXT_BA_51_48 GENMASK_ULL(3, 0)
#define NBL_SRQ_SHDW_SRQ_NXT_BA_47_0 GENMASK_ULL(63, 16)
#define NBL_SRQ_SHDW_SW_SRQ_PI_PHASE BIT_ULL(15)
#define NBL_SRQ_SHDW_SW_SRQ_PI GENMASK_ULL(14, 0)
#define SRQ_NXT_BA_51_48_MASK 0xF
#define SRQ_NXT_BA_51_48_SHIFT 48
#define SRQ_NXT_BA_47_0_MASK 0xFFFFFFFFFFFF
/* SRQ DB0 */
#define NBL_SRQ_DB0_TH 3
#define NBL_SRQ_DB0_NXT_ID GENMASK_ULL(31, 24)
#define NBL_SRQ_DB0_SEQ_NUM GENMASK_ULL(23, 20)
#define NBL_SRQ_DB0_QUEUE_NUM GENMASK_ULL(19, 18)
#define NBL_SRQ_DB0_SRQN_V2 GENMASK_ULL(17, 0)
#define NBL_SRQ_DB0_SW_SRQ_PI_PAHSE_COPY BIT_ULL(63)
#define NBL_SRQ_DB0_NXT_SRQE_VLD BIT_ULL(62)
#define NBL_SRQ_DB0_SRQ_NXT_PM GENMASK_ULL(61, 60)
#define NBL_SRQ_DB0_SRQ_NXT_BA_51_24 GENMASK_ULL(59, 32)
#define NBL_SRQ_DB0_SRQ_NXT_BA_51_24_SHIFT 24

/* SRQ DB1 */
#define NBL_SRQ_DB1_SRQ_NXT_BA_7_0 GENMASK_ULL(31, 24)
#define NBL_SRQ_DB1_SEQ_NUM GENMASK_ULL(23, 20)
#define NBL_SRQ_DB1_QUEUE_NUM GENMASK_ULL(19, 18)
#define NBL_SRQ_DB1_SRQN_V2 GENMASK_ULL(17, 0)
#define NBL_SRQ_DB1_SW_SRQ_PI_PHASE BIT_ULL(63)
#define NBL_SRQ_DB1_SW_SRQ_PI GENMASK_ULL(62, 48)
#define NBL_SRQ_DB1_SRQ_NXT_BA_23_8 GENMASK_ULL(47, 32)
#define NBL_SRQ_DB1_SRQ_NXT_BA_23_8_SHIFT 8
#define NBL_SRQ_DB1_SRQ_NXT_BA_23_8_MASK 0xFFFF
#define NBL_SRQ_DB1_SRQ_NXT_BA_7_0_MASK 0xFF

/* SRQ HW DRING DB Threshold */
#define SRQ_HW_SRQ_CI_RTH 16
#define SRQ_XRCDN_INV_VAL 0xffffff

#pragma pack(1)
struct nbl_rq_wqe_data_seg_v2 {
	__be32 wqe_valid_dma_len;
	__be64 local_addr;
	__be32 lkey;
};
#pragma pack()

struct nbl_rq_ctrl_param {
	bool wqe_vld;
	u16 wqe_idx;
	u32 qpn_srqn;
	u32 wqe_quanta;
	u32 payload_len;
	u32 valid_sge_num;
};

void free_subq_item(struct nbl_sc_dev *sc_dev, struct nbl_srq *srq, struct nbl_srq_subq *subq);
void free_subq(struct nbl_sc_dev *sc_dev, struct nbl_srq *srq, struct nbl_srq_subq **subq_arr);
int nbl_create_subq_user(struct nbl_srq *srq, struct nbl_device *dev,
			u64 *buf_base, u32 buf_size, struct ib_udata *udata,
			u8 sorted_indices[], u64 sorted_ba[], u32 *page_0_num);
int nbl_create_subq_kernel(struct nbl_srq *srq, struct nbl_device *dev,
			u32 buf_size, u16 max_wqe);
int nbl_ib_create_srq(struct ib_srq *ib_srq,
				struct ib_srq_init_attr *init_attr,
				struct ib_udata *udata);

int nbl_ib_destroy_srq(struct ib_srq *srq, struct ib_udata *udata);

int nbl_ib_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
				enum ib_srq_attr_mask attr_mask, struct ib_udata *udata);
int nbl_ib_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *srq_attr);
void nbl_ib_free_srq_wqe(struct nbl_srq *srq, u8 subq_id, u32 wqe_index);
int nbl_cqp_create_srq_cmd(struct nbl_pci_f *rf, struct nbl_pd *nblpd, struct nbl_srq *srq);
int nbl_cqp_destroy_srq_cmd(struct nbl_pci_f *rf, struct nbl_srq *srq);
int nbl_cqp_modify_srq_cmd(struct nbl_pci_f *rf, struct nbl_srq *srq, u32 srq_limit);
int nbl_cqp_query_srq_cmd(struct nbl_pci_f *rf, struct nbl_srq *srq, __be64 *out);

int nbl_ib_alloc_xrcd(struct ib_xrcd *ib_xrcd, struct ib_udata *udata);
int nbl_ib_dealloc_xrcd(struct ib_xrcd *ib_xrcd, struct ib_udata *udata);

void nbl_srq_add_ref(struct nbl_srq *srq);
void nbl_srq_rem_ref(struct ib_srq *ibsrq);
int nbl_dump_hmc_srqc(struct nbl_device *nbl_dev, u32 dump_mask);
void nbl_debug_query_cache_srqc(struct nbl_pci_f *rf, int srqn);

#endif /* NBL_IB_QP_H */
