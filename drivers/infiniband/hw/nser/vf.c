// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
#include "osdep.h"
#include "hmc.h"
#include "defs.h"
#include "type.h"
#include "protos.h"
#include "vf.h"

/**
 * nser_manage_vf_pble_bp - manage vf pble
 * @cqp: cqp for cqp' sq wqe
 * @info: pble info
 * @scratch: pointer for completion
 * @post_sq: to post and ring
 */
int nser_manage_vf_pble_bp(struct nser_sc_cqp *cqp,
			    struct nser_manage_vf_pble_info *info, u64 scratch,
			    bool post_sq)
{
	__le64 *wqe;
	u64 temp, hdr, pd_pl_pba;

	wqe = nser_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOMEM;

	temp = FIELD_PREP(NSER_CQPSQ_MVPBP_PD_ENTRY_CNT, info->pd_entry_cnt) |
	       FIELD_PREP(NSER_CQPSQ_MVPBP_FIRST_PD_INX, info->first_pd_index) |
	       FIELD_PREP(NSER_CQPSQ_MVPBP_SD_INX, info->sd_index);
	set_64bit_val(wqe, 16, temp);

	pd_pl_pba = FIELD_PREP(NSER_CQPSQ_MVPBP_PD_PLPBA, info->pd_pl_pba >> 3);
	set_64bit_val(wqe, 32, pd_pl_pba);

	hdr = FIELD_PREP(NSER_CQPSQ_MVPBP_INV_PD_ENT, info->inv_pd_ent ? 1 : 0) |
	      FIELD_PREP(NSER_CQPSQ_OPCODE, NSER_CQP_OP_MANAGE_VF_PBLE_BP) |
	      FIELD_PREP(NSER_CQPSQ_WQEVALID, cqp->polarity);

	dma_wmb();	/* make sure WQE is populated before valid bit is set */
	set_64bit_val(wqe, 24, hdr);

	print_hex_dump_debug("WQE: MANAGE VF_PBLE_BP WQE", DUMP_PREFIX_OFFSET,
			     16, 8, wqe, NSER_CQP_WQE_SIZE * 8, false);

	if (post_sq)
		nser_sc_cqp_post_sq(cqp);
	return 0;
}

