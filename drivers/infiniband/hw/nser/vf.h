/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
#ifndef NSER_VF_H
#define NSER_VF_H

struct nser_sc_cqp;

struct nser_manage_vf_pble_info {
	u32 sd_index;
	u16 first_pd_index;
	u16 pd_entry_cnt;
	u8 inv_pd_ent;
	u64 pd_pl_pba;
};

int nser_manage_vf_pble_bp(struct nser_sc_cqp *cqp,
			    struct nser_manage_vf_pble_info *info, u64 scratch,
			    bool post_sq);
#endif
