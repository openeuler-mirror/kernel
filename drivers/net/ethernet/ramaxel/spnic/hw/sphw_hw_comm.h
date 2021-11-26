/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_HW_COMM_H
#define SPHW_HW_COMM_H

#include "sphw_comm_msg_intf.h"

#define MSG_TO_MGMT_SYNC_RETURN_ERR(err, out_size, status)	\
		((err) || (status) || !(out_size))

#define SPHW_PAGE_SIZE_HW(pg_size)	((u8)ilog2((u32)((pg_size) >> 12)))

enum func_tmr_bitmap_status {
	FUNC_TMR_BITMAP_DISABLE,
	FUNC_TMR_BITMAP_ENABLE,
};

enum ppf_tmr_status {
	SPHW_PPF_TMR_FLAG_STOP,
	SPHW_PPF_TMR_FLAG_START,
};

#define SPHW_HT_GPA_PAGE_SIZE 4096UL
#define SPHW_PPF_HT_GPA_SET_RETRY_TIMES 10

int sphw_set_cmdq_depth(void *hwdev, u16 cmdq_depth);

int sphw_set_cmdq_ctxt(struct sphw_hwdev *hwdev, u8 cmdq_id, struct cmdq_ctxt_info *ctxt);

int sphw_ppf_ext_db_init(void *dev);

int sphw_ppf_ext_db_deinit(void *dev);

int sphw_set_ceq_ctrl_reg(struct sphw_hwdev *hwdev, u16 q_id, u32 ctrl0, u32 ctrl1);

int sphw_set_dma_attr_tbl(struct sphw_hwdev *hwdevm, u8 entry_idx, u8 st, u8 at, u8 ph,
			  u8 no_snooping, u8 tph_en);

int sphw_get_comm_features(void *hwdev, u64 *s_feature, u16 size);
int sphw_set_comm_features(void *hwdev, u64 *s_feature, u16 size);

int sphw_get_global_attr(void *hwdev, struct comm_global_attr *attr);

#endif
