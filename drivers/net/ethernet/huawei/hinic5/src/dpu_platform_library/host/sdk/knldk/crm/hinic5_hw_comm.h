/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hw_comm.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_COMM_H
#define HINIC5_COMM_H

#include <linux/types.h>

#include "mpu_inband_cmd_defs.h"
#include "hinic5_hwdev.h"

#define MSG_TO_MGMT_SYNC_RETURN_ERR(err, out_size, status)	\
		(((err) != 0) || ((status) != 0) || ((out_size) == 0))

#define HINIC5_PAGE_SIZE_HW(pg_size)	((u8)ilog2((u32)((pg_size) >> 12)))

enum func_tmr_bitmap_status {
	FUNC_TMR_BITMAP_DISABLE,
	FUNC_TMR_BITMAP_ENABLE,
};

enum ppf_tmr_status {
	HINIC_PPF_TMR_FLAG_STOP,
	HINIC_PPF_TMR_FLAG_START,
};

#define HINIC5_HT_GPA_PAGE_SIZE 4096UL
#define HINIC5_HT_GPA_SET_RETRY_TIMES 10

extern unsigned char lowpower_mode;

int hinic5_set_cmdq_depth(void *hwdev, u16 cmdq_depth);

int hinic5_set_enhance_cmdq_ctxt(struct hinic5_hwdev *hwdev, u8 cmdq_id,
				 struct enhance_cmdq_ctxt_info *ctxt);

int hinic5_set_cmdq_ctxt(struct hinic5_hwdev *hwdev, u8 cmdq_id,
			 struct cmdq_ctxt_info *ctxt);

int hinic5_ppf_ext_db_init(struct hinic5_hwdev *hwdev);

int hinic5_ppf_ext_db_deinit(struct hinic5_hwdev *hwdev);

int hinic5_set_ceq_ctrl_reg(struct hinic5_hwdev *hwdev, u16 q_id,
			    u32 ctrl0, u32 ctrl1);

int hinic5_set_dma_attr_tbl(struct hinic5_hwdev *hwdev, u8 entry_idx, u8 st, u8 at, u8 ph,
			    u8 no_snooping, u8 tph_en);

int hinic5_get_comm_features(void *hwdev, u64 *s_feature, u16 size);
int hinic5_set_comm_features(void *hwdev, u64 *s_feature, u16 size);

int hinic5_comm_channel_detect(struct hinic5_hwdev *hwdev);

int hinic5_get_global_attr(void *hwdev, struct comm_global_attr *attr);

int hinic5_get_secure_mem_cfg(struct hinic5_hwdev *hwdev, dma_addr_t *gpa, u32 *len);

int hisdk5_get_plug_srv_bitmap(void *hwdev, u8 srv_type, u16 func_id, u8 *attach_en);
int hisdk5_set_plug_srv_bitmap(void *hwdev, u8 srv_type, u16 func_id, u8 attach_en);

int hinic5_get_board_info(void *hwdev, struct hinic5_board_info *info, u16 channel);

/**
 * @brief Initialize HT GPA
 * @param hwdev device handle
 *
 * @return whether success
 *  @retval zero: success
 *  @retval non-zero: failure
 */
int hinic5_ht_gpa_init(struct hinic5_hwdev *hwdev);

/**
 * @brief Deinitialize HT GPA
 * @param hwdev device handle
 */
void hinic5_ht_gpa_deinit(struct hinic5_hwdev *hwdev);

#endif
