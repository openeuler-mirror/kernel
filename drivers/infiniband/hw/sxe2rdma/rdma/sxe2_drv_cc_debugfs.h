/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_cc_debugfs.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_CC_DEBUGFS_H__
#define __SXE2_DRV_CC_DEBUGFS_H__

#include "sxe2_drv_rdma_common.h"

#define SXE2_OK								0
#define CC_DEBUGFS_WRITE_BUF_MAX_LEN			64
#define CC_MAX_CC_QP_IDX						4096
#define RTT_DFX_H_SHIFIT						(9)
#define RTT_DFX_H_MASK							(0x7F)
#define RTT_DFX_L_MASK							(0x1FF)

struct cc_dcqcn_entry {
	u32 t_h                  : 12;
	u32 g                    : 20;

	u32 rhai_h              : 8;
	u32 rai                 : 16;
	u32 f                   : 4;
	u32 t_l                 : 4;

	u32 rreduce_mperiod_h   : 8;
	u32 k                   : 16;
	u32 rhai_l              : 8;

	u32 min_dec_factor      : 8;
	u32 increase_rate_cnt   : 16;
	u32 rreduce_mperiod_l   : 8;

	u32 rc_h                : 4;
	u32 alpha               : 20;
	u32 min_rate             : 8;

	u32 rt_h                : 16;
	u32 rc_l                : 16;

	u32 func_id             : 12;
	u32 decrease_rate_cnt   : 16;
	u32 rt_l                : 4;

	u32 t_counter           : 3;
	u32 byte_counter        : 25;
	u32 decrease_rate_valid : 4;

	u32 qpn                 : 18;
	u32 ccEn                : 2;
	u32 rtt_event_l         : 9;
	u32 bc                  : 3;
};

struct cc_timely_entry {
	u32 min_rtt_h        :12;
	u32 alpha            :20;

	u32 high_h           :12;
	u32 low              :16;
	u32 min_rtt_l        :4;

	u32 pre_rtt_h        :8;
	u32 beta             :20;
	u32 high_l           :4;

	u32 rtt_event_h      :7;
	u32 rtt_diff_symbol  :1;
	u32 rtt_diff         :16;
	u32 pre_rtt_l        :8;
};

struct cc_sw_entry {
	struct cc_timely_entry timely;
	struct cc_dcqcn_entry dcqcn;
};

struct sxe2_get_cc_qp_dfx_cmd_info {
	u32 cc_qp_idx;
};

int drv_rdma_debug_cc_add(struct sxe2_rdma_device *rdma_dev);

#endif

