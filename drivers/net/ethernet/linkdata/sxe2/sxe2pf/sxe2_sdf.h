/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_sdf.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_SDF_H__
#define __SXE2_SDF_H__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/if_ether.h>
#include <linux/idr.h>

#include "sxe2_vsi.h"
#include "sxe2_flow.h"
#include "sxe2_fnav.h"

#ifdef SXE2_TEST
#define STATIC
#else
#define STATIC static
#endif

#define SXE2_SDF_PTG_ID (55)
#define SXE2_SDF_PTG_CNT (1)

struct sxe2_sdf_fnav_cfg {
	u16 vsi_id_hw;
	u16 dst_queue;
	u16 flex_offset;
	u16 flex_mask;
	u16 flex_word;
	__be16 eth_type;
	u16 loc;
};

struct sxe2_sdf_flow_cfg {
	s32 blk;
	u16 mask_id;
	u16 mask;
	u16 ptg_id;
	u16 ptg_cnt;
	struct sxe2_fv_word fv[SXE2_MAX_FV_WORDS];
	u8 key[SXE2_TCAM_KEY_SZ];
	u16 prof_id;
	u16 tcam_id;
	u16 mac_fv_id;
	u16 etype_fv_id;
	bool used;
};

struct sxe2_sdf_fnav_filter {
	struct list_head l_node;
	u32 filter_loc;
	u8 fdid_prio;
	u16 q_index;
	u8 q_region;
	u8 act_prio;
	u16 ori_vsi_hw;
	u16 dst_vsi_hw;
	enum sxe2_hw_fnav_act_type act_type;
	enum sxe2_fnav_flow_type flow_type;
	u8 complete_report;
	u8 stat_ctrl;
	u16 stat_index;
	u8 inputset[SXE2_FNAV_INPUT_CNT * 2];
	u8 fd_space;
	u16 prof_id;
};

struct sxe2_sdf_ctxt {
	u16 eth_type;
	u16 mask;
	u8  en;
	struct sxe2_sdf_flow_cfg flow_cfg;
	struct list_head filter_list;
	u32 filter_cnt;
};

void sxe2_sdf_clear_cfg(struct sxe2_adapter *adapter);

void sxe2_sdf_ctxt_init(struct sxe2_adapter *adapter);

void sxe2_sdf_ctxt_deinit(struct sxe2_adapter *adapter);

void sxe2_sdf_open_test(struct sxe2_adapter *adapter);

void sxe2_sdf_close_test(struct sxe2_adapter *adapter);

s32 sxe2_sdf_etype_get(struct sxe2_adapter *adapter, u16 *eth_type, u16 *mask);

#endif
