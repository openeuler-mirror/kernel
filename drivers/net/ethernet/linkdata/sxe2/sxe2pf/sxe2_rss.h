/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_rss.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_RSS_H__
#define __SXE2_RSS_H__

#include <linux/types.h>
#include <linux/kernel.h>

#include "sxe2_vsi.h"

#ifdef SXE2_TEST
#define STATIC
#else
#define STATIC static
#endif

#define SXE2_RSS_HASH_KEY_SIZE 52

enum sxe2_rss_lut_type {
	SXE2_RSS_VSI_LUT = 0,
	SXE2_RSS_LUT_TYPE_RSV,
	SXE2_RSS_PF_LUT,
	SXE2_RSS_GLOBAL_LUT,
	SXE2_RSS_MAX_LUT_TYPE,
};

enum sxe2_rss_lut_size {
	SXE2_RSS_LUT_SIZE_64  = 64,
	SXE2_RSS_LUT_SIZE_128 = 128,
	SXE2_RSS_LUT_SIZE_512 = 512,
	SXE2_RSS_LUT_SIZE_2K  = 2048,
};

enum sxe2_rss_lut_max_queue {
	SXE2_VSI_LUT_MAX_QUEUE	  = 16,
	SXE2_GLOBAL_LUT_MAX_QUEUE = 64,
	SXE2_PF_LUT_MAX_QUEUE	  = 256,
};

void sxe2_rss_flow_ctxt_init(struct sxe2_adapter *adapter);

void sxe2_rss_flow_ctxt_deinit(struct sxe2_adapter *adapter);

void sxe2_rss_ctxt_init(struct sxe2_vsi *vsi);

void sxe2_rss_fill_lut(u8 *lut, u16 lut_size, u16 queue_size);

s32 sxe2_rss_default_flow_set(struct sxe2_vsi *vsi);

void sxe2_rss_vsi_flow_clean(struct sxe2_vsi *vsi);

s32 sxe2_fwc_rss_hash_ctrl_set(struct sxe2_vsi *vsi);

s32 sxe2_fwc_rss_lut_set(struct sxe2_vsi *vsi, u8 *lut, u16 lut_size);

s32 sxe2_fwc_rss_lut_get(struct sxe2_vsi *vsi, u8 *lut, u16 lut_size);

s32 sxe2_fwc_rss_hkey_set(struct sxe2_vsi *vsi, u8 *hkey);

s32 sxe2_fwc_rss_hkey_get(struct sxe2_vsi *vsi, u8 *hkey);

void sxe2_fwc_rss_trace_trigger(struct sxe2_adapter *adapter);

void sxe2_fwc_rss_trace_recorder(struct sxe2_adapter *adapter);

u16 sxe2_rss_queue_size_correct(u16 new_size);

s32 sxe2_rss_lut_reset(struct sxe2_vsi *vsi, u16 queue_size);

void sxe2_rss_clean_for_vf(struct sxe2_vsi *vsi, bool need_clear_hw);

s32 sxe2_rss_ptg_parse_from_ddp(u8 *data, u16 cnt, u16 base_id,
				struct sxe2_adapter *adapter);

void sxe2_rss_xlt2_dump(struct sxe2_adapter *adapter);

void sxe2_rss_vsig_dump(struct sxe2_adapter *adapter);

void sxe2_rss_prof_dump(struct sxe2_adapter *adapter);

void sxe2_rss_mask_dump(struct sxe2_adapter *adapter);

#endif
