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
#include "sxe2_mbx_public.h"

#ifdef SXE2_TEST
#define STATIC
#else
#define STATIC static
#endif

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

void sxe2_rss_vf_sw_cfg_clear(struct sxe2_adapter *adapter);

s32 sxe2_rss_ptg_parse_from_ddp(u8 *data, u16 cnt, u16 base_id,
				struct sxe2_adapter *adapter);

void sxe2_rss_xlt2_dump(struct sxe2_adapter *adapter);

void sxe2_rss_vsig_dump(struct sxe2_adapter *adapter);

void sxe2_rss_prof_dump(struct sxe2_adapter *adapter);

void sxe2_rss_mask_dump(struct sxe2_adapter *adapter);

#endif
