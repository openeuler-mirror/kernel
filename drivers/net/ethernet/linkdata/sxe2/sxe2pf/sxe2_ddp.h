/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_ddp.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DDP_H__
#define __SXE2_DDP_H__

#include "sxe2.h"
#include "sxe2_ddp_common.h"
#include <linux/firmware.h>

#define SXE2_DDP_PKG_PATH "sxe2/ddp/"
#define SXE2_DDP_PKG_FILE SXE2_DDP_PKG_PATH "sxe2.cfg"

#define SXE2_DDP_DELAY_100MS (100)

#define SXE2_MAX_ENTRIES_IN_BUF(hd_sz, ent_sz)                                 \
	((SXE2_PKG_BUF_SIZE -                                                  \
	  struct_size((struct sxe2_buf_hdr *)0, section_entry, 1) - (hd_sz)) / \
	 (ent_sz))

typedef s32 (*sxe2_ddp_data_parse_cb)(u8 *data, u16 cnt, u16 base_id,
				      struct sxe2_adapter *adapter);

struct sxe2_ddp_data_parse {
	enum sxe2_section_type sec_type;
	sxe2_ddp_data_parse_cb cb;
};

s32 sxe2_get_pkg_info(struct sxe2_adapter *adapter, struct sxe2_pkg_hdr *hdr);

struct sxe2_buf_table *sxe2_get_buf_table(struct sxe2_seg *sxe2_seg);

struct sxe2_seg *sxe2_get_pkg_segment(struct sxe2_pkg_hdr *hdr,
				      enum sxe2_segment_type type);

s32 sxe2_ddp_pre_deal(struct sxe2_adapter *adapter, struct sxe2_pkg_hdr *hdr);

s32 sxe2_ddp_proc_deal(struct sxe2_adapter *adapter, struct sxe2_buf *buffer);

s32 sxe2_ddp_deal_done(struct sxe2_adapter *adapter, s32 result);

s32 sxe2_ddp_acquire_state(struct sxe2_adapter *adapter,
			   struct sxe2_pkg_hdr *hdr);

s32 sxe2_init_pkg(struct sxe2_adapter *adapter, u8 *buff, u32 len);

s32 sxe2_copy_and_init_pkg(struct sxe2_adapter *adapter, const u8 *buf,
			   u32 len);

bool sxe2_is_init_pkg_successful(s32 state);

void sxe2_free_seg(struct sxe2_adapter *adapter);

void sxe2_load_pkg(const struct firmware *firmware,
		   struct sxe2_adapter *adapter);

s32 sxe2_ddp_rebuild(struct sxe2_adapter *adapter);

void sxe2_pci_deinit(struct sxe2_adapter *adapter);

s32 sxe2_hw_cfg_info_get(struct sxe2_adapter *adapter);

s32 sxe2_ddp_params_store(struct sxe2_adapter *adapter);

#endif
