/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_REG_DEFINE_H
#define XSC_REG_DEFINE_H

struct xsc_mpt_entry {
	u32 va_l;
	u32 va_h;
	u32 mem_size;
	u32 pdn:24;
	u32 key:8;
	u32 mtt_base:18;
	u32 acc:4;
	u32 page_mode:2;
	u32 mem_map_en:1;
	u32 rsv:7;
};

#endif
