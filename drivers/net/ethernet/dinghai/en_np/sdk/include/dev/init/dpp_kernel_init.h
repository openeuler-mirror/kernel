/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_KERNEL_INIT_H_
#define _DPP_KERNEL_INIT_H_

#include "zxic_common.h"
#include "dpp_dtb_table_api.h"

s32 dpp_dtb_queue_dma_mem_alloc(struct dpp_dev_t *dev, u32 queue_id, u32 size);
s32 dpp_dtb_queue_dma_mem_get(struct dpp_dev_t *dev, u32 queue_id,
			      struct dtb_queue_dma_addr_info *dmaAddrInfo);
s32 dpp_dtb_queue_dma_mem_release(struct dpp_dev_t *dev, u32 queue_id);
s32 dtb_sdt_dump_dma_alloc(struct dpp_dev_t *dev, u32 dma_size, u64 *p_dma_phy_addr,
			   u64 *p_dma_vir_addr);

s32 dtb_sdt_dump_dma_release(struct dpp_dev_t *dev, u32 dma_size, u64 dma_phy_addr,
			     u64 dma_vir_addr);
#endif
