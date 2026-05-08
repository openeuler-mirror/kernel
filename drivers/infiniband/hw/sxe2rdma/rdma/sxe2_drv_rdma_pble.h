/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_pble.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef SXE2_DRV_RDMA_PBLE_H
#define SXE2_DRV_RDMA_PBLE_H

#define SXE2_OK				0
#define SXE2_PBL_MIN_ALLOC_PBLE		(1)
#define SXE2_PBL_IDX_VALID_VAL		(0xFFFFFFFFFFFFFFFF)
#define SXE2_PBL_PBLE_CNT_IN_4K		(512)
#define SXE2_PBL_2MB_PAGE_PBLE_CNT	(0x40000)
#define SXE2_PBL_4KB_PAGE_PBLE_CNT	(0x200)
#define SXE2_PBL_PBLE_SIZE		(8)
#define SXE2_PBL_2MB_PAGE_OFFSET	(0x1FFFFF)
#define SXE2_PBL_4KB_PAGE_OFFSET	(0xFFF)
#define SXE2_PBL_CP_PBLE_CNT_SHIFT	(9)
#define SXE2_PBL_PBLE_CNT_PER_4KB_CP	(512)
#define SXE2_PBL_MANAGE_CP_WQE_PA_SHIFT (3)
#define SXE2_PBL_SPTE_SIZE		(8)
#define SXE2_PBL_SPTE_CP_SIZE		(4096)
#define SXE2_PBL_PBLE_SIZE_SHIFT	(3)
#define LINER_ADDR_TO_REL_SPTE_IDX(a)	(((a) >> 12) & 0x1FF)
#define SXE2_FIRST_PAGE_INVALID_IDX	(0xFFFFFFFF)
#define SXE2_PBL_FPTE_IDX_TO_PBL_IDX(a) ((a) << 21)
#define SXE2_PBL_PBL_IDX_TO_FPTE_IDX(a) ((u32)((a) >> 21))

struct sxe2_pbl_table_idx_info {
	u32 fpte_idx;
	u32 spte_idx;
	u32 rel_spte_idx;
};
struct sxe2_pbl_add_page_info {
	struct sxe2_rcms_fpt_entry *fpte;
	struct sxe2_rcms_info *rcms_info;
	struct sxe2_pbl_table_idx_info idx_info;
	u64 start_liner_addr;
	u32 pages;
};

int sxe2_pbl_set_fpte(struct sxe2_rdma_ctx_dev *dev, u32 fpte_idx, u64 page_pa,
		      u16 fn_id);

int sxe2_pbl_clear_fpte(struct sxe2_rdma_ctx_dev *dev, u32 fpte_idx,
			u32 pble_cnt, u16 fn_id);

int sxe2_pbl_init(struct sxe2_rdma_device *rdma_dev);

void sxe2_pbl_exit(struct sxe2_rdma_device *rdma_dev);

int sxe2_pbl_get_pble(struct sxe2_pbl_pble_rsrc *pble_rsrc,
		      struct sxe2_pbl_pble_alloc_info *pble_alloc_info,
		      u32 pble_cnt, enum sxe2_pbl_obj_type obj_type);

void sxe2_pbl_free_pble(struct sxe2_pbl_pble_rsrc *pble_rsrc,
			u64 pble_liner_addr, u32 pble_cnt, bool firt_type_flag);

int sxe2_pbl_set_pble(struct sxe2_pbl_pble_rsrc *pble_rsrc,
		      u64 pble_liner_index, u64 page_pa, bool firt_type_flag);

int sxe2_pbl_manage_pble_cp_cmd(struct sxe2_mq_ctx *mq,
				struct sxe2_pbl_manage_pble_info *info,
				u64 scratch, bool post_sq);
int sxe2_pbl_buddy_alloc(struct sxe2_pbl_buddy *buddy, u32 order,
			 u64 *pbl_seg_index, u32 *total_pble_cnt);
int sxe2_pbl_liner_addr_to_pble_pa(struct sxe2_pbl_pble_rsrc *pble_rsrc,
				   u64 liner_addr, u64 *pa);

int sxe2_pbl_build_second_type_table(struct sxe2_pbl_pble_rsrc *pble_rsrc,
				     struct sxe2_pbl_add_page_info *info);
int sxe2_pbl_build_third_type_table(struct sxe2_pbl_pble_rsrc *pble_rsrc,
				    struct sxe2_pbl_add_page_info *info);

int sxe2_pbl_add_pble_prm(struct sxe2_pbl_pble_rsrc *pble_rsrc);

int sxe2_pbl_add_second_type_table(
	struct sxe2_pbl_pble_rsrc *pble_rsrc,
	struct sxe2_pbl_pble_alloc_info *pble_alloc_info);

int sxe2_pbl_add_third_type_table(
	struct sxe2_pbl_pble_rsrc *pble_rsrc,
	struct sxe2_pbl_pble_alloc_info *pble_alloc_info);
int sxe2_pbl_alloc_pble_idx(struct sxe2_pbl_pble_rsrc *pble_rsrc,
			    struct sxe2_pbl_pble_alloc_info *pble_alloc_info,
			    u32 pble_cnt);

int sxe2_pbl_alloc_second_type_pble(
	struct sxe2_pbl_pble_rsrc *pble_rsrc,
	struct sxe2_pbl_pble_alloc_info *pble_alloc_info, u32 pble_cnt,
	enum sxe2_pbl_obj_type obj_type);

int sxe2_pbl_alloc_third_type_pble(
	struct sxe2_pbl_pble_rsrc *pble_rsrc,
	struct sxe2_pbl_pble_alloc_info *pble_alloc_info, u32 pble_cnt,
	enum sxe2_pbl_obj_type obj_type);

#endif
