/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_rcms.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_drv_rdma_common.h"
#ifndef SXE2_RCMS_H
#define SXE2_RCMS_H

#define SXE2_OK				       0
#define SXE2_FPTE_RCMS_2MB_MASK		       0x1FFFFF
#define SXE2_MAX_FPTE_CNT		       0x1000
#define SXE2_RCMS_MAX_CP_COUNT		       512
#define SXE2_MAX_FPT_ENTRIES		       35
#define SXE2_FIRST_VF_FPM_ID		       8
#define SXE2_MIN_PBLE_PAGES		       3
#define SXE2_RCMS_FPM_MULTIPLIER	       1024
#define SXE2_RCMS_FPTE_SIZE		       0x200000
#define SXE2_RCMS_FIRST_CP_SIZE		       0x200000
#define SXE2_RCMS_SECOND_CP_SIEZ	       0X1000
#define SXE2_RCMS_SPT_PAGE_SIZE		       0x1000
#define SXE2_RCMS_FPT_SPT_BUF_ALIGNMENT	       4096
#define SXE2_RCMS_SPTE_INVALID_VAL	       0xFF
#define SXE2_RCMS_UPDATE_FPTE_BUF_SIZE	       512
#define SXE2_RDMA_PF			       0
#define SXE2_RDMA_VF			       1
#define SXE2_RCMS_SPT_INVALID_VAL	       0xFF
#define SXE2_RCMS_LINER_ADDR_BASE	       0x0
#define SXE2_UPDATE_FPTE_WQE_INCLUDE_ENTRY_CNT 3
#define SXE2_RCMS_SPT_INVALID_MASK_REG_VAL     0x3FFFFF
#define SXE2_RCMS_SPT_INVALID_REG_PULL	       200
#define SXE2_RCMS_DEL_OBJ_START_IDX	       0
#define SXE2_RCMS_QUERY_BUF_PA_SHIFT	       2
#define SXE2_RCMS_PARSE_QUERY_BUF_SHIFT	       4
#define SXE2_RCMS_MAX_FPTE_CNT_BUF_OFFSET      0x50
#define SXE2_RCMS_FIRST_FPTE_IDX_BUF_OFFSET    0x54
#define SXE2_RCMS_CEQS_DB_BUF_OFFSET	       0x58
#define SXE2_RCMS_DB_BAR_ADDR_BUF_OFFSET       0x5C
#define SXE2_RCMS_MAX_FPTE_CNT_MASK	       GENMASK(13, 0)
#define SXE2_RCMS_MAX_CC_QP_CNT_MASK	       GENMASK(26, 14)
#define SXE2_RCMS_FIRST_FPTE_IDX_MASK	       GENMASK(12, 0)
#define SXE2_RCMS_IRRL_OST_NUM_MASK	       GENMASK(16, 13)
#define SXE2_RCMS_SSNT_OST_NUM_MASK	       GENMASK(20, 17)
#define SXE2_RCMS_RESP_OST_NUM_MASK	       GENMASK(24, 21)
#define SXE2_RCMS_MAX_CEQS_MASK		       GENMASK(9, 0)
#define SXE2_RCMS_MAX_DB_PAGE_NUM_MASK	       GENMASK(31, 16)
#define SXE2_RCMS_OBJ_BASE_MASK		       GENMASK(30, 0)
#define SXE2_RCMS_PRINT_HEX_ROW_SIZE	       16
#define SXE2_RCMS_PRINT_HEX_GROUP_SIZE	       8
#define SXE2_RCMS_PRINT_HEX_WQE_TO_BIT	       8
#define SXE2_RCMS_FPTE_BUF_ENTRIES_SIZE_SHIFT  4
#define SXE2_RCMS_OBJ_LINER_BASE_SHIFT	       3
#define SXE2_RCMS_COMMIT_BUF_SHIFT	       4
#define SXE2_RCMS_MQ_CMD_NO_SCRATCH	       0
#define SXE2_RCMS_FPTE_BUF_SHIFT	       7
#define SXE2_RCMS_MQ_WQE_LEN		       8
#define SXE2_RCMS_QUERY_BUF_LEN		       24
#define SXE2_RCMS_AMO_PAGE_SIZE		       12

#define FPT_INDEX_GET(a)		   ((a >> 21))
#define SPT_INDEX_GET(a)		   ((a >> 12))
#define REL_SPTE_INDEX_GET(a)		   ((a & 0x1FF))
#define SPT_IDX_TO_FPT_IDX(a)		   ((a >> 9))
#define FIST_PAGE_TABLE_CP_OFFSET_GET(a)   (a & 0x1FFFFF)
#define SECOND_PAGE_TABLE_CP_OFFSET_GET(a) (a & 0xFFF)
#define LINER_ADDR_TO_REL_SPT_IDX(a)	   ((a >> 12) & 0x1FF)

#define SXE2_RCMS_FPT_CMD_WR	       BIT(31)
#define SXE2_RCMS_FPT_DATALOW_VALID    BIT(0)
#define SXE2_RCMS_FPT_DATALOW_TYPE     BIT(1)
#define SXE2_RCMS_FPT_DATALOW_CP_COUNT GENMASK(11, 2)
#define SXE2_RCMS_FPT_CMD_PARTSEL      BIT(15)

#define SPT_CACHE_INVALID_MASK_S 0
#define SPT_CACHE_INVALID_MASK_M GENMASK(21, 0)

#define SPT_CACHE_INVALID_IDX_SPT_IDX_S 0
#define SPT_CACHE_INVALID_IDX_SPT_IDX_M GENMASK(21, 0)

#define SPT_CACHE_INVALID_IDX_EN_S 24
#define SPT_CACHE_INVALID_IDX_EN_M BIT(24)

#define SPT_CACHE_INVALID_IDX_DONE_S 25
#define SPT_CACHE_INVALID_IDX_DONE_M BIT(25)

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
extern u32 g_inject_fpte_err;
#endif

struct sxe2_rcms_rsrc_limits {
	u32 qp_limit;
	u32 mr_limit;
	u32 cq_limit;
};

struct sxe2_rcms_create_obj_info {
	struct sxe2_rcms_info *rcms_info;
	u32 rsrc_type;
	u32 add_fpte_cnt;
	u32 start_idx;
	u32 obj_cnt;
	enum sxe2_rcms_fpt_entry_type entry_type;
	enum sxe2_rcms_creat_table_mode init_mode;
	bool privileged;
};
struct sxe2_rcms_del_obj_info {
	struct sxe2_rcms_info *rcms_info;
	u32 rsrc_type;
	u32 del_fpte_cnt;
	u32 start_idx;
	u32 obj_cnt;
	bool privileged;
};

int sxe2_rcms_create_obj(struct sxe2_rdma_ctx_dev *dev,
			 struct sxe2_rcms_create_obj_info *obj_info);

int sxe2_rcms_del_obj(struct sxe2_rdma_ctx_dev *dev,
		      struct sxe2_rcms_del_obj_info *info, bool reset,
		      bool mq_update);

int sxe2_rcms_pf_config_vf_fpm_val(struct sxe2_rdma_vchnl_dev *vc_dev);

int sxe2_rcms_commit_fpm_val_cmd(struct sxe2_mq_ctx *mq, u64 scratch,
				 u16 rcms_fn_id,
				 struct sxe2_rdma_dma_mem *commit_fpm_mem,
				 bool post_sq, u8 wait_type);

int sxe2_rcms_query_fpm_val_cmd(struct sxe2_mq_ctx *mq, u64 scratch,
				u16 rcms_fn_id,
				struct sxe2_rdma_dma_mem *query_fpm_mem,
				bool post_sq, u8 wait_type);

int sxe2_rcms_add_fpt_entry(struct sxe2_rdma_ctx_dev *dev,
			    struct sxe2_rcms_info *rcms_info, u32 fpte_index,
			    enum sxe2_rcms_fpt_entry_type fpte_type);

int sxe2_rcms_add_spt_entry(struct sxe2_rdma_ctx_dev *dev,
			    struct sxe2_rcms_info *rcms_info, u32 spte_index);

int sxe2_rcms_remove_spt_entry(struct sxe2_rdma_ctx_dev *dev,
			       struct sxe2_rcms_info *rcms_info,
			       u32 spte_index);
void sxe2_rcms_remove_fpt_entry(struct sxe2_rdma_ctx_dev *dev,
				struct sxe2_rcms_info *rcms_info,
				u32 fpte_index,
				enum sxe2_rcms_fpt_entry_type fpte_type);

int sxe2_rcms_update_fptes(struct sxe2_rdma_ctx_dev *dev,
			   struct sxe2_rcms_info *rcms_info,
			   u16 *fpte_index_addr, u32 fpte_cnt, bool seted);

int sxe2_rcms_update_pe_fptes(struct sxe2_rdma_ctx_dev *dev,
			      struct sxe2_rcms_update_fptes_info *info,
			      u64 scratch);

int sxe2_rcms_update_fptes_cmd(struct sxe2_rdma_ctx_dev *dev,
			       struct sxe2_rcms_update_fptes_info *info);

int sxe2_rcms_update_fptes_cmd_complete(
	struct sxe2_rdma_ctx_dev *dev,
	struct sxe2_rcms_update_fptes_info *info);
int sxe2_rcms_vf_update_fptes(struct sxe2_rdma_ctx_dev *dev,
			      struct sxe2_rcms_info *rcms_info,
			      u16 *fpte_index_addr, u32 fpte_cnt, bool seted);

int sxe2_rcms_setup(struct sxe2_rdma_device *rdma_dev);

void sxe2_rcms_del_objs(struct sxe2_rdma_ctx_dev *dev,
			struct sxe2_rcms_info *rcms_info, bool privileged,
			bool reset, bool mq_update);

void sxe2_rcms_exit(struct sxe2_rdma_device *rdma_dev);

int sxe2_rcms_pf_config_fpm_val(struct sxe2_rdma_ctx_dev *dev,
				u32 qp_limit_count);

void sxe2_rcms_get_obj_spte_range(struct sxe2_rcms_info *rcms_info,
				  u32 obj_type, u32 start_idx, u32 obj_cnt,
				  u32 *spte_idx, u32 *spte_limit);
int sxe2_rcms_invalidate_spt_cache(struct sxe2_rdma_ctx_dev *dev, u32 fpte_idx,
				   u32 spte_idx);
int sxe2_rcms_update_fpte_wqe_fill(struct sxe2_mq_ctx *mq,
				   struct sxe2_rcms_update_fptes_info *info,
				   u64 scratch);

int sxe2_rcms_build_first_type_table(struct sxe2_rdma_ctx_dev *dev,
				     struct sxe2_rcms_create_obj_info *obj_info);

int sxe2_rcms_build_second_type_table(
	struct sxe2_rdma_ctx_dev *dev,
	struct sxe2_rcms_create_obj_info *obj_info);

void sxe2_rcms_get_obj_fpte_range(struct sxe2_rcms_info *rcms_info,
				  u32 obj_type, u32 start_idx, u32 obj_cnt,
				  u32 *fpte_idx, u32 *fpte_limit);
int sxe2_rcms_modify_fpm_val(struct sxe2_rdma_ctx_dev *dev,
			     struct sxe2_rcms_info *rcms_info,
			     u32 qp_limit_count);

#endif
