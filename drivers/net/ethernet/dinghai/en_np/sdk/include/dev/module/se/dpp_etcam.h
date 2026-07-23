/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_ETCAM_H_
#define _DPP_ETCAM_H_
#define DPP_ETCAM_BLOCK_NUM (8)
#define DPP_ETCAM_TBLID_NUM (8)
#define DPP_ETCAM_RAM_NUM (8)
#define DPP_ETCAM_RAM_WIDTH (80U)

#ifdef DPP_FPGA_TEST_BAORD_SA500FT
#define DPP_ETCAM_RAM_DEPTH (16U)
#else
#define DPP_ETCAM_RAM_DEPTH (512U)
#endif

#define DPP_ETCAM_WR_MASK_MAX (((u32)1 << DPP_ETCAM_RAM_NUM) - 1) /*255*/
#define DPP_ETCAM_WIDTH_MIN (DPP_ETCAM_RAM_WIDTH)
#define DPP_ETCAM_WIDTH_MAX (DPP_ETCAM_RAM_NUM * DPP_ETCAM_RAM_WIDTH)

#define DPP_ETCAM_DEFAULT_MIN (0)
#define DPP_ETCAM_ONE_BIT_MAX (1)

#define DPP_ETCAM_PORT_NUM (1)

enum dpp_etcam_data_type_e {
	DPP_ETCAM_DTYPE_MASK = 0,
	DPP_ETCAM_DTYPE_DATA = 1,
};

struct dpp_etcam_entry_vld_t {
	u8 vld;
	u8 rsv[3];
};

/* error code */
#define DPP_STAT_ETCAM_RC_BASE (0x6000)
#define DPP_ETCAM_RC_INVALID_PARA (DPP_STAT_ETCAM_RC_BASE | 0x0)

/* macro function */
#define DPP_ETCAM_ENTRY_SIZE_GET(entry_mode) (((u32)DPP_ETCAM_RAM_WIDTH << (3 - entry_mode)) / 8)

/* api */
DPP_STATUS dpp_etcam_dm_to_xy(struct dpp_etcam_entry_t *p_dm, struct dpp_etcam_entry_t *p_xy,
			      u32 len);

DPP_STATUS dpp_etcam_xy_to_dm(struct dpp_etcam_entry_t *p_dm, struct dpp_etcam_entry_t *p_xy,
			      u32 len);

DPP_STATUS dpp_etcam_block_tbl_id_set(struct dpp_dev_t *dev, u32 block_idx, u32 tbl_id);

DPP_STATUS dpp_etcam_block_tbl_id_get(struct dpp_dev_t *dev, u32 block_idx, u32 *p_tbl_id);

DPP_STATUS dpp_etcam_block_baddr_set(struct dpp_dev_t *dev, u32 block_idx, u32 base_addr);

DPP_STATUS dpp_etcam_block_baddr_get(struct dpp_dev_t *dev, u32 block_idx, u32 *p_base_addr);

DPP_STATUS dpp_etcam_cpu_afull_get(struct dpp_dev_t *dev, u32 block_idx, u32 *p_cpu_afull);

DPP_STATUS dpp_etcam_ind_cmd_set(struct dpp_dev_t *dev, u32 addr, u32 block_idx, u32 data_or_mask,
				 u32 wr_mask, u32 opr_type, u32 tacm_reg_flag, u32 row_mask_flag,
				 u32 vben, u32 vbit);
DPP_STATUS dpp_etcam_entry_add(struct dpp_dev_t *dev, u32 addr, u32 block_idx, u32 wr_mask,
			       u32 opr_type, struct dpp_etcam_entry_t *p_entry);
DPP_STATUS dpp_etcam_entry_del(struct dpp_dev_t *dev, u32 addr, u32 block_idx, u32 wr_mask);

u32 dpp_etcam_entry_cmp(struct dpp_etcam_entry_t *p_entry_dm, struct dpp_etcam_entry_t *p_entry_xy);

u32 dpp_etcam_ind_data_reg_opr_mask_get(u32 mask);

#if ZXIC_REAL("")

struct dpp_etcam_port_cnt {
	u32 as_etcam_req_cnt;
	u32 etcam_as_index_cnt;
	u32 etcam_not_hit_cnt;
};

struct dpp_etcam_dbg_cnt {
	struct dpp_etcam_port_cnt dpp_etcam_port_cnt[DPP_ETCAM_PORT_NUM];
	u32 table_id_not_match_cnt;
	u32 table_id_clash01_cnt;
};

#endif

#endif
