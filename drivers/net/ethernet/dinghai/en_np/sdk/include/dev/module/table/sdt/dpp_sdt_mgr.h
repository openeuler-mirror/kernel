/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/*********************************************************************
 * DEPARTMENT: ASIC_FPGA_R&D_Dept
 * MANUAL_PERCENT   : 100%
 ********************************************************************
 */

#ifndef _DPP_SDT_MGR_H_
#define _DPP_SDT_MGR_H_

#include "dpp_sdt_def.h"
#define DPP_SDT_CFG_LEN (2)

#define DPP_SDT_VALID (1)
#define DPP_SDT_INVALID (0)

#define DPP_SDT_WRITE (0)
#define DPP_SDT_READ (1)

#define DPP_SDT_MAX_BUFF (18)

#define DPP_TBL_DATA_MAX (50)

enum dpp_opr_type_e {
	DPP_TABLE_UPDATE = 0,
	DPP_TABLE_DELETE = 1,
	DPP_TABLE_SEARCH = 2,
};

struct dpp_eram128_params_t {
	u32 tbl_base_addr;
	enum dpp_eram128_mode_e eram128_mode;
	u32 tbl_depth;
	u32 count;
};

struct dpp_ddr3_params_t {
	u32 base_addr;
	u32 crc_check;
	enum dpp_dde3_mode_e ddr3_mode;
	u32 tbl_share_mode;
	u32 wr_rd_count;
};

enum dpp_hash_key_width_e {
	HashKey_Invalid = 0,
	HashKey_128b,
	HashKey_256b,
	HashKey_512b,
	HashKey_MAX
};

struct dpp_hash_params_t {
	u8 hash_id;
	u8 key_tbl_width;
	u8 key_size;
	u8 table_id;
	u8 rsp_mode;
};

struct dpp_lpm_params_t {
	u8 v46_flag; /* 1:Ipv4, 0:Ipv6 */
	u8 count;
	u8 pad[2];
};

struct dpp_etcam_params_t {
	u8 id;
	u8 table_id;
	u8 key_mode;
	u8 rsp_mode;
	u8 as_en;
	u32 as_baddr;
	u8 as_rsp_mode;
};

typedef u32 (*dpp_sdt_mgr_smmu0_mux_fun_ptr)(u32 dev_id, struct dpp_sdt_smmu0_t *p_sdt_smmu0);
typedef u32 (*dpp_sdt_mgr_smmu1_mux_fun_ptr)(u32 dev_id, struct dpp_sdt_smmu1_t *p_sdt_smmu1);
typedef u32 (*dpp_sdt_mgr_hash_mux_fun_ptr)(u32 dev_id, struct dpp_sdt_hash_t *p_sdt_hash);
typedef u32 (*dpp_sdt_mgr_lpm_mux_fun_ptr)(u32 dev_id, struct dpp_sdt_lpm_t *p_sdt_lpm);
typedef u32 (*dpp_sdt_mgr_etcam_mux_fun_ptr)(u32 dev_id, struct dpp_sdt_etcam_t *p_sdt_etcam);

struct dpp_sdt_item_t {
	u32 valid;
	u32 table_cfg[DPP_SDT_CFG_LEN];
};

struct dpp_sdt_soft_table_t {
	u32 device_id;
	struct dpp_sdt_item_t sdt_array[DPP_PCIE_SLOT_MAX][DPP_DEV_SDT_ID_MAX];
};

struct dpp_sdt_mgr_t {
	u32 channel_num;
	u32 is_init;
	struct dpp_sdt_soft_table_t *sdt_tbl_array[DPP_DEV_CHANNEL_MAX];
	dpp_sdt_mgr_smmu0_mux_fun_ptr p_sdt_mgr_smmu0_mux;
	dpp_sdt_mgr_smmu1_mux_fun_ptr p_sdt_mgr_smmu1_mux;
	dpp_sdt_mgr_hash_mux_fun_ptr p_sdt_mgr_hash_mux;
	dpp_sdt_mgr_lpm_mux_fun_ptr p_sdt_mgr_lpm_mux;
	dpp_sdt_mgr_etcam_mux_fun_ptr p_sdt_mgr_etcam_mux;
};

u32 dpp_sdt_mgr_init(void);
u32 dpp_sdt_mgr_create(u32 dev_id);
u32 dpp_sdt_mgr_destroy(u32 dev_id);

DPP_STATUS dpp_sdt_mgr_sdt_item_add(struct dpp_dev_t *dev, u32 sdt_no, u32 sdt_hig32,
				    u32 sdt_low32);
DPP_STATUS dpp_sdt_mgr_sdt_item_srh(struct dpp_dev_t *dev, u32 sdt_no, u32 *p_sdt_hig32,
				    u32 *p_sdt_low32);
DPP_STATUS dpp_sdt_mgr_sdt_item_del(struct dpp_dev_t *dev, u32 sdt_no);

#endif
