/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/*********************************************************************
 * DEPARTMENT: ASIC_FPGA_R&D_Dept
 * MANUAL_PERCENT   : 100%
 ********************************************************************
 */
#ifndef _DPP_SDT_DEF_H_
#define _DPP_SDT_DEF_H_

enum dpp_tbl_type_e {
	TblType_Invalid = 0,
	TblType_Eram128 = 1,
	TblType_DDR3 = 2,
	TblType_HASH = 3,
	TblType_LPM = 4,
	TblType_eTcam = 5,
	TblType_PORTTBL = 6,
	TblType_MAX = 7
};

enum dpp_eram128_mode_e {
	Eram128Mode_1BITS = 0,
	Eram128Mode_32BITS = 1,
	Eram128Mode_64BITS = 2,
	Eram128Mode_128BITS = 3,
	Eram128Mode_2BITS = 4,
	Eram128Mode_4BITS = 5,
	Eram128Mode_8BITS = 6,
	Eram128Mode_16BITS = 7,
	Eram128Mode_MAX = 8
};

enum dpp_dde3_mode_e {
	DDR3Mode_128BITS = 0,
	DDR3Mode_256BITS = 1,
	DDR3Mode_512BITS = 2,
	DDR3Mode_MAX = 3
};

enum dpp_ddr3_share_mode_e {
	DDR_SHARE_MODE_NONE = 0,
	DDR_SHARE_MODE_1_2 = 1,
	DDR_SHARE_MODE_1_4 = 2,
	DDR_SHARE_MODE_1_8 = 3,
	DDR_SHARE_MODE_MAX = 4,
};

enum dpp_ddr3_copy_type_e {
	DDR3_COPY_TYPE_INN_0 = 0,
	DDR3_COPY_TYPE_INN_2 = 1,
	DDR3_COPY_TYPE_INN_4 = 2,
	DDR3_COPY_TYPE_INN_8 = 3,
	DDR3_COPY_TYPE_OUT_0 = 4,
	DDR3_COPY_TYPE_OUT_1 = 5,
	DDR3_COPY_TYPE_OUT_2 = 7,
};

#define HASH_SIM_ADD_ADDR (0xFFFFFFF4)
#define HASH_SIM_DEL_ADDR (0xFFFFFFF8)
#define LPM_SIM_ADD_ADDR (0xFFFFFFE4)
#define LPM_SIM_DEL_ADDR (0xFFFFFFE8)
#define ETCAM_SIM_ADD_ADDR (0xFFFFFFD4)
#define ETCAM_SIM_DEL_ADDR (0xFFFFFFD8)

struct dpp_sdt_smmu0_t {
	u32 *p_data;
	u32 wr_rd_flag; /*0: Write 1: Read        */
	u32 tbl_index;
	u32 tbl_base_addr;
	u32 mode;
	u32 tbl_depth;
};

struct dpp_sdt_smmu1_t {
	u32 *p_data;
	u32 crc_chk_en;
	u32 wr_rd_flag; /*0: Write 1: Read            */
	u32 ddr_share_type;
	u32 tbl_index;
	u32 tbl_base_addr;
	u32 ddr_mode;
	u32 sdt_no;
};

struct dpp_sdt_hash_t {
	u32 id;
	u32 tbl_id;
	u32 *p_data;
	u32 addr;
	u32 length;
	u32 key_size;
	u32 key_type;
	u32 rsp_mode;
	u32 wr_rd_flag; /* 0: Write 1: Read */
};

struct dpp_sdt_lpm_t {
	u32 *p_data;
	u32 addr;
	u32 length;
	u32 wr_rd_flag; /* 0: Write 1: Read */
	u32 v46_flag; /* 1:ipv4, 0:ipv6 */
};

struct dpp_sdt_etcam_t {
	u32 id;
	u32 tbl_id;
	u32 *p_data;
	u32 length;
	u32 addr;
	u32 wr_rd_flag; /* 0: Write 1: Read */
	u32 key_mode;
	u32 rsp_mode;
	u32 as_en;
	u32 as_eram_baddr;
	u32 as_rsp_mode;
};

#endif
