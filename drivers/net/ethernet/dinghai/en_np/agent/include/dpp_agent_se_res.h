/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_AGENT_SE_RES_H
#define DPP_AGENT_SE_RES_H

#include "zxic_common.h"
#include "dpp_type_api.h"

#define HASH_FUNC_MAX_NUM (4)
#define HASH_BULK_MAX_NUM (32)
#define HASH_TABLE_MAX_NUM (38)
#define ERAM_MAX_NUM (60)
#define ETCAM_MAX_NUM (8)
#define DDR_MAX_NUM (50)
#define LPM_MAX_NUM (2)
#define STAT_ITEM_MAX_NUM (256)

#define ETCAM_BLOCK_NUM (8)
#define SMMU0_LPM_AS_TBL_ID_NUM (8)

#pragma pack(1)

struct sdt_tbl_eram_t {
	u32 table_type;
	u32 eram_mode;
	u32 eram_base_addr;
	u32 eram_table_depth;
	u32 eram_clutch_en;
};

struct sdt_tbl_ddr3_t {
	u32 table_type;
	u32 ddr3_base_addr;
	u32 ddr3_share_type;
	u32 ddr3_rw_len;
	u32 ddr3_sdt_num;
	u32 ddr3_ecc_en;
	u32 ddr3_clutch_en;
};

struct sdt_tbl_hash_t {
	u32 table_type;
	u32 hash_id;
	u32 hash_table_width;
	u32 key_size;
	u32 hash_table_id;
	u32 learn_en;
	u32 keep_alive;
	u32 keep_alive_baddr;
	u32 rsp_mode;
	u32 hash_clutch_en;
};

struct sdt_tbl_lpm_t {
	u32 table_type;
	u32 lpm_v46_id;
	u32 rsp_mode;
	u32 lpm_table_depth;
	u32 lpm_clutch_en;
};

struct sdt_tbl_etcam_t {
	u32 table_type;
	u32 etcam_id;
	u32 etcam_key_mode;
	u32 etcam_table_id;
	u32 no_as_rsp_mode;
	u32 as_en;
	u32 as_eram_baddr;
	u32 as_rsp_mode;
	u32 etcam_table_depth;
	u32 etcam_clutch_en;
};

struct hash_func_res_t {
	u32 func_id;
	u32 zblk_num;
	u32 zblk_bitmap;
	u32 ddr_dis;
};

struct hash_bulk_res_t {
	u32 func_id;
	u32 bulk_id;
	u32 zcell_num;
	u32 zreg_num;
	u32 ddr_baddr;
	u32 ddr_item_num;
	u32 ddr_width_mode;
	u32 ddr_crc_sel;
	u32 ddr_ecc_en;
};

struct hash_table_t {
	u32 sdtNo;
	u32 sdt_partner;
	struct sdt_tbl_hash_t hashSdt;
	u32 tbl_flag;
};

struct eram_table_t {
	u32 sdtNo;
	struct sdt_tbl_eram_t eRamSdt;
	u32 opr_mode;
	u32 rd_mode;
};

struct ddr_table_t {
	u32 sdtNo; /** <@brief sdt no 0~255 */
	struct sdt_tbl_ddr3_t eDdrSdt;
	u32 ddr_table_depth;
};

struct acl_res_t {
	u32 pri_mode;
	u32 entry_num;
	u32 block_num;
	u32 block_index[ETCAM_BLOCK_NUM]; /** <@brief 0~7 */
};

struct acl_table_t {
	u32 sdtNo; /** <@brief sdt no 0~255 */
	u32 sdt_partner;
	struct sdt_tbl_etcam_t aclSdt;
	struct acl_res_t aclRes;
};

struct route_as_eram_t {
	u32 baddr;
	u32 rsp_mode;
};

struct route_as_ddr_t {
	u32 baddr;
	u32 rsp_len;
	u32 ecc_en;
};

struct lpm_res_t {
	u32 pri_mode;
	u32 entry_num;
	u32 block_num;
	u32 block_index[ETCAM_BLOCK_NUM]; /** <@brief 0~7 */
};

/* @param lpm_flags
 * |0:eRam(5bit)1:ddr| (4bit) | (3bit) | (2bit) | (1bit) | (0bit) |
 * | | v6 | v4 | v6 | v4 | |
 */
struct route_res_t {
	u32 lpm_flags;
	u32 zblk_num;
	u32 zblk_bitmap;
	u32 mono_ipv4_zblk_num;
	u32 mono_ipv4_zblk_bitmap;
	u32 mono_ipv6_zblk_num;
	u32 mono_ipv6_zblk_bitmap;
	u32 ddr4_item_num;
	u32 ddr4_baddr;
	u32 ddr4_base_offset;
	u32 ddr4_ecc_en;
	u32 ddr6_item_num;
	u32 ddr6_baddr;
	u32 ddr6_base_offset;
	u32 ddr6_ecc_en;
};

struct lpm_table_t {
	u32 sdtNo; /** <@brief sdt no 0~255 */
	struct sdt_tbl_lpm_t lpmSdt;
	struct route_as_eram_t as_eram_cfg[SMMU0_LPM_AS_TBL_ID_NUM];
	struct route_as_ddr_t as_ddr_cfg;
};

struct se_hash_func_bulk_t {
	u32 func_num;
	u32 bulk_num;
	struct hash_func_res_t fun[HASH_FUNC_MAX_NUM];
	struct hash_bulk_res_t bulk[HASH_BULK_MAX_NUM];
};

struct se_hash_tbl_t {
	u32 tbl_num;
	struct hash_table_t table[HASH_TABLE_MAX_NUM];
};

struct se_eram_tbl_t {
	u32 tbl_num;
	struct eram_table_t eram[ERAM_MAX_NUM];
};

struct se_acl_tbl_t {
	u32 tbl_num;
	struct acl_table_t acl[ETCAM_MAX_NUM];
};

struct se_ddr_tbl_t {
	u32 tbl_num;
	struct ddr_table_t ddr[DDR_MAX_NUM];
};

struct se_lpm_tbl_t {
	u32 tbl_num;
	struct lpm_table_t lpm_res[LPM_MAX_NUM];
	struct route_res_t glb_res;
};

struct se_stat_cfg_t {
	u32 eram_baddr;
	u32 eram_depth;
	u32 ddr_baddr;
	u32 ppu_ddr_offset;
};

struct zxdh_np_se_res_t {
	struct se_hash_func_bulk_t hash_func_bulk;
	struct se_hash_tbl_t hash_tbl;
	struct se_eram_tbl_t eram_tbl;
	struct se_acl_tbl_t acl_tbl;
	struct se_lpm_tbl_t lpm_tbl;
	struct se_ddr_tbl_t ddr_tbl;
	struct se_stat_cfg_t stat_cfg;
};

struct zxdh_np_res {
	struct zxdh_np_se_res_t std_res;
	struct zxdh_np_se_res_t offload_res;
};

#pragma pack()

#endif
