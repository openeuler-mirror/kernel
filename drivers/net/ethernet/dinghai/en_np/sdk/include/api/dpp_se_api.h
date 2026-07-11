/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_SE_API_H_
#define _DPP_SE_API_H_

#if ZXIC_REAL("header file")
#include "dpp_type_api.h" /* xcx_0619 */
#endif

#if ZXIC_REAL("data struct define")

#define SE_SMMU0_ERAM_BLOCK_NUM (32)
#define SE_SMMU0_ERAM_ADDR_NUM_PER_BLOCK (0x4000)
#define SE_SMMU0_ERAM_ADDR_NUM_TOTAL (SE_SMMU0_ERAM_BLOCK_NUM * SE_SMMU0_ERAM_ADDR_NUM_PER_BLOCK)

#define DPP_DDR4_PER_BANK_BADDR_SETP (0x800) /* 8G X16 */
#define DPP_DDR4_BANK_NUM (64)
#define DPP_DDR4_PER_BANK_BADDR_CONV(ddr4_phy_type) \
	(DPP_DDR4_PER_BANK_BADDR_SETP * (4U >> ddr4_phy_type))

enum dpp_dma_ecc_en_e {
	DMA_ECC_DISABLE = 0,
	DMA_ECC_ENABLE = 1,
};

enum dpp_eram128_rd_clr_mode_e {
	RD_MODE_HOLD = 0,
	RD_MODE_CLEAR = 1,
};

enum dpp_eram128_opr_mode_e {
	ERAM128_OPR_128b = 0,
	ERAM128_OPR_64b = 1,
	ERAM128_OPR_1b = 2,
	ERAM128_OPR_32b = 3
};

enum dpp_eram128_tbl_mode_e {
	ERAM128_TBL_1b = 0,
	ERAM128_TBL_32b = 1,
	ERAM128_TBL_64b = 2,
	ERAM128_TBL_128b = 3,
	ERAM128_TBL_2b = 4,
	ERAM128_TBL_4b = 5,
	ERAM128_TBL_8b = 6,
	ERAM128_TBL_16b = 7
};

enum smmu0_empty_type_e {
	SMMU0_EMPTY_CLS0 = 0,
	SMMU0_EMPTY_CLS1 = 1,
	SMMU0_EMPTY_CLS2 = 2,
	SMMU0_EMPTY_CLS3 = 3,
	SMMU0_EMPTY_CLS4 = 4,
	SMMU0_EMPTY_CLS5 = 5,
	SMMU0_EMPTY_CLS6 = 6,
	SMMU0_EMPTY_CLS7 = 7,
	SMMU0_EMPTY_MCAST = 8,
	SMMU0_EMPTY_ODMA = 9,
};

enum smmu0_mcast_tbl_type_e {
	MCAST_TDM = 0,
	MCAST_DATA = 1,

	MCAST_INVALID,
};

enum se_dbg_cnt_read_mode_e {
	SE_DBG_CNT_READ_UNCLR = 0,
	SE_DBG_CNT_READ_CLR,
};

enum se_dbg_cnt_overflow_mode_e {
	SE_DBG_CNT_OVERFLOW_UNREVERSE = 0,
	SE_DBG_CNT_OVERFLOW_REVERSE,
};

enum se_ddr_phy_cfg_type_e {
	DPP_SE_DDR_PHY_32G_16 = 0,
	DPP_SE_DDR_PHY_16G_16,
	DPP_SE_DDR_PHY_8G_16,
	DPP_SE_DDR_PHY_4G_16,
	DPP_SE_DDR_PHY_32G_8,
	DPP_SE_DDR_PHY_16G_8,
	DPP_SE_DDR_PHY_8G_8,
	DPP_SE_DDR_PHY_4G_8,
	DPP_SE_DDR_PHY_MAX,
};

enum smmu1_ddr_wrt_mode_e {
	SMMU1_DDR_WRT_128b = 0,
	SMMU1_DDR_WRT_256b = 1,
	SMMU1_DDR_WRT_384b = 2,
	SMMU1_DDR_WRT_512b = 3,
};

enum smmu1_ddr_share_mode_e {
	SMMU1_DDR_SHARE_NO_SHARE = 0,
	SMMU1_DDR_SHARE_1_2 = 1,
	SMMU1_DDR_SHARE_1_4 = 2,
	SMMU1_DDR_SHARE_1_8 = 3,
	SMMU1_DDR_SHARE_MAX
};

enum smmu1_ddr_tbl_type_e {
	SMMU1_DDR_TBL_TYPE_DIR_TBL = 0,
	SMMU1_DDR_TBL_TYPE_HASH_TBL = 1,
	SMMU1_DDR_TBL_TYPE_LPM_TBL = 2,
	SMMU1_DDR_TBL_TYPE_OAM_TBL = 3,
	SMMU1_DDR_TBL_TYPE_FTM_TBL = 4,
	SMMU1_DDR_TBL_TYPE_ETM_TBL = 5,
	SMMU1_DDR_TBL_TYPE_MAX
};

enum cmmu_rd_mode_e {
	CMMU_RD_MODE_29_35 = 0,
	CMMU_RD_MODE_32 = 1,
	CMMU_RD_MODE_64 = 2,
	CMMU_RD_MODE_128 = 3,
	CMMU_RD_MODE_MAX,
};

enum cmmu_rd_clr_mode_e {
	CMMU_RD_CLR_MODE_UNCLR = 0,
	CMMU_RD_CLR_MODE_CLR = 1,
	CMMU_RD_CLR_MODE_MAX,
};

enum smmu1_ddr_srh_mode_e {
	SMMU1_DDR_SRH_128b = 0,
	SMMU1_DDR_SRH_256b,
	SMMU1_DDR_SRH_512b,
	SMMU1_DDR_SRH_MAX
};

struct se_ddr_addr_map_info_t {
	u32 is_inited;
	u32 ddr_phy_type;
	u32 se_use_bank_num;
	u32 bank_used_sate[64];
};

struct dpp_se_ept_flag_t {
	u32 ppu5_ept_flag;
	u32 ppu4_ept_flag;
	u32 ppu3_ept_flag;
	u32 ppu2_ept_flag;
	u32 ppu1_ept_flag;
	u32 ppu0_ept_flag;
};

struct dpp_smmu0_ept_flag_t {
	u32 ept_flag8;
	u32 ept_flag7;
	u32 ept_flag6;
	u32 ept_flag5;
	u32 ept_flag4;
	u32 ept_flag3;
	u32 ept_flag2;
	u32 ept_flag1;
	u32 ept_flag0;
};

struct dpp_se_smmu0_int0_t {
	u32 dma_ordfifo;
	u32 odma_ordfifo;
	u32 mcast_ordfifo;
};

struct data_mcast_t_ {
	u8 valid;
	u8 rsv;
	u16 mc_cnt; /**< @brief mc_cnt 16bit */
};

struct tdm_mcast_t_ {
	u8 valid;
	u8 rsv;
	u8 bitmap[6];
};

#endif

#if ZXIC_REAL("eTcam data struct define")

#endif

#if ZXIC_REAL("interrupt data struct define")

struct dpp_se_smmu0_int_t {
	u32 smmu0_int0;
	u32 smmu0_int1;
	u32 smmu0_int2;
	u32 smmu0_int3;
	u32 smmu0_int4;
	u32 smmu0_int5;
	u32 smmu0_int6;
	u32 smmu0_int7;
	u32 smmu0_int8;
	u32 smmu0_int9;
	u32 smmu0_int10;
	u32 smmu0_int11;
	u32 smmu0_int12;
	u32 smmu0_int13;
	u32 smmu0_int14;
	u32 smmu0_int15;
	u32 smmu0_int16;
	u32 smmu0_int17;
	u32 smmu0_int18;
	u32 smmu0_int19;
	u32 smmu0_int20;
	u32 smmu0_int21;
	u32 smmu0_int22;
	u32 smmu0_int23;
	u32 smmu0_int24;
	u32 smmu0_int25;
	u32 smmu0_int26;
	u32 smmu0_int27;
	u32 smmu0_int28;
	u32 smmu0_int29;
	u32 smmu0_int30;
	u32 smmu0_int31;
	u32 smmu0_int32;
	u32 smmu0_int33;
	u32 smmu0_int34;
	u32 smmu0_int35;
	u32 smmu0_int36;
	u32 smmu0_int37;
	u32 smmu0_int38;
};

struct dpp_smmu0_brief_int_t {
	u32 smmu0_int14_unmask_flag;
	u32 smmu0_int13_unmask_flag;
	u32 smmu0_int12_unmask_flag;
	u32 smmu0_int11_unmask_flag;
	u32 smmu0_int10_unmask_flag;
	u32 smmu0_int9_unmask_flag;
	u32 smmu0_int8_unmask_flag;
	u32 smmu0_int7_unmask_flag;
	u32 smmu0_int6_unmask_flag;
	u32 smmu0_int5_unmask_flag;
	u32 smmu0_int4_unmask_flag;
	u32 smmu0_int3_unmask_flag;
	u32 smmu0_int2_unmask_flag;
	u32 smmu0_int1_unmask_flag;
	u32 smmu0_int0_unmask_flag;
};

struct dpp_se_int_status_t {
	u32 as_int_unmask_flag;
	u32 kschd_int_unmask_flag;
	u32 rschd_int_unmask_flag;
	u32 smmu1_int_unmask_flag;
	u32 cmmu_int_unmask_flag;
	u32 parser_int_unmask_flag;
};

struct dpp_se_parser_int_t {
	u32 parser_int_en;
	u32 parser_int_mask;
	u32 parser_int_status;
};

struct dpp_se_kschd_int_t {
	u32 kschd_int_0;
	u32 kschd_int_1;
	u32 kschd_int_2;
	u32 kschd_int_3;
	u32 kschd_int_4;
};

struct dpp_se_rschd_int_t {
	u32 port0_int;
	u32 port1_int;
};

struct dpp_se_as_int_t {
	u32 as_int_0;
	u32 as_int_1;
	u32 as_int_2;
};

struct dpp_se_cmmu_int_t {
	u32 cmmu_int12;
	u32 cmmu_int11;
	u32 cmmu_int10;
	u32 cmmu_int9;
	u32 cmmu_int8;
	u32 cmmu_int7;
	u32 cmmu_int6;
	u32 cmmu_int5;
	u32 cmmu_int4;
	u32 cmmu_int3;
	u32 cmmu_int2;
	u32 cmmu_int1;
	u32 cmmu_int0;
};

struct dpp_se_alg_int_t {
	u32 wr_rsp_fifo_ovfl_int;
	u32 init_rd_cft_int;
	u32 schd_lpm_fifo_parity_err_int;
	u32 schd_hash3_fifo_parity_err_int;
	u32 schd_hash2_fifo_parity_err_int;
	u32 schd_hash1_fifo_parity_err_int;
	u32 schd_hash0_fifo_parity_err_int;
	u32 schd_learn_fifo_parity_err_int;
	u32 schd_lpm_fifo_ovfl_int;
	u32 schd_hash3_fifo_ovfl_int;
	u32 schd_hash2_fifo_unfl_int;
	u32 schd_hash1_fifo_ovfl_int;
	u32 schd_hash0_fifo_ovfl_int;
	u32 schd_learn_fifo_ovfl_int;

	u32 zblk31_parity_int;
	u32 zblk30_parity_int;
	u32 zblk29_parity_int;
	u32 zblk28_parity_int;
	u32 zblk27_parity_int;
	u32 zblk26_parity_int;
	u32 zblk25_parity_int;
	u32 zblk24_parity_int;
	u32 zblk23_parity_int;
	u32 zblk22_parity_int;
	u32 zblk21_parity_int;
	u32 zblk20_parity_int;
	u32 zblk19_parity_int;
	u32 zblk18_parity_int;
	u32 zblk17_parity_int;
	u32 zblk16_parity_int;
	u32 zblk15_parity_int;
	u32 zblk14_parity_int;
	u32 zblk13_parity_int;
	u32 zblk12_parity_int;
	u32 zblk11_parity_int;
	u32 zblk10_parity_int;
	u32 zblk9_parity_int;
	u32 zblk8_parity_int;
	u32 zblk7_parity_int;
	u32 zblk6_parity_int;
	u32 zblk5_parity_int;
	u32 zblk4_parity_int;
	u32 zblk3_parity_int;
	u32 zblk2_parity_int;
	u32 zblk1_parity_int;
	u32 zblk0_parity_int;

	u32 zcam_hash_p0_err_int;
	u32 hash0_agree_int_fifo_ovf_int;
	u32 hash0_agree_ext_fifo_ovf_int;
	u32 hash0_agree_ext_fifo_parity_err_int;
	u32 hash0_agree_int_fifo_parity_err_int;
	u32 hash0_key_fifo_ovfl_int;
	u32 hash0_sreq_fifo_ovfl_int;
	u32 hash0_key_fifo_parity_err_int;

	u32 zcam_hash_p1_err_int;
	u32 hash1_agree_int_fifo_ovf_int;
	u32 hash1_agree_ext_fifo_ovf_int;
	u32 hash1_agree_ext_fifo_parity_err_int;
	u32 hash1_agree_int_fifo_parity_err_int;
	u32 hash1_key_fifo_ovfl_int;
	u32 hash1_sreq_fifo_ovfl_int;
	u32 hash1_key_fifo_parity_err_int;

	u32 zcam_hash_p2_err_int;
	u32 hash2_agree_int_fifo_ovf_int;
	u32 hash2_agree_ext_fifo_ovf_int;
	u32 hash2_agree_ext_fifo_parity_err_int;
	u32 hash2_agree_int_fifo_parity_err_int;
	u32 hash2_key_fifo_ovfl_int;
	u32 hash2_sreq_fifo_ovfl_int;
	u32 hash2_key_fifo_parity_err_int;

	u32 zcam_hash_p3_err_int;
	u32 hash3_agree_int_fifo_ovf_int;
	u32 hash3_agree_ext_fifo_ovf_int;
	u32 hash3_agree_ext_fifo_parity_err_int;
	u32 hash3_agree_int_fifo_parity_err_int;
	u32 hash3_key_fifo_ovfl_int;
	u32 hash3_sreq_fifo_ovfl_int;
	u32 hash3_key_fifo_parity_err_int;

	u32 zcam_lpm_err_int;
	u32 lpm_as_int_rsp_fifo_ovfl_int;
	u32 lpm_as_req_fifo_ovfl_int;
	u32 lpm_ext_ddr_rsp_fifo_parity_int;
	u32 lpm_ext_v6_key_parity_int;
	u32 lpm_ext_v4_key_parity_int;
	u32 lpm_ext_addr_fifo_ovfl_int;
	u32 lpm_ext_v4_fifo_ovfl_int;
	u32 lpm_ext_v6_fifo_ovfl_int;
	u32 lpm_ext_ddr_rsp_ovf_int;
};

struct dpp_se_alg_brief_int_t {
	u32 schd_int_unmask_flag;
	u32 zblk_parity_int_unmask_flag;
	u32 hash0_int_unmask_flag;
	u32 hash1_int_unmask_flag;
	u32 hash2_int_unmask_flag;
	u32 hash3_int_unmask_flag;
	u32 lpm_int_unmask_flag;
};

struct dpp_se_smmu1_int_t {
	u32 smmu1_int0;
	u32 smmu1_int1;
	u32 smmu1_int2;
	u32 smmu1_int3;
	u32 smmu1_int4;
	u32 smmu1_int5;
	u32 smmu1_int6;
	u32 smmu1_int7;
	u32 smmu1_int8;
	u32 smmu1_int9;
	u32 smmu1_int10;
	u32 smmu1_int11;
	u32 smmu1_int12;
	u32 smmu1_int13;
	u32 smmu1_int14;
	u32 smmu1_int15;
	u32 smmu1_int16;
	u32 smmu1_int17;
};

struct dpp_etcam_intr_t {
	u32 etcam_int_33;
	u32 etcam_int_32;
	u32 etcam_int_31;
	u32 etcam_int_30;
	u32 etcam_int_29;
	u32 etcam_int_28;
	u32 etcam_int_27;
	u32 etcam_int_26;
	u32 etcam_int_25;
	u32 etcam_int_24;
	u32 etcam_int_23;
	u32 etcam_int_22;
	u32 etcam_int_21;
	u32 etcam_int_20;
	u32 etcam_int_19;
	u32 etcam_int_18;
	u32 etcam_int_17;
	u32 etcam_int_16;
	u32 etcam_int_15;
	u32 etcam_int_14;
	u32 etcam_int_13;
	u32 etcam_int_12;
	u32 etcam_int_11;
	u32 etcam_int_10;
	u32 etcam_int_9;
	u32 etcam_int_8;
	u32 etcam_int_7;
	u32 etcam_int_6;
	u32 etcam_int_5;
	u32 etcam_int_4;
	u32 etcam_int_3;
	u32 etcam_int_2;
	u32 etcam_int_1;
	u32 etcam_int_0;
};

struct dpp_se_stat_int_t {
	u32 stat_int0;
	u32 stat_int1;
	u32 stat_int2;
	u32 stat_int3;
	u32 stat_int4;
	u32 stat_int5;
};

#endif

#if ZXIC_REAL("macro function define")

#endif

#if ZXIC_REAL("function declaration")
DPP_STATUS dpp_se_smmu0_ind_write(struct dpp_dev_t *dev, u32 base_addr, u32 index, u32 wrt_mode,
				  u32 *p_data);
DPP_STATUS dpp_se_smmu0_ind_read(struct dpp_dev_t *dev, u32 base_addr, u32 index, u32 rd_mode,
				 u32 rd_clr_mode, u32 *p_data);

#endif

#if ZXIC_REAL("Hash & LPM data struct and function")

typedef DPP_STATUS (*WRITE32_FUN)(u32 dev_id, u32 addr, u32 write_data);
typedef DPP_STATUS (*READ32_FUN)(u32 dev_id, u32 addr, u32 *read_data);

typedef DPP_STATUS (*LPM_AS_RSLT_WRT_FUNCTION)(u32 dev_id, u32 as_type, u32 tbl_id, u32 index,
					       u8 *p_data);

#define SE_ZGRP_NUM (4)
#define SE_ZBLK_NUM (32)
#define SE_ZCELL_NUM (4)
#define SE_ZCELL_TOTAL_NUM (SE_ZBLK_NUM * SE_ZCELL_NUM)
#define SE_ZREG_NUM (4)
#define SE_RAM_DEPTH (512)
#define MAX_FUN_NUM (8)
#define SE_ALG_BANK_NUM (29)

#define LPM_THREAD_HW_WRITE_EN (0) /* ??????????????? */
#if LPM_THREAD_HW_WRITE_EN
#define ROUTE_DEV_CHANNEL_MAX (4) /* ?????? NPE_DEV_CHANNEL_MAX ??????? */
#define MAX_ITEM_INFO_BAK_NUM (0x100)
#endif

struct se_item_cfg {
	struct _d_head item_list;
	u32 item_index;
	u32 hw_addr;
	u32 bulk_id;
	u32 item_type;
	u8 wrt_mask;
	u8 valid;
	u8 pad[2];
};

#define DPP_ZCELL_FLAG_IS_MONO (1)

#define DPP_ZREG_FLAG_IS_MONO (1)

struct se_zcell_cfg {
	u8 flag;
	u32 bulk_id;
	u32 zcell_idx;
	u16 mask_len;
	u8 is_used;
	u8 is_share;
	u32 item_used;
	struct se_item_cfg item_info[SE_RAM_DEPTH];

	struct _d_node zcell_dn;
	struct _ZXIC_AVL_NODE zcell_avl;
};

struct se_zreg_cfg {
	u8 flag;
	u8 pad[3];
	u32 bulk_id;
	struct se_item_cfg item_info;
};

struct se_zblk_cfg {
	u32 zblk_idx;
	u16 is_used;
	u16 zcell_bm;
	u16 hash_arg;
	u16 pad;

	struct se_zcell_cfg zcell_info[SE_ZCELL_NUM];
	struct se_zreg_cfg zreg_info[SE_ZREG_NUM];

	struct _d_node zblk_dn;
};

struct func_id_info {
	void *fun_ptr;
	u8 fun_type;
	u8 fun_id;
	u8 is_used;
	u8 pad;
};

struct ddr_mem {
	u32 total_num;
	u32 base_addr;
	u32 base_addr_offset;
	u32 ecc_en;
	u32 bank_num;
	u32 bank_info[SE_ALG_BANK_NUM];
	u32 share_type;
	u32 item_used;
	struct _s_List_Stack_Manager *p_ddr_mng;
};

struct share_ram {
	u32 zblk_array[SE_ZBLK_NUM];
	struct _d_head zblk_list;
	struct _d_head zcell_free_list;
	u32 def_route_num;

	struct _rb_cfg def_rb;
	struct def_route_info *p_dr_info;

	struct ddr_mem ddr4_info;
	struct ddr_mem ddr6_info;
};

struct dpp_se_cfg {
	struct se_zblk_cfg zblk_info[SE_ZBLK_NUM];

	struct func_id_info fun_info[MAX_FUN_NUM];

	struct share_ram route_shareram;
	u32 reg_base;

	WRITE32_FUN p_write32_fun;
	READ32_FUN p_read32_fun;

	u32 lpm_flags;

	void *p_client;

	struct dpp_dev_t dev;
	u32 dev_id;

	LPM_AS_RSLT_WRT_FUNCTION p_as_rslt_wrt_fun;

#if LPM_THREAD_HW_WRITE_EN
	struct zxic_mutex_t cache_index_mutex[MAX_ITEM_INFO_BAK_NUM];
	u32 thread_hw_write_is_create;
	struct _s_List_Stack_Manager *p_thread_liststack_mng;
#endif
};

enum dpp_hash_ddr_width_mode {
	DDR_WIDTH_INVALID = 0,
	DDR_WIDTH_256b,
	DDR_WIDTH_512b,
};

enum dpp_hash_key_type {
	HASH_KEY_INVALID = 0,
	HASH_KEY_128b,
	HASH_KEY_256b,
	HASH_KEY_512b,
};

/**  hash ddr resource cfg info*/
struct dpp_hash_ddr_resc_cfg_t {
	u32 ddr_width_mode;
	u32 ddr_crc_sel;
	u32 ddr_item_num;
	u32 ddr_baddr;
	u32 ddr_ecc_en;
};

/** hash search mode */
enum dpp_hash_srh_mode {
	HASH_SRH_MODE_SOFT = 1,
	HASH_SRH_MODE_HDW = 2,
};

/** hash tbl_flag */
#define HASH_TBL_FLAG_AGE (1 << 0)
#define HASH_TBL_FLAG_LEARN (1 << 1)
#define HASH_TBL_FLAG_MC_WRT (1 << 2)

struct dpp_hash_entry {
	u8 *p_key;
	u8 *p_rst;
};

#define LPM_FLAG_RT_HANDLE_START (0)
#define LPM_FLAG_RT_HANDLE_WIDTH (1)
#define LPM4_FLAG_DDR_EN_START (1)
#define LPM4_FLAG_DDR_EN_WIDTH (1)
#define LPM6_FLAG_DDR_EN_START (2)
#define LPM6_FLAG_DDR_EN_WIDTH (1)
#define LPM4_FLAG_DDR_SEL_START (3)
#define LPM4_FLAG_DDR_SEL_WIDTH (1)
#define LPM6_FLAG_DDR_SEL_START (4)
#define LPM6_FLAG_DDR_SEL_WIDTH (1)
#define LPM_FLAG_AS_MODE_START (5)
#define LPM_FLAG_AS_MODE_WIDTH (1)

enum dpp_route_as_rsp_len_e {
	DPP_ROUTE_AS_128b = 0,
	DPP_ROUTE_AS_256b = 1,
	DPP_ROUTE_AS_384b = 2,
	DPP_ROUTE_AS_512b = 3
};

enum dpp_route_id_e {
	DPP_ROUTE_V4_ID = 4, /**<  @brief route ipv4 ID*/
	DPP_ROUTE_V6_ID = 5, /**<  @brief route ipv6 ID*/
};

enum dpp_route_mode_e { DPP_ROUTE_MODE_IPV4 = 1UL, DPP_ROUTE_MODE_IPV6 };

enum dpp_route_ddr_use_mode_e {
	DPP_ROUTE_DDR_USE_MINOR = 1,
	DPP_ROUTE_DDR_USE_MIDDLE = 2,
	DPP_ROUTE_DDR_USE_MAJOR = 3,
};

enum dpp_route_srh_mode_e {
	DPP_ROUTE_SRH_MODE_LP = 1,
	DPP_ROUTE_SRH_MODE_EQUAL = 2,
};

struct dpp_route_resource_t {
	u32 zblk_num;
	u32 *zblk_idx;
	u32 ddr4_item_num;
	u32 ddr4_baddr;
	u32 ddr4_base_offset;
	u32 ddr4_ecc_en;
	u32 ddr4_bank_num;
	u32 *ddr4_bank_info;
	u32 ddr4_share_type;
	u32 ddr6_item_num;
	u32 ddr6_baddr;
	u32 ddr6_base_offset;
	u32 ddr6_ecc_en;
	u32 ddr6_bank_num;
	u32 *ddr6_bank_info;
	u32 ddr6_share_type;
};

struct dpp_route_as_eram_t {
	u32 baddr;
	u32 rsp_mode;
};

struct dpp_route_as_ddr_t {
	u32 baddr;
	u32 rsp_len;
	u32 ecc_en;
};

union dpp_route_as_rslttbl_u {
	struct dpp_route_as_eram_t as_eram_cfg;
	struct dpp_route_as_ddr_t as_ddr_cfg;
};

struct dpp_route_ipv4_key_t {
	u32 vpnid; /**<  @brief vpnid，16bit*/
	u32 mask_len;
	u32 ipv4_addr;
};

struct dpp_route_entry_ipv4_t {
	struct dpp_route_ipv4_key_t route_key;
	u32 route_handle;
	u8 *p_as_rslt;
};

struct dpp_route_ipv6_key_t {
	u32 vpnid; /**<  @brief vpnid，16bit*/
	u32 mask_len;
	u32 ipaddr[4];
};

struct dpp_route_entry_ipv6_t {
	struct dpp_route_ipv6_key_t route_key;
	u32 route_handle;
	u8 *p_as_rslt;
};

struct dpp_hash_soft_reset_stor_dat {
	u32 ddr_dis_flag[4];
	u32 zblk_num[4];
	u32 *zblk_idx_start[4];

	u32 ddr_item_num[4][8];
	u32 ddr_base_addr[4];
	u32 ddr_bank_cp[4];
	u32 ddr_ecc_en[4];

	u32 hash_id_valid;
};
DPP_STATUS dpp_se_init(struct dpp_dev_t *dev, struct dpp_se_cfg *p_se_cfg);
DPP_STATUS dpp_se_client_init(struct dpp_se_cfg *p_se_cfg, void *p_client);
DPP_STATUS dpp_hash_init(struct dpp_se_cfg *p_se_cfg, u32 fun_id, u32 zblk_num, u32 *zblk_idx,
			 u32 ddr_dis);
DPP_STATUS dpp_hash_bulk_init(struct dpp_se_cfg *p_se_cfg, u32 fun_id, u32 bulk_id,
			      struct dpp_hash_ddr_resc_cfg_t *p_ddr_resc_cfg, u32 zcell_num,
			      u32 zreg_num);
DPP_STATUS dpp_hash_tbl_id_info_init(struct dpp_se_cfg *p_se_cfg, u32 fun_id, u32 tbl_id,
				     u32 tbl_flag, u32 key_type, u32 actu_key_size);

#endif

#if ZXIC_REAL("eTcam data struct and function")
typedef DPP_STATUS (*ACL_AS_RSLT_WRT_FUNCTION)(u32 dev_id, u32 base_addr, u32 index, u32 as_mode,
					       u8 *p_data);
#define DPP_ACL_TBL_ID_NUM (8U)
#define DPP_ACL_ETCAM_ID_NUM (1U)
#define DPP_ACL_BLOCK_NUM (8U)

enum dpp_etcam_entry_mode_e {
	DPP_ETCAM_KEY_640b = 0,
	DPP_ETCAM_KEY_320b = 1,
	DPP_ETCAM_KEY_160b = 2,
	DPP_ETCAM_KEY_80b = 3,
	DPP_ETCAM_KEY_INVALID,
};

enum dpp_etcam_opr_type_e {
	DPP_ETCAM_OPR_DM = 0,
	DPP_ETCAM_OPR_XY = 1,
};

struct dpp_etcam_entry_t {
	u32 mode;
	u8 *p_data;
	u8 *p_mask;
};

enum dpp_acl_key_mode_e {
	DPP_ACL_KEY_640b = 0,
	DPP_ACL_KEY_320b,
	DPP_ACL_KEY_160b,
	DPP_ACL_KEY_80b,
	DPP_ACL_KEY_INVALID,
};

enum dpp_acl_as_mode_e {
	DPP_ACL_AS_MODE_16b = 0,
	DPP_ACL_AS_MODE_32b = 1,
	DPP_ACL_AS_MODE_64b = 2,
	DPP_ACL_AS_MODE_128b = 3,
	DPP_ACL_AS_MODE_INVALID,
};

enum dpp_acl_srh_mode_e {
	DPP_ACL_SRH_SOFT = 0,
	DPP_ACL_SRH_HARDWARE = 1,
};

struct dpp_acl_entry_t {
	u32 handle;
	u8 *key_data;
	u8 *key_mask;
	u8 *p_as_rslt;
};

struct dpp_acl_block_info_t {
	u32 is_used;
	u32 tbl_id;
	u32 idx_base;
};

struct dpp_acl_etcamid_cfg_t {
	u32 is_valid;
	u32 as_enable;
	u32 as_idx_offset;
	u32 as_eRam_base;
	struct _d_head tbl_list;
};

struct dpp_acl_key_info_t {
	u32 handle;
	u32 pri;
	u8 key[0]; /* data+mask */
};

#define DPP_ACL_FLAG_ETCAM0_EN (1 << 0)
#define DPP_ACL_FLAG_ETCAM0_AS (1 << 2)

typedef DPP_STATUS (*ACL_TBL_AS_DDR_WR_FUN)(u32 dev_id, u32 tbl_type, u32 tbl_id,
					    u32 dir_tbl_share_type, u32 dir_tbl_base_addr,
					    u32 ecc_en, u32 index, u32 as_mode, u8 *p_data);
typedef DPP_STATUS (*ACL_TBL_AS_DDR_RD_FUN)(u32 dev_id, u32 base_addr, u32 index, u32 as_mode,
					    u8 *p_data);

/**  */
struct dpp_acl_tbl_cfg_t {
	u32 tbl_type;
	u32 table_id;
	u8 is_as_ddr;
	u8 ddr_bankcp_info;
	u32 dir_tbl_share_type;
	u8 ddr_ecc_en;
	u32 pri_mode;
	u32 key_mode;
	u32 entry_num;
	u32 block_num;
	u32 *block_array;
	u32 is_used;
	u32 as_mode;
	u32 as_idx_base;
	u32 as_enable;
	u32 as_eRam_base;
	u32 ddr_baddr;
	u32 idx_offset;
	ACL_TBL_AS_DDR_WR_FUN p_as_ddr_wr_fun;
	ACL_TBL_AS_DDR_RD_FUN p_as_ddr_rd_fun;
	struct _d_node entry_dn;
	struct INDEX_FILL_CFG index_mng;
	struct _rb_cfg acl_rb;
	struct dpp_acl_key_info_t **acl_key_buff;
	u8 *as_rslt_buff;
};

struct dpp_acl_cfg_t {
	void *p_client;
	struct dpp_dev_t *dev;
	u32 dev_id;
	u32 flags;
	ACL_AS_RSLT_WRT_FUNCTION p_as_rslt_write_fun;
	ACL_AS_RSLT_WRT_FUNCTION p_as_rslt_read_fun;
	struct dpp_acl_block_info_t acl_blocks[DPP_ACL_BLOCK_NUM];
	struct dpp_acl_etcamid_cfg_t acl_etcamids;
	struct dpp_acl_tbl_cfg_t acl_tbls[DPP_ACL_TBL_ID_NUM];
};

struct dpp_acl_cfg_ex_t {
	void *p_client;
	struct dpp_dev_t *dev;
	u32 dev_id;
	u32 flags;
	ACL_AS_RSLT_WRT_FUNCTION p_as_rslt_write_fun;
	ACL_AS_RSLT_WRT_FUNCTION p_as_rslt_read_fun;
	struct dpp_acl_block_info_t acl_blocks[DPP_ACL_BLOCK_NUM];
	struct dpp_acl_etcamid_cfg_t acl_etcamids;
	struct dpp_acl_tbl_cfg_t acl_tbls[DPP_ACL_TBL_ID_NUM];
};

enum dpp_acl_pri_mode_e {
	DPP_ACL_PRI_EXPLICIT = 1,
	DPP_ACL_PRI_IMPLICIT,
	DPP_ACL_PRI_SPECIFY,
	DPP_ACL_PRI_INVALID,
};

struct dpp_acl_entry_ex_t {
	u32 idx_val;
	struct _d_head idx_list;
	u32 pri;
	u8 *key_data;
	u8 *key_mask;
	u8 *p_as_rslt;
};
DPP_STATUS dpp_etcam_init(u32 dev_id);
DPP_STATUS dpp_acl_cfg_init_ex(struct dpp_dev_t *dev, struct dpp_acl_cfg_ex_t *p_acl_cfg,
			       void *p_client, u32 flags, ACL_AS_RSLT_WRT_FUNCTION p_as_wrt_fun);
DPP_STATUS dpp_acl_tbl_init_ex(struct dpp_acl_cfg_ex_t *p_acl_cfg, u32 table_id, u32 as_enable,
			       u32 entry_num, enum dpp_acl_pri_mode_e pri_mode, u32 key_mode,
			       enum dpp_acl_as_mode_e as_mode, u32 as_baddr, u32 block_num,
			       u32 *p_block_idx);
DPP_STATUS dpp_acl_res_destroy(u32 dev_id);

#endif

#if ZXIC_REAL("SDT data struct and function")

enum dpp_sdt_table_type_e {
	DPP_SDT_TBLT_INVALID = 0,
	DPP_SDT_TBLT_eRAM = 1,
	DPP_SDT_TBLT_DDR3 = 2,
	DPP_SDT_TBLT_HASH = 3,
	DPP_SDT_TBLT_LPM = 4,
	DPP_SDT_TBLT_eTCAM = 5,
	DPP_SDT_TBLT_PORTTBL = 6,
	DPP_SDT_TBLT_MAX = 7,
};

enum dpp_sdt_rsp_mode_e {
	DPP_SDT_RSP_32b = 0,
	DPP_SDT_RSP_64b = 1,
	DPP_SDT_RSP_128b = 2,
	DPP_SDT_RSP_256b = 3,
};

struct dpp_sdt_tbl_eram_t {
	u32 table_type;
	u32 eram_mode;
	u32 eram_base_addr;
	u32 eram_table_depth;
	u32 eram_clutch_en;
};

struct dpp_sdt_tbl_ddr3_t {
	u32 table_type;
	u32 ddr3_base_addr;
	u32 ddr3_share_type;
	u32 ddr3_rw_len;
	u32 ddr3_sdt_num;
	u32 ddr3_ecc_en;
	u32 ddr3_clutch_en;
};

struct dpp_sdt_tbl_hash_t {
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

struct dpp_sdt_tbl_lpm_t {
	u32 table_type;
	u32 lpm_v46_id;
	u32 rsp_mode;
	u32 lpm_table_depth;
	u32 lpm_clutch_en;
};

struct dpp_sdt_tbl_etcam_t {
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

struct dpp_sdt_tbl_porttbl_t {
	u32 table_type;
	u32 porttbl_clutch_en;
};
DPP_STATUS dpp_sdt_init(u32 dev_num, u32 *dev_id_array);
DPP_STATUS dpp_sdt_tbl_write(struct dpp_dev_t *dev, u32 sdt_no, u32 table_type, void *p_sdt_info,
			     u32 opr_type);
DPP_STATUS dpp_hash_search(struct dpp_se_cfg *p_se_cfg, u32 fun_id, struct dpp_hash_entry *p_entry,
			   u32 *p_space_vld, u32 srh_mode);

#endif

#endif /*dpp_se_api.h*/
