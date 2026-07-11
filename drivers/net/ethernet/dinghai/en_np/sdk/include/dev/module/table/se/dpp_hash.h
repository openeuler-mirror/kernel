/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_HASH_H_
#define _DPP_HASH_H_

#include "dpp_se_cfg.h"

#define HASH_FUNC_ID_MIN (0)
#define HASH_FUNC_ID_NUM (4)

#define HASH_DDR_CRC_NUM (4)

#define HASH_KEY_MAX (49)
#define HASH_RST_MAX (32)
#define HASH_ENTRY_POS_STEP (16)

#define HASH_TBL_ID_NUM (32)
#define HASH_BULK_NUM (8)

#define HASH_ACTU_KEY_MIN (1)
#define HASH_ACTU_KEY_MAX (48)
#define HASH_ACTU_KEY_STEP (1)
#define HASH_KEY_CTR_SIZE (1)
#define ITEM_ENTRY_NUM_2 (2)
#define ITEM_ENTRY_NUM_4 (4)

#define HASH_DDR_ITEM_MIN (1 << 14)
#define HASH_DDR_ITEM_MAX (1 << 26)

#define HASH_ZBLK_ID_MAX (31)

/* hash ext cfg reg */
#define HASH_EXT_MODE_BT_START (1)
#define HASH_EXT_MODE_BT_WIDTH (8)
#define HASH_EXT_FLAG_BT_START (0)
#define HASH_EXT_FLAG_BT_WIDTH (1)

/* hash tbl30 depth reg */
#define HASH_TBL0_DEPTH_BT_START (0)
#define HASH_TBL0_DEPTH_BT_WIDTH (8)
#define HASH_TBL1_DEPTH_BT_START (8)
#define HASH_TBL1_DEPTH_BT_WIDTH (8)
#define HASH_TBL2_DEPTH_BT_START (16)
#define HASH_TBL2_DEPTH_BT_WIDTH (8)
#define HASH_TBL3_DEPTH_BT_START (24)
#define HASH_TBL3_DEPTH_BT_WIDTH (8)

/* hash tbl74 depth reg*/
#define HASH_TBL4_DEPTH_BT_START (0)
#define HASH_TBL4_DEPTH_BT_WIDTH (8)
#define HASH_TBL5_DEPTH_BT_START (8)
#define HASH_TBL5_DEPTH_BT_WIDTH (8)
#define HASH_TBL6_DEPTH_BT_START (16)
#define HASH_TBL6_DEPTH_BT_WIDTH (8)
#define HASH_TBL7_DEPTH_BT_START (24)
#define HASH_TBL7_DEPTH_BT_WIDTH (8)

/* hash ext crc cfg*/
#define TBL0_EXT_CRC_CFG_BT_START (0)
#define TBL0_EXT_CRC_CFG_BT_WIDTH (2)
#define TBL1_EXT_CRC_CFG_BT_START (2)
#define TBL1_EXT_CRC_CFG_BT_WIDTH (2)
#define TBL2_EXT_CRC_CFG_BT_START (4)
#define TBL2_EXT_CRC_CFG_BT_WIDTH (2)
#define TBL3_EXT_CRC_CFG_BT_START (6)
#define TBL3_EXT_CRC_CFG_BT_WIDTH (2)
#define TBL4_EXT_CRC_CFG_BT_START (8)
#define TBL4_EXT_CRC_CFG_BT_WIDTH (2)
#define TBL5_EXT_CRC_CFG_BT_START (10)
#define TBL5_EXT_CRC_CFG_BT_WIDTH (2)
#define TBL6_EXT_CRC_CFG_BT_START (12)
#define TBL6_EXT_CRC_CFG_BT_WIDTH (2)
#define TBL7_EXT_CRC_CFG_BT_START (14)
#define TBL7_EXT_CRC_CFG_BT_WIDTH (2)

/* hash mono flags*/
#define HASH0_MONO_FLAG_BT_START (0)
#define HASH0_MONO_FLAG_BT_WIDTH (8)
#define HASH1_MONO_FLAG_BT_START (8)
#define HASH1_MONO_FLAG_BT_WIDTH (8)
#define HASH2_MONO_FLAG_BT_START (16)
#define HASH2_MONO_FLAG_BT_WIDTH (8)
#define HASH3_MONO_FLAG_BT_START (24)
#define HASH3_MONO_FLAG_BT_WIDTH (8)

/* hash zcell mono*/
#define ZCELL0_BULK_ID_BT_START (2)
#define ZCELL0_BULK_ID_BT_WIDTH (3)
#define ZCELL0_MONO_FLAG_BT_START (3)
#define ZCELL0_MONO_FLAG_BT_WIDTH (1)
#define ZCELL1_BULK_ID_BT_START (10)
#define ZCELL1_BULK_ID_BT_WIDTH (3)
#define ZCELL1_MONO_FLAG_BT_START (11)
#define ZCELL1_MONO_FLAG_BT_WIDTH (1)
#define ZCELL2_BULK_ID_BT_START (18)
#define ZCELL2_BULK_ID_BT_WIDTH (3)
#define ZCELL2_MONO_FLAG_BT_START (19)
#define ZCELL2_MONO_FLAG_BT_WIDTH (1)
#define ZCELL3_BULK_ID_BT_START (26)
#define ZCELL3_BULK_ID_BT_WIDTH (3)
#define ZCELL3_MONO_FLAG_BT_START (27)
#define ZCELL3_MONO_FLAG_BT_WIDTH (1)

/* hash zreg mono                         */
#define ZREG0_BULK_ID_BT_START (2)
#define ZREG0_BULK_ID_BT_WIDTH (3)
#define ZREG0_MONO_FLAG_BT_START (3)
#define ZREG0_MONO_FLAG_BT_WIDTH (1)
#define ZREG1_BULK_ID_BT_START (10)
#define ZREG1_BULK_ID_BT_WIDTH (3)
#define ZREG1_MONO_FLAG_BT_START (11)
#define ZREG1_MONO_FLAG_BT_WIDTH (1)
#define ZREG2_BULK_ID_BT_START (18)
#define ZREG2_BULK_ID_BT_WIDTH (3)
#define ZREG2_MONO_FLAG_BT_START (19)
#define ZREG2_MONO_FLAG_BT_WIDTH (1)
#define ZREG3_BULK_ID_BT_START (26)
#define ZREG3_BULK_ID_BT_WIDTH (3)
#define ZREG3_MONO_FLAG_BT_START (27)
#define ZREG3_MONO_FLAG_BT_WIDTH (1)

#define OPR_CLR (0)
#define OPR_WR (1)

#define OBTAIN_CONFLICT_KEY (0)

/* HASH soft reset*/
#define HASH_ARG_NUM_PER_BULK (8)
#define HASH_ARG_NUM_PER_TBL (4)
#define HASH_INIT_NUM (8)
#define HASH_BULK_INIT_NUM (1 + HASH_BULK_NUM * HASH_ARG_NUM_PER_BULK + 3)
#define HASH_TBL_INIT_NUM (1 + HASH_TBL_ID_NUM * HASH_ARG_NUM_PER_TBL + 3)

struct dpp_hash_table_stat {
	int ddr;
	int zcell;
	int zreg;
	int sum;
};

struct dpp_hash_zreg_mono_stat {
	u32 zblk_id;
	u32 zreg_id;
};

struct dpp_hash_bulk_zcam_stat {
	u32 zcell_mono_idx[SE_ZBLK_NUM * SE_ZCELL_NUM];
	struct dpp_hash_zreg_mono_stat zreg_mono_id[SE_ZBLK_NUM][SE_ZREG_NUM];
};

struct dpp_hash_stat {
	u32 insert_ok;
	u32 insert_fail;
	u32 insert_same;
	u32 insert_ddr;
	u32 insert_zcell;
	u32 insert_zreg;

	u32 delete_ok;
	u32 delete_fail;

	u32 search_ok;
	u32 search_fail;

	u32 zblock_num;
	u32 zblock_array[SE_ZBLK_NUM];

	struct dpp_hash_table_stat insert_table[HASH_TBL_ID_NUM];
	struct dpp_hash_bulk_zcam_stat *p_bulk_zcam_mono[HASH_BULK_NUM];
};

enum dpp_hash_itme_pos {
	HASH_ITEM_POS_0 = 0,
	HASH_ITEM_POS_1 = 1,
	HASH_ITEM_POS_2 = 2,
	HASH_ITEM_POS_3 = 3,
	HASH_ITEM_POS_MAX = 4,
};

enum dpp_hash_item_inst_mode {
	HASH_ITEM_INSERT_LAST = 0,
	HASH_ITEM_INSERT_1ST,
	HASH_ITEM_INSERT_NULL
};

struct dpp_hash_tbl_info {
	u32 fun_id;
	u32 actu_key_size;
	u32 key_type;
	u8 is_init;
	u8 mono_zcell;
	u8 zcell_num;
	u8 mono_zreg;
	u8 zreg_num;
	u8 is_age;
	u8 is_lrn;
	u8 is_mc_wrt;
	//u8 pad[3];
};

struct dpp_hash_rbkey_info {
	u8 key[HASH_KEY_MAX];
	u8 rst[HASH_RST_MAX];
	struct _d_node entry_dn;
	struct se_item_cfg *p_item_info;
	/*    u32       rb_idx;*/
	u32 entry_size;
	u32 entry_pos;
};

/* DDR*/
struct hash_ddr_cfg {
	u32 bulk_use;
	u32 ddr_baddr;
	u32 ddr_ecc_en;
	u32 item_num;
	u32 bulk_id;
	u32 hash_ddr_arg;
	u32 width_mode;
	u32 hw_baddr;
	u32 zcell_num;
	u32 zreg_num;

	struct se_item_cfg **p_item_array;
};

#define HASH_ADDR_EXT_FLAG_BT_OFF (31)
#define HASH_ADDR_WRT_MASK_BT_OFF (27)
#define HASH_ADDR_BT_OFF (1)
#define HASH_ADDR_DDR_BT_LEN (26)
#define HASH_ADDR_ZCAM_BT_LEN (17)
struct dpp_hash_wrt_lrn_rsp {
	u8 space_vld;
	u8 ext_flag;
	u8 wrt_mask;
	u8 width_flag;
	u32 lrn_addr;
};

struct dpp_hash_cfg {
	u32 fun_id;
	u8 ddr_valid;
	u8 pad[3];
	HASH_FUNCTION32 p_hash32_fun;
	HASH_FUNCTION p_hash16_fun;

	struct hash_ddr_cfg *p_bulk_ddr_info[HASH_BULK_NUM];
	u8 bulk_ram_mono[HASH_BULK_NUM];
	struct share_ram hash_shareram;
	struct dpp_se_cfg *p_se_info;

	struct _rb_cfg hash_rb;
	struct _rb_cfg ddr_cfg_rb;
	struct dpp_hash_stat hash_stat;
};

struct hash_entry_cfg {
	u32 fun_id;
	u8 bulk_id;
	u8 table_id;
	u8 key_type;
	u8 rsp_mode;
	u32 actu_key_size;
	u32 key_by_size;
	u32 rst_by_size;
	struct dpp_se_cfg *p_se_cfg;
	struct dpp_hash_cfg *p_hash_cfg;
	struct dpp_hash_rbkey_info *p_rbkey_new;
	struct _rb_tn *p_rb_tn_new;
};

#define DPP_GET_HASH_KEY_CTRL(valid, type, tbl_id) \
	(((valid & 0x1) << 7) | ((type & 0x3) << 5) | (tbl_id & 0x1f))
#define DPP_GET_HASH_TBL_ID(p_key) ((p_key)[0] & 0x1F)
#define DPP_GET_HASH_KEY_TYPE(p_key) (((p_key)[0] >> 5) & 0x3)
#define DPP_GET_HASH_KEY_VALID(p_key) (((p_key)[0] >> 7) & 0x1)

#define DPP_GET_HASH_ENTRY_SIZE(key_type) \
	((key_type == HASH_KEY_128b) ?    \
	16U :                    \
	((key_type == HASH_KEY_256b) ? 32U : ((key_type == HASH_KEY_512b) ? 64U : 0)))

#define DPP_GET_ACTU_KEY_BY_SIZE(actu_key_size) (actu_key_size * HASH_ACTU_KEY_STEP)

#define DPP_GET_KEY_SIZE(actu_key_size) \
	(DPP_GET_ACTU_KEY_BY_SIZE(actu_key_size) + HASH_KEY_CTR_SIZE)
#define DPP_GET_RST_SIZE(key_type, actu_key_size)   \
	((DPP_GET_HASH_ENTRY_SIZE(key_type) != 0) ?        \
	(DPP_GET_HASH_ENTRY_SIZE(key_type) - DPP_GET_ACTU_KEY_BY_SIZE(actu_key_size) - \
	HASH_KEY_CTR_SIZE) :                        \
	0xFF) /* modify coverity kfr 2022.05.31 */

#define DPP_GET_HASH_RB_KEY(p_hash_rb, idx) \
	((p_hash_rb)->p_keybase + ((p_hash_rb)->key_size * (idx)))

#define DPP_GET_DDR_WR_MODE(key_type) ((key_type == HASH_KEY_512b) ? key_type : (key_type - 1))

#define DPP_GET_HASH_ENTRY_MASK(entry_size, entry_pos) \
	((((1U << (entry_size / 16U)) - 1U) << (4U - entry_size / 16U - entry_pos)) & 0xF)

DPP_STATUS dpp_hash_zblkcfg_write(struct dpp_se_cfg *p_se_cfg, u32 fun_id,
				  struct se_zblk_cfg *p_zblk_cfg);

DPP_STATUS dpp_hash_bulk_mono_flags_write(struct dpp_se_cfg *p_se_cfg, u32 hash_id, u32 bulk_id);

DPP_STATUS dpp_hash_zcell_mono_write(struct dpp_se_cfg *p_se_cfg, struct se_zcell_cfg *p_zcell_cfg);

DPP_STATUS dpp_hash_zreg_mono_write(struct dpp_se_cfg *p_se_cfg, u32 tbl_id, u32 zblk_idx,
				    u32 zreg_id);

DPP_STATUS dpp_hash_ext_cfg_write(struct dpp_se_cfg *p_se_cfg, u32 fun_id, u32 bulk_id,
				  struct hash_ddr_cfg *p_ddr_cfg);

DPP_STATUS dpp_hash_ext_cfg_clr(struct dpp_se_cfg *p_se_cfg, u32 fun_id);

DPP_STATUS dpp_hash_tbl_depth_write(struct dpp_se_cfg *p_se_cfg, u32 fun_id, u32 bulk_id,
				    struct hash_ddr_cfg *p_ddr_cfg);

DPP_STATUS dpp_hash_tbl_depth_clr(struct dpp_se_cfg *p_se_cfg, u32 fun_id);

DPP_STATUS dpp_hash_tbl_crc_poly_write(struct dpp_se_cfg *p_se_cfg, u32 fun_id, u32 bulk_id,
				       u32 crc_sel);

s32 dpp_hash_rb_key_cmp(void *p_new, void *p_old, u32 key_size);

DPP_STATUS dpp_hash_insrt_to_item(struct dpp_hash_cfg *p_hash_cfg,
				  struct dpp_hash_rbkey_info *p_rbkey, struct se_item_cfg *p_item,
				  u32 item_idx, u32 item_type, u32 insrt_key_type);

DPP_STATUS dpp_hash_red_black_node_alloc(struct dpp_dev_t *dev, struct _rb_tn **p_rb_tn_new,
					 struct dpp_hash_rbkey_info **p_rbkey_new);

DPP_STATUS dpp_hash_rb_insert(struct dpp_dev_t *dev, struct hash_entry_cfg *p_hash_entry_cfg,
			      struct dpp_hash_entry *p_entry);

DPP_STATUS dpp_hash_set_crc_key(struct dpp_dev_t *dev, struct hash_entry_cfg *p_hash_entry_cfg,
				struct dpp_hash_entry *p_entry, u8 *p_temp_key);

DPP_STATUS dpp_hash_insert_ddr(struct dpp_dev_t *dev, struct hash_entry_cfg *p_hash_entry_cfg,
			       u8 *p_temp_key, u8 *p_end_flag);

DPP_STATUS dpp_hash_insert_zcell(struct dpp_dev_t *dev, struct dpp_se_cfg *p_se_cfg,
				 struct hash_entry_cfg *p_hash_entry_cfg, u8 *p_temp_key,
				 u8 *p_end_flag);

DPP_STATUS dpp_hash_insert_zreg(struct dpp_dev_t *dev, struct hash_entry_cfg *p_hash_entry_cfg,
				u8 *p_temp_key, u8 *p_end_flag);
DPP_STATUS dpp_hash_soft_all_entry_delete(struct dpp_se_cfg *p_se_cfg, u32 hash_id);
DPP_STATUS dpp_hash_soft_delete_by_sdt(struct dpp_dev_t *dev, u32 sdt_no);

DPP_STATUS dpp_hash_get_hash_info_from_sdt(struct dpp_dev_t *dev, u32 sdt_no,
					   struct hash_entry_cfg *p_hash_entry_cfg);

DPP_STATUS dpp_hash_soft_uninstall(struct dpp_dev_t *dev);

DPP_STATUS dpp_one_hash_soft_uninstall(struct dpp_dev_t *dev, u32 hash_id);

DPP_STATUS dpp_hash_tbl_clr(u32 dev_id);
#endif /* dpp_hash.h */
