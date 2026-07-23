/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_APT_SE_H_
#define _DPP_APT_SE_H_

#include "dpp_apt_se_api.h"

#define SDT_OPER_ADD ((u32)(0))
#define SDT_OPER_DEL ((u32)(1))

#define SDT_DDR_RW_128BIT ((u32)(0))
#define SDT_DDR_RW_256BIT ((u32)(1))
#define SDT_DDR_RW_512BIT ((u32)(2))

#define DDR_128BIT_BYTE ((u32)(16))

#define ERAM_ENTRY_SOFT_MAX ((u32)(16))
#define HASH_ENTRY_SOFT_MAX ((u32)(64))
#define ACL_ENTRY_SOFT_MAX ((u32)(160))

struct se_apt_eram_func_t {
	u32 opr_mode;
	u32 rd_mode;
	DPP_APT_ERAM_SET_FUNC eram_set_func;
	DPP_APT_ERAM_GET_FUNC eram_get_func;
};

struct se_apt_ddr_func_t {
	u32 ddr_tbl_depth;
	DPP_APT_DDR_SET_FUNC ddr_set_func;
	DPP_APT_DDR_GET_FUNC ddr_get_func;
};

struct se_apt_acl_func_t {
	u32 sdt_partner;
	DPP_APT_ACL_ENTRY_SET_FUNC acl_set_func;
	DPP_APT_ACL_ENTRY_GET_FUNC acl_get_func;
};

struct se_apt_hash_func_t {
	DPP_APT_HASH_ENTRY_SET_FUNC hash_set_func;
	DPP_APT_HASH_ENTRY_GET_FUNC hash_get_func;
};

struct se_apt_lpm_func_t {
	DPP_APT_LPM_ENTRY_SET_FUNC lpm_set_func;
	DPP_APT_LPM_ENTRY_GET_FUNC lpm_get_func;
};
struct se_apt_callback_t {
	u32 sdtNo; /** <@brief sdt no 0~255 */
	u32 table_type;

	union {
		struct se_apt_eram_func_t eramFunc;
		struct se_apt_ddr_func_t ddrFunc;
		struct se_apt_acl_func_t aclFunc;
		struct se_apt_hash_func_t hashFunc;
		struct se_apt_lpm_func_t lpmFunc;
	} se_func_info;
};

struct se_apt_eram_convert_t {
	u32 sdt_no;
	DPP_APT_ERAM_SET_FUNC eram_set_func;
	DPP_APT_ERAM_GET_FUNC eram_get_func;
};

struct se_apt_ddr_convert_t {
	u32 sdt_no;
	DPP_APT_DDR_SET_FUNC ddr_set_func;
	DPP_APT_DDR_GET_FUNC ddr_get_func;
};

struct se_apt_hash_convert_t {
	u32 sdt_no;
	DPP_APT_HASH_ENTRY_SET_FUNC hash_set_func;
	DPP_APT_HASH_ENTRY_GET_FUNC hash_get_func;
};

struct se_apt_acl_convert_t {
	u32 sdt_no;
	DPP_APT_ACL_ENTRY_SET_FUNC acl_set_func;
	DPP_APT_ACL_ENTRY_GET_FUNC acl_get_func;
};

struct se_apt_lpm_convert_t {
	u32 sdt_no;
	DPP_APT_LPM_ENTRY_SET_FUNC lpm_set_func;
	DPP_APT_LPM_ENTRY_GET_FUNC lpm_get_func;
};

struct se_apt_eram_soft_t {
	u32 index;
	u32 buff[ERAM_ENTRY_SOFT_MAX / 4];
};

struct se_apt_eram_hash_t {
	u32 index;
	u8 aucData[HASH_ENTRY_SOFT_MAX];
};

struct se_apt_eram_acl_t {
	u32 index;
	u8 aucData[ACL_ENTRY_SOFT_MAX];
};

s32 dpp_apt_table_key_cmp(void *p_new_key, void *p_old_key, u32 key_len);
struct se_apt_callback_t *dpp_apt_get_func(struct dpp_dev_t *dev, u32 sdt_no);
DPP_STATUS dpp_apt_set_callback(struct dpp_dev_t *dev, u32 sdt_no, u32 table_type, void *pData);
DPP_STATUS dpp_apt_sw_list_insert(struct _rb_cfg *rb_cfg, void *pData, u32 len);
DPP_STATUS dpp_apt_sw_list_search(struct _rb_cfg *rb_cfg, void *pData, u32 len);
DPP_STATUS dpp_apt_sw_list_delete(struct _rb_cfg *rb_cfg, void *pData, u32 len);
DPP_STATUS dpp_apt_get_zblock_index(u32 zblock_bitmap, u32 *zblk_idx);
DPP_STATUS dpp_apt_dtb_res_init(struct dpp_dev_t *dev);
DPP_STATUS dpp_apt_se_callback_init(struct dpp_dev_t *dev);
u32 dpp_apt_get_sdt_partner(struct dpp_dev_t *dev, u32 sdt_no);
DPP_STATUS dpp_se_res_mem_alloc(struct dpp_dev_t *dev);
DPP_STATUS dpp_se_res_mem_free(struct dpp_dev_t *dev);
#endif
