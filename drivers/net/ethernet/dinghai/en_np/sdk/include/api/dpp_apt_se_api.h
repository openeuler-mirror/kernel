/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_APT_SE_API_H_
#define _DPP_APT_SE_API_H_

#include "zxic_common.h"

#if ZXIC_REAL("header file")
#include "dpp_dev.h"
#include "dpp_se_api.h"
#include "dpp_etcam.h"
#include "dpp_se.h"
#include "dpp_agent_se_res.h"
#endif

#if ZXIC_REAL("data struct define")
typedef u32 (*DPP_APT_ACL_ENTRY_SET_FUNC)(void *pData, struct dpp_acl_entry_ex_t *aclEntry);
typedef u32 (*DPP_APT_ACL_ENTRY_GET_FUNC)(void *pData, struct dpp_acl_entry_ex_t *aclEntry);

typedef u32 (*DPP_APT_ERAM_SET_FUNC)(void *pData, u32 buf[4]);
typedef u32 (*DPP_APT_ERAM_GET_FUNC)(void *pData, u32 buf[4]);

typedef u32 (*DPP_APT_HASH_ENTRY_SET_FUNC)(void *pData, struct dpp_hash_entry *pEntry);
typedef u32 (*DPP_APT_HASH_ENTRY_GET_FUNC)(void *pData, struct dpp_hash_entry *pEntry);

typedef u32 (*DPP_APT_LPM_ENTRY_SET_FUNC)(void *pData, void *pEntry);
typedef u32 (*DPP_APT_LPM_ENTRY_GET_FUNC)(void *pData, void *pEntry);

typedef u32 (*DPP_APT_DDR_SET_FUNC)(void *pData, u32 buf[DPP_DIR_TBL_BUF_MAX_NUM]);
typedef u32 (*DPP_APT_DDR_GET_FUNC)(void *pData, u32 buf[DPP_DIR_TBL_BUF_MAX_NUM]);

enum dpp_se_res_type_e { SE_STD_NIC_RES_TYPE = 0, SE_NON_STD_NIC_RES_TYPE = 1, SE_RES_TYPE_BUTT };

struct dpp_apt_eram_table_t {
	u32 sdtNo; /** <@brief sdt no 0~255 */
	struct dpp_sdt_tbl_eram_t eRamSdt;
	u32 opr_mode;
	u32 rd_mode;
	DPP_APT_ERAM_SET_FUNC eram_set_func;
	DPP_APT_ERAM_GET_FUNC eram_get_func;
};

struct dpp_apt_ddr_table_t {
	u32 sdtNo; /** <@brief sdt no 0~255 */
	struct dpp_sdt_tbl_ddr3_t eDdrSdt;
	u32 ddr_table_depth;
	DPP_APT_DDR_SET_FUNC ddr_set_func;
	DPP_APT_DDR_GET_FUNC ddr_get_func;
};

struct dpp_apt_acl_res_t {
	u32 pri_mode;
	u32 entry_num;
	u32 block_num;
	u32 block_index[DPP_ETCAM_BLOCK_NUM]; /** <@brief  0~7 */
};

struct dpp_apt_acl_table_t {
	u32 sdtNo; /** <@brief sdt no 0~255 */
	u32 sdt_partner;
	struct dpp_sdt_tbl_etcam_t aclSdt;
	struct dpp_apt_acl_res_t aclRes;
	DPP_APT_ACL_ENTRY_SET_FUNC acl_set_func;
	DPP_APT_ACL_ENTRY_GET_FUNC acl_get_func;
};

struct dpp_apt_hash_table_t {
	u32 sdtNo; /** <@brief sdt no 0~255 */
	u32 sdt_partner;
	struct dpp_sdt_tbl_hash_t hashSdt;
	u32 tbl_flag;

	DPP_APT_HASH_ENTRY_SET_FUNC
	hash_set_func;
	DPP_APT_HASH_ENTRY_GET_FUNC hash_get_func;
};

struct dpp_apt_hash_func_res_t {
	u32 func_id;
	u32 zblk_num; /**<  @brief 0~32*/
	u32 zblk_bitmap;
	u32 ddr_dis;
};

struct dpp_apt_hash_bulk_res_t {
	u32 func_id; /**<  @brief 0~3*/
	u32 bulk_id; /**<  @brief 0~7*/
	u32 zcell_num; /**<  @brief 0~128*/
	u32 zreg_num; /**<  @brief 0~128*/
	u32 ddr_baddr;
	u32 ddr_item_num;

	enum dpp_hash_ddr_width_mode ddr_width_mode;
	u32 ddr_crc_sel;
	u32 ddr_ecc_en;
};

struct dpp_apt_route_res_t {
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

struct dpp_apt_lpm_table_t {
	u32 sdtNo; /** <@brief sdt no 0~255 */
	struct dpp_sdt_tbl_lpm_t lpmSdt;
	struct dpp_route_as_eram_t as_eram_cfg[DPP_SMMU0_LPM_AS_TBL_ID_NUM];
	struct dpp_route_as_ddr_t as_ddr_cfg;
	DPP_APT_LPM_ENTRY_SET_FUNC lpm_set_func;
	DPP_APT_LPM_ENTRY_GET_FUNC lpm_get_func;
};

struct dpp_apt_eram_res_init_t {
	u32 tbl_num;
	struct dpp_apt_eram_table_t *eram_res;
};

struct dpp_ddr_res_init_t {
	u32 tbl_num;
	struct dpp_apt_ddr_table_t *ddr_res;
};

struct dpp_apt_hash_res_init_t {
	u32 func_num;
	u32 bulk_num;
	u32 tbl_num;
	struct dpp_apt_hash_func_res_t *func_res;
	struct dpp_apt_hash_bulk_res_t *bulk_res;
	struct dpp_apt_hash_table_t *tbl_res;
};

struct dpp_apt_lpm_res_init_t {
	u32 tbl_num;
	struct dpp_apt_lpm_table_t *lpm_res;
	struct dpp_apt_route_res_t *glb_res;
};

struct dpp_apt_acl_res_init_t {
	u32 tbl_num;
	struct dpp_apt_acl_table_t *acl_res;
};

struct dpp_apt_stat_res_init_t {
	u32 eram_baddr;
	u32 eram_depth;
	u32 ddr_baddr;
	u32 ppu_ddr_offset;
};

struct dpp_stat_item_t {
	u32 mode;
	u32 addr_offset;
	u32 depth;
};

struct dpp_apt_se_res_t {
	u32 valid;
	u32 hash_func_num;
	u32 hash_bulk_num;
	u32 hash_tbl_num;
	u32 eram_num;
	u32 acl_num;
	u32 lpm_num;
	u32 ddr_num;
	u32 stat_item_num;
	struct dpp_apt_hash_func_res_t hash_func[HASH_FUNC_MAX_NUM];
	struct dpp_apt_hash_bulk_res_t hash_bulk[HASH_BULK_MAX_NUM];
	struct dpp_apt_hash_table_t hash_tbl[HASH_TABLE_MAX_NUM];
	struct dpp_apt_eram_table_t eram_tbl[ERAM_MAX_NUM];
	struct dpp_apt_acl_table_t acl_tbl[ETCAM_MAX_NUM];
	struct dpp_apt_route_res_t lpm_global_res;
	struct dpp_apt_lpm_table_t lpm_tbl[LPM_MAX_NUM];
	struct dpp_apt_ddr_table_t ddr_tbl[DDR_MAX_NUM];
	struct dpp_apt_stat_res_init_t stat_cfg;
	struct dpp_stat_item_t stat_item[STAT_ITEM_MAX_NUM];
};

#define DTB_DUMP_UNICAST_MAC_DUMP_NUM (32 * 257)
#define DTB_DUMP_MULTICAST_MAC_DUMP_NUM (32 * 257)
#endif

#if ZXIC_REAL("SE APT FUNCTION")
DPP_STATUS dpp_apt_eram_res_init(struct dpp_dev_t *dev, u32 tbl_num,
				 struct dpp_apt_eram_table_t *pEramTbl);
DPP_STATUS dpp_apt_ddr_res_init(struct dpp_dev_t *dev, u32 tbl_num,
				struct dpp_apt_ddr_table_t *pDdrTbl);
DPP_STATUS dpp_apt_acl_res_init(struct dpp_dev_t *dev, u32 tbl_num,
				struct dpp_apt_acl_table_t *pAclTblRes);
DPP_STATUS dpp_apt_acl_soft_res_uninit(struct dpp_dev_t *dev);
DPP_STATUS dpp_apt_hash_global_res_init(struct dpp_dev_t *dev);
DPP_STATUS dpp_apt_hash_global_res_uninit(struct dpp_dev_t *dev);
DPP_STATUS dpp_apt_hash_func_res_init(struct dpp_dev_t *dev, u32 func_num,
				      struct dpp_apt_hash_func_res_t *pHashFuncRes);
DPP_STATUS
dpp_apt_hash_func_flush_hardware_all(struct dpp_dev_t *dev, u32 func_num,
				     struct dpp_apt_hash_func_res_t *pHashFuncRes, u32 queue_id);
DPP_STATUS dpp_apt_hash_bulk_res_init(struct dpp_dev_t *dev, u32 bulk_num,
				      struct dpp_apt_hash_bulk_res_t *pBulkRes);
DPP_STATUS dpp_apt_hash_tbl_res_init(struct dpp_dev_t *dev, u32 tbl_num,
				     struct dpp_apt_hash_table_t *pHashTbl);
DPP_STATUS dpp_apt_dtb_eram_insert(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index,
				   void *pData);
DPP_STATUS dpp_apt_dtb_eram_get(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index,
				void *pData);
DPP_STATUS dpp_apt_dtb_eram_clear(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, u32 index);
DPP_STATUS dpp_apt_dtb_hash_insert(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData);
DPP_STATUS dpp_apt_dtb_hash_delete(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData);
DPP_STATUS dpp_apt_dtb_multi_hash_insert(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					 u32 entry_num, u32 entry_size, void *pData);
DPP_STATUS dpp_apt_dtb_multi_hash_delete(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					 u32 entry_num, u32 entry_size, void *pData);
DPP_STATUS dpp_apt_dtb_acl_entry_insert(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					void *pData);
DPP_STATUS dpp_apt_dtb_acl_entry_del(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData);
DPP_STATUS dpp_apt_dtb_acl_entry_search(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
					void *pData);
DPP_STATUS dpp_apt_dtb_acl_entry_get(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no, void *pData);
DPP_STATUS dpp_apt_sdt_res_deinit(struct dpp_dev_t *dev, u32 sdt_no);
DPP_STATUS dpp_agent_se_res_get(struct dpp_dev_t *dev);
DPP_STATUS dpp_se_res_init(struct dpp_dev_t *dev);
DPP_STATUS dpp_se_res_get_and_init(struct dpp_dev_t *dev);
DPP_STATUS dpp_hash_max_item_num_get(struct dpp_dev_t *dev, u32 sdt_no, u32 *max_num);
DPP_STATUS dpp_stat_tbl_get(struct dpp_dev_t *dev, struct dpp_apt_se_res_t *p_se_res);
DPP_STATUS dpp_apt_sdt_is_exist(struct dpp_apt_se_res_t *p_se_res,
				enum dpp_sdt_table_type_e sdt_type, u32 sdt_no, u32 *p_is_exist);

#endif

#endif
