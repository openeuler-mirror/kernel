/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/*****************************************************************************
 * DEPARTMENT       : ASIC_FPGA_R&D_Dept
 * MANUAL_PERCENT   : 100%
 *****************************************************************************
 */

#ifndef _DPP_SE_CFG_H_
#define _DPP_SE_CFG_H_

#include "dpp_se_api.h"

#define DPP_WRITE_FILE_EN (0)

#define LPM_OPTIMIZE_EZXIC_VOLUTION_TIME_SET_EN (0)

#define SE_ITEM_WIDTH_MAX (64)
#define SE_ENTRY_WIDTH_MAX (64)

#define SE_RAM_WIDTH (512)

#define IPV4_DDR_WIDTH (256)
#define IPV6_DDR_WIDTH (512)
#define IPV6_DDR_WIDTH_LR (384)

#define ROUTE_DEFAULT_REG_NUM (8)
#define ZBLK_LAST_INDREG_ADDR (0x15)
#define ZBLK_ECC_STATU_REG_ADDR (0x11)
#define ZBLK_HASH_LIST_REG0_ADDR (0xd)
#define ZBLK_HASH_LIST_REG3_ADDR (0x10)

#define ZCELL_ADDR_BT_START (0)
#define ZCELL_ADDR_BT_WIDTH (9)
#define ZCELL_IDX_BT_START (9)
#define ZCELL_IDX_BT_WIDTH (2)
#define ZBLK_IDX_BT_START (11)
#define ZBLK_IDX_BT_WIDTH (3)
#define ZGRP_IDX_BT_START (14)
#define ZGRP_IDX_BT_WIDTH (2)
#define REG_SRAM_FLAG_BT_START (16)
#define REG_SRAM_FLAG_BT_WIDTH (1)
#define ZBLK_WRT_MASK_BT_START (17)
#define ZBLK_WRT_MASK_BT_WIDTH (4)

#define ZBLK_NUM_PER_ZGRP (8)

#define SE_DDR_WIDTH (128)

struct def_route_info;

typedef u16 (*HASH_FUNCTION)(u8 *pkey, u32 width, u16 arg);
typedef u32 (*HASH_FUNCTION32)(u8 *pkey, u32 width, u32 arg);

typedef u32 (*WR_PROCESS)(u8 *p_buff, u32 size);

enum file_type {
	FILE_TYPE_REG = 0,
	FILE_TYPE_RAM,
	FILE_TYPE_ZBLK_CFG,
	FILE_TYPE_ZCELL_CFG,
	FILE_TYPE_DEF_ROUTE,
	FILE_TYPE_DDR256,
	FILE_TYPE_DDR512,
	FILE_TYPE_V6CMP_CFG,
	FILE_TYPE_V4CMP_CFG,
	FILE_TYPE_DDR128,
};

enum se_item_type {
	ITEM_INVALID = 0,
	ITEM_RAM,
	ITEM_DDR_256,
	ITEM_DDR_512,
	ITEM_REG,
};

enum se_fun_type { FUN_HASH = 1, FUN_LPM, FUN_ACL, FUN_MAX };

struct file_info {
	struct file *fp;
	u32 f_status; /*1 open, 0 close*/
};

struct file_mng {
	struct _rb_cfg rb_fn;
	struct file_info *p_fi;
};

#define ZBLK_CFG_BASE (0x8000)
#define SERVICE_REG_ADDR (0)
#define MASK_REG_ADDR (1)
#define DEFAULT_REG_ADDR (5)
#define V6CMP_REG_ADDR (0x12)
#define V4CMP_REG_ADDR (0x13)

#define GET_ZBLK_IDX(zcell_idx) (((zcell_idx)&0x7F) >> 2)

#define GET_ZCELL_IDX(zcell_idx) ((zcell_idx)&0x3)

#define DPP_SE_GET_ZBLK_CFG(p_se, zblk_idx) (&(((struct dpp_se_cfg *)(p_se))->zblk_info[zblk_idx]))

#define DPP_SE_GET_ZCELL_CFG(p_se, zcell_idx)           \
	(&(((struct dpp_se_cfg *)(p_se))                \
		   ->zblk_info[GET_ZBLK_IDX(zcell_idx)] \
		   .zcell_info[GET_ZCELL_IDX(zcell_idx)]))

#define DPP_GET_FUN_INFO(p_se, fun_id) (&(((struct dpp_se_cfg *)(p_se))->fun_info[fun_id]))

#define ZBLK_CHECK_FULL(p_zblk_cfg) \
	(((((struct se_zblk_cfg *)(p_zblk_cfg))->zcell_bm & 0xF) == 0xF) ? 1 : 0)

#define GET_ZCELL_CRC_VAL(zcell_id, crc16_val) (((crc16_val) >> (zcell_id)) & (SE_RAM_DEPTH - 1))

#define ZBLK_ADDR_CONV(zblk_idx)                                       \
	(((zblk_idx) / ZBLK_NUM_PER_ZGRP) * (1 << ZBLK_IDX_BT_WIDTH) + \
	 (zblk_idx) % ZBLK_NUM_PER_ZGRP)

#define ZCELL_ADDR_CONV(zcell_idx)                                             \
	((ZBLK_ADDR_CONV(((zcell_idx) >> ZCELL_IDX_BT_WIDTH) &                 \
			 ((1 << (ZBLK_IDX_BT_WIDTH + ZGRP_IDX_BT_WIDTH)) - 1)) \
	  << ZCELL_IDX_BT_WIDTH) |                                             \
	 ((zcell_idx) & ((1 << ZCELL_IDX_BT_WIDTH) - 1)))

#define ZCELL_BASE_ADDR_CALC(zcell_idx)                                               \
	((0xF << ZBLK_WRT_MASK_BT_START) |                                            \
	 (((ZCELL_ADDR_CONV(zcell_idx)) &                                             \
	   ((1 << (ZCELL_IDX_BT_WIDTH + ZBLK_IDX_BT_WIDTH + ZGRP_IDX_BT_WIDTH)) - 1)) \
	  << ZCELL_ADDR_BT_WIDTH))

#define ZBLK_ITEM_ADDR_CALC(zcell_idx, item_idx) \
	((ZCELL_BASE_ADDR_CALC(zcell_idx)) | ((item_idx) & (SE_RAM_DEPTH - 1)))

#define ZBLK_REG_ADDR_CALC(zblk_idx, offset)                                 \
	((0xF << ZBLK_WRT_MASK_BT_START) | (0x1 << REG_SRAM_FLAG_BT_START) | \
	 ((ZBLK_ADDR_CONV(zblk_idx) & 0x1F) << ZBLK_IDX_BT_START) | ((offset)&0x1FF))

#define ZBLK_HASH_LIST_REG_ADDR_CALC(zblk_idx, reg_idx) \
	(ZBLK_REG_ADDR_CALC((zblk_idx), (0xD + (reg_idx))))

#define ROUTEID_CONVT_ROUTEMODE(rout_id) \
	((rout_id & 0x01) ? DPP_ROUTE_MODE_IPV6 : DPP_ROUTE_MODE_IPV4)

DPP_STATUS dpp_se_cfg_set(struct dpp_dev_t *dev, struct dpp_se_cfg *p_se_cfg);

DPP_STATUS dpp_se_cfg_get(struct dpp_dev_t *dev, struct dpp_se_cfg **p_se_cfg);

DPP_STATUS dpp_se_init(struct dpp_dev_t *dev, struct dpp_se_cfg *p_se_cfg);

DPP_STATUS dpp_se_fun_init(struct dpp_se_cfg *p_se_cfg, u8 id, u32 fun_type);

DPP_STATUS dpp_se_fun_deinit(struct dpp_se_cfg *p_se_cfg, u8 id, u32 fun_type);

static inline int dpp_se_check_function(struct func_id_info *p_func_id, u32 id,
					enum se_fun_type type)
{
	if (!(p_func_id)->is_used) {
		ZXIC_COMM_TRACE_ERROR(
			"\n Error[0x%x],is_used Fun_id is invalid,(p_func_id)->is_used is [%d]",
			DPP_SE_RC_FUN_INVALID, (p_func_id)->is_used);
		return DPP_SE_RC_FUN_INVALID;
	} else if ((p_func_id)->fun_id != (id)) {
		ZXIC_COMM_TRACE_ERROR(
			"\n Error[0x%x],fun_id != (id) Fun_id is invalid;p_func_id->fun_id is [%d]",
			DPP_SE_RC_FUN_INVALID, (p_func_id)->fun_id);
		return DPP_SE_RC_FUN_INVALID;
	} else if (!(p_func_id)->fun_ptr) {
		ZXIC_COMM_TRACE_ERROR("\n Error[0x%x],fun_ptr Fun_id is invalid",
				      DPP_SE_RC_FUN_INVALID);
		return DPP_SE_RC_FUN_INVALID;
	} else if ((p_func_id)->fun_type != (type)) {
		ZXIC_COMM_TRACE_ERROR("\n Error[0x%x],type Fun_id is invalid",
				      DPP_SE_RC_FUN_INVALID);
		return DPP_SE_RC_FUN_INVALID;
	}
	return 0;
}

#define DPP_SE_CHECK_FUN(p_func_id, id, type) dpp_se_check_function((p_func_id), (id), (type))

static inline int dpp_se_check_function_mem_free(struct func_id_info *p_func_id, u32 id,
						 enum se_fun_type type, u8 *ptr)
{
	if (!(p_func_id)->is_used) {
		ZXIC_COMM_TRACE_ERROR(
			"\n Error[0x%x],is_used Fun_id is invalid,(p_func_id)->is_used is [%d]",
			DPP_SE_RC_FUN_INVALID, (p_func_id)->is_used);
		ZXIC_COMM_FREE(ptr);
		return DPP_SE_RC_FUN_INVALID;
	} else if ((p_func_id)->fun_id != (id)) {
		ZXIC_COMM_TRACE_ERROR(
			"\n Error[0x%x],fun_id != (id) Fun_id is invalid;p_func_id->fun_id is [%d]",
			DPP_SE_RC_FUN_INVALID, (p_func_id)->fun_id);
		ZXIC_COMM_FREE(ptr);
		return DPP_SE_RC_FUN_INVALID;
	} else if (!(p_func_id)->fun_ptr) {
		ZXIC_COMM_TRACE_ERROR("\n Error[0x%x],fun_ptr Fun_id is invalid",
				      DPP_SE_RC_FUN_INVALID);
		ZXIC_COMM_FREE(ptr);
		return DPP_SE_RC_FUN_INVALID;
	} else if ((p_func_id)->fun_type != (type)) {
		ZXIC_COMM_TRACE_ERROR("\n Error[0x%x],type Fun_id is invalid",
				      DPP_SE_RC_FUN_INVALID);
		ZXIC_COMM_FREE(ptr);
		return DPP_SE_RC_FUN_INVALID;
	}
	return 0;
}

#define DPP_SE_CHECK_FUN_MEMORY_FREE(p_func_id, id, type, ptr) \
	dpp_se_check_function_mem_free((p_func_id), (id), (type), (ptr))

#define DPP_SE_HW_POS(x) (SE_RAM_WIDTH - 1 - (x))

#define DPP_SE_ZBLK_OUT_DDR_V6_START (0)
#define DPP_SE_ZBLK_OUT_DDR_V6_END (0)

#define DPP_SE_ZBLK_OUT_DDR_V4_START (0)
#define DPP_SE_ZBLK_OUT_DDR_V4_END (0)

#define DPP_SE_ZBLK_SERVICE_TYPE_START (3)
#define DPP_SE_ZBLK_SERVICE_TYPE_END (3)

#define DPP_SE_ZBLK_HASH_CHAN_START (2)
#define DPP_SE_ZBLK_HASH_CHAN_END (1)

#define DPP_SE_ZBLK_HW_POS_EN_START (0)
#define DPP_SE_ZBLK_HW_POS_EN_END (0)

#endif
