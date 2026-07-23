/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_ACL_H_
#define _DPP_ACL_H_

#include "dpp_se_api.h"

#define DPP_ACL_TBL_ID_MIN (0)
#define DPP_ACL_TBL_ID_MAX (7)
#define DPP_ACL_ETCAM_ID_MIN (0)
#define DPP_ACL_ETCAM_ID_MAX (0)

#define DPP_ACL_ENTRY_MAX_GET(key_mode, block_num) \
	((block_num)*DPP_ETCAM_RAM_DEPTH * (1U << (key_mode)))

#define DPP_ACL_AS_RSLT_SIZE_GET(mode)                       \
	(((mode) == DPP_ACL_AS_MODE_128b) ?                  \
		       (128 / 8) :                                 \
		       (((mode) == DPP_ACL_AS_MODE_64b) ?          \
				(64 / 8) :                         \
				(((mode) == DPP_ACL_AS_MODE_32b) ? \
					 (32 / 8) :                \
					 (((mode) == DPP_ACL_AS_MODE_16b) ? (16 / 8) : (0)))))

#define DPP_ACL_AS_RSLT_SIZE_GET_EX(mode) (2U << (mode))

enum dpp_acl_as_mode_ex_e {
	DPP_ACL_AS_MODE_EX_64b = 1,
	DPP_ACL_AS_MODE_EX_128b = 2,
	DPP_ACL_AS_MODE_EX_256b = 3,
	DPP_ACL_AS_MODE_EX_INVALID,
};
DPP_STATUS dpp_acl_cfg_init(struct dpp_acl_cfg_t *p_acl_cfg, void *p_client, u32 flags,
			    ACL_AS_RSLT_WRT_FUNCTION p_as_wrt_fun);

/***********************************************************/
DPP_STATUS dpp_acl_cfg_get(struct dpp_dev_t *dev, struct dpp_acl_cfg_ex_t **p_acl_cfg);

/***********************************************************/
void dpp_acl_cfg_set(struct dpp_dev_t *dev, struct dpp_acl_cfg_ex_t *p_acl_cfg);
DPP_STATUS dpp_acl_tbl_init(struct dpp_acl_cfg_t *p_acl_cfg, u32 table_id, u32 as_enable,
			    u32 entry_num, enum dpp_acl_key_mode_e key_mode,
			    enum dpp_acl_as_mode_e as_mode, u32 block_num, u32 *p_block_idx);

DPP_STATUS dpp_acl_hdw_addr_get(struct dpp_acl_tbl_cfg_t *p_tbl_cfg, u32 handle, u32 *p_block_idx,
				u32 *p_addr, u32 *p_wr_mask);
#endif
