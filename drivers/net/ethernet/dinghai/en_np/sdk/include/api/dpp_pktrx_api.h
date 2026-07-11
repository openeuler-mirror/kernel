/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_PKTRX_API_H_
#define _DPP_PKTRX_API_H_

#include "zxic_common.h"
#include "dpp_module.h"
#include "dpp_reg.h"

#define PKTRX_IND_CMD_WRT_FLAG (0)
#define PKTRX_IND_CMD_RD_FLAG (1)

#define DPP_MCODE_FEATURE_LIST_NUM (6U)

enum dpp_pktrx_table_mem_id_e {
	PHYPORT_TAB_0_MEM_ID = 0,
	PHYPORT_TAB_1_MEM_ID = 1,
	PHYPORT_TAB_2_MEM_ID = 2,
	TCAM_MEM_ID_0 = 3,
	TCAM_MEM_ID_1 = 4,
	TCAM_RESULT_MEM_ID_0 = 5,
	TCAM_RESULT_MEM_ID_1 = 6,
	PKT_CAPTURE_MEM_ID = 7,
	MEM_ID_MUX_NUM = 8,
};

struct dpp_pktrx_phyport_udf_table_t {
	u32 port_based_user_data[4];
};
u32 dpp_pktrx_mcode_glb_cfg_set_0(struct dpp_dev_t *dev, u32 glb_cfg_data_0);
u32 dpp_pktrx_mcode_glb_cfg_set_1(struct dpp_dev_t *dev, u32 glb_cfg_data_1);
u32 dpp_pktrx_mcode_glb_cfg_set_2(struct dpp_dev_t *dev, u32 glb_cfg_data_2);
u32 dpp_pktrx_mcode_glb_cfg_set_3(struct dpp_dev_t *dev, u32 glb_cfg_data_3);
u32 dpp_pktrx_mcode_glb_cfg_get_0(struct dpp_dev_t *dev, u32 *p_glb_cfg_data_0);
u32 dpp_pktrx_mcode_glb_cfg_get_1(struct dpp_dev_t *dev, u32 *p_glb_cfg_data_1);
u32 dpp_pktrx_mcode_glb_cfg_get_2(struct dpp_dev_t *dev, u32 *p_glb_cfg_data_2);
u32 dpp_pktrx_mcode_glb_cfg_get_3(struct dpp_dev_t *dev, u32 *p_glb_cfg_data_3);
u32 dpp_pktrx_mcode_glb_cfg_write_0(struct dpp_dev_t *dev, u32 start_bit_no, u32 end_bit_no,
				    u32 glb_cfg_data_0);
u32 dpp_pktrx_mcode_glb_cfg_write_1(struct dpp_dev_t *dev, u32 start_bit_no, u32 end_bit_no,
				    u32 glb_cfg_data_1);
DPP_STATUS
dpp_pktrx_udf_table_get(struct dpp_dev_t *dev, u32 index,
			struct dpp_pktrx_phyport_udf_table_t *p_phyport_user_info);

#endif
