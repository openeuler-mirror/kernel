/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_REG_API_H_
#define _DPP_REG_API_H_
#include "dpp_dev.h"
#include "dpp_reg_struct.h"

extern struct dpp_reg_t g_dpp_reg_info[];

/**  public*/
#define DPP_REG(no) (g_dpp_reg_info[no])
#define DPP_REG_NAME(no) ((DPP_REG(no)).reg_name)
#define DPP_REG_NO(no) ((DPP_REG(no)).reg_no)
#define DPP_REG_MODULE_NO(no) ((DPP_REG(no)).module_no)
#define DPP_REG_FLAGS(no) ((DPP_REG(no)).flags)
#define DPP_REG_TYPE(no) ((DPP_REG(no)).array_type)
#define DPP_REG_ADDR(no) ((DPP_REG(no)).addr)
#define DPP_REG_WIDTH(no) ((DPP_REG(no)).width)
#define DPP_REG_M_SIZE(no) ((DPP_REG(no)).m_size)
#define DPP_REG_N_SIZE(no) ((DPP_REG(no)).n_size)
#define DPP_REG_M_STEP(no) ((DPP_REG(no)).m_step)
#define DPP_REG_N_STEP(no) ((DPP_REG(no)).n_step)
#define DPP_REG_FIELD_NUM(no) ((DPP_REG(no)).field_num)
#define DPP_REG_FIELD_NAME(no, field_no) (((DPP_REG(no)).p_fields + field_no)->p_name)

enum dpp_bar_4k_e {
	BAR_4K_DTB = 0, /**<  @brief 0*/
	BAR_4K_ETCAM, /**<  @brief 1*/
	BAR_4K_CLS0, /**<  @brief 2*/
	BAR_4K_CLS1, /**<  @brief 3*/
	BAR_4K_CLS2, /**<  @brief 4*/
	BAR_4K_CLS3, /**<  @brief 5*/
	BAR_4K_CLS4, /**<  @brief 6*/
	BAR_4K_CLS5, /**<  @brief 7*/
	BAR_4K_SE, /**<  @brief 8*/
	BAR_4K_SMMU1, /**<  @brief 9*/
	BAR_4K_MAX
};

struct DPP_REG_OFFSET_ADDR {
	u32 reg_module; /*DPP_MODULE_E*/
	u32 index_4k;
	u32 addr_offset;
};
struct dpp_reg_t *dpp_reg_info_get(u32 reg_no);
DPP_STATUS dpp_reg_write(struct dpp_dev_t *dev, u32 reg_no, u32 m_offset, u32 n_offset,
			 void *p_data);
DPP_STATUS dpp_reg_read(struct dpp_dev_t *dev, u32 reg_no, u32 m_offset, u32 n_offset,
			void *p_data);
u32 dpp_reg_get_reg_addr(u32 reg_no, u32 m_offset, u32 n_offset);
DPP_STATUS dpp_reg_write32(struct dpp_dev_t *dev, u32 reg_no, u32 data);
DPP_STATUS dpp_reg_read32(struct dpp_dev_t *dev, u32 reg_no, u32 m_offset, u32 n_offset,
			  u32 *p_data);
BOOLEAN dpp_4k_reg(u32 reg_module);
u32 dpp_reg_addr_convert(u32 dev_id, u32 reg_module, u32 flags, u32 addr);

#endif
