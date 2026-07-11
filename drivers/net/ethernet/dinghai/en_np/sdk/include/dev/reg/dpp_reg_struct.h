/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_REG_STRUCT_H_
#define _DPP_REG_STRUCT_H_
#include "zxic_common.h"
#include "dpp_dev.h"
#include "dpp_type_api.h"

typedef u32 (*DPP_REG_WRITE)(struct dpp_dev_t *dev, u32 addr, u32 *p_data);
typedef u32 (*DPP_REG_READ)(struct dpp_dev_t *dev, u32 addr, u32 *p_data);

#define DPP_FIELD_FLAG_RO (1 << 0)
#define DPP_FIELD_FLAG_RW (1 << 1)
#define DPP_FIELD_FLAG_RC (1 << 2)
#define DPP_FIELD_FLAG_WO (1 << 3)
#define DPP_FIELD_FLAG_WC (1 << 4)

struct dpp_field_t {
	char *p_name;
	u32 flags;
	u16 msb_pos;
	u16 len;
	u32 default_value;
	u32 default_step;
};

#define DPP_REG_FLAG_DIRECT (0 << 0)
#define DPP_REG_FLAG_INDIRECT (1 << 0)
#define DPP_REG_FLAG_WO (1 << 1)

#define DPP_REG_NUL_ARRAY (0 << 0)
#define DPP_REG_UNI_ARRAY (1 << 0)
#define DPP_REG_BIN_ARRAY (1 << 1)

struct dpp_reg_t {
	char *reg_name;
	u32 reg_no;
	u32 module_no;
	u32 flags;
	u32 array_type;
	u32 addr;
	u32 width;
	u32 m_size;
	u32 n_size;
	u32 m_step;
	u32 n_step;
	u32 field_num;
	struct dpp_field_t *p_fields;

	DPP_REG_WRITE p_write_fun;
	DPP_REG_READ p_read_fun;
};

#endif
