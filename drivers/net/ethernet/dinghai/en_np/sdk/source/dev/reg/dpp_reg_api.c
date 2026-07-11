// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_module.h"
#include "dpp_dev.h"
#include "dpp_reg_api.h"
#include "dpp_reg_info.h"
#include "dpp_agent_channel.h"
#include "dpp_pci.h"

#define REG_DATA_MAX (512 / 32)

static struct DPP_REG_OFFSET_ADDR g_module_offset_addr[] = {
	{ DTB4K, BAR_4K_DTB, SYS_DTB_BASE_ADDR + MODULE_DTB_ENQ_BASE_ADDR },
	{ STAT4K, BAR_4K_ETCAM, SYS_STAT_BASE_ADDR + MODULE_STAT_ETCAM_BASE_ADDR },
	{ PPU4K, BAR_4K_CLS0, SYS_PPU_BASE_ADDR + MODULE_CLUSTER0_BASE_ADDR + 0x4000 },
	{ SE4K, BAR_4K_SE, SYS_SE_BASE_ADDR + MODULE_SE_ALG_BASE_ADDR },
	{ SMMU14K, BAR_4K_SMMU1, SYS_SE_SMMU1_BASE_ADDR + MODULE_SE_SMMU1_BASE_ADDR }
};

struct dpp_reg_t *dpp_reg_info_get(u32 reg_no)
{
	ZXIC_COMM_CHECK_INDEX_RETURN_NULL(reg_no, 0, REG_ENUM_MAX_VALUE - 1);

	return &g_dpp_reg_info[reg_no];
}
u32 dpp_reg_get_reg_addr(u32 reg_no, u32 m_offset, u32 n_offset)
{
	u32 addr = 0;
	struct dpp_reg_t *p_reg_info = NULL;

	ZXIC_COMM_CHECK_INDEX(reg_no, 0, REG_ENUM_MAX_VALUE - 1);

	p_reg_info = dpp_reg_info_get(reg_no);
	ZXIC_COMM_CHECK_POINT(p_reg_info);

	addr = p_reg_info->addr;

	if (p_reg_info->array_type & DPP_REG_UNI_ARRAY) {
		if (n_offset > (p_reg_info->n_size - 1))
			ZXIC_COMM_TRACE_ERROR(
				"reg n_offset is out of range, reg_no:%d, n:%d, size:%d\n", reg_no,
				n_offset, p_reg_info->n_size - 1);

		ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_NO_ASSERT(addr, n_offset * p_reg_info->n_step);
		addr += n_offset * p_reg_info->n_step;
	} else if (p_reg_info->array_type & DPP_REG_BIN_ARRAY) {
		if ((n_offset > (p_reg_info->n_size - 1)) || (m_offset > (p_reg_info->m_size - 1)))
			ZXIC_COMM_TRACE_ERROR(
				"reg n_offset or m_offset is out of range, reg_no:%d, n:%d, n_size:%d, m:%d, m_size:%d,\n",
				reg_no, n_offset, p_reg_info->n_size - 1, m_offset,
				p_reg_info->m_size - 1);

		ZXIC_COMM_CHECK_INDEX_MUL_OVERFLOW_NO_ASSERT(m_offset, p_reg_info->m_step);
		ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_NO_ASSERT((m_offset * (p_reg_info->m_step)),
							     (n_offset * (p_reg_info->n_step)));
		ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_NO_ASSERT(
			addr,
			(m_offset * (p_reg_info->m_step)) + (n_offset * (p_reg_info->n_step)));
		addr += (m_offset * (p_reg_info->m_step)) + (n_offset * (p_reg_info->n_step));
	}

	return addr;
}

BOOLEAN dpp_4k_reg(u32 reg_module)
{
	if ((reg_module >= DTB4K) && (reg_module <= SMMU14K))
		return ZXIC_TRUE;

	return ZXIC_FALSE;
}

u32 dpp_reg_addr_convert(u32 dev_id, u32 reg_module, u32 flags, u32 addr)
{
	u32 convert_addr = addr;
	u32 i = 0;
	u32 cluster_index = 0;
	u32 index_4k = 0;
	u32 size_4k = 4096;
	u32 module_addr_offset = 0;
	u32 dtb_addr_offset = SYS_DTB_BASE_ADDR + MODULE_DTB_ENQ_BASE_ADDR;

	if (flags == DPP_REG_FLAG_INDIRECT)
		return addr;

	for (i = 0; i < (sizeof(g_module_offset_addr) / sizeof(struct DPP_REG_OFFSET_ADDR)); i++) {
		if (reg_module == g_module_offset_addr[i].reg_module) {
			module_addr_offset = g_module_offset_addr[i].addr_offset;
			if (reg_module == PPU4K) {
				cluster_index =
					(addr - module_addr_offset) / DPP_PPU_CLUSTER_SPACE_SIZE;
				index_4k = g_module_offset_addr[i].index_4k + cluster_index;
				module_addr_offset += cluster_index * DPP_PPU_CLUSTER_SPACE_SIZE;
			} else {
				index_4k = g_module_offset_addr[i].index_4k;
			}
			convert_addr = ((addr + (size_4k * index_4k) + dtb_addr_offset) >
					module_addr_offset) ?
					(addr + (size_4k * index_4k) + dtb_addr_offset -
					module_addr_offset) : addr;
		}
	}

	return convert_addr;
}

DPP_STATUS dpp_reg_write(struct dpp_dev_t *dev, u32 reg_no, u32 m_offset, u32 n_offset,
			 void *p_data)
{
	DPP_STATUS rc = 0;
	u32 i = 0;
	u32 addr = 0;

#ifdef DPP_FLOW_HW_INIT
	u32 convert_addr = 0;
#endif

	u32 p_buff[REG_DATA_MAX] = { 0 };
	u32 temp_data = 0;
	u32 reg_type = 0;
	u32 reg_module = 0;
	u32 reg_width = 0;
	struct dpp_reg_t *p_reg_info = NULL;
	struct dpp_field_t *p_field_info = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), reg_no, 0, REG_ENUM_MAX_VALUE - 1);
	ZXIC_COMM_CHECK_POINT(p_data);

	p_reg_info = dpp_reg_info_get(reg_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_reg_info);
	p_field_info = p_reg_info->p_fields;
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_field_info);
	reg_type = p_reg_info->flags;
	reg_module = p_reg_info->module_no;
	reg_width = p_reg_info->width;
	ZXIC_COMM_CHECK_INDEX_UPPER(reg_width, REG_DATA_MAX * 4);

#ifndef ZXIC_OS_WIN
#ifdef DPP_FOR_LLT
	if (dpp_stump_reg_en_check(DEV_ID(dev), reg_no) &&
	    (p_reg_info->flags == DPP_REG_FLAG_DIRECT ||
	     p_reg_info->flags == DPP_REG_FLAG_WO | DPP_REG_FLAG_DIRECT)) {
		rc = dpp_stump_reg_write(DEV_ID(dev), reg_no, m_offset, n_offset, p_data);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stump_reg_write");

		return DPP_OK;
	}
#endif
#endif

	for (i = 0; i < p_reg_info->field_num; i++) {
		if (p_field_info[i].len <= 32) {
			/* lint -e64 */
			temp_data = *((u32 *)p_data + i) &
				    ZXIC_COMM_GET_BIT_MASK(u32, p_field_info[i].len);
			rc = zxic_comm_write_bits_ex((u8 *)p_buff, p_reg_info->width * 8, temp_data,
						     p_field_info[i].msb_pos, p_field_info[i].len);
			/* lint +e64 */
			ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "zxic_comm_write_bits_ex");
		}
	}

	ZXIC_COMM_TRACE_DEV_DEBUG(DEV_ID(dev), "zxic_comm_write_bits_ex data = 0x%08x.\n",
				  p_buff[0]);

	if (!zxic_comm_is_big_endian()) {
		for (i = 0; i < ((p_reg_info->width) / 4); i++) {
			p_buff[i] = ZXIC_COMM_CONVERT32(p_buff[i]);

			/* for debug */
			ZXIC_COMM_TRACE_DEV_DEBUG(
				DEV_ID(dev), "ZXIC_COMM_CONVERT32 data = 0x%08x.\n", p_buff[i]);
		}
	}

	addr = dpp_reg_get_reg_addr(reg_no, m_offset, n_offset);

	ZXIC_COMM_TRACE_DEV_DEBUG(DEV_ID(dev), "reg_no = %d. m_offset = %d n_offset = %d\n", reg_no,
				  m_offset, n_offset);
	ZXIC_COMM_TRACE_DEV_DEBUG(DEV_ID(dev), "baseaddr = 0x%08x.\n", addr);

#ifdef DPP_FLOW_HW_INIT
	if (dpp_4k_reg(reg_module)) {
		convert_addr = dpp_reg_addr_convert(DEV_ID(dev), reg_module, reg_type, addr);
		ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_reg_info->p_write_fun);
		rc = p_reg_info->p_write_fun(dev, convert_addr, p_buff);
		ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "p_reg_info->p_write_fun");
	}
#else
	if (reg_module == DTB4K) {
		ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_reg_info->p_write_fun);
		rc = p_reg_info->p_write_fun(dev, addr, p_buff);
		ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "p_reg_info->p_write_fun");
	}
#endif
	else {

		rc = dpp_agent_channel_reg_write(dev, reg_type, reg_no, reg_width, addr, p_buff);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_agent_channel_reg_write");
	}

	return DPP_OK;
}

DPP_STATUS dpp_reg_read(struct dpp_dev_t *dev, u32 reg_no, u32 m_offset, u32 n_offset, void *p_data)
{
	DPP_STATUS rc = 0;
	u32 i = 0;
	u32 addr = 0;
#ifdef DPP_FLOW_HW_INIT
	u32 convert_addr = 0;
#endif
	u32 reg_type = 0;
	u32 p_buff[REG_DATA_MAX] = { 0 };
	u32 reg_module = 0;
	u32 reg_width = 0;
	struct dpp_reg_t *p_reg_info = NULL;
	struct dpp_field_t *p_field_info = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), reg_no, 0, REG_ENUM_MAX_VALUE - 1);
	ZXIC_COMM_CHECK_POINT(p_data);

	p_reg_info = dpp_reg_info_get(reg_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_reg_info);
	p_field_info = p_reg_info->p_fields;
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_field_info);
	reg_type = p_reg_info->flags;
	reg_module = p_reg_info->module_no;
	reg_width = p_reg_info->width;
	ZXIC_COMM_CHECK_INDEX_UPPER(reg_width, REG_DATA_MAX * 4);

#ifndef ZXIC_OS_WIN
#ifdef DPP_FOR_LLT
	if (dpp_stump_reg_en_check(DEV_ID(dev), reg_no) &&
	    (p_reg_info->flags == DPP_REG_FLAG_DIRECT ||
	     p_reg_info->flags == DPP_REG_FLAG_WO | DPP_REG_FLAG_DIRECT)) {
		rc = dpp_stump_reg_read(DEV_ID(dev), reg_no, m_offset, n_offset, p_data);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stump_reg_read");

		return DPP_OK;
	}
#endif
#endif

	addr = dpp_reg_get_reg_addr(reg_no, m_offset, n_offset);
#ifdef DPP_FLOW_HW_INIT
	if (dpp_4k_reg(reg_module)) {
		convert_addr = dpp_reg_addr_convert(DEV_ID(dev), reg_module, reg_type, addr);
		ZXIC_COMM_CHECK_POINT(p_reg_info->p_read_fun);
		rc = p_reg_info->p_read_fun(dev, convert_addr, p_buff);
		ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "p_reg_info->p_read_fun");
	}
#else
	if (reg_module == DTB4K) {
		ZXIC_COMM_CHECK_POINT(p_reg_info->p_read_fun);
		rc = p_reg_info->p_read_fun(dev, addr, p_buff);
		ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "p_reg_info->p_read_fun");
	}
#endif
	else {

		rc = dpp_agent_channel_reg_read(dev, reg_type, reg_no, reg_width, addr, p_buff);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_agent_channel_reg_read");
	}

	if (!zxic_comm_is_big_endian()) {
		for (i = 0; i < ((p_reg_info->width) / 4); i++) {
			/* for debug */

			//printf("dpp_reg_read data = 0x%08x.\n", p_buff[i]);
			ZXIC_COMM_TRACE_DEV_DEBUG(DEV_ID(dev), "dpp reg read data = 0x%08x.\n",
						  p_buff[i]);

			p_buff[i] = ZXIC_COMM_CONVERT32(p_buff[i]);
		}
	}

	for (i = 0; i < p_reg_info->field_num; i++) {
		/* lint -e64 */
		rc = zxic_comm_read_bits_ex((u8 *)p_buff, p_reg_info->width * 8, (u32 *)p_data + i,
					    p_field_info[i].msb_pos, p_field_info[i].len);
		ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "zxic_comm_read_bits_ex");
		/* lint +e64 */
	}

	return DPP_OK;
}

DPP_STATUS dpp_reg_write32(struct dpp_dev_t *dev, u32 reg_no, u32 data)
{
	DPP_STATUS rc = 0;
	u32 addr = 0;
	struct dpp_reg_t *p_reg_info = NULL;
	u32 value = data;
	u32 j = 0;
	u32 k = 0;
	u32 m_size = 0;
	u32 n_size = 0;
	u32 reg_type = 0;
	// u32      reg_module = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), reg_no, 0, REG_ENUM_MAX_VALUE - 1);

	p_reg_info = dpp_reg_info_get(reg_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_reg_info);
	reg_type = p_reg_info->flags;
	// reg_module = p_reg_info->module_no;

	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_reg_info->width, 4, 4); /* width must be 32bit */

	m_size = (p_reg_info->m_size == 0) ? (1) : (p_reg_info->m_size);
	n_size = (p_reg_info->n_size == 0) ? (1) : (p_reg_info->n_size);

	for (j = 0; j < m_size; j++) {
		for (k = 0; k < n_size; k++) {
#ifndef ZXIC_OS_WIN
#ifdef DPP_FOR_LLT
			if (dpp_stump_reg_en_check(DEV_ID(dev), reg_no) &&
			    (p_reg_info->flags == DPP_REG_FLAG_DIRECT)) {
				rc = dpp_stump_reg_write(DEV_ID(dev), reg_no, j, k, &data);
				ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stump_reg_write");

				return DPP_OK;
			}
#endif
#endif

			addr = dpp_reg_get_reg_addr(reg_no, j, k);

			rc = dpp_agent_channel_reg_write(dev, reg_type, reg_no, 4, addr, &value);
			ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_agent_channel_reg_write");
		}
	}

	return DPP_OK;
}

DPP_STATUS dpp_reg_read32(struct dpp_dev_t *dev, u32 reg_no, u32 m_offset, u32 n_offset,
			  u32 *p_data)
{
	DPP_STATUS rc = 0;
	u32 addr = 0;
	u32 reg_type = 0;
	// u32 reg_module = 0;
	u32 p_buff[REG_DATA_MAX] = { 0 };

	struct dpp_reg_t *p_reg_info = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX_UPPER(DEV_ID(dev), DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), reg_no, 0, REG_ENUM_MAX_VALUE - 1);
	ZXIC_COMM_CHECK_POINT(p_data);

	p_reg_info = dpp_reg_info_get(reg_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_reg_info);
	reg_type = p_reg_info->flags;
	// reg_module = p_reg_info->module_no;

	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_reg_info->width, 4, 4); /* width must be 32bit */

#ifndef ZXIC_OS_WIN
#ifdef DPP_FOR_LLT
	if (dpp_stump_reg_en_check(DEV_ID(dev), reg_no) &&
	    (p_reg_info->flags == DPP_REG_FLAG_DIRECT)) {
		rc = dpp_stump_reg_read(DEV_ID(dev), reg_no, m_offset, n_offset, p_data);
		ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_stump_reg_read");

		return DPP_OK;
	}
#endif
#endif

	addr = dpp_reg_get_reg_addr(reg_no, m_offset, n_offset);

	rc = dpp_agent_channel_reg_read(dev, reg_type, reg_no, 4, addr, p_buff);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_agent_channel_reg_read");
	*p_data = p_buff[0];

	return DPP_OK;
}
