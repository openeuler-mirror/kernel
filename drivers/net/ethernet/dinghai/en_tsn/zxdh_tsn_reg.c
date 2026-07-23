// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/log.h>
#include "zxdh_tsn.h"
#include "zxdh_tsn_reg.h"
#include "zxdh_tsn_comm.h"

s32 tsn_read(u64 base_addr, u32 offset, u32 *p_val)
{
	if (IS_ERR_OR_NULL((void *)base_addr)) {
		DH_LOG_ERR(MODULE_TSN, "base_addr 0x%llx invalid.\n", base_addr);
		return -EINVAL;
	}

	*p_val = readl((void *)(base_addr + offset));

	return TSN_OK;
}

s32 tsn_write(u64 base_addr, u32 offset, u32 val)
{
	if (IS_ERR_OR_NULL((void *)base_addr)) {
		DH_LOG_ERR(MODULE_TSN, "base_addr 0x%llx invalid.\n", base_addr);
		return -EINVAL;
	}

	writel(val, (void *)(base_addr + offset));

	return TSN_OK;
}

s32 tsn_reg_read(struct zxdh_tsn_private *tsn, u32 offset, u32 *p_val)
{
	s32 ret = 0;

	if (!tsn) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}
	if (!p_val) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	ret = tsn_read(tsn->tsn_reg_base_addr, offset, p_val);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_reg_write(struct zxdh_tsn_private *tsn, u32 offset, u32 val)
{
	s32 ret = 0;

	if (!tsn) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	ret = tsn_write(tsn->tsn_reg_base_addr, offset, val);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_enable_set(struct zxdh_tsn_private *tsn, u32 enable)
{
	s32 ret = 0;

	ret = tsn_reg_write(tsn, TSN_PORT_QBV_ENABLE, enable);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_enable_get(struct zxdh_tsn_private *tsn, u32 *p_enable)
{
	s32 ret = 0;

	ret = tsn_reg_read(tsn, TSN_PORT_QBV_ENABLE, p_enable);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_phy_port_set(struct zxdh_tsn_private *tsn, u32 phy_port)
{
	s32 ret = 0;

	ret = tsn_reg_write(tsn, TSN_PORT_PHY_PORT_SEL, phy_port);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_phy_port_get(struct zxdh_tsn_private *tsn, u32 *p_phy_port)
{
	s32 ret = 0;

	ret = tsn_reg_read(tsn, TSN_PORT_PHY_PORT_SEL, p_phy_port);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_timer_id_set(struct zxdh_tsn_private *tsn, u32 timer_id)
{
	s32 ret = 0;

	ret = tsn_reg_write(tsn, TSN_PORT_TIME_SEL, timer_id);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_timer_id_get(struct zxdh_tsn_private *tsn, u32 *p_time_id)
{
	s32 ret = 0;

	ret = tsn_reg_read(tsn, TSN_PORT_TIME_SEL, p_time_id);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_status_get(struct zxdh_tsn_private *tsn, u32 *p_ram_n, u32 *p_status)
{
	s32 ret = 0;
	u32 val = 0;

	if (!p_ram_n) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}
	if (!p_status) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	ret = tsn_reg_read(tsn, TSN_PORT_READ_RAM_N, &val);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	*p_ram_n = val & 0x3;
	*p_status = (val & 0x3C) >> 2;

	return TSN_OK;
}

s32 tsn_port_base_time_l_set(struct zxdh_tsn_private *tsn, u32 base_time)
{
	s32 ret = 0;

	ret = tsn_reg_write(tsn, TSN_PORT_BASE_TIME_L, base_time);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_base_time_h_set(struct zxdh_tsn_private *tsn, u32 base_time)
{
	s32 ret = 0;

	ret = tsn_reg_write(tsn, TSN_PORT_BASE_TIME_H, base_time);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_base_time_set(struct zxdh_tsn_private *tsn, u64 base_time)
{
	s32 ret = 0;
	u32 base_time_l = (u32)((base_time)&0xffffffff);
	u32 base_time_h = (u32)((base_time >> 32) & 0xffffffff);

	ret = tsn_port_base_time_l_set(tsn, base_time_l);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_port_base_time_h_set(tsn, base_time_h);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_base_time_get(struct zxdh_tsn_private *tsn, u64 *p_base_time)
{
	s32 ret = 0;
	u32 base_time_l = 0;
	u32 base_time_h = 0;

	if (!p_base_time) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	ret = tsn_reg_read(tsn, TSN_PORT_BASE_TIME_L, &base_time_l);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_reg_read(tsn, TSN_PORT_BASE_TIME_H, &base_time_h);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	*p_base_time = (u64)((((u64)(base_time_h)) << 32) | ((u64)(base_time_l)));

	return TSN_OK;
}

s32 tsn_port_cycle_time_l_set(struct zxdh_tsn_private *tsn, u32 cycle_time)
{
	s32 ret = 0;

	ret = tsn_reg_write(tsn, TSN_PORT_CYCLE_TIME_L, cycle_time);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_cycle_time_h_set(struct zxdh_tsn_private *tsn, u32 cycle_time)
{
	s32 ret = 0;

	ret = tsn_reg_write(tsn, TSN_PORT_CYCLE_TIME_H, cycle_time);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_cycle_time_set(struct zxdh_tsn_private *tsn, u64 cycle_time)
{
	s32 ret = 0;
	u32 cycle_time_l = (u32)((cycle_time)&0x000fffff);
	u32 cycle_time_h = (u32)((cycle_time >> 20) & 0x000fffff);

	ret = tsn_port_cycle_time_l_set(tsn, cycle_time_l);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_port_cycle_time_h_set(tsn, cycle_time_h);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_cycle_time_get(struct zxdh_tsn_private *tsn, u64 *p_cycle_time)
{
	s32 ret = 0;
	u32 cycle_time_l = 0;
	u32 cycle_time_h = 0;

	if (!p_cycle_time) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	ret = tsn_reg_read(tsn, TSN_PORT_CYCLE_TIME_L, &cycle_time_l);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_reg_read(tsn, TSN_PORT_CYCLE_TIME_H, &cycle_time_h);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	*p_cycle_time = (u64)((((u64)(cycle_time_h)) << 20) | ((u64)(cycle_time_l)));

	return TSN_OK;
}

s32 tsn_port_guard_band_time_set(struct zxdh_tsn_private *tsn, u32 cos, u32 band_time)
{
	s32 ret = 0;

	if (cos > TSN_PORT_QUEUE_MAX) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MAX %u] !\n", cos,
			   TSN_PORT_QUEUE_MAX);
		return -EINVAL;
	}

	ret = tsn_reg_write(tsn, TSN_PORT_GUARD_BAND_TIME + (cos * 4), band_time);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_guard_band_time_get(struct zxdh_tsn_private *tsn, u32 cos, u32 *p_band_time)
{
	s32 ret = 0;

	if (cos > TSN_PORT_QUEUE_MAX) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MAX %u] !\n", cos,
			   TSN_PORT_QUEUE_MAX);
		return -EINVAL;
	}

	ret = tsn_reg_read(tsn, TSN_PORT_GUARD_BAND_TIME + (cos * 4), p_band_time);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_default_gate_set(struct zxdh_tsn_private *tsn, u32 gate_state)
{
	s32 ret = 0;

	ret = tsn_reg_write(tsn, TSN_PORT_DEFAULT_GATE_EN, gate_state);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_default_gate_get(struct zxdh_tsn_private *tsn, u32 *p_gate_state)
{
	s32 ret = 0;

	ret = tsn_reg_read(tsn, TSN_PORT_DEFAULT_GATE_EN, p_gate_state);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_change_gate_set(struct zxdh_tsn_private *tsn, u32 gate_state)
{
	s32 ret = 0;

	ret = tsn_reg_write(tsn, TSN_PORT_CHANGE_GATE_EN, gate_state);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_init_finish_set(struct zxdh_tsn_private *tsn, u32 init_finish)
{
	s32 ret = 0;

	ret = tsn_reg_write(tsn, TSN_PORT_INIT_FINISH, init_finish);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_init_finish_get(struct zxdh_tsn_private *tsn, u32 *p_init_finish)
{
	s32 ret = 0;

	ret = tsn_reg_read(tsn, TSN_PORT_INIT_FINISH, p_init_finish);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_change_en_set(struct zxdh_tsn_private *tsn, u32 change_en)
{
	s32 ret = 0;

	ret = tsn_reg_write(tsn, TSN_PORT_CHANGE_EN, change_en);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_change_en_get(struct zxdh_tsn_private *tsn, u32 *p_change_en)
{
	s32 ret = 0;

	ret = tsn_reg_read(tsn, TSN_PORT_CHANGE_EN, p_change_en);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_gcl_num_set(struct zxdh_tsn_private *tsn, u32 ram_n, u32 gcl_num)
{
	s32 ret = 0;
	u32 tsn_port_gcl_num[TSN_PORT_RAM_NUM] = { TSN_PORT_GCL_NUM0, TSN_PORT_GCL_NUM1 };

	if (ram_n > TSN_PORT_RAM_MAX) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MAX %u] !\n", ram_n,
			   TSN_PORT_RAM_MAX);
		return -EINVAL;
	}

	ret = tsn_reg_write(tsn, tsn_port_gcl_num[ram_n], gcl_num);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_gcl_num_get(struct zxdh_tsn_private *tsn, u32 ram_n, u32 *p_gcl_num)
{
	s32 ret = 0;
	u32 tsn_port_gcl_num[TSN_PORT_RAM_NUM] = { TSN_PORT_GCL_NUM0, TSN_PORT_GCL_NUM1 };

	if (ram_n > TSN_PORT_RAM_MAX) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MAX %u] !\n", ram_n,
			   TSN_PORT_RAM_MAX);
		return -EINVAL;
	}

	ret = tsn_reg_read(tsn, tsn_port_gcl_num[ram_n], p_gcl_num);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_gcl_control_set(struct zxdh_tsn_private *tsn, u32 ram_n, u32 index, u32 gate_state,
			     u32 internal)
{
	s32 ret = 0;
	u32 tsn_port_gcl_value[TSN_PORT_RAM_NUM] = { TSN_PORT_GCL_VALUE0, TSN_PORT_GCL_VALUE1 };

	if (ram_n > TSN_PORT_RAM_MAX) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MAX %u] !\n", ram_n,
			   TSN_PORT_RAM_MAX);
		return -EINVAL;
	}
	if (index > TSN_PORT_GCL_MAX) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MAX %u] !\n", index,
			   TSN_PORT_GCL_MAX);
		return -EINVAL;
	}

	ret = tsn_reg_write(tsn, tsn_port_gcl_value[ram_n] + (index * 4),
			    (gate_state << 24) | internal);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_disable_set(struct zxdh_tsn_private *tsn)
{
	s32 ret = 0;

	ret = tsn_port_enable_set(tsn, TSN_PORT_GATE_DISABLE);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_port_init_finish_set(tsn, TSN_PORT_INIT_DISABLE);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_port_change_en_set(tsn, TSN_PORT_CHANGE_DISABLE);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	return TSN_OK;
}

s32 tsn_port_real_tod_time_get(struct zxdh_tsn_private *tsn, u64 *p_tod_time)
{
	s32 ret = 0;
	u32 tsn_timer_id = 0;
	u32 tod_second_h = 0;
	u32 tod_second_l = 0;
	u32 tod_nanosecond = 0;

	u32 tsn_real_tod_nanosecond_reg_offset[TSN_PORT_TIMER_ID_NUM] = {
		TSN0_REAL_TOD_NANOSECOND, TSN1_REAL_TOD_NANOSECOND, TSN2_REAL_TOD_NANOSECOND,
		TSN3_REAL_TOD_NANOSECOND
	};
	u32 tsn_real_high_tod_second_reg_offset[TSN_PORT_TIMER_ID_NUM] = {
		TSN0_REAL_HIGH_TOD_SECOND, TSN1_REAL_HIGH_TOD_SECOND, TSN2_REAL_HIGH_TOD_SECOND,
		TSN3_REAL_HIGH_TOD_SECOND
	};
	u32 tsn_real_lower_tod_second_reg_offset[TSN_PORT_TIMER_ID_NUM] = {
		TSN0_REAL_LOWER_TOD_SECOND, TSN1_REAL_LOWER_TOD_SECOND, TSN2_REAL_LOWER_TOD_SECOND,
		TSN3_REAL_LOWER_TOD_SECOND
	};

	if (!p_tod_time) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	ret = tsn_port_timer_id_get(tsn, &tsn_timer_id);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}
	if (tsn_timer_id > TSN_PORT_TIMER_ID_MAX) {
		DH_LOG_ERR(MODULE_TSN, "[Error: VALUE %u INVALID] [MAX %u] !\n", tsn_timer_id,
			   TSN_PORT_TIMER_ID_MAX);
		return -EINVAL;
	}

	ret = tsn_read(tsn->pci_ioremap_addr + 0xC000,
		       tsn_real_high_tod_second_reg_offset[tsn_timer_id], &tod_second_h);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_read(tsn->pci_ioremap_addr + 0xC000,
		       tsn_real_lower_tod_second_reg_offset[tsn_timer_id], &tod_second_l);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	ret = tsn_read(tsn->pci_ioremap_addr + 0xC000,
		       tsn_real_tod_nanosecond_reg_offset[tsn_timer_id], &tod_nanosecond);
	if (ret) {
		DH_LOG_ERR(MODULE_TSN, "[ErrorCode: %d] !\n", ret);
		return ret;
	}

	*p_tod_time =
		((((u64)tod_second_h << 32) | (u64)tod_second_l) * NSEC_PER_SEC) + tod_nanosecond;

	return TSN_OK;
}
