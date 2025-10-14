/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef MPU_BOARD_DEFS_H
#define MPU_BOARD_DEFS_H

#define BOARD_TYPE_TEST_RANGE_START 1
#define BOARD_TYPE_TEST_RANGE_END   29
#define BOARD_TYPE_STRG_RANGE_START 30
#define BOARD_TYPE_STRG_RANGE_END   99
#define BOARD_TYPE_CAL_RANGE_START  100
#define BOARD_TYPE_CAL_RANGE_END	169
#define BOARD_TYPE_CLD_RANGE_START  170
#define BOARD_TYPE_CLD_RANGE_END	239
#define BOARD_TYPE_RSVD_RANGE_START 240
#define BOARD_TYPE_RSVD_RANGE_END   255

enum board_type_define_e {
	BOARD_TYPE_MPU_DEFAULT			= 0,
	BOARD_TYPE_TEST_EVB_4X25G		= 1,
	BOARD_TYPE_TEST_CEM_2X100G		= 2,
	BOARD_TYPE_STRG_SMARTIO_4X32G_FC	= 30,
	BOARD_TYPE_STRG_SMARTIO_4X25G_TIOE	= 31,
	BOARD_TYPE_STRG_SMARTIO_4X25G_ROCE	= 32,
	BOARD_TYPE_STRG_SMARTIO_4X25G_ROCE_AA	= 33,
	BOARD_TYPE_STRG_SMARTIO_4X25G_SRIOV	= 34,
	BOARD_TYPE_STRG_SMARTIO_4X25G_SRIOV_SW	= 35,
	BOARD_TYPE_STRG_4X25G_COMSTORAGE	= 36,
	BOARD_TYPE_STRG_2X100G_TIOE		= 40,
	BOARD_TYPE_STRG_2X100G_ROCE		= 41,
	BOARD_TYPE_STRG_2X100G_ROCE_AA		= 42,
	BOARD_TYPE_CAL_2X25G_NIC_75MPPS		= 100,
	BOARD_TYPE_CAL_2X25G_NIC_40MPPS		= 101,
	BOARD_TYPE_CAL_2X100G_DPU_VL		= 102,
	BOARD_TYPE_CAL_4X25G_NIC_120MPPS	= 105,
	BOARD_TYPE_CAL_4X25G_COMSTORAGE		= 106,
	BOARD_TYPE_CAL_2X32G_FC_HBA		= 110,
	BOARD_TYPE_CAL_2X16G_FC_HBA		= 111,
	BOARD_TYPE_CAL_2X100G_NIC_120MPPS	= 115,
	BOARD_TYPE_CAL_2X25G_DPU_BD		= 116,
	BOARD_TYPE_CAL_2X100G_TCE_BACKPLANE	= 117,
	BOARD_TYPE_CAL_4X25G_DPU_VL		= 118,
	BOARD_TYPE_CAL_4X25G_SMARTNIC_120MPPS  = 119,
	BOARD_TYPE_CAL_2X100G_SMARTNIC_120MPPS = 120,
	BOARD_TYPE_CAL_6X25G_DPU_VL		= 121,
	BOARD_TYPE_CAL_4X25G_DPU_BD		= 122,
	BOARD_TYPE_CAL_2X25G_NIC_4HOST		= 123,
	BOARD_TYPE_CAL_2X10G_LOW_POWER		= 125,
	BOARD_TYPE_CAL_2X200G_NIC_INTERNET	= 127,
	BOARD_TYPE_CAL_1X100GR2_OCP		= 129,
	BOARD_TYPE_CAL_2X200G_DPU_VL		= 130,
	BOARD_TYPE_CLD_2X100G_SDI5_1		= 170,
	BOARD_TYPE_CLD_2X25G_SDI5_0_LITE	= 171,
	BOARD_TYPE_CLD_2X100G_SDI5_0		= 172,
	BOARD_TYPE_CLD_4X25G_SDI5_0_C		= 175,
	BOARD_TYPE_MAX_INDEX			= 0xFF
};

static inline u32 spu_board_type_valid(u32 board_type)
{
	return ((board_type) == BOARD_TYPE_CLD_2X25G_SDI5_0_LITE) ||
		((board_type) == BOARD_TYPE_CLD_2X100G_SDI5_0) ||
		((board_type) == BOARD_TYPE_CLD_4X25G_SDI5_0_C) ||
		((board_type) == BOARD_TYPE_CAL_2X25G_DPU_BD) ||
		((board_type) == BOARD_TYPE_CAL_2X100G_DPU_VL) ||
		((board_type) == BOARD_TYPE_CAL_4X25G_DPU_VL) ||
		((board_type) == BOARD_TYPE_CAL_4X25G_DPU_BD) ||
		((board_type) == BOARD_TYPE_CAL_2X200G_DPU_VL);
}

static inline int board_type_is_sdi_50(u32 board_type)
{
	return ((board_type) == BOARD_TYPE_CLD_2X25G_SDI5_0_LITE) ||
		((board_type) == BOARD_TYPE_CLD_2X100G_SDI5_0) ||
		((board_type) == BOARD_TYPE_CLD_4X25G_SDI5_0_C);
}

static inline int board_type_is_sdi(u32 board_type)
{
	return ((board_type) == BOARD_TYPE_CLD_2X100G_SDI5_1) ||
		((board_type) == BOARD_TYPE_CLD_2X25G_SDI5_0_LITE) ||
		((board_type) == BOARD_TYPE_CLD_2X100G_SDI5_0) ||
		((board_type) == BOARD_TYPE_CLD_4X25G_SDI5_0_C);
}

static inline int board_type_is_dpu_spu(u32 board_type)
{
	return ((board_type) == BOARD_TYPE_CAL_2X25G_DPU_BD) ||
		((board_type) == BOARD_TYPE_CAL_2X100G_DPU_VL) ||
		((board_type) == BOARD_TYPE_CAL_4X25G_DPU_VL) ||
		((board_type) == BOARD_TYPE_CAL_4X25G_DPU_BD) ||
		((board_type) == BOARD_TYPE_CAL_2X200G_DPU_VL);
}

static inline int board_type_is_dpu(u32 board_type)
{
	return ((board_type) == BOARD_TYPE_CAL_2X25G_DPU_BD) ||
		((board_type) == BOARD_TYPE_CAL_2X100G_DPU_VL) ||
		((board_type) == BOARD_TYPE_CAL_4X25G_DPU_VL) ||
		((board_type) == BOARD_TYPE_CAL_4X25G_DPU_BD) ||
		((board_type) == BOARD_TYPE_CAL_6X25G_DPU_VL) ||
		((board_type) == BOARD_TYPE_CAL_2X200G_DPU_VL);
}

static inline int board_type_is_smartnic(u32 board_type)
{
	return ((board_type) == BOARD_TYPE_CAL_4X25G_SMARTNIC_120MPPS) ||
		((board_type) == BOARD_TYPE_CAL_2X100G_SMARTNIC_120MPPS);
}

/*	此接口判断是否是分布式存储的标卡以及计算的标卡(含ROCE特性),
 *	仅用于LLDP TX功能冲突命令字处理的判断
 */
static inline int board_type_is_compute(u32 board_type)
{
	return ((board_type) == BOARD_TYPE_CAL_2X25G_NIC_75MPPS) ||
		((board_type) == BOARD_TYPE_CAL_2X25G_NIC_40MPPS) ||
		((board_type) == BOARD_TYPE_CAL_4X25G_NIC_120MPPS) ||
		((board_type) == BOARD_TYPE_CAL_4X25G_COMSTORAGE) ||
		((board_type) == BOARD_TYPE_CAL_2X100G_NIC_120MPPS) ||
		((board_type) == BOARD_TYPE_CAL_2X10G_LOW_POWER) ||
		((board_type) == BOARD_TYPE_CAL_2X200G_NIC_INTERNET) ||
		((board_type) == BOARD_TYPE_CAL_1X100GR2_OCP) ||
		((board_type) == BOARD_TYPE_CAL_4X25G_SMARTNIC_120MPPS) ||
		((board_type) == BOARD_TYPE_CAL_2X25G_NIC_4HOST) ||
		((board_type) == BOARD_TYPE_CAL_2X100G_SMARTNIC_120MPPS);
}

/* 此接口判断服务器输入reboot网卡是否需要复位 */
static inline int board_type_is_multi_socket(u32 board_type)
{
    return ((board_type) == BOARD_TYPE_CAL_1X100GR2_OCP);
}

#endif
