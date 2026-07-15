/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mag_mpu_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : serdesmag cmd definition between driver and mpu
 */

#ifndef MAG_MPU_CMD_H
#define MAG_MPU_CMD_H

/* serdes/mag message command code definition */
enum mag_cmd {
	/* serdes command code, unified encapsulation of all serdes commands */
	SERDES_CMD_PROCESS = 0,

	/* mag command code, divided by function */
	/* port configuration related 0-29 */
	MAG_CMD_SET_PORT_CFG = 1,
	MAG_CMD_SET_PORT_ADAPT = 2,
	MAG_CMD_CFG_LOOPBACK_MODE = 3,

	MAG_CMD_GET_PORT_ENABLE = 5,
	MAG_CMD_SET_PORT_ENABLE = 6,
	MAG_CMD_GET_LINK_STATUS = 7,
	MAG_CMD_SET_LINK_FOLLOW = 8,
	MAG_CMD_SET_PMA_ENABLE = 9,
	MAG_CMD_CFG_FEC_MODE = 10,

	MAG_CMD_CFG_AN_TYPE = 12, /* reserved for future use */
	MAG_CMD_CFG_LINK_TIME = 13,

	MAG_CMD_SET_PANGEA_ADAPT = 15,
	MAG_CMD_HILINK_MODE = 16, /* set port hilink debug mode @see struct mag_cmd_hilink_mode */

	/* bios link configuration related 30-49 */
	MAG_CMD_CFG_BIOS_LINK_CFG = 31,
	MAG_CMD_RESTORE_LINK_CFG = 32,
	MAG_CMD_ACTIVATE_BIOS_LINK_CFG = 33,

	/* optical module, LED, PHY and other peripheral configuration management 50-99 */
	/* LED */
	MAG_CMD_SET_LED_CFG = 50,

	/* PHY */
	MAG_CMD_GET_PHY_INIT_STATUS = 55, /* reserved for future use */

	/* optical module */
	MAG_CMD_GET_XSFP_INFO = 60,
	MAG_CMD_SET_XSFP_ENABLE = 61,
	MAG_CMD_GET_XSFP_PRESENT = 62,
	MAG_CMD_SET_XSFP_RW = 63, /* sfp/qsfp single byte read/write, for equipment test */
	MAG_CMD_CFG_XSFP_TEMPERATURE = 64,
	MAG_CMD_SET_XSFP_TLV_INFO = 65,
	MAG_CMD_GET_XSFP_TLV_INFO = 66,

	/* event report 100-149 */
	MAG_CMD_WIRE_EVENT = 100,
	MAG_CMD_LINK_ERR_EVENT = 101,

	/* DFX, Counter related */
	MAG_CMD_EVENT_PORT_INFO = 150,
	MAG_CMD_GET_PORT_STAT = 151,
	MAG_CMD_CLR_PORT_STAT = 152,
	MAG_CMD_GET_PORT_INFO = 153,
	MAG_CMD_GET_PCS_ERR_CNT = 154,
	MAG_CMD_GET_MAG_CNT = 155,
	MAG_CMD_DUMP_ANTRAIN_INFO = 156,
	MAG_CMD_GET_UBMAC_COUNTER = 157,
	MAG_CMD_GET_HIMAC_BER = 158,
	MAG_CMD_OP_HIMAC_THRD = 159,
	MAG_CMD_GET_HIMAC_BANDWIDTH = 160,
	MAG_CMD_SET_HIMAC_PRBS = 161,
	MAG_CMD_GET_HIMAC_PRBS = 162,

	/* patch reserved cmd */
	MAG_CMD_PATCH_RSVD_0 = 200,
	MAG_CMD_PATCH_RSVD_1 = 201,
	MAG_CMD_PATCH_RSVD_2 = 202,
	MAG_CMD_PATCH_RSVD_3 = 203,
	MAG_CMD_PATCH_RSVD_4 = 204,

	MAG_CMD_MAX = 0xFF
};

#endif
