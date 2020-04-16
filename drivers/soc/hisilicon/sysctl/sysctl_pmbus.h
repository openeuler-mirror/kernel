/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Hisilicon Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef _HIS_SYSCTL_PMBUS_H_
#define _HIS_SYSCTL_PMBUS_H_

#define VOL_LOOP_NUM_MAX (0x3)
#define PAGE_NUM_MAX (0x6f)
#define DATA_NUM_MAX (0x4)

#define I2C_TX_ABRT (0x040)
#define I2C_TX_ABRT_SRC_REG (0x0880)
#define I2C_CLR_TX_ABRT_REG (0x0854)
#define I2C_STATUS_REG (0x0870)
#define I2C_TX_FIFO_EMPTY (0x04)
#define I2C_TX_FIFO_DATA_NUM_REG (0x0874)

#define I2C_SS_SCLHCNT 0x3db
#define I2C_SS_SCLLCNT 0x3e6

/* AVS_REG_GEN */
#define AVS_WR_OPEN_OFFSET 0x0004
#define AVS_INT_STATUS_OFFSET 0x0008
#define AVS_ERROR_INT_STATUS_OFFSET 0x000C
#define AVS_PARITY_INT_STATUS_OFFSET 0x0010
#define AVS_INT_CLEAR_OFFSET 0x0020
#define AVS_ERROR_INT_CLEAR_OFFSET 0x0024
#define AVS_INT_MASK_OFFSET 0x0034

/* PMBUSIF_REG_GEN */
#define I2C_CON_OFFSET 0x0800
#define I2C_DATA_CMD_OFFSET 0x0810
#define I2C_SS_SCL_HCNT_OFFSET 0x0814
#define I2C_SS_SCL_LCNT_OFFSET 0x0818
#define I2C_FS_SCL_HCNT_OFFSET 0x081C
#define I2C_FS_SCL_LCNT_OFFSET 0x0820
#define I2C_INTR_STAT_OFFSET 0x082C
#define I2C_INTR_MASK_OFFSET 0x0830
#define I2C_INTR_RAW_OFFSET 0x0834
#define I2C_ENABLE_OFFSET 0x086C
#define I2C_RXFLR_OFFSET 0x0878
#define I2C_SDA_HOLD_OFFSET 0x087C
#define I2C_SCL_SWITCH_OFFSET 0x08A0
#define I2C_SCL_SIM_OFFSET 0x08A4
#define I2C_LOCK_OFFSET 0x08AC
#define I2C_SDA_SWITCH_OFFSET 0x08B0
#define I2C_SDA_SIM_OFFSET 0x08B4
#define I2C_PMBUS_CTRL_OFFSET 0x0904
#define I2C_LOW_TIMEOUT_OFFSET 0x0908
#define I2C_PMBUS_SCL_DET_OFFSET 0x092C
#define I2C_PMBUS_IDLECNT_OFFSET 0x0930
#define I2C_PMBUS_RST_OFFSET 0x0934

/* PMBUS_PROC_REG_GEN */
#define PMBUS_REG_BASE (0x000094180000)
#define PMBUS_WR_OPEN_OFFSET 0x0A04
#define PMBUS_INT_OFFSET 0x0A08
#define PMBUS_INT_CLR_OFFSET 0x0A10
#define PMBUS_PROC_TIMEOUT_TH_OFFSET 0x0A1C
#define PMBUS_VOLTAGE_STABLE_OFFSET 0x0A20
#define READ_VOUD_INTERVAL_OFFSET 0x0A28
#define PMBUS_OTHER_CFG_OFFSET 0x0A2C
#define VOLTAGE_ADDR_CFG_OFFSET 0x0A30
#define VOLTAGE_CONVERT_CFG_OFFSET 0x0A34
#define STATUS_RPT_OFFSET 0x0AA4
#define STATUS_ERR_RPT_OFFSET 0x0AA8

/* Define the union pmbus_vout_mode */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int vid_table : 5 ; /* [4..0]  */
		unsigned int vout_mode_surport : 3 ; /* [7..5]  */
		unsigned int reserved_0 : 24 ; /* [31..8]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} pmbus_vout_mode;

enum {
	CPU_VOUT_MODE_INVALID = 0,
	CPU_VOUT_MODE_VR120,
	CPU_VOUT_MODE_VR125,
	CPU_VOUT_MODE_MAX,
};

int hip_sysctl_pmbus_init(void);
void hip_sysctl_pmbus_exit(void);

#endif
