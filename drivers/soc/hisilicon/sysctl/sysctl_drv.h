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
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http:
 */

#ifndef _HIS_SYSCTL_H_
#define _HIS_SYSCTL_H_

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/pci.h>
#include <linux/time.h>
#include <linux/nmi.h>
#include <linux/rcupdate.h>
#include <linux/completion.h>
#include <linux/kobject.h>
#include <linux/platform_device.h>
#include <linux/workqueue.h>
#include <linux/edac.h>

/********************SYSCTRL ERR********************/
#define ERR_OK 0   /* Ok */
#define ERR_PARAM 1   /* Invalid parameter */
#define ERR_FAILED 2   /* Operation failed */
#define ERR_PORT 3   /* Invalid port */
#define ERR_TIMEOUT 4   /* Operation time out */
#define ERR_NOMATCH 5   /* Version not match */
#define ERR_EXIST 6   /* Entry exists */
#define ERR_NOMEM 7   /* Out of memory */
#define ERR_INIT 8   /* Feature not initialized */
#define ERR_FAULT 9   /* Invalid address */
#define ERR_PERM 10  /* Operation not permitted */
#define ERR_EMPTY 11  /* Table empty */
#define ERR_FULL 12  /* Table full */
#define ERR_NOT_FOUND 13  /* Not found */
#define ERR_BUSY 14  /* Device or resource busy */
#define ERR_RESOURCE 15  /* No resources for operation */
#define ERR_CONFIG 16  /* Invalid configuration */
#define ERR_UNAVAIL 17  /* Feature unavailable */
#define ERR_CRC 18  /* CRC check failed */
#define ERR_NXIO 19  /* No such device or address */
#define ERR_ROLLBACK 20  /* chip rollback fail */
#define ERR_LEN 32  /* Length too short or too long */
#define ERR_UNSUPPORT 0xFF/* Feature not supported*/

#define PEH_REG_ADDR (0xd7d00008)
#define HLLC0_REG_BASE (0x000200080000)
#define HLLC1_REG_BASE (0x000200090000)
#define HLLC2_REG_BASE (0x0002000a0000)
#define PCS0_REG_BASE (0x0002000c0000)
#define PA_REG_BASE (0x0002001d0000)
#define PM_REG_BASE (0x000094180000)
#define DDRC0_TB_REG_BASE (0x000094d20000)
#define DDRC0_TA_REG_BASE (0x00009cd20000)

#define HLLC_INTLV_MODE_2PX8		 0x0
#define HLLC_INTLV_MODE_2PX16		0x1
#define HLLC_INTLV_MODE_2PX24		0x2
#define HLLC_INTLV_MODE_4PX8		 0x3
#define HLLC_INTLV_MODE_3P1		  0x5
#define HLLC_INTLV_MODE_3P2		  0x6

#define CHIP_VERSION_MASK (0xff)
#define CHIP_VERSION_ES (0x20)
#define CHIP_VERSION_CS (0x21)
#define HLLC_CHIP_MODULE_ES (0x400000000000)
#define HLLC_CHIP_MODULE_CS (0x200000000000)
#define HLLC_NUM_MAX (0x3)
#define HLLC_CH_NUM_MAX (0x3)
#define TOTEM_NUM_MAX (0x2)
#define TOTEM_TA_NUM (0x0)
#define TOTEM_TB_NUM (0x1)
#define DDRC_CH_NUM_MAX (0x4)
#define DDRC_RANK_NUM_MAX (0x8)
#define HLLC_LANE_NUM_MAX (0x8)
#define CHIP_ID_NUM_MAX (0x4)
#define VOL_LOOP_NUM_MAX (0x3)
#define PAGE_NUM_MAX (0x6f)
#define DATA_NUM_MAX (0x4)

#define DDRC_ECC_EN (0x5001)

#define I2C_TX_ABRT (0x040)
#define I2C_TX_ABRT_SRC_REG (0x0880)
#define I2C_CLR_TX_ABRT_REG (0x0854)
#define I2C_STATUS_REG (0x0870)
#define I2C_TX_FIFO_EMPTY (0x04)
#define I2C_TX_FIFO_DATA_NUM_REG (0x0874)

#define I2C_SS_SCLHCNT 0x3db
#define I2C_SS_SCLLCNT 0x3e6

/*AVS_REG_GEN*/
#define AVS_WR_OPEN_OFFSET 0x0004
#define AVS_INT_STATUS_OFFSET 0x0008
#define AVS_ERROR_INT_STATUS_OFFSET 0x000C
#define AVS_PARITY_INT_STATUS_OFFSET 0x0010
#define AVS_INT_CLEAR_OFFSET 0x0020
#define AVS_ERROR_INT_CLEAR_OFFSET 0x0024
#define AVS_INT_MASK_OFFSET 0x0034

/*PMBUSIF_REG_GEN*/
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

/*PMBUS_PROC_REG_GEN*/
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

#define SYSCTL_DEBUG_LEVEL 0

#if (SYSCTL_DEBUG_LEVEL == 0)
#define debug_sysctrl_print(fmt...)
#else
#define debug_sysctrl_print(fmt...) printk(fmt)
#endif

typedef struct {
	unsigned char hllc_enable;
	unsigned char rvs0[3];
	unsigned int hllc_crc_ecc[HLLC_NUM_MAX];
} hllc_crc_ecc_info;

typedef union {
	/* Define the struct bits */
	struct {
		unsigned int hllc_enable : 8   ; /* [7..0]  0:hllc0, 1:hllc1, 2:hllc2*/
		unsigned int hllc_link_status : 8  ; /* [15..8]  */
		unsigned int rsv1							   : 16  ; /* [31..16]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;

} hllc_link_sta_info;

typedef union {
	/* Define the struct bits */
	struct {
		unsigned int hydra_tx_ch0_1bit_ecc_err : 1   ; /* [0]  */
		unsigned int hydra_tx_ch1_1bit_ecc_err : 1   ; /* [1]  */
		unsigned int hydra_tx_ch2_1bit_ecc_err : 1   ; /* [2]  */
		unsigned int phy_tx_retry_1bit_ecc_err : 1   ; /* [3]  */
		unsigned int hydra_rx_ch0_1bit_ecc_err : 1   ; /* [4]  */
		unsigned int hydra_rx_ch1_1bit_ecc_err : 1   ; /* [5]  */
		unsigned int hydra_rx_ch2_1bit_ecc_err : 1   ; /* [6]  */
		unsigned int hydra_tx_ch0_2bit_ecc_err : 1   ; /* [7]  */
		unsigned int hydra_tx_ch1_2bit_ecc_err : 1   ; /* [8]  */
		unsigned int hydra_tx_ch2_2bit_ecc_err : 1   ; /* [9]  */
		unsigned int phy_tx_retry_2bit_ecc_err : 1   ; /* [10]  */
		unsigned int hydra_rx_ch0_2bit_ecc_err : 1   ; /* [11]  */
		unsigned int hydra_rx_ch1_2bit_ecc_err : 1   ; /* [12]  */
		unsigned int hydra_rx_ch2_2bit_ecc_err : 1   ; /* [13]  */
		unsigned int rsv1						: 18  ; /* [31..14]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;

} hllc_mem_ecc_info;

typedef struct {
	unsigned char ddrc_mem_secc_en;
	unsigned char rsv0[3];
	unsigned int ddrc_mem_secc;
	unsigned int ddrc_mem_mecc;
} ddrc_mem_ecc_info;

/* Define the union pmbus_vout_mode */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int vid_table : 5   ; /* [4..0]  */
		unsigned int vout_mode_surport : 3   ; /* [7..5]  */
		unsigned int reserved_0			: 24  ; /* [31..8]  */
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

#endif /* _HIS_SYSCTL_H_ */
