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

#ifndef _SYSCTL_DRV_H_
#define _SYSCTL_DRV_H_

/* SYSCTRL ERR */
#define SYSCTL_ERR_OK 0   /* Ok */
#define SYSCTL_ERR_PARAM 1   /* Invalid parameter */
#define SYSCTL_ERR_FAILED 2   /* Operation failed */
#define SYSCTL_ERR_PORT 3   /* Invalid port */
#define SYSCTL_ERR_TIMEOUT 4   /* Operation time out */
#define SYSCTL_ERR_NOMATCH 5   /* Version not match */
#define SYSCTL_ERR_EXIST 6   /* Entry exists */
#define SYSCTL_ERR_NOMEM 7   /* Out of memory */
#define SYSCTL_ERR_INIT 8   /* Feature not initialized */
#define SYSCTL_ERR_FAULT 9   /* Invalid address */
#define SYSCTL_ERR_PERM 10  /* Operation not permitted */
#define SYSCTL_ERR_EMPTY 11  /* Table empty */
#define SYSCTL_ERR_FULL 12  /* Table full */
#define SYSCTL_ERR_NOT_FOUND 13  /* Not found */
#define SYSCTL_ERR_BUSY 14  /* Device or resource busy */
#define SYSCTL_ERR_RESOURCE 15  /* No resources for operation */
#define SYSCTL_ERR_CONFIG 16  /* Invalid configuration */
#define SYSCTL_ERR_UNAVAIL 17  /* Feature unavailable */
#define SYSCTL_ERR_CRC 18  /* CRC check failed */
#define SYSCTL_ERR_NXIO 19  /* No such device or address */
#define SYSCTL_ERR_ROLLBACK 20  /* chip rollback fail */
#define SYSCTL_ERR_LEN 32  /* Length too short or too long */
#define SYSCTL_ERR_UNSUPPORT 0xFF  /* Feature not supported */

#define CHIP_VER_BASE 0x20107E238
#define PEH_REG_ADDR (0xd7d00008)
#define HLLC0_REG_BASE (0x000200080000)
#define HLLC1_REG_BASE (0x000200090000)
#define HLLC2_REG_BASE (0x0002000a0000)
#define PCS0_REG_BASE (0x0002000c0000)
#define PA_REG_BASE (0x0002001d0000)
#define DDRC0_TB_REG_BASE (0x000094d20000)
#define DDRC0_TA_REG_BASE (0x00009cd20000)

#define HLLC_INTLV_MODE_2PX8		 0x0
#define HLLC_INTLV_MODE_2PX16	   0x1
#define HLLC_INTLV_MODE_2PX24	   0x2
#define HLLC_INTLV_MODE_4PX8		 0x3
#define HLLC_INTLV_MODE_3P1	   0x5
#define HLLC_INTLV_MODE_3P2	   0x6

#define CHIP_VERSION_ES (0x1)
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
#define DDRC_ECC_EN (0x5001)

#define RSV_CHAR_NUM 3

extern unsigned int g_sysctrl_debug;

#define debug_sysctrl_print(fmt...) \
do { \
	if (g_sysctrl_debug) \
		printk(fmt); \
} while (0)

typedef struct {
	unsigned char hllc_enable;
	unsigned char rvs0[RSV_CHAR_NUM];
	unsigned int hllc_crc_ecc[HLLC_NUM_MAX];
} hllc_crc_ecc_info;

typedef union {
	/* Define the struct bits */
	struct {
		unsigned int hllc_enable : 8   ; /* [7..0]  0:hllc0, 1:hllc1, 2:hllc2 */
		unsigned int hllc_link_status : 8  ; /* [15..8] */
		unsigned int rsv1							  : 16  ; /* [31..16] */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} hllc_link_sta_info;

typedef union {
	/* Define the struct bits */
	struct {
		unsigned int hydra_tx_ch0_bit1_ecc_err : 1   ; /* [0]  */
		unsigned int hydra_tx_ch1_bit1_ecc_err : 1   ; /* [1]  */
		unsigned int hydra_tx_ch2_bit1_ecc_err : 1   ; /* [2]  */
		unsigned int phy_tx_retry_bit1_ecc_err : 1   ; /* [3]  */
		unsigned int hydra_rx_ch0_bit1_ecc_err : 1   ; /* [4]  */
		unsigned int hydra_rx_ch1_bit1_ecc_err : 1   ; /* [5]  */
		unsigned int hydra_rx_ch2_bit1_ecc_err : 1   ; /* [6]  */
		unsigned int hydra_tx_ch0_bit2_ecc_err : 1   ; /* [7]  */
		unsigned int hydra_tx_ch1_bit2_ecc_err : 1   ; /* [8]  */
		unsigned int hydra_tx_ch2_bit2_ecc_err : 1   ; /* [9]  */
		unsigned int phy_tx_retry_bit2_ecc_err : 1   ; /* [10]  */
		unsigned int hydra_rx_ch0_bit2_ecc_err : 1   ; /* [11]  */
		unsigned int hydra_rx_ch1_bit2_ecc_err : 1   ; /* [12]  */
		unsigned int hydra_rx_ch2_bit2_ecc_err : 1   ; /* [13]  */
		unsigned int rsv1					  : 18  ; /* [31..14]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} hllc_mem_ecc_info;

typedef struct {
	unsigned char ddrc_mem_secc_en;
	unsigned char rsv0[RSV_CHAR_NUM];
	unsigned int ddrc_mem_secc;
	unsigned int ddrc_mem_mecc;
} ddrc_mem_ecc_info;

u64 get_chip_base(void);

#endif /* _SYSCTL_DRV_H_ */
