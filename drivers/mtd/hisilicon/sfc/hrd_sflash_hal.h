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

#ifndef __SFC_PHY_H__
#define __SFC_PHY_H__

#define SFC_BUSY_WAIT_TIMEOUT 1000

/* 3Byte or 4Byte addr */
#define SPI_FLASH_3BYTE_ADDR (1)
#define SPI_FLASH_4BYTE_ADDR (1 << 1)

 /* Standard SPI */
#define STANDARD_SPI_IF (1)

/* Dual Input/Dual Output SPI */
#define DUAL_IN_DUAL_OUT_SPI_IF (1 << 1)
/* Dual I/O SPI */
#define DUAL_IO_SPI_IF (1 << 2)
/* Full Dual I/O SPI */
#define FULL_DUAL_IO_SPI_IF (1 << 3)
/* Quad Input/Quad Output SPI */
#define QUAD_IN_DUAL_OUT_SPI_IF (1 << 5)
/* Quad I/O SPI */
#define QUAD_IO_SPI_IF (1 << 6)
/* Full Quad SPI */
#define FULL_QUAD_IO_SPI_IF (1 << 7)

#define SFC_REGISTER_RW_MODE (1)
#define SFC_BUS_RW_MODE (1 << 1)
#define SFC_DMA_RW_MODE (1 << 2)

#define SFC_RW_MODE_SUPPORT \
	(SFC_REGISTER_RW_MODE | SFC_BUS_RW_MODE | SFC_DMA_RW_MODE)

#define SFC_SYNC_FREQ_25M 25000000
#define SFC_SYNC_FREQ_36M 36000000
#define SFC_SYNC_FREQ_50M 50000000
#define SFC_SYNC_FREQ_72M 72000000

#define SFC_CHIP_CS 0
#define WAIT_MAX_COUNT 0x4000000
#define WAIT_TIME_OUT 0xFFFFFF
#define ERASE_WAIT_TIME 50

#define DMA_WAIT_MAX_COUNT 0x20000000
#define SFC_BUS_DMA_LEN_MAX 0x10000000

#define SFC_DMA_READ 1
#define SFC_DMA_WRITE 0

#define SYNC_CLOCK_72M 72
#define SYNC_CLOCK_50M 50
#define SYNC_CLOCK_36M 36
#define SYNC_CLOCK_25M 25

#define SYNC_CLK_SET_ADDR 0xA000001C

#define BLOCK_PROT_MAX 9
#define BLOCK_PROT_MAP 2

#define SFC_INT_NUM 47

#define SFC_CS_NUM 2

#define STATUS_REG_P_ERR (1<<6)
#define STATUS_REG_E_ERR (1<<5)
#define STATUS_REG_BUSY_BIT 0x1
#define FLASH_SIZE_CS_BIT(x) (8 * x)
#define SPI_FLASH_SIZE_NUM 16

#define SPI_FLASH_BASE_ADDR (0x204000000L)
#define SPI_REG_BASE_ADDR (0x206200000L)
#define SPI_FLASH_DEV_SIZE 0x2000000
#define SPI_REG_END_ADDR (0x500)

/* SFC REG */
#define GLOBAL_CONFIG (0x0100)
#define TIMING (0x0110)
#define INTRAWSTATUS (0x0120)
#define INTSTATUS (0x0124)
#define INTMASK (0x0128)
#define INTCLEAR (0x012C)
#define VERSION (0x01F8)
#define VERSION_SEL (0x01FC)
#define BUS_CONFIG1			   (0x0200)
#define BUS_CONFIG2			   (0x0204)
#define BUS_FLASH_SIZE (0x0210)
#define BUS_BASE_ADDR_CS0		 (0x0214)
#define BUS_BASE_ADDR_CS1		 (0x0218)
#define BUS_ALIAS_ADDR (0x021C)
#define BUS_ALIAS_CS (0x0220)
#define BUS_DMA_CTRL (0x0240)
#define BUS_DMA_MEM_SADDR (0x0244)
#define BUS_DMA_FLASH_SADDR (0x0248)
#define BUS_DMA_LEN (0x024C)
#define BUS_DMA_AHB_CTRL (0x0250)
#define CMD_CONFIG (0x0300)
#define CMD_INS (0x0308)
#define CMD_ADDR (0x030C)

#define CMD_DATABUF(x) (0x0400 + 4 * ((x) - 1))

#define SC_PERCTRL0			   (0x20000000 + 0x1c)
#define SFC_DIV_REG_BIT 24

#define CONFIG BUS_CONFIG1
#define CMD CMD_CONFIG
#define INS CMD_INS
#define ADDR CMD_ADDR
#define DATABUFFER1	CMD_DATABUF(1)
#define DATABUFFER2	CMD_DATABUF(2)
#define DATABUFFER3	CMD_DATABUF(3)
#define DATABUFFER4	CMD_DATABUF(4)
#define DATABUFFER5	CMD_DATABUF(5)
#define DATABUFFER6	CMD_DATABUF(6)
#define DATABUFFER7	CMD_DATABUF(7)
#define DATABUFFER8	CMD_DATABUF(8)
#define SFC_HARD_BUF_LEN (64)

/* GLOBAL_CONFIG */
#define RD_DELAY 3
#define API_ADDR_MODE 2
#define WP_EN 1
#define SPI_MODE 0

/* BUS_FLASH_SIZE */
#define FLASH_SIZE_CS0 0
#define FLASH_SIZE_CS1 8

/* BUS_CONFIG1 */
#define RD_ENABLE 31
#define WR_ENABLE 30
#define WR_INS 22
#define WR_DUMMY_CNT 19
#define WR_MEM_TYPE 16
#define RD_INS 8
#define PRE_CNT 6
#define RD_DUMMY 3
#define RD_MEM_TYPE 0

/* INT */
#define INT_MASK (0x1ff)
#define DMA_DONE_INT_BIT (1 << 1)
#define CMD_OP_END_INT_BIT (1)

/* BUS_CONFIG2 */

/* CMD_CONFIG */
#define LOCK_FLASH 20
#define MEM_TYPE 17
#define DATA_CNT 9
#define RW_DATA 8	/* 0 read 1 write*/
#define DATA_EN 7
#define CMD_DUMMY 4
#define ADDR_EN 3
#define SEL_CS 1
#define START 0

/* TIMING */
#define TCSH 12
#define TCSS 8
#define TSHSL 0

/* BUS_DMA_CTRL */
#define DMA_SEL_CS 4
#define DMA_RD_WR 1
#define DMA_START 0

union UN_SFC_CMD_CONFIG {
	struct {
		unsigned int start:1;
		unsigned int sel_cs:1;
		unsigned int rsv0:1;
		unsigned int addr_en:1;
		unsigned int dummy_byte_cnt:3;
		unsigned int data_en:1;
#define SFC_CMD_CFG_READ 1
#define SFC_CMD_CFG_WRITE 0
		unsigned int rw:1;
#define SFC_CMD_DATA_CNT(x) ((x) - 1)
		unsigned int data_cnt:8;
		unsigned int mem_if_type:3;
		unsigned int rsv1:12;
	} bits;
	unsigned int u32;
};

extern u32 SFC_ControllerInit(u64 sfc_reg_base);
extern s32 SFC_RegModeRead(struct SFC_SFLASH_INFO *sflash, u32 offset,
			   u8 *pucDest, u32 ulReadLen);
extern s32 SFC_BusModeRead(struct SFC_SFLASH_INFO *sflash, u32 offset,
			   u8 *pucDest, u32 ulReadLen);
extern s32 SFC_RegModeWrite(struct SFC_SFLASH_INFO *sflash, u32 offset,
				const u8 *pucSrc, u32 ulWriteLen);
extern s32 SFC_BusModeWrite(struct SFC_SFLASH_INFO *sflash, u32 offset,
				const u8 *pucSrc, u32 ulWriteLen);
extern s32 SFC_SPIFlashIdGet(struct SFC_SFLASH_INFO *pFlinfo,
				 u8 *pulManuId, u16 *pulDevId, u8 *pcfi_len,
				 u8 *psec_arch, u8 *pfid);
extern s32 SFC_ControllerAddrModeSet(struct SFC_SFLASH_INFO *pFlinfo);
extern s32 SFC_BlockErase(struct SFC_SFLASH_INFO *sflash, u32 ulAddr,
			  u32 ErCmd);
extern int hrd_sflash_init(struct SFC_SFLASH_INFO *pFlinfo);
extern int SFC_WPSet(struct SFC_SFLASH_INFO *sflash, BOOL val);

#endif
