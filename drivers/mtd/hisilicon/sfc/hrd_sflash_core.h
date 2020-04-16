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

#ifndef __HRD_SFLASH_CORE_H__
#define __HRD_SFLASH_CORE_H__

#include "hrd_sflash_driver.h"

#define SFC_HARD_BUF_LEN (256)

#define SPI_CMD_SR_WIP 1 /* Write in Progress bit in status register position */
#define SPI_CMD_RDSR 0x05 /* Read Status Register */

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

#define SFC_CHIP_CS 0
#define WAIT_TIME_OUT 0xFFFFFF
#define ERASE_WAIT_TIME 50

#define SFC_INT_WAIT_CNT 1000000
#define FLASH_ERASE_BUSY_WAIT_CNT 1000000
#define FLASH_WRITE_BUSY_WAIT_CNT 1000

#define STATUS_REG_P_ERR (1 << 6)
#define STATUS_REG_E_ERR (1 << 5)
#define STATUS_REG_BUSY_BIT 0x1
#define FLASH_SIZE_CS_BIT(x) (8 * (x))

#define SFC_OP_ERR_MASK (0x1EC)

/* SFC REG */
#define GLOBAL_CONFIG (0x0100)
#define TIMING (0x0110)
#define INTRAWSTATUS (0x0120)
#define INTSTATUS (0x0124)
#define INTMASK (0x0128)
#define INTCLEAR (0x012C)
#define VERSION (0x01F8)
#define VERSION_SEL (0x01FC)
#define BUS_CONFIG1 (0x0200)
#define BUS_CONFIG2 (0x0204)
#define BUS_FLASH_SIZE (0x0210)
#define BUS_BASE_ADDR_CS0 (0x0214)
#define BUS_BASE_ADDR_CS1 (0x0218)
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

#define CONFIG BUS_CONFIG1
#define CMD CMD_CONFIG
#define INS CMD_INS
#define ADDR CMD_ADDR
#define DATABUFFER1 CMD_DATABUF(1)
#define DATABUFFER2 CMD_DATABUF(2)
#define DATABUFFER3 CMD_DATABUF(3)
#define DATABUFFER4 CMD_DATABUF(4)
#define DATABUFFER5 CMD_DATABUF(5)
#define DATABUFFER6 CMD_DATABUF(6)
#define DATABUFFER7 CMD_DATABUF(7)
#define DATABUFFER8 CMD_DATABUF(8)

/* INT */
#define INT_MASK (0x1ff)
#define CMD_OP_END_INT_BIT (1)

/* CMD_CONFIG */
#define LOCK_FLASH 20
#define MEM_TYPE 17
#define DATA_CNT 9
#define RW_DATA 8   /* 0 read 1 write */
#define DATA_EN 7
#define CMD_DUMMY 4
#define ADDR_EN 3
#define SEL_CS 1
#define START 0

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

u32 SFC_RegisterRead(u64 reg_addr);
void SFC_RegisterWrite(u64 reg_addr, u32 ulValue);
s32 SFC_ClearInt(u64 reg_addr);
s32 SFC_WaitInt(u64 reg_addr);
bool SFC_IsOpErr(u64 reg_addr);
s32 SFC_WriteEnable(struct SFC_SFLASH_INFO *sflash);
void SFC_FlashUnlock(struct SFC_SFLASH_INFO *sflash);
u32 SFC_ReadStatus(struct SFC_SFLASH_INFO *sflash);
s32 SFC_CheckBusy(struct SFC_SFLASH_INFO *sflash, u32 ulTimeOut);
s32 SFC_ClearStatus(struct SFC_SFLASH_INFO *sflash);
void SFC_CheckErr(struct SFC_SFLASH_INFO *sflash);
s32 SFC_CheckCmdExcStatus(struct SFC_SFLASH_INFO *sflash);
int SFC_WaitFlashIdle(struct SFC_SFLASH_INFO *sflash);
int SFC_GetDeviceId(struct SFC_SFLASH_INFO *sflash, u32 *id);
s32 SFC_RegWordAlignRead(struct SFC_SFLASH_INFO *sflash,
	u32 ulOffsetAddr, u32 *pulData, u32 ulReadLen);
s32 SFC_RegByteRead(struct SFC_SFLASH_INFO *sflash,
	u32 ulOffsetAddr, u8 *pucData);
s32 SFC_RegWordAlignWrite(struct SFC_SFLASH_INFO *sflash,
	const u32 *ulData, u32 ulOffsetAddr, u32 ulWriteLen);
s32 SFC_RegByteWrite(struct SFC_SFLASH_INFO *sflash,
	u8 ucData, u32 ulOffsetAddr);

#endif
