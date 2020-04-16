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

#ifndef __HRD_SFLASH_SPEC_H__
#define __HRD_SFLASH_SPEC_H__

#define SFLASH_DEFAULT_RDID_OPCD 0x9F /* Default Read ID */
#define SFLASH_DEFAULT_WREN_OPCD 0x06 /* Default Write Enable */

/* Constants */
#define HISI_SFLASH_READ_CMND_LENGTH 4 /* 1B opcode + 3B address */
#define HISI_SFLASH_SE_CMND_LENGTH 4 /* 1B opcode + 3B address */
#define HISI_SFLASH_BE_CMND_LENGTH 1 /* 1B opcode */
#define HISI_SFLASH_PP_CMND_LENGTH 4 /* 1B opcode + 3B address */
#define HISI_SFLASH_WREN_CMND_LENGTH 1 /* 1B opcode */
#define HISI_SFLASH_WRDI_CMND_LENGTH 1 /* 1B opcode */
#define HISI_SFLASH_RDID_CMND_LENGTH 1 /* 1B opcode */
/* 1B manf ID and 2B device ID */
#define HISI_SFLASH_RDID_REPLY_LENGTH 3
#define HISI_SFLASH_RDSR_CMND_LENGTH 1 /* 1B opcode */
#define HISI_SFLASH_RDSR_REPLY_LENGTH 1 /* 1B status */
/* 1B opcode + 1B status value */
#define HISI_SFLASH_WRSR_CMND_LENGTH 2
#define HISI_SFLASH_DP_CMND_LENGTH 1 /* 1B opcode */
#define HISI_SFLASH_RES_CMND_LENGTH 1 /* 1B opcode */

/* Status Register Bit Masks */
/* bit 0; write in progress */
#define HISI_SFLASH_STATUS_REG_WIP_OFFSET 0
/* bit 2-4; write protect option */
#define HISI_SFLASH_STATUS_REG_WP_OFFSET 2
/* bit 7; lock status register write */
#define HISI_SFLASH_STATUS_REG_SRWD_OFFSET 7
#define HISI_SFLASH_STATUS_REG_WIP_MASK \
				(0x1 << HISI_SFLASH_STATUS_REG_WIP_OFFSET)
#define HISI_SFLASH_STATUS_REG_SRWD_MASK \
				(0x1 << HISI_SFLASH_STATUS_REG_SRWD_OFFSET)

#define HISI_SFLASH_MAX_WAIT_LOOP 1000000
#define HISI_SFLASH_CHIP_ERASE_MAX_WAIT_LOOP 0x50000000

#define HISI_SFLASH_DEFAULT_RDID_OPCD 0x9F /* Default Read ID */
#define HISI_SFLASH_DEFAULT_WREN_OPCD 0x06 /* Default Write Enable */
#define HISI_SFLASH_NO_SPECIFIC_OPCD 0x00
#define HISI_SFLASH_UNKOWN_OPCD 0xFF

/********************************/
/*  ST M25Pxxx Device Specific */
/********************************/
/* Manufacturer IDs and Device IDs for SFLASHs supported by the driver */
#define HISI_M25PXXX_ST_MANF_ID 0x20
#define HISI_M25P80_DEVICE_ID 0x2014
#define HISI_M25P80_MAX_SPI_FREQ 20000000 /* 20MHz */
#define HISI_M25P80_MAX_FAST_SPI_FREQ 50000000 /* 50MHz */
#define HISI_M25P80_FAST_READ_DUMMY_BYTES 1
#define HISI_M25P32_DEVICE_ID 0x2016
#define HISI_M25P32_MAX_SPI_FREQ 20000000 /* 20MHz */
#define HISI_M25P32_MAX_FAST_SPI_FREQ 50000000 /* 50MHz */
#define HISI_M25P32_FAST_READ_DUMMY_BYTES 1
#define HISI_M25P64_DEVICE_ID 0x2017
#define HISI_M25P64_MAX_SPI_FREQ 20000000 /* 20MHz */
#define HISI_M25P64_MAX_FAST_SPI_FREQ 50000000 /* 50MHz */
#define HISI_M25P64_FAST_READ_DUMMY_BYTES 1
#define HISI_M25P128_DEVICE_ID 0x2018
#define HISI_M25P128_MAX_SPI_FREQ 20000000 /* 20MHz */
#define HISI_M25P128_MAX_FAST_SPI_FREQ 50000000 /* 50MHz */
#define HISI_M25P128_FAST_READ_DUMMY_BYTES 1

/* Sector Sizes and population per device model */
#define HISI_M25P80_SECTOR_SIZE 0x10000 /* 64K */
#define HISI_M25P32_SECTOR_SIZE 0x10000 /* 64K */
#define HISI_M25P64_SECTOR_SIZE 0x10000 /* 64K */
#define HISI_M25P128_SECTOR_SIZE 0x40000 /* 256K */
#define HISI_M25P80_SECTOR_NUMBER 16
#define HISI_M25P32_SECTOR_NUMBER 64
#define HISI_M25P64_SECTOR_NUMBER 128
#define HISI_M25P128_SECTOR_NUMBER 64
#define HISI_M25P_PAGE_SIZE 0x100 /* 256 byte */

#define HISI_M25P_WREN_CMND_OPCD 0x06 /* Write Enable */
#define HISI_M25P_WRDI_CMND_OPCD 0x04 /* Write Disable */
#define HISI_M25P_RDID_CMND_OPCD 0x9F /* Read ID */
/* Read Status Register */
#define HISI_M25P_RDSR_CMND_OPCD 0x05
/* Write Status Register */
#define HISI_M25P_WRSR_CMND_OPCD 0x01
#define HISI_M25P_READ_CMND_OPCD 0x03 /* Sequential Read */
#define HISI_M25P_FAST_RD_CMND_OPCD 0x0B /* Fast Read */
#define HISI_M25P_PP_CMND_OPCD 0x02 /* Page Program */
#define HISI_M25P_SSE_CMND_OPCD 0x20 /* SubSectorErase */
#define HISI_M25P_SE_CMND_OPCD 0xD8 /* Sector Erase */
#define HISI_M25P_BE_CMND_OPCD 0xC7 /* Bulk Erase */
/* Read Electronic Signature */
#define HISI_M25P_RES_CMND_OPCD 0xAB

/* Status Register Write Protect Bit Masks - 3bits */
#define HISI_M25P_STATUS_REG_WP_MASK (0x07 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_M25P_STATUS_BP_NONE (0x00 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_M25P_STATUS_BP_1_OF_64   (0x01 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_M25P_STATUS_BP_1_OF_32   (0x02 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_M25P_STATUS_BP_1_OF_16   (0x03 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_M25P_STATUS_BP_1_OF_8  (0x04 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_M25P_STATUS_BP_1_OF_4  (0x05 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_M25P_STATUS_BP_1_OF_2  (0x06 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_M25P_STATUS_BP_ALL (0x07 << HISI_SFLASH_STATUS_REG_WP_OFFSET)

/************************************/
/*  MXIC MX25L6405 Device Specific */
/************************************/
/* Manufacturer IDs and Device IDs for SFLASHs supported by the driver */
#define HISI_MXIC_MANF_ID 0xC2
#define HISI_MX25L6405_DEVICE_ID 0x2017
#define HISI_MX25L6405_MAX_SPI_FREQ 20000000 /* 20MHz */
#define HISI_MX25L6405_MAX_FAST_SPI_FREQ 50000000 /* 50MHz */
#define HISI_MX25L6405_FAST_READ_DUMMY_BYTES 1
#define HISI_MXIC_DP_EXIT_DELAY 30 /* 30 ms */

/* Sector Sizes and population per device model */
#define HISI_MX25L6405_SECTOR_SIZE 0x10000 /* 64K */
#define HISI_MX25L6405_SECTOR_NUMBER 128
#define HISI_MXIC_PAGE_SIZE 0x100 /* 256 byte */

#define HISI_MX25L_WREN_CMND_OPCD 0x06 /* Write Enable */
#define HISI_MX25L_WRDI_CMND_OPCD 0x04 /* Write Disable */
#define HISI_MX25L_RDID_CMND_OPCD 0x9F /* Read ID */
/* Read Status Register */
#define HISI_MX25L_RDSR_CMND_OPCD 0x05
/* Write Status Register */
#define HISI_MX25L_WRSR_CMND_OPCD 0x01
#define HISI_MX25L_READ_CMND_OPCD 0x03 /* Sequential Read */
#define HISI_MX25L_FAST_RD_CMND_OPCD 0x0B /* Fast Read */
#define HISI_MX25L_PP_CMND_OPCD 0x02 /* Page Program */
#define HISI_MX25L_SSE_CMND_OPCD 0x20 /* SubSector Erase */
#define HISI_MX25L_SE_CMND_OPCD 0xD8 /* Sector Erase */
#define HISI_MX25L_BE_CMND_OPCD 0xC7 /* Bulk Erase */
#define HISI_MX25L_DP_CMND_OPCD 0xB9 /* Deep Power Down */
/* Read Electronic Signature */
#define HISI_MX25L_RES_CMND_OPCD 0xAB

/* Status Register Write Protect Bit Masks - 4bits */
#define HISI_MX25L_STATUS_REG_WP_MASK (0x0F << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25L_STATUS_BP_NONE (0x00 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25L_STATUS_BP_1_OF_128 (0x01 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25L_STATUS_BP_1_OF_64  (0x02 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25L_STATUS_BP_1_OF_32  (0x03 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25L_STATUS_BP_1_OF_16  (0x04 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25L_STATUS_BP_1_OF_8   (0x05 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25L_STATUS_BP_1_OF_4   (0x06 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25L_STATUS_BP_1_OF_2   (0x07 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25L_STATUS_BP_ALL (0x0F << HISI_SFLASH_STATUS_REG_WP_OFFSET)

/************************************/
/*  MXIC MX25LU12835F Device Specific */
/************************************/
/* Manufacturer IDs and Device IDs for SFLASHs supported by the driver */
#define HISI_MX25U12835F_MANF_ID 0xC2
#define HISI_MX25U12835F_DEVICE_ID 0x2538
#define HISI_MX25U12835F_MAX_SPI_FREQ 20000000 /* 20MHz */
#define HISI_MX25U12835F_MAX_FAST_SPI_FREQ 50000000 /* 50MHz */
#define HISI_MX25U12835F_FAST_READ_DUMMY_BYTES 1
#define HISI_MX25U12835F_DP_EXIT_DELAY 30 /* 30 ms */

/* Sector Sizes and population per device model */
#define HISI_MX25U12835F_SECTOR_SIZE 0x10000 /* 64K */
#define HISI_MX25U12835F_SECTOR_NUMBER 256
#define HISI_MX25U12835F_PAGE_SIZE 0x1000 /* 4KB */

#define HISI_MX25U12835F_WREN_CMND_OPCD 0x06 /* Write Enable */
#define HISI_MX25U12835F_WRDI_CMND_OPCD 0x04 /* Write Disable */
#define HISI_MX25U12835F_RDID_CMND_OPCD 0x9F /* Read ID */
/* Read Status Register */
#define HISI_MX25U12835F_RDSR_CMND_OPCD 0x05
/* Write Status Register */
#define HISI_MX25U12835F_WRSR_CMND_OPCD 0x01
#define HISI_MX25U12835F_READ_CMND_OPCD 0x03 /* Sequential Read */
#define HISI_MX25U12835F_FAST_RD_CMND_OPCD 0x0B /* Fast Read */
#define HISI_MX25U12835F_PP_CMND_OPCD 0x02 /* Page Program */
#define HISI_MX25U12835F_SSE_CMND_OPCD 0x20 /* SubSector Erase */
#define HISI_MX25U12835F_SE_CMND_OPCD 0xD8 /* Sector Erase */
#define HISI_MX25U12835F_BE_CMND_OPCD 0xC7 /* Bulk Erase */
#define HISI_MX25U12835F_DP_CMND_OPCD 0xB9 /* Deep Power Down */
/* Read Electronic Signature */
#define HISI_MX25U12835F_RES_CMND_OPCD 0xAB

/* Status Register Write Protect Bit Masks - 4bits */
#define HISI_MX25U12835F_STATUS_REG_WP_MASK (0x0F << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25U12835F_STATUS_BP_NONE (0x00 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25U12835F_STATUS_BP_1_OF_128   (0x01 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25U12835F_STATUS_BP_1_OF_64  (0x02 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25U12835F_STATUS_BP_1_OF_32  (0x03 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25U12835F_STATUS_BP_1_OF_16  (0x04 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25U12835F_STATUS_BP_1_OF_8 (0x05 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25U12835F_STATUS_BP_1_OF_4 (0x06 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25U12835F_STATUS_BP_1_OF_2 (0x07 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_MX25U12835F_STATUS_BP_ALL (0x0F << HISI_SFLASH_STATUS_REG_WP_OFFSET)

/************************************/
/* MXIC MX25L1606E Device Specific */
/************************************/
/* Manufacturer IDs and Device IDs for SFLASHs supported by the driver */
#define HISI_MX25L1606E_DEVICE_ID 0x2015
#define HISI_MX25L1606E_MAX_SPI_FREQ 33000000 /* 33MHz */
#define HISI_MX25L1606E_MAX_FAST_SPI_FREQ 86000000 /* 86MHz */
#define HISI_MX25L1606E_FAST_READ_DUMMY_BYTES 1

#define HISI_MX25L1606E_PAGE_SIZE 0x1000 /* 4K */
#define HISI_MX25L1606E_SECTOR_SIZE 0x10000 /* 64K */
#define HISI_MX25L1606E_SECTOR_NUMBER 32

/************************************/
/*  SPANSION S25Fx128 Device Specific */
/************************************/
/* Manufacturer IDs and Device IDs for SFLASHs supported by the driver */
#define HISI_SPANSION_MANF_ID 0x01
#define HISI_S25FL128_DEVICE_ID 0x2018
#define HISI_S25FL128_MAX_SPI_FREQ 33000000 /* 33MHz */
#define HISI_S25FL128_MAX_FAST_SPI_FREQ 104000000 /* 104MHz */
#define HISI_S25FL128_FAST_READ_DUMMY_BYTES 1

/* Sector Sizes and population per device model */
#define HISI_S25FL128_SECTOR_SIZE 0x10000 /* 64K */
#define HISI_S25FL128_SECTOR_NUMBER 256
#define HISI_S25FL_PAGE_SIZE 0x100 /* 256 byte */

#define HISI_S25FL_WREN_CMND_OPCD 0x06 /* Write Enable */
#define HISI_S25FL_WRDI_CMND_OPCD 0x04 /* Write Disable */
#define HISI_S25FL_RDID_CMND_OPCD 0x9F /* Read ID */
/* Read Status Register */
#define HISI_S25FL_RDSR_CMND_OPCD 0x05
/* Write Status Register */
#define HISI_S25FL_WRSR_CMND_OPCD 0x01
#define HISI_S25FL_READ_CMND_OPCD 0x03 /* Sequential Read */
#define HISI_S25FL_FAST_RD_CMND_OPCD 0x0B /* Fast Read */
#define HISI_S25FL_PP_CMND_OPCD 0x02 /* Page Program */
#define HISI_S25FL_SSE_CMND_OPCD 0x20 /* SubSector Erase */
#define HISI_S25FL_SE_CMND_OPCD 0xD8 /* Sector Erase */
#define HISI_S25FL_BE_CMND_OPCD 0xC7 /* Bulk Erase */
#define HISI_S25FL_DP_CMND_OPCD 0xB9 /* Deep Power Down */
/* Read Electronic Signature */
#define HISI_S25FL_RES_CMND_OPCD 0xAB

/* Status Register Write Protect Bit Masks - 4bits */
#define HISI_S25FL_STATUS_REG_WP_MASK \
				(0x0F << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_S25FL_STATUS_BP_NONE \
				(0x00 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_S25FL_STATUS_BP_1_OF_128 \
				(0x01 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_S25FL_STATUS_BP_1_OF_64 \
				(0x02 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_S25FL_STATUS_BP_1_OF_32 \
				(0x03 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_S25FL_STATUS_BP_1_OF_16 \
				(0x04 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_S25FL_STATUS_BP_1_OF_8 \
				(0x05 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_S25FL_STATUS_BP_1_OF_4 \
				(0x06 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_S25FL_STATUS_BP_1_OF_2 \
				(0x07 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_S25FL_STATUS_BP_ALL \
				(0x0F << HISI_SFLASH_STATUS_REG_WP_OFFSET)

/********************************/
/*  ATMEL ATxx Device Specific */
/********************************/
/* Manufacturer IDs and Device IDs for SFLASHs supported by the driver */
#define HISI_AT25DFXXX_AT_MANF_ID 0x1F
#define HISI_AT25DF641_DEVICE_ID 0x4800
#define HISI_AT25DF641_MAX_SPI_FREQ 20000000 /* 20MHz */
#define HISI_AT25DF641_MAX_FAST_SPI_FREQ 50000000 /* 50MHz */
#define HISI_AT25DF641_FAST_READ_DUMMY_BYTES 1

/* Sector Sizes and population per device model */
#define HISI_AT25DF641_SECTOR_SIZE 0x10000 /* 64K */
#define HISI_AT25DF641_SECTOR_NUMBER 128
#define HISI_AT25DF_PAGE_SIZE 0x100 /* 256 byte */

#define HISI_AT25DF_WREN_CMND_OPCD 0x06 /* Write Enable */
#define HISI_AT25DF_WRDI_CMND_OPCD 0x04 /* Write Disable */
#define HISI_AT25DF_RDID_CMND_OPCD 0x9F /* Read ID */
#define HISI_AT25DF_RDSR_CMND_OPCD 0x05 /* Read Status Register */
#define HISI_AT25DF_WRSR_CMND_OPCD 0x01 /* Write Status Register */
#define HISI_AT25DF_READ_CMND_OPCD 0x03 /* Sequential Read */
#define HISI_AT25DF_FAST_RD_CMND_OPCD 0x0B /* Fast Read */
#define HISI_AT25DF_PP_CMND_OPCD 0x02 /* Page Program */
#define HISI_AT25DF_SSE_CMND_OPCD 0x20 /* SubSector Erase */
#define HISI_AT25DF_SE_CMND_OPCD 0xD8 /* Sector Erase */
#define HISI_AT25DF_BE_CMND_OPCD 0xC7 /* Bulk Erase */
#define HISI_AT25DF_RES_CMND_OPCD 0xAB /* Read Electronic Signature */

/* Status Register Write Protect Bit Masks - 4bits */
#define HISI_AT25DF_STATUS_REG_WP_MASK \
				(0x0F << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_AT25DF_STATUS_BP_NONE \
				(0x00 << HISI_SFLASH_STATUS_REG_WP_OFFSET)

#define HISI_AT25DF_STATUS_BP_WP_NONE (0x04 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_AT25DF_STATUS_BP_SOME (0x05 << HISI_SFLASH_STATUS_REG_WP_OFFSET)
#define HISI_AT25DF_STATUS_BP_ALL (0x07 << HISI_SFLASH_STATUS_REG_WP_OFFSET)

/********************************/
/*  NUMONYX N25Q Device Specific */
/********************************/
#define HISI_N25Q_WREN_CMND_OPCD 0x06 /* Write Enable */
#define HISI_N25Q_WRDI_CMND_OPCD 0x04 /* Write Disable */
#define HISI_N25Q_RDID_CMND_OPCD 0x9F /* Read ID */
/* Read Status Register */
#define HISI_N25Q_RDSR_CMND_OPCD 0x05
/* Write Status Register */
#define HISI_N25Q_WRSR_CMND_OPCD 0x01
#define HISI_N25Q_READ_CMND_OPCD 0x03 /* Sequential Read */
#define HISI_N25Q_FAST_RD_CMND_OPCD 0x0B /* Fast Read */
#define HISI_N25Q_PP_CMND_OPCD 0x02 /* Page Program */
#define HISI_N25Q_SSE_CMND_OPCD 0x20 /* SubSectorErase */
#define HISI_N25Q_SE_CMND_OPCD 0xD8 /* Sector Erase */
#define HISI_N25Q_BE_CMND_OPCD 0xC7 /* Bulk Erase */
/* Read Volatile Enhanced Configuration Register */
#define HISI_N25Q_RDVECR_CMND_OPCD 0x65
/* Write Volatile Enhanced Configuration Register */
#define HISI_N25Q_WRVECR_CMND_OPCD 0x61
/* Enter 4-byte address mode */
#define HISI_N25Q_EN4BADDR_CMND_OPCD 0xB7
/* Exit 4-byte address mode */
#define HISI_N25Q_EX4BADDR_CMND_OPCD 0xE9
/* STATUS REGISTER BUSY BIT */
#define HISI_N25Q_BUSY_FLAG_BIT 0xC7

#define HISI_N25Q256_MANF_ID 0x20
#define HISI_N25Q256_DEVICE_ID 0xBA19
#define HISI_N25Q256_MAX_SPI_FREQ 108000000 /* 108MHz */
#define HISI_N25Q256_MAX_FAST_SPI_FREQ 432000000 /* 432MHz */
#define HISI_N25Q256_FAST_READ_DUMMY_BYTES 8

#define HISI_N25Q256_SECTOR_SIZE 0x10000 /* 64K */
#define HISI_N25Q256_SECTOR_NUMBER 512
#define HISI_N25Q256_PAGE_SIZE 0x1000 /* 4K */

/* support 3byte and 4byte addr */
#define HISI_N25Q256_3B_4B_SUPPORT 0x3
/* support ESPI, FULL DIO, FULL QIO mode */
#define HISI_N25Q256_IF_TYPE_SUPPORT 0x89

#define HISI_N25Q128_MANF_ID 0x20
#define HISI_N25Q128_DEVICE_ID 0xBA18
#define HISI_N25Q128_MAX_SPI_FREQ 108000000 /* 108MHz */
#define HISI_N25Q128_MAX_FAST_SPI_FREQ 432000000 /* 432MHz */
#define HISI_N25Q128_FAST_READ_DUMMY_BYTES 8

#define HISI_N25Q128_SECTOR_SIZE 0x10000 /* 64K */
#define HISI_N25Q128_SECTOR_NUMBER 256
#define HISI_N25Q128_PAGE_SIZE 0x1000 /* 4K */

/* NUMONYX N25Q128B SPI flash */
#define HISI_N25Q128B_MANF_ID 0x20
#define HISI_N25Q128B_DEVICE_ID 0xBB18

/* support 3byte and 4byte addr */
#define HISI_N25Q128_3B_4B_SUPPORT 0x3
/* support ESPI, FULL DIO, FULL QIO mode */
#define HISI_N25Q128_IF_TYPE_SUPPORT 0x89

#endif
