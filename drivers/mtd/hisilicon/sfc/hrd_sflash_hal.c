// SPDX-License-Identifier: GPL-2.0
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

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/resource.h>
#include <linux/signal.h>
#include <linux/types.h>
#include "hrdCommon.h"
#include "hrd_sflash_driver.h"
#include "hrd_sflash_hal.h"
#include "hrd_sflash_spec.h"
#include "lbc.h"

#define CPLD_WP_REG (0x13)
#define BIT0						   (1<<0)
#define SPI_CMD_WRR 0x01	/* Write Register */
#define SPI_CMD_RDSR 0x05	/* Read Status Register */
#define SPI_CMD_CLSR 0x30	/* Clear Status Register */

#define SPI_CMD_SR_WIP 1	/* Write in Progress bit in status register position */

struct SPI_FLASH_DEVICE_PARAMS g_stSPIFlashDevTable[] = {
	/* NUMONYX N25Q128 SPI flash, 16MB, 256 sectors of 64K each */
	{
	 MV_N25Q_WREN_CMND_OPCD,
	 MV_N25Q_WRDI_CMND_OPCD,
	 MV_N25Q_RDID_CMND_OPCD,
	 MV_N25Q_RDSR_CMND_OPCD,
	 MV_N25Q_WRSR_CMND_OPCD,
	 MV_N25Q_READ_CMND_OPCD,
	 MV_N25Q_FAST_RD_CMND_OPCD,
	 MV_N25Q_PP_CMND_OPCD,
	 MV_N25Q_SSE_CMND_OPCD,
	 MV_N25Q_SE_CMND_OPCD,
	 MV_N25Q_BE_CMND_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 MV_N25Q_RDVECR_CMND_OPCD,
	 MV_N25Q_WRVECR_CMND_OPCD,
	 MV_N25Q_EN4BADDR_CMND_OPCD,
	 MV_N25Q_EX4BADDR_CMND_OPCD,
	 MV_N25Q_BUSY_FLAG_BIT,
	 0,
	 0,
	 MV_N25Q128_PAGE_SIZE,
	 MV_N25Q128_SECTOR_NUMBER,
	 MV_N25Q128_SECTOR_SIZE,
	 "NUMONYX N25Q128",
	 MV_N25Q128_MANF_ID,
	 MV_N25Q128_DEVICE_ID,
	 0xff,
	 0xff,
	 0xff,
	 MV_N25Q128_MAX_SPI_FREQ,
	 MV_N25Q128_MAX_FAST_SPI_FREQ,
	 MV_N25Q128_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},

	/* NUMONYX N25Q128B SPI flash, 16MB, 256 sectors of 64K each */
	{
	 MV_N25Q_WREN_CMND_OPCD,
	 MV_N25Q_WRDI_CMND_OPCD,
	 MV_N25Q_RDID_CMND_OPCD,
	 MV_N25Q_RDSR_CMND_OPCD,
	 MV_N25Q_WRSR_CMND_OPCD,
	 MV_N25Q_READ_CMND_OPCD,
	 MV_N25Q_FAST_RD_CMND_OPCD,
	 MV_N25Q_PP_CMND_OPCD,
	 MV_N25Q_SSE_CMND_OPCD,
	 MV_N25Q_SE_CMND_OPCD,
	 MV_N25Q_BE_CMND_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 MV_N25Q_RDVECR_CMND_OPCD,
	 MV_N25Q_WRVECR_CMND_OPCD,
	 MV_N25Q_EN4BADDR_CMND_OPCD,
	 MV_N25Q_EX4BADDR_CMND_OPCD,
	 MV_N25Q_BUSY_FLAG_BIT,
	 0,
	 0,
	 MV_N25Q128_PAGE_SIZE,
	 MV_N25Q128_SECTOR_NUMBER,
	 MV_N25Q128_SECTOR_SIZE,
	 "NUMONYX N25Q128",
	 MV_N25Q128B_MANF_ID,
	 MV_N25Q128B_DEVICE_ID,
	 0xff,
	 0xff,
	 0xff,
	 MV_N25Q128_MAX_SPI_FREQ,
	 MV_N25Q128_MAX_FAST_SPI_FREQ,
	 MV_N25Q128_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},

	/* NUMONYX N25Q256 SPI flash, 32MB, 256 sectors of 64K each */
	{
	 MV_N25Q_WREN_CMND_OPCD,
	 MV_N25Q_WRDI_CMND_OPCD,
	 MV_N25Q_RDID_CMND_OPCD,
	 MV_N25Q_RDSR_CMND_OPCD,
	 MV_N25Q_WRSR_CMND_OPCD,
	 MV_N25Q_READ_CMND_OPCD,
	 MV_N25Q_FAST_RD_CMND_OPCD,
	 MV_N25Q_PP_CMND_OPCD,
	 MV_N25Q_SSE_CMND_OPCD,
	 MV_N25Q_SE_CMND_OPCD,
	 MV_N25Q_BE_CMND_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 MV_N25Q_RDVECR_CMND_OPCD,
	 MV_N25Q_WRVECR_CMND_OPCD,
	 MV_N25Q_EN4BADDR_CMND_OPCD,
	 MV_N25Q_EX4BADDR_CMND_OPCD,
	 MV_N25Q_BUSY_FLAG_BIT,
	 0,
	 0,
	 MV_N25Q256_PAGE_SIZE,
	 MV_N25Q256_SECTOR_NUMBER,
	 MV_N25Q256_SECTOR_SIZE,
	 "NUMONYX N25Q256",
	 MV_N25Q256_MANF_ID,
	 MV_N25Q256_DEVICE_ID,
	 0xff,
	 0xff,
	 0xff,
	 MV_N25Q256_MAX_SPI_FREQ,
	 MV_N25Q256_MAX_FAST_SPI_FREQ,
	 MV_N25Q256_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},
	/* ST M25P80 SPI flash, 1MB, 16 sectors of 64K each */
	{
	 MV_M25P_WREN_CMND_OPCD,
	 MV_M25P_WRDI_CMND_OPCD,
	 MV_M25P_RDID_CMND_OPCD,
	 MV_M25P_RDSR_CMND_OPCD,
	 MV_M25P_WRSR_CMND_OPCD,
	 MV_M25P_READ_CMND_OPCD,
	 MV_M25P_FAST_RD_CMND_OPCD,
	 MV_M25P_PP_CMND_OPCD,
	 MV_M25P_SSE_CMND_OPCD,
	 MV_M25P_SE_CMND_OPCD,
	 MV_M25P_BE_CMND_OPCD,
	 MV_M25P_RES_CMND_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD, 	/* power save not supported */
	 MV_SFLASH_UNKOWN_OPCD, 	/* next code need see datasheet */
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 0,
	 0,
	 MV_M25P_PAGE_SIZE,
	 MV_M25P80_SECTOR_NUMBER,
	 MV_M25P80_SECTOR_SIZE,
	 "ST M25P80",
	 MV_M25PXXX_ST_MANF_ID,
	 MV_M25P80_DEVICE_ID,
	 0xff,
	 0xff,
	 0xff,
	 MV_M25P80_MAX_SPI_FREQ,
	 MV_M25P80_MAX_FAST_SPI_FREQ,
	 MV_M25P80_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},
	/* ST M25P32 SPI flash, 4MB, 64 sectors of 64K each */
	{
	 MV_M25P_WREN_CMND_OPCD,
	 MV_M25P_WRDI_CMND_OPCD,
	 MV_M25P_RDID_CMND_OPCD,
	 MV_M25P_RDSR_CMND_OPCD,
	 MV_M25P_WRSR_CMND_OPCD,
	 MV_M25P_READ_CMND_OPCD,
	 MV_M25P_FAST_RD_CMND_OPCD,
	 MV_M25P_PP_CMND_OPCD,
	 MV_M25P_SSE_CMND_OPCD,
	 MV_M25P_SE_CMND_OPCD,
	 MV_M25P_BE_CMND_OPCD,
	 MV_M25P_RES_CMND_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD, 	/* power save not supported */
	 MV_SFLASH_UNKOWN_OPCD, 	/* next code need see datasheet */
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 0,
	 0,
	 MV_M25P_PAGE_SIZE,
	 MV_M25P32_SECTOR_NUMBER,
	 MV_M25P32_SECTOR_SIZE,
	 "ST M25P32",
	 MV_M25PXXX_ST_MANF_ID,
	 MV_M25P32_DEVICE_ID,
	 0xff,
	 0xff,
	 0xff,
	 MV_M25P32_MAX_SPI_FREQ,
	 MV_M25P32_MAX_FAST_SPI_FREQ,
	 MV_M25P32_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},

	/* ST M25P64 SPI flash, 8MB, 128 sectors of 64K each */
	{
	 MV_M25P_WREN_CMND_OPCD,
	 MV_M25P_WRDI_CMND_OPCD,
	 MV_M25P_RDID_CMND_OPCD,
	 MV_M25P_RDSR_CMND_OPCD,
	 MV_M25P_WRSR_CMND_OPCD,
	 MV_M25P_READ_CMND_OPCD,
	 MV_M25P_FAST_RD_CMND_OPCD,
	 MV_M25P_PP_CMND_OPCD,
	 MV_M25P_SSE_CMND_OPCD,
	 MV_M25P_SE_CMND_OPCD,
	 MV_M25P_BE_CMND_OPCD,
	 MV_M25P_RES_CMND_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD, 	/* power save not supported */
	 MV_SFLASH_UNKOWN_OPCD, 	/* next code need see datasheet */
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 0,
	 0,
	 MV_M25P_PAGE_SIZE,
	 MV_M25P64_SECTOR_NUMBER,
	 MV_M25P64_SECTOR_SIZE,
	 "ST M25P64",
	 MV_M25PXXX_ST_MANF_ID,
	 MV_M25P64_DEVICE_ID,
	 0xff,
	 0xff,
	 0xff,
	 MV_M25P64_MAX_SPI_FREQ,
	 MV_M25P64_MAX_FAST_SPI_FREQ,
	 MV_M25P64_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},
	/* ST M25P128 SPI flash, 16MB, 64 sectors of 256K each */
	{
	 MV_M25P_WREN_CMND_OPCD,
	 MV_M25P_WRDI_CMND_OPCD,
	 MV_M25P_RDID_CMND_OPCD,
	 MV_M25P_RDSR_CMND_OPCD,
	 MV_M25P_WRSR_CMND_OPCD,
	 MV_M25P_READ_CMND_OPCD,
	 MV_M25P_FAST_RD_CMND_OPCD,
	 MV_M25P_PP_CMND_OPCD,
	 MV_M25P_SSE_CMND_OPCD,
	 MV_M25P_SE_CMND_OPCD,
	 MV_M25P_BE_CMND_OPCD,
	 MV_M25P_RES_CMND_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD, 	/* power save not supported */
	 MV_SFLASH_UNKOWN_OPCD, 	/* next code need see datasheet */
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 0,
	 0,
	 MV_M25P_PAGE_SIZE,
	 MV_M25P128_SECTOR_NUMBER,
	 MV_M25P128_SECTOR_SIZE,
	 "ST M25P128",
	 MV_M25PXXX_ST_MANF_ID,
	 MV_M25P128_DEVICE_ID,
	 0xff,
	 0xff,
	 0xff,
	 MV_M25P128_MAX_SPI_FREQ,
	 MV_M25P128_MAX_FAST_SPI_FREQ,
	 MV_M25P128_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},
	/* Macronix MXIC MX25L6405 SPI flash, 8MB, 128 sectors of 64K each */
	{
	 MV_MX25L_WREN_CMND_OPCD,
	 MV_MX25L_WRDI_CMND_OPCD,
	 MV_MX25L_RDID_CMND_OPCD,
	 MV_MX25L_RDSR_CMND_OPCD,
	 MV_MX25L_WRSR_CMND_OPCD,
	 MV_MX25L_READ_CMND_OPCD,
	 MV_MX25L_FAST_RD_CMND_OPCD,
	 MV_MX25L_PP_CMND_OPCD,
	 MV_MX25L_SSE_CMND_OPCD,
	 MV_MX25L_SE_CMND_OPCD,
	 MV_MX25L_BE_CMND_OPCD,
	 MV_MX25L_RES_CMND_OPCD,
	 MV_MX25L_DP_CMND_OPCD,
	 MV_SFLASH_UNKOWN_OPCD, 	/* next code need see datasheet */
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 0,
	 0,
	 MV_MXIC_PAGE_SIZE,
	 MV_MX25L6405_SECTOR_NUMBER,
	 MV_MX25L6405_SECTOR_SIZE,
	 "MXIC MX25L6405",
	 MV_MXIC_MANF_ID,
	 MV_MX25L6405_DEVICE_ID,
	 0xff,
	 0xff,
	 0xff,
	 MV_MX25L6405_MAX_SPI_FREQ,
	 MV_MX25L6405_MAX_FAST_SPI_FREQ,
	 MV_MX25L6405_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},
	/* Macronix MXIC MX25L1606E SPI flash, 2MB, 32 sectors of 64K each */
	{
	 MV_MX25L_WREN_CMND_OPCD,
	 MV_MX25L_WRDI_CMND_OPCD,
	 MV_MX25L_RDID_CMND_OPCD,
	 MV_MX25L_RDSR_CMND_OPCD,
	 MV_MX25L_WRSR_CMND_OPCD,
	 MV_MX25L_READ_CMND_OPCD,
	 MV_MX25L_FAST_RD_CMND_OPCD,
	 MV_MX25L_PP_CMND_OPCD,
	 MV_MX25L_SSE_CMND_OPCD,
	 MV_MX25L_SE_CMND_OPCD,
	 MV_MX25L_BE_CMND_OPCD,
	 MV_MX25L_RES_CMND_OPCD,
	 MV_MX25L_DP_CMND_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD, 	/* can't support next 5 code */
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 0,
	 0,
	 MV_MXIC_PAGE_SIZE,
	 MV_MX25L1606E_SECTOR_NUMBER,
	 MV_MX25L1606E_SECTOR_SIZE,
	 "MXIC MX25L1606E",
	 MV_MXIC_MANF_ID,
	 MV_MX25L1606E_DEVICE_ID,
	 0xff,
	 0xff,
	 0xff,
	 MV_MX25L1606E_MAX_SPI_FREQ,
	 MV_MX25L1606E_MAX_FAST_SPI_FREQ,
	 MV_MX25L1606E_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},
	/* Macronix MXIC MX25U12835F SPI flash, 16MB, 255 sectors of 64K each */
	{
	 MV_MX25U12835F_WREN_CMND_OPCD,
	 MV_MX25U12835F_WRDI_CMND_OPCD,
	 MV_MX25U12835F_RDID_CMND_OPCD,
	 MV_MX25U12835F_RDSR_CMND_OPCD,
	 MV_MX25U12835F_WRSR_CMND_OPCD,
	 MV_MX25U12835F_READ_CMND_OPCD,
	 MV_MX25U12835F_FAST_RD_CMND_OPCD,
	 MV_MX25U12835F_PP_CMND_OPCD,
	 MV_MX25U12835F_SSE_CMND_OPCD,
	 MV_MX25U12835F_SE_CMND_OPCD,
	 MV_MX25U12835F_BE_CMND_OPCD,
	 MV_MX25U12835F_RES_CMND_OPCD,
	 MV_MX25U12835F_DP_CMND_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD, 	/* can't support next 5 code */
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD,
	 0,
	 0,
	 MV_MX25U12835F_PAGE_SIZE,
	 MV_MX25U12835F_SECTOR_NUMBER,
	 MV_MX25U12835F_SECTOR_SIZE,
	 "MXIC MX25U12835F",
	 MV_MX25U12835F_MANF_ID,
	 MV_MX25U12835F_DEVICE_ID,
	 0xff,
	 0xff,
	 0xff,
	 MV_MX25U12835F_MAX_SPI_FREQ,
	 MV_MX25U12835F_MAX_FAST_SPI_FREQ,
	 MV_MX25U12835F_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},
	/* SPANSION S25FL128P SPI flash, 16MB, 64 sectors of 256K each */
	{
	 MV_S25FL_WREN_CMND_OPCD,
	 MV_S25FL_WRDI_CMND_OPCD,
	 MV_S25FL_RDID_CMND_OPCD,
	 MV_S25FL_RDSR_CMND_OPCD,
	 MV_S25FL_WRSR_CMND_OPCD,
	 MV_S25FL_READ_CMND_OPCD,
	 MV_S25FL_FAST_RD_CMND_OPCD,
	 MV_S25FL_PP_CMND_OPCD,
	 MV_S25FL_SSE_CMND_OPCD,
	 MV_S25FL_SE_CMND_OPCD,
	 MV_S25FL_BE_CMND_OPCD,
	 MV_S25FL_RES_CMND_OPCD,
	 MV_S25FL_DP_CMND_OPCD,
	 MV_SFLASH_UNKOWN_OPCD, 	/* next code need see datasheet */
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 0,
	 0,
	 MV_S25FL_PAGE_SIZE,
	 MV_S25FL128_SECTOR_NUMBER,
	 MV_S25FL128_SECTOR_SIZE,
	 "SPANSION S25FL128",
	 MV_SPANSION_MANF_ID,
	 MV_S25FL128_DEVICE_ID,
	 0xff,
	 0xff,
	 0x80,
	 MV_S25FL128_MAX_SPI_FREQ,
	 MV_M25P128_MAX_FAST_SPI_FREQ,
	 MV_M25P128_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},
	/* SPANSION S25FS128S SPI flash, 16MB, 255 sectors of 64K each + */
	{
	 MV_S25FL_WREN_CMND_OPCD,
	 MV_S25FL_WRDI_CMND_OPCD,
	 MV_S25FL_RDID_CMND_OPCD,
	 MV_S25FL_RDSR_CMND_OPCD,
	 MV_S25FL_WRSR_CMND_OPCD,
	 MV_S25FL_READ_CMND_OPCD,
	 MV_S25FL_FAST_RD_CMND_OPCD,
	 MV_S25FL_PP_CMND_OPCD,
	 MV_S25FL_SSE_CMND_OPCD,
	 MV_S25FL_SE_CMND_OPCD,
	 MV_S25FL_BE_CMND_OPCD,
	 MV_S25FL_RES_CMND_OPCD,
	 MV_S25FL_DP_CMND_OPCD,
	 MV_SFLASH_UNKOWN_OPCD, 	/* next code need see datasheet */
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 0,
	 0,
	 MV_S25FL_PAGE_SIZE,
	 MV_S25FL128_SECTOR_NUMBER,
	 MV_S25FL128_SECTOR_SIZE,
	 "SPANSION S25FS128",
	 MV_SPANSION_MANF_ID,
	 MV_S25FL128_DEVICE_ID,
	 0xff,
	 0xff,
	 0x81,
	 MV_S25FL128_MAX_SPI_FREQ,
	 MV_M25P128_MAX_FAST_SPI_FREQ,
	 MV_M25P128_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},
	/* ATMEL AT25DF641 SPI flash, 8MB, 128 sectors of 64K each */
	{
	 MV_AT25DF_WREN_CMND_OPCD,
	 MV_AT25DF_WRDI_CMND_OPCD,
	 MV_AT25DF_RDID_CMND_OPCD,
	 MV_AT25DF_RDSR_CMND_OPCD,
	 MV_AT25DF_WRSR_CMND_OPCD,
	 MV_AT25DF_READ_CMND_OPCD,
	 MV_AT25DF_FAST_RD_CMND_OPCD,
	 MV_AT25DF_PP_CMND_OPCD,
	 MV_AT25DF_SSE_CMND_OPCD,
	 MV_AT25DF_SE_CMND_OPCD,
	 MV_AT25DF_BE_CMND_OPCD,
	 MV_AT25DF_RES_CMND_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD, 	/* power save not supported */
	 MV_SFLASH_UNKOWN_OPCD, 	/* next code need see datasheet */
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 0,
	 0,
	 MV_AT25DF_PAGE_SIZE,
	 MV_AT25DF641_SECTOR_NUMBER,
	 MV_AT25DF641_SECTOR_SIZE,
	 "AT 25DF641",
	 MV_AT25DFXXX_AT_MANF_ID,
	 MV_AT25DF641_DEVICE_ID,
	 0xff,
	 0xff,
	 0xff,
	 MV_AT25DF641_MAX_SPI_FREQ,
	 MV_AT25DF641_MAX_FAST_SPI_FREQ,
	 MV_AT25DF641_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},

	/* new add , M25P */
	{
	 MV_M25P_WREN_CMND_OPCD,
	 MV_M25P_WRDI_CMND_OPCD,
	 MV_M25P_RDID_CMND_OPCD,
	 MV_M25P_RDSR_CMND_OPCD,
	 MV_M25P_WRSR_CMND_OPCD,
	 MV_M25P_READ_CMND_OPCD,
	 MV_M25P_FAST_RD_CMND_OPCD,
	 MV_M25P_PP_CMND_OPCD,
	 MV_M25P_SSE_CMND_OPCD,
	 MV_M25P_SE_CMND_OPCD,
	 MV_M25P_BE_CMND_OPCD,
	 MV_M25P_RES_CMND_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD, 	/* power save not supported */
	 MV_SFLASH_UNKOWN_OPCD, 	/* next code need see datasheet */
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 0,
	 0,
	 MV_M25P_PAGE_SIZE,
	 MV_M25P32_SECTOR_NUMBER,
	 MV_M25P32_SECTOR_SIZE,
	 "ST_M25PXXX",
	 MV_M25PXXX_ST_MANF_ID,
	 0xffff,
	 0xff,
	 0xff,
	 0xff,
	 MV_M25P32_MAX_SPI_FREQ,
	 MV_M25P32_MAX_FAST_SPI_FREQ,
	 MV_M25P32_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},

	/*  new add , M25L */
	{
	 MV_MX25L_WREN_CMND_OPCD,
	 MV_MX25L_WRDI_CMND_OPCD,
	 MV_MX25L_RDID_CMND_OPCD,
	 MV_MX25L_RDSR_CMND_OPCD,
	 MV_MX25L_WRSR_CMND_OPCD,
	 MV_MX25L_READ_CMND_OPCD,
	 MV_MX25L_FAST_RD_CMND_OPCD,
	 MV_MX25L_PP_CMND_OPCD,
	 MV_MX25L_SSE_CMND_OPCD,
	 MV_MX25L_SE_CMND_OPCD,
	 MV_MX25L_BE_CMND_OPCD,
	 MV_MX25L_RES_CMND_OPCD,
	 MV_MX25L_DP_CMND_OPCD,
	 MV_SFLASH_UNKOWN_OPCD, 	/* next code need see datasheet */
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 0,
	 0,
	 MV_MXIC_PAGE_SIZE,
	 MV_MX25L6405_SECTOR_NUMBER,
	 MV_MX25L6405_SECTOR_SIZE,
	 "MXIC MX25LXXX",
	 MV_MXIC_MANF_ID,
	 0xffff,
	 0xff,
	 0xff,
	 0xff,
	 MV_MX25L6405_MAX_SPI_FREQ,
	 MV_MX25L6405_MAX_FAST_SPI_FREQ,
	 MV_MX25L6405_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},
	/* new add , M25FL */
	{
	 MV_S25FL_WREN_CMND_OPCD,
	 MV_S25FL_WRDI_CMND_OPCD,
	 MV_S25FL_RDID_CMND_OPCD,
	 MV_S25FL_RDSR_CMND_OPCD,
	 MV_S25FL_WRSR_CMND_OPCD,
	 MV_S25FL_READ_CMND_OPCD,
	 MV_S25FL_FAST_RD_CMND_OPCD,
	 MV_S25FL_PP_CMND_OPCD,
	 MV_S25FL_SSE_CMND_OPCD,
	 MV_S25FL_SE_CMND_OPCD,
	 MV_S25FL_BE_CMND_OPCD,
	 MV_S25FL_RES_CMND_OPCD,
	 MV_S25FL_DP_CMND_OPCD,
	 MV_SFLASH_UNKOWN_OPCD, 	/* next code need see datasheet */
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 0,
	 0,
	 MV_S25FL_PAGE_SIZE,
	 MV_S25FL128_SECTOR_NUMBER,
	 MV_S25FL128_SECTOR_SIZE,
	 "SPANSION S25FLXXX",
	 MV_SPANSION_MANF_ID,
	 0xffff,
	 0xff,
	 0xff,
	 0xff,
	 MV_S25FL128_MAX_SPI_FREQ,
	 MV_M25P128_MAX_FAST_SPI_FREQ,
	 MV_M25P128_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF},
	/* new add , ATMEL */
	{
	 MV_AT25DF_WREN_CMND_OPCD,
	 MV_AT25DF_WRDI_CMND_OPCD,
	 MV_AT25DF_RDID_CMND_OPCD,
	 MV_AT25DF_RDSR_CMND_OPCD,
	 MV_AT25DF_WRSR_CMND_OPCD,
	 MV_AT25DF_READ_CMND_OPCD,
	 MV_AT25DF_FAST_RD_CMND_OPCD,
	 MV_AT25DF_PP_CMND_OPCD,
	 MV_AT25DF_SSE_CMND_OPCD,
	 MV_AT25DF_SE_CMND_OPCD,
	 MV_AT25DF_BE_CMND_OPCD,
	 MV_AT25DF_RES_CMND_OPCD,
	 MV_SFLASH_NO_SPECIFIC_OPCD, 	/* power save not supported */
	 MV_SFLASH_UNKOWN_OPCD, 	/* next code need see datasheet */
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 MV_SFLASH_UNKOWN_OPCD,
	 0,
	 0,
	 MV_AT25DF_PAGE_SIZE,
	 MV_AT25DF641_SECTOR_NUMBER,
	 MV_AT25DF641_SECTOR_SIZE,
	 "AT 25DFXX",
	 MV_AT25DFXXX_AT_MANF_ID,
	 0xffff,
	 0xff,
	 0xff,
	 0xff,
	 MV_AT25DF641_MAX_SPI_FREQ,
	 MV_AT25DF641_MAX_FAST_SPI_FREQ,
	 MV_AT25DF641_FAST_READ_DUMMY_BYTES,
	 SPI_FLASH_3BYTE_ADDR,
	 STANDARD_SPI_IF}
};

u32 SFC_RegisterRead(u64 reg_addr)
{
	u32 ulResult;

	ulResult = *(__iomem u32 *) (reg_addr);

	return HRD_32BIT_LE(ulResult);
}

void SFC_RegisterWrite(u64 reg_addr, u32 ulValue)
{
	*(__iomem u32 *) (reg_addr) = HRD_32BIT_LE(ulValue);
}

s32 SFC_ClearInt(u64 reg_addr)
{
	u32 IntStatus;
	IntStatus = SFC_RegisterRead(reg_addr + (u32) INTRAWSTATUS);

	if ((0 != (IntStatus & INT_MASK))) {
		pr_err("[%s %d]: Int status=%u not cleared, clear\r\n",
			   __func__, __LINE__, IntStatus);
		SFC_RegisterWrite(reg_addr + INTCLEAR, INT_MASK);
	}

	return 0;
}

s32 SFC_WaitInt(u64 reg_addr)
{
	u32 ulRegValue;
	u32 ulCount = 0;

	ulRegValue = SFC_RegisterRead(reg_addr + (u32) INTRAWSTATUS);

	while (((CMD_OP_END_INT_BIT != (ulRegValue & CMD_OP_END_INT_BIT)))
		   && (ulCount < WAIT_MAX_COUNT)) {

		udelay((unsigned long)1);

		ulRegValue = SFC_RegisterRead(reg_addr + INTRAWSTATUS);
		ulCount++;
	}

	if (ulCount >= WAIT_MAX_COUNT) {
		pr_err("[%s %d]: time out\n", __func__, __LINE__);
		return WAIT_TIME_OUT;
	}

	SFC_RegisterWrite(reg_addr + INTCLEAR, CMD_OP_END_INT_BIT);

	return HRD_OK;
}

s32 SFC_WriteEnable(struct SFC_SFLASH_INFO *sflash)
{
	u32 ulRegValue;
	s32 ulRet;

	(void)SFC_ClearInt(sflash->sfc_reg_base);

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
			  sflash->sflash_dev_params.ucOpcodeWREN);

	/* set interface support */

	/* set configure reg and startup */
	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &= (~(1 << ADDR_EN)) & (~(1 << DATA_EN)) & (~(1 << SEL_CS));
	ulRegValue |=
		(1 << LOCK_FLASH) | (SFC_CHIP_CS << SEL_CS) | (1 << START);

	wmb();

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);

	/* wait operate end */
	ulRet = SFC_WaitInt(sflash->sfc_reg_base);

	if (HRD_OK != ulRet) {
		return ulRet;
	}

	return HRD_OK;
}

s32 SFC_FlashUnlock(struct SFC_SFLASH_INFO *sflash)
{
	u32 ulRegValue;

	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &= (~(1 << LOCK_FLASH));
	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);

	return HRD_OK;
}

u32 SFC_ReadStatus(struct SFC_SFLASH_INFO *sflash)
{
	u32 ulRegValue;
	s32 ulRet;

	(void)SFC_ClearInt(sflash->sfc_reg_base);

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
			  sflash->sflash_dev_params.ucOpcodeRDSR);

	/* set configure reg and startup */
	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);

	ulRegValue &=
		(~(0xff << DATA_CNT)) & (~(1 << RW_DATA)) & (~(1 << SEL_CS));
	ulRegValue |= (3 << DATA_CNT) | (1 << RW_DATA) | (1 << DATA_EN)
		| (SFC_CHIP_CS << SEL_CS) | (0x1 << START);

	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);

	ulRet = SFC_WaitInt(sflash->sfc_reg_base);

	if (HRD_OK != ulRet) {
		return WAIT_TIME_OUT;
	}

	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + DATABUFFER1);

	ulRegValue = ulRegValue & 0xff;

	return ulRegValue;
}

s32 SFC_CheckBusy(struct SFC_SFLASH_INFO *sflash, u32 ulTimeOut)
{
	u32 ulRegValue;
	u32 ulWaitCount = 0;

	ulRegValue = SFC_ReadStatus(sflash);

	if (WAIT_TIME_OUT == ulRegValue) {
		pr_err("[%s %d]: SFC_ReadStatus time out\n", __func__,
			   __LINE__);
		return HRD_ERR;
	}

	while ((STATUS_REG_BUSY_BIT == (ulRegValue & STATUS_REG_BUSY_BIT))
		   && (ulWaitCount < ulTimeOut)) {
		udelay((unsigned long)1);

		ulRegValue = SFC_ReadStatus(sflash);

		if (WAIT_TIME_OUT == ulRegValue) {
			pr_err("[%s %d]: SFC_ReadStatus time out\n",
				   __func__, __LINE__);
			return HRD_ERR;
		}

		if ((sflash->manufacturerId == MV_SPANSION_MANF_ID)
			&& (ulRegValue & (STATUS_REG_P_ERR | STATUS_REG_E_ERR))) {
			pr_err
				("[%s %d]: program err or erase err, status = %08x\n",
				 __func__, __LINE__, ulRegValue);
			return HRD_ERR;
		}

		ulWaitCount++;

		if ((ulWaitCount > 0) && (ulWaitCount % 1000 == 0)) {
			msleep(1);
		}
	}

	if (ulWaitCount >= ulTimeOut) {
		pr_err("[%s %d]: SFC_CheckBusy time out\n", __func__, __LINE__);
		return WAIT_TIME_OUT;
	}

	return HRD_OK;
}

s32 SFC_ClearStatus(struct SFC_SFLASH_INFO *sflash)
{
	u32 ulRegValue = 0;
	s32 ulRet = HRD_ERR;

	(void)SFC_ClearInt(sflash->sfc_reg_base);

	if (sflash->manufacturerId == MV_SPANSION_MANF_ID) {

		/* 30 for spansion , clear status */
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, 0x30);

		/* set interface support */

		/* set configure reg and startup */
		ulRegValue =
			SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);

		ulRegValue &=
			(~(1 << ADDR_EN)) & (~(1 << DATA_EN)) & (~(1 << SEL_CS));
		ulRegValue |= (SFC_CHIP_CS << SEL_CS | 1 << START);

		wmb();

		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG,
				  ulRegValue);

		/* wait operate end */
		ulRet = SFC_WaitInt(sflash->sfc_reg_base);

		if (HRD_OK != ulRet) {
			return ulRet;
		}
	}

	return HRD_OK;
}

s32 SFC_CheckErr(struct SFC_SFLASH_INFO *sflash)
{
	u32 ulRegValue = 0;

	if (sflash->manufacturerId == MV_SPANSION_MANF_ID) {

		ulRegValue = SFC_ReadStatus(sflash);

		if (WAIT_TIME_OUT == ulRegValue) {
			pr_err("[%s %d]: SFC_ReadStatus time out\n", __func__,
				   __LINE__);
			return HRD_ERR;
		}

		udelay((unsigned long)50);

		if (ulRegValue & (STATUS_REG_P_ERR | STATUS_REG_E_ERR)) {
			pr_err
				("[%s %d]: program err or erase err, status = %08x\n",
				 __func__, __LINE__, ulRegValue);

			if (HRD_OK != SFC_ClearStatus(sflash)) {
				pr_err("[%s %d]: clear status failed\r\n",
					   __func__, __LINE__);
				return HRD_ERR;
			} else {
				udelay((unsigned long)50);
			}
		}
	} else {
		return HRD_OK;
	}

	return HRD_OK;
}

s32 SFC_ControllerAddrModeSet(struct SFC_SFLASH_INFO *sflash)
{
	u32 ulTemp;

	ulTemp = SFC_RegisterRead(sflash->sfc_reg_base + GLOBAL_CONFIG);

	if (SPI_FLASH_3BYTE_ADDR == sflash->addr_mode) {
		/* set 3Byte addr mode */
		ulTemp &= ~(1 << API_ADDR_MODE);
	} else if (SPI_FLASH_4BYTE_ADDR == sflash->addr_mode) {
		/* set 4Byte addr mode */
		ulTemp |= (1 << API_ADDR_MODE);
	} else {
		pr_err("[%s %d]: ulMode(%d) is invalid\n", __func__,
			   __LINE__, sflash->addr_mode);
		return HRD_COMMON_ERR_INPUT_INVALID;
	}

	SFC_RegisterWrite(sflash->sfc_reg_base + GLOBAL_CONFIG, ulTemp);

	return HRD_OK;
}

s32 SFC_BlockErase(struct SFC_SFLASH_INFO *sflash, u32 ulAddr, u32 ErCmd)
{
	u32 ulRegValue;
	s32 ulRet;

	SFC_CheckErr(sflash);
	ulRet = SFC_WriteEnable(sflash);

	if (HRD_OK != ulRet) {
		pr_err("[%s %d]: SFC_WriteEnable fail\n", __func__, __LINE__);
		goto rel;
	}

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
			  ErCmd ? ErCmd : sflash->sflash_dev_params.ucOpcodeSE);
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_ADDR, ulAddr);

	/* set configure reg and startup */
	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &= (~(1 << DATA_EN) & (~(1 << SEL_CS)));
	ulRegValue |= ((SFC_CHIP_CS << SEL_CS) | (1 << START) | (1 << ADDR_EN));

	wmb();

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);

	ulRet = SFC_WaitInt(sflash->sfc_reg_base);

	if (HRD_OK != ulRet) {
		pr_err("[%s %d]: SFC_WaitInt fail\n", __func__, __LINE__);
		goto rel;
	}

	ulRet = SFC_CheckBusy(sflash, WAIT_MAX_COUNT);

	if (HRD_OK != ulRet) {
		pr_err("[%s %d]: SFC_WaitInt fail\n", __func__, __LINE__);
		goto rel;
	}

 rel:
	SFC_FlashUnlock(sflash);
	return HRD_OK;

}

s32 SFC_RegWordRead(struct SFC_SFLASH_INFO *sflash,
			u32 ulOffsetAddr, u32 *pulData)
{
	u32 ulRegValue;
	s32 ulRet;

	(void)SFC_ClearInt(sflash->sfc_reg_base);
	SFC_CheckErr(sflash);

	/* configure INS reg,send RDDATA operate */
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
			  sflash->sflash_dev_params.ucOpcodeREAD);
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_ADDR, ulOffsetAddr);

	/* set configure reg and startup */
	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &= (~(0xff << DATA_CNT) & (~(1 << SEL_CS)));
	ulRegValue |=
		(3 << DATA_CNT) | (1 << ADDR_EN) | (1 << DATA_EN) | (1 << RW_DATA)
		| (SFC_CHIP_CS << SEL_CS) | (0x1 << START);

	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);

	ulRet = SFC_WaitInt(sflash->sfc_reg_base);

	if (HRD_OK != ulRet) {
		pr_err("[%s %d]: SFC_WaitInt fail\n", __func__, __LINE__);
		return ulRet;
	}

	*pulData = SFC_RegisterRead(sflash->sfc_reg_base + DATABUFFER1);

	return ulRet;

}

s32 SFC_RegByteRead(struct SFC_SFLASH_INFO *sflash,
			u32 ulOffsetAddr, u8 *pucData)
{
	u32 ulRegValue;
	s32 ulRet;

	(void)SFC_ClearInt(sflash->sfc_reg_base);
	SFC_CheckErr(sflash);

	/* configure INS reg,send RDDATA operate */
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
			  sflash->sflash_dev_params.ucOpcodeREAD);
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_ADDR, ulOffsetAddr);

	/* set configure reg and startup */
	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &= (~(0xff << DATA_CNT) & (~(1 << SEL_CS)));
	ulRegValue |=
		(0 << DATA_CNT) | (1 << ADDR_EN) | (1 << DATA_EN) | (1 << RW_DATA)
		| (SFC_CHIP_CS << SEL_CS) | (0x1 << START);

	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);

	ulRet = SFC_WaitInt(sflash->sfc_reg_base);

	if (HRD_OK != ulRet) {
		pr_err("[%s %d]: SFC_WaitInt fail\n", __func__, __LINE__);
		return ulRet;
	}

	*pucData = SFC_RegisterRead(sflash->sfc_reg_base + DATABUFFER1) & 0xff;

	return ulRet;
}

s32 SFC_RegWordWrite(struct SFC_SFLASH_INFO *sflash,
			 u32 ulData, u32 ulOffsetAddr)
{
	u32 ulRegValue;
	s32 ulRet = HRD_OK;
	/* u32 i = 0; */

	SFC_CheckErr(sflash);
	ulRet = SFC_WriteEnable(sflash);

	if (HRD_OK != ulRet) {
		pr_err("[%s %d]: SFC_WriteEnable fail\n", __func__, __LINE__);
		goto rel;
	}

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
			  sflash->sflash_dev_params.ucOpcodePP);
	SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1, ulData);
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_ADDR, ulOffsetAddr);

	/* set configure reg and startup */

	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &=
		(~(0xff << DATA_CNT)) & (~(1 << RW_DATA) & (~(1 << SEL_CS)));
	ulRegValue |= (3 << DATA_CNT) | (1 << ADDR_EN) | (1 << DATA_EN)
		| (SFC_CHIP_CS << SEL_CS) | (0x1 << START);

	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);

	ulRet = SFC_WaitInt(sflash->sfc_reg_base);

	if (HRD_OK != ulRet) {
		pr_err("[%s %d]: SFC_WaitInt fail\n", __func__, __LINE__);
		goto rel;
	}

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
			  sflash->sflash_dev_params.ucOpcodeRDSR);

	ulRet = SFC_CheckBusy(sflash, SFC_BUSY_WAIT_TIMEOUT);

 rel:
	SFC_FlashUnlock(sflash);
	return ulRet;

}

s32 SFC_RegByteWrite(struct SFC_SFLASH_INFO *sflash,
			 u8 ucData, u32 ulOffsetAddr)
{
	u32 ulRegValue;
	s32 ulRet = HRD_OK;

	SFC_CheckErr(sflash);
	ulRet = SFC_WriteEnable(sflash);

	if (HRD_OK != ulRet) {
		pr_err("[%s %d]: SFC_WriteEnable failed\r\n", __func__,
			   __LINE__);
		goto rel;
	}

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
			  sflash->sflash_dev_params.ucOpcodePP);
	SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1, ucData);
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_ADDR, ulOffsetAddr);

	/* set configure reg and startup */
	ulRegValue = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
	ulRegValue &=
		(~(0xff << DATA_CNT)) & (~(1 << RW_DATA)) & (~(1 << SEL_CS));
	ulRegValue |= (0 << DATA_CNT) | (1 << ADDR_EN) | (1 << DATA_EN)
		| (SFC_CHIP_CS << SEL_CS) | (0x1 << START);

	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, ulRegValue);

	ulRet = SFC_WaitInt(sflash->sfc_reg_base);

	if (HRD_OK != ulRet) {
		pr_err("[%s %d]: wait int failed\r\n", __func__, __LINE__);
		goto rel;
	}

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
			  sflash->sflash_dev_params.ucOpcodeRDSR);

	ulRet = SFC_CheckBusy(sflash, SFC_BUSY_WAIT_TIMEOUT);

 rel:
	SFC_FlashUnlock(sflash);

	return ulRet;

}

s32 SFC_RegModeWrite(struct SFC_SFLASH_INFO *sflash,
			 u32 offset, const u8 *pucSrc, u32 ulWriteLen)
{
	u32 i;
	s32 ulRet;
	u32 ulRemain;
	u32 ulAlignLen;

	/* pr_info("SFC_RegModeWrite call\n"); */

	if (!pucSrc) {
		pr_err("[%s %d]: Pointer is null\n", __func__, __LINE__);
		return HRD_COMMON_ERR_NULL_POINTER;
	}

	if (ulWriteLen > sflash->space_size) {
		pr_err("[%s %d]: ulReadLen is invalid\n", __func__, __LINE__);
		return HRD_COMMON_ERR_INPUT_INVALID;
	}

	/* reset controller adde mode, make sure different cs can work well */
	ulRet = SFC_ControllerAddrModeSet(sflash);

	if (HRD_OK != ulRet) {
		pr_err("[%s %d]: SFC_ControllerAddrModeSet fail\n",
			   __func__, __LINE__);
		return HRD_ERR;
	}

	ulRemain = ulWriteLen % 4;

	ulAlignLen = ulWriteLen - ulRemain;

	for (i = 0; i < ulAlignLen; i += 4) {
		ulRet =
			SFC_RegWordWrite(sflash,
					 *(const u32 *)(pucSrc + i), offset + i);

		if (HRD_OK != ulRet) {
			pr_err
				("[%s %d]: SFC_RegWordWrite fail\n",
				 __func__, __LINE__);
			return ulRet;
		}

		if ((i > 0) && (i % 8192 == 0)) {
			msleep(1);
		}
	}

	for (; i < ulWriteLen; i++) {
		ulRet =
			SFC_RegByteWrite(sflash,
					 *(const u8 *)(pucSrc + i), offset + i);

		if (HRD_OK != ulRet) {
			pr_err
				("[%s %d]: SFC_RegByteWrite fail\n",
				 __func__, __LINE__);
			return ulRet;
		}
	}

	return HRD_OK;
}

s32 SFC_BusModeWrite(struct SFC_SFLASH_INFO *sflash,
			 u32 offset, const u8 *pucSrc, u32 ulWriteLen)
{
	s32 ulRet;
	u32 ulRemain;
	u32 ulAlignLen;
	u32 i;
	/* pr_info("SFC_BusModeWrite call\n"); */

	if (!sflash || !pucSrc) {
		pr_err("[%s %d]: Pointer is null\n", __func__, __LINE__);
		return HRD_COMMON_ERR_NULL_POINTER;
	}

	if (ulWriteLen > sflash->space_size) {
		pr_err("[%s %d]: ulReadLen is invalid\n", __func__, __LINE__);
		return HRD_COMMON_ERR_INPUT_INVALID;
	}

	/* reset controller adde mode, make sure different cs can work well */
	ulRet = SFC_ControllerAddrModeSet(sflash);

	ulRemain = ulWriteLen % 4;
	ulAlignLen = ulWriteLen - ulRemain;

	for (i = 0; i < ulAlignLen; i += 4) {
		*(__iomem u32 *) (sflash->baseAddr + offset +
				  i) = *(const u32 *)(pucSrc + i);

		if ((i > 0) && (i % 65536 == 0)) {
			msleep(1);
			continue;
		}

	}

	for (; i < ulWriteLen; i++) {
		*(__iomem u8 *) (sflash->baseAddr + offset +
				 i) = *(const u8 *)(pucSrc + i);
	}

	return ulRet;
}

s32 SFC_RegModeRead(struct SFC_SFLASH_INFO *sflash,
			u32 offset, u8 *pucDest, u32 ulReadLen)
{
	u32 i;
	s32 ulRet;
	u32 ulRemain;
	u32 ulAlignLen;

	/* pr_info("SFC_RegModeRead call\n"); */

	if (!sflash || !pucDest) {
		pr_err("[%s %d]: Pointer is null\n", __func__, __LINE__);
		return HRD_COMMON_ERR_NULL_POINTER;
	}

	if (ulReadLen > sflash->space_size) {
		pr_err("[%s %d]: ulReadLen is invalid\n", __func__, __LINE__);
		return HRD_COMMON_ERR_INPUT_INVALID;
	}

	/* reset controller adde mode, make sure different cs can work well */
	ulRet = SFC_ControllerAddrModeSet(sflash);

	if (HRD_OK != ulRet) {
		pr_err("[%s %d]: SFC_ControllerAddrModeSet fail\n",
			   __func__, __LINE__);
		return HRD_ERR;
	}

	ulRemain = ulReadLen % 4;

	ulAlignLen = ulReadLen - ulRemain;

	for (i = 0; i < ulAlignLen; i += 4) {
		(void)SFC_RegWordRead(sflash, offset + i,
					  (u32 *) (pucDest + i));
	}

	for (; i < ulReadLen; i++) {
		(void)SFC_RegByteRead(sflash, offset + i, pucDest + i);
	}

	return HRD_OK;
}

s32 SFC_BusModeRead(struct SFC_SFLASH_INFO *sflash,
			u32 offset, u8 *pucDest, u32 ulReadLen)
{
	s32 ulRet;
	u32 i;
	u32 ulRemain;
	u32 ulAlignLen;

	/* pr_info("SFC_BusModeRead call\n"); */

	if (!sflash || !pucDest) {
		pr_err("[%s %d]: Pointer is null\n", __func__, __LINE__);
		return HRD_COMMON_ERR_NULL_POINTER;
	}

	if (ulReadLen > sflash->space_size) {
		pr_err("[%s %d]: ulReadLen is invalid\n", __func__, __LINE__);
		return HRD_COMMON_ERR_INPUT_INVALID;
	}

	/* reset controller adde mode, make sure different cs can work well */
	ulRet = SFC_ControllerAddrModeSet(sflash);
	ulRemain = ulReadLen % 4;

	ulAlignLen = ulReadLen - ulRemain;

	for (i = 0; i < ulAlignLen; i += 4) {
		*(u32 *) (pucDest + i) =
			*(__iomem u32 *) (sflash->baseAddr + offset + i);
	}

	for (; i < ulReadLen; i++) {
		*(u8 *) (pucDest + i) =
			*(__iomem u8 *) (sflash->baseAddr + offset + i);
	}

	return ulRet;
}

s32 SFC_CheckCmdExcStatus(struct SFC_SFLASH_INFO *sflash)
{
	u32 temp;
	u32 timeout = 1000;
	temp = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);

	while (temp & 1) {
		udelay((unsigned long)1);
		temp = SFC_RegisterRead(sflash->sfc_reg_base + CMD_CONFIG);
		timeout--;

		if (0 == timeout) {
			pr_err("%s (%d):Check cmd execute status time out!\n",
				   __func__, __LINE__);
			return HRD_ERR;
		}
	}

	return HRD_OK;
}

s32 SFC_SPIFlashIdGet(struct SFC_SFLASH_INFO *pFlinfo,
			  u8 *pulManuId, u16 *pulDevId, u8 *pcfi_len,
			  u8 *psec_arch, u8 *pfid)
{
	u8 ulID0;
	u16 ulID1;
	u16 ulID2;
	s32 ulRet;
	u32 ulRegValue;
	u32 readid_cmd;

	if (!pulManuId || !pulDevId) {
		pr_err("[%s %d]: input params is invalid\n", __func__,
			   __LINE__);
		return HRD_COMMON_ERR_NULL_POINTER;
	}

	(void)SFC_ClearInt(pFlinfo->sfc_reg_base);

	if (pFlinfo->index >= HI_ARRAY_SIZE(g_stSPIFlashDevTable)) {
		readid_cmd = SFLASH_DEFAULT_RDID_OPCD;
	} else {
		readid_cmd = g_stSPIFlashDevTable[pFlinfo->index].ucOpcodeRDID;
	}

	SFC_RegisterWrite(pFlinfo->sfc_reg_base + CMD_INS, readid_cmd);

	ulRegValue = SFC_RegisterRead(pFlinfo->sfc_reg_base + CMD_CONFIG);
	ulRegValue &=
		(~(0xff << DATA_CNT)) & (~(1 << RW_DATA)) & (~(1 << SEL_CS)) &
		(~(1 << ADDR_EN));
	ulRegValue |= (5 << DATA_CNT) | (1 << RW_DATA) | (1 << DATA_EN)
		| (SFC_CHIP_CS << SEL_CS) | (0x1 << START);

	wmb();
	SFC_RegisterWrite(pFlinfo->sfc_reg_base + CMD_CONFIG, ulRegValue);

	ulRet = SFC_WaitInt(pFlinfo->sfc_reg_base);

	if (HRD_OK != ulRet) {
		pr_err("[%s %d]: wait int failed\r\n", __func__, __LINE__);
		return WAIT_TIME_OUT;
	}

	ulRet = SFC_CheckCmdExcStatus(pFlinfo);

	if (ulRet) {
		pr_err("[%s %d]: cmd execute timeout\r\n", __func__, __LINE__);
		return WAIT_TIME_OUT;
	}

	ulRegValue = SFC_RegisterRead(pFlinfo->sfc_reg_base + DATABUFFER1);

	ulID0 = ulRegValue & 0xff;
	ulID1 = (ulRegValue >> 8) & 0xff;
	ulID2 = (ulRegValue >> 16) & 0xff;

	*pulManuId = ulID0;
	*pulDevId = (u16) (ulID1 << 8) | ulID2;
	*pcfi_len = (ulRegValue >> 24) & 0xff;;

	ulRegValue = SFC_RegisterRead(pFlinfo->sfc_reg_base + DATABUFFER2);
	*psec_arch = ulRegValue & 0xff;
	*pfid = (ulRegValue >> 8) & 0xff;

	pr_info
		("[%s %d]:ulManuId=0x%x, ulDevId=0x%x cfi_len=0x%x, sec_arch=0x%x, fid=0x%x\n",
		 __func__, __LINE__, *pulManuId, *pulDevId, *pcfi_len, *psec_arch,
		 *pfid);

	return HRD_OK;
}

void CPLD_WPSet(u32 val)
{
	int ret;
	u8 value;
	u32 RegAddr = CPLD_WP_REG;

	ret = lbc_read8(1, RegAddr, &value);

	if (0 != ret) {
		pr_err("[%s %d]: lbc_read8 fail\r\n", __func__, __LINE__);
		return;
	}

	if (val) {
		value &= (~BIT0);
	} else {
		value |= BIT0;
	}

	(void)lbc_write8(1, RegAddr, value);
	return;
}

int SFC_WaitFlashIdle(struct SFC_SFLASH_INFO *sflash)
{
	union UN_SFC_CMD_CONFIG temp;
	u32 temp2 = 0;
	u32 timeout = 10000;
	int ret;

	temp.u32 = 0;

	(void)SFC_ClearInt(sflash->sfc_reg_base);

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, SPI_CMD_RDSR);

	do {
		temp.bits.rw = SFC_CMD_CFG_READ;
		temp.bits.addr_en = FALSE;
		temp.bits.data_en = TRUE;
		temp.bits.data_cnt = SFC_CMD_DATA_CNT(1);
		temp.bits.sel_cs = SFC_CHIP_CS;
		temp.bits.start = TRUE;
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, temp.u32);

		ret = SFC_CheckCmdExcStatus(sflash);

		if (HRD_OK != ret) {
			pr_err("[%s %d]: cmd execute timeout\r\n", __func__,
				   __LINE__);
			return ret;
		}

		udelay((unsigned long)80);
		temp2 = SFC_RegisterRead(sflash->sfc_reg_base + DATABUFFER1);

		if (!(temp2 & SPI_CMD_SR_WIP)) {
			return HRD_OK;
		}

		udelay((unsigned long)20);
	} while (timeout--);

	pr_err("[%s %d]: Write in progress!\r\n", __func__, __LINE__);

	return HRD_ERR;
}

int SFC_GetDeviceId(struct SFC_SFLASH_INFO *sflash, u32 *id)
{
	int ret;
	union UN_SFC_CMD_CONFIG temp;

	temp.u32 = 0;

	(void)SFC_ClearInt(sflash->sfc_reg_base);

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS,
			  SFLASH_DEFAULT_RDID_OPCD);

	temp.bits.rw = SFC_CMD_CFG_READ;
	temp.bits.addr_en = FALSE;
	temp.bits.data_en = TRUE;
	temp.bits.data_cnt = SFC_CMD_DATA_CNT(1);
	temp.bits.sel_cs = SFC_CHIP_CS;
	temp.bits.start = TRUE;

	wmb();
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, temp.u32);

	ret = SFC_CheckCmdExcStatus(sflash);

	if (HRD_OK != ret) {
		pr_err("%s %d\n", __func__, __LINE__);
		return ret;
	}

	*id = SFC_RegisterRead(sflash->sfc_reg_base + DATABUFFER1);
	pr_info("%s(%d):get_device_id: 0x%x !\n", __func__, __LINE__, *id);

	return ret;
}

static void SFC_SetBusMode(struct SFC_SFLASH_INFO *sflash, BOOL val)
{
	/*shuwdown the bus mode */
	if (!val) {

		SFC_RegisterWrite(sflash->sfc_reg_base + BUS_CONFIG1,
				  0x00800300);
	} else {
		SFC_RegisterWrite(sflash->sfc_reg_base + BUS_CONFIG1,
				  0x80800300);

	}

}

static int MirconWPSet(struct SFC_SFLASH_INFO *sflash, BOOL val)
{
	int ret = HRD_OK;

	if (val) {
		SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1, 0xDC);
	} else {

		ret = SFC_WriteEnable(sflash);

		if (HRD_OK != ret) {
			pr_err("[%s %d]: SFC_WriteEnable fail\n", __func__,
				   __LINE__);
			return ret;
		}

		SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1, 0x0);
	}

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, SPI_CMD_WRR);
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, 0x81);
	udelay((unsigned long)10);

	return ret;
}

static int SpansionWPSet(struct SFC_SFLASH_INFO *sflash, BOOL val)
{
	int ret = HRD_OK;

	if (val) {

		SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1, 0x9C);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, SPI_CMD_WRR);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, 0x81);
	} else {

		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, SPI_CMD_CLSR);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, 0x1);
		udelay((unsigned long)50);

		ret = SFC_CheckCmdExcStatus(sflash);

		if (HRD_OK != ret) {
			pr_err("[%s %d]: SFC_CheckCmdExcStatus fail\n",
				   __func__, __LINE__);
			return ret;
		}

		udelay((unsigned long)50);

		ret = SFC_WaitFlashIdle(sflash);

		if (HRD_OK != ret) {
			pr_err("[%s %d]: SFC_WaitFlashIdle fail\n", __func__,
				   __LINE__);
			return ret;
		}

		udelay((unsigned long)200);
		ret = SFC_WriteEnable(sflash);

		if (HRD_OK != ret) {
			pr_err("[%s %d]: SFC_WriteEnable fail\n", __func__,
				   __LINE__);
			return ret;
		}

		udelay((unsigned long)50);
		SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1, 0);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, SPI_CMD_WRR);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, 0x81);
	}

	return ret;
}

static int MxicWPSet(struct SFC_SFLASH_INFO *sflash, BOOL val)
{
	u32 status;
	int ret = HRD_OK;

	/* status register[7:0] : bit7[SRWD], bit6[QE], bit5~bit2[BP3 ~ BP0], bit1[WEL], bit0[WIP] */

	/* read status register */
	status = SFC_ReadStatus(sflash);

	if (WAIT_TIME_OUT == status) {
		ret = HRD_ERR;
		pr_err("[%s %d]: SFC_ReadStatus time out\n", __func__,
			   __LINE__);
		return ret;
	}

	if (((status >> 1) & 0x1) != 1) {
		ret = HRD_ERR;
		pr_err("[%s %d]: Write enable fail\n", __func__, __LINE__);
		return ret;
	}

	/* config status register data */
	if (val) {

		status |= 0x3c;
		status &= (~(u32) 0x2);
		SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1, status);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, SPI_CMD_WRR);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, 0x81);
	} else {

		status = status & (~(u32) 0x3c);
		status = status & (~(u32) 0x2);
		SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1, status);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, SPI_CMD_WRR);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, 0x81);
	}

	/* read status register */
	status = SFC_ReadStatus(sflash);

	if (WAIT_TIME_OUT == status) {
		ret = HRD_ERR;
		pr_err("[%s %d]: SFC_ReadStatus time out\n", __func__,
			   __LINE__);
		return ret;
	}

	/* check status register data */
	if (((status >> 1) & 0x1) == 1) {
		ret = HRD_ERR;
		pr_err("[%s %d]: Value of write enable latch bit error\n",
			   __func__, __LINE__);
		return ret;
	}

	if (val) {
		if (((status >> 2) & 0xF) != 0xF) {
			ret = HRD_ERR;
			pr_err("[%s %d]: Set to protect all blocks failed\n",
				   __func__, __LINE__);
			return ret;
		}
	} else {
		if (((status >> 2) & 0xF) != 0x0) {
			ret = HRD_ERR;
			pr_err
				("[%s %d]: Set to not protect any blocks failed\n",
				 __func__, __LINE__);
			return ret;
		}
	}

	return ret;
}

#define retval_if_fail(ret, str) 		\
	do {	 						\
		if (ret != HRD_OK) { 		\
			pr_err(str);			\
			return ret; }			\
	} while (0)

int SFC_WPSet(struct SFC_SFLASH_INFO *sflash, BOOL val)
{
	u32 device_id;
	int ret;
	bool isFlashLock = false;

	SFC_SetBusMode(sflash, val);

	udelay((unsigned long)1000);

	(void)SFC_ClearInt(sflash->sfc_reg_base);

	(void)SFC_CheckErr(sflash);

	/* First try to read the Manufacturer and Device IDs */
	ret = SFC_GetDeviceId(sflash, &device_id);
	retval_if_fail(ret, "Failed to get the SFlash ID!\n");

	udelay((unsigned long)100);
	CPLD_WPSet((unsigned int)0);
	udelay((unsigned long)20);

	ret = SFC_WaitFlashIdle(sflash);

	if (HRD_OK != ret) {
		pr_err("[%s %d]: SFC_WaitFlashIdle fail\n", __func__, __LINE__);
		goto error;
	}

	ret = SFC_WriteEnable(sflash);
	isFlashLock = true;

	if (HRD_OK != ret) {
		pr_err("[%s %d]: SFC_WriteEnable fail\n", __func__, __LINE__);
		goto error;
	}

	if (MV_M25PXXX_ST_MANF_ID == (u8) (device_id)) {
		ret = MirconWPSet(sflash, val);

		if (HRD_OK != ret) {
			goto error;
		}
	} else if (MV_SPANSION_MANF_ID == (u8) (device_id)) {
		ret = SpansionWPSet(sflash, val);

		if (HRD_OK != ret) {
			goto error;
		}
	} else if (MV_MX25U12835F_MANF_ID == (u8) (device_id)) {
		ret = MxicWPSet(sflash, val);

		if (HRD_OK != ret) {
			goto error;
		}
	} else {
		pr_err("[%s %d]: not support devid=0x%08x\n", __func__,
			   __LINE__, device_id);
		ret = HRD_ERR;
		goto error;
	}

	udelay((unsigned long)10);

	ret = SFC_CheckCmdExcStatus(sflash);

	if (HRD_OK != ret) {
		pr_err("[%s %d]: SFC_CheckCmdExcStatus fail\n", __func__,
			   __LINE__);
		goto error;
	}

	ret = SFC_WaitFlashIdle(sflash);

	if (HRD_OK != ret) {
		pr_err("[%s %d]: SFC_WaitFlashIdle fail\n", __func__, __LINE__);
		goto error;
	}

	if (TRUE == val) {
		CPLD_WPSet(val);
	}

	SFC_FlashUnlock(sflash);
	return ret;

 error:
	CPLD_WPSet(TRUE);
	/*enable bus mode write */

	SFC_SetBusMode(sflash, 1);

	if (isFlashLock) {
		SFC_FlashUnlock(sflash);
	}

	return ret;
}

u32 SFC_ControllerInit(u64 sfc_reg_base)
{
	u32 ulRegValue;
	/* use default 128Mbit SPI FLASH large */
	u32 ulSFlashSizeIndex = 0x09;

	ulRegValue = SFC_RegisterRead(sfc_reg_base + (u32) BUS_FLASH_SIZE);
	ulRegValue &= (~((u32) 0xf << FLASH_SIZE_CS_BIT(SFC_CHIP_CS)));
	ulRegValue |= (ulSFlashSizeIndex << FLASH_SIZE_CS_BIT(SFC_CHIP_CS));
	SFC_RegisterWrite(sfc_reg_base + (u32) BUS_FLASH_SIZE, ulRegValue);

	ulRegValue = SFC_RegisterRead(sfc_reg_base + BUS_CONFIG1);
	ulRegValue &= ~(1 << WR_ENABLE);
	SFC_RegisterWrite(sfc_reg_base + BUS_CONFIG1, ulRegValue);

	return HRD_OK;
}

#define CMPEXTERNID(indx, cfi_len, sec_arch, fid) \
(((g_stSPIFlashDevTable[indx].ulIdCFILen != 0xff) ? (g_stSPIFlashDevTable[indx].ulIdCFILen == cfi_len) : 1) && \
((g_stSPIFlashDevTable[indx].ulPhySecArch != 0xff) ? (g_stSPIFlashDevTable[indx].ulPhySecArch == sec_arch) : 1) && \
((g_stSPIFlashDevTable[indx].ulFId != 0xff) ? (g_stSPIFlashDevTable[indx].ulFId == fid) : 1))

int hrd_sflash_init(struct SFC_SFLASH_INFO *pFlinfo)
{
	int ret;
	u8 manf;
	u16 dev;
	u8 cfi_len;
	u8 sec_arch;
	u8 fid;
	u32 indx;
	int detectFlag = FALSE;

	/* check for NULL pointer */
	if (pFlinfo == NULL) {
		pr_err("%s HRD_ERR: Null pointer parameter!\n", __func__);
		return HRD_COMMON_ERR_INPUT_INVALID;
	}

	/* First try to read the Manufacturer and Device IDs */
	ret =
		SFC_SPIFlashIdGet(pFlinfo, &manf, &dev, &cfi_len, &sec_arch, &fid);

	if (ret != HRD_OK) {
		pr_err("%s HRD_ERR: Failed to get the SFlash ID!\n", __func__);
		return ret;
	}

	/* loop over the whole table and look for the appropriate SFLASH */
	for (indx = 0; indx < HI_ARRAY_SIZE(g_stSPIFlashDevTable); indx++) {
		if ((manf == g_stSPIFlashDevTable[indx].ulManufacturerId)
			&& (dev == g_stSPIFlashDevTable[indx].ulDeviceId)
			&& (CMPEXTERNID(indx, cfi_len, sec_arch, fid))) {
			pFlinfo->manufacturerId = manf;
			pFlinfo->deviceId = dev;
			pFlinfo->index = indx;
			pFlinfo->addr_mode =
				g_stSPIFlashDevTable[indx].ulAddrModeSuport;
			pFlinfo->sfc_type_flag =
				g_stSPIFlashDevTable[indx].ulIfTypeSuport;
			pFlinfo->rw_mode = SFC_REGISTER_RW_MODE;
			detectFlag = TRUE;
			break;
		}
	}

	if (!detectFlag) {
		pr_err
			("%s HRD_ERR: manf:0x%x, dev:0x%x, Unknown SPI flash device!\n",
			 __func__, manf, dev);
		return HRD_ERR;
	}

	/* init SPI FLASH Controller */
	(void)SFC_ControllerInit(pFlinfo->sfc_reg_base);

	/* fill the info based on the model detected */
	pFlinfo->sectorSize = g_stSPIFlashDevTable[pFlinfo->index].ulBlockSize;
	pFlinfo->sectorNumber =
		g_stSPIFlashDevTable[pFlinfo->index].ulBlockNumber;
	pFlinfo->pageSize = g_stSPIFlashDevTable[pFlinfo->index].ulSectorSize;
	pFlinfo->space_size = pFlinfo->sectorSize * pFlinfo->sectorNumber;
	memcpy(&pFlinfo->sflash_dev_params,
		   &g_stSPIFlashDevTable[pFlinfo->index],
		   sizeof(struct SPI_FLASH_DEVICE_PARAMS));
	DB(pr_info("%s rw_mode %d\n", __func__, pFlinfo->rw_mode));

	return ret;
}
