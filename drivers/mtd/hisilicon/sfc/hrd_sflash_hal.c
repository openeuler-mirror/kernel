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
#include "hrd_common.h"
#include "hrd_sflash_driver.h"
#include "hrd_sflash_core.h"
#include "hrd_sflash_spec.h"

#define BIT0						   (1<<0)
#define SPI_CMD_WRR 0x01 /* Write Register */
#define SPI_CMD_CLSR 0x30 /* Clear Status Register */

struct SPI_FLASH_DEVICE_PARAMS g_stSPIFlashDevTable[] = {
	/* NUMONYX N25Q128 SPI flash, 16MB, 256 sectors of 64K each */
	{
	HISI_N25Q_WREN_CMND_OPCD,
	HISI_N25Q_WRDI_CMND_OPCD,
	HISI_N25Q_RDID_CMND_OPCD,
	HISI_N25Q_RDSR_CMND_OPCD,
	HISI_N25Q_WRSR_CMND_OPCD,
	HISI_N25Q_READ_CMND_OPCD,
	HISI_N25Q_FAST_RD_CMND_OPCD,
	HISI_N25Q_PP_CMND_OPCD,
	HISI_N25Q_SSE_CMND_OPCD,
	HISI_N25Q_SE_CMND_OPCD,
	HISI_N25Q_BE_CMND_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_N25Q_RDVECR_CMND_OPCD,
	HISI_N25Q_WRVECR_CMND_OPCD,
	HISI_N25Q_EN4BADDR_CMND_OPCD,
	HISI_N25Q_EX4BADDR_CMND_OPCD,
	HISI_N25Q_BUSY_FLAG_BIT,
	0,
	0,
	HISI_N25Q128_PAGE_SIZE,
	HISI_N25Q128_SECTOR_NUMBER,
	HISI_N25Q128_SECTOR_SIZE,
	"NUMONYX N25Q128",
	HISI_N25Q128_MANF_ID,
	HISI_N25Q128_DEVICE_ID,
	0xff,
	0xff,
	0xff,
	HISI_N25Q128_MAX_SPI_FREQ,
	HISI_N25Q128_MAX_FAST_SPI_FREQ,
	HISI_N25Q128_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},
	/* MIRCON MT25QU128AB SPI flash, 16MB, 256 sectors of 64K each */
	{
	HISI_N25Q_WREN_CMND_OPCD,
	HISI_N25Q_WRDI_CMND_OPCD,
	HISI_N25Q_RDID_CMND_OPCD,
	HISI_N25Q_RDSR_CMND_OPCD,
	HISI_N25Q_WRSR_CMND_OPCD,
	HISI_N25Q_READ_CMND_OPCD,
	HISI_N25Q_FAST_RD_CMND_OPCD,
	HISI_N25Q_PP_CMND_OPCD,
	HISI_N25Q_SSE_CMND_OPCD,
	HISI_N25Q_SE_CMND_OPCD,
	HISI_N25Q_BE_CMND_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_N25Q_RDVECR_CMND_OPCD,
	HISI_N25Q_WRVECR_CMND_OPCD,
	HISI_N25Q_EN4BADDR_CMND_OPCD,
	HISI_N25Q_EX4BADDR_CMND_OPCD,
	HISI_N25Q_BUSY_FLAG_BIT,
	0,
	0,
	HISI_N25Q128_PAGE_SIZE,
	HISI_N25Q128_SECTOR_NUMBER,
	HISI_N25Q128_SECTOR_SIZE,
	"MIRCON MT25QU128AB",
	HISI_N25Q128B_MANF_ID,
	HISI_N25Q128B_DEVICE_ID,
	0xff,
	0xff,
	0xff,
	HISI_N25Q128_MAX_SPI_FREQ,
	HISI_N25Q128_MAX_FAST_SPI_FREQ,
	HISI_N25Q128_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},

	/* NUMONYX N25Q256 SPI flash, 32MB, 256 sectors of 64K each */
	{
	HISI_N25Q_WREN_CMND_OPCD,
	HISI_N25Q_WRDI_CMND_OPCD,
	HISI_N25Q_RDID_CMND_OPCD,
	HISI_N25Q_RDSR_CMND_OPCD,
	HISI_N25Q_WRSR_CMND_OPCD,
	HISI_N25Q_READ_CMND_OPCD,
	HISI_N25Q_FAST_RD_CMND_OPCD,
	HISI_N25Q_PP_CMND_OPCD,
	HISI_N25Q_SSE_CMND_OPCD,
	HISI_N25Q_SE_CMND_OPCD,
	HISI_N25Q_BE_CMND_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_N25Q_RDVECR_CMND_OPCD,
	HISI_N25Q_WRVECR_CMND_OPCD,
	HISI_N25Q_EN4BADDR_CMND_OPCD,
	HISI_N25Q_EX4BADDR_CMND_OPCD,
	HISI_N25Q_BUSY_FLAG_BIT,
	0,
	0,
	HISI_N25Q256_PAGE_SIZE,
	HISI_N25Q256_SECTOR_NUMBER,
	HISI_N25Q256_SECTOR_SIZE,
	"NUMONYX N25Q256",
	HISI_N25Q256_MANF_ID,
	HISI_N25Q256_DEVICE_ID,
	0xff,
	0xff,
	0xff,
	HISI_N25Q256_MAX_SPI_FREQ,
	HISI_N25Q256_MAX_FAST_SPI_FREQ,
	HISI_N25Q256_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},
	/* ST M25P80 SPI flash, 1MB, 16 sectors of 64K each */
	{
	HISI_M25P_WREN_CMND_OPCD,
	HISI_M25P_WRDI_CMND_OPCD,
	HISI_M25P_RDID_CMND_OPCD,
	HISI_M25P_RDSR_CMND_OPCD,
	HISI_M25P_WRSR_CMND_OPCD,
	HISI_M25P_READ_CMND_OPCD,
	HISI_M25P_FAST_RD_CMND_OPCD,
	HISI_M25P_PP_CMND_OPCD,
	HISI_M25P_SSE_CMND_OPCD,
	HISI_M25P_SE_CMND_OPCD,
	HISI_M25P_BE_CMND_OPCD,
	HISI_M25P_RES_CMND_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD, /* power save not supported */
	HISI_SFLASH_UNKOWN_OPCD, /* next code need see datasheet */
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	0,
	0,
	HISI_M25P_PAGE_SIZE,
	HISI_M25P80_SECTOR_NUMBER,
	HISI_M25P80_SECTOR_SIZE,
	"ST M25P80",
	HISI_M25PXXX_ST_MANF_ID,
	HISI_M25P80_DEVICE_ID,
	0xff,
	0xff,
	0xff,
	HISI_M25P80_MAX_SPI_FREQ,
	HISI_M25P80_MAX_FAST_SPI_FREQ,
	HISI_M25P80_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},
	/* ST M25P32 SPI flash, 4MB, 64 sectors of 64K each */
	{
	HISI_M25P_WREN_CMND_OPCD,
	HISI_M25P_WRDI_CMND_OPCD,
	HISI_M25P_RDID_CMND_OPCD,
	HISI_M25P_RDSR_CMND_OPCD,
	HISI_M25P_WRSR_CMND_OPCD,
	HISI_M25P_READ_CMND_OPCD,
	HISI_M25P_FAST_RD_CMND_OPCD,
	HISI_M25P_PP_CMND_OPCD,
	HISI_M25P_SSE_CMND_OPCD,
	HISI_M25P_SE_CMND_OPCD,
	HISI_M25P_BE_CMND_OPCD,
	HISI_M25P_RES_CMND_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD, /* power save not supported */
	HISI_SFLASH_UNKOWN_OPCD, /* next code need see datasheet */
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	0,
	0,
	HISI_M25P_PAGE_SIZE,
	HISI_M25P32_SECTOR_NUMBER,
	HISI_M25P32_SECTOR_SIZE,
	"ST M25P32",
	HISI_M25PXXX_ST_MANF_ID,
	HISI_M25P32_DEVICE_ID,
	0xff,
	0xff,
	0xff,
	HISI_M25P32_MAX_SPI_FREQ,
	HISI_M25P32_MAX_FAST_SPI_FREQ,
	HISI_M25P32_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},

	/* ST M25P64 SPI flash, 8MB, 128 sectors of 64K each */
	{
	HISI_M25P_WREN_CMND_OPCD,
	HISI_M25P_WRDI_CMND_OPCD,
	HISI_M25P_RDID_CMND_OPCD,
	HISI_M25P_RDSR_CMND_OPCD,
	HISI_M25P_WRSR_CMND_OPCD,
	HISI_M25P_READ_CMND_OPCD,
	HISI_M25P_FAST_RD_CMND_OPCD,
	HISI_M25P_PP_CMND_OPCD,
	HISI_M25P_SSE_CMND_OPCD,
	HISI_M25P_SE_CMND_OPCD,
	HISI_M25P_BE_CMND_OPCD,
	HISI_M25P_RES_CMND_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD, /* power save not supported */
	HISI_SFLASH_UNKOWN_OPCD, /* next code need see datasheet */
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	0,
	0,
	HISI_M25P_PAGE_SIZE,
	HISI_M25P64_SECTOR_NUMBER,
	HISI_M25P64_SECTOR_SIZE,
	"ST M25P64",
	HISI_M25PXXX_ST_MANF_ID,
	HISI_M25P64_DEVICE_ID,
	0xff,
	0xff,
	0xff,
	HISI_M25P64_MAX_SPI_FREQ,
	HISI_M25P64_MAX_FAST_SPI_FREQ,
	HISI_M25P64_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},
	/* ST M25P128 SPI flash, 16MB, 64 sectors of 256K each */
	{
	HISI_M25P_WREN_CMND_OPCD,
	HISI_M25P_WRDI_CMND_OPCD,
	HISI_M25P_RDID_CMND_OPCD,
	HISI_M25P_RDSR_CMND_OPCD,
	HISI_M25P_WRSR_CMND_OPCD,
	HISI_M25P_READ_CMND_OPCD,
	HISI_M25P_FAST_RD_CMND_OPCD,
	HISI_M25P_PP_CMND_OPCD,
	HISI_M25P_SSE_CMND_OPCD,
	HISI_M25P_SE_CMND_OPCD,
	HISI_M25P_BE_CMND_OPCD,
	HISI_M25P_RES_CMND_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD, /* power save not supported */
	HISI_SFLASH_UNKOWN_OPCD, /* next code need see datasheet */
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	0,
	0,
	HISI_M25P_PAGE_SIZE,
	HISI_M25P128_SECTOR_NUMBER,
	HISI_M25P128_SECTOR_SIZE,
	"ST M25P128",
	HISI_M25PXXX_ST_MANF_ID,
	HISI_M25P128_DEVICE_ID,
	0xff,
	0xff,
	0xff,
	HISI_M25P128_MAX_SPI_FREQ,
	HISI_M25P128_MAX_FAST_SPI_FREQ,
	HISI_M25P128_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},
	/* Macronix MXIC MX25L6405 SPI flash, 8MB, 128 sectors of 64K each */
	{
	HISI_MX25L_WREN_CMND_OPCD,
	HISI_MX25L_WRDI_CMND_OPCD,
	HISI_MX25L_RDID_CMND_OPCD,
	HISI_MX25L_RDSR_CMND_OPCD,
	HISI_MX25L_WRSR_CMND_OPCD,
	HISI_MX25L_READ_CMND_OPCD,
	HISI_MX25L_FAST_RD_CMND_OPCD,
	HISI_MX25L_PP_CMND_OPCD,
	HISI_MX25L_SSE_CMND_OPCD,
	HISI_MX25L_SE_CMND_OPCD,
	HISI_MX25L_BE_CMND_OPCD,
	HISI_MX25L_RES_CMND_OPCD,
	HISI_MX25L_DP_CMND_OPCD,
	HISI_SFLASH_UNKOWN_OPCD, /* next code need see datasheet */
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	0,
	0,
	HISI_MXIC_PAGE_SIZE,
	HISI_MX25L6405_SECTOR_NUMBER,
	HISI_MX25L6405_SECTOR_SIZE,
	"MXIC MX25L6405",
	HISI_MXIC_MANF_ID,
	HISI_MX25L6405_DEVICE_ID,
	0xff,
	0xff,
	0xff,
	HISI_MX25L6405_MAX_SPI_FREQ,
	HISI_MX25L6405_MAX_FAST_SPI_FREQ,
	HISI_MX25L6405_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},
	/* Macronix MXIC MX25L1606E SPI flash, 2MB, 32 sectors of 64K each */
	{
	HISI_MX25L_WREN_CMND_OPCD,
	HISI_MX25L_WRDI_CMND_OPCD,
	HISI_MX25L_RDID_CMND_OPCD,
	HISI_MX25L_RDSR_CMND_OPCD,
	HISI_MX25L_WRSR_CMND_OPCD,
	HISI_MX25L_READ_CMND_OPCD,
	HISI_MX25L_FAST_RD_CMND_OPCD,
	HISI_MX25L_PP_CMND_OPCD,
	HISI_MX25L_SSE_CMND_OPCD,
	HISI_MX25L_SE_CMND_OPCD,
	HISI_MX25L_BE_CMND_OPCD,
	HISI_MX25L_RES_CMND_OPCD,
	HISI_MX25L_DP_CMND_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD, /* can't support next 5 code */
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	0,
	0,
	HISI_MXIC_PAGE_SIZE,
	HISI_MX25L1606E_SECTOR_NUMBER,
	HISI_MX25L1606E_SECTOR_SIZE,
	"MXIC MX25L1606E",
	HISI_MXIC_MANF_ID,
	HISI_MX25L1606E_DEVICE_ID,
	0xff,
	0xff,
	0xff,
	HISI_MX25L1606E_MAX_SPI_FREQ,
	HISI_MX25L1606E_MAX_FAST_SPI_FREQ,
	HISI_MX25L1606E_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},
	/* Macronix MXIC MX25U12835F SPI flash, 16MB, 255 sectors of 64K each */
	{
	HISI_MX25U12835F_WREN_CMND_OPCD,
	HISI_MX25U12835F_WRDI_CMND_OPCD,
	HISI_MX25U12835F_RDID_CMND_OPCD,
	HISI_MX25U12835F_RDSR_CMND_OPCD,
	HISI_MX25U12835F_WRSR_CMND_OPCD,
	HISI_MX25U12835F_READ_CMND_OPCD,
	HISI_MX25U12835F_FAST_RD_CMND_OPCD,
	HISI_MX25U12835F_PP_CMND_OPCD,
	HISI_MX25U12835F_SSE_CMND_OPCD,
	HISI_MX25U12835F_SE_CMND_OPCD,
	HISI_MX25U12835F_BE_CMND_OPCD,
	HISI_MX25U12835F_RES_CMND_OPCD,
	HISI_MX25U12835F_DP_CMND_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD, /* can't support next 5 code */
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	0,
	0,
	HISI_MX25U12835F_PAGE_SIZE,
	HISI_MX25U12835F_SECTOR_NUMBER,
	HISI_MX25U12835F_SECTOR_SIZE,
	"MXIC MX25U12835F",
	HISI_MX25U12835F_MANF_ID,
	HISI_MX25U12835F_DEVICE_ID,
	0xff,
	0xff,
	0xff,
	HISI_MX25U12835F_MAX_SPI_FREQ,
	HISI_MX25U12835F_MAX_FAST_SPI_FREQ,
	HISI_MX25U12835F_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},
	/* SPANSION S25FL128P SPI flash, 16MB, 64 sectors of 256K each */
	{
	HISI_S25FL_WREN_CMND_OPCD,
	HISI_S25FL_WRDI_CMND_OPCD,
	HISI_S25FL_RDID_CMND_OPCD,
	HISI_S25FL_RDSR_CMND_OPCD,
	HISI_S25FL_WRSR_CMND_OPCD,
	HISI_S25FL_READ_CMND_OPCD,
	HISI_S25FL_FAST_RD_CMND_OPCD,
	HISI_S25FL_PP_CMND_OPCD,
	HISI_S25FL_SSE_CMND_OPCD,
	HISI_S25FL_SE_CMND_OPCD,
	HISI_S25FL_BE_CMND_OPCD,
	HISI_S25FL_RES_CMND_OPCD,
	HISI_S25FL_DP_CMND_OPCD,
	HISI_SFLASH_UNKOWN_OPCD, /* next code need see datasheet */
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	0,
	0,
	HISI_S25FL_PAGE_SIZE,
	HISI_S25FL128_SECTOR_NUMBER,
	HISI_S25FL128_SECTOR_SIZE,
	"SPANSION S25FL128",
	HISI_SPANSION_MANF_ID,
	HISI_S25FL128_DEVICE_ID,
	0xff,
	0xff,
	0x80,
	HISI_S25FL128_MAX_SPI_FREQ,
	HISI_M25P128_MAX_FAST_SPI_FREQ,
	HISI_M25P128_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},
	/* SPANSION S25FS128S SPI flash, 16MB, 255 sectors of 64K each + */
	{
	HISI_S25FL_WREN_CMND_OPCD,
	HISI_S25FL_WRDI_CMND_OPCD,
	HISI_S25FL_RDID_CMND_OPCD,
	HISI_S25FL_RDSR_CMND_OPCD,
	HISI_S25FL_WRSR_CMND_OPCD,
	HISI_S25FL_READ_CMND_OPCD,
	HISI_S25FL_FAST_RD_CMND_OPCD,
	HISI_S25FL_PP_CMND_OPCD,
	HISI_S25FL_SSE_CMND_OPCD,
	HISI_S25FL_SE_CMND_OPCD,
	HISI_S25FL_BE_CMND_OPCD,
	HISI_S25FL_RES_CMND_OPCD,
	HISI_S25FL_DP_CMND_OPCD,
	HISI_SFLASH_UNKOWN_OPCD, /* next code need see datasheet */
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	0,
	0,
	HISI_S25FL_PAGE_SIZE,
	HISI_S25FL128_SECTOR_NUMBER,
	HISI_S25FL128_SECTOR_SIZE,
	"SPANSION S25FS128",
	HISI_SPANSION_MANF_ID,
	HISI_S25FL128_DEVICE_ID,
	0xff,
	0xff,
	0x81,
	HISI_S25FL128_MAX_SPI_FREQ,
	HISI_M25P128_MAX_FAST_SPI_FREQ,
	HISI_M25P128_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},
	/* ATMEL AT25DF641 SPI flash, 8MB, 128 sectors of 64K each */
	{
	HISI_AT25DF_WREN_CMND_OPCD,
	HISI_AT25DF_WRDI_CMND_OPCD,
	HISI_AT25DF_RDID_CMND_OPCD,
	HISI_AT25DF_RDSR_CMND_OPCD,
	HISI_AT25DF_WRSR_CMND_OPCD,
	HISI_AT25DF_READ_CMND_OPCD,
	HISI_AT25DF_FAST_RD_CMND_OPCD,
	HISI_AT25DF_PP_CMND_OPCD,
	HISI_AT25DF_SSE_CMND_OPCD,
	HISI_AT25DF_SE_CMND_OPCD,
	HISI_AT25DF_BE_CMND_OPCD,
	HISI_AT25DF_RES_CMND_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD, /* power save not supported */
	HISI_SFLASH_UNKOWN_OPCD, /* next code need see datasheet */
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	0,
	0,
	HISI_AT25DF_PAGE_SIZE,
	HISI_AT25DF641_SECTOR_NUMBER,
	HISI_AT25DF641_SECTOR_SIZE,
	"AT 25DF641",
	HISI_AT25DFXXX_AT_MANF_ID,
	HISI_AT25DF641_DEVICE_ID,
	0xff,
	0xff,
	0xff,
	HISI_AT25DF641_MAX_SPI_FREQ,
	HISI_AT25DF641_MAX_FAST_SPI_FREQ,
	HISI_AT25DF641_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},

	/* MIRCON DEFAULT */
	{
	HISI_N25Q_WREN_CMND_OPCD,
	HISI_N25Q_WRDI_CMND_OPCD,
	HISI_N25Q_RDID_CMND_OPCD,
	HISI_N25Q_RDSR_CMND_OPCD,
	HISI_N25Q_WRSR_CMND_OPCD,
	HISI_N25Q_READ_CMND_OPCD,
	HISI_N25Q_FAST_RD_CMND_OPCD,
	HISI_N25Q_PP_CMND_OPCD,
	HISI_N25Q_SSE_CMND_OPCD,
	HISI_N25Q_SE_CMND_OPCD,
	HISI_N25Q_BE_CMND_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_N25Q_RDVECR_CMND_OPCD,
	HISI_N25Q_WRVECR_CMND_OPCD,
	HISI_N25Q_EN4BADDR_CMND_OPCD,
	HISI_N25Q_EX4BADDR_CMND_OPCD,
	HISI_N25Q_BUSY_FLAG_BIT,
	0,
	0,
	HISI_N25Q128_PAGE_SIZE,
	HISI_N25Q128_SECTOR_NUMBER,
	HISI_N25Q128_SECTOR_SIZE,
	"MIRCON DEFAULT",
	HISI_N25Q128B_MANF_ID,
	0xffff,
	0xff,
	0xff,
	0xff,
	HISI_N25Q128_MAX_SPI_FREQ,
	HISI_N25Q128_MAX_FAST_SPI_FREQ,
	HISI_N25Q128_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},

	/* MIXC DEFAULT */
	{
	HISI_MX25U12835F_WREN_CMND_OPCD,
	HISI_MX25U12835F_WRDI_CMND_OPCD,
	HISI_MX25U12835F_RDID_CMND_OPCD,
	HISI_MX25U12835F_RDSR_CMND_OPCD,
	HISI_MX25U12835F_WRSR_CMND_OPCD,
	HISI_MX25U12835F_READ_CMND_OPCD,
	HISI_MX25U12835F_FAST_RD_CMND_OPCD,
	HISI_MX25U12835F_PP_CMND_OPCD,
	HISI_MX25U12835F_SSE_CMND_OPCD,
	HISI_MX25U12835F_SE_CMND_OPCD,
	HISI_MX25U12835F_BE_CMND_OPCD,
	HISI_MX25U12835F_RES_CMND_OPCD,
	HISI_MX25U12835F_DP_CMND_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	0,
	0,
	HISI_MX25U12835F_PAGE_SIZE,
	HISI_MX25U12835F_SECTOR_NUMBER,
	HISI_MX25U12835F_SECTOR_SIZE,
	"MIXC DEFAULT",
	HISI_MX25U12835F_MANF_ID,
	0xffff,
	0xff,
	0xff,
	0xff,
	HISI_MX25U12835F_MAX_SPI_FREQ,
	HISI_MX25U12835F_MAX_FAST_SPI_FREQ,
	HISI_MX25U12835F_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},

	/* SPANSION DEFAULT */
	{
	HISI_S25FL_WREN_CMND_OPCD,
	HISI_S25FL_WRDI_CMND_OPCD,
	HISI_S25FL_RDID_CMND_OPCD,
	HISI_S25FL_RDSR_CMND_OPCD,
	HISI_S25FL_WRSR_CMND_OPCD,
	HISI_S25FL_READ_CMND_OPCD,
	HISI_S25FL_FAST_RD_CMND_OPCD,
	HISI_S25FL_PP_CMND_OPCD,
	HISI_S25FL_SSE_CMND_OPCD,
	HISI_S25FL_SE_CMND_OPCD,
	HISI_S25FL_BE_CMND_OPCD,
	HISI_S25FL_RES_CMND_OPCD,
	HISI_S25FL_DP_CMND_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	HISI_SFLASH_UNKOWN_OPCD,
	0,
	0,
	HISI_S25FL_PAGE_SIZE,
	HISI_S25FL128_SECTOR_NUMBER,
	HISI_S25FL128_SECTOR_SIZE,
	"SPANSION DEFAULT",
	HISI_SPANSION_MANF_ID,
	0xffff,
	0xff,
	0xff,
	0xff,
	HISI_S25FL128_MAX_SPI_FREQ,
	HISI_M25P128_MAX_FAST_SPI_FREQ,
	HISI_M25P128_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF},

	/* DEFAULT */
	{
	HISI_MX25U12835F_WREN_CMND_OPCD,
	HISI_MX25U12835F_WRDI_CMND_OPCD,
	HISI_MX25U12835F_RDID_CMND_OPCD,
	HISI_MX25U12835F_RDSR_CMND_OPCD,
	HISI_MX25U12835F_WRSR_CMND_OPCD,
	HISI_MX25U12835F_READ_CMND_OPCD,
	HISI_MX25U12835F_FAST_RD_CMND_OPCD,
	HISI_MX25U12835F_PP_CMND_OPCD,
	HISI_MX25U12835F_SSE_CMND_OPCD,
	HISI_MX25U12835F_SE_CMND_OPCD,
	HISI_MX25U12835F_BE_CMND_OPCD,
	HISI_MX25U12835F_RES_CMND_OPCD,
	HISI_MX25U12835F_DP_CMND_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	HISI_SFLASH_NO_SPECIFIC_OPCD,
	0,
	0,
	HISI_MX25U12835F_PAGE_SIZE,
	HISI_MX25U12835F_SECTOR_NUMBER,
	HISI_MX25U12835F_SECTOR_SIZE,
	"DEFAULT",
	0xff,
	0xffff,
	0xff,
	0xff,
	0xff,
	HISI_MX25U12835F_MAX_SPI_FREQ,
	HISI_MX25U12835F_MAX_FAST_SPI_FREQ,
	HISI_MX25U12835F_FAST_READ_DUMMY_BYTES,
	SPI_FLASH_3BYTE_ADDR,
	STANDARD_SPI_IF}
};

s32 SFC_BlockErase(struct SFC_SFLASH_INFO *sflash, u32 ulAddr, u32 ErCmd)
{
	u32 ulRegValue;
	s32 ulRet;

	ulRet = SFC_WriteEnable(sflash);
	if (ulRet != HRD_OK) {
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
	if (ulRet != HRD_OK) {
		pr_err("[SFC] [%s %d]: SFC_WaitInt fail\n", __func__, __LINE__);
		goto rel;
	}

	if (SFC_IsOpErr(sflash->sfc_reg_base)) {
		ulRet = HRD_ERR;
		goto rel;
	}

	ulRet = SFC_CheckBusy(sflash, FLASH_ERASE_BUSY_WAIT_CNT);
	if (ulRet != HRD_OK) {
		pr_err("[SFC] [%s %d]: SFC_CheckBusy fail\n", __func__, __LINE__);
		goto rel;
	}

 rel:
	SFC_FlashUnlock(sflash);
	return ulRet;
}

static s32 _SFC_RegModeWrite(struct SFC_SFLASH_INFO *sflash,
	u32 offset, const u8 *pucSrc, u32 ulWriteLen)
{
	u32 i;
	s32 slRet;
	u32 ulRemain;
	u32 ulAlignLen;

	ulRemain = ulWriteLen % SFC_HARD_BUF_LEN;
	ulAlignLen = ulWriteLen - ulRemain;

	for (i = 0; i < ulAlignLen; i += SFC_HARD_BUF_LEN) {
		slRet =  SFC_RegWordAlignWrite(sflash, (const u32 *)(pucSrc + i), offset + i, SFC_HARD_BUF_LEN);
		if (slRet != HRD_OK) {
			pr_err("[SFC] [%s %d]: SFC_RegWordWrite fail\n", __func__, __LINE__);
			return slRet;
		}

		if ((i > 0) && (i % 8192 == 0)) { /* After write 8192 bytes of data, sleep 1 ms. */
			msleep(1);
		}
	}

	if (ulRemain >= 0x4) {
		slRet = SFC_RegWordAlignWrite(sflash, (const u32 *)(pucSrc + i), offset + i, ulRemain & (~0x3));
		if (slRet != HRD_OK) {
			pr_err("[SFC] [%s %d]: SFC_RegWordAlignWrite fail\n", __func__, __LINE__);
			return slRet;
		}
		i += ulRemain&(~0x3);
	}

	for (; i < ulWriteLen; i++) {
		slRet = SFC_RegByteWrite(sflash, *(const u8 *)(pucSrc + i), offset + i);
		if (slRet != HRD_OK) {
			pr_err("[SFC] [%s %d]: SFC_RegByteWrite fail\n", __func__, __LINE__);
			return slRet;
		}
	}

	return HRD_OK;
}

s32 SFC_RegModeWrite(struct SFC_SFLASH_INFO *sflash,
	u32 offset, const u8 *pucSrc, u32 ulWriteLen)
{
	s32 slRet;

	if (!pucSrc) {
		pr_err("[SFC] [%s %d]: Pointer is null\n", __func__, __LINE__);
		return HRD_COMMON_ERR_NULL_POINTER;
	}

	if (ulWriteLen > sflash->space_size) {
		pr_err("[SFC] [%s %d]: ulReadLen is invalid\n", __func__, __LINE__);
		return HRD_COMMON_ERR_INPUT_INVALID;
	}

	SFC_CheckErr(sflash);

	slRet = _SFC_RegModeWrite(sflash, offset, pucSrc, ulWriteLen);
	if (slRet != HRD_OK)
		return slRet;

	if (SFC_IsOpErr(sflash->sfc_reg_base))
		return HRD_ERR;

	return HRD_OK;
}

s32 SFC_RegModeRead(struct SFC_SFLASH_INFO *sflash,
	u32 offset, u8 *pucDest, u32 ulReadLen)
{
	u32 i;
	u32 ulRemain;
	u32 ulAlignLen;
	s32 ret = HRD_OK;

	if (!sflash || !pucDest) {
		pr_err("[SFC] [%s %d]: Pointer is null\n", __func__, __LINE__);
		return HRD_COMMON_ERR_NULL_POINTER;
	}

	if (ulReadLen > sflash->space_size) {
		pr_err("[SFC] [%s %d]: ulReadLen is invalid\n", __func__, __LINE__);
		return HRD_COMMON_ERR_INPUT_INVALID;
	}

	SFC_CheckErr(sflash);

	ulRemain = ulReadLen % SFC_HARD_BUF_LEN;
	ulAlignLen = ulReadLen - ulRemain;

	for (i = 0; i < ulAlignLen; i += SFC_HARD_BUF_LEN) {
		ret = SFC_RegWordAlignRead(sflash, offset + i, (u32 *) (pucDest + i), SFC_HARD_BUF_LEN);
		if (ret != HRD_OK) {
			pr_err("[SFC] [%s %d]: SFC_RegWordAlignRead fail\n", __func__, __LINE__);
			return ret;
		}
	}

	if (ulRemain >= 0x4) {
		ret = SFC_RegWordAlignRead(sflash, offset + i, (u32 *) (pucDest + i), ulRemain & (~0x3));
		if (ret != HRD_OK) {
			pr_err("[SFC] [%s %d]: SFC_RegWordAlignRead fail\n", __func__, __LINE__);
			return ret;
		}
		i += ulRemain&(~0x3);
	}

	for (; i < ulReadLen; i++) {
		ret = SFC_RegByteRead(sflash, offset + i, pucDest + i);
		if (ret != HRD_OK) {
			pr_err("[SFC] [%s %d]: SFC_RegByteRead fail\n", __func__, __LINE__);
			return ret;
		}
	}

	return ret;
}

static s32 SFC_SPIFlashIdGet(struct SFC_SFLASH_INFO *pFlinfo,
	u8 *pulManuId, u16 *pulDevId, u8 *pcfi_len, u8 *psec_arch, u8 *pfid)
{
	u8 ulID0;
	u16 ulID1;
	u16 ulID2;
	s32 ulRet;
	u32 ulRegValue;
	u32 readid_cmd;

	if (!pulManuId || !pulDevId) {
		pr_err("[SFC] [%s %d]: input params is invalid\n", __func__, __LINE__);
		return HRD_COMMON_ERR_NULL_POINTER;
	}

	(void)SFC_ClearInt(pFlinfo->sfc_reg_base);

	if (pFlinfo->index >= HI_ARRAY_SIZE(g_stSPIFlashDevTable))
		readid_cmd = SFLASH_DEFAULT_RDID_OPCD;
	else
		readid_cmd = g_stSPIFlashDevTable[pFlinfo->index].ucOpcodeRDID;

	SFC_RegisterWrite(pFlinfo->sfc_reg_base + CMD_INS, readid_cmd);

	ulRegValue = SFC_RegisterRead(pFlinfo->sfc_reg_base + CMD_CONFIG);
	ulRegValue &= (~(0xff << DATA_CNT)) & (~(1 << RW_DATA))
		& (~(1 << SEL_CS)) & (~(1 << ADDR_EN));
	ulRegValue |= (0x5 << DATA_CNT) | (0x1 << RW_DATA) | (0x1 << DATA_EN)
		| (SFC_CHIP_CS << SEL_CS) | (0x1 << START);

	wmb();
	SFC_RegisterWrite(pFlinfo->sfc_reg_base + CMD_CONFIG, ulRegValue);
	ulRet = SFC_WaitInt(pFlinfo->sfc_reg_base);
	if (ulRet != HRD_OK) {
		pr_err("[SFC] [%s %d]: wait int failed\r\n", __func__, __LINE__);
		return WAIT_TIME_OUT;
	}

	ulRet = SFC_CheckCmdExcStatus(pFlinfo);
	if (ulRet) {
		pr_err("[SFC] [%s %d]: cmd execute timeout\r\n", __func__, __LINE__);
		return WAIT_TIME_OUT;
	}

	ulRegValue = SFC_RegisterRead(pFlinfo->sfc_reg_base + DATABUFFER1);

	ulID0 = ulRegValue & 0xff;
	ulID1 = (ulRegValue >> 0x8) & 0xff;
	ulID2 = (ulRegValue >> 0x10) & 0xff;

	*pulManuId = ulID0;
	*pulDevId = (u16) (ulID1 << 0x8) | ulID2;
	*pcfi_len = (ulRegValue >> 0x18) & 0xff;

	ulRegValue = SFC_RegisterRead(pFlinfo->sfc_reg_base + DATABUFFER2);
	*psec_arch = ulRegValue & 0xff;
	*pfid = (ulRegValue >> 0x8) & 0xff;

	pr_info("[SFC] [%s %d]:ulManuId=0x%x, ulDevId=0x%x cfi_len=0x%x, sec_arch=0x%x, fid=0x%x\n",
		__func__, __LINE__, *pulManuId, *pulDevId, *pcfi_len, *psec_arch, *pfid);

	return HRD_OK;
}

static int MirconWPSet(struct SFC_SFLASH_INFO *sflash, bool val)
{
	int ret;

	ret = SFC_WriteEnable(sflash);
	if (ret != HRD_OK) {
		pr_err("SFC_WriteEnable fail\n");
		return ret;
	}

	if (val)
		SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1, 0xDC);
	else
		SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1, 0x0);

	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, SPI_CMD_WRR);
	SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, 0x81);
	udelay((unsigned long)10); /* Delay 10 subtleties */

	return ret;
}

static int SpansionWPSet(struct SFC_SFLASH_INFO *sflash, bool val)
{
	int ret;

	ret = SFC_WriteEnable(sflash);
	if (ret != HRD_OK) {
		pr_err("SFC_WriteEnable fail\n");
		return ret;
	}

	if (val) {
		SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1, 0x9C);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, SPI_CMD_WRR);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, 0x81);
	} else {
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, SPI_CMD_CLSR);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, 0x1);
		udelay(50); /* Delay 50 subtleties */
		ret = SFC_CheckCmdExcStatus(sflash);
		if (ret != HRD_OK) {
			pr_err("[SFC] [%s %d]: SFC_CheckCmdExcStatus fail\n", __func__, __LINE__);
			return ret;
		}

		udelay(50); /* Delay 50 subtleties */
		ret = SFC_WaitFlashIdle(sflash);
		if (ret != HRD_OK) {
			pr_err("[SFC] [%s %d]: SFC_WaitFlashIdle fail\n", __func__, __LINE__);
			return ret;
		}

		udelay(200); /* Delay 200 subtleties */
		ret = SFC_WriteEnable(sflash);
		if (ret != HRD_OK) {
			pr_err("[SFC] [%s %d]: SFC_WriteEnable fail\n", __func__, __LINE__);
			return ret;
		}

		udelay(50); /* Delay 50 subtleties */
		SFC_RegisterWrite(sflash->sfc_reg_base + DATABUFFER1, 0);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_INS, SPI_CMD_WRR);
		SFC_RegisterWrite(sflash->sfc_reg_base + CMD_CONFIG, 0x81);
	}

	return ret;
}

static int MxicWPSet(struct SFC_SFLASH_INFO *sflash, bool val)
{
	u32 status;
	int ret;

	ret = SFC_WriteEnable(sflash);
	if (ret != HRD_OK) {
		pr_err("SFC_WriteEnable fail\n");
		return ret;
	}

	/* status register[7:0] : bit7[SRWD], bit6[QE], bit5~bit2[BP3 ~ BP0], bit1[WEL], bit0[WIP] */
	status = SFC_ReadStatus(sflash);
	if (status == WAIT_TIME_OUT) {
		ret = HRD_ERR;
		pr_err("[SFC] [%s %d]: SFC_ReadStatus time out\n", __func__, __LINE__);
		return ret;
	}

	if (((status >> 1) & 0x1) != 1) {
		ret = HRD_ERR;
		pr_err("[SFC] [%s %d]: Write enable fail\n", __func__, __LINE__);
		return ret;
	}

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

	ret = SFC_WaitInt(sflash->sfc_reg_base);
	if (ret != HRD_OK)
		return ret;

	return ret;
}

int SFC_WPSet(struct SFC_SFLASH_INFO *sflash, bool val)
{
	u32 device_id;
	int ret;

	(void)SFC_ClearInt(sflash->sfc_reg_base);

	SFC_CheckErr(sflash);

	/* First try to read the Manufacturer and Device IDs */
	ret = SFC_GetDeviceId(sflash, &device_id);
	if (ret != HRD_OK) {
		pr_err("[SFC][%s %d]: Failed to get the device id\n", __func__, __LINE__);
		return ret;
	}

	sflash->manufacturerId = device_id;
	ret = SFC_WaitFlashIdle(sflash);
	if (ret != HRD_OK) {
		pr_err("[SFC][%s %d]: SFC_WaitFlashIdle fail\n", __func__, __LINE__);
		return ret;
	}

	/* WP will lock sfc */
	if (HISI_M25PXXX_ST_MANF_ID == (u8) (device_id)) {
		ret = MirconWPSet(sflash, val);
	} else if (HISI_SPANSION_MANF_ID == (u8) (device_id)) {
		ret = SpansionWPSet(sflash, val);
	} else if (HISI_MX25U12835F_MANF_ID == (u8) (device_id)) {
		ret = MxicWPSet(sflash, val);
	/* default */
	} else {
		ret = MxicWPSet(sflash, val);
	}

	if (ret != HRD_OK)
		goto done;

	udelay(10); /* delay 10 us */

	ret = SFC_CheckCmdExcStatus(sflash);
	if (ret != HRD_OK) {
		pr_err("[SFC] [%s %d]: SFC_CheckCmdExcStatus fail\n", __func__, __LINE__);
		goto done;
	}

	ret = SFC_WaitFlashIdle(sflash);
	if (ret != HRD_OK) {
		pr_err("[SFC] [%s %d]: SFC_WaitFlashIdle fail\n", __func__, __LINE__);
		goto done;
	}

done:
	SFC_FlashUnlock(sflash);
	return ret;
}

#define CMP_MANF_ID(indx, id) \
	((g_stSPIFlashDevTable[indx].ulManufacturerId != 0xff) ? (g_stSPIFlashDevTable[indx].ulManufacturerId == (id)) : 1)

#define CMP_DEVICE_ID(indx, id) \
	((g_stSPIFlashDevTable[indx].ulDeviceId != 0xffff) ? (g_stSPIFlashDevTable[indx].ulDeviceId == (id)) : 1)

#define CMP_EXTERN_ID(indx, cfi_len, sec_arch, fid) \
	(((g_stSPIFlashDevTable[indx].ulIdCFILen != 0xff) ? (g_stSPIFlashDevTable[indx].ulIdCFILen == (cfi_len)) : 1) && \
	((g_stSPIFlashDevTable[indx].ulPhySecArch != 0xff) ? (g_stSPIFlashDevTable[indx].ulPhySecArch == (sec_arch)) : 1) && \
	((g_stSPIFlashDevTable[indx].ulFId != 0xff) ? (g_stSPIFlashDevTable[indx].ulFId == (fid)) : 1))

static bool SFC_IsFlashIdErr(u8 manf, u16 dev)
{
	if (((manf == 0xFF) && (dev == 0xFFFF))
		|| ((manf == 0x0) && (dev == 0x0))) {
		return true;
	}

	return false;
}

int hrd_sflash_init(struct SFC_SFLASH_INFO *pFlinfo)
{
	int ret;
	u8 manf;
	u16 dev;
	u8 cfi_len;
	u8 sec_arch;
	u8 fid;
	u32 indx;
	bool detectFlag = false;

	/* check for NULL pointer */
	if (pFlinfo == NULL) {
		pr_err("[SFC] %s HRD_ERR: Null pointer parameter!\n", __func__);
		return HRD_COMMON_ERR_INPUT_INVALID;
	}

	/* First try to read the Manufacturer and Device IDs */
	ret = SFC_SPIFlashIdGet(pFlinfo, &manf, &dev, &cfi_len, &sec_arch, &fid);
	if (ret != HRD_OK) {
		pr_err("[SFC] %s HRD_ERR: Failed to get the SFlash ID!\n", __func__);
		return ret;
	}

	if (SFC_IsFlashIdErr(manf, dev)) {
		pr_err("flash id err, manf=0x%x,dev=0x%x\n", manf, dev);
		return HRD_ERR;
	}

	/* loop over the whole table and look for the appropriate SFLASH */
	for (indx = 0; indx < HI_ARRAY_SIZE(g_stSPIFlashDevTable); indx++) {
		if ((CMP_MANF_ID(indx, manf))
			&& (CMP_DEVICE_ID(indx, dev))
			&& (CMP_EXTERN_ID(indx, cfi_len, sec_arch, fid))) {
			pFlinfo->manufacturerId = manf;
			pFlinfo->deviceId = dev;
			pFlinfo->index = indx;
			pFlinfo->addr_mode = g_stSPIFlashDevTable[indx].ulAddrModeSuport;
			pFlinfo->sfc_type_flag = g_stSPIFlashDevTable[indx].ulIfTypeSuport;
			detectFlag = true;
			break;
		}
	}

	if (!detectFlag) {
		pr_err("[SFC] %s HRD_ERR: manf:0x%x, dev:0x%x, Unknown SPI flash device!\n", __func__, manf, dev);
		return HRD_ERR;
	}

	/* fill the info based on the model detected */
	pFlinfo->sectorSize = g_stSPIFlashDevTable[pFlinfo->index].ulBlockSize;
	pFlinfo->sectorNumber = g_stSPIFlashDevTable[pFlinfo->index].ulBlockNumber;
	pFlinfo->pageSize = g_stSPIFlashDevTable[pFlinfo->index].ulSectorSize;
	pFlinfo->space_size = pFlinfo->sectorSize * pFlinfo->sectorNumber;
	memcpy(&pFlinfo->sflash_dev_params,
		   &g_stSPIFlashDevTable[pFlinfo->index],
		   sizeof(struct SPI_FLASH_DEVICE_PARAMS));

	return ret;
}
