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

#ifndef _HRD_SFLASH_DRIVER_H
#define _HRD_SFLASH_DRIVER_H

#include <linux/mtd/map.h>

#define INVALID_DEVICE_NUMBER 0xFFFFFFFF

/* SFC cs num */
#define SFC_CS_MAX_NUM 2

#define MTD_MAX_FLASH_NUMBER 1

/* SFC cs size 1GByte */
#define SFC_CS_MAX_SIZE 0x40000000

#define HI_ARRAY_SIZE(a) ((sizeof(a)) / (sizeof(a[0])))

struct maps_init_info {
	struct map_info mapInfo;
	const char **mtdDrv;
	struct mtd_info *mtdInfo;
};

struct sfc_host {
	u32 mapsNum;
	struct maps_init_info maps[MTD_MAX_FLASH_NUMBER];
};

struct SPI_FLASH_DEVICE_PARAMS {
	u8 ucOpcodeWREN; /* Write enable opcode */
	u8 ucOpcodeWRDI; /* Write disable opcode */
	u8 ucOpcodeRDID; /* Read ID opcode */
	u8 ucOpcodeRDSR; /* Read Status Register opcode */
	u8 ucOpcodeWRSR; /* Write Status register opcode */
	u8 ucOpcodeREAD; /* Read opcode */
	u8 ucOpcodeFSTRD; /* Fast Read opcode */
	u8 ucOpcodePP; /* Page program opcode */
	u8 ucOpcodeSSE; /* SubSector erase opcode */
	u8 ucOpcodeSE; /* Sector erase opcode */
	u8 ucOpcodeBE; /* Bulk erase opcode */
	u8 ucOpcodeRES; /* Read electronic signature */
	u8 ucOpcodePwrSave; /* Go into power save mode */
	u8 ucOpcodeRDVECR; /* Read Volatile Enhanced Configuration Reg */
	u8 ucOpcodeWRVECR; /* Write Volatile Enhanced Configuration Reg */
	u8 ucOpcodeEN4BAddr; /* Enter 4-byte address mode */
	u8 ucOpcodeEX4BAddr; /* Exit 4-byte address mode */
	u8 ucBusyFlagBit;
	u8 ucReserve1;
	u8 ucReserve2;
	u32 ulSectorSize; /* Size of each sector */
	u32 ulBlockNumber; /* Number of blocks */
	u32 ulBlockSize; /* size of each block */
	const char *deviceModel; /* string with the device model */
	u32 ulManufacturerId; /* The manufacturer ID */
	u32 ulDeviceId; /* Device ID */
	u32 ulIdCFILen; /* ID-CFI Length - number bytes following */
	u32 ulPhySecArch; /* Physical Sector Architecture */
	u32 ulFId; /* Family ID */
	/* The MAX frequency that can be used with the device */
	u32 ulSpiMaxFreq;
	/* The MAX frequency that can be used with the device for fast reads */
	u32 ulSpiMaxFastFreq;
	/* Number of dumy bytes to read before real data when working in fast read mode. */
	u32 ulSpiFastRdDummyBytes;
	u32 ulAddrModeSuport; /* it[1:0]:4/3Byte addr mode, 1:support */
	u32 ulIfTypeSuport; /* bit[6:0]:show 7 type, 1:supporu */
};

struct SFC_SFLASH_INFO {
	u64 baseAddr; /* Flash Base Address used in fast mode */
	u64 sfc_reg_base; /* sfc reg base addr */
	u32 space_size;
	u8 manufacturerId; /* Manufacturer ID */
	u16 deviceId; /* Device ID */
	u32 sectorSize; /* Size of each sector - all the same */
	u32 sectorNumber; /* Number of sectors */
	u32 pageSize; /* Page size - affect allignment */
	/* index of the device in the sflash table (internal parameter) */
	u32 index;
	u32 addr_mode;
	u32 sfc_type_flag;
	struct SPI_FLASH_DEVICE_PARAMS sflash_dev_params;
	struct mutex lock;
};

extern struct mtd_info *sflash_probe(struct map_info *map, struct resource *sfc_regres);
extern void sflash_destroy(struct mtd_info *mtd);

#endif /* _HRD_SLASH_DRIVER_H */
