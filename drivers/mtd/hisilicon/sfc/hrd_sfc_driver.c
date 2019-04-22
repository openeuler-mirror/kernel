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

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
#include <linux/mtd/partitions.h>
#include <linux/platform_device.h>
#include <linux/acpi.h>
#include "hrdCommon.h"
#include "hrd_sflash_driver.h"
#include "hrd_sflash_hal.h"

static const char *sflashMtdList[] = { "sflash", NULL };

static unsigned int hrd_flash_info_fill(struct maps_init_info *maps,
					struct resource *flash_iores,
					struct platform_device *pdev)
{
	u32 i;

	/* clear the whole array */
	memset((void *)maps, 0x0, sizeof(maps));

	for (i = 0; i < MTD_MAX_FLASH_NUMBER; i++) {
		maps[i].mtdDrv = sflashMtdList;
		maps[i].mapInfo.name = pdev->name;
		maps[i].mapInfo.phys = flash_iores->start;
		maps[i].mapInfo.size = resource_size(flash_iores);
		maps[i].mapInfo.bankwidth = 8;
		DB(pr_info("i is 0x%x, phys 0x%llx,size 0x%lx\n",
			   (u32) i, maps[i].mapInfo.phys,
			   maps[i].mapInfo.size));

		DB(pr_info("\nINFO: Found %s %d - base 0x%08x, size 0x%x",
			   maps[i].mapInfo.name, i,
			   (unsigned int)maps[i].mapInfo.phys,
			   (unsigned int)maps[i].mapInfo.size));

	}

	DB(pr_info("\nINFO: %s - Found %d Flash Devices", __func__, i));
	return i;
}

static int __init hrd_flashProbe(const char **mtdDrv, struct map_info *map,
				 struct resource *sfc_regres,
				 struct mtd_info **mtd)
{
	if ((mtdDrv == NULL)
		|| (map == NULL)
		|| (mtd == NULL)) {
		pr_err("\nERROR: NULL pointer parameter at %s entry", __func__);
		return -EINVAL;
	}

	/* remap the physical address to a virtual address */
	map->virt = ioremap(map->phys, map->size);

	if (!map->virt) {
		pr_err("\nFailed ioremap Flash device at base 0x%x.",
			   (unsigned int)map->phys);
		return -EIO;
	}

	DB(pr_info
	   ("\nIo remapped ok.phy addr:0x%llx, virt addr:0x%llx",
		(u64) map->phys, (u64) map->virt));

	/* Skip bankwidths that are not supported */
	if (!map_bankwidth_supported(map->bankwidth)) {
		pr_err("\nERROR: bankwidth %d not supported.",
			   (unsigned int)map->bankwidth);
		iounmap((void *)map->virt);
		return -EIO;
	}

	*mtd = NULL;

	for (; (!(*mtd) && *mtdDrv); mtdDrv++) {
		DB(pr_info
		   ("\nUsing %s probe %s at addr 0x%llx,size 0x%x, width %dm",
			*mtdDrv, map->name, (u64) map->phys,
			(unsigned int)map->size, map->bankwidth));

		*mtd = sflash_probe(map, sfc_regres);

		if (*mtd) {
			DB(pr_info(" - detected OK"));
			/*map->size = (*mtd)->size; */
			(*mtd)->owner = THIS_MODULE;

			if (mtd_device_register(*mtd, NULL, 0)) {
				pr_err
					("\nERROR: %s - Failed to add the mtd device",
					 __func__);
				iounmap((void *)map->virt);
				map->virt = 0;
				return -ENXIO;
			}

			return 0;
		} else {
			DB(pr_info(" - Not detected"));
		}
	}

	iounmap((void *)map->virt);
	map->virt = 0;
	pr_err("\nERROR: %s - probe failed", __func__);

	return -ENXIO;
}

static unsigned int flash_map_init(struct platform_device *pdev)
{
	u32 i;
	u32 mapsNum;
	struct device *dev = &pdev->dev;
	struct resource *sfc_regres;
	struct resource *flash_iores;
	struct sfc_host *host;

	pr_info("SFC Driver V0.11");

	host = devm_kzalloc(dev, sizeof(struct sfc_host), GFP_KERNEL);

	if (!host)
		return -ENOMEM;

	sfc_regres = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	flash_iores = platform_get_resource(pdev, IORESOURCE_MEM, 1);

	if (sfc_regres->end <= sfc_regres->start) {
		pr_info("\nERROR: %s - sfc register error\r\n", __func__);
		return -EFAULT;
	}

	if (flash_iores->end <= flash_iores->start) {
		pr_info("\nERROR: %s - sflash addr error\r\n", __func__);
		return -EFAULT;
	}

	mapsNum = hrd_flash_info_fill(host->maps, flash_iores, pdev);
	DB(pr_info
	   ("\nINFO: hrd_flash_info_fill - DEtected %d devices\n", mapsNum));

	for (i = 0; i < mapsNum; i++) {
		DB(pr_info
		   ("MTD: Initialize the %s device at address 0x%08x\n",
			host->maps[i].mapInfo.name,
			(unsigned int)host->maps[i].mapInfo.phys));

		if (hrd_flashProbe
			(host->maps[i].mtdDrv, &host->maps[i].mapInfo, sfc_regres,
			 &host->maps[i].mtdInfo) == 0) {
			DB(pr_info(" - OK.\n"));
		} else {
			host->maps[i].mtdInfo = NULL;
			DB(pr_err(" - FAILED!\n"));
		}
	}

	host->mapsNum = mapsNum;

	platform_set_drvdata(pdev, host);

	return 0;
}

static void __exit flash_map_exit(struct platform_device *pdev)
{
	u32 i;

	struct sfc_host *host = platform_get_drvdata(pdev);

	for (i = 0; i < host->mapsNum; i++) {
		if (host->maps[i].mtdInfo) {
			(void)mtd_device_unregister(host->maps[i].mtdInfo);
			map_destroy(host->maps[i].mtdInfo);
		}

		if (host->maps[i].mapInfo.virt) {
			iounmap((void *)host->maps[i].mapInfo.virt);
			host->maps[i].mapInfo.virt = 0;
		}

		sflash_destroy(host->maps[i].mtdInfo);
	}

}

static int hisi_sfc_probe(struct platform_device *pdev)
{
	flash_map_init(pdev);

	return 0;
}

static int hisi_sfc_remove(struct platform_device *pdev)
{
	flash_map_exit(pdev);

	return 0;
}

static const struct acpi_device_id sfc_acpi_match[] = {
	{"HISI0173", 0},
	{}
};

MODULE_DEVICE_TABLE(acpi, sfc_acpi_match);

static struct platform_driver hisi_sfc_driver = {
	.probe = hisi_sfc_probe,
	.remove = hisi_sfc_remove,
	.driver = {
		   .name = "hisi_sfc",
		   .acpi_match_table = ACPI_PTR(sfc_acpi_match),
		   },
};

module_platform_driver(hisi_sfc_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("Hi16xx SFC driver");
MODULE_VERSION("1.07");
