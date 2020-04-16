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

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
#include <linux/mtd/partitions.h>
#include <linux/platform_device.h>
#include <linux/acpi.h>
#include "hrd_common.h"
#include "hrd_sflash_driver.h"

#define SFC_DRIVER_VERSION  "1.9.39.0"

static const char *g_sflashMtdList[] = {"sflash", NULL};

static unsigned int hrd_flash_info_fill(struct maps_init_info *maps,
	struct resource *flash_iores, struct platform_device *pdev)
{
	u32 i;

	memset((void *)maps, 0x0, sizeof(struct maps_init_info)*MTD_MAX_FLASH_NUMBER);

	for (i = 0; i < MTD_MAX_FLASH_NUMBER; i++) {
		maps[i].mtdDrv = g_sflashMtdList;
		maps[i].mapInfo.name = pdev->name;
		maps[i].mapInfo.phys = flash_iores->start;
		maps[i].mapInfo.size = resource_size(flash_iores);
		maps[i].mapInfo.bankwidth = 0x8;
		DB(pr_info("[SFC] i is 0x%x, phys 0x%llx,size 0x%lx\n",
				   (u32) i, maps[i].mapInfo.phys,
				   maps[i].mapInfo.size));

		DB(pr_info("[SFC] INFO: Found %s %d - base 0x%08x, size 0x%x\n",
				   maps[i].mapInfo.name, i,
				   (unsigned int)maps[i].mapInfo.phys,
				   (unsigned int)maps[i].mapInfo.size));
	}

	DB(pr_info("[SFC] INFO: %s - Found %d Flash Devices\n", __func__, i));
	return i;
}

static int _hrd_flashProbe(const char **mtdDrv, struct map_info *map,
						   struct resource *sfc_regres, struct mtd_info **mtd)
{
	*mtd = NULL;

	for (; (!(*mtd) && *mtdDrv); mtdDrv++) {
		DB(pr_info
			("[SFC] Using %s probe %s at addr 0x%llx,size 0x%x, width %dm\n",
			*mtdDrv, map->name, (u64) map->phys,
			(unsigned int)map->size, map->bankwidth));

		*mtd = sflash_probe(map, sfc_regres);
		if (*mtd) {
			(*mtd)->owner = THIS_MODULE;

			if (mtd_device_register(*mtd, NULL, 0)) {
				pr_err("probe: Failed to add the mtd device\n");
				iounmap((void *)map->virt);
				map->virt = 0;
				return -ENXIO;
			}

			return HRD_OK;
		}
		DB(pr_info("[SFC] - Not detected\n"));
	}

	return HRD_ERR;
}

static int __init hrd_flashProbe(const char **mtdDrv, struct map_info *map,
													 struct resource *sfc_regres, struct mtd_info **mtd)
{
	int ret;

	if ((mtdDrv == NULL)
		|| (map == NULL)
		|| (mtd == NULL)) {
		pr_err("[SFC] ERROR: NULL pointer parameter at %s entry\n", __func__);
		return -EINVAL;
	}

	map->virt = ioremap(map->phys, map->size);
	if (!map->virt) {
		pr_err("[SFC] Failed ioremap Flash device at base 0x%x.\n",
			   (unsigned int)map->phys);
		return -EIO;
	}

	DB(pr_info
		("[SFC] Io remapped ok.phy addr:0x%llx, virt addr:0x%llx\n",
		(u64) map->phys, (u64) map->virt));

	/* Skip bankwidths that are not supported */
	if (!map_bankwidth_supported(map->bankwidth)) {
		pr_err("[SFC] ERROR: bankwidth %d not supported.\n",
			   (unsigned int)map->bankwidth);
		iounmap((void *)map->virt);
		return -EIO;
	}

	ret = _hrd_flashProbe(mtdDrv, map, sfc_regres, mtd);
	if (ret == HRD_OK)
		return 0;

	iounmap((void *)map->virt);
	map->virt = 0;
	pr_err("[SFC] ERROR: %s - probe failed\n", __func__);

	return -ENXIO;
}

static int flash_map_init(struct platform_device *pdev)
{
	u32 i;
	u32 mapsNum;
	struct device *dev = &pdev->dev;
	struct resource *sfc_regres = NULL;
	struct resource *flash_iores = NULL;
	struct sfc_host *host = NULL;

	pr_info("SFC Driver\n");
	host = devm_kzalloc(dev, sizeof(struct sfc_host), GFP_KERNEL);
	if (!host) {
		pr_err("[SFC] ERROR: %s devm_kzalloc failed\n", __func__);
		return -ENOMEM;
	}

	sfc_regres = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	flash_iores = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!sfc_regres || !flash_iores)
		return -EFAULT;

	if (sfc_regres->end <= sfc_regres->start) {
		pr_err("ERROR: sfc register error\n");
		return -EFAULT;
	}

	if (flash_iores->end <= flash_iores->start) {
		pr_err("[SFC] ERROR: flash addr error\n");
		return -EFAULT;
	}

	mapsNum = hrd_flash_info_fill(host->maps, flash_iores, pdev);
	DB(pr_info("[SFC] INFO:  DEtected %d devices\n", mapsNum));

	for (i = 0; i < mapsNum; i++) {
		DB(pr_info("[SFC] MTD: Initialize the %s device at address 0x%08x\n",
			host->maps[i].mapInfo.name, (unsigned int)host->maps[i].mapInfo.phys));

		if (hrd_flashProbe
			(host->maps[i].mtdDrv, &host->maps[i].mapInfo, sfc_regres,
			 &host->maps[i].mtdInfo) == 0) {
			DB(pr_info("[SFC]- OK.\n"));
		} else {
			host->maps[i].mtdInfo = NULL;
			DB(pr_err(" [SFC]- FAILED!\n"));
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
		if (host->maps[i].mtdInfo)
			(void)mtd_device_unregister(host->maps[i].mtdInfo);

		if (host->maps[i].mapInfo.virt) {
			iounmap((void *)host->maps[i].mapInfo.virt);
			host->maps[i].mapInfo.virt = 0;
		}

		if (host->maps[i].mtdInfo)
			sflash_destroy(host->maps[i].mtdInfo);
	}

}

static int hisi_sfc_probe(struct platform_device *pdev)
{
	return flash_map_init(pdev);
}

static int hisi_sfc_remove(struct platform_device *pdev)
{
	flash_map_exit(pdev);

	return 0;
}

static const struct acpi_device_id g_sfc_acpi_match[] = {
	{"HISI0343", 0},
	{}
};

MODULE_DEVICE_TABLE(acpi, g_sfc_acpi_match);

static struct platform_driver g_hisi_sfc_driver = {
	.probe = hisi_sfc_probe,
	.remove = hisi_sfc_remove,
	.driver = {
		.name = "hisi_sfc",
		.acpi_match_table = ACPI_PTR(g_sfc_acpi_match),
	},
};

module_platform_driver(g_hisi_sfc_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("Hi16xx SFC driver");
MODULE_VERSION(SFC_DRIVER_VERSION);


