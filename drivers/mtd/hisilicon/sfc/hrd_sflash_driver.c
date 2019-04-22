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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/console.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/mtd/map.h>
#include <linux/mtd/mtd.h>
#include <linux/mutex.h>
#include <linux/version.h>

#include "hrdCommon.h"

#include "hrd_sflash_driver.h"
#include "hrd_sflash_hal.h"

#ifdef MTD_SFLASH_DEBUG
#define DB_LOCAL(x) x
#else
#define DB_LOCAL(x)
#endif

#define sflash_disable_irqs(flags, sflash_in_irq) \
	do {						\
		sflash_in_irq = in_interrupt();	 \
		if (!sflash_in_irq) \
			local_irq_save(flags);	  \
	} while (0)

#define sflash_enable_irqs(flags, sflash_in_irq) \
	do {						\
		if (!sflash_in_irq) \
			local_irq_restore(flags);   \
	} while (0)

static int sflash_read(struct mtd_info *mtd, loff_t from, size_t len,
			   size_t *retlen, u_char *buf);
static int sflash_write(struct mtd_info *mtd, loff_t from, size_t len,
			size_t *retlen, const u_char *buf);
static int sflash_erase(struct mtd_info *mtd, struct erase_info *instr);
static void sflash_sync(struct mtd_info *mtd);
static int sflash_suspend(struct mtd_info *mtd);
static void sflash_resume(struct mtd_info *mtd);
static int sflash_lock(struct mtd_info *mtd, loff_t ofs, uint64_t len);
static int sflash_unlock(struct mtd_info *mtd, loff_t ofs, uint64_t len);
static int sflash_block_isbad(struct mtd_info *mtd, loff_t ofs);
static int sflash_block_markbad(struct mtd_info *mtd, loff_t ofs);

struct mtd_info *sflash_probe(struct map_info *map, struct resource *sfc_regres)
{
	struct mtd_info *mtd;
	struct SFC_SFLASH_INFO *sflash;
	unsigned long flags = 0, sflash_in_irq = 0;

	DB_LOCAL(pr_info("\nINFO: entering %s", __func__));

	mtd = kmalloc(sizeof(*mtd), GFP_KERNEL);

	if (!mtd) {
		pr_err(KERN_NOTICE
			   "\nERROR: %s - Failed to allocate memory for mtd structure",
			   __func__);
		return NULL;
	}

	sflash = kmalloc(sizeof(struct SFC_SFLASH_INFO), GFP_KERNEL);

	if (!sflash) {
		pr_err(KERN_NOTICE
			   "\nERROR: %s - Failed to allocate memory for sflash structure",
			   __func__);
		kfree(mtd);
		return NULL;
	}

	memset(mtd, 0, sizeof(*mtd));
	memset(sflash, 0, sizeof(*sflash));

	DB_LOCAL(pr_info
		 ("\nINFO: %s - Base address %llx\n", __func__, map->phys));

	sflash->baseAddr = (u64) ioremap(map->phys, map->size);

	if (!sflash->baseAddr) {
		pr_err(KERN_NOTICE
			   "\nERROR: %s - map flash error\r\n", __func__);
		goto exit0;
	}

	sflash->sfc_reg_base =
		(u64) ioremap_nocache(sfc_regres->start, resource_size(sfc_regres));

	if (!sflash->sfc_reg_base) {
		pr_err(KERN_NOTICE
			   "\nERROR: %s - map register error\r\n", __func__);

		goto exit1;
	}

	mutex_init(&sflash->lock);

	sflash->index = INVALID_DEVICE_NUMBER;	/* will be detected in init */
	sflash_disable_irqs(flags, sflash_in_irq);

	if (hrd_sflash_init(sflash) != HRD_OK) {
		sflash_enable_irqs(flags, sflash_in_irq);
		pr_err(KERN_NOTICE
			   "ERROR: %s - Failed to initialize the SFlash.",
			   __func__);
		goto exit2;
	}

	sflash_enable_irqs(flags, sflash_in_irq);

	mtd->erasesize = sflash->sectorSize;
	mtd->size = (u64) sflash->sectorSize * (u64) sflash->sectorNumber;
	mtd->priv = map;
	mtd->type = MTD_NORFLASH;
	mtd->_erase = sflash_erase;
	mtd->_read = sflash_read;
	mtd->_write = sflash_write;
	mtd->_sync = sflash_sync;
	mtd->_suspend = sflash_suspend;
	mtd->_resume = sflash_resume;
	mtd->_lock = sflash_lock;
	mtd->_unlock = sflash_unlock;
	mtd->_block_isbad = sflash_block_isbad;
	mtd->_block_markbad = sflash_block_markbad;
	/* just like MTD_CAP_NORFLASH */
	mtd->flags = (MTD_WRITEABLE | MTD_BIT_WRITEABLE);
	mtd->name = map->name;
	mtd->writesize = 1;

	map->fldrv_priv = sflash;

	DB_LOCAL(pr_info
		 ("\nINFO: %s - Detected SFlash device (size 0x%llx)", __func__,
		  mtd->size));
	DB_LOCAL(pr_info
		 ("\n Base Address : 0x%llx", sflash->baseAddr));
	DB_LOCAL(pr_info
		 ("\n Manufacturer ID : 0x%02x",
		  sflash->manufacturerId));
	DB_LOCAL(pr_info
		 ("\n Device ID : 0x%04x", sflash->deviceId));
	DB_LOCAL(pr_info
		 ("\n Sector Size : 0x%x", sflash->sectorSize));
	DB_LOCAL(pr_info
		 ("\n Sector Number : %d", sflash->sectorNumber));

	pr_info("SPI Serial flash detected @ 0x%08llx, %dKB (%dsec x %dKB)\n",
		sflash->baseAddr,
		((sflash->sectorNumber * sflash->sectorSize) / 1024),
		sflash->sectorNumber, (sflash->sectorSize / 1024));

	__module_get(THIS_MODULE);
	return mtd;

 exit0:
	kfree(mtd);
	kfree(sflash);
	return NULL;
 exit1:
	iounmap((void *)sflash->baseAddr);
	kfree(mtd);
	kfree(sflash);
	return NULL;
 exit2:
	iounmap((void *)sflash->baseAddr);
	iounmap((void *)sflash->sfc_reg_base);
	kfree(mtd);
	kfree(sflash);
	return NULL;
}

void sflash_destroy(struct mtd_info *mtd)
{
	struct map_info *map = mtd->priv;
	struct SFC_SFLASH_INFO *sflash = map->fldrv_priv;

	DB_LOCAL(pr_info("\nINFO: %s called", __func__));

	if (sflash->baseAddr != 0)
		iounmap((void *)sflash->baseAddr);

	if (sflash->sfc_reg_base != 0)
		iounmap((void *)sflash->sfc_reg_base);

	kfree(mtd);
	kfree(sflash);
}

static int sflash_read(struct mtd_info *mtd, loff_t from, size_t len,
			   size_t *retlen, u_char *buf)
{
	struct map_info *map = mtd->priv;
	struct SFC_SFLASH_INFO *sflash = map->fldrv_priv;
	u32 offset = ((u32) from);
	int ret;

	*retlen = 0;

	DB_LOCAL(pr_info
		 ("\nINFO: %s - offset %08x, len %d", __func__, offset,
		  (int)len));

	mutex_lock(&sflash->lock);

	switch (sflash->rw_mode) {
	case SFC_REGISTER_RW_MODE:
		ret = SFC_RegModeRead(sflash, offset, (u8 *) buf, (u32) len);
		break;

	case SFC_BUS_RW_MODE:
		ret = SFC_BusModeRead(sflash, offset, (u8 *) buf, (u32) len);
		break;

	default:
		pr_err(KERN_NOTICE "\nERROR: %s - rw mode error", __func__);
		ret = -1;

	}

	if (ret != HRD_OK) {

		mutex_unlock(&sflash->lock);
		pr_err(KERN_NOTICE "\nERROR: %s - Failed to read block",
			   __func__);
		return -1;
	}

	mutex_unlock(&sflash->lock);

	*retlen = len;

	DB_LOCAL(pr_info(" - OK"));
	return 0;
}

static int sflash_write(struct mtd_info *mtd, loff_t to, size_t len,
			size_t *retlen, const u_char *buf)
{
	struct map_info *map = mtd->priv;
	struct SFC_SFLASH_INFO *sflash = map->fldrv_priv;
	u32 offset = ((u32) to);
	int ret;

	*retlen = 0;

	DB_LOCAL(pr_info("\nINFO: %s-offset %08x, len %d",
			 __func__, offset, (u32) len));

	mutex_lock(&sflash->lock);

	switch (sflash->rw_mode) {
	case SFC_REGISTER_RW_MODE:
		ret = SFC_RegModeWrite(sflash, offset, buf, (u32) len);
		break;

	case SFC_BUS_RW_MODE:
		ret = SFC_BusModeWrite(sflash, offset, buf, (u32) len);
		break;

	default:
		pr_err(KERN_NOTICE "\nERROR: %s - rw mode error", __func__);
		ret = -1;
	}

	if (ret != HRD_OK) {

		mutex_unlock(&sflash->lock);
		pr_err(KERN_NOTICE "\nERROR: %s - Failed to write block",
			   __func__);
		return -1;
	}

	mutex_unlock(&sflash->lock);

	*retlen = len;

	DB_LOCAL(pr_info(" - OK"));
	return 0;

}

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

static int sflash_erase(struct mtd_info *mtd, struct erase_info *instr)
{
	struct map_info *map = mtd->priv;
	struct SFC_SFLASH_INFO *sflash = map->fldrv_priv;
	u64 fsec, lsec;
	u64 i;

	DB_LOCAL(pr_info
		 ("\nINFO: %s - Addr %08llx, len %lld", __func__, instr->addr,
		  instr->len));

	if (!sflash) {
		pr_err("\nError: sflash is NULL");
		return -EINVAL;
	}

	if (instr->addr & (mtd->erasesize - 1)) {
		pr_err("\nError: %s - Erase address not sector alligned",
			   __func__);
		return -EINVAL;
	}

	if (instr->len & (mtd->erasesize - 1)) {
		pr_err("\nError: %s - Erase length is not sector alligned",
			   __func__);
		return -EINVAL;
	}

	if (instr->len + instr->addr > mtd->size) {
		pr_err("\nError: %s - Erase exceeded flash size", __func__);
		return -EINVAL;
	}

	if (0 != SFC_ControllerAddrModeSet(sflash)) {
		pr_err("\nError: %s - SFC_ControllerAddrModeSet %d failed",
			   __func__, sflash->addr_mode);
		return -1;
	}

	{
		fsec = instr->addr;
		do_div(fsec, 4 * 1024);
		lsec = MIN(instr->addr + instr->len, 64 * 1024);
		do_div(lsec, 4 * 1024);

		if (fsec < lsec) {
			pr_info("\nINFO: %s - for 4K from sector %lld to %lld",
				__func__, fsec, lsec - 1);
			mutex_lock(&sflash->lock);

			for (i = fsec; i < lsec; i++) {
				if (SFC_BlockErase
					(sflash, ((u32) i) * 0x1000,
					 0x20) != HRD_OK) {

					mutex_unlock(&sflash->lock);
					pr_err
						("\nError: %s - mvSFlashSectorErase on sector %lld",
						 __func__, i);
					return -1;
				}
			}

			mutex_unlock(&sflash->lock);
		}
	}

	fsec = instr->addr;
	do_div(fsec, mtd->erasesize);
	lsec = instr->len;
	do_div(lsec, mtd->erasesize);
	lsec = (fsec + lsec);

	DB_LOCAL(pr_info("\nINFO: %s - from sector %u to %u", __func__, fsec,
			 lsec - 1));

	mutex_lock(&sflash->lock);

	for (i = fsec; i < lsec; i++) {
		if (SFC_BlockErase(sflash, ((u32) i) * mtd->erasesize, 0) !=
			HRD_OK) {

			mutex_unlock(&sflash->lock);
			pr_err
				("\nError: %s - mvSFlashSectorErase on sector %lld",
				 __func__, i);
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
			instr->fail_addr = ((u32) i) * mtd->erasesize;
#endif

			return -1;
		}
	}

	mutex_unlock(&sflash->lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
	instr->state = MTD_ERASE_DONE;
	mtd_erase_callback(instr);
#endif

	return 0;
}

static int sflash_lock(struct mtd_info *mtd, loff_t ofs, uint64_t len)
{
	int ret;
	struct map_info *map = mtd->priv;
	struct SFC_SFLASH_INFO *sflash = map->fldrv_priv;

	DB_LOCAL(pr_info("\nINFO: %s called", __func__));

	mutex_lock(&sflash->lock);
	ret = SFC_WPSet(sflash, 1);
	mutex_unlock(&sflash->lock);

	return ret;
}

static int sflash_unlock(struct mtd_info *mtd, loff_t ofs, uint64_t len)
{
	int ret;
	struct map_info *map = mtd->priv;
	struct SFC_SFLASH_INFO *sflash = map->fldrv_priv;

	pr_info("\nINFO: %s called", __func__);

	mutex_lock(&sflash->lock);
	ret = SFC_WPSet(sflash, 0);
	mutex_unlock(&sflash->lock);

	return ret;
}

static void sflash_sync(struct mtd_info *mtd)
{
	DB_LOCAL(pr_info("\nINFO: %s called - DUMMY", __func__));
}

static int sflash_suspend(struct mtd_info *mtd)
{
	DB_LOCAL(pr_info("\nINFO: %s called - DUMMY()", __func__));
	return 0;
}

static void sflash_resume(struct mtd_info *mtd)
{
	DB_LOCAL(pr_info("\nINFO: %s called - DUMMY", __func__));
}

static int sflash_block_isbad(struct mtd_info *mtd, loff_t ofs)
{
	DB_LOCAL(pr_info("\nINFO: %s called - DUMMY", __func__));
	return 0;
}

static int sflash_block_markbad(struct mtd_info *mtd, loff_t ofs)
{
	DB_LOCAL(pr_info("\nINFO: %s called - DUMMY", __func__));
	return 0;
}
