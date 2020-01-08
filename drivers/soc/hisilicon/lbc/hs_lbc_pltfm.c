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
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/spinlock.h>
#include <linux/of_address.h>
#include <linux/acpi.h>

#include "hs_lbc_pltfm.h"

#define LBC_DRIVER_VERSION  "1.9.30.0"

struct hisi_lbc_dev g_lbc_dev = {0};

static void lbc_set_cs_base_addr(unsigned int index, unsigned int cs_base_addr)
{
	LBC_REG_REGION *lbc_reg = (LBC_REG_REGION *)(ACCESS_ONCE(g_lbc_dev.regs_base));

	lbc_reg->cs_base[index] = cs_base_addr;
}

static void lbc_set_cs_data_width(unsigned int index, unsigned int width)
{
	LBC_REG_REGION *lbc_reg = (LBC_REG_REGION *)(ACCESS_ONCE(g_lbc_dev.regs_base));

	lbc_reg->cs_ctrl[index].data_width = width;
}

static void lbc_set_cs_data_offset(unsigned int index, unsigned int offset)
{
	LBC_REG_REGION *lbc_reg = (LBC_REG_REGION *)(ACCESS_ONCE(g_lbc_dev.regs_base));

	lbc_reg->cs_ctrl[index].addr_offset = offset;
}

static void lbc_set_cs_mem_size(unsigned int index, u64 mem_size)
{
	unsigned int size = 0;
	LBC_REG_REGION *lbc_reg = (LBC_REG_REGION *)(ACCESS_ONCE(g_lbc_dev.regs_base));

	switch (mem_size) {
	case LBC_CS_MEM_SIZE_0:
		size = LBC_CS_MEM_SIZE_REG_0;
		break;
	case LBC_CS_MEM_SIZE_64K:
		size = LBC_CS_MEM_SIZE_REG_64K;
		break;
	case LBC_CS_MEM_SIZE_128K:
		size = LBC_CS_MEM_SIZE_REG_128K;
		break;
	case LBC_CS_MEM_SIZE_256K:
		size = LBC_CS_MEM_SIZE_REG_256K;
		break;
	case LBC_CS_MEM_SIZE_512K:
		size = LBC_CS_MEM_SIZE_REG_512K;
		break;
	case LBC_CS_MEM_SIZE_1M:
		size = LBC_CS_MEM_SIZE_REG_1M;
		break;
	case LBC_CS_MEM_SIZE_2M:
		size = LBC_CS_MEM_SIZE_REG_2M;
		break;
	case LBC_CS_MEM_SIZE_4M:
		size = LBC_CS_MEM_SIZE_REG_4M;
		break;
	case LBC_CS_MEM_SIZE_8M:
		size = LBC_CS_MEM_SIZE_REG_8M;
		break;
	case LBC_CS_MEM_SIZE_16M:
		size = LBC_CS_MEM_SIZE_REG_16M;
		break;
	case LBC_CS_MEM_SIZE_32M:
		size = LBC_CS_MEM_SIZE_REG_32M;
		break;
	case LBC_CS_MEM_SIZE_64M:
		size = LBC_CS_MEM_SIZE_REG_64M;
		break;
	case LBC_CS_MEM_SIZE_128M:
		size = LBC_CS_MEM_SIZE_REG_128M;
		break;
	case LBC_CS_MEM_SIZE_256M:
		size = LBC_CS_MEM_SIZE_REG_256M;
		break;
	default:
		size = 0;
	}

	lbc_reg->cs_ctrl[index].mem_size = size;
}

static int hisi_lbc_para_check(unsigned int index, unsigned int offset, unsigned int type)
{
	/* cs index check */
	if (index >= LBC_CS_MAX_NUM)
		return -EINVAL;

	/* cs offset check */
	if (offset >= g_lbc_dev.cs[index].size)
		return -EINVAL;

	if (type !=  LBC_RWDATA_WIDTH_8
		&& type !=  LBC_RWDATA_WIDTH_16
		&& type != LBC_RWDATA_WIDTH_32)
		return -EINVAL;

	/* width check */
	if ((type == LBC_RWDATA_WIDTH_16)
		|| (type == LBC_RWDATA_WIDTH_32)) {

		if (offset % (type * 0x2))
			return -EINVAL;
	}

	return 0;
}

static unsigned int lbc_read(unsigned int index, unsigned int offset, unsigned int type)
{
	void __iomem *base_addr = ACCESS_ONCE(g_lbc_dev.cs[index].cs_base);
	unsigned int value;
	unsigned long flags;

	spin_lock_irqsave(&g_lbc_dev.cs[index].lock, flags);

	if (type == LBC_RWDATA_WIDTH_8)
		value = readb(base_addr + offset) & 0xff;
	else if (type == LBC_RWDATA_WIDTH_16)
		value = readw(base_addr + offset) & 0xffff;
	else
		value = readl(base_addr + offset) & 0xffffffff;

	spin_unlock_irqrestore(&g_lbc_dev.cs[index].lock, flags);

	return value;

}

static unsigned int lbc_read_unlock(unsigned int index, unsigned int offset, unsigned int type)
{
	void __iomem *base_addr = ACCESS_ONCE(g_lbc_dev.cs[index].cs_base);
	unsigned int value;

	if (type == LBC_RWDATA_WIDTH_8)
		value = readb(base_addr + offset) & 0xff;
	else if (type == LBC_RWDATA_WIDTH_16)
		value = readw(base_addr + offset) & 0xffff;
	else
		value = readl(base_addr + offset) & 0xffffffff;

	return value;

}

static int lbc_write(unsigned int index, unsigned int offset, unsigned int type, unsigned int data)
{
	void __iomem *base_addr = ACCESS_ONCE(g_lbc_dev.cs[index].cs_base);
	unsigned long flags;

	spin_lock_irqsave(&g_lbc_dev.cs[index].lock, flags);

	if (type == LBC_RWDATA_WIDTH_8)
		writeb(data & 0xff, base_addr + offset);
	else if (type == LBC_RWDATA_WIDTH_16)
		writew(data & 0xffff, base_addr + offset);
	else
		writel(data & 0xffffffff, base_addr + offset);

	spin_unlock_irqrestore(&g_lbc_dev.cs[index].lock, flags);

	return 0;
}

static int lbc_write_unlock(unsigned int index, unsigned int offset, unsigned int type, unsigned int data)
{
	void __iomem *base_addr = ACCESS_ONCE(g_lbc_dev.cs[index].cs_base);

	if (type == LBC_RWDATA_WIDTH_8)
		writeb(data & 0xff, base_addr + offset);
	else if (type == LBC_RWDATA_WIDTH_16)
		writew(data & 0xffff, base_addr + offset);
	else
		writel(data & 0xffffffff, base_addr + offset);

	return 0;
}

int lbc_read8(unsigned int index, unsigned int offset, unsigned char *value)
{
	/* para check */
	if (hisi_lbc_para_check(index, offset, LBC_RWDATA_WIDTH_8)) {
		pr_err("Lbc para check failed\n");
		return -EINVAL;
	}

	if (!value) {
		pr_err("value is null\n");
		return -EINVAL;
	}

	*value = (unsigned char)lbc_read(index, offset, LBC_RWDATA_WIDTH_8);

	return 0;
}
EXPORT_SYMBOL(lbc_read8);

int lbc_read8_nolock(unsigned int index, unsigned int offset, unsigned char *value)
{
	/* para check */
	if (hisi_lbc_para_check(index, offset, LBC_RWDATA_WIDTH_8)) {
		pr_err("Lbc para check failed\n");
		return -EINVAL;
	}

	if (!value) {
		pr_err("value is null\n");
		return -EINVAL;
	}

	*value = (unsigned char)lbc_read_unlock(index, offset, LBC_RWDATA_WIDTH_8);
	return 0;
}
EXPORT_SYMBOL(lbc_read8_nolock);

unsigned short lbc_read16(unsigned int index, unsigned int offset)
{
	/* para check */
	if (hisi_lbc_para_check(index, offset, LBC_RWDATA_WIDTH_16)) {
		pr_err("Lbc para check failed\n");
		return 0;
	}

	return (unsigned short)lbc_read(index, offset, LBC_RWDATA_WIDTH_16);
}

unsigned int lbc_read32(unsigned int index, unsigned int offset)
{
	/* para check */
	if (hisi_lbc_para_check(index, offset, LBC_RWDATA_WIDTH_32)) {
		pr_err("Lbc para check failed\n");
		return 0;
	}

	return lbc_read(index, offset, LBC_RWDATA_WIDTH_32);
}

int lbc_write8(unsigned int index, unsigned int offset, unsigned char data)
{
	/* para check */
	if (hisi_lbc_para_check(index, offset, LBC_RWDATA_WIDTH_8)) {
		pr_err("Lbc para check failed\n");
		return -EINVAL;
	}

	return lbc_write(index, offset, LBC_RWDATA_WIDTH_8, (unsigned int)data);
}
EXPORT_SYMBOL(lbc_write8);

int lbc_write8_nolock(unsigned int index, unsigned int offset, unsigned char data)
{
	/* para check */
	if (hisi_lbc_para_check(index, offset, LBC_RWDATA_WIDTH_8)) {
		pr_err("Lbc para check failed\n");
		return -EINVAL;
	}

	return lbc_write_unlock(index, offset, LBC_RWDATA_WIDTH_8, (unsigned int)data);
}
EXPORT_SYMBOL(lbc_write8_nolock);

int lbc_write16(unsigned int index, unsigned int offset, unsigned short data)
{

	/* para check */
	if (hisi_lbc_para_check(index, offset, LBC_RWDATA_WIDTH_16)) {
		pr_err("Lbc para check failed\n");
		return -EINVAL;
	}

	return lbc_write(index, offset, LBC_RWDATA_WIDTH_16, (unsigned int)data);
}

int lbc_write32(unsigned int index, unsigned int offset, unsigned int data)
{

	/* para check */
	if (hisi_lbc_para_check(index, offset, LBC_RWDATA_WIDTH_32)) {
		pr_err("Lbc para check failed\n");
		return -EINVAL;
	}

	return lbc_write(index, offset, LBC_RWDATA_WIDTH_32, (unsigned int)data);
}

static int hisi_lbc_cs_init(struct platform_device *pdev)
{
	unsigned int index;
	unsigned int width;
	unsigned int shift;
	struct resource *cs_base = NULL;

	if (has_acpi_companion(g_lbc_dev.dev)) {
		/* get cs index */
		index = 0;
		(void)device_property_read_u32(g_lbc_dev.dev, "index", &index);

		if (index >= LBC_CS_MAX_NUM) {
			dev_err(g_lbc_dev.dev, "Cs index error\n");
			return -EINVAL;
		}

		/* lock init */
		spin_lock_init(&g_lbc_dev.cs[index].lock);

		/* get cs base address */
		cs_base = platform_get_resource(pdev, IORESOURCE_MEM, 1);

		if (!cs_base) {
			dev_err(g_lbc_dev.dev, "Can not find this cs base resource\n");
			return -ENOENT;
		}

		g_lbc_dev.cs[index].cs_base = devm_ioremap_resource(&pdev->dev, cs_base);

		if (IS_ERR(g_lbc_dev.cs[index].cs_base))
			return (int)PTR_ERR(g_lbc_dev.cs[index].cs_base);

		g_lbc_dev.cs[index].size = (unsigned int)resource_size(cs_base);

		lbc_set_cs_base_addr(index, (unsigned int)cs_base->start);
		lbc_set_cs_mem_size(index, resource_size(cs_base));

		/* get cs width */
		width = 0;
		(void)device_property_read_u32(g_lbc_dev.dev, "width", &width);

		if (width > LBC_CS_WIDTH_32) {
			dev_err(g_lbc_dev.dev, "Cs width error\n");
			return -EINVAL;
		}

		g_lbc_dev.cs[index].width = width;
		lbc_set_cs_data_width(index, width);

		/* get cs address offset */
		shift = 0;
		(void)device_property_read_u32(g_lbc_dev.dev, "shift", &shift);

		if (shift > LBC_CS_ADDR_SHIFT_2) {
			dev_err(g_lbc_dev.dev, "Cs address shift error\n");
			return -EINVAL;
		}

		g_lbc_dev.cs[index].shift = shift;

		lbc_set_cs_data_offset(index, shift);

	}

	return 0;
}

static int hisi_lbc_probe(struct platform_device *pdev)
{
	int ret;
	struct resource *regs_base = NULL;

	dev_info(&pdev->dev, "hisi lbc probe\n");

	if ((!pdev->dev.of_node) && (!ACPI_COMPANION(&pdev->dev))) {
		dev_err(&pdev->dev, "Device OF-Node and ACPI-Node is NULL\n");
		return -EFAULT;
	}

	g_lbc_dev.dev = &pdev->dev;

	/* get resource num */
	regs_base = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	if (!g_lbc_dev.is_reg_remaped) {

		g_lbc_dev.regs_base = devm_ioremap_resource(&pdev->dev, regs_base);
		g_lbc_dev.is_reg_remaped = 1;
	}

	if (IS_ERR(g_lbc_dev.regs_base)) {
		dev_err(&pdev->dev, "ERROR: regbase\n");
		return (int)PTR_ERR(g_lbc_dev.regs_base);
	}

	/* localbus cs init */
	ret = hisi_lbc_cs_init(pdev);
	if (ret) {
		dev_err(&pdev->dev, "Localbus cs init failed\n");
		return -1;
	}

	platform_set_drvdata(pdev, &g_lbc_dev);
	dev_info(&pdev->dev, "hisi lbc probe prob ok\n");
	return 0;
}

static int hisi_lbc_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id g_hisi_lbc_pltfm_match[] = {
	{
		.compatible = "hisilicon, hi1620_lbc",
	},
	{},
};

#ifdef CONFIG_ACPI
static const struct acpi_device_id g_hisi_lbc_acpi_match[] = {
	{ "HISI0C01", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, g_hisi_lbc_acpi_match);
#endif

static struct platform_driver g_hisi_lbc_driver = {
	.probe = hisi_lbc_probe,
	.remove = hisi_lbc_remove,
	.driver = {
		.name = "hisi-lbc",
		.owner = THIS_MODULE,
		.of_match_table = g_hisi_lbc_pltfm_match,
#ifdef CONFIG_ACPI
		.acpi_match_table = ACPI_PTR(g_hisi_lbc_acpi_match),
#endif
	},

};

static int __init hisi_lbc_init_driver(void)
{
	return platform_driver_register((struct platform_driver *)&g_hisi_lbc_driver);
}

static void __exit hisi_lbc_exit_driver(void)
{
	platform_driver_unregister((struct platform_driver *)&g_hisi_lbc_driver);
}

module_init(hisi_lbc_init_driver);
module_exit(hisi_lbc_exit_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_VERSION(LBC_DRIVER_VERSION);
MODULE_DESCRIPTION("LBC driver for linux");
