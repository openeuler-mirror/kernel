// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2026. All rights reserved.
 *
 * Description: uburma device number management
 */

#include <linux/bitmap.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/string.h>

#include "ub/urma/ubcore_types.h"

#include "uburma_log.h"
#include "uburma_devnum.h"

#define UBURMA_DRIVER_TYPE_BITS 3
#define UBURMA_DRIVER_TYPE_MASK ((1U << UBURMA_DRIVER_TYPE_BITS) - 1)
#define UBURMA_STATIC_HIGH_NUM 8192
#define UBURMA_STATIC_DEVICE_NUM \
	(UBURMA_STATIC_HIGH_NUM << UBURMA_DRIVER_TYPE_BITS)
#define UBURMA_STATIC_MAJOR 120
#define UBURMA_DYNAMIC_DEVICE_NUM 1024
#define UBURMA_MODULE_NAME "uburma"

#define UBURMA_UDMA_DRIVER_NAME "udma"
#define UBURMA_UDMA_CHIP_NUM 4
#define UBURMA_UDMA_DIE_NUM 4
#define UBURMA_UDMA_ENTITY_NUM 512

#define UBURMA_UBAGG_DRIVER_NAME "ub_agg"
#define UBURMA_UBAGG_DEV_PREFIX "bonding_dev_"

enum uburma_driver_type {
	UBURMA_DRIVER_UNKNOWN,
	UBURMA_DRIVER_UDMA,
	UBURMA_DRIVER_UBAGG,
};

static bool g_uburma_static_devnum;
module_param_named(static_devnum, g_uburma_static_devnum, bool, 0444);
MODULE_PARM_DESC(static_devnum,
		 "Use a static major and stable per-device minor numbers");

static DECLARE_BITMAP(g_dev_bitmap, UBURMA_DYNAMIC_DEVICE_NUM);
static dev_t g_uburma_dev;

static enum uburma_driver_type
uburma_get_driver_type(const struct ubcore_device *ubc_dev)
{
	if (!ubc_dev->ops)
		return UBURMA_DRIVER_UNKNOWN;

	if (!strcmp(ubc_dev->ops->driver_name, UBURMA_UDMA_DRIVER_NAME))
		return UBURMA_DRIVER_UDMA;

	if (!strcmp(ubc_dev->ops->driver_name, UBURMA_UBAGG_DRIVER_NAME))
		return UBURMA_DRIVER_UBAGG;

	return UBURMA_DRIVER_UNKNOWN;
}

static int uburma_parse_udma_high(const char *dev_name, unsigned int *high)
{
	char canonical[UBCORE_MAX_DEV_NAME];
	unsigned int chip;
	unsigned int die;
	unsigned int entity;
	char tail;

	if (sscanf(dev_name, "udmac%ud%ue%u%c", &chip, &die, &entity,
		   &tail) == 3) {
		if (chip >= UBURMA_UDMA_CHIP_NUM ||
		    die >= UBURMA_UDMA_DIE_NUM ||
		    entity >= UBURMA_UDMA_ENTITY_NUM)
			return -ERANGE;

		scnprintf(canonical, sizeof(canonical), "udmac%ud%ue%u", chip,
			  die, entity);
		if (strcmp(dev_name, canonical))
			return -EINVAL;

		*high = (chip * UBURMA_UDMA_DIE_NUM + die) *
			UBURMA_UDMA_ENTITY_NUM + entity;
		return 0;
	}

	if (sscanf(dev_name, "udma%u%c", &entity, &tail) != 1)
		return -EINVAL;

	if (entity >= UBURMA_STATIC_HIGH_NUM)
		return -ERANGE;

	scnprintf(canonical, sizeof(canonical), "udma%u", entity);
	if (strcmp(dev_name, canonical))
		return -EINVAL;

	*high = entity;
	return 0;
}

static int uburma_parse_ubagg_high(const char *dev_name, unsigned int *high)
{
	char canonical[UBCORE_MAX_DEV_NAME];
	const char *suffix;
	int ret;

	if (strncmp(dev_name, UBURMA_UBAGG_DEV_PREFIX,
		    strlen(UBURMA_UBAGG_DEV_PREFIX)))
		return -EINVAL;

	suffix = dev_name + strlen(UBURMA_UBAGG_DEV_PREFIX);
	ret = kstrtouint(suffix, 10, high);
	if (ret)
		return ret;

	if (*high >= UBURMA_STATIC_HIGH_NUM)
		return -ERANGE;

	scnprintf(canonical, sizeof(canonical), "%s%u",
		  UBURMA_UBAGG_DEV_PREFIX, *high);
	if (strcmp(dev_name, canonical))
		return -EINVAL;

	return 0;
}

static int uburma_parse_static_minor(const struct ubcore_device *ubc_dev,
				     unsigned int *minor)
{
	enum uburma_driver_type driver_type;
	unsigned int high = 0;
	int ret = 0;

	if (!ubc_dev || !minor)
		return -EINVAL;

	driver_type = uburma_get_driver_type(ubc_dev);
	if (driver_type == UBURMA_DRIVER_UDMA)
		ret = uburma_parse_udma_high(ubc_dev->dev_name, &high);
	else if (driver_type == UBURMA_DRIVER_UBAGG)
		ret = uburma_parse_ubagg_high(ubc_dev->dev_name, &high);
	else
		return -EOPNOTSUPP;

	if (ret)
		return ret;

	*minor = (high << UBURMA_DRIVER_TYPE_BITS) | driver_type;
	return 0;
}

static int uburma_static_devnum_init(void)
{
	int ret;

	g_uburma_dev = MKDEV(UBURMA_STATIC_MAJOR, 0);
	ret = register_chrdev_region(g_uburma_dev, UBURMA_STATIC_DEVICE_NUM,
				     UBURMA_MODULE_NAME);
	if (ret == 0)
		return 0;

	uburma_log_warn("static major %u unavailable, allocating a dynamic major.\n",
			UBURMA_STATIC_MAJOR);
	return alloc_chrdev_region(&g_uburma_dev, 0, UBURMA_STATIC_DEVICE_NUM,
				   UBURMA_MODULE_NAME);
}

int uburma_devnum_init(void)
{
	int ret;

	if (g_uburma_static_devnum)
		return uburma_static_devnum_init();

	ret = alloc_chrdev_region(&g_uburma_dev, 0, UBURMA_DYNAMIC_DEVICE_NUM,
				  UBURMA_MODULE_NAME);
	if (ret != 0)
		uburma_log_err("couldn't register dynamic device number.\n");

	return ret;
}

void uburma_devnum_exit(void)
{
	unsigned int count = g_uburma_static_devnum ?
		UBURMA_STATIC_DEVICE_NUM : UBURMA_DYNAMIC_DEVICE_NUM;

	unregister_chrdev_region(g_uburma_dev, count);
}

static int uburma_dynamic_minor_alloc(unsigned int *minor)
{
	*minor = (unsigned int)find_first_zero_bit(g_dev_bitmap,
						   UBURMA_DYNAMIC_DEVICE_NUM);
	if (*minor >= UBURMA_DYNAMIC_DEVICE_NUM)
		return -ENOSPC;

	set_bit(*minor, g_dev_bitmap);
	return 0;
}

static int uburma_static_devnum_alloc(const struct ubcore_device *ubc_dev,
				      dev_t *devt)
{
	unsigned int minor;
	int ret;

	ret = uburma_parse_static_minor(ubc_dev, &minor);
	if (ret != 0) {
		uburma_log_warn("static minor unavailable for %s, ret:%d; using default segment.\n",
				ubc_dev->dev_name, ret);
		ret = uburma_dynamic_minor_alloc(&minor);
		if (ret != 0)
			return ret;

		minor = (minor << UBURMA_DRIVER_TYPE_BITS) |
			UBURMA_DRIVER_UNKNOWN;
	}

	if (minor >= UBURMA_STATIC_DEVICE_NUM) {
		uburma_log_err(
			"static minor %u for device:%s is out of range.\n",
			minor, ubc_dev->dev_name);
		return -ERANGE;
	}

	*devt = MKDEV(MAJOR(g_uburma_dev), minor);
	return 0;
}

int uburma_devnum_alloc(const struct ubcore_device *ubc_dev, dev_t *devt)
{
	unsigned int minor;
	int ret;

	if (g_uburma_static_devnum)
		return uburma_static_devnum_alloc(ubc_dev, devt);

	ret = uburma_dynamic_minor_alloc(&minor);
	if (ret != 0)
		return ret;

	*devt = g_uburma_dev + minor;
	return 0;
}

void uburma_devnum_free(unsigned int minor)
{
	if (g_uburma_static_devnum) {
		if ((minor & UBURMA_DRIVER_TYPE_MASK) != UBURMA_DRIVER_UNKNOWN)
			return;

		minor >>= UBURMA_DRIVER_TYPE_BITS;
	}

	if (minor < UBURMA_DYNAMIC_DEVICE_NUM)
		clear_bit(minor, g_dev_bitmap);
}
