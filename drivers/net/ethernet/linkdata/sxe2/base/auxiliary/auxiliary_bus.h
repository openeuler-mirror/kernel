/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: auxiliary_bus.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef _AUXILIARY_BUS_H_
#define _AUXILIARY_BUS_H_

#include <linux/pm_qos.h>
#include <linux/device.h>
#include <linux/mod_devicetable.h>
#include "auxiliary_compat.h"

#ifndef HAVE_AUXILIARY_DEVICE_ID
#define AUXILIARY_NAME_SIZE 32
#define AUXILIARY_MODULE_PREFIX "sxe2_auxiliary:"
struct auxiliary_device_id {
	char name[AUXILIARY_NAME_SIZE];
	kernel_ulong_t driver_data;
};
#endif

struct auxiliary_device {
	struct device dev;
	const char *name;
	u32 id;
};

struct auxiliary_driver {
	int (*probe)(struct auxiliary_device *auxdev, const struct auxiliary_device_id *id);
	void (*remove)(struct auxiliary_device *auxdev);
	void (*shutdown)(struct auxiliary_device *auxdev);
	int (*suspend)(struct auxiliary_device *auxdev, pm_message_t state);
	int (*resume)(struct auxiliary_device *auxdev);
	const char *name;
	struct device_driver driver;
	const struct auxiliary_device_id *id_table;
};

static inline struct auxiliary_device *to_auxiliary_dev(struct device *dev)
{
	return container_of(dev, struct auxiliary_device, dev);
}

static inline struct auxiliary_driver *to_auxiliary_drv(struct device_driver *drv)
{
	return container_of(drv, struct auxiliary_driver, driver);
}

int sxe2_auxiliary_device_init(struct auxiliary_device *auxdev);
#define auxiliary_device_init(auxdev)  sxe2_auxiliary_device_init(auxdev)

int __sxe2_auxiliary_device_add(struct auxiliary_device *auxdev, const char *modname);

#define auxiliary_device_add(auxdev) __sxe2_auxiliary_device_add(auxdev, KBUILD_MODNAME)

static inline void auxiliary_device_uninit(struct auxiliary_device *auxdev)
{
	put_device(&auxdev->dev);
}

static inline void auxiliary_device_delete(struct auxiliary_device *auxdev)
{
	device_del(&auxdev->dev);
}

int __sxe2_auxiliary_driver_register(struct auxiliary_driver *auxdrv, struct module *owner,
				     const char *modname);
#define auxiliary_driver_register(auxdrv) \
	__sxe2_auxiliary_driver_register(auxdrv, THIS_MODULE, KBUILD_MODNAME)

void sxe2_auxiliary_driver_unregister(struct auxiliary_driver *auxdrv);

#define auxiliary_driver_unregister(auxdrv)  sxe2_auxiliary_driver_unregister(auxdrv)

#define module_auxiliary_driver(__auxiliary_driver) \
	module_driver(__auxiliary_driver, auxiliary_driver_register, auxiliary_driver_unregister)

#ifndef NO_NEED_AUXILIARY_FIND_DEVICE_CONST_DATA
struct auxiliary_device *sxe2_auxiliary_find_device(struct device *start,
						    const void *data,
						    int (*match)(struct device *dev,
								 const void *data));
#else
struct auxiliary_device *sxe2_auxiliary_find_device(struct device *start,
						    void *data,
						    int (*match)(struct device *dev,
								 void *data));
#endif

#define auxiliary_find_device sxe2_auxiliary_find_device

#endif
