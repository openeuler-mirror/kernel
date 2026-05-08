/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __AUXILIARY_COMPAT_H__
#define __AUXILIARY_COMPAT_H__

#include <net/devlink.h>
#include <linux/netdevice.h>

#include "sxe2_compat_gcc.h"

#include "sxe2_compat_inc.h"

#include "sxe2_compat.h"

#ifdef NEED_BUS_FIND_DEVICE_CONST_DATA
struct _kc_bus_find_device_custom_data {
	const void *real_data;
	int (*real_match)(struct device *dev, const void *data);
};

static inline int _kc_bus_find_device_wrapped_match(struct device *dev, void *data)
{
	struct _kc_bus_find_device_custom_data *custom_data = data;

	return custom_data->real_match(dev, custom_data->real_data);
}

static inline struct device *
_kc_bus_find_device(struct bus_type *type, struct device *start,
		    const void *data,
		    int (*match)(struct device *dev, const void *data))
{
	struct _kc_bus_find_device_custom_data custom_data = {};

	custom_data.real_data = data;
	custom_data.real_match = match;

	return bus_find_device(type, start, &custom_data,
				_kc_bus_find_device_wrapped_match);
}

#define bus_find_device(type, start, data, match) \
	_kc_bus_find_device(type, start, data, match)
#endif
#endif

