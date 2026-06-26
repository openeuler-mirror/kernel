/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubagg device helper header file
 */

#ifndef UBAGG_DEVICE_H
#define UBAGG_DEVICE_H

#include <ub/urma/ubcore_types.h>

struct ubagg_device;

static inline bool is_eid_valid(const char *eid)
{
	int i;

	for (i = 0; i < UBCORE_EID_SIZE; i++) {
		if (eid[i] != 0)
			return true;
	}
	return false;
}

struct ubcore_ucontext *
ubagg_alloc_ucontext(struct ubcore_device *dev, uint32_t eid_index,
		     struct ubcore_udrv_priv *udrv_data);
int ubagg_free_ucontext(struct ubcore_ucontext *uctx);
uint32_t ubagg_get_ucontext_count(void);

void ubagg_uninit_device_res(struct ubagg_device *ubagg_dev);

void ubagg_get_device(struct ubagg_device *dev);
void ubagg_put_device(struct ubagg_device *dev);

struct ubagg_device *ubagg_get_device_by_name(const char *dev_name);
struct ubagg_device *ubagg_get_device_by_eid(const union ubcore_eid *eid);
struct ubagg_device *ubagg_get_first_device(void);

int ubagg_add_dev_to_list(struct ubagg_device *ubagg_dev);
void ubagg_remove_dev_from_list(struct ubagg_device *ubagg_dev);
struct ubagg_device *ubagg_pop_device_from_list(void);

#endif /* UBAGG_DEVICE_H */
