/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2026. All rights reserved.
 *
 * Description: uburma device number management
 */

#ifndef UBURMA_DEVNUM_H
#define UBURMA_DEVNUM_H

#include <linux/types.h>

struct ubcore_device;

int uburma_devnum_init(void);
void uburma_devnum_exit(void);
int uburma_devnum_alloc(const struct ubcore_device *ubc_dev, dev_t *devt);
void uburma_devnum_free(unsigned int minor);

#endif /* UBURMA_DEVNUM_H */
