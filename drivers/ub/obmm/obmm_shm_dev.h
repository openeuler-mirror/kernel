/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 */

#ifndef OBMM_SHM_DEV_H
#define OBMM_SHM_DEV_H

#include "obmm_core.h"

int obmm_shm_dev_init(void);
void obmm_shm_dev_exit(void);

/*
 * Per-region device life cycle:
 *
 *   obmm_shm_dev_init_device()  initialize the embedded cdev+device
 *   obmm_shm_dev_publish()      create /dev/obmm_shmdev<regionid> + sysfs entry
 *   obmm_shm_dev_unpublish()    remove the device file and sysfs entry
 *   obmm_shm_dev_put()          drop the initial reference, freeing the region
 *
 * Once obmm_shm_dev_init_device() has run, the region's memory is owned by
 * the device core and is freed by the device's release callback; callers
 * must never kfree() it directly and must finish all teardown that touches
 * the region before the final obmm_shm_dev_put().
 */
int obmm_shm_dev_init_device(struct obmm_region *reg);
int obmm_shm_dev_publish(struct obmm_region *reg);
void obmm_shm_dev_unpublish(struct obmm_region *reg);
void obmm_shm_dev_put(struct obmm_region *reg);

#endif
