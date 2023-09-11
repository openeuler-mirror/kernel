/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: API definition provided by ubcore to ubep device driver
 * Author: Qian Guoxin
 * Create: 2022-1-25
 * Note:
 * History: 2022-1-25: Create file
 */

#ifndef UBCORE_API_H
#define UBCORE_API_H

#include <urma/ubcore_types.h>

/**
 * Register a device to ubcore
 * @param[in] dev: the ubcore device;
 * @return: 0 on success, other value on error
 */
int ubcore_register_device(struct ubcore_device *dev);
/**
 * Unregister a device from ubcore
 * @param[in] dev: the ubcore device;
 */
void ubcore_unregister_device(struct ubcore_device *dev);

/**
 * Allocate physical memory and do DMA mapping
 * @param[in] dev: the ubcore device;
 * @param[in] va: the VA address to be mapped.
 * @param[in] len: Length of the address space to be allocated and mapped by DMA.
 * @param[in] flag: Attribute flags
 * Return: umem ptr on success, ERR_PTR on error
 */
struct ubcore_umem *ubcore_umem_get(struct ubcore_device *dev, uint64_t va, uint64_t len,
				    union ubcore_umem_flag flag);
/**
 * Release umem allocated
 * @param[in] umem: the ubcore umem created before
 */
void ubcore_umem_release(struct ubcore_umem *umem);

#endif
