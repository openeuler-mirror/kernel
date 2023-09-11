/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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
 * Description: ubcore api for other client kmod, such as uburma.
 * Author: Qian Guoxin, Ouyang Changchun
 * Create: 2021-8-3
 * Note:
 * History: 2021-8-3: Create file
 * History: 2021-11-25: add segment and jetty management function
 * History: 2022-7-25: modify file name
 */

#ifndef UBCORE_UAPI_H
#define UBCORE_UAPI_H

#include <urma/ubcore_types.h>

/**
 * Application specifies the device to allocate an context.
 * @param[in] dev: ubcore_device found by add ops in the client.
 * @param[in] uasid: (deprecated)
 * @param[in] udrv_data (optional): ucontext and user space driver data
 * @return: ubcore_ucontext pointer on success, NULL on fail.
 * Note: this API is called only by uburma representing user-space application,
 * not by other kernel modules
 */
struct ubcore_ucontext *ubcore_alloc_ucontext(struct ubcore_device *dev, uint32_t uasid,
					      struct ubcore_udrv_priv *udrv_data);
/**
 * Free the allocated context.
 * @param[in] dev: device to free context.
 * @param[in] ucontext: handle of the allocated context.
 * Note: this API is called only by uburma representing user-space application,
 * not by other kernel modules
 */
void ubcore_free_ucontext(const struct ubcore_device *dev, struct ubcore_ucontext *ucontext);
/**
 * set function entity id for ub device. must be called before alloc context
 * @param[in] dev: the ubcore_device handle;
 * @param[in] eid: function entity id (eid) to set;
 * @return: 0 on success, other value on error
 */
int ubcore_set_eid(struct ubcore_device *dev, union ubcore_eid *eid);
/**
 * query device attributes
 * @param[in] dev: the ubcore_device handle;
 * @param[out] attr: attributes returned to client
 * @return: 0 on success, other value on error
 */
int ubcore_query_device_attr(struct ubcore_device *dev, struct ubcore_device_attr *attr);
/**
 * config device
 * @param[in] dev: the ubcore_device handle;
 * @param[in] cfg: device configuration
 * @return: 0 on success, other value on error
 */
int ubcore_config_device(struct ubcore_device *dev, const struct ubcore_device_cfg *cfg);

/**
 * set ctx data of a client
 * @param[in] dev: the ubcore_device handle;
 * @param[in] client: ubcore client pointer
 * @param[in] data: client private data to be set
 * @return: 0 on success, other value on error
 */
void ubcore_set_client_ctx_data(struct ubcore_device *dev, const struct ubcore_client *client,
				void *data);
/**
 * get ctx data of a client
 * @param[in] dev: the ubcore_device handle;
 * @param[in] client: ubcore client pointer
 * @return: client private data set before
 */
void *ubcore_get_client_ctx_data(struct ubcore_device *dev, const struct ubcore_client *client);
/**
 * Register a new client to ubcore
 * @param[in] dev: the ubcore_device handle;
 * @param[in] new_client: ubcore client to be registered
 * @return: 0 on success, other value on error
 */
int ubcore_register_client(struct ubcore_client *new_client);
/**
 * Unregister a client from ubcore
 * @param[in] rm_client: ubcore client to be unregistered
 */
void ubcore_unregister_client(struct ubcore_client *rm_client);
/**
 * query stats
 * @param[in] dev: the ubcore_device handle;
 * @param[in] key: stats type and key;
 * @param[in/out] val: addr and len of value
 * @return: 0 on success, other value on error
 */
int ubcore_query_stats(const struct ubcore_device *dev, struct ubcore_stats_key *key,
		       struct ubcore_stats_val *val);

#endif
