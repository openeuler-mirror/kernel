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
