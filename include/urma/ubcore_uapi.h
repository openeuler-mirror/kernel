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

#endif
