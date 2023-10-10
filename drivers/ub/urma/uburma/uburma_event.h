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
 * Description: uburma event header
 * Author: Yan Fangfang
 * Create: 2022-07-28
 * Note:
 * History: 2022-07-28: create file
 */

#ifndef UBURMA_EVENT_H
#define UBURMA_EVENT_H

#include <urma/ubcore_types.h>
#include "uburma_uobj.h"

void uburma_init_jfe(struct uburma_jfe *jfe);
void uburma_uninit_jfe(struct uburma_jfe *jfe);
void uburma_write_event(struct uburma_jfe *jfe, uint64_t event_data, uint32_t event_type,
			struct list_head *obj_event_list, uint32_t *counter);

struct uburma_jfce_uobj *uburma_get_jfce_uobj(int fd, struct uburma_file *ufile);
void uburma_jfce_handler(struct ubcore_jfc *jfc);
void uburma_release_comp_event(struct uburma_jfce_uobj *jfce, struct list_head *event_list);

void uburma_init_jfae(struct uburma_jfae_uobj *jfae, struct ubcore_device *ubc_dev);
void uburma_release_async_event(struct uburma_file *ufile, struct list_head *event_list);
int uburma_get_jfae(struct uburma_file *ufile);
void uburma_put_jfae(struct uburma_file *ufile);
#endif /* UBURMA_EVENT_H */
