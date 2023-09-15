// SPDX-License-Identifier: GPL-2.0
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
 * Description: uburma event implementation
 * Author: Yan Fangfang
 * Create: 2022-07-28
 * Note:
 * History: 2022-07-28: create file
 */

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/poll.h>

#include <urma/ubcore_uapi.h>

#include "uburma_log.h"
#include "uburma_types.h"
#include "uburma_cmd.h"
#include "uburma_uobj.h"
#include "uburma_event.h"

#define UBURMA_JFCE_DELETE_EVENT 0
struct uburma_jfe_event {
	struct list_head node;
	uint32_t event_type; /* support async event */
	uint64_t event_data;
	struct list_head obj_node;
	uint32_t *counter;
};

struct uburma_jfce_uobj *uburma_get_jfce_uobj(int fd, struct uburma_file *ufile)
{
	struct uburma_uobj *uobj;
	struct uburma_jfce_uobj *jfce;

	if (fd < 0)
		return ERR_PTR(-ENOENT);

	uobj = uobj_get_read(UOBJ_CLASS_JFCE, fd, ufile);
	if (IS_ERR(uobj)) {
		uburma_log_err("get jfce uobj fail with fd %d\n", fd);
		return (void *)uobj;
	}

	jfce = container_of(uobj, struct uburma_jfce_uobj, uobj);
	uobj_get(uobj); // To keep the event file until jfce destroy.
	uobj_put_read(uobj);
	return jfce;
}

void uburma_write_event(struct uburma_jfe *jfe, uint64_t event_data, uint32_t event_type,
			struct list_head *obj_event_list, uint32_t *counter)
{
}

void uburma_jfce_handler(struct ubcore_jfc *jfc)
{
}

void uburma_uninit_jfe(struct uburma_jfe *jfe)
{
}

const struct file_operations uburma_jfce_fops = {
};

void uburma_init_jfe(struct uburma_jfe *jfe)
{
}

const struct file_operations uburma_jfae_fops = {
};

void uburma_init_jfae(struct uburma_jfae_uobj *jfae, struct ubcore_device *ubc_dev)
{
}

void uburma_release_comp_event(struct uburma_jfce_uobj *jfce, struct list_head *event_list)
{
}

void uburma_release_async_event(struct uburma_file *ufile, struct list_head *event_list)
{
}

int uburma_get_jfae(struct uburma_file *ufile)
{
	return 0;
}

void uburma_put_jfae(struct uburma_file *ufile)
{
}
