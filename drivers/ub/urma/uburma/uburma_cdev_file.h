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
 * Description: uburma device file ops file
 * Author: Qian Guoxin
 * Create: 2022-8-16
 * Note:
 * History: 2022-8-16: Create file
 */

#ifndef UBURMA_CDEV_FILE_H
#define UBURMA_CDEV_FILE_H

#include "uburma_types.h"

struct uburma_port_attribute {
	struct attribute attr;
	ssize_t (*show)(struct uburma_port *p, struct uburma_port_attribute *attr, char *buf);
	ssize_t (*store)(struct uburma_port *p, struct uburma_port_attribute *attr, const char *buf,
			 size_t count);
};

#define PORT_ATTR(_name, _mode, _show, _store)	\
	struct uburma_port_attribute port_attr_##_name = __ATTR(_name, _mode, _show, _store)

#define PORT_ATTR_RO(_name) struct uburma_port_attribute port_attr_##_name = __ATTR_RO(_name)

struct uburma_vf_attribute {
	struct attribute attr;
	ssize_t (*show)(struct uburma_vf *vf, struct uburma_vf_attribute *attr, char *buf);
	ssize_t (*store)(struct uburma_vf *vf, struct uburma_vf_attribute *attr, const char *buf,
			 size_t count);
};

#define VF_ATTR(_name, _mode, _show, _store)	\
	struct uburma_vf_attribute vf_attr_##_name = __ATTR(_name, _mode, _show, _store)

#define VF_ATTR_RO(_name) struct uburma_vf_attribute vf_attr_##_name = __ATTR_RO(_name)

int uburma_create_port_attr_files(struct uburma_device *ubu_dev, uint8_t port_num);
int uburma_create_vf_attr_files(struct uburma_device *ubu_dev, uint32_t vf_num);
int uburma_create_dev_attr_files(struct uburma_device *ubu_dev);
void uburma_remove_port_attr_files(struct uburma_device *ubu_dev, uint8_t port_num);
void uburma_remove_vf_attr_files(struct uburma_device *ubu_dev, uint32_t vf_num);
void uburma_remove_dev_attr_files(struct uburma_device *ubu_dev);

#endif /* UBURMA_CDEV_FILE_H */
