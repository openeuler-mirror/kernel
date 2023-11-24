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
	ssize_t (*store)(struct uburma_port *p, struct uburma_port_attribute *attr,
		const char *buf, size_t count);
};

#define PORT_ATTR(_name, _mode, _show, _store)	\
	struct uburma_port_attribute port_attr_##_name = __ATTR(_name, _mode, _show, _store)

#define PORT_ATTR_RO(_name) struct uburma_port_attribute port_attr_##_name = __ATTR_RO(_name)

struct uburma_fe_attribute {
	struct attribute attr;
	ssize_t (*show)(struct uburma_fe *fe, struct uburma_fe_attribute *attr, char *buf);
	ssize_t (*store)(struct uburma_fe *fe, struct uburma_fe_attribute *attr,
		const char *buf, size_t count);
};

#define FE_ATTR(_name, _mode, _show, _store) \
struct uburma_fe_attribute fe_attr_##_name = __ATTR(_name, _mode, _show, _store)

#define FE_ATTR_RO(_name) \
struct uburma_fe_attribute fe_attr_##_name = __ATTR_RO(_name)

struct uburma_eid_attribute {
	struct attribute attr;
	ssize_t (*show)(struct uburma_eid *eid, struct uburma_eid_attribute *attr, char *buf);
	ssize_t (*store)(struct uburma_eid *eid, struct uburma_eid_attribute *attr,
		const char *buf, size_t count);
};

#define EID_ATTR(_name, _mode, _show, _store) \
struct uburma_eid_attribute eid_attr_##_name = __ATTR(_name, _mode, _show, _store)

#define EID_ATTR_RO(_name) \
struct uburma_eid_attribute eid_attr_##_name = __ATTR_RO(_name)

int uburma_create_port_attr_files(struct uburma_logic_device *ldev,
	struct uburma_device *ubu_dev, uint8_t port_num);
int uburma_create_fe_attr_files(struct uburma_logic_device *ldev,
	struct uburma_device *ubu_dev, uint16_t fe_num);
int uburma_create_eid_attr_files(struct uburma_logic_device *ldev, uint32_t eid_num);
int uburma_create_dev_attr_files(struct uburma_logic_device *ldev);

void uburma_remove_port_attr_files(struct uburma_logic_device *ldev, uint8_t port_num);
void uburma_remove_fe_attr_files(struct uburma_logic_device *ldev, uint16_t fe_num);
void uburma_remove_eid_attr_files(struct uburma_logic_device *ldev, uint32_t eid_num);
void uburma_remove_dev_attr_files(struct uburma_logic_device *ldev);

#endif /* UBURMA_CDEV_FILE_H */
