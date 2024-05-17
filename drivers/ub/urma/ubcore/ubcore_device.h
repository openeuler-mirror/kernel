/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * Description: ubcore device head file
 * Author: Yan Fangfang
 * Create: 2024-02-05
 * Note:
 * History: 2024-02-05: Create file
 */

#ifndef UBCORE_DEVICE_H
#define UBCORE_DEVICE_H

int ubcore_register_pnet_ops(void);
void ubcore_unregister_pnet_ops(void);
int ubcore_class_register(void);
void ubcore_class_unregister(void);
int ubcore_unregister_sysfs(void);
int ubcore_set_ns_mode(bool shared);
int ubcore_set_dev_ns(char *device_name, uint32_t ns_fd);
bool ubcore_dev_accessible(struct ubcore_device *dev, struct net *net);
int ubcore_get_max_mtu(struct ubcore_device *dev, enum ubcore_mtu *mtu);
struct ubcore_nlmsg *ubcore_new_tpf_dev_msg(struct ubcore_device *dev);
bool ubcore_eid_accessible(struct ubcore_device *dev, uint32_t eid_index);
#endif // UBCORE_DEVICE_H
