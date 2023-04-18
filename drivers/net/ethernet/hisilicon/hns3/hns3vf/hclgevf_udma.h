/* SPDX-License-Identifier: GPL-2.0+ */
/* Hisilicon UNIC Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#ifndef __HCLGEVF_UDMA_H
#define __HCLGEVF_UDMA_H

#include <linux/types.h>

int hclgevf_notify_udma_client(struct hclgevf_dev *hdev,
			       enum hnae3_reset_notify_type type);
int hclgevf_init_udma_client_instance(struct hnae3_ae_dev *ae_dev,
				      struct hnae3_client *client);

#endif
