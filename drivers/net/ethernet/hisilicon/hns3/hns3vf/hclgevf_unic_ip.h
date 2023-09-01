/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2023-2023 Hisilicon Limited.
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

#ifndef __HCLGEVF_UNIC_IP_H
#define __HCLGEVF_UNIC_IP_H

#include <linux/in6.h>
#include <linux/types.h>
#include <net/ipv6.h>

void hclgevf_unic_sync_ip_list(struct hclgevf_dev *hdev);
void hclgevf_unic_clear_ip_list(struct hclgevf_dev *hdev);
int hclgevf_unic_update_ip_list(struct hnae3_handle *handle,
				enum HCLGE_COMM_ADDR_NODE_STATE state,
				const struct sockaddr *addr);

#endif
