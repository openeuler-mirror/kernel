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

#ifndef __HCLGE_UNIC_IP_H
#define __HCLGE_UNIC_IP_H

#include <linux/in6.h>
#include <linux/types.h>
#include <net/ipv6.h>

struct hclge_dev;

#define HCLGE_UNIC_IP_ADDR_NOTSET	255
#define HCLGE_UNIC_IP_TBL_MISS	1

int hclge_unic_init_iptbl_info(struct hclge_dev *hdev);
void hclge_unic_reset_iptbl_space(struct hclge_dev *hdev);
void hclge_unic_sync_ip_table(struct hclge_dev *hdev);
void hclge_unic_restore_ip_table(struct hclge_vport *vport);
void hclge_unic_rm_vport_all_ip_table(struct hclge_vport *vport,
				      bool is_del_list);
void hclge_unic_uninit_ip_table(struct hclge_dev *hdev);
int hclge_unic_set_vf_ip_addr(struct hclge_vport *vport,
			      struct hclge_mbx_vf_to_pf_cmd *mbx_req);
int hclge_unic_update_ip_list(struct hclge_vport *vport,
			      enum HCLGE_COMM_ADDR_NODE_STATE state,
			      const struct sockaddr *addr);

#endif
