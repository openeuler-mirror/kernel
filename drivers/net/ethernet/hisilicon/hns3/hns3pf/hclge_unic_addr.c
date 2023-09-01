// SPDX-License-Identifier: GPL-2.0+
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

#include "hclge_comm_unic_addr.h"
#include "hclge_main.h"
#include "hclge_mbx.h"
#include "hclge_unic_guid.h"
#include "hclge_unic_ip.h"
#include "hclge_unic_addr.h"

int hclge_unic_add_addr(struct hnae3_handle *handle, const unsigned char *addr,
			enum hnae3_unic_addr_type addr_type)
{
	struct hclge_vport *vport = hclge_get_vport(handle);

	switch (addr_type) {
	case HNAE3_UNIC_IP_ADDR:
		return hclge_unic_update_ip_list(vport,
						 HCLGE_COMM_UNIC_ADDR_TO_ADD,
						 (const struct sockaddr *)addr);
	case HNAE3_UNIC_MCGUID_ADDR:
		return hclge_unic_update_guid_list(vport,
						   HCLGE_COMM_UNIC_ADDR_TO_ADD,
						   addr);
	default:
		return -EINVAL;
	}
}

int hclge_unic_rm_addr(struct hnae3_handle *handle, const unsigned char *addr,
		       enum hnae3_unic_addr_type addr_type)
{
	struct hclge_vport *vport = hclge_get_vport(handle);

	switch (addr_type) {
	case HNAE3_UNIC_IP_ADDR:
		return hclge_unic_update_ip_list(vport,
						 HCLGE_COMM_UNIC_ADDR_TO_DEL,
						 (const struct sockaddr *)addr);
	case HNAE3_UNIC_MCGUID_ADDR:
		return hclge_unic_update_guid_list(vport,
						   HCLGE_COMM_UNIC_ADDR_TO_DEL,
						   addr);
	default:
		return -EINVAL;
	}
}
