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

#ifndef __HCLGE_COMM_UNIC_ADDR_H
#define __HCLGE_COMM_UNIC_ADDR_H

#include <linux/in6.h>
#include <linux/types.h>
#include <net/ipv6.h>

#include "ubl.h"
#include "hnae3.h"
#include "hclge_comm_cmd.h"

#define HCLGE_COMM_UNIC_IPV6_UPPER_LEN		13
#define HCLGE_COMM_UNIC_IPV6_LOWER_LEN		3
#define HCLGE_COMM_UNIC_MSG_IPADDR_POS		1

enum HCLGE_COMM_ADDR_NODE_STATE {
	HCLGE_COMM_UNIC_ADDR_TO_ADD,
	HCLGE_COMM_UNIC_ADDR_TO_DEL,
	HCLGE_COMM_UNIC_ADDR_ACTIVE
};

#define UNIC_ADDR_LEN				16
#define HCLGE_COMM_MGUID_PREFIX_LEN		14
struct hclge_comm_unic_addr_node {
	struct list_head node;
	enum HCLGE_COMM_ADDR_NODE_STATE state;
	union {
		u8 unic_addr[UNIC_ADDR_LEN];
		u8 mguid[UBL_ALEN];
		struct {
			u8 prefix[HCLGE_COMM_MGUID_PREFIX_LEN];
			__le16 proto;
		};
		struct in6_addr ip_addr;
	};
};

#define HCLGE_COMM_FUNC_GUID_ENTRY_VALID_EN	0x01

struct hclge_comm_func_guid_cmd {
	u8 entry_vld	 : 1;
	u8 lookup_enable : 1;
	u8 rsv0		 : 6;
	u8 rsv1;
	__le16 rsv2;
	/* use big endian here */
	u8 guid[UBL_ALEN];
	__le16 hit_info;
	__le16 rsv3;
};

#define HCLGE_COMM_FORMAT_GUID_ADDR_LEN		48
#define HCLGE_COMM_FORMAT_GUID_ADDR_PROTO_HIGH	14
#define HCLGE_COMM_FORMAT_GUID_ADDR_PROTO_LOW	15

static inline void hclge_comm_format_guid_addr(char *format_guid_addr,
					       const u8 *guid_addr)
{
	snprintf(format_guid_addr, HCLGE_COMM_FORMAT_GUID_ADDR_LEN,
		 "ff:ff:**:**:**:**:**:**:**:**:**:**:**:**:%02x:%02x",
		 guid_addr[HCLGE_COMM_FORMAT_GUID_ADDR_PROTO_HIGH],
		 guid_addr[HCLGE_COMM_FORMAT_GUID_ADDR_PROTO_LOW]);
}

static inline bool hclge_comm_unic_addr_equal(const u8 *addr1, const u8 *addr2)
{
	const u32 *a = (const u32 *)addr1;
	const u32 *b = (const u32 *)addr2;

	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) |
		(a[2] ^ b[2]) | (a[3] ^ b[3])) == 0;
}

void hclge_comm_unic_sync_from_addr_del_list(struct list_head *del_list,
					     struct list_head *addr_list);
int hclge_comm_unic_update_addr_list(struct list_head *list,
				     spinlock_t *addr_list_lock,
				     enum HCLGE_COMM_ADDR_NODE_STATE state,
				     const unsigned char *addr);
bool hclge_comm_unic_sync_addr_table(struct hnae3_handle *handle,
				     struct list_head *list,
				     spinlock_t *addr_list_lock,
				     void (*sync)(struct hnae3_handle *,
						  struct list_head *),
				     void (*unsync)(struct hnae3_handle *,
						    struct list_head *));
int hclge_comm_unic_convert_ip_addr(const struct sockaddr *addr,
				    struct in6_addr *ip_addr);
void hclge_comm_unic_set_func_guid(struct hclge_comm_hw *hw, u8 **guid);
int hclge_comm_unic_get_func_guid(struct hclge_comm_hw *hw, u8 *guid);
void hclge_comm_unic_rm_func_guid(struct hclge_comm_hw *hw, u8 **guid);

#endif
