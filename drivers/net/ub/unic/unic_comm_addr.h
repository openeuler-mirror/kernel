/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_COMM_ADDR_H__
#define __UNIC_COMM_ADDR_H__

#include <linux/in6.h>
#include <linux/types.h>

#include "unic_dev.h"

enum UNIC_COMM_ADDR_STATE {
	UNIC_COMM_ADDR_TO_ADD,
	UNIC_COMM_ADDR_TO_DEL,
	UNIC_COMM_ADDR_ACTIVE
};

#define UNIC_COMM_ADDR_NO_MASK		0
#define UNIC_IPV4_PREFIX		0xffff0000

#define UNIC_ADDR_LEN			16

struct unic_comm_addr_node {
	struct list_head node;
	enum UNIC_COMM_ADDR_STATE state;
	union {
		u8 unic_addr[UNIC_ADDR_LEN];
		struct in6_addr ip_addr;
		u8 mac_addr[ETH_ALEN];
	};
	u8 is_pfc;
	u16 node_mask;
};

#define	UNIC_FORMAT_MAC_LEN		18
#define UNIC_FORMAT_MAC_OFFSET_0	0
#define UNIC_FORMAT_MAC_OFFSET_4	4
#define UNIC_FORMAT_MAC_OFFSET_5	5
static inline void unic_comm_format_mac_addr(char *format_mac, const u8 *mac)
{
	snprintf(format_mac, UNIC_FORMAT_MAC_LEN, "%02x:**:**:**:%02x:%02x",
		 mac[UNIC_FORMAT_MAC_OFFSET_0], mac[UNIC_FORMAT_MAC_OFFSET_4],
		 mac[UNIC_FORMAT_MAC_OFFSET_5]);
}

static inline bool unic_comm_addr_equal(const u8 *addr1, const u8 *addr2,
					u16 mask1, u16 mask2)
{
	const u32 *a = (const u32 *)addr1;
	const u32 *b = (const u32 *)addr2;

	return (((a[0] ^ b[0]) | (a[1] ^ b[1]) |
		 (a[2] ^ b[2]) | (a[3] ^ b[3])) |
		(mask1 ^ mask2)) == 0;
}

struct unic_comm_addr_node *unic_comm_find_addr_node(struct list_head *list,
						     const u8 *addr,
						     u16 node_mask);
void unic_comm_update_addr_state(struct unic_comm_addr_node *addr_node,
				 enum UNIC_COMM_ADDR_STATE state);
int unic_comm_update_addr_list(struct list_head *list,
			       spinlock_t *addr_list_lock,
			       enum UNIC_COMM_ADDR_STATE state,
			       const u8 *addr);
bool unic_comm_sync_addr_table(struct unic_vport *vport,
			       struct list_head *list,
			       spinlock_t *addr_list_lock,
			       void (*sync)(struct unic_vport *,
					    struct list_head *),
			       void (*unsync)(struct unic_vport *,
					      struct list_head *));
void unic_comm_sync_from_addr_del_list(struct list_head *del_list,
				       struct list_head *addr_list);
void unic_comm_sync_from_addr_add_list(struct list_head *add_list,
				       struct list_head *addr_list,
				       bool *all_added);
int unic_convert_ip_addr(struct sockaddr *addr, struct in6_addr *ip_addr);

#endif /* __UNIC_COMM_ADDR_H__ */
