/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei IP notify Protocol Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
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
 */

#ifndef _IP_NOTIFY_H
#define _IP_NOTIFY_H

#define SUB_PROTOCOL_IP_NOTIFY 0x102
#define IPV6_ADDR_LEN 16
#define VER_SHIFT_4 4u
#define IP_NOTIFY_TIMEOUT_MS 30000

/* IP Protocol type */
enum { UB_PROTO_IPV4 = 1, UB_PROTO_IPV6 };

/* IP Notify protocol opcodes */
enum { IP_NOTIFY_OP_REQ = 1, IP_NOTIFY_OP_REP };

struct ip_notify_pdu {
	u8 ver;  /* bit[7:4]: version, bit[3:0]: rsvd */
	u8 mask; /* Subnet Mask */
	union {
		struct {
			__be32 ip;
		} ipv4;
		struct {
			u8 ip[IPV6_ADDR_LEN];
		} ipv6;
	};
} __packed;

/* This structure defines ub ip notify header. */
struct ip_notify_hdr {
	u8 cfg;				  /* cfg param support ubnic handling msg */
	__be16 protocol;		  /* sub protocol of network congtrol */
	u8 dest_guid[16];		  /* destination GUID */
	u8 src_guid[16];		  /* source GUID */
	struct ip_notify_pdu pdu;	  /* PDU content */
} __packed;

static inline int ip_notify_hdr_len(void)
{
	return sizeof(struct ip_notify_hdr);
}

#endif /* _IP_NOTIFY_H */
