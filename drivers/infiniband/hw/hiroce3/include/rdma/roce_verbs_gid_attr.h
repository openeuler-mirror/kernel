/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_VERBS_GID_ATTR_H
#define ROCE_VERBS_GID_ATTR_H

#ifndef BIG_ENDIAN
#define BIG_ENDIAN	0x4321
#endif

#pragma pack(push, 4)
struct tag_roce_verbs_gid_ipv4_attr {
	/* DW0 */
	union {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 udpudp_len_gap : 8;
			u32 rsvd : 8;
			u32 bth_addr : 16;
#else
			u32 bth_addr : 16;
			u32 rsvd : 8;
			u32 udpudp_len_gap : 8;
#endif
		u32 value;
	} dw0;

	/* DW1 */
	union {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 ip_addr : 16;
			u32 udp_addr : 16;
#else
			u32 udp_addr : 16;
			u32 ip_addr : 16;
#endif
		u32 value;
	} dw1;
};

struct tag_roce_verbs_gid_attr {
	/* DW0~3 */
	u32 gid[4];

	/* DW4 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd0 : 12;
			u32 cvlan : 12;
			u32 rsvd : 8;
#else
			u32 rsvd : 8;
			u32 cvlan : 12;
			u32 rsvd0 : 12;
#endif
		} bs;
		u32 value;
	} dw4;

	/* DW5 */
	union {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 ppersp_pad_len : 8;
			u32 l2_len : 8;
			u32 ipv4_hdr_len : 8;
			u32 pkthdr_len : 8;
#else
			u32 pkthdr_len : 8;
			u32 ipv4_hdr_len : 8;
			u32 l2_len : 8;
			u32 ppersp_pad_len : 8;
#endif
		u32 value;
	} dw5;

	/* DW6 */
	union {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 7;
			u32 o_ip_type : 1;
			u32 o_tag : 2;
			u32 gid_update : 1;
			u32 rsvd0 : 1;
			u32 gid_type : 2;
			u32 tag : 2;
			u32 smac_hi16 : 16;
#else
			u32 smac_hi16 : 16;
			u32 tag : 2;
			/* 0:ROCE V1; 1:ROCE V2 IPV4; 2:ROCE V2 IPV6; other:rsvd */
			u32 gid_type : 2;
			u32 rsvd0 : 1;
			u32 gid_update : 1;
			u32 o_tag : 2;
			u32 o_ip_type : 1;
			u32 rsvd : 7;
#endif
		u32 value;
	} dw6;

	u32 smac_lo32;

	struct tag_roce_verbs_gid_ipv4_attr ipv4;
};

struct tag_roce_verbs_clear_gid_info {
	u32 gid_num;
};
#pragma pack(pop)

#endif /* ROCE_VERBS_GID_ATTR_H */
