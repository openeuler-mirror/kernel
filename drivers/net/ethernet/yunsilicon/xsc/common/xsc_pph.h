/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_PPH_H
#define XSC_PPH_H

#define XSC_PPH_HEAD_LEN	64

enum {
	L4_PROTO_NONE	= 0,
	L4_PROTO_TCP	= 1,
	L4_PROTO_UDP	= 2,
	L4_PROTO_ICMP	= 3,
	L4_PROTO_GRE	= 4,
};

enum {
	L3_PROTO_NONE	= 0,
	L3_PROTO_IP	= 2,
	L3_PROTO_IP6	= 3,
};

struct epp_pph {
	u16 outer_eth_type;              //2 bytes
	u16 inner_eth_type;              //4 bytes

	u16 rsv1:1;
	u16 outer_vlan_flag:2;
	u16 outer_ip_type:2;
	u16 outer_ip_ofst:5;
	u16 outer_ip_len:6;                //6 bytes

	u16 rsv2:1;
	u16 outer_tp_type:3;
	u16 outer_tp_csum_flag:1;
	u16 outer_tp_ofst:7;
	u16 ext_tunnel_type:4;              //8 bytes

	u8 tunnel_ofst;                     //9 bytes
	u8 inner_mac_ofst;                  //10 bytes

	u32 rsv3:2;
	u32 inner_mac_flag:1;
	u32 inner_vlan_flag:2;
	u32 inner_ip_type:2;
	u32 inner_ip_ofst:8;
	u32 inner_ip_len:6;
	u32 inner_tp_type:2;
	u32 inner_tp_csum_flag:1;
	u32 inner_tp_ofst:8;		//14 bytees

	u16 rsv4:1;
	u16 payload_type:4;
	u16 payload_ofst:8;
	u16 pkt_type:3;			//16 bytes

	u16 rsv5:2;
	u16 pri:3;
	u16 logical_in_port:11;
	u16 vlan_info;
	u8 error_bitmap:8;			//21 bytes

	u8 rsv6:7;
	u8 recirc_id_vld:1;
	u16 recirc_id;			//24 bytes

	u8 rsv7:7;
	u8 recirc_data_vld:1;
	u32 recirc_data;			//29 bytes

	u8 rsv8:6;
	u8 mark_tag_vld:2;
	u16 mark_tag;			//32 bytes

	u8 rsv9:4;
	u8 upa_to_soc:1;
	u8 upa_from_soc:1;
	u8 upa_re_up_call:1;
	u8 upa_pkt_drop:1;			//33 bytes

	u8 ucdv;
	u16 rsv10:2;
	u16 pkt_len:14;			//36 bytes

	u16 rsv11:2;
	u16 pkt_hdr_ptr:14;		//38 bytes

	u64	 rsv12:5;
	u64	 csum_ofst:8;
	u64	 csum_val:29;
	u64	 csum_plen:14;
	u64	 rsv11_0:8;			//46 bytes

	u64	 rsv11_1;
	u64	 rsv11_2;
	u16 rsv11_3;
};

#define OUTER_L3_BIT	BIT(3)
#define OUTER_L4_BIT	BIT(2)
#define INNER_L3_BIT	BIT(1)
#define INNER_L4_BIT	BIT(0)
#define OUTER_BIT		(OUTER_L3_BIT | OUTER_L4_BIT)
#define INNER_BIT		(INNER_L3_BIT | INNER_L4_BIT)
#define OUTER_AND_INNER	(OUTER_BIT | INNER_BIT)

#define PACKET_UNKNOWN	BIT(4)

#define EPP2SOC_PPH_EXT_TUNNEL_TYPE_OFFSET (6UL)
#define EPP2SOC_PPH_EXT_TUNNEL_TYPE_BIT_MASK (0XF00)
#define EPP2SOC_PPH_EXT_TUNNEL_TYPE_BIT_OFFSET (8)

#define EPP2SOC_PPH_EXT_ERROR_BITMAP_OFFSET (20UL)
#define EPP2SOC_PPH_EXT_ERROR_BITMAP_BIT_MASK (0XFF)
#define EPP2SOC_PPH_EXT_ERROR_BITMAP_BIT_OFFSET (0)

#define XSC_GET_EPP2SOC_PPH_EXT_TUNNEL_TYPE(PPH_BASE_ADDR)	\
	((*(u16 *)((u8 *)(PPH_BASE_ADDR) + EPP2SOC_PPH_EXT_TUNNEL_TYPE_OFFSET) & \
	EPP2SOC_PPH_EXT_TUNNEL_TYPE_BIT_MASK) >> EPP2SOC_PPH_EXT_TUNNEL_TYPE_BIT_OFFSET)

#define XSC_GET_EPP2SOC_PPH_ERROR_BITMAP(PPH_BASE_ADDR)		\
	((*(u8 *)((u8 *)(PPH_BASE_ADDR) + EPP2SOC_PPH_EXT_ERROR_BITMAP_OFFSET) & \
	EPP2SOC_PPH_EXT_ERROR_BITMAP_BIT_MASK) >> EPP2SOC_PPH_EXT_ERROR_BITMAP_BIT_OFFSET)

#define PPH_OUTER_IP_TYPE_OFF		(4UL)
#define PPH_OUTER_IP_TYPE_MASK		(0x3)
#define PPH_OUTER_IP_TYPE_SHIFT		(11)
#define PPH_OUTER_IP_TYPE(base)		\
	((ntohs(*(u16 *)((u8 *)(base) + PPH_OUTER_IP_TYPE_OFF)) >> \
	PPH_OUTER_IP_TYPE_SHIFT) & PPH_OUTER_IP_TYPE_MASK)

#define PPH_OUTER_IP_OFST_OFF		(4UL)
#define PPH_OUTER_IP_OFST_MASK		(0x1f)
#define PPH_OUTER_IP_OFST_SHIFT		(6)
#define PPH_OUTER_IP_OFST(base)		 \
	((ntohs(*(u16 *)((u8 *)(base) + PPH_OUTER_IP_OFST_OFF)) >> \
	PPH_OUTER_IP_OFST_SHIFT) & PPH_OUTER_IP_OFST_MASK)

#define PPH_OUTER_IP_LEN_OFF		(4UL)
#define PPH_OUTER_IP_LEN_MASK		(0x3f)
#define PPH_OUTER_IP_LEN_SHIFT		(0)
#define PPH_OUTER_IP_LEN(base)		\
	((ntohs(*(u16 *)((u8 *)(base) + PPH_OUTER_IP_LEN_OFF)) >> \
	PPH_OUTER_IP_LEN_SHIFT) & PPH_OUTER_IP_LEN_MASK)

#define PPH_OUTER_TP_TYPE_OFF		(6UL)
#define PPH_OUTER_TP_TYPE_MASK		(0x7)
#define PPH_OUTER_TP_TYPE_SHIFT		(12)
#define PPH_OUTER_TP_TYPE(base)		\
	((ntohs(*(u16 *)((u8 *)(base) + PPH_OUTER_TP_TYPE_OFF)) >> \
	PPH_OUTER_TP_TYPE_SHIFT) & PPH_OUTER_TP_TYPE_MASK)

#define PPH_PAYLOAD_OFST_OFF		(14UL)
#define PPH_PAYLOAD_OFST_MASK		(0xff)
#define PPH_PAYLOAD_OFST_SHIFT		(3)
#define PPH_PAYLOAD_OFST(base)		\
	((ntohs(*(u16 *)((u8 *)(base) + PPH_PAYLOAD_OFST_OFF)) >> \
	PPH_PAYLOAD_OFST_SHIFT) & PPH_PAYLOAD_OFST_MASK)

#define PPH_CSUM_OFST_OFF		(38UL)
#define PPH_CSUM_OFST_MASK		(0xff)
#define PPH_CSUM_OFST_SHIFT		(51)
#define PPH_CSUM_OFST(base)		\
	((be64_to_cpu(*(u64	 *)((u8 *)(base) + PPH_CSUM_OFST_OFF)) >> \
	PPH_CSUM_OFST_SHIFT) & PPH_CSUM_OFST_MASK)

#define PPH_CSUM_VAL_OFF		(38UL)
#define PPH_CSUM_VAL_MASK		(0xeffffff)
#define PPH_CSUM_VAL_SHIFT		(22)
#define PPH_CSUM_VAL(base)		\
	((be64_to_cpu(*(u64	 *)((u8 *)(base) + PPH_CSUM_VAL_OFF)) >> \
	PPH_CSUM_VAL_SHIFT) & PPH_CSUM_VAL_MASK)
#endif /* XSC_TBM_H */

