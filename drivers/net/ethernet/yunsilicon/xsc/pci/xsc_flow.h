/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 - 2022, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_FLOW_H
#define XSC_FLOW_H

#include "xsc_flow_tbl.h"

struct xsc_flow_group;
struct xsc_flow_table;
struct fs_fte;
struct xsc_core_device;

#define XSC_MAX_TBL_NUM_PER_FLOW 20
#define XSC_FLOW_POOL_ARRAY_SIZE 8192

#define XSC_IFC_MATCH_IP_TYPE_IPV4		0x2	//2'b10
#define XSC_IFC_MATCH_IP_TYPE_IPV6		0x3	//2'b11

#define XSC_IFC_MATCH_VOID	0
#define XSC_IFC_MATCH_MAX_NUM	128
#define XSC_IFC_MATCH_U64_NUM (XSC_IFC_MATCH_MAX_NUM / 64)

#define IFC_MATCH_BIT(bit_field)	(XSC_IFC_MATCH_ ## bit_field)

#define XSC_SET_FTE_MATCH_ATTR(flags, bit) \
	(((struct xsc_ifc_match_flag *)(flags))->bits[(IFC_MATCH_BIT(bit)) / 64] |= \
	 (1ULL << ((IFC_MATCH_BIT(bit)) % 64)))

#define XSC_CLR_FTE_MATCH_ATTR(flags, bit) \
	(((struct xsc_ifc_match_flag *)(flags))->bits[(IFC_MATCH_BIT(bit)) / 64] &= \
	 ~(1ULL << ((IFC_MATCH_BIT(bit)) % 64)))

#define XSC_TEST_FTE_MATCH_ATTR(flags, bit) \
	((((struct xsc_ifc_match_flag *)(flags))->bits[(IFC_MATCH_BIT(bit)) / 64] >> \
	  (IFC_MATCH_BIT(bit) % 64)) & 0x1)

#define XSC_IFC_MATCH_BIT_TEST(flags, bit) \
	((((struct xsc_ifc_match_flag *)(flags))->bits[(bit) / 64] >> ((bit) % 64)) & 0x1)

struct xsc_ifc_match_flag {
	u64 bits[XSC_IFC_MATCH_U64_NUM];
};

enum xsc_ifc_match_bit {
	XSC_IFC_MATCH_IN_PORT = 0,
	XSC_IFC_MATCH_PKT_TYPE,

	/* Normal L2/L3/L4 */
	XSC_IFC_MATCH_ETH_TYPE = 8,
	XSC_IFC_MATCH_ETH_SRC,
	XSC_IFC_MATCH_ETH_DST,
	XSC_IFC_MATCH_VLAN_ID,
	XSC_IFC_MATCH_VLAN_PCP,
	XSC_IFC_MATCH_VLAN_TPID,
	XSC_IFC_MATCH_CVLAN_ID,
	XSC_IFC_MATCH_CVLAN_PCP,
	XSC_IFC_MATCH_CVLAN_TPID,
	XSC_IFC_MATCH_IP_TYPE,
	XSC_IFC_MATCH_SRC_IPV4,
	XSC_IFC_MATCH_DST_IPV4,
	XSC_IFC_MATCH_SRC_IPV6,
	XSC_IFC_MATCH_DST_IPV6,
	XSC_IFC_MATCH_DSCP,
	XSC_IFC_MATCH_TTL,
	XSC_IFC_MATCH_TP_TYPE,
	XSC_IFC_MATCH_SPORT,
	XSC_IFC_MATCH_DPORT,
	XSC_IFC_MATCH_ICMP_TYPE,
	XSC_IFC_MATCH_ICMP_CODE,
	XSC_IFC_MATCH_UDF0,
	XSC_IFC_MATCH_UDF1,
	XSC_IFC_MATCH_UDF2,
	XSC_IFC_MATCH_TAG,

	/* Tunnel */
	XSC_IFC_MATCH_TNL_ID = 63,
	XSC_IFC_MATCH_TNL_TYPE,
	XSC_IFC_MATCH_TNL_ETH_DST,
	XSC_IFC_MATCH_TNL_VLAN_ID,
	XSC_IFC_MATCH_TNL_VLAN_PCP,
	XSC_IFC_MATCH_TNL_VLAN_TPID,
	XSC_IFC_MATCH_TNL_CVLAN_ID,
	XSC_IFC_MATCH_TNL_CVLAN_PCP,
	XSC_IFC_MATCH_TNL_CVLAN_TPID,
	XSC_IFC_MATCH_TNL_IP_TYPE,
	XSC_IFC_MATCH_TNL_SRC_IPV4,
	XSC_IFC_MATCH_TNL_DST_IPV4,
	XSC_IFC_MATCH_TNL_SRC_IPV6,
	XSC_IFC_MATCH_TNL_DST_IPV6,
	XSC_IFC_MATCH_TNL_DSCP,
	XSC_IFC_MATCH_TNL_TP_TYPE,
	XSC_IFC_MATCH_TNL_SPORT,
	XSC_IFC_MATCH_TNL_DPORT,
	XSC_IFC_MATCH_TNL_ICMP_TYPE,
	XSC_IFC_MATCH_TNL_ICMP_CODE,

	XSC_IFC_MATCH_END,
};

#define XSC_IFC_ACTION_MAX_NUM    128
#define XSC_IFC_ACTION_U64_NUM (XSC_IFC_ACTION_MAX_NUM / 64)

enum xsc_ifc_action_bit {
	XSC_ACTION_DST_PORT = 0,
	XSC_ACTION_COUNTER,
	XSC_ACTION_DROP,
	XSC_ACTION_QUEUE,
	XSC_ACTION_POP_VLAN,
	XSC_ACTION_POP_CVLAN,
	XSC_ACTION_PUSH_VLAN,
	XSC_ACTION_PUSH_CVLAN,

	XSC_ACTION_SET_HDR_START,
	XSC_ACTION_SET_VLAN_VID = XSC_ACTION_SET_HDR_START,
	XSC_ACTION_SET_VLAN_PCP,
	XSC_ACTION_SET_TTL,
	XSC_ACTION_DEC_TTL,
	XSC_ACTION_SET_SRC_MAC,
	XSC_ACTION_SET_DST_MAC,
	XSC_ACTION_SET_SRC_IPV4,
	XSC_ACTION_SET_DST_IPV4,
	XSC_ACTION_SET_SRC_IPV6,
	XSC_ACTION_SET_DST_IPV6,
	XSC_ACTION_SET_IPV4_ECN,
	XSC_ACTION_SET_IPV6_ECN,
	XSC_ACTION_SET_TP_SPORT,
	XSC_ACTION_SET_TP_DPORT,
	XSC_ACTION_SET_TAG,
	XSC_ACTION_SET_DSCP,
	XSC_ACTION_SET_HDR_END,

	XSC_ACTION_UPCALL = XSC_ACTION_SET_HDR_END,
	XSC_ACTION_GOTO_CHAIN,
	XSC_ACTION_SAMPLE,
	XSC_ACTION_CONNTRACK,
	XSC_ACTION_DST_LAG,
	XSC_ACTION_ENCAP_VXLAN,
	XSC_ACTION_DECAP_VXLAN,
	XSC_ACTION_ENCAP_GENEVE,
	XSC_ACTION_ENCAP_ERSPAN2,
	XSC_ACTION_ENCAP_ERSPAN3,
	XSC_ACTION_ERSPAN_PORT_ID,
};

#define IFC_ACTION_BIT(bit_field)	(XSC_ACTION_ ## bit_field)
#define IFC_ACTION_SET_BIT(bit_field)	(XSC_ACTION_SET_ ## bit_field)

#define XSC_IFC_ACTION_FLAG_SET(flags, bit) \
	(((struct xsc_ifc_action_flag *)(flags))->bits[(bit) / 64] |= (1ULL << (bit) % 64))

#define XSC_IFC_ACTION_BIT_SET(flags, bit) \
	(((struct xsc_ifc_action_flag *)(flags))->bits[(IFC_ACTION_BIT(bit)) / 64] |= \
	 (1ULL << ((IFC_ACTION_BIT(bit)) % 64)))

#define XSC_IFC_ACTION_BIT_CLEAR(flags, bit) \
	(((struct xsc_ifc_action_flag *)(flags))->bits[(IFC_ACTION_BIT(bit)) / 64] &= \
	 ~(1ULL << ((IFC_ACTION_BIT(bit)) % 64)))

#define XSC_IFC_ACTION_BIT_TEST(flags, bit) \
	((((struct xsc_ifc_action_flag *)(flags))->bits[(bit) / 64] >> ((bit) % 64)) & 0x1)

struct xsc_ifc_action_flag {
	u64  bits[XSC_IFC_ACTION_U64_NUM];
};

static inline bool xsc_ifc_action_flag_is_empty(const struct xsc_ifc_action_flag *f)
{
	int i;

	for (i = 0; i < XSC_IFC_ACTION_U64_NUM; i++) {
		if (f->bits[i])
			return false;
	}
	return true;
}

#define XSC_IFC_ACTION_IS_SET(flags)  (!xsc_ifc_action_flag_is_empty(&(flags)))

#define GROUP_TBL_BITMAP	1
#define GROUP_TBL_PCT		BIT(0)
#define GROUP_TBL_WCT		BIT(1)
#define GROUP_TBL_EM		BIT(2)
#define GROUP_TBL_WCT_CHAIN	BIT(3)

#define XSC_HW_FLOW_CT_TYPE_FT		BIT(0)
#define XSC_HW_FLOW_CT_TYPE_EACL	BIT(1)

#define XSC_HW_FLOW_ADD_TBL(hw_flow, tbl_type, res_hw_tbl)			\
do {										\
	hw_flow->hw_tbl_array[hw_flow->hw_tbl_num].hw_tbl = res_hw_tbl;		\
	hw_flow->hw_tbl_array[hw_flow->hw_tbl_num].ofld_tbl_type = tbl_type;	\
	hw_flow->hw_tbl_num++;							\
	atomic_inc(&res_hw_tbl->refcnt);					\
} while (0)

#define WCT_AD_TYPE_TO_FAT		BIT(0)
#define WCT_AD_TYPE_TO_FT		BIT(1)

#define PCT_AD_TYPE_TO_FDIR		BIT(0)
#define PCT_AD_TYPE_TO_WCT		BIT(1)
#define PCT_AD_TYPE_TO_FT		BIT(2)
#define PCT_AD_TYPE_TO_CHAIN_WCT	BIT(3)
#define PCT_AD_TYPE_TO_CHAIN_FT		BIT(4)

struct xsc_flow_em_key {
	u32 prf_bitmap;  // 17 bits
	u8 table_id;  // 8 bits
	u16 logic_in_port;  // 11 bits
	u32 tunnel_id;  // 24 bits
	u8 smac[6];  // 48 bits
	u8 dmac[6];  // 48 bits
	u16 vid;  // 16 bits
	u8 ip_tp_type;  // 5 bits
	u8 sip_v6h[12];  // 96 bits
	u32 sip_v4_v6l;  // 32 bits
	u8 dip_v6h[12];  // 96 bits
	u32 dip_v4_v6l;  // 32 bits
	u16 sport_type;  // 16 bits
	u16 dport_code;  // 16 bits
	u8 ttl;  // 8 bits
	u8 dscp;  // 6 bits
	u16 udf0;  // 16 bits
	u16 udf1;  // 16 bits
	u16 udf2;  // 16 bits
};

struct xsc_flow_em_pf_match_key {
	u8 dip_mask_len;
	struct xsc_ifc_match_flag em_template;
};

struct xsc_flow_em_match_key {
	u8 table_id;
	u16 vport;
	u16 vhca_id;
	u32 tunnel_id;
	u8 smac[6];
	u8 dmac[6];
	u16 vid;
	u8 ip_type;
	u8 tp_type;
	u32 src_v4;
	u32 dst_v4;
	u8 src_v6[16];
	u8 dst_v6[16];
	u16 sport_type;
	u16 dport_code;
	u8 ttl;
	u8 dscp;
	u16 udf0;
	u16 udf1;
	u16 udf2;
	struct xsc_ifc_match_flag em_template;
};

struct xsc_flow_pct_match_key {
	u32 grp_id;
	u16 vport;
	u16 vhca_id;
	u16 sport;
	u8 direction;
	u8 ip_type;
	u8 tp_type;
	u8 dip[16];   //do value & mask
	//to add more

	struct xsc_ifc_match_flag pct_template;
};

struct xsc_flow_pct_action {
	u32 table_id;
};

struct xsc_flow_wct_key {
	u8 ingress;
	u8 egress;
	u16 vport;
	u16 vhca_id;
	//to add more
};

struct xsc_flow_wct_action {
	u32 table_id;
	u32 action_idx;
	//to add more
};

struct xsc_ifc_flow_attr {
	u32 table_id;
	u32 group_id;
	u32 start_flow_index;
	u32 end_flow_index;

	u16 vport;
	u16 vhca_id;

	u8 match_mask_enable;
	u8 ingress;
	u8 egress;
	u8 chain_no;
	u16 priority;
	u16 resv0;
	u8 dest_type;
	u8 tnl_valid;
	u8 fdir;
	u8 acl;

	struct xsc_ifc_match_flag match_fields;
	struct xsc_ifc_match_flag mask_fields;
	u8 resv1[8];
};

struct xsc_ifc_fte_match_set_lyr_2_4 {
	u8 src_mac[6];
	u8 dst_mac[6];
	u8 ip_type;
	u8 tp_type; //tcp or udp
	u16 ethertype;

	u8 dscp;
	u8 ttl_hoplimit;
	u8 icmp_code;
	u8 icmp_type;

	u16 dport;
	u16 sport;

	u16 vlan_tpid;
	u16 vlan_id;
	u8  vlan_pcp;
	u8  resv0[3];

	u16 cvlan_tpid;
	u16 cvlan_id;
	u8  cvlan_pcp;
	u8  resv1[3];

	union {
		struct {
			u32 sip;
			u32 dip;
		} ipv4;
		struct {
			u8 src_addr[16];
			u8 dst_addr[16];
		} ipv6;
	};
	u8  resv2[16];
};

struct xsc_ifc_fte_match_set_misc {
	u16 vport;
	u16 vhca_id;
	u16 logical_in_port;
	u16 tag;

	u8 pkt_type;
	u8 member_bitmap;
	u32 tunnel_id;
	u8 tunnel_type;
	u8 resv0[3];

	u16 udf0;
	u16 udf1;
	u16 udf2;
	u16 resv1[9];
};

struct xsc_ifc_fte_match_param {
	struct xsc_ifc_fte_match_set_misc misc;
	struct xsc_ifc_fte_match_set_lyr_2_4 inner_headers;
	struct xsc_ifc_fte_match_set_lyr_2_4 outer_headers;
};

struct xsc_ifc_fte_match {
	struct xsc_ifc_flow_attr	attr;
	struct xsc_ifc_fte_match_param	match_mask;
	struct xsc_ifc_fte_match_param  match_value;
};

struct xsc_erspan_md2 {
	u8 hwid_upper;	//2 bits
	u8 ft;		//5 bits
	u8 p;		//1bits
	u8 o;		//1 bits
	u8 gra;		//2 bits
	u8 dir;		//1 bits
	u8 hwid;	//4 bits
};

struct session_index {
	u16 session;
	u32 index;
};

struct xsc_ifc_l2_encap_info {
	u8 ecp_pkt_type;
	u8 ecp_dmac[6];
	u8 ecp_smac[6];
	u8 ecp_vlan_flag;
	u8 ecp_ttl;
	u8 ip_type;
	union {
		struct {
			u32 ecp_sip;
			u32 ecp_dip;
		} ipv4;
		struct {
			u8 ecp_sip[16];
			u8 ecp_dip[16];
		} ipv6;
	};
	union {
		u32 tunnel_id;
		struct session_index si;
	};
	union {
		u16 ecp_sport;
		u16 sgt;
	};
	union {
		u16 ecp_dport;
		struct xsc_erspan_md2 md2;
	};
	u8 flags;
	union {
		u16 proto;
		u16 ecp_outport_id;
	};
	u8 opt_len;
	u8 opt_data[8];
	union {
		u8 vx_rsvd0[3];
		u32 vx_rsvd00;
	};
	u8 vx_rsvd1;
};

struct xsc_ifc_modify_hdr {
	u8 dst[6];
	u8 src[6];
	u16 tp_sport;
	u16 tp_dport;

	u8  time_to_live;
	u8  dscp;
	u8  ecn;
	u8  resv0;

	u32 src_addr;
	u32 dst_addr;
	u8 ipv6_src[16];
	u8 ipv6_dst[16];
};

struct xsc_ifc_mirror_info {
	struct xsc_ifc_l2_encap_info encap_info;
	struct xsc_ifc_action_flag type_flag;
	u16 port_id;
	u16 qpid;
	u16 mtr_id0;
	u8 pop_vlan;
	u8 nxt_mirror_index;
	u8 ratio;
	u8 direction;
};

struct xsc_ifc_vlan_info {
	u16 tpid;
	u16 vid;
	u8 pcp;
};

struct xsc_ifc_action {
	struct xsc_ifc_action_flag type_flag;
	u32 counter;
	u16 vport;
	u16 vhca_id;
	u16 port_id;
	u16 def_port;
	u8 queue_id;
	/* recirc */
	u8 recirc_flag;
	u16 recirc_id;
	u32 recirc_data;
	u16 tag;
	u8 mirror_flag;
	u8 chain_no;
	struct xsc_ifc_vlan_info vlan;
	struct xsc_ifc_vlan_info cvlan;
	struct xsc_ifc_l2_encap_info l2_encap_info;
	struct xsc_ifc_modify_hdr modify_hdr;
	struct xsc_ifc_mirror_info mirror_info;
};

struct xsc_ifc_hw_tbl {
	u32 idx;
};

struct xsc_ifc_flow_group {
	u32	grp_id;
	u16	priority;
	u32	base_idx;
	u32	max_entries;
	u8	direction;
	u8	is_reserved;
	u8	pct_ad_type;
	u8	wct_ad_type;
	u8	tbl_bitmap;
	u8	dst_port_flag;
	u8	grp_dip_mask_len;
	struct xsc_ifc_match_flag full_key;
	struct xsc_ifc_match_flag pct_template;
	struct xsc_ifc_match_flag wct_template;
	struct xsc_ifc_match_flag em_template;
};

struct xsc_create_hw_flow_req {
	u64 hw_tbl_bitmap;
	struct xsc_ifc_hw_tbl hw_tbl[XSC_OFLD_MAX_TBL_NUM];
	struct xsc_ifc_flow_group group;
	struct xsc_ifc_fte_match matches;
	struct xsc_ifc_action actions;
	//u16 actions_n; //TODO, not used
};

struct xsc_create_hw_flow_rsp {
	u64 hw_tbl_bitmap;
	struct xsc_ifc_hw_tbl hw_tbl[XSC_OFLD_MAX_TBL_NUM];  //for PRG tbl, eacl return idx
	struct xsc_flow_em_key em_key;  //return em key for em entry del
};

struct xsc_del_hw_flow_req {
	u64 hw_tbl_bitmap;
	struct xsc_ifc_hw_tbl hw_tbl[XSC_OFLD_MAX_TBL_NUM];
	struct xsc_flow_em_key em_key;
};

struct xsc_ifc_create_flow_group_in {
	struct xsc_ifc_flow_attr	match_attr;
	struct xsc_ifc_fte_match_param	match_mask;
};

struct xsc_flow_hw_tbl {
	struct xsc_hw_tbl *hw_tbl;
	enum xsc_offload_tbl ofld_tbl_type;
};

struct xsc_hw_flow {
	const struct xsc_ifc_flow_attr *attr;
	const struct xsc_ifc_fte_match_param *match;
	const struct xsc_ifc_fte_match_param *mask;
	const struct xsc_ifc_action *actions;
	struct xsc_flow_hw_tbl hw_tbl_array[XSC_MAX_TBL_NUM_PER_FLOW];
	u32 grp_id;
	u8 hw_tbl_num;
	u8 counter_type;    /* bit 0 off tbl, bit 1 on tbl, bit 2 eacl */
	u8 eacl_counter;
	u32 ft_counter;
	u64 last_pkt_cnt;
	u64 pkt_cnt;
};

struct xsc_ecp_tnl_action_data {
	u32 dmac_idx;
};

struct xsc_ecp_hdr_action_data {
	u32 smac_idx;
	u32 tp_tnl_idx;
	u32 sip_idx;
	u32 dip_idx;
};

struct xsc_ecp_tnl_tp_action_data {
	u32 dport_idx;
};

struct xsc_ifc_set_action_in {
	u8 action_type;
	u8 field;
	u8 resv0[2];

	u16 offset;
	u16 length;
	u8 data[16];
};

struct xsc_ifc_add_action_in {
	u8 action_type;
	u8 field;
	u8 resv0[2];
	u8 data[16];
};

struct xsc_ifc_copy_action_in {
	u8 action_type;
	u8 src_field;
	u16 src_offset;

	u8 dst_field;
	u8 dst_offset;
	u16 length;
};

union xsc_ifc_set_add_copy_action_in {
	struct xsc_ifc_set_action_in  set_action_in;
	struct xsc_ifc_add_action_in  add_action_in;
	struct xsc_ifc_copy_action_in copy_action_in;
	u32 resv0;
};

int xsc_hflow_create_group(struct xsc_core_device *dev,
			   struct xsc_flow_table *ft,
			   u32 *in,
			   struct xsc_flow_group *fg);
int xsc_hflow_destroy_group(struct xsc_core_device *dev,
			    struct xsc_flow_table *ft,
			    struct xsc_flow_group *fg);
int xsc_hflow_create_fte(struct xsc_core_device *dev,
			 struct xsc_ifc_fte_match *matches,
			 struct xsc_ifc_action *actions,
			 u32 grp_id, u32 *flow_id);
int xsc_hflow_delete_fte(struct xsc_core_device *dev,
			 struct xsc_flow_table *ft,
			 struct fs_fte *fte);

int xsc_hflow_counter_bulk_query(struct xsc_core_device *dev,
				 void *out, u32 base_id, u32 num_counters);
int xsc_hflow_counter_bulk_alloc(struct xsc_core_device *dev,
				 u32 *base_id, u32 num_counters);
int xsc_hflow_counter_bulk_free(struct xsc_core_device *dev,
				u32 base_id, u32 num_counters);

static inline void xsc_bytes_le2be(u8 *dst_addr, const u8 *src_addr, int size)
{
	int i;

	for (i = 0; i < size; i++)
		dst_addr[i] = src_addr[size - 1 - i];
}

#endif

