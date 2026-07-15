/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_flow.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_FLOW_H__
#define __SXE2_FLOW_H__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/bitfield.h>
#include "sxe2_cmd_channel.h"
#include "sxe2_mbx_public.h"

struct sxe2_adapter;
struct sxe2_rss_ctxt;
struct sxe2_acl_scen_info;
struct sxe2_acl_flow_entry;
struct sxe2_acl_flow_action;

#if (BITS_PER_LONG == 64)
#define SXE2_PTYPE_MAP_SIZE 16
#define SXE2_PTYPE_BITMAP(high3, high2, high1, high0, low3, low2, low1, low0)  \
	(0x##high3##high2##high1##high0##low3##low2##low1##low0##ULL)
#elif (BITS_PER_LONG == 32)
#define SXE2_PTYPE_MAP_SIZE 32
#define SXE2_PTYPE_BITMAP(high3, high2, high1, high0, low3, low2, low1, low0)  \
	(0x##low3##low2##low1##low0, 0x##high3##high2##high1##high0)
#else
#define SXE2_PTYPE_MAP_SIZE 0
#define SXE2_PTYPE_BITMAP(high3, high2, high1, high0, low3, low2, low1, low0)  \
	(0x##low3##low2##low1##low0, 0x##high3##high2##high1##high0)
#error please modify macro SXE2_PTYPE_MAP_SIZE and SXE2_PTYPE_BITMAP
#endif

#define SXE2_FV_OFFSET_INVAL  0x1FF
#define SXE2_FV_PORT_ID_INVAL 0xFF
#define SXE2_FV_MASK_NUM      32
#define SXE2_MAX_FV_WORDS	   48
#define SXE2_MAX_PTYPE_NUM	   1024
#define SXE2_MAX_CDID_NUM	   8
#define SXE2_MAX_PTG_NUM	   256
#define SXE2_MAX_VSIG_NUM	   768
#define SXE2_MAX_VSI_NUM	   768
#define SXE2_MAX_PROF_NUM	   256
#define SXE2_MAX_PTG_PER_PROF_NUM  64
#define SXE2_MAX_TCAM_PER_PROF_NUM 64
#define SXE2_MAX_DISSECTOR_NUM	   2
#define SXE2_MAX_RAW_CNT	   2
#define SXE2_MAX_TCAM_NUM	   512
#define SXE2_MAX_FV_MASK	   32
#define SXE2_PPP_DEFAULT_VSIG_IDX  0
#define SXE2_TCAM_DEFAULT_CD_ID	   0
#define SXE2_TCAM_DEFAULT_FLAGS	   0

#define SXE2_FNAV_PROF_CNT (128)
#define SXE2_RSS_PROF_CNT  (128)
#define SXE2_ACL_PROF_CNT  (128)
#define SXE2_FNAV_FV_CNT   (30)
#define SXE2_RSS_FV_CNT	   (24)
#define SXE2_ACL_FV_CNT	   (32)

#define SXE2_FLOW_DISSECTOR_SINGLE 1
#define SXE2_FLOW_DISSECTOR_DOUBLE 2

#define SXE2_TCAM_KEY_VAL_SZ	      5
#define SXE2_TCAM_KEY_SZ	      (2 * SXE2_TCAM_KEY_VAL_SZ)
#define SXE2_KEY_MATCH_MAX_NM_SET_NUM 1

#define SXE2_FLOW_FV_SIZE (2)

#define SXE2_U8_MASK  (0xFF)
#define SXE2_U16_MASK (0xFFFF)

#pragma pack(1)
struct sxe2_fv_word {
	u8 prot_id;
	u16 off;
	u8 resvrd;
};

#pragma pack()

enum sxe2_prot_id {
	SXE2_PROT_ID_INVAL	  = 0,
	SXE2_PROT_MAC_OF_OR_S	  = 1,
	SXE2_PROT_MAC_O2	  = 2,
	SXE2_PROT_MAC_IL	  = 4,
	SXE2_PROT_MAC_IN_MAC	  = 7,
	SXE2_PROT_ETYPE_OL	  = 9,
	SXE2_PROT_ETYPE_IL	  = 10,
	SXE2_PROT_PAY		  = 15,
	SXE2_PROT_EVLAN_O	  = 16,
	SXE2_PROT_VLAN_O	  = 17,
	SXE2_PROT_VLAN_IF	  = 18,
	SXE2_PROT_MPLS_OL_MINUS_1 = 27,
	SXE2_PROT_MPLS_OL_OR_OS	  = 28,
	SXE2_PROT_MPLS_IL	  = 29,
	SXE2_PROT_IPV4_OF_OR_S	  = 32,
	SXE2_PROT_IPV4_IL	  = 33,
	SXE2_PROT_IPV4_IL_IL	  = 34,
	SXE2_PROT_IPV6_OF_OR_S	  = 40,
	SXE2_PROT_IPV6_IL	  = 41,
	SXE2_PROT_IPV6_IL_IL	  = 42,
	SXE2_PROT_IPV6_NEXT_PROTO = 43,
	SXE2_PROT_IPV6_FRAG	  = 47,
	SXE2_PROT_TCP_IL	  = 49,
	SXE2_PROT_UDP_OF	  = 52,
	SXE2_PROT_UDP_IL_OR_S	  = 53,
	SXE2_PROT_GRE_OF	  = 64,
	SXE2_PROT_NSH_F		  = 84,
	SXE2_PROT_ESP_F		  = 88,
	SXE2_PROT_ESP_2		  = 89,
	SXE2_PROT_SCTP_IL	  = 96,
	SXE2_PROT_ICMP_IL	  = 98,
	SXE2_PROT_ICMPV6_IL	  = 100,
	SXE2_PROT_VRRP_F	  = 101,
	SXE2_PROT_OSPF		  = 102,
	SXE2_PROT_PPPOE		  = 103,
	SXE2_PROT_L2TPV3	  = 104,
	SXE2_PROT_ECPRI		  = 105,
	SXE2_PROT_PPP		  = 106,
	SXE2_PROT_ATAOE_OF	  = 114,
	SXE2_PROT_CTRL_OF	  = 116,
	SXE2_PROT_LLDP_OF	  = 117,
	SXE2_PROT_ARP_OF	  = 118,
	SXE2_PROT_EAPOL_OF	  = 120,
	SXE2_PROT_META_ID	  = 255,
	SXE2_PROT_INVALID = 255
};

enum sxe2_flow_priority {
	SXE2_FLOW_PRIO_LEVEL_OUTER_ETH = 0,
	SXE2_FLOW_PRIO_LEVLE_OUTER_L3,
	SXE2_FLOW_PRIO_LEVEL_OUTER_L3_FRAG,
	SXE2_FLOW_PRIO_LEVEL_OUTER_L4,
	SXE2_FLOW_PRIO_LEVEL_INNER_ETH,
	SXE2_FLOW_PRIO_LEVEL_INNER_L3,
	SXE2_FLOW_PRIO_LEVLE_INNER_L3_FRAG,
	SXE2_FLOW_PRIO_LEVEL_INNER_L4,
	SXE2_FLOW_PRIO_LEVEL_HIGHEST,
};

#define SXE2_FLOW_FLD_SZ_ETH_TYPE	    2
#define SXE2_FLOW_FLD_SZ_VLAN		    2
#define SXE2_FLOW_FLD_SZ_IPV4_ADDR	    4
#define SXE2_FLOW_FLD_SZ_IPV6_ADDR	    16
#define SXE2_FLOW_FLD_SZ_IPV6_PRE32_ADDR    4
#define SXE2_FLOW_FLD_SZ_IPV6_PRE48_ADDR    6
#define SXE2_FLOW_FLD_SZ_IPV6_PRE64_ADDR    8
#define SXE2_FLOW_FLD_SZ_IPV4_ID	    2
#define SXE2_FLOW_FLD_SZ_IPV6_ID	    4
#define SXE2_FLOW_FLD_SZ_IP_CHKSUM	    2
#define SXE2_FLOW_FLD_SZ_TCP_CHKSUM	    2
#define SXE2_FLOW_FLD_SZ_UDP_CHKSUM	    2
#define SXE2_FLOW_FLD_SZ_SCTP_CHKSUM	    4
#define SXE2_FLOW_FLD_SZ_IP_DSCP	    1
#define SXE2_FLOW_FLD_SZ_IP_TTL		    1
#define SXE2_FLOW_FLD_SZ_IP_PROT	    1
#define SXE2_FLOW_FLD_SZ_PORT		    2
#define SXE2_FLOW_FLD_SZ_TCP_FLAGS	    1
#define SXE2_FLOW_FLD_SZ_ICMP_TYPE	    1
#define SXE2_FLOW_FLD_SZ_ICMP_CODE	    1
#define SXE2_FLOW_FLD_SZ_ARP_OPER	    2
#define SXE2_FLOW_FLD_SZ_GRE_KEYID	    4
#define SXE2_FLOW_FLD_SZ_GTP_TEID	    4
#define SXE2_FLOW_FLD_SZ_GTP_QFI	    2
#define SXE2_FLOW_FLD_SZ_PPPOE_SESS_ID	    2
#define SXE2_FLOW_FLD_SZ_PFCP_SEID	    8
#define SXE2_FLOW_FLD_SZ_L2TPV3_SESS_ID	    4
#define SXE2_FLOW_FLD_SZ_ESP_SPI	    4
#define SXE2_FLOW_FLD_SZ_AH_SPI		    4
#define SXE2_FLOW_FLD_SZ_NAT_T_ESP_SPI	    4
#define SXE2_FLOW_FLD_SZ_VXLAN_VNI	    4
#define SXE2_FLOW_FLD_SZ_ECPRI_TP0_PC_ID    2
#define SXE2_FLOW_FLD_SZ_L2TPV2_SESS_ID	    2
#define SXE2_FLOW_FLD_SZ_L2TPV2_LEN_SESS_ID 2
#define SXE2_FLOW_FLD_SZ_GENEVE_VNI	    4
#define SXE2_FLOW_FLD_SZ_GTPU_TEID	    4
#define SXE2_FLOW_FLD_SZ_GRE_TNI	    4

struct sxe2_flow_fld_info {
	enum sxe2_flow_hdr hdr;
	u16 off;
	u16 size;
	u16 mask;
};

#define SXE2_FLOW_FLD_INFO(_hdr, _offset_bytes, _size_bytes)                   \
	{                                                                      \
		.hdr = _hdr, .off = (_offset_bytes) * BITS_PER_BYTE,             \
		.size = (_size_bytes) * BITS_PER_BYTE, .mask = 0,                \
	}

#define SXE2_FLOW_FLD_INFO_MASK(_hdr, _offset_bytes, _size_bytes, _mask)       \
	{                                                                      \
		.hdr = _hdr, .off = (_offset_bytes) * BITS_PER_BYTE,             \
		.size = (_size_bytes) * BITS_PER_BYTE, .mask = _mask,            \
	}

struct sxe2_flow_fld_xtrct {
	u8 prot_id;
	u16 off;
	u8 idx;
	u8 disp;
	u16 mask;
};

enum sxe2_flow_fld_type {
	SXE2_FLOW_FLD_TYPE_VAL,
	SXE2_FLOW_FLD_TYPE_RANGE,
};

struct sxe2_flow_fld_val {
	u16 val;
	u16 mask;
	u16 len;
};

struct sxe2_flow_fld {
	enum sxe2_flow_fld_type type;
	struct sxe2_flow_fld_val fld_val;
	struct sxe2_flow_fld_val last_val;
	struct sxe2_flow_fld_xtrct xtrct;
};

struct sxe2_flow_raw {
	u16 offset;
	struct sxe2_flow_fld fld;
};

struct sxe2_flow_dissector_info {
	DECLARE_BITMAP(headers, SXE2_FLOW_HDR_MAX);
	DECLARE_BITMAP(fields,
		       SXE2_FLOW_FLD_ID_MAX);
	struct sxe2_flow_fld fld[SXE2_FLOW_FLD_ID_MAX];
	struct sxe2_flow_raw raw[SXE2_MAX_RAW_CNT];
	u8 raw_cnt;
};

struct sxe2_prof_ptg_info {
	u8 ptg_cnt;
	u8 ptg[SXE2_MAX_PTG_PER_PROF_NUM];
};

struct sxe2_prof_tcam_full_key {
	__le64 vsig : 12;
	__le64 flg : 16;
	__le64 ptg : 8;
	__le64 cdid : 4;
	__le64 pad : 24;
};

#pragma pack(1)
struct sxe2_prof_tcam_entry {
	__le16 addr;
	u8 key[SXE2_TCAM_KEY_SZ];
	u8 prof_id;
};

#pragma pack()

struct sxe2_prof_tcam_info {
	u16 idx;
	u8 ptg;
	u8 prof_id;
	bool used;
};

struct sxe2_flow_info_node {
	struct list_head l_node;

	u8 prof_id;

	u8 dissector_cnt;

	u8 priority;

	struct sxe2_flow_dissector_info dissectors[SXE2_MAX_DISSECTOR_NUM];
	union {
		struct sxe2_acl_scen_info *scen;
		bool symm;
	} cfg;
	struct sxe2_prof_ptg_info ptg_info;
	DECLARE_BITMAP(used_vsi, SXE2_MAX_VSI_NUM);
	/* in order to protect the data */
	struct mutex acl_entry_lock;
	struct list_head acl_entry;
};

struct sxe2_flow_hw_prof {
	struct sxe2_fv_word fv[SXE2_MAX_FV_WORDS];
	u32 fv_masks_sel;
	u16 ref_cnt;
	bool avail;
};

struct sxe2_fv_mask {
	u16 mask_idx;
	u16 mask;
	DECLARE_BITMAP(filds, SXE2_FLOW_FLD_ID_MAX);
};

struct sxe2_associated_flow_node {
	struct list_head l_node;
	struct sxe2_flow_info_node *flow_ptr;
	struct sxe2_prof_tcam_info tcams[SXE2_MAX_TCAM_PER_PROF_NUM];
	u16 tcam_cnt;
};

struct sxe2_vsi_group {
	struct list_head associated_flow_list;
	DECLARE_BITMAP(vsis, SXE2_MAX_VSI_NUM);
	u16 vsi_cnt;
	bool used;
};

struct sxe2_vsi_to_vsig {
	u16 idx;
};

struct sxe2_ptype_to_group {
	u8 idx;
};

struct sxe2_ppp_common_ctxt {
	struct list_head flow_list;
	/* in order to protect the data */
	struct mutex flow_list_lock;
	struct sxe2_ptype_to_group
		pt_to_grp[SXE2_MAX_PTYPE_NUM];
	struct sxe2_vsi_group vsig
		[SXE2_MAX_VSIG_NUM];
	struct sxe2_vsi_to_vsig
		vsi_to_grp[SXE2_MAX_VSI_NUM];

	struct sxe2_flow_hw_prof
		hw_prof[SXE2_MAX_PROF_NUM];
	struct sxe2_fv_mask fv_mask[SXE2_MAX_FV_MASK];
	struct sxe2_prof_tcam_entry
		tcam_entry[SXE2_MAX_TCAM_NUM];
	u8 hw_prof_num;
	u8 hw_fv_num;
	u8 hw_fv_mask_num;
	enum sxe2_block_id block_id;
	struct sxe2_adapter *adapter;
};

struct sxe2_flow_info_params {
	struct sxe2_flow_info_node *flow_info;
	struct sxe2_fv_word fv[SXE2_MAX_FV_WORDS];
	u16 fv_mask[SXE2_MAX_FV_WORDS];
	u8 fv_cnt;
	DECLARE_BITMAP(ptypes, SXE2_MAX_PTYPE_NUM);
	u16 match_size;
};

struct sxe2_rss_hash_cfg {
	DECLARE_BITMAP(headers, SXE2_FLOW_HDR_MAX);
	DECLARE_BITMAP(hash_flds,
		       SXE2_FLOW_FLD_ID_MAX);
	enum sxe2_rss_cfg_hdr_type hdr_type;
	bool symm;
};

struct sxe2_rss_cfg {
	struct list_head l_node;
	DECLARE_BITMAP(vsis, SXE2_MAX_VSI_NUM);
	struct sxe2_rss_hash_cfg hash_cfg;
};

struct sxe2_rss_symm_fv_pair {
	u16 src_fld;
	u16 dst_fld;
	u8 fld_len;
};

enum sxe2_og_chg_type {
	SXE2_OG_CHG_TYPE_XLT2,
	SXE2_OG_CHG_TYPE_TCAM,
	SXE2_OG_CHG_TYPE_ES,
	SXE2_OG_CHG_TYPE_MAX,
};

struct sxe2_og_chg {
	struct list_head l_entry;
	enum sxe2_og_chg_type type;
	union og_chg_info {
		struct sxe2_og_chg_xlt2 {
			u16 vsi_hw_idx;
			u16 vsig;
		} xlt2;
		struct sxe2_og_chg_tcam {
			u16 tcam_idx;
			u8 prof_id;
		} tcam;
		struct sxe2_og_chg_es {
			u8 prof_id;
		} es;
	} info;
};

#define SXE2_FLD_BIT (32)
#define SXE2_FLD_WIDTH (32)
struct sxe2_ddp_fnav_mask {
	u32 val : 16;
	u32 rsv : 16;
	u32 fldbit_l;
	u32 fldbit_h;
};

struct sxe2_ddp_rxft_ptg {
	u32 ptg0 : 8;
	u32 ptg1 : 8;
	u32 ptg2 : 8;
	u32 ptg3 : 8;
};

struct sxe2_ddp_acl_ptg {
	u32       ptg0                :8;
	u32       ptg1                :8;
	u32       ptg2                :8;
	u32       ptg3                :8;
};

struct sxe2_ptype_map {
	unsigned long sxe2_ptypes_mac_ofos_all
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_mac_il_all
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_mac_ofos_with_l3
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_mac_il_with_l3
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_mac_ofos_no_l3
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_mac_il_no_l3
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv4_ofos_with_l4
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv4_il_with_l4
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv6_ofos_with_l4
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv6_il_with_l4
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv4_ofos_no_l4
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv4_il_no_l4
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv6_ofos_no_l4
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv6_il_no_l4
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_udp_ofos
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_udp_il
		[SXE2_PTYPE_MAP_SIZE];

	unsigned long sxe2_ptypes_tcp_ofos[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_tcp_il[SXE2_PTYPE_MAP_SIZE];

	unsigned long sxe2_ptypes_sctp_ofos[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_sctp_il[SXE2_PTYPE_MAP_SIZE];

	unsigned long sxe2_ptypes_vxlan_vni
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_gre_of
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv4_ofos_frag
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv4_il_frag
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv6_ofos_frag
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv6_il_frag
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv4_ofos_all
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv4_il_all
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv6_ofos_all
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_ipv6_il_all
		[SXE2_PTYPE_MAP_SIZE];
	unsigned long sxe2_ptypes_gtpu
		[SXE2_PTYPE_MAP_SIZE];
};

enum sxe2_fnav_seg_type {
	SXE2_FNAV_SEG_NON_TUN = 0,
	SXE2_FNAV_SEG_TUN,
	SXE2_FNAV_SEG_MAX,
};

struct sxe2_fnav_flow_raw {
	u16 offset;
	u8 len;
};

struct sxe2_fnav_flow_seg {
	DECLARE_BITMAP(headers, SXE2_FLOW_HDR_MAX);
	DECLARE_BITMAP(fields, SXE2_FLOW_FLD_ID_MAX);
	struct sxe2_fnav_flow_raw raw[SXE2_MAX_RAW_CNT];
	u8 raw_cnt;
	DECLARE_BITMAP(vsis, SXE2_MAX_VSI_NUM);
	bool is_tunnel;
	struct sxe2_flow_info_node *flow_ptr;
};

struct sxe2_fnav_vsi_used_cnt {
	u16 vsi_id_sw;
	u32 filter_cnt;
};

struct sxe2_fnav_flow_cfg {
	struct list_head l_node;
	struct sxe2_fnav_flow_seg *seg[SXE2_FNAV_SEG_MAX];
	u32 filter_cnt[SXE2_FNAV_SEG_MAX];
	bool full_match;
	enum sxe2_fnav_flow_type flow_type;
	struct sxe2_fnav_vsi_used_cnt peer_vsi_used;
	struct sxe2_fnav_vsi_used_cnt self_vsi_used;
};

void sxe2_flow_set_diss_fld(struct sxe2_flow_dissector_info *dissector,
			    enum sxe2_flow_fld_id fld, u16 val, u16 mask,
			    u16 len);

void sxe2_flow_add_diss_raw(struct sxe2_flow_dissector_info *dissector, u16 off,
			    u16 val, u16 mask, u8 len);

struct sxe2_flow_info_node *
sxe2_find_flow(struct sxe2_ppp_common_ctxt *ppp_ctxt,
	       struct sxe2_flow_dissector_info *dissectors, u8 dissectors_cnt);

s32 sxe2_flow_creat(struct sxe2_ppp_common_ctxt *ppp_ctxt,
		    struct sxe2_flow_dissector_info *dissectors,
		    u8 dissectors_cnt, struct sxe2_flow_info_node **flow);

s32 sxe2_flow_delete(struct sxe2_ppp_common_ctxt *ppp_ctxt,
		     struct sxe2_flow_info_node *flow);

s32 sxe2_flow_assoc_vsi(struct sxe2_ppp_common_ctxt *ppp_ctxt,
			struct sxe2_flow_info_node *flow, u16 vsi_sw_idx);

s32 sxe2_flow_disassoc_vsi(struct sxe2_ppp_common_ctxt *ppp_ctxt,
			   struct sxe2_flow_info_node *flow, u16 vsi_sw_idx);

s32 sxe2_add_rss_flow(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx,
		      const struct sxe2_rss_hash_cfg *cfg);

s32 sxe2_rss_delete_vsi_flows_for_vfr(struct sxe2_rss_ctxt *rss_ctxt,
				      u16 vsi_sw_idx);

s32 sxe2_rss_delete_vsi_flows(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx);

void sxe2_flow_ppp_comm_ctxt_init(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				  struct sxe2_adapter *adapter,
				  enum sxe2_block_id block_id);
void sxe2_flow_ppp_comm_ctxt_deinit(struct sxe2_ppp_common_ctxt *ppp_ctxt);

void sxe2_flow_ppp_comm_ctxt_clean(struct sxe2_ppp_common_ctxt *ppp_ctxt);

void sxe2_rss_ppp_ctxt_clean(struct sxe2_rss_ctxt *rss_ctxt);

s32 sxe2_rss_add_cfg(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx,
		     const struct sxe2_rss_hash_cfg *cfg);

s32 sxe2_rss_rem_cfg(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx,
		     const struct sxe2_rss_hash_cfg *cfg);

void sxe2_rss_get_hash_cfg_with_hdrs(struct sxe2_rss_ctxt *rss_ctxt,
				     u16 vsi_sw_idx, unsigned long *headers,
				     unsigned long *hash_flds);

s32 sxe2_rss_replay_hash_cfg(struct sxe2_rss_ctxt *rss_ctxt, u16 vsi_sw_idx);

void sxe2_rss_comm_init(struct sxe2_rss_ctxt *rss_ctxt);

void sxe2_rss_comm_deinit(struct sxe2_rss_ctxt *rss_ctxt);

s32 sxe2_flow_update_fv_mask_sel(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				 u8 prof_id, u32 mask_sel);

s32 sxe2_flow_default_mask_get(enum sxe2_block_id block_id,
			       struct sxe2_adapter *adapter,
			       enum sxe2_flow_fld_id fld_id, u16 *mask_idx,
			       u16 *fv_idx);

void sxe2_rss_delete_vsi_cfg_list(struct sxe2_rss_ctxt *rss_ctxt,
				  u16 vsi_sw_idx);

void sxe2_flow_xlt2_dump(struct sxe2_ppp_common_ctxt *ppp_ctxt);

void sxe2_flow_vsig_dump(struct sxe2_ppp_common_ctxt *ppp_ctxt);

void sxe2_flow_prof_dump(struct sxe2_ppp_common_ctxt *ppp_ctxt);

void sxe2_flow_mask_dump(struct sxe2_ppp_common_ctxt *ppp_ctxt);

s32 sxe2_flow_find_vsig_with_vsi(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				 u16 vsi_sw_idx, u16 *vsig_idx);

s32 sxe2_flow_op_move_vsi_to_vsig(struct sxe2_ppp_common_ctxt *ppp_ctxt,
				  u16 vsi_sw_idx, u16 vsig_idx,
				  struct list_head *op_list);

s32 sxe2_fwc_update_profile(struct sxe2_ppp_common_ctxt *ppp_ctxt,
			    enum sxe2_block_id blk, struct list_head *chgs);

s32 sxe2_flow_cfg_clear_muti_vsi_in_vsig(struct sxe2_adapter *adapter,
					 struct sxe2_ppp_common_ctxt *ppp_ctxt,
					 u16 vsi_sw_idx);

s32 sxe2_flow_cfg_tcam_entry(struct sxe2_ppp_common_ctxt *ppp_ctxt,
			     u16 tcam_idx, u8 prof_id, u8 ptg_idx,
			     u16 vsig_idx, u8 cdid, u16 flags,
			     u8 vl_mask[SXE2_TCAM_KEY_VAL_SZ],
			     u8 dc_mask[SXE2_TCAM_KEY_VAL_SZ],
			     u8 nm_mask[SXE2_TCAM_KEY_VAL_SZ]);

s32 sxe2_rss_save_cfg_list(struct sxe2_rss_ctxt *rss_ctxt,
			   u16 vsi_sw_idx,
			   struct sxe2_flow_info_node *flow);

s32 sxe2_flow_acl_format_lut_act_entry(struct sxe2_adapter *adapter,
				       struct sxe2_acl_flow_entry *flow_entry,
				       struct sxe2_flow_info_node *flow,
				       struct sxe2_acl_flow_action *acts, u8 *data);

s32 sxe2_flow_assoc_vsi_fnav(struct sxe2_ppp_common_ctxt *ppp_ctxt,
			     struct sxe2_flow_info_node *flow,
			     u16 vsi_sw_idx, enum sxe2_fnav_flow_type flow_type);

#endif
