/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_FDIR_H_
#define _MCEVF_FDIR_H_

enum mcevf_fltr_ptype {
	MCEVF_FLTR_PTYPE_NONE = 0,
	MCEVF_FLTR_PTYPE_IPV4_TCP,
	MCEVF_FLTR_PTYPE_IPV4_UDP,
	MCEVF_FLTR_PTYPE_IPV4_SCTP,
	MCEVF_FLTR_PTYPE_IPV4_OTHER,
	MCEVF_FLTR_PTYPE_IPV6_TCP,
	MCEVF_FLTR_PTYPE_IPV6_UDP,
	MCEVF_FLTR_PTYPE_IPV6_SCTP,
	MCEVF_FLTR_PTYPE_IPV6_OTHER,
};

struct mcevf_fdir_v4 {
	__be32 dst_ip;
	__be32 src_ip;
	__be16 dst_port;
	__be16 src_port;
	__be32 l4_header;
	__be32 sec_parm_idx; /* security parameter index */
	u8 tos;
	u8 ip_ver;
	u8 proto;
	u8 ttl;
};

#define MCEVF_IPV6_ADDR_LEN_AS_U32 4

struct mcevf_fdir_v6 {
	__be32 dst_ip[MCEVF_IPV6_ADDR_LEN_AS_U32];
	__be32 src_ip[MCEVF_IPV6_ADDR_LEN_AS_U32];
	__be16 dst_port;
	__be16 src_port;
	__be32 l4_header; /* next header */
	__be32 sec_parm_idx; /* security parameter index */
	u8 tc;
	u8 proto;
	u8 hlim;
};

struct mcevf_fdir_fltr {
	struct list_head fltr_node;
	union {
		struct mcevf_fdir_v4 v4;
		struct mcevf_fdir_v6 v6;
	} ip, mask;
	enum mcevf_fltr_ptype flow_type;
	u32 fltr_id;
	u32 q_id;
	u32 fltr_config;
	u32 fltr_action;
#define F_FLTR_ACTION_DROP BIT(31)
};

struct mcevf_fdir_fltr *mcevf_fdir_find_fltr_by_idx(struct mcevf_hw *hw,
						    u32 fltr_idx);
bool mcevf_fdir_is_dup_fltr(struct mcevf_hw *hw,
			    struct mcevf_fdir_fltr *input);

#endif /* _MCEVF_FDIR_H_ */
