/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_FDIR_H_
#define _MCE_FDIR_H_

enum mce_fltr_ptype {
	MCE_FLTR_PTYPE_NONE = 0,
	MCE_FLTR_PTYPE_NONF_ETH,
	MCE_FLTR_PTYPE_IPV4_TCP,
	MCE_FLTR_PTYPE_IPV4_UDP,
	MCE_FLTR_PTYPE_IPV4_SCTP,
	MCE_FLTR_PTYPE_IPV4_OTHER,
	MCE_FLTR_PTYPE_IPV6_TCP,
	MCE_FLTR_PTYPE_IPV6_UDP,
	MCE_FLTR_PTYPE_IPV6_SCTP,
	MCE_FLTR_PTYPE_IPV6_OTHER,
};

struct mce_fdir_v4 {
	__be32 dst_ip;
	__be32 src_ip;
	__be16 dst_port;
	__be16 src_port;
	__be32 l4_header;
	__be32 sec_parm_idx;	/* security parameter index */
	u8 tos;
	u8 ip_ver;
	u8 proto;
	u8 ttl;
};

#define MCE_IPV6_ADDR_LEN_AS_U32		4
#define N20_MAX_ETYPE_FDIR_CNT (15)

struct mce_fdir_v6 {
	__be32 dst_ip[MCE_IPV6_ADDR_LEN_AS_U32];
	__be32 src_ip[MCE_IPV6_ADDR_LEN_AS_U32];
	__be16 dst_port;
	__be16 src_port;
	__be32 l4_header; /* next header */
	__be32 sec_parm_idx; /* security parameter index */
	u8 tc;
	u8 proto;
	u8 hlim;
};

struct mce_fdir_eth {
	u8 dst[ETH_ALEN];
	u8 src[ETH_ALEN];
	__be16 type;
};

struct mce_fdir_fltr {
	struct list_head fltr_node;
	struct mce_fdir_eth eth, eth_mask;
	union {
		struct mce_fdir_v4 v4;
		struct mce_fdir_v6 v6;
	} ip, mask;
	enum mce_fltr_ptype flow_type;
	u32 fltr_id;
	u32 q_id;
	u32 fltr_config;
	u32 fltr_action;
	int vfid;
	int etype_loc;
	int tuple5_loc;
#define F_FLTR_ACTION_DROP BIT(31)
};

struct mce_fdir_fltr *mce_fdir_find_fltr_by_idx(struct mce_hw *hw, u32 fltr_idx);
bool mce_fdir_is_dup_fltr(struct mce_hw *hw, struct mce_fdir_fltr *input);
void mce_fdir_del_fltrs(struct mce_hw *hw, bool del_fltr_node);
void mce_fdir_restore_fltr(struct mce_hw *hw);
int mce_handle_acl_filter(struct mce_hw *hw, struct mce_fdir_fltr *rule,
			  bool add);

#endif /* _MCE_FDIR_H_ */
