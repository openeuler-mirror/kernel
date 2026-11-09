/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
#ifndef NSER_UDA_H
#define NSER_UDA_H

#define NSER_UDA_MAX_FSI_MGS	4096
#define NSER_UDA_MAX_PFS	16
#define NSER_UDA_MAX_VFS	128

struct nser_sc_cqp;

struct nser_ah_info {
	struct nser_sc_vsi *vsi;
	u32 pd_idx;
	u32 dst_arpindex;
	u32 dest_ip_addr[4];
	u32 src_ip_addr[4];
	u32 flow_label;
	u32 ah_idx;
	u16 vlan_tag;
	u8 insert_vlan_tag;
	u8 tc_tos;
	u8 hop_ttl;
	u8 mac_addr[ETH_ALEN];
	bool ah_valid:1;
	bool ipv4_valid:1;
	bool do_lpbk:1;
};

struct nser_sc_ah {
	struct nser_sc_dev *dev;
	struct nser_ah_info ah_info;
	struct nser_cqp_request *req;
};

int nser_sc_add_mcast_grp(struct nser_mcast_grp_info *ctx,
			   struct nser_mcast_grp_ctx_entry_info *mg);
int nser_sc_del_mcast_grp(struct nser_mcast_grp_info *ctx,
			   struct nser_mcast_grp_ctx_entry_info *mg);
int nser_sc_access_ah(struct nser_sc_cqp *cqp, struct nser_ah_info *info,
		       u32 op, u64 scratch);
int nser_access_mcast_grp(struct nser_sc_cqp *cqp,
			   struct nser_mcast_grp_info *info, u32 op,
			   u64 scratch);

static inline void nser_sc_init_ah(struct nser_sc_dev *dev, struct nser_sc_ah *ah)
{
	ah->dev = dev;
}

static inline int nser_sc_create_ah(struct nser_sc_cqp *cqp,
				     struct nser_ah_info *info, u64 scratch)
{
	return nser_sc_access_ah(cqp, info, NSER_CQP_OP_CREATE_ADDR_HANDLE,
				  scratch);
}

static inline int nser_sc_destroy_ah(struct nser_sc_cqp *cqp,
				      struct nser_ah_info *info, u64 scratch)
{
	return nser_sc_access_ah(cqp, info, NSER_CQP_OP_DESTROY_ADDR_HANDLE,
				  scratch);
}

static inline int nser_sc_create_mcast_grp(struct nser_sc_cqp *cqp,
					    struct nser_mcast_grp_info *info,
					    u64 scratch)
{
	return nser_access_mcast_grp(cqp, info, NSER_CQP_OP_CREATE_MCAST_GRP,
				      scratch);
}

static inline int nser_sc_modify_mcast_grp(struct nser_sc_cqp *cqp,
					    struct nser_mcast_grp_info *info,
					    u64 scratch)
{
	return nser_access_mcast_grp(cqp, info, NSER_CQP_OP_MODIFY_MCAST_GRP,
				      scratch);
}

static inline int nser_sc_destroy_mcast_grp(struct nser_sc_cqp *cqp,
					     struct nser_mcast_grp_info *info,
					     u64 scratch)
{
	return nser_access_mcast_grp(cqp, info, NSER_CQP_OP_DESTROY_MCAST_GRP,
				      scratch);
}
#endif /* NSER_UDA_H */
