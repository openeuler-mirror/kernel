/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */
#ifndef NBL_IB_AH_H
#define NBL_IB_AH_H

#include <linux/kernel.h>
#include <rdma/ib_verbs.h>
#include <linux/if_ether.h>

#include "nbl_adapt.h"
#include "main.h"

#define NBL_AH_VECTOR_IPV4_VALID 0x1
#define NBL_AH_VECTOR_VLAN_TAG 0x2
#define NBL_ROCE_MIN_SRC_UDP_SPORT 49152
#define NBL_GRH_DGID_RAW_SIZE 16

#define NBL_GET_PRI_FROM_TOS(tos) (((tos) >> 5) & 0x7)

/*
 * address vector info struct
 */
struct nbl_av {
	u32 q_key;
	u32 dest_qp;
	u8 eth_prio;
	u8 vlan_tag_ipv4_valid;
	u16 udp_sport;
	u8 dest_mac[ETH_ALEN];
	u8 tclass;
	u8 hop_limit;
	u32 flow_label;
	u32 pd_idx;
	u16 vlan_id;
	u8 src_addr_index;
	u8 rsv;
	u8 dest_ip[16];
};

/*
 * address handle info struct
 */
struct nbl_ah {
	struct ib_ah ibah;
	struct nbl_sc_dev *dev;
	struct nbl_pd *pd;
	struct nbl_av av;
	u32 ah_id;
	u8 sgid_index; /* used for querying address handle info */
	u8 rsv[3];
};

static inline struct nbl_ah *to_nbl_ah(struct ib_ah *ah)
{
	return container_of(ah, struct nbl_ah, ibah);
}

u16 nbl_ah_get_udp_sport(const struct nbl_device *dev,
			 const struct rdma_ah_attr *ah_attr);

/* create ah */
int nbl_ib_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr,
		     struct ib_udata *udata);

/* destroy ah */
int nbl_ib_destroy_ah(struct ib_ah *ibah, u32 flags);
int nbl_ib_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *ah_attr);

#endif /* NBL_IB_AH_H */
