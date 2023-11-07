/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2023 Mucse Corporation. */

#ifndef __RNP_TC_U32_PARSE_H__
#define __RNP_TC_U32_PARSE_H__
#include "rnp.h"

struct rnp_match_parser {
	int off; /* the skb offset begin form the 12 bytes mac_type */
	/* parse the value/mask to realy value*/
	int (*val)(struct rnp_fdir_filter *f, __be32 val, __be32 mask);
};
/* Ipv4 Rule Parse */
static inline int rnp_fill_ipv4_src_ip(struct rnp_fdir_filter *f,
				       __be32 val, __be32 mask)
{
	memcpy(&f->filter.formatted.src_ip[0], &val, sizeof(u32));
	memcpy(&f->filter.formatted.src_ip_mask[0], &mask, sizeof(u32));

	f->filter.formatted.flow_type = RNP_ATR_FLOW_TYPE_IPV4;
	f->filter.layer2_formate.proto = htons(ETH_P_IP);

	return 0;
}

static inline int rnp_fill_ipv4_dst_ip(struct rnp_fdir_filter *f,
				       __be32 val, __be32 mask)
{
	memcpy(&f->filter.formatted.dst_ip[0], &val, sizeof(u32));
	memcpy(&f->filter.formatted.dst_ip_mask[0], &mask, sizeof(u32));

	f->filter.formatted.flow_type = RNP_ATR_FLOW_TYPE_IPV4;
	f->filter.layer2_formate.proto = htons(ETH_P_IP);

	return 0;
}

static const struct rnp_match_parser rnp_ipv4_parser[] = {
	{ .off = 12, .val = rnp_fill_ipv4_src_ip },
	{ .off = 16, .val = rnp_fill_ipv4_dst_ip },
	{ .val = NULL }
};

#endif
