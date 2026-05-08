/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_rxft.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2VF_RXFT_H__
#define __SXE2VF_RXFT_H__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/bitfield.h>
#include <linux/ethtool.h>
#include "sxe2vf.h"

struct sxe2vf_rss_hash_cfg {
	DECLARE_BITMAP(headers, SXE2_FLOW_HDR_MAX);
	DECLARE_BITMAP(hash_flds, SXE2_FLOW_FLD_ID_MAX);
	bool symm;
};

struct sxe2vf_rss_cfg *
sxe2vf_find_rss_cfg_by_hdrs(struct sxe2vf_adapter *adapter,
			    unsigned long *hdrs);

void sxe2vf_analysis_hdrs(struct ethtool_rxnfc *nfc, unsigned long *hdrs);

void sxe2vf_analysis_hash_flds(struct ethtool_rxnfc *nfc,
			       unsigned long *hash_flds);

void sxe2vf_get_rss_flow(struct sxe2vf_adapter *adapter,
			 struct ethtool_rxnfc *nfc);

int sxe2vf_set_rss_flow(struct sxe2vf_adapter *adapter,
			struct ethtool_rxnfc *nfc);

void sxe2vf_rss_delete_cfg(struct sxe2vf_adapter *adapter);

s32 sxe2vf_rss_add_cfg(struct sxe2vf_adapter *adapter,
		       struct sxe2vf_rss_hash_cfg *hash_cfg, bool is_default);

s32 sxe2vf_rss_default_flow_set(struct sxe2vf_adapter *adapter);

s32 sxe2vf_rss_init(struct sxe2vf_adapter *adapter);

void sxe2vf_rss_deinit(struct sxe2vf_adapter *adapter);

s32 sxe2vf_rss_rebuild(struct sxe2vf_adapter *adapter);

s32 sxe2vf_set_channels_rss_reset(struct net_device *netdev,
				  struct sxe2vf_adapter *adapter, u32 new_queue);

#define SXE2VF_MAX_FNAV_FILTERS (128)
#define SXE2VF_FLEX_WORD_NUM (2)
#define SXE2VF_USERDEF_FLEX_WORD_M GENMASK(15, 0)
#define SXE2VF_USERDEF_FLEX_OFFS_S 16
#define SXE2VF_USERDEF_FLEX_OFFS_M GENMASK(31, SXE2VF_USERDEF_FLEX_OFFS_S)
#define SXE2VF_USERDEF_FLEX_FLTR_M GENMASK(31, 0)
#define SXE2VF_USERDEF_FLEX_MAX_OFFS_VAL 0x1FE

#define SXE2VF_FNAV_L4_PROT_TCP    6
#define SXE2VF_FNAV_L4_PROT_UDP    17
#define SXE2VF_FNAV_L4_PROT_SCTP   132

struct sxe2vf_ipv4_addrs {
	__be32 src_ip;
	__be32 dst_ip;
};

struct sxe2vf_ipv6_addrs {
	struct in6_addr src_ip;
	struct in6_addr dst_ip;
};

struct sxe2vf_fnav_eth {
	u8 src[SXE2_FNAV_ETH_ADDR_LEN];
	u8 dst[SXE2_FNAV_ETH_ADDR_LEN];
	__be16 etype;
};

struct sxe2vf_fnav_ip {
	union {
		struct sxe2vf_ipv4_addrs v4_addrs;
		struct sxe2vf_ipv6_addrs v6_addrs;
	};
	__be16 src_port;
	__be16 dst_port;
	__be32 l4_header;
	__be32 spi;
	union {
		u8 tos;
		u8 tclass;
	};
	u8 proto;
};

struct sxe2vf_fnav_extra {
	__be32 usr_def[SXE2VF_FLEX_WORD_NUM];
	__be16 vlan_type;
	__be16 s_vlan_tag;
	__be16 c_vlan_tag;
};

struct sxe2vf_fnav_filter_full_key {
	struct sxe2vf_fnav_eth eth_data;
	struct sxe2vf_fnav_eth eth_mask;

	struct sxe2vf_fnav_ip ip_data;
	struct sxe2vf_fnav_ip ip_mask;

	struct sxe2vf_fnav_extra ext_data;
	struct sxe2vf_fnav_extra ext_mask;

	u8 ip_ver;
};

void sxe2vf_fnav_deinit(struct sxe2vf_adapter *adapter);

s32 sxe2vf_fnav_init(struct sxe2vf_adapter *adapter);

u32 sxe2vf_fnav_max_filter_cnt_get(struct sxe2vf_adapter *adapter);

struct sxe2vf_fnav_filter *
sxe2vf_fnav_find_filter_by_loc_unlock(struct sxe2vf_adapter *adapter, u32 loc);

u32 sxe2vf_flow_type_to_ethtool_flow(enum sxe2_fnav_flow_type flow_type);

enum sxe2_fnav_flow_type sxe2vf_ethtool_flow_to_type(u32 flow);

int sxe2vf_ethtool_fnav_filter_get_by_loc(struct sxe2vf_adapter *adapter,
					  struct ethtool_rxnfc *cmd);

int sxe2vf_ethtool_ntuple_filter_locs_get(struct sxe2vf_adapter *adapter,
					  struct ethtool_rxnfc *cmd,
					  u32 *filter_locs);

bool sxe2vf_fnav_filter_cmp(struct sxe2vf_fnav_filter *fltrA,
			    struct sxe2vf_fnav_filter *fltrB);

struct sxe2vf_fnav_filter *
sxe2vf_fnav_filter_search_for_dup(struct sxe2vf_adapter *adapter,
				  struct sxe2vf_fnav_filter *filter);

s32 sxe2vf_fnav_del_filter(struct sxe2vf_adapter *adapter,
			   struct sxe2vf_fnav_filter *filter);

s32 sxe2vf_fnav_all_filter_del(struct sxe2vf_adapter *adapter);

bool sxe2vf_fnav_is_dup_filter(struct sxe2vf_adapter *adapter,
			       struct sxe2vf_fnav_filter *filter);

s32 sxe2vf_fnav_rebuild(struct sxe2vf_adapter *adapter);

int sxe2vf_set_channels_fnav_check(struct sxe2vf_adapter *adapter, u32 new_cnt);

#endif
