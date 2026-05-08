/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_ipsec.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2VF_IPSEC_H__
#define __SXE2VF_IPSEC_H__

#include <linux/pci.h>
#ifdef NEED_COMPAT_DIM
#include "sxe2_compat_dim.h"
#else
#include <linux/dim.h>
#endif
#include <linux/cpumask.h>
#include <linux/interrupt.h>
#include <net/xfrm.h>

#define SXE2VF_IPSEC_KEY_LENGTH	  (32)

#define SXE2VF_IPSEC_AESKEY_LENGTH (32)
#define SXE2VF_IPSEC_AESAUTH_LENGTH (32)
#define SXE2VF_IPSEC_SMKEY_LENGTH (16)
#define SXE2VF_IPSEC_SMAUTH_LENGTH (32)

#define SXE2VF_IPV6_ADDR_LEN (4)

#define SXE2VF_IPSEC_PAYLOAD_LIMIT (2048)

struct sxe2vf_adapter;
union sxe2vf_rx_desc;
struct sxe2vf_tx_offload_info;

enum sxe2vf_ipsec_status {
	SXE2VF_IPSEC_UNINITIALIZED,
	SXE2VF_IPSEC_READY,
	SXE2VF_IPSEC_RESETTING,
	SXE2VF_IPSEC_ERROR,
};

struct sxe2vf_rx_sa {
	struct hlist_node hlist;
	u16 index;
	u16 hw_index;
	bool used;
	struct xfrm_state *xs;
	__be32 spi;
	u32 ipaddr[SXE2VF_IPV6_ADDR_LEN];
	u8 auth_key[SXE2VF_IPSEC_KEY_LENGTH];
	u8 enc_key[SXE2VF_IPSEC_KEY_LENGTH];
	bool ipv6;
	bool is_auth;
	bool engine;
};

struct sxe2vf_tx_sa {
	u16 index;
	u16 hw_index;
	bool used;
	struct xfrm_state *xs;
	u8 auth_key[SXE2VF_IPSEC_KEY_LENGTH];
	u8 enc_key[SXE2VF_IPSEC_KEY_LENGTH];
	bool is_auth;
	bool engine;
	__be32 spi;
};

struct sxe2vf_ipsec_hw_stats {
	u64 rx_decrypt_success;
	u64 over_2k;
	u64 spi_ip_not_matched;
	u64 ip_key_invalid;
	u64 not_aligned;
	u64 icv_fail;
	u64 bypass_disable;
	u64 bypass_macsec;
};

struct sxe2vf_ipsec_sw_stats {
	u64 tx_error_invalid_sp;
	u64 tx_error_invalid_state;
	u64 tx_offload_success;

	u64 rx_error_invalid_sp;
	u64 rx_error_invalid_state;
	u64 rx_error_invalid_ptype;
	u64 rx_error_decrypt_fail;
	u64 rx_offload_success;
};

struct sxe2vf_ipsec_context {
	u32 max_tx_sa_cnt;
	u32 max_rx_sa_cnt;
	struct sxe2vf_tx_sa *tx_sa_table;
	struct sxe2vf_rx_sa *rx_sa_table;
	u32 rx_sa_cnt;
	u32 tx_sa_cnt;
	enum sxe2vf_ipsec_status status;
	struct sxe2vf_ipsec_hw_stats hw_stats;
	DECLARE_HASHTABLE(rx_sa_list, 12);
	/* in order to protect the data */
	struct mutex context_lock;
	/* in order to protect the data */
	spinlock_t rx_hlist_lock;
};

s32 sxe2vf_ipsec_init(struct sxe2vf_adapter *adapter);

void sxe2vf_ipsec_deinit(struct sxe2vf_adapter *adapter);

s32 sxe2vf_ipsec_tx(struct sxe2vf_queue *txq, struct sxe2vf_tx_buf *first,
		    struct sxe2vf_tx_offload_info *offload);
void sxe2vf_ipsec_rx(struct sxe2vf_queue *rxq, union sxe2vf_rx_desc *desc,
		     struct sk_buff *skb, u16 ptype);

s32 sxe2vf_ipsec_stop(struct sxe2vf_adapter *adapter);

s32 sxe2vf_ipsec_rebuild(struct sxe2vf_adapter *adapter);

bool sxe2vf_is_ipsec_can_not_disable(struct sxe2vf_adapter *adapter);

bool sxe2vf_ipsec_conflict_features_check(struct net_device *netdev);

bool sxe2vf_is_ipsec_offload_enable(struct net_device *netdev);

#endif

