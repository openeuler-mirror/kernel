/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_ipsec.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_IPSEC_H__
#define __SXE2_IPSEC_H__

#include <linux/pci.h>
#ifdef NEED_COMPAT_DIM
#include "sxe2_compat_dim.h"
#else
#include <linux/dim.h>
#endif
#include <linux/cpumask.h>
#include <linux/interrupt.h>
#include <net/xfrm.h>
#include "sxe2_cmd.h"

#define SXE2_IPSEC_KEY_LENGTH	(32)

#define SXE2_IPSEC_AESKEY_LENGTH (32)
#define SXE2_IPSEC_AESAUTH_LENGTH (32)
#define SXE2_IPSEC_SMKEY_LENGTH (16)
#define SXE2_IPSEC_SMAUTH_LENGTH (32)

#define SXE2_IPSEC_PAYLOAD_LIMIT (2048)

#define SXE2_IPV6_ADDR_LEN (4)

#define SXE2_IPSEC_HW_INDEX_INVALID (0xFFFFFFFF)

enum sxe2_ptype_outer_protocol;
struct sxe2_vt_ipsec_msg;
struct sxe2_adapter;
union sxe2_rx_desc;
struct sxe2_tx_offload_info;

enum sxe2_ipsec_status {
	SXE2_IPSEC_UNINITIALIZED,
	SXE2_IPSEC_READY,
	SXE2_IPSEC_RESETTING,
	SXE2_IPSEC_ERROR,
};

struct sxe2_rx_sa {
	struct hlist_node hlist;
	struct xfrm_state *xs;
	__be32 spi;
	u16 index;
	u32 ipaddr[SXE2_IPV6_ADDR_LEN];
	u8 auth_key[SXE2_IPSEC_KEY_LENGTH];
	u8 enc_key[SXE2_IPSEC_KEY_LENGTH];
	bool ipv6;
	bool is_auth;
	bool engine;
	bool used;
	u32 hw_index;
	u32 ip_id;
	bool is_vf;
	u32 vf_id;
};

struct sxe2_tx_sa {
	struct xfrm_state *xs;
	u16 index;
	u8 auth_key[SXE2_IPSEC_KEY_LENGTH];
	u8 enc_key[SXE2_IPSEC_KEY_LENGTH];
	bool is_auth;
	bool engine;
	bool used;
	u32 hw_index;
	bool is_vf;
	u32 vf_id;
	__be32 spi;
};

struct sxe2_ipsec_hw_stats {
	u64 rx_decrypt_success;
	u64 over_2k;
	u64 spi_ip_not_matched;
	u64 ip_key_invalid;
	u64 not_aligned;
	u64 icv_fail;
	u64 bypass_disable;
	u64 bypass_macsec;
};

struct sxe2_ipsec_sw_stats {
	u64 tx_error_invalid_sp;
	u64 tx_error_invalid_state;
	u64 tx_offload_success;

	u64 rx_error_invalid_sp;
	u64 rx_error_invalid_state;
	u64 rx_error_invalid_ptype;
	u64 rx_error_decrypt_fail;
	u64 rx_offload_success;
};

struct sxe2_ipsec_context {
	u32 max_tx_sa_cnt;
	u32 max_rx_sa_cnt;
	struct sxe2_tx_sa *tx_sa_table;
	struct sxe2_rx_sa *rx_sa_table;
	u32 rx_sa_cnt;
	u32 tx_sa_cnt;
	enum sxe2_ipsec_status status;
	struct sxe2_ipsec_hw_stats hw_stats;
	DECLARE_HASHTABLE(rx_sa_list, 12);
	/* in order to protect the data */
	struct mutex context_lock;
	/* in order to protect the data */
	spinlock_t rx_hlist_lock;
};

s32 sxe2_fwc_ipsec_init(struct sxe2_adapter *adapter);

s32 sxe2_ipsec_init(struct sxe2_adapter *adapter);

void sxe2_ipsec_deinit(struct sxe2_adapter *adapter);

s32 sxe2_ipsec_tx(struct sxe2_queue *txq, struct sxe2_tx_buf *first,
		  struct sxe2_tx_offload_info *offload);
void sxe2_ipsec_rx(struct sxe2_queue *rxq, union sxe2_rx_desc *desc,
		   struct sk_buff *skb, u16 ptype);

void sxe2_ipsec_stop(struct sxe2_adapter *adapter);

void sxe2_ipsec_sa_clean(struct sxe2_adapter *adapter);

s32 sxe2_ipsec_rebuild(struct sxe2_adapter *adapter);

bool sxe2_is_ipsec_can_not_disable(struct sxe2_adapter *adapter);

bool sxe2_ipsec_conflict_features_check(struct sxe2_adapter *adapter,
					struct net_device *netdev);

bool sxe2_is_ipsec_offload_enable(struct net_device *netdev);

s32 sxe2_ipsec_vf_sa_add(struct sxe2_adapter *adapter, u32 vf_id,
			 struct sxe2_vf_ipsec_sa_add_msg *req, u32 *hw_index,
			 bool is_restore);

s32 sxe2_ipsec_vf_sa_free(struct sxe2_adapter *adapter, u32 vf_id,
			  struct sxe2_vf_ipsec_sa_del_msg *req);

void sxe2_ipsec_vf_sa_clear(struct sxe2_adapter *adapter, u32 vf_id);

void sxe2_ipsec_rx_state_free(struct sxe2_adapter *adapter,
			      struct sxe2_rx_sa *rsa);

void sxe2_ipsec_tx_state_free(struct sxe2_adapter *adapter,
			      struct sxe2_tx_sa *tsa);

s32 sxe2_ipsec_fwc_get_ipsec_capa(struct sxe2_adapter *adapter,
				  struct sxe2_fwc_ipsec_capa_resq *resp);

s32 sxe2_fwc_ipsec_tx_sa_add(struct sxe2_adapter *adapter,
			     struct sxe2_fwc_ipsec_txsa_add_req *req,
			     struct sxe2_fwc_ipsec_txsa_add_resp *resp);

s32 sxe2_fwc_ipsec_tx_sa_del(struct sxe2_adapter *adapter,
			     struct sxe2_fwc_ipsec_txsa_del_req *req);

s32 sxe2_fwc_ipsec_tx_sa_set(struct sxe2_adapter *adapter,
			     struct sxe2_fwc_ipsec_txsa_set_req *req,
			     struct sxe2_fwc_ipsec_txsa_add_resp *resp);

s32 sxe2_fwc_ipsec_rx_sa_add(struct sxe2_adapter *adapter,
			     struct sxe2_fwc_ipsec_rxsa_add_req *req,
			     struct sxe2_fwc_ipsec_rxsa_add_resp *resp);

s32 sxe2_fwc_ipsec_rx_sa_del(struct sxe2_adapter *adapter,
			     struct sxe2_fwc_ipsec_rxsa_del_req *req);

s32 sxe2_fwc_ipsec_rx_sa_set(struct sxe2_adapter *adapter,
			     struct sxe2_fwc_ipsec_rxsa_set_req *req,
			     struct sxe2_fwc_ipsec_rxsa_add_resp *resp);

s32 sxe2_dpdk_ipsec_resource_release(struct sxe2_adapter *adapter,
				     struct sxe2_obj *obj);

#endif
