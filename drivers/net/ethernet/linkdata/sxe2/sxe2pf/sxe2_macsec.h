/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_macsec.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_MACSEC_H__
#define __SXE2_MACSEC_H__

#include "sxe2_compat.h"

#ifdef HAVE_MACSEC_SUPPORT
#include <net/macsec.h>

#define SXE2_MACSEC_MAX_DEVICE_NUM 1

#define SXE2_MACSEC_MAX_SA 2

#define SXE2_MACSEC_KEY_LEN 16

enum sxe2_macsec_state {
	SXE2_MACSEC_STATE_UNINIT,
	SXE2_MACSEC_STATE_READY,
	SXE2_MACSEC_STATE_RESET,
};

struct sxe2_macsec_sa {
	bool added;
	bool active;
	u8 an_value;
	u32 key[4];
	u32 pn[2];
	u32 ssci;
	u32 salt[MACSEC_SALT_COUNT];
};

struct sxe2_macsec_txsc {
	bool active;
	bool encrypt;
	bool aisci;
	bool es;
	struct sxe2_macsec_sa sa[SXE2_MACSEC_MAX_SA];
};

struct sxe2_macsec_rxsc {
	struct rcu_head rcu;
	bool active;
	bool protect;
	struct sxe2_macsec_sa sa[SXE2_MACSEC_MAX_SA];
	sci_t sci;
	struct metadata_dst *md_dst;
};

struct sxe2_macsec_context {
	const struct net_device *netdev;
	enum sxe2_macsec_state state;
	/* in order to protect the data */
	struct mutex lock;
	struct sxe2_macsec_rxsc *rx_sc;
	struct sxe2_macsec_txsc tx_sc;
	bool xpn;
	sci_t sci;
	bool protect;
	enum macsec_validation_type validate_frames;
};

s32 sxe2_macsec_init(struct sxe2_adapter *adapter);

void sxe2_macsec_deinit(struct sxe2_adapter *adapter);

s32 sxe2_macsec_rebuild(struct sxe2_adapter *adapter);

bool sxe2_macsec_offload(struct sxe2_adapter *adapter, struct sk_buff *skb);

void sxe2_macsec_rx(struct sxe2_queue *rxq, struct sk_buff *skb);

s32 sxe2_macsec_rxsc_clear_and_del(struct macsec_context *ctx);

s32 sxe2_macsec_rxsa_fill_and_cfg(u8 sa_id, struct macsec_context *ctx);

s32 sxe2_macsec_rxsa_clear_and_del(u8 sa_id, struct macsec_context *ctx);

s32 sxe2_macsec_txsc_fill_and_cfg(struct macsec_context *ctx);

s32 sxe2_macsec_txsa_upd_cfg(struct macsec_context *ctx);

void sxe2_macsec_enter_reset(struct sxe2_adapter *adapter, bool to_reset);

bool sxe2_macsec_conflict_features_check(struct net_device *netdev);

bool sxe2_is_macsec_can_not_disable(struct sxe2_adapter *adapter);

#endif

#endif
