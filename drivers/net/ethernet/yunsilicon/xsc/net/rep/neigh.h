/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __NEIGH__
#define __NEIGH__

#include "xsc_eth_rep.h"

#ifdef CONFIG_XSC_OFFLOAD_TUN
int xsc_rep_neigh_init(struct xsc_rep_priv *rpriv);
void xsc_rep_neigh_cleanup(struct xsc_rep_priv *rpriv);

struct xsc_neigh_hash_entry *
xsc_rep_neigh_entry_lookup(struct xsc_adapter *priv,
			   struct xsc_neigh *x_neigh);
int xsc_rep_neigh_entry_create(struct xsc_adapter *priv, struct xsc_neigh *x_neigh,
			       struct net_device *neigh_dev,
			       struct xsc_neigh_hash_entry **nhe);
void xsc_rep_neigh_entry_release(struct xsc_neigh_hash_entry *nhe);

void xsc_rep_queue_neigh_stats_work(struct xsc_adapter *priv);

#else /* CONFIG_XSC_OFFLOAD_TUN */

static inline int
xsc_rep_neigh_init(struct xsc_rep_priv *rpriv) { return 0; }
static inline void
xsc_rep_neigh_cleanup(struct xsc_rep_priv *rpriv) {}

#endif /* CONFIG_XSC_OFFLOAD_TUN */

#endif /* __NEIGH__ */
