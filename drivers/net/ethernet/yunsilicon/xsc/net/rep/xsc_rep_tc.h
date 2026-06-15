/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_REP_TC_H__
#define __XSC_REP_TC_H__

#include <linux/skbuff.h>
#include "../xsc_eth.h"
#include "common/xsc_hsi.h"
#include "../rep/xsc_eth_rep.h"

int xsc_rep_tc_init(struct xsc_rep_priv *rpriv);
void xsc_rep_tc_cleanup(struct xsc_rep_priv *rpriv);

int xsc_rep_tc_netdevice_event_register(struct xsc_rep_priv *rpriv);
void xsc_rep_tc_netdevice_event_unregister(struct xsc_rep_priv *rpriv);

void xsc_rep_tc_enable(struct xsc_adapter *adapter);
void xsc_rep_tc_disable(struct xsc_adapter *adapter);

int xsc_rep_tc_event_port_affinity(struct xsc_adapter *adapter);

void xsc_rep_update_flows(struct xsc_adapter *adapter,
			  struct xsc_encap_entry *e,
			  bool neigh_connected,
			  unsigned char ha[ETH_ALEN]);

int xsc_rep_encap_entry_attach(struct xsc_adapter *adapter,
			       struct xsc_encap_entry *e,
			       struct xsc_neigh *x_neigh,
			       struct net_device *neigh_dev);
void xsc_rep_encap_entry_detach(struct xsc_adapter *adapter,
				struct xsc_encap_entry *e);

int xsc_rep_setup_tc(struct net_device *dev, enum tc_setup_type type,
		     void *type_data);

void xsc_rep_tc_receive(struct xsc_cqe *cqe, struct xsc_rq *rq,
			struct sk_buff *skb);

#endif /* __XSC_REP_TC_H__ */
