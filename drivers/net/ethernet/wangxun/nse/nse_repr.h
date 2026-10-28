/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_REPR_H_
#define _NSE_REPR_H_
#include "nse_repr_sysfs.h"

struct nse_repr {
	struct nse_vsi *src_vsi;
	struct nse_vf *vf;
	struct nse_q_vector *q_vector;			/* fake q_vector of repr */
	/* pointing to real q_vector of pf->switchdev.control_vsi */
	struct nse_q_vector *real_q_vector;
	struct net_device *netdev;
	struct metadata_dst *dst;
	struct nse_rep_sysfs rep_sysfs;
	struct nse_rep_meter rep_meter;

	u64	rx_packets;
	u64	tx_packets;
	u64	rx_bytes;
	u64	tx_bytes;
};

int nse_repr_add_for_all_vfs(struct nse_pf *pf);
void nse_repr_rem_from_all_vfs(struct nse_pf *pf);
void nse_repr_start_tx_queues(struct nse_repr *repr);
void nse_repr_stop_tx_queues(struct nse_repr *repr);
void nse_repr_set_traffic_vsi(struct nse_repr *repr, struct nse_vsi *vsi);
#if IS_ENABLED(CONFIG_NET_DEVLINK)
bool nse_is_port_repr_netdev(struct net_device *netdev);
struct nse_repr *nse_netdev_to_repr(const struct net_device *netdev);
#else
static inline
bool nse_is_port_repr_netdev(struct net_device *netdev) { return false; }
static inline
struct nse_repr *nse_netdev_to_repr(const struct net_device *netdev) { return NULL; }
#endif /* CONFIG_NET_DEVLINK */
#endif
