/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_ESWITCH_H_
#define _NSE_ESWITCH_H_
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#include <net/devlink.h>

#define NSE_ESWITH_SET_MODE

#define NSE_STOLEN 1

void nse_eswitch_release(struct nse_pf *pf);
int nse_eswitch_configure(struct nse_pf *pf);
int nse_eswitch_rebuild(struct nse_pf *pf, enum nse_reset_req reset_type);
int nse_eswitch_mode_get(struct devlink *devlink, u16 *mode);
void nse_eswitch_stop_all_tx_queues(struct nse_pf *pf);

struct net_device *
nse_eswitch_get_target_netdev(struct nse_ring *rx_ring,
			      union nse_32b_rx_desc *rx_desc, struct sk_buff *skb);
int nse_eswitch_restore_skb(struct nse_ring *rx_ring,
			      union nse_32b_rx_desc *rx_desc, struct sk_buff *skb);
void nse_eswitch_set_target_vsi(struct sk_buff *skb,
				struct nse_tx_offload_params *off);
void nse_eswitch_update_repr(struct nse_vsi *vsi);
netdev_tx_t
nse_eswitch_port_start_xmit(struct sk_buff *skb, struct net_device *netdev);

int nse_eswitch_mode_set(struct devlink *devlink, u16 mode,
			 struct netlink_ext_ack *extack);

bool nse_is_eswitch_mode_switchdev(struct nse_pf *pf);
#else /* !CONFIG_NET_DEVLINK */
static inline void nse_eswitch_release(struct nse_pf *pf) { }
static inline
void nse_eswitch_set_target_vsi(struct sk_buff *skb, struct nse_tx_offload_params *off) { }
static inline void nse_eswitch_update_repr(struct nse_vsi *vsi) { }
static inline void nse_eswitch_stop_all_tx_queues(struct nse_pf *pf) { }

static inline int
nse_eswitch_configure(struct nse_pf *pf)
{
	return 0;
}

static inline bool
nse_is_eswitch_mode_switchdev(struct nse_pf __always_unused *pf)
{
	return false;
}

static inline int
nse_eswitch_rebuild(struct nse_pf __always_unused *pf, enum nse_reset_req reset_type)
{
	return 0;
}

static inline netdev_tx_t
nse_eswitch_port_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	return 0;
}

static inline struct net_device *
nse_eswitch_get_target_netdev(struct nse_ring *rx_ring,
			      union nse_32b_rx_desc *rx_desc, struct sk_buff *skb)
{
	return NULL;
}

static inline int
nse_eswitch_restore_skb(struct nse_ring *rx_ring,
			      union nse_32b_rx_desc *rx_desc, struct sk_buff *skb)
{
	return 0;
}
#endif /* CONFIG_NET_DEVLINK */
#endif /* _NSE_ESWITCH_H_ */

