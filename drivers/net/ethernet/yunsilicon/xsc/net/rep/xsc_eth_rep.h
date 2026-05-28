/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_ETH_REP_H__
#define __XSC_ETH_REP_H__

#include "../../common/vport.h"
#include "../../common/xsc_eswitch.h"
#include "../xsc_eth.h"
#include <net/ipv6.h>
#include <net/addrconf.h>

extern const struct xsc_profile xsc_nic_profile;
extern const struct xsc_rx_handlers xsc_rx_handlers_nic;

extern const struct net_device_ops xsc_netdev_ops;
extern const struct net_device_ops xsc_netdev_ops_rep;

struct xsc_encap_entry {
	/* attached neigh hash entry */
	struct xsc_neigh_hash_entry *nhe;
	/* neigh hash entry list of encaps sharing the same neigh */
	struct list_head encap_list;
	/* a node of the eswitch encap hash table which keeping all the encap
	 * entries
	 */
	struct hlist_node encap_hlist;
	struct list_head flows;
	struct list_head route_list;
	struct xsc_pkt_reformat *pkt_reformat;
	const struct ip_tunnel_info *tun_info;
	unsigned char h_dest[ETH_ALEN];	/* destination eth addr	*/

	struct net_device *out_dev;
	int route_dev_ifindex;
	struct xsc_tc_tunnel *tunnel;
	int reformat_type;
	u8 flags;
	char *encap_header;
	int encap_size;
	refcount_t refcnt;
	struct completion res_ready;
	int compl_result;
	struct rcu_head rcu;
};

struct xsc_neigh_update_table {
	struct rhashtable       neigh_ht;
	/* Save the neigh hash entries in a list in addition to the hash table
	 * (neigh_ht). In order to iterate easily over the neigh entries.
	 * Used for stats query.
	 */
	struct list_head	neigh_list;
	/* protect lookup/remove operations */
	struct mutex		encap_lock;
	struct notifier_block   netevent_nb;
	struct delayed_work     neigh_stats_work;
	unsigned long           min_interval; /* jiffies */
};

struct xsc_tc_int_port_priv {
	struct xsc_core_device *dev;
	struct mutex int_ports_lock; /* Protects int ports list */
	struct list_head int_ports; /* Uses int_ports_lock */
	u16 num_ports;
	bool ul_rep_rx_ready; /* Set when uplink is performing teardown */
};

struct xsc_rep_uplink_priv {
	/* indirect block callbacks are invoked on bind/unbind events
	 * on registered higher level devices (e.g. tunnel devices)
	 *
	 * tc_indr_block_cb_priv_list is used to lookup indirect callback
	 * private data
	 *
	 */
	struct list_head	tc_indr_block_priv_list;

#ifdef CONFIG_XSC_OFFLOAD_TUN
	struct xsc_tun_entropy tun_entropy;
	/* maps tun_info to a unique id*/
	struct mapping_ctx *tunnel_mapping;
	/* maps tun_enc_opts to a unique id*/
	struct mapping_ctx *tunnel_enc_opts_mapping;
	/* tc tunneling encapsulation private data */
	struct xsc_tc_tun_encap *encap;
#endif

	/* protects unready_flows */
	struct mutex                unready_flows_lock;
	struct list_head            unready_flows;
	struct work_struct          reoffload_flows_work;

	struct xsc_post_act *post_act;

#ifdef CONFIG_XSC_OFFLOAD_CT
	struct xsc_tc_ct_priv *ct_priv;
#endif

#ifdef CONFIG_XSC_OFFLOAD_SAMPLE
	struct xsc_tc_psample *tc_psample;
#endif

	/* OVS internal port support */
	struct xsc_tc_int_port_priv *int_port_priv;

#ifdef CONFIG_XSC_OFFLOAD_METER
	struct xsc_flow_meters *flow_meters;
#endif
};

struct xsc_rep_priv {
	struct xsc_eswitch_rep *rep;
	struct net_device      *netdev;
	struct xsc_neigh_update_table neigh_update;
	struct xsc_flow_table *root_ft;
	struct xsc_flow_handle *vport_rx_rule;
	struct xsc_rep_uplink_priv uplink_priv; /* valid for uplink rep */
	struct rhashtable tc_ht;
};

static inline
struct xsc_rep_priv *xsc_rep_to_rep_priv(struct xsc_eswitch_rep *rep)
{
	return rep->rep_data[REP_ETH].priv;
}

static inline bool xsc_is_vport_rep(const struct xsc_adapter *adapter)
{
	struct xsc_rep_priv *rpriv;
	struct xsc_eswitch_rep *rep;

	if (adapter->ppriv) {
		rpriv = adapter->ppriv;
		rep = rpriv->rep;

		if (rep->vport != XSC_VPORT_UPLINK)
			return true;
	}

	return false;
}

struct xsc_neigh {
	union {
		__be32	v4;
		struct in6_addr v6;
	} dst_ip;
	int family;
};

struct xsc_neigh_hash_entry {
	struct rhash_head rhash_node;
	struct xsc_neigh x_neigh;
	struct xsc_priv *priv;
	struct net_device *neigh_dev;

	/* Save the neigh hash entry in a list on the representor in
	 * addition to the hash table. In order to iterate easily over the
	 * neighbour entries. Used for stats query.
	 */
	struct list_head neigh_list;

	/* protects encap list */
	spinlock_t encap_list_lock;
	/* encap list sharing the same neigh */
	struct list_head encap_list;

	/* neigh hash entry can be deleted only when the refcount is zero.
	 * refcount is needed to avoid neigh hash entry removal by TC, while
	 * it's used by the neigh notification call.
	 */
	refcount_t refcnt;

	/* Save the last reported time offloaded traffic pass over one of the
	 * neigh hash entry flows. Use it to periodically update the neigh
	 * 'used' value and avoid neigh deleting by the kernel.
	 */
	unsigned long reported_lastuse;

	struct rcu_head rcu;
};

enum {
	/* set when the encap entry is successfully offloaded into HW */
	XSC_ENCAP_ENTRY_VALID     = BIT(0),
	XSC_REFORMAT_DECAP        = BIT(1),
	XSC_ENCAP_ENTRY_NO_ROUTE  = BIT(2),
};

void xsc_rep_register_vport_reps(struct xsc_core_device *xdev);
void xsc_rep_unregister_vport_reps(struct xsc_core_device *xdev);
void xsc_uplink_netdev_set(struct xsc_core_device *xdev, struct net_device *netdev);
bool xsc_is_vf_rep(const struct net_device *netdev);
struct xsc_eswitch_rep *xsc_get_vf_rep(const struct xsc_adapter *adapter);
bool xsc_is_vf_rep_profile(const struct xsc_profile *profile);
bool xsc_eswitch_uplink_rep(const struct net_device *netdev);
bool xsc_is_uplink_rep(const struct xsc_adapter *adapter);
int xsc_eth_rep_enable_nic_hca(struct xsc_adapter *adapter);
int xsc_eth_rep_disable_nic_hca(struct xsc_adapter *adapter);
int xsc_eth_rep_modify_nic_hca(struct xsc_adapter *adapter, u16 flags);

static inline bool is_xsc_eswitch_rep(const struct net_device *netdev)
{
	return xsc_is_vf_rep(netdev) || xsc_eswitch_uplink_rep(netdev);
}

#endif /* __XSC_ETH_REP_H__ */

