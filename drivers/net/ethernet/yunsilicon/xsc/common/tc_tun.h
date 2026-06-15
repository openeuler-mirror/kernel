/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_TC_TUNNEL_H__
#define __XSC_TC_TUNNEL_H__

#include <linux/netdevice.h>
#include <net/pkt_cls.h>
#include <linux/netlink.h>
#include "../net/xsc_eth.h"
#include "common/xsc_core.h"

enum xsc_flow_match_level {
	XSC_MATCH_NONE = XSC_INLINE_MODE_NONE,
	XSC_MATCH_L2   = XSC_INLINE_MODE_L2,
	XSC_MATCH_L3   = XSC_INLINE_MODE_IP,
	XSC_MATCH_L4   = XSC_INLINE_MODE_TCP_UDP,
};

enum {
	XSC_TC_TUNNEL_TYPE_UNKNOWN,
	XSC_TC_TUNNEL_TYPE_VXLAN,
	XSC_TC_TUNNEL_TYPE_GENEVE,
	XSC_TC_TUNNEL_TYPE_GRETAP,
};

struct xsc_tc_tunnel;
struct xsc_encap_entry;
struct xsc_flow_spec;

struct xsc_encap_key {
	const struct ip_tunnel_key *ip_tun_key;
	struct xsc_tc_tunnel     *tc_tunnel;
};

struct xsc_tc_tunnel {
	int tunnel_type;
	enum xsc_flow_match_level match_level;

	bool (*can_offload)(struct xsc_adapter *adapter);
	int (*calc_hlen)(struct xsc_encap_entry *e);
	int (*init_encap_attr)(struct net_device *tunnel_dev,
			       struct xsc_adapter *adapter,
			       struct xsc_encap_entry *e
			       , struct netlink_ext_ack *extack
			       );
	int (*generate_ip_tun_hdr)(char buf[],
				   __u8 *ip_proto,
				   struct xsc_encap_entry *e);
	int (*parse_udp_ports)(struct xsc_adapter *adapter,
			       struct xsc_flow_spec *spec,
			       struct flow_cls_offload *f,
			       void *headers_c,
			       void *headers_v);
	int (*parse_tunnel)(struct xsc_adapter *adapter,
			    struct xsc_flow_spec *spec,
			    struct flow_cls_offload *f,
			    void *headers_c,
			    void *headers_v);
	bool (*encap_info_equal)(struct xsc_encap_key *a,
				 struct xsc_encap_key *b);
	int (*get_remote_ifindex)(struct net_device *mirred_dev);
};

extern struct xsc_tc_tunnel vxlan_tunnel;
extern struct xsc_tc_tunnel geneve_tunnel;
extern struct xsc_tc_tunnel gre_tunnel;
extern struct xsc_tc_tunnel mplsoudp_tunnel;

struct xsc_route_key {
	int ip_version;
	union {
		__be32 v4;
		struct in6_addr v6;
	} endpoint_ip;
};

struct xsc_route_entry {
	struct xsc_route_key key;
	struct list_head encap_entries;
	struct list_head decap_flows;
	u32 flags;
	struct hlist_node hlist;
	refcount_t refcnt;
	int tunnel_dev_index;
	struct rcu_head rcu;
};

struct xsc_tc_tun_encap {
	struct xsc_adapter *priv;
	struct notifier_block fib_nb;
	spinlock_t route_lock; /* protects route_tbl */
	unsigned long route_tbl_last_update;
	DECLARE_HASHTABLE(route_tbl, 8);
};

#ifdef CONFIG_XSC_OFFLOAD_TUN
struct xsc_tc_tunnel *xsc_get_tc_tun(struct net_device *tunnel_dev);

int xsc_tc_tun_init_encap_attr(struct net_device *tunnel_dev,
			       struct xsc_adapter *priv,
			       struct xsc_encap_entry *e,
			       struct netlink_ext_ack *extack);

int xsc_tc_tun_create_header_ipv4(struct xsc_adapter *priv,
				  struct net_device *mirred_dev,
				  struct xsc_encap_entry *e);
int xsc_tc_tun_update_header_ipv4(struct xsc_adapter *priv,
				  struct net_device *mirred_dev,
				  struct xsc_encap_entry *e);

int xsc_tc_tun_create_header_ipv6(struct xsc_adapter *priv,
				  struct net_device *mirred_dev,
				  struct xsc_encap_entry *e);
int xsc_tc_tun_update_header_ipv6(struct xsc_adapter *priv,
				  struct net_device *mirred_dev,
				  struct xsc_encap_entry *e);

int xsc_tc_tun_route_lookup(struct xsc_adapter *priv,
			    struct xsc_flow_spec *spec,
			    struct xsc_flow_attr *attr,
			    struct net_device *filter_dev);

bool xsc_tc_tun_device_to_offload(struct xsc_adapter *priv,
				  struct net_device *netdev);

int xsc_tc_tun_parse(struct net_device *filter_dev,
		     struct xsc_adapter *priv,
		     struct xsc_flow_spec *spec,
		     struct flow_cls_offload *f,
		     u8 *match_level);

int xsc_tc_tun_parse_udp_ports(struct xsc_adapter *priv,
			       struct xsc_flow_spec *spec,
			       struct flow_cls_offload *f,
			       void *headers_c, void *headers_v);

bool xsc_tc_tun_encap_info_equal_generic(struct xsc_encap_key *a,
					 struct xsc_encap_key *b);

bool xsc_tc_tun_encap_info_equal_options(struct xsc_encap_key *a,
					 struct xsc_encap_key *b,
					 __be16 tun_flags);
#endif

#endif //__XSC_TC_TUNNEL_H__
