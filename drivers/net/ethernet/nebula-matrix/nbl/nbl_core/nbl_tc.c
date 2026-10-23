// SPDX-License-Identifier: GPL-2.0
#include <net/vxlan.h>
#include <linux/inet.h>
#include "nbl_tc.h"
#include "nbl_tc_tun.h"

static int nbl_tc_pedit_header_offsets[] = {
	[FLOW_ACT_MANGLE_HDR_TYPE_ETH] = offsetof(struct nbl_tc_pedit_headers, eth),
	[FLOW_ACT_MANGLE_HDR_TYPE_IP4] = offsetof(struct nbl_tc_pedit_headers, ip4),
	[FLOW_ACT_MANGLE_HDR_TYPE_IP6] = offsetof(struct nbl_tc_pedit_headers, ip6),
	[FLOW_ACT_MANGLE_HDR_TYPE_TCP] = offsetof(struct nbl_tc_pedit_headers, tcp),
	[FLOW_ACT_MANGLE_HDR_TYPE_UDP] = offsetof(struct nbl_tc_pedit_headers, udp),
};

#define nbl_pedit_header(_ph, _htype) ((void *)(_ph) + nbl_tc_pedit_header_offsets[_htype])

static int nbl_tc_parse_proto(const struct flow_rule *rule,
			      struct nbl_flow_pattern_conf *filter,
			      const struct nbl_common_info *common,
			      u16 flag)
{
	struct flow_match_basic match;
	u16 type = 0;

	flow_rule_match_basic(rule, &match);

	if (match.key->n_proto & match.mask->n_proto) {
		type = ntohs(match.key->n_proto);
		if (type != ETH_P_IP && type != ETH_P_IPV6 &&
		    type != ETH_P_8021Q && type != ETH_P_8021AD) {
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "tc flow with ethtype 0x%04x is not supported\n",
				  type);
			return -EOPNOTSUPP;
		}

		filter->input.l2_data.ether_type = ntohs(match.key->n_proto);
		filter->input.l2_mask.ether_type = ntohs(match.mask->n_proto);
		filter->key_flag |= NBL_FLOW_KEY_ETHERTYPE_FLAG;
	}
	if (match.key->ip_proto & match.mask->ip_proto) {
		filter->key_flag |= NBL_FLOW_KEY_PROTOCOL_FLAG;
		filter->input.ip.proto = match.key->ip_proto;
		filter->input.ip_mask.proto = match.mask->ip_proto;
	}

	nbl_debug(common, NBL_DEBUG_FLOW,
		  "tc flow parse proto l2_data, wildcard_flow:%u, ether_type=0x%04x, l2_mask.ether_type=0x%04x, proto=0x%x, proto_mask=0x%x",
		  filter->wildcard_flow, filter->input.l2_data.ether_type,
		  filter->input.l2_mask.ether_type,
		  filter->input.ip.proto, filter->input.ip_mask.proto);
	return 0;
}

static int nbl_tc_parse_eth(const struct flow_rule *rule,
			    struct nbl_flow_pattern_conf *filter,
			    const struct nbl_common_info *common,
			    u16 flag)
{
	struct flow_match_eth_addrs match;
	int idx = 0;
	u8 mac_f[6];
	u8 mac_z[6];

	memset(mac_f, 0xff, sizeof(mac_f));
	memset(mac_z, 0, sizeof(mac_z));

	flow_rule_match_eth_addrs(rule, &match);

	if (match.key && match.mask) {
		if (is_broadcast_ether_addr(match.key->dst) ||
		    is_multicast_ether_addr(match.key->dst) ||
		    is_zero_ether_addr(match.key->dst)) {
			/* ignore src mac check for normal flow offload */
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "tc flow dmac broadcast, multicast and zero is not supported\n");
			return -EOPNOTSUPP;
		}

		if (flag & BIT(NBL_FLOW_ITEM_DKEY_MASK) || flag & BIT(NBL_FLOW_ITEM_SKEY_MASK)) {
			if (flag & BIT(NBL_FLOW_ITEM_DKEY_MASK) &&
			    memcmp(&match.mask->dst, mac_f, ETH_ALEN) &&
			    memcmp(&match.mask->dst, mac_z, ETH_ALEN))
				filter->wildcard_flow = true;
		} else {
			if (!is_broadcast_ether_addr(match.mask->dst)) {
				nbl_debug(common, NBL_DEBUG_FLOW, "tc flow dmac need exact\n");
				return -EOPNOTSUPP;
			}
		}

		/* ether_addr_copy(filter->input.l2_mask.dst_mac, match.mask->dst); */
		for (idx = 0; idx < ETH_ALEN; idx++) {
			filter->input.l2_data.dst_mac[idx] = match.key->dst[ETH_ALEN - 1 - idx];
			filter->input.l2_mask.dst_mac[idx] = match.mask->dst[ETH_ALEN - 1 - idx];
		}

		filter->key_flag |= NBL_FLOW_KEY_DSTMAC_FLAG;
		/* set vlan flag to match table profile graph even there is no vlan match */
		filter->key_flag |= NBL_FLOW_KEY_SVLAN_FLAG;
		filter->key_flag |= NBL_FLOW_KEY_CVLAN_FLAG;
	}

	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow l2_data, wildcard_flow:%u, dst_mac=0x%02x:%02x:%02x:%02x:%02x:%02x/0x%02x:%02x:%02x:%02x:%02x:%02x",
		  filter->wildcard_flow,
		  filter->input.l2_data.dst_mac[5], filter->input.l2_data.dst_mac[4],
		  filter->input.l2_data.dst_mac[3], filter->input.l2_data.dst_mac[2],
		  filter->input.l2_data.dst_mac[1], filter->input.l2_data.dst_mac[0],
		  filter->input.l2_mask.dst_mac[5], filter->input.l2_mask.dst_mac[4],
		  filter->input.l2_mask.dst_mac[3], filter->input.l2_mask.dst_mac[2],
		  filter->input.l2_mask.dst_mac[1], filter->input.l2_mask.dst_mac[0]);

	return 0;
}

static int nbl_tc_parse_control(const struct flow_rule *rule,
				struct nbl_flow_pattern_conf *filter,
				const struct nbl_common_info *common,
				u16 flag)
{
	struct flow_match_control match;

	flow_rule_match_control(rule, &match);

	if (match.key->addr_type & match.mask->addr_type) {
		if (!filter->input.l2_data.ether_type) {
			filter->input.l2_data.ether_type = ntohs(match.key->addr_type);
			filter->input.l2_mask.ether_type = ntohs(match.mask->addr_type);
		}
	}

	nbl_debug(common, NBL_DEBUG_FLOW,
		  "tc flow parse control, wildcard_flow:%u, ether_type=0x%04x, flag:%x",
		  filter->wildcard_flow, filter->input.l2_data.ether_type, match.key->flags);
	return 0;
}

static int nbl_tc_parse_vlan(const struct flow_rule *rule,
			     struct nbl_flow_pattern_conf *filter,
			     const struct nbl_common_info *common,
			     u16 flag)
{
	struct flow_match_vlan match;

	flow_rule_match_vlan(rule, &match);
	if (match.key && match.mask) {
		if (flag & BIT(NBL_FLOW_ITEM_KEY_MASK)) {
			if (match.mask->vlan_id != NBL_FLOW_TABLE_VLAN_MASK_AS_U12 &&
			    match.mask->vlan_id != 0)
				filter->wildcard_flow = 1;
		} else {
			if (match.mask->vlan_id != VLAN_VID_MASK) {
				nbl_info(common, NBL_DEBUG_FLOW, "tc flow fuzzy vlan mask 0x%04x is not supported\n",
					 match.mask->vlan_id);
				return -EOPNOTSUPP;
			}
		}

		filter->input.svlan_tag = match.key->vlan_id & 0xFFF;
		filter->input.svlan_mask = match.mask->vlan_id;
		filter->input.svlan_type = filter->input.l2_data.ether_type;
		filter->input.vlan_cnt++;
		nbl_debug(common, NBL_DEBUG_FLOW, "parse vlan, wildcard_flow:%u, svlan_id=%d/0x%x, vlan_type=0x%04x",
			  filter->wildcard_flow, filter->input.svlan_tag, filter->input.svlan_mask,
			  filter->input.svlan_type);
	}

	return 0;
}

static int nbl_tc_parse_cvlan(const struct flow_rule *rule,
			      struct nbl_flow_pattern_conf *filter,
			      const struct nbl_common_info *common,
			      u16 flag)
{
	filter->input.is_cvlan = true;

	return 0;
}

static int nbl_tc_parse_tunnel_ip(const struct flow_rule *rule,
				  struct nbl_flow_pattern_conf *filter,
				  const struct nbl_common_info *common,
				  u16 flag)
{
	return 0;
}

static int nbl_tc_parse_tunnel_ports(const struct flow_rule *rule,
				     struct nbl_flow_pattern_conf *filter,
				     const struct nbl_common_info *common,
				     u16 flag)
{
	struct flow_match_ports enc_ports;

	flow_rule_match_enc_ports(rule, &enc_ports);

	if (memchr_inv(&enc_ports.mask->dst, 0xff, sizeof(enc_ports.mask->dst))) {
		nbl_err(common, NBL_DEBUG_FLOW, "nbl tc parse tunnel err: udp tunnel decap filter must match dst_port fully.\n");
		return -EOPNOTSUPP;
	}

	filter->input.l4_outer.dst_port = be16_to_cpu(enc_ports.key->dst);
	filter->input.l4_mask_outer.dst_port = enc_ports.mask->dst;

	filter->key_flag |= NBL_FLOW_KEY_T_DSTPORT_FLAG;

	nbl_debug(common, NBL_DEBUG_FLOW, "parse outer tnl udp:dport:0x%x.\n",
		  filter->input.l4_outer.dst_port);

	return 0;
}

static int nbl_tc_parse_tunnel_keyid(const struct flow_rule *rule,
				     struct nbl_flow_pattern_conf *filter,
				     const struct nbl_common_info *common,
				     u16 flag)
{
	struct flow_match_enc_keyid enc_keyid;
#define NBL_TC_VNI_FLAG_BIT 8

	flow_rule_match_enc_keyid(rule, &enc_keyid);

	if (flag & BIT(NBL_FLOW_ITEM_KEY_MASK)) {
		if (enc_keyid.mask->keyid != 0xffffffff &&
		    enc_keyid.mask->keyid != 0)
			filter->wildcard_flow = 1;
	} else if (!enc_keyid.mask->keyid) {
		return 0;
	}

	filter->input.tnl.vni = be32_to_cpu(enc_keyid.key->keyid) << NBL_TC_VNI_FLAG_BIT;
	filter->input.tnl_mask.vni = enc_keyid.mask->keyid;

	filter->key_flag |= NBL_FLOW_KEY_T_VNI_FLAG;
	nbl_debug(common, NBL_DEBUG_FLOW, "parse outer tnl keyid:0x%x/0x%x, wildcard_flow:%u.\n",
		  filter->input.tnl.vni, filter->input.tnl_mask.vni, filter->wildcard_flow);

	return 0;
}

static bool
nbl_tc_find_ipv4_address(const struct net_device *dev, __be32 ipv4_addr)
{
	bool ip_find = false;
	struct in_ifaddr *ifa;
	struct in_device *in_dev = in_dev_get(dev);

	/* check whether the dev has the ip addr */
	if (!in_dev)
		goto end;

	for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_address == ipv4_addr) {
			ip_find = true;
			break;
		}
	}

	in_dev_put(in_dev);

end:
	return ip_find;
}

static bool
nbl_tc_find_vlan_v4_address(const struct net_device *dev, __be32 ipv4_addr)
{
	struct net_device *child;
	const struct net_device *real_dev;
	bool ip_find = false;

	for_each_netdev(dev_net(dev), child) {
		if (is_vlan_dev(child)) {
			real_dev = vlan_dev_real_dev(child);
			if (real_dev != dev)
				continue;
			ip_find = nbl_tc_find_ipv4_address(child, ipv4_addr);
			if (ip_find)
				break;
		}
	}

	return ip_find;
}

static bool
nbl_tc_find_ipv6_address(const struct net_device *dev, struct in6_addr ipv6_addr)
{
	bool ip_find = false;
	struct inet6_ifaddr *ifa6;
	struct inet6_dev *in6_dev = in6_dev_get(dev);

	/* check whether the dev has the ip addr */
	if (!in6_dev)
		goto end;

	read_lock_bh(&in6_dev->lock);
	list_for_each_entry(ifa6, &in6_dev->addr_list, if_list) {
		char addr[INET6_ADDRSTRLEN];

		snprintf(addr, sizeof(addr), "%pI6", &ifa6->addr);
		if (!memcmp(&ifa6->addr, &ipv6_addr, sizeof(ifa6->addr))) {
			ip_find = true;
			break;
		}
	}
	read_unlock_bh(&in6_dev->lock);

	in6_dev_put(in6_dev);

end:
	return ip_find;
}

static bool
nbl_tc_find_vlan_v6_address(const struct net_device *dev, struct in6_addr ipv6_addr)
{
	struct net_device *child;
	const struct net_device *real_dev;
	bool ip_find = false;

	for_each_netdev(dev_net(dev), child) {
		if (is_vlan_dev(child)) {
			real_dev = vlan_dev_real_dev(child);
			if (real_dev != dev)
				continue;
			ip_find = nbl_tc_find_ipv6_address(child, ipv6_addr);
			if (ip_find)
				break;
		}
	}

	return ip_find;
}

static int nbl_tc_parse_tunnel_control(const struct flow_rule *rule,
				       struct nbl_flow_pattern_conf *filter,
				       const struct nbl_common_info *common,
				       u16 flag)
{
	struct flow_match_control match;
	u16 addr_type;
	int max_idx = NBL_IPV6_ADDR_LEN_AS_U8 - 1;
	int idx = 0;
	bool dev_ok = false;
	struct net_device *upper_dev = NULL;
	bool is_lag_port;

	flow_rule_match_enc_control(rule, &match);
	addr_type = match.key->addr_type;

	is_lag_port = !!(filter->input.port & NBL_FLOW_IN_PORT_TYPE_LAG);

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs ip4;

		flow_rule_match_enc_ipv4_addrs(rule, &ip4);

		if (flag & BIT(NBL_FLOW_ITEM_DKEY_MASK) || flag & BIT(NBL_FLOW_ITEM_SKEY_MASK)) {
			if (flag & BIT(NBL_FLOW_ITEM_SKEY_MASK) &&
			    ip4.mask->src != NBL_FLOW_TABLE_IPV4_DEFAULT_MASK && ip4.mask->src != 0)
				filter->wildcard_flow = 1;

			if (flag & BIT(NBL_FLOW_ITEM_DKEY_MASK) &&
			    ip4.mask->dst != NBL_FLOW_TABLE_IPV4_DEFAULT_MASK && ip4.mask->dst != 0)
				filter->wildcard_flow = 1;
		} else {
			if (ip4.mask->src != NBL_FLOW_TABLE_IPV4_DEFAULT_MASK ||
			    ip4.mask->dst != NBL_FLOW_TABLE_IPV4_DEFAULT_MASK) {
				nbl_info(common, NBL_DEBUG_FLOW, "sip/dip must exact, sip:0x%x/0x%x, dip:0x%x/0x%x",
					 ip4.key->src, ip4.mask->src, ip4.key->dst, ip4.mask->dst);
				return -EOPNOTSUPP;
			}
		}
		filter->input.ip_outer.src_ip.addr = be32_to_cpu(ip4.key->src);
		filter->input.ip_mask_outer.src_ip.addr = ip4.mask->src;
		filter->input.ip_outer.dst_ip.addr = be32_to_cpu(ip4.key->dst);
		filter->input.ip_mask_outer.dst_ip.addr = ip4.mask->dst;

		filter->input.ip_outer.ip_ver = NBL_IP_VERSION_V4;
		filter->key_flag |= NBL_FLOW_KEY_T_DIPV4_FLAG;
		filter->key_flag |= NBL_FLOW_KEY_T_OPT_DATA_FLAG;
		filter->key_flag |= NBL_FLOW_KEY_T_OPT_CLASS_FLAG;

		nbl_debug(common, NBL_DEBUG_FLOW, "parse outer tnl ctl ip: sip:0x%x/0x%x, dip:0x%x/0x%x, wildcard_flow:%u.\n",
			  filter->input.ip_outer.src_ip.addr,
			filter->input.ip_mask_outer.src_ip.addr,
			filter->input.ip_outer.dst_ip.addr,
			filter->input.ip_mask_outer.dst_ip.addr,
			filter->wildcard_flow);
		if (is_lag_port || filter->in_same_bond) {
			dev_ok = true;
		} else {
			dev_ok = nbl_tc_find_ipv4_address(filter->input_dev, ip4.key->dst);
			if (!dev_ok)
				dev_ok = nbl_tc_find_vlan_v4_address(filter->input_dev,
								     ip4.key->dst);
			if (!dev_ok) {
				rcu_read_lock();
				upper_dev = netdev_master_upper_dev_get_rcu(filter->input_dev);
				if (upper_dev && netif_is_lag_master(upper_dev)) {
					dev_ok = nbl_tc_find_ipv4_address(upper_dev, ip4.key->dst);
					if (!dev_ok)
						dev_ok = nbl_tc_find_vlan_v4_address(upper_dev,
										     ip4.key->dst);
				}
				rcu_read_unlock();
			}
		}

		nbl_debug(common, NBL_DEBUG_FLOW, "parse outer tnl ctl ip: is lag:%u, in and out in same bond:%u, dev_ok:%u",
			  is_lag_port, filter->in_same_bond, dev_ok);
	} else if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs ip6;
		char sipv6[INET6_ADDRSTRLEN];
		char dipv6[INET6_ADDRSTRLEN];
		char sipv6_msk[INET6_ADDRSTRLEN];
		char dipv6_msk[INET6_ADDRSTRLEN];

		flow_rule_match_enc_ipv6_addrs(rule, &ip6);

		for (idx = 0; idx < NBL_IPV6_ADDR_LEN_AS_U8; idx++) {
			filter->input.ip_outer.src_ip.v6_addr[idx] =
				ip6.key->src.in6_u.u6_addr8[max_idx - idx];
			filter->input.ip_mask_outer.src_ip.v6_addr[idx] =
				ip6.mask->src.in6_u.u6_addr8[max_idx - idx];
			filter->input.ip_outer.dst_ip.v6_addr[idx] =
				ip6.key->dst.in6_u.u6_addr8[max_idx - idx];
			filter->input.ip_mask_outer.dst_ip.v6_addr[idx] =
				ip6.mask->dst.in6_u.u6_addr8[max_idx - idx];
		}
		filter->input.ip_outer.ip_ver = NBL_IP_VERSION_V6;
		filter->key_flag |= NBL_FLOW_KEY_T_DIPV6_FLAG;
		filter->key_flag |= NBL_FLOW_KEY_T_OPT_DATA_FLAG;
		filter->key_flag |= NBL_FLOW_KEY_T_OPT_CLASS_FLAG;

		snprintf(sipv6, sizeof(sipv6), "%pI6", &ip6.key->src);
		snprintf(dipv6, sizeof(dipv6), "%pI6", &ip6.key->dst);
		snprintf(sipv6_msk, sizeof(sipv6_msk), "%pI6", &ip6.mask->src);
		snprintf(dipv6_msk, sizeof(dipv6_msk), "%pI6", &ip6.mask->src);

		if (is_lag_port || filter->in_same_bond) {
			dev_ok = true;
		} else {
			dev_ok = nbl_tc_find_ipv6_address(filter->input_dev, ip6.key->dst);
			if (!dev_ok)
				dev_ok = nbl_tc_find_vlan_v6_address(filter->input_dev,
								     ip6.key->dst);
			if (!dev_ok) {
				rcu_read_lock();
				upper_dev = netdev_master_upper_dev_get_rcu(filter->input_dev);
				if (upper_dev && netif_is_lag_master(upper_dev)) {
					dev_ok = nbl_tc_find_ipv6_address(upper_dev, ip6.key->dst);
					if (!dev_ok)
						dev_ok = nbl_tc_find_vlan_v6_address(upper_dev,
										     ip6.key->dst);
				}
				rcu_read_unlock();
			}
		}

		nbl_debug(common, NBL_DEBUG_FLOW, "parse outer tnl ipv6, sip:%s/%s, dip:%s/%s,\nis lag:%u, in and out in same bond:%u, dev_ok:%u",
			  sipv6, sipv6_msk, dipv6, dipv6_msk,
			  is_lag_port, filter->in_same_bond, dev_ok);
	}

	if (dev_ok)
		return 0;
	else
		return -EOPNOTSUPP;
}

static int nbl_tc_parse_ip(const struct flow_rule *rule,
			   struct nbl_flow_pattern_conf *filter,
			   const struct nbl_common_info *common,
			   u16 flag)
{
	struct flow_match_ip ip;

	flow_rule_match_ip(rule, &ip);
	filter->input.ip.tos = ip.key->tos;
	filter->input.ip.ttl = ip.key->ttl;
	filter->input.ip_mask.tos = ip.mask->tos;
	filter->input.ip_mask.ttl = ip.mask->ttl;
	filter->key_flag |= NBL_FLOW_KEY_TTL_FLAG;
	filter->key_flag |= NBL_FLOW_KEY_TOS_FLAG;
	filter->key_flag |= NBL_FLOW_KEY_DSCP_FLAG;

	nbl_debug(common, NBL_DEBUG_FLOW, "tos is %u, ttl is %u", ip.key->tos, ip.key->ttl);
	return 0;
}

static int nbl_tc_parse_ip4(const struct flow_rule *rule,
			    struct nbl_flow_pattern_conf *filter,
			    const struct nbl_common_info *common,
			    u16 flag)
{
	struct flow_match_ipv4_addrs ip_addrs;

	flow_rule_match_ipv4_addrs(rule, &ip_addrs);

	if (flag & BIT(NBL_FLOW_ITEM_DKEY_MASK) || flag & BIT(NBL_FLOW_ITEM_SKEY_MASK)) {
		if (flag & BIT(NBL_FLOW_ITEM_DKEY_MASK) &&
		    ip_addrs.mask->dst != NBL_FLOW_TABLE_IPV4_DEFAULT_MASK &&
		    ip_addrs.mask->dst != 0)
			filter->wildcard_flow = 1;

		if (flag & BIT(NBL_FLOW_ITEM_SKEY_MASK) &&
		    ip_addrs.mask->src != NBL_FLOW_TABLE_IPV4_DEFAULT_MASK &&
		    ip_addrs.mask->src != 0)
			filter->wildcard_flow = 1;
	} else {
		if (ip_addrs.mask->dst != NBL_FLOW_TABLE_IPV4_DEFAULT_MASK) {
			nbl_info(common, NBL_DEBUG_FLOW, "dip must exact, dip:0x%x-0x%x",
				 ip_addrs.key->dst, ip_addrs.mask->dst);
			return -EOPNOTSUPP;
		}
	}

	if (ip_addrs.mask->dst == 0 || ip_addrs.key->dst == 0) {
		nbl_debug(common, NBL_DEBUG_FLOW, "dst ipv4:key 0x%x masked 0x%x",
			  ip_addrs.key->dst, ip_addrs.mask->dst);
		return 0;
	}

	filter->input.ip.ip_ver = NBL_IP_VERSION_V4;
	filter->key_flag |= NBL_FLOW_KEY_DIPV4_FLAG;
	filter->key_flag |= NBL_FLOW_KEY_SIPV4_FLAG;
	filter->input.ip.src_ip.addr = be32_to_cpu(ip_addrs.key->src);
	filter->input.ip_mask.src_ip.addr = ip_addrs.mask->src;
	filter->input.ip.dst_ip.addr = be32_to_cpu(ip_addrs.key->dst);
	filter->input.ip_mask.dst_ip.addr = ip_addrs.mask->dst;

	nbl_debug(common, NBL_DEBUG_FLOW, "nbl parse ipv4, sip:0x%x mask:0x%x, dip:0x%x mask:0x%x wildcard_flow:%u",
		  filter->input.ip.src_ip.addr, filter->input.ip_mask.src_ip.addr,
		  filter->input.ip.dst_ip.addr, filter->input.ip_mask.dst_ip.addr,
		  filter->wildcard_flow);

	return 0;
}

static int nbl_tc_parse_ip6(const struct flow_rule *rule,
			    struct nbl_flow_pattern_conf *filter,
			    const struct nbl_common_info *common,
			    u16 flag)
{
	struct flow_match_ipv6_addrs ip6_addrs;
	int idx = 0;
	int max_idx = NBL_IPV6_ADDR_LEN_AS_U8 - 1;
	u8 ipv6_z[NBL_IPV6_ADDR_LEN_AS_U8];
	u8 ipv6_f[NBL_IPV6_ADDR_LEN_AS_U8];

	memset(ipv6_f, 0xff, sizeof(ipv6_f));
	memset(ipv6_z, 0, sizeof(ipv6_z));

	flow_rule_match_ipv6_addrs(rule, &ip6_addrs);

	if (!memcmp(ipv6_z, ip6_addrs.mask->dst.in6_u.u6_addr8, NBL_IPV6_ADDR_LEN_AS_U8) ||
	    !memcmp(ipv6_z, ip6_addrs.key->dst.in6_u.u6_addr8, NBL_IPV6_ADDR_LEN_AS_U8)) {
		nbl_debug(common, NBL_DEBUG_FLOW, "dst ipv6:0x%x-0x%x-0x%x-0x%x masked",
			  ip6_addrs.key->dst.in6_u.u6_addr32[0],
			  ip6_addrs.key->dst.in6_u.u6_addr32[1],
			  ip6_addrs.key->dst.in6_u.u6_addr32[2],
			  ip6_addrs.key->dst.in6_u.u6_addr32[3]);
		return 0;
	}

	if (flag & BIT(NBL_FLOW_ITEM_DKEY_MASK) || flag & BIT(NBL_FLOW_ITEM_SKEY_MASK)) {
		if (flag & BIT(NBL_FLOW_ITEM_DKEY_MASK) &&
		    memcmp(ipv6_z, ip6_addrs.mask->dst.in6_u.u6_addr8, NBL_IPV6_ADDR_LEN_AS_U8) &&
		    memcmp(ipv6_f, ip6_addrs.mask->dst.in6_u.u6_addr8, sizeof(ipv6_f)))
			filter->wildcard_flow = 1;

		if (flag & BIT(NBL_FLOW_ITEM_SKEY_MASK) &&
		    memcmp(ipv6_z, ip6_addrs.mask->src.in6_u.u6_addr8, NBL_IPV6_ADDR_LEN_AS_U8) &&
		    memcmp(ipv6_f, ip6_addrs.mask->src.in6_u.u6_addr8, sizeof(ipv6_f)))
			filter->wildcard_flow = 1;
	} else {
		if (memcmp(ipv6_f, ip6_addrs.mask->dst.in6_u.u6_addr8, sizeof(ipv6_f))) {
			nbl_info(common, NBL_DEBUG_FLOW, "dst ipv6:0x%x-0x%x-0x%x-0x%x mask:0x%x-0x%x-0x%x-0x%x not support",
				 ip6_addrs.key->dst.in6_u.u6_addr32[0],
				 ip6_addrs.key->dst.in6_u.u6_addr32[1],
				 ip6_addrs.key->dst.in6_u.u6_addr32[2],
				 ip6_addrs.key->dst.in6_u.u6_addr32[3],
				 ip6_addrs.mask->dst.in6_u.u6_addr32[1],
				 ip6_addrs.mask->dst.in6_u.u6_addr32[1],
				 ip6_addrs.mask->dst.in6_u.u6_addr32[2],
				 ip6_addrs.mask->dst.in6_u.u6_addr32[3]);
			return -EOPNOTSUPP;
		}
	}

	filter->input.ip.ip_ver = NBL_IP_VERSION_V6;
	filter->key_flag |= NBL_FLOW_KEY_DIPV6_FLAG;
	filter->key_flag |= NBL_FLOW_KEY_SIPV6_FLAG;
	filter->key_flag |= NBL_FLOW_KEY_HOPLIMIT_FLAG;
	nbl_debug(common, NBL_DEBUG_FLOW, "nbl pasre dst ipv6:0x%x-0x%x-0x%x-0x%x mask:0x%x-0x%x-0x%x-0x%x, wildcard_flow:%u",
		  ip6_addrs.key->dst.in6_u.u6_addr32[0], ip6_addrs.key->dst.in6_u.u6_addr32[1],
		  ip6_addrs.key->dst.in6_u.u6_addr32[2], ip6_addrs.key->dst.in6_u.u6_addr32[3],
		  ip6_addrs.mask->dst.in6_u.u6_addr32[1], ip6_addrs.mask->dst.in6_u.u6_addr32[1],
		  ip6_addrs.mask->dst.in6_u.u6_addr32[2], ip6_addrs.mask->dst.in6_u.u6_addr32[3],
		  filter->wildcard_flow);
	for (idx = 0; idx < NBL_IPV6_ADDR_LEN_AS_U8; idx++) {
		filter->input.ip.src_ip.v6_addr[idx] =
			ip6_addrs.key->src.in6_u.u6_addr8[max_idx - idx];
		filter->input.ip_mask.src_ip.v6_addr[idx] =
			ip6_addrs.mask->src.in6_u.u6_addr8[max_idx - idx];
		filter->input.ip.dst_ip.v6_addr[idx] =
			ip6_addrs.key->dst.in6_u.u6_addr8[max_idx - idx];
		filter->input.ip_mask.dst_ip.v6_addr[idx] =
			ip6_addrs.mask->dst.in6_u.u6_addr8[max_idx - idx];
	}

	return 0;
}

static int nbl_tc_parse_ports(const struct flow_rule *rule,
			      struct nbl_flow_pattern_conf *filter,
			      const struct nbl_common_info *common,
			      u16 flag)
{
	struct flow_match_ports port;

	flow_rule_match_ports(rule, &port);

	if (flag & BIT(NBL_FLOW_ITEM_DKEY_MASK) || flag & BIT(NBL_FLOW_ITEM_SKEY_MASK)) {
		if (flag & BIT(NBL_FLOW_ITEM_DKEY_MASK) &&
		    port.mask->dst != NBL_FLOW_TABLE_L4_PORT_DEFAULT_MASK && port.mask->dst != 0)
			filter->wildcard_flow = true;

		if (flag & BIT(NBL_FLOW_ITEM_SKEY_MASK) &&
		    port.mask->src != NBL_FLOW_TABLE_L4_PORT_DEFAULT_MASK && port.mask->src != 0)
			filter->wildcard_flow = true;
	} else if (!port.mask->dst && !port.mask->src) {
		nbl_debug(common, NBL_DEBUG_FLOW, "src and dst port:%d-%d masked",
			  port.key->src, port.key->dst);
		return 0;
	} else if (port.mask->dst != NBL_FLOW_TABLE_L4_PORT_DEFAULT_MASK ||
		   port.mask->src != NBL_FLOW_TABLE_L4_PORT_DEFAULT_MASK) {
		nbl_info(common, NBL_DEBUG_FLOW, "src and dst port mask:%d-%d not support",
			 port.mask->src, port.mask->dst);
		return -EOPNOTSUPP;
	}

	filter->key_flag |= NBL_FLOW_KEY_DSTPORT_FLAG;
	filter->key_flag |= NBL_FLOW_KEY_SRCPORT_FLAG;
	nbl_debug(common, NBL_DEBUG_FLOW, "nbl parse src and dst port key:%d-%d, mask:%d-%d, wildcard_flow:%u",
		  port.key->src, port.key->dst, port.mask->src, port.mask->dst,
		  filter->wildcard_flow);
	filter->input.l4.dst_port = be16_to_cpu(port.key->dst);
	filter->input.l4_mask.dst_port = be16_to_cpu(port.mask->dst);
	filter->input.l4.src_port = be16_to_cpu(port.key->src);
	filter->input.l4_mask.src_port = be16_to_cpu(port.mask->src);
	return 0;
}

static int nbl_tc_parse_icmp(const struct flow_rule *rule,
			     struct nbl_flow_pattern_conf *filter,
			     const struct nbl_common_info *common,
			     u16 flag)
{
	return 0;
}

static struct nbl_tc_flow_parse_pattern parse_pattern_list[] = {
	{ FLOW_DISSECTOR_KEY_BASIC, nbl_tc_parse_proto },
	{ FLOW_DISSECTOR_KEY_ETH_ADDRS, nbl_tc_parse_eth },
	{ FLOW_DISSECTOR_KEY_CONTROL, nbl_tc_parse_control },
	{ FLOW_DISSECTOR_KEY_VLAN, nbl_tc_parse_vlan },
	{ FLOW_DISSECTOR_KEY_CVLAN, nbl_tc_parse_cvlan },
	{ FLOW_DISSECTOR_KEY_ENC_IP, nbl_tc_parse_tunnel_ip},
	{ FLOW_DISSECTOR_KEY_ENC_PORTS, nbl_tc_parse_tunnel_ports },
	{ FLOW_DISSECTOR_KEY_ENC_KEYID, nbl_tc_parse_tunnel_keyid },
	{ FLOW_DISSECTOR_KEY_ENC_CONTROL, nbl_tc_parse_tunnel_control },
	{ FLOW_DISSECTOR_KEY_IPV4_ADDRS, nbl_tc_parse_ip4 },
	{ FLOW_DISSECTOR_KEY_IPV6_ADDRS, nbl_tc_parse_ip6 },
	{ FLOW_DISSECTOR_KEY_IP, nbl_tc_parse_ip },
	{ FLOW_DISSECTOR_KEY_PORTS, nbl_tc_parse_ports },
	{ FLOW_DISSECTOR_KEY_ICMP, nbl_tc_parse_icmp },
};

static int nbl_tc_outdev_and_indev_in_same_sw_id(struct nbl_netdev_priv *out_priv,
						 struct nbl_netdev_priv *in_priv,
						 struct nbl_tc_flow_param *param)
{
	struct net_device *out_upper_dev = NULL;
	struct net_device *in_upper_dev = NULL;
	u32 in_board_key, out_board_key;
	struct nbl_common_info *common = param->common;
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(out_priv->adapter);
	int ret = -EOPNOTSUPP;
	char out_name[IFNAMSIZ];
	char in_name[IFNAMSIZ];

	if (!serv_mgt || !serv_mgt->net_resource_mgt || !serv_mgt->net_resource_mgt->netdev)
		return -EOPNOTSUPP;

	rcu_read_lock();

	if (in_priv && in_priv->adapter) {
		struct nbl_service_mgt *in_serv_mgt = NBL_ADAPTER_TO_SERV_MGT(in_priv->adapter);
		struct net_device *in_netdev = NULL;

		if (in_serv_mgt && in_serv_mgt->net_resource_mgt &&
		    in_serv_mgt->net_resource_mgt->netdev)
			in_netdev = in_serv_mgt->net_resource_mgt->netdev;

		if (in_netdev)
			in_upper_dev = netdev_master_upper_dev_get_rcu(in_netdev);
	}

	out_upper_dev = netdev_master_upper_dev_get_rcu(serv_mgt->net_resource_mgt->netdev);

	if (out_upper_dev && in_upper_dev && netif_is_lag_master(out_upper_dev) &&
	    out_upper_dev == in_upper_dev) {
		in_board_key = pci_domain_nr(common->pdev->bus) << 16 | common->pdev->bus->number;
		out_board_key = pci_domain_nr(out_priv->adapter->common.pdev->bus) << 16 |
						out_priv->adapter->common.pdev->bus->number;
		strscpy(out_name, out_upper_dev->name, IFNAMSIZ);
		if (in_board_key != out_board_key) {
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow in and out pf are in same bond %s but on different cards, not supported\n",
				  out_name);
			goto out;
		}
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow in and out pf are in same bond %s, skip tc_inst_id check\n",
			  out_name);
		param->filter.in_same_bond = true;
		ret = 0;
	} else {
		strscpy(in_name, in_upper_dev ? in_upper_dev->name : "null", IFNAMSIZ);
		strscpy(out_name, out_upper_dev ? out_upper_dev->name : "null", IFNAMSIZ);
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow rule in different nic is not supported, in:%s out:%s\n",
			  in_name, out_name);
	}

out:
	rcu_read_unlock();
	return ret;
}

static bool nbl_tc_check_is_my_bond(struct nbl_serv_net_resource_mgt *net_resource_mgt,
				    struct net_device *out_dev)
{
	if (net_resource_mgt->lag_info &&
	    netdev_master_upper_dev_get_rcu(net_resource_mgt->netdev) == out_dev)
		return true;

	return false;
}

static int nbl_tc_flow_set_out_param(struct net_device *out_dev,
				     struct nbl_netdev_priv *in_priv,
				     struct nbl_serv_net_resource_mgt *net_resource_mgt,
				     struct nbl_tc_port *out,
				     struct nbl_tc_flow_param *param)
{
	int ret = 0;
	struct nbl_netdev_priv *out_priv = NULL;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	u16 eswitch_mode = NBL_ESWITCH_NONE;
	struct nbl_common_info *common = param->common;

	if (!out_dev)
		return -EINVAL;

	if (netif_is_lag_master(out_dev)) {
		if (nbl_tc_check_is_my_bond(net_resource_mgt, out_dev)) {
			out->type = NBL_TC_PORT_TYPE_BOND;
			out->id = net_resource_mgt->lag_info->lag_id;
			goto set_param_end;
		} else {
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow rule not support other nic bond out_dev:%s\n",
				  out_dev->name);
			return -EINVAL;
		}
	}

	out_priv = netdev_priv(out_dev);
	if (!out_priv->adapter) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow rule out_dev is not self nic, adapter is null, out_dev:%s\n",
			  out_dev->name);
		return -EINVAL;
	}

	if (common->tc_inst_id != out_priv->adapter->common.tc_inst_id) {
		if (common->product_type == NBL_LEONIS_TYPE) {
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow rule in different nic is not supported, out_dev:%s\n",
				  out_dev->name);
			ret = -EOPNOTSUPP;
			goto end;
		} else {
			ret = nbl_tc_outdev_and_indev_in_same_sw_id(out_priv, in_priv, param);
			if (ret)
				return ret;
		}
	}

	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(out_priv->adapter);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	eswitch_mode = disp_ops->get_eswitch_mode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (eswitch_mode != NBL_ESWITCH_OFFLOADS) {
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow is not in offload mode, out_dev:%s\n",
			  out_dev->name);
		return -EINVAL;
	}

	if (out_priv->rep) {
		out->type = NBL_TC_PORT_TYPE_VSI;
		out->id = out_priv->rep->rep_vsi_id;
	} else {
		out->type = NBL_TC_PORT_TYPE_ETH;
		out->id = out_priv->adapter->common.eth_id;
	}

set_param_end:
	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow set out.type=%s, out.id=%d, out_dev:%s\n",
		  out->type == NBL_TC_PORT_TYPE_VSI ? "vsi" : "uplink", out->id, out_dev->name);

end:
	return ret;
}

static bool nbl_tc_is_valid_netdev(struct net_device *netdev,
				   struct nbl_serv_netdev_ops *netdev_ops)
{
	if (!netdev || !netdev_ops)
		return false;

	if (netif_is_lag_master(netdev))
		return true;

	if (netdev->netdev_ops == netdev_ops->pf_netdev_ops ||
	    netdev->netdev_ops == netdev_ops->rep_netdev_ops)
		return true;

	return false;
}

static int nbl_tc_flow_init_param(struct nbl_netdev_priv *priv, struct flow_cls_offload *f,
				  struct nbl_common_info *common, struct nbl_tc_flow_param *param)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	const struct flow_action_entry *act_entry;
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(priv->adapter);
	struct nbl_serv_netdev_ops *netdev_ops = &serv_mgt->net_resource_mgt->netdev_ops;
	int i = 0;
	int ret = 0;
	int redirect_cnt = 0;
	int mirred_cnt = 0;
	const struct rtnl_link_ops *tnl_ops = NULL;

	if (priv->rep) {
		param->in.type = NBL_TC_PORT_TYPE_VSI;
		param->in.id = priv->rep->rep_vsi_id;
	} else if (serv_mgt->net_resource_mgt->lag_info) {
		if (serv_mgt->net_resource_mgt->lag_info->lag_id >= NBL_LAG_MAX_NUM)
			return  -EINVAL;
		param->in.type = NBL_TC_PORT_TYPE_BOND;
		param->in.id = serv_mgt->net_resource_mgt->lag_info->lag_id;
	} else {
		param->in.type = NBL_TC_PORT_TYPE_ETH;
		param->in.id = common->eth_id;
	}

	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow init param in.type=%s, type=%d, in.id=%d, dev:%s",
		  param->in.type == NBL_TC_PORT_TYPE_VSI ? "vsi" : "uplink",
		  param->in.type, param->in.id, priv->netdev ? priv->netdev->name : "NULL");

	flow_action_for_each(i, act_entry, &rule->action) {
		if (act_entry->id == FLOW_ACTION_REDIRECT) {
			if (!act_entry->dev)
				return -EINVAL;
			if (redirect_cnt) {
				nbl_debug(common, NBL_DEBUG_FLOW,
					  "tc flow with more than one redirect outport is not supported");
				return -EINVAL;
			}
			tnl_ops = act_entry->dev->rtnl_link_ops;

			if (!tnl_ops ||
			    (tnl_ops && memcmp(tnl_ops->kind, "vxlan", sizeof("vxlan")))) {
				if (!nbl_tc_is_valid_netdev(act_entry->dev,
							    netdev_ops))
					return -ENODEV;

				ret = nbl_tc_flow_set_out_param(act_entry->dev, priv,
								serv_mgt->net_resource_mgt,
								&param->out, param);
				if (ret)
					return ret;
			}
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow init redirect act, tnl_ops:%p, tnl_ops->kind:%s, out.type=%d, out.id=%d, out_dev:%s",
				  tnl_ops, tnl_ops ? tnl_ops->kind : "NULL", param->out.type,
				  param->out.id, act_entry->dev->name);

			redirect_cnt++;
		} else if (act_entry->id == FLOW_ACTION_MIRRED) {
			if (!act_entry->dev)
				return -EINVAL;
			if (mirred_cnt) {
				nbl_debug(common, NBL_DEBUG_FLOW,
					  "tc flow with more than one mirror outport is not supported");
				return -EINVAL;
			}
			if (!nbl_tc_is_valid_netdev(act_entry->dev,
						    &serv_mgt->net_resource_mgt->netdev_ops))
				return -ENODEV;
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow init mirror outport");

			ret = nbl_tc_flow_set_out_param(act_entry->dev, priv,
							serv_mgt->net_resource_mgt,
							&param->mirror_out, param);
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow init mirror outport, tnl_ops:%p, mirror_out.type=%d, mirror_out.id=%d, ret:%d",
				  tnl_ops, param->mirror_out.type, param->mirror_out.id, ret);
			if (ret)
				return ret;
			mirred_cnt++;
		} else if (redirect_cnt > 0 || mirred_cnt > 0) {
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "tc flow different edit action with multiple outport is not supported");
			return -EOPNOTSUPP;
		}
	}

	return ret;
}

static int nbl_tc_parse_pattern(struct nbl_service_mgt *serv_mgt,
				struct flow_cls_offload *f,
				struct nbl_flow_pattern_conf *filter,
				struct nbl_tc_flow_param *param)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_dissector *dissector = rule->match.dissector;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_tc_parse_key_info *parse_info = NULL;
	u32 pattern_type;
	u16 flag = 0;
	u32 i = 0;
	int ret = 0;

	if (param->parse_info)
		parse_info = param->parse_info->key_parse_info;

	if (param->parse_info && param->parse_info->set_in_port_info) {
		ret = param->parse_info->set_in_port_info(param, filter);
		if (ret)
			return ret;
	}
	filter->key_flag |= NBL_FLOW_KEY_INPORT8_FLAG;
	filter->key_flag |= NBL_FLOW_KEY_INPORT4_FLAG;
	filter->in_same_bond = param->filter.in_same_bond;

	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow dissector->used_keys=%llx\n",
		  dissector->used_keys);
	if (dissector->used_keys &
	    ~(BIT_ULL(FLOW_DISSECTOR_KEY_META) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_VLAN) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_CVLAN) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_IP) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ENC_IP) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ICMP) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ENC_PORTS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_PORTS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ENC_CONTROL) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ENC_KEYID))) {
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow key used: 0x%llx is not supported\n",
			  dissector->used_keys);
		return -EOPNOTSUPP;
	}

	for (i = 0; i < ARRAY_SIZE(parse_pattern_list); i++) {
		pattern_type = parse_pattern_list[i].pattern_type;
		if (parse_info)
			flag = parse_info[pattern_type].mask_type;

		if (flow_rule_match_key(rule, pattern_type)) {
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow key %d\n", pattern_type);
			ret = parse_pattern_list[i].parse_func(rule, filter, common, flag);
			if (ret != 0)
				return ret;

			if (parse_info && parse_info[pattern_type].parse_func_after) {
				ret = parse_info[pattern_type].parse_func_after(rule, filter, flag);
				if (ret)
					return ret;
			}
		}
	}

	return 0;
}

static int nbl_tc_fill_encap_out_info_draco(struct nbl_tc_flow_param *param,
					    struct nbl_rule_action *rule_act)
{
	int ret = 0;
	const struct nbl_serv_lag_info *lag_info =
			param->serv_mgt->net_resource_mgt->lag_info;
	struct nbl_netdev_priv *out_priv = NULL;
	struct nbl_netdev_priv *in_priv = NULL;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	u16 eswitch_mode = NBL_ESWITCH_NONE;

	if (netif_is_lag_master(rule_act->tc_tun_encap_out_dev)) {
		if (nbl_tc_check_is_my_bond(param->serv_mgt->net_resource_mgt,
					    rule_act->tc_tun_encap_out_dev)) {
			rule_act->port_type = NBL_TC_PORT_TYPE_BOND;
			rule_act->port_id = lag_info->lag_id;
			rule_act->vlan.port_id = lag_info->lag_id;
			rule_act->vlan.port_type = NBL_TC_PORT_TYPE_BOND;
			param->out.type = NBL_TC_PORT_TYPE_BOND;
			param->out.id = lag_info->lag_id;
			goto end;
		} else {
			nbl_err(param->common, NBL_DEBUG_FLOW, "fill encap out info err.\n");
			return -EINVAL;
		}
	}

	in_priv = netdev_priv(rule_act->in_port);
	if (!in_priv || !in_priv->adapter) {
		nbl_err(param->common, NBL_DEBUG_FLOW, "encap in dev priv or adapter is NULL, out_dev:%s.\n",
			rule_act->tc_tun_encap_out_dev->name);
		return -EINVAL;
	}

	out_priv = netdev_priv(rule_act->tc_tun_encap_out_dev);
	if (!out_priv || !out_priv->adapter) {
		nbl_err(param->common, NBL_DEBUG_FLOW, "encap out dev priv adapter is NULL, out_dev:%s.\n",
			rule_act->tc_tun_encap_out_dev->name);
		return -EINVAL;
	}

	if (param->common->tc_inst_id != out_priv->adapter->common.tc_inst_id) {
		ret = nbl_tc_outdev_and_indev_in_same_sw_id(out_priv, in_priv, param);
		if (ret)
			return ret;
	}

	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(out_priv->adapter);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	eswitch_mode = disp_ops->get_eswitch_mode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (eswitch_mode != NBL_ESWITCH_OFFLOADS) {
		nbl_err(param->common, NBL_DEBUG_FLOW, "eswitch mode is not in offload.\n");
		return -EINVAL;
	}

	if (out_priv->rep) {
		rule_act->port_type = NBL_TC_PORT_TYPE_VSI;
		rule_act->port_id = out_priv->rep->rep_vsi_id;
		rule_act->vlan.port_id = out_priv->rep->rep_vsi_id;
		rule_act->vlan.port_type = NBL_TC_PORT_TYPE_VSI;
		param->out.type = NBL_TC_PORT_TYPE_VSI;
		param->out.id = out_priv->rep->rep_vsi_id;
	} else {
		rule_act->port_type = NBL_TC_PORT_TYPE_ETH;
		rule_act->port_id = out_priv->adapter->common.eth_id;
		rule_act->vlan.port_id = out_priv->adapter->common.eth_id;
		rule_act->vlan.port_type = NBL_TC_PORT_TYPE_ETH;
		param->out.type = NBL_TC_PORT_TYPE_ETH;
		param->out.id = out_priv->adapter->common.eth_id;
	}

	nbl_debug(param->common, NBL_DEBUG_FLOW, "draco tun encap out dev:%s, out_priv->rep:%p, rule_act->port_type:%u, rule_act->port_id:%u, rule_act->vlan.port_id:%u, rule_act->vlan.port_type:%u, param->out.id:%u, param->out.type:%u",
		  rule_act->tc_tun_encap_out_dev->name, out_priv->rep, rule_act->port_type,
		  rule_act->port_id, rule_act->vlan.port_id, rule_act->vlan.port_type,
		  param->out.id, param->out.type);
end:
	return 0;
}

static int nbl_tc_fill_encap_out_info(struct nbl_tc_flow_param *param,
				      struct nbl_rule_action *rule_act)
{
	const struct nbl_serv_lag_info *lag_info =
			param->serv_mgt->net_resource_mgt->lag_info;
	struct nbl_netdev_priv *dev_priv = NULL;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	u16 eswitch_mode = NBL_ESWITCH_NONE;

	if (netif_is_lag_master(rule_act->tc_tun_encap_out_dev)) {
		if (nbl_tc_check_is_my_bond(param->serv_mgt->net_resource_mgt,
					    rule_act->tc_tun_encap_out_dev)) {
			rule_act->port_type = SET_DPORT_TYPE_ETH_LAG;
			rule_act->port_id = (lag_info->lag_id << 2) | NBL_FLOW_OUT_PORT_TYPE_LAG;
			rule_act->vlan.port_id = lag_info->lag_id;
			rule_act->vlan.port_type = NBL_TC_PORT_TYPE_BOND;
			goto end;
		} else {
			nbl_err(param->common, NBL_DEBUG_FLOW, "fill encap out info err.\n");
			return -EINVAL;
		}
	}

	dev_priv = netdev_priv(rule_act->tc_tun_encap_out_dev);
	if (!dev_priv->adapter) {
		nbl_err(param->common, NBL_DEBUG_FLOW, "encap out dev priv adapter is NULL, out_dev:%s.\n",
			rule_act->tc_tun_encap_out_dev->name);
		return -EINVAL;
	}

	if (param->common->tc_inst_id != dev_priv->adapter->common.tc_inst_id) {
		nbl_err(param->common, NBL_DEBUG_FLOW, "tc flow rule in different nic is not supported\n");
		return -EINVAL;
	}

	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(dev_priv->adapter);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	eswitch_mode = disp_ops->get_eswitch_mode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (eswitch_mode != NBL_ESWITCH_OFFLOADS) {
		nbl_err(param->common, NBL_DEBUG_FLOW, "eswitch mode is not in offload.\n");
		return -EINVAL;
	}

	if (dev_priv->rep) {
		rule_act->port_type = SET_DPORT_TYPE_VSI_HOST;
		rule_act->port_id = dev_priv->rep->rep_vsi_id;
		rule_act->vlan.port_id = dev_priv->rep->rep_vsi_id;
		rule_act->vlan.port_type = NBL_TC_PORT_TYPE_VSI;
	} else {
		rule_act->port_type = SET_DPORT_TYPE_ETH_LAG;
		rule_act->port_id = dev_priv->adapter->common.eth_id | NBL_FLOW_OUT_PORT_TYPE_ETH;
		rule_act->vlan.port_id = dev_priv->adapter->common.eth_id + NBL_VLAN_TYPE_ETH_BASE;
		rule_act->vlan.port_type = NBL_TC_PORT_TYPE_ETH;
	}

	nbl_debug(param->common, NBL_DEBUG_FLOW, "tc tun encap out_dev:%s, dev_priv->rep:%p, rule_act->port_type:%u, rule_act->port_id:%u, rule_act->vlan.port_id:%u, rule_act->vlan.port_type:%u",
		  rule_act->tc_tun_encap_out_dev->name, dev_priv->rep, rule_act->port_type,
		  rule_act->port_id, rule_act->vlan.port_id, rule_act->vlan.port_type);
end:
	return 0;
}

static inline bool nbl_tc_is_dmac_offset(u32 oft)
{
	return (oft < 6);
}

static inline bool nbl_tc_is_smac_offset(u32 oft)
{
	return (oft >= 6 && oft < 12);
}

static inline bool nbl_tc_is_sip_offset(u32 oft)
{
	return (oft >= 12 && oft < 16);
}

static inline bool nbl_tc_is_dip_offset(u32 oft)
{
	return (oft >= 16 && oft < 20);
}

static inline bool nbl_tc_is_sip6_offset(u32 oft)
{
	return (oft >= 8 && oft < 24);
}

static inline bool nbl_tc_is_dip6_offset(u32 oft)
{
	return (oft >= 24 && oft < 40);
}

static inline bool nbl_tc_is_sp_offset(u32 oft)
{
	return (oft >= 0 && oft < 2);
}

static inline bool nbl_tc_is_dp_offset(u32 oft)
{
	return (oft >= 2 && oft < 4);
}

static int nbl_tc_pedit_parse_eth(u32 offset, u64 *act_flag)
{
	int ret = 0;

	if (nbl_tc_is_dmac_offset(offset))
		*act_flag |= NBL_FLOW_ACTION_SET_DST_MAC;
	else if (nbl_tc_is_smac_offset(offset))
		*act_flag |= NBL_FLOW_ACTION_SET_SRC_MAC;
	else
		ret = -EOPNOTSUPP;

	return ret;
}

static int nbl_tc_pedit_parse_ip(u32 offset, u64 *act_flag)
{
	int ret = 0;

	if (nbl_tc_is_dip_offset(offset))
		*act_flag |= NBL_FLOW_ACTION_SET_IPV4_DST_IP;
	else if (nbl_tc_is_sip_offset(offset))
		*act_flag |= NBL_FLOW_ACTION_SET_IPV4_SRC_IP;
	else
		/* we only support sip & dip field now */
		ret = -EOPNOTSUPP;

	return ret;
}

static int nbl_tc_pedit_parse_ip6(u32 offset, u64 *act_flag)
{
	int ret = 0;

	if (nbl_tc_is_dip6_offset(offset))
		*act_flag |= NBL_FLOW_ACTION_SET_IPV6_DST_IP;
	else if (nbl_tc_is_sip6_offset(offset))
		*act_flag |= NBL_FLOW_ACTION_SET_IPV6_SRC_IP;
	else
		/* we only support sip6 & dip6 field now */
		ret = -EOPNOTSUPP;

	return ret;
}

static int nbl_tc_pedit_parse_port(u32 offset, u64 *act_flag)
{
	int ret = 0;

	if (nbl_tc_is_dp_offset(offset))
		*act_flag |= NBL_FLOW_ACTION_SET_DST_PORT;
	else if (nbl_tc_is_sp_offset(offset))
		*act_flag |= NBL_FLOW_ACTION_SET_SRC_PORT;
	else
		/* we only support src & dst port field now */
		ret = -EOPNOTSUPP;

	return ret;
}

static int nbl_tc_pedit_check_field(const struct nbl_common_info *common, u32 offset,
				    u8 pedit_type, u64 *pedit_flag)
{
	int ret  = 0;

	switch (pedit_type) {
	case FLOW_ACT_MANGLE_HDR_TYPE_ETH:
		ret = nbl_tc_pedit_parse_eth(offset,  pedit_flag);
		break;
	case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
		ret = nbl_tc_pedit_parse_ip(offset, pedit_flag);
		break;
	case FLOW_ACT_MANGLE_HDR_TYPE_IP6:
		ret = nbl_tc_pedit_parse_ip6(offset, pedit_flag);
		break;
	case FLOW_ACT_MANGLE_HDR_TYPE_TCP:
	case FLOW_ACT_MANGLE_HDR_TYPE_UDP:
		ret = nbl_tc_pedit_parse_port(offset, pedit_flag);
		break;
	default:
		nbl_info(common, NBL_DEBUG_FLOW, "nbl_tc_pedit not support %d\n", pedit_type);
		ret = -EOPNOTSUPP;
	}

	if (ret)
		nbl_info(common, NBL_DEBUG_FLOW, "nbl_tc_pedit:type(%d)-oft(%u) err\n",
			 pedit_type, offset);
	return ret;
}

static int nbl_tc_pedit_set_val(u8 htype, u32 mask, u32 val, u32 offset,
				struct nbl_tc_pedit_info *pedit_info)
{
	u32 *cur_pmask = (u32 *)(nbl_pedit_header(&pedit_info->mask, htype) + offset);
	u32 *cur_pval = (u32 *)(nbl_pedit_header(&pedit_info->val, htype) + offset);

	if (*cur_pmask & mask)
		return -EINVAL;

	*cur_pmask |= mask;
	*cur_pval |= (val & mask);

	return 0;
}

static u32 nbl_tc_pedit_update_oft(u32 *oft, u32 mask)
{
	int ret = 0;

	if (NBL_TC_MASK_FORWARD_OFT0(mask))
		*oft += 0;
	else if (NBL_TC_MASK_FORWARD_OFT1(mask))
		*oft += 1;
	else if (NBL_TC_MASK_FORWARD_OFT2(mask))
		*oft += 2;
	else if (NBL_TC_MASK_FORWARD_OFT3(mask))
		*oft += 3;
	else if (NBL_TC_MASK_BACKWARD_OFT3(mask))
		*oft = *oft > 3 ? (*oft - 3) : *oft;
	else if (NBL_TC_MASK_BACKWARD_OFT2(mask))
		*oft = *oft > 2 ? (*oft - 2) : *oft;
	else if (NBL_TC_MASK_BACKWARD_OFT1(mask))
		*oft = *oft > 1 ? (*oft - 1) : *oft;
	else
		ret = -EINVAL;
	return ret;
}

static int nbl_tc_pedit_parse_edit_info(struct nbl_rule_action *rule_act,
					const struct flow_action_entry *act_entry,
					struct nbl_tc_flow_param *param)
{
	int ret = 0;
	u8 htype = (u8)act_entry->mangle.htype;
	u32 mask = act_entry->mangle.mask;
	u32 val = act_entry->mangle.val;
	u32 offset = act_entry->mangle.offset;
	const struct nbl_common_info *common = param->common;

	if (htype == FLOW_ACT_MANGLE_UNSPEC) {
		nbl_info(common, NBL_DEBUG_FLOW, "legacy pedit isn't offloaded");
		ret = -EOPNOTSUPP;
		goto pedit_err;
	}

	if (htype > FLOW_ACT_MANGLE_HDR_TYPE_UDP) {
		nbl_info(common, NBL_DEBUG_FLOW, "pedit:%d isn't offloaded", htype);
		ret = -EOPNOTSUPP;
		goto pedit_err;
	}

	/* try get located pedit val, drop it if we got a bad location*/
	ret = nbl_tc_pedit_set_val(htype, ~mask, val, offset, &rule_act->tc_pedit_info);
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW, "nbl_tc_pedit err: disallow edit on same location");
		goto pedit_err;
	}

	ret = nbl_tc_pedit_update_oft(&offset, mask);
	nbl_debug(common, NBL_DEBUG_FLOW, "nbl_tc_pedit:type-val-mask-oft->%d-%u-%x-%u %s",
		  htype, val, mask, offset, ret ? "failed" : "success");
	if (ret)
		goto pedit_err;
	if (htype == FLOW_ACT_MANGLE_HDR_TYPE_UDP)
		NBL_TC_PEDIT_SET_NODE_RES_PRO(rule_act->tc_pedit_info.pedit_node);

	/* now set action flag if we supported it */
	ret = nbl_tc_pedit_check_field(common, offset, htype, &rule_act->flag);
	if (ret)
		goto pedit_err;

	NBL_TC_PEDIT_INC_NODE_RES_EDITS(rule_act->tc_pedit_info.pedit_node);
pedit_err:
	return ret;
}

static int nbl_tc_handle_action_pedit(struct nbl_rule_action *rule_act,
				      const struct flow_action_entry *act_entry,
				      enum flow_action_id type,
				      struct nbl_flow_pattern_conf *filter,
				      struct nbl_tc_flow_param *param)
{
	return nbl_tc_pedit_parse_edit_info(rule_act, act_entry, param);
}

static int nbl_tc_handle_action_csum(struct nbl_rule_action *rule_act,
				     const struct flow_action_entry *act_entry,
				     enum flow_action_id type,
				     struct nbl_flow_pattern_conf *filter,
				     struct nbl_tc_flow_param *param)
{
	return 0;
}

static int
nbl_tc_handle_action_port_id(struct nbl_rule_action *rule_act,
			     const struct flow_action_entry *act_entry,
			     enum flow_action_id type,
			     struct nbl_flow_pattern_conf *filter,
			     struct nbl_tc_flow_param *param)
{
	int ret = 0;
	struct net_device *encap_dev = act_entry->dev;

	if (param->mirror_out.type)
		return 0;

	if (param->encap) {
		param->encap = false;
		/* encap info */
		ret = nbl_tc_tun_parse_encap_info(rule_act, param, encap_dev);

		if (ret) {
			nbl_info(param->common, NBL_DEBUG_FLOW, "parse tc encap info failed.\n");
			return ret;
		}

		/* fill encap out port info */
		if (param->common->product_type == NBL_LEONIS_TYPE)
			ret = nbl_tc_fill_encap_out_info(param, rule_act);
		else
			ret = nbl_tc_fill_encap_out_info_draco(param, rule_act);
		if (ret)
			return ret;
	} else {
		switch (param->out.type) {
		case NBL_TC_PORT_TYPE_VSI:
			rule_act->port_type = SET_DPORT_TYPE_VSI_HOST;
			rule_act->port_id = param->out.id;
			rule_act->vlan.port_id = param->out.id;
			rule_act->vlan.port_type = NBL_TC_PORT_TYPE_VSI;
			break;
		case NBL_TC_PORT_TYPE_ETH:
			rule_act->port_type = SET_DPORT_TYPE_ETH_LAG;
			//rule_act->port_id = param->out.id | NBL_FLOW_OUT_PORT_TYPE_ETH;
			//rule_act->vlan.port_id = param->out.id + NBL_VLAN_TYPE_ETH_BASE;
			rule_act->vlan.port_type = NBL_TC_PORT_TYPE_ETH;
			break;
		case NBL_TC_PORT_TYPE_BOND:
			rule_act->port_type = SET_DPORT_TYPE_ETH_LAG;
			//rule_act->port_id = (param->out.id << 2) | NBL_FLOW_OUT_PORT_TYPE_LAG;
			//rule_act->vlan.port_id = param->out.id;
			rule_act->vlan.port_type = NBL_TC_PORT_TYPE_BOND;
			break;
		default:
			nbl_info(param->common, NBL_DEBUG_FLOW, "out type invalid, out type:%d.\n",
				 param->out.type);
			return -EINVAL;
		}

		if (param->parse_info && param->parse_info->set_out_port_info) {
			ret = param->parse_info->set_out_port_info(param, rule_act);
			if (ret)
				return ret;
		}
	}
	rule_act->flag |= NBL_FLOW_ACTION_PORT_ID;

	return 0;
}

static int
nbl_tc_handle_action_drop(struct nbl_rule_action *rule_act,
			  const struct flow_action_entry *act_entry,
			  enum flow_action_id type,
			  struct nbl_flow_pattern_conf *filter,
			  struct nbl_tc_flow_param *param)
{
	rule_act->flag |= NBL_FLOW_ACTION_DROP;
	rule_act->drop_flag = 1;
	return 0;
}

static int
nbl_tc_handle_action_mirror(struct nbl_rule_action *rule_act,
			    const struct flow_action_entry *act_entry,
			    enum flow_action_id type,
			    struct nbl_flow_pattern_conf *filter,
			    struct nbl_tc_flow_param *param)
{
	if (!(param->out.type && param->mirror_out.type))
		return -EINVAL;

	if (rule_act->mcc_cnt >= NBL_TC_MCC_MEMBER_MAX)
		return -EINVAL;
	rule_act->port_mcc[rule_act->mcc_cnt].dport_id = param->out.id;
	rule_act->port_mcc[rule_act->mcc_cnt].port_type = param->out.type;
	rule_act->mcc_cnt++;

	if (rule_act->mcc_cnt >= NBL_TC_MCC_MEMBER_MAX)
		return -EINVAL;
	rule_act->port_mcc[rule_act->mcc_cnt].dport_id = param->mirror_out.id;
	rule_act->port_mcc[rule_act->mcc_cnt].port_type = param->mirror_out.type;
	rule_act->mcc_cnt++;

	rule_act->flag |= NBL_FLOW_ACTION_MCC;

	return 0;
}

static int
nbl_tc_handle_action_push_vlan(struct nbl_rule_action *rule_act,
			       const struct flow_action_entry *act_entry,
			       enum flow_action_id type,
			       struct nbl_flow_pattern_conf *filter,
			       struct nbl_tc_flow_param *param)
{
	rule_act->vlan.eth_proto = htons(act_entry->vlan.proto);
	if (rule_act->vlan.eth_proto != NBL_VLAN_TPID_VALUE &&
	    rule_act->vlan.eth_proto != NBL_QINQ_TPID_VALUE)
		return -EINVAL;

	if (filter->input.svlan_tag)
		rule_act->flag |= NBL_FLOW_ACTION_PUSH_OUTER_VLAN;
	else
		rule_act->flag |= NBL_FLOW_ACTION_PUSH_INNER_VLAN;
	rule_act->vlan.vlan_tag = act_entry->vlan.vid;
	rule_act->vlan.vlan_tag |= act_entry->vlan.prio << NBL_VLAN_PCP_SHIFT;

	return 0;
}

static int
nbl_tc_handle_action_pop_vlan(struct nbl_rule_action *rule_act,
			      const struct flow_action_entry *act_entry,
			      enum flow_action_id type,
			      struct nbl_flow_pattern_conf *filter,
			      struct nbl_tc_flow_param *param)
{
	if (filter->input.is_cvlan)
		rule_act->flag |= NBL_FLOW_ACTION_POP_OUTER_VLAN;
	else
		rule_act->flag |= NBL_FLOW_ACTION_POP_INNER_VLAN;

	return 0;
}

static int
nbl_tc_handle_action_tun_encap(struct nbl_rule_action *rule_act,
			       const struct flow_action_entry *act_entry,
			       enum flow_action_id type,
			       struct nbl_flow_pattern_conf *filter,
			       struct nbl_tc_flow_param *param)
{
	param->tunnel = (struct ip_tunnel_info *)act_entry->tunnel;
	if (param->tunnel) {
		rule_act->flag |= NBL_FLOW_ACTION_TUNNEL_ENCAP;
		param->encap = true;
		return 0;
	} else {
		return -EOPNOTSUPP;
	}
}

static int
nbl_tc_handle_action_tun_decap(struct nbl_rule_action *rule_act,
			       const struct flow_action_entry *act_entry,
			       enum flow_action_id type,
			       struct nbl_flow_pattern_conf *filter,
			       struct nbl_tc_flow_param *param)
{
	rule_act->flag |= NBL_FLOW_ACTION_TUNNEL_DECAP;

	return 0;
}

const struct nbl_tc_flow_action_driver_ops nbl_port_id_act = {
	.act_update = nbl_tc_handle_action_port_id,
};

const struct nbl_tc_flow_action_driver_ops nbl_drop = {
	.act_update = nbl_tc_handle_action_drop,
};

const struct nbl_tc_flow_action_driver_ops nbl_mirror_act = {
	.act_update = nbl_tc_handle_action_mirror,
};

const struct nbl_tc_flow_action_driver_ops nbl_push_vlan = {
	.act_update = nbl_tc_handle_action_push_vlan,
};

const struct nbl_tc_flow_action_driver_ops nbl_pop_vlan = {
	.act_update = nbl_tc_handle_action_pop_vlan,
};

const struct nbl_tc_flow_action_driver_ops nbl_tunnel_encap_act = {
	.act_update = nbl_tc_handle_action_tun_encap,
};

const struct nbl_tc_flow_action_driver_ops nbl_tunnel_decap_act = {
	.act_update = nbl_tc_handle_action_tun_decap,
};

const struct nbl_tc_flow_action_driver_ops nbl_pedit_act = {
	.act_update = nbl_tc_handle_action_pedit,
};

const struct nbl_tc_flow_action_driver_ops nbl_csum_act = {
	.act_update = nbl_tc_handle_action_csum,
};

const struct nbl_tc_flow_action_driver_ops *nbl_act_ops[] = {
	[FLOW_ACTION_REDIRECT] = &nbl_port_id_act,
	[FLOW_ACTION_DROP] = &nbl_drop,
	[FLOW_ACTION_MIRRED] = &nbl_mirror_act,
	[FLOW_ACTION_VLAN_PUSH] = &nbl_push_vlan,
	[FLOW_ACTION_VLAN_POP] = &nbl_pop_vlan,
	[FLOW_ACTION_TUNNEL_ENCAP] = &nbl_tunnel_encap_act,
	[FLOW_ACTION_TUNNEL_DECAP] = &nbl_tunnel_decap_act,
	[FLOW_ACTION_MANGLE] = &nbl_pedit_act,
	[FLOW_ACTION_CSUM] = &nbl_csum_act,
};

/**
 * @brief: handle action parse by type
 *
 * @param[in] type: action type
 * @param[in] actions: nbl_flow_pattern_conf info
 * @param[in] act: nbl_rule_action info storage
 * @param[out] error: error info
 * @return int: 0-success, other-failed
 */
static int nbl_tc_parse_action_by_type(struct nbl_rule_action *rule_act,
				       const struct flow_action_entry *act_entry,
				       enum flow_action_id type,
				       struct nbl_flow_pattern_conf *filter,
				       struct nbl_tc_flow_param *param)
{
	int ret = 0;
	const struct nbl_tc_flow_action_driver_ops *fops;
	struct nbl_tc_parse_act_info *parse_info = NULL;

	if (param->parse_info)
		parse_info = param->parse_info->act_parse_info;

	fops = nbl_act_ops[type];

	if (!fops)
		return 0;

	if (!parse_info || !parse_info[type].ignore_parse_action) {
		ret = fops->act_update(rule_act, act_entry, type, filter, param);
		if (ret)
			return ret;
	}

	if (parse_info && parse_info[type].parse_func_after)
		ret = parse_info[type].parse_func_after(rule_act, act_entry, filter);

	return ret;
}

/**
 * @brief: handle action parse
 *
 * @param[in] attr: attr info
 * @param[in] action: nbl_flow_pattern_conf info
 * @param[in] act: nbl_rule_action info storage
 * @param[out] error: error info
 * @return int: 0-success, other-failed
 *
 */
static int nbl_tc_parse_action(struct nbl_service_mgt *serv_mgt,
			       struct flow_cls_offload *f,
			       struct nbl_flow_pattern_conf *filter,
			       struct nbl_rule_action *rule_act,
			       struct nbl_tc_flow_param *param)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	const struct flow_action_entry *act_entry;
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	int i;
	int ret = 0;

	flow_action_for_each(i, act_entry, &rule->action) {
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow parse action id %d, act idx %d\n",
			  act_entry->id, i);
		switch (act_entry->id) {
		case FLOW_ACTION_REDIRECT:
		case FLOW_ACTION_DROP:
		case FLOW_ACTION_MIRRED:
		case FLOW_ACTION_VLAN_PUSH:
		case FLOW_ACTION_VLAN_POP:
		case FLOW_ACTION_TUNNEL_ENCAP:
		case FLOW_ACTION_TUNNEL_DECAP:
		case FLOW_ACTION_MANGLE:
		case FLOW_ACTION_CSUM:
			ret = nbl_tc_parse_action_by_type(rule_act, act_entry,
							  act_entry->id, filter, param);
			if (ret)
				return ret;
			break;
		default:
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow action %d is not supported",
				  act_entry->id);
			return -EOPNOTSUPP;
		}
	}

	return ret;
}

static int nbl_serv_add_cls_flower(struct nbl_netdev_priv *priv, struct flow_cls_offload *f)
{
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(priv->adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_flow_pattern_conf *filter = NULL;
	struct nbl_rule_action *act = NULL;
	struct nbl_tc_flow_param *param = NULL;
	int ret = 0;
	int ret_act = 0;

	if (!priv->netdev || !priv->adapter)
		return -EOPNOTSUPP;

	if (!tc_can_offload(priv->netdev))
		return -EOPNOTSUPP;

	if (!nbl_tc_is_valid_netdev(priv->netdev, &serv_mgt->net_resource_mgt->netdev_ops))
		return -EOPNOTSUPP;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param)
		return -ENOMEM;

	param->key.cookie = f->cookie;
	param->common = common;
	param->serv_mgt = serv_mgt;

	ret = disp_ops->flow_index_lookup(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param->key);
	if (!ret) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow cookie %llx has already add, do not add again, dev %s.\n",
			  param->key.cookie, netdev_name(priv->netdev));
		ret = -EEXIST;
		goto ret_param_fail;
	} else if (ret != -ENOKEY) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow lookup failed, ret %d, dev %s.\n",
			  ret, netdev_name(priv->netdev));
		goto ret_param_fail;
	}

	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow add cls, cookie=%lx, dev %s.\n",
		  f->cookie, netdev_name(priv->netdev));

	if (nbl_tc_flow_init_param(priv, f, common, param)) {
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow init param failed, dev %s.\n",
			  netdev_name(priv->netdev));
		ret = -EINVAL;
		goto ret_param_fail;
	}

	filter = kzalloc(sizeof(*filter), GFP_KERNEL);
	if (!filter) {
		ret = -ENOMEM;
		goto ret_param_fail;
	}

	/* get parse info */
	disp_ops->get_tc_flow_parse_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param->parse_info);
	if (!param->parse_info) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow parse info is NULL, dev %s.\n",
			  netdev_name(priv->netdev));
		ret = -EPERM;
		goto ret_filter_fail;
	}
	filter->input_dev = priv->netdev;
	filter->common = common;

	ret = nbl_tc_parse_pattern(serv_mgt, f, filter, param);
	if (ret) {
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow failed to parse pattern, dev %s, ret %d.\n",
			  netdev_name(priv->netdev), ret);
		ret = -EINVAL;
		goto ret_filter_fail;
	}

	act = kzalloc(sizeof(*act), GFP_KERNEL);
	if (!act) {
		ret = -ENOMEM;
		goto ret_filter_fail;
	}

	act->in_port = priv->netdev;
	ret = nbl_tc_parse_action(serv_mgt, f, filter, act, param);
	if (ret) {
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow failed to parse action, dev %s, ret %d.\n",
			  netdev_name(priv->netdev), ret);
		ret = -EINVAL;
		goto ret_act_fail;
	}

	memcpy(&param->filter, filter, sizeof(param->filter));
	memcpy(&param->act, act, sizeof(param->act));

	ret = disp_ops->add_tc_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);

ret_act_fail:
	/* free edit act */
	if (ret && act->flag & NBL_FLOW_ACTION_TUNNEL_ENCAP &&
	    act->encap_parse_ok) {
		ret_act = disp_ops->tc_tun_encap_del(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						     &act->encap_key);
		if (ret_act)
			nbl_debug(common, NBL_DEBUG_FLOW, "in add tc flow err, encap del err, tc flow add ret %d, encap_idx:%d, encap del ret:%d",
				  ret, act->encap_idx, ret_act);
	}

	kfree(act);
ret_filter_fail:
	kfree(filter);
ret_param_fail:
	kfree(param);
	return ret;
}

static int nbl_serv_del_cls_flower(struct nbl_netdev_priv *priv, struct flow_cls_offload *f)
{
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(priv->adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_tc_flow_param *param = NULL;
	int ret = 0;

	if (!priv->netdev || !priv->adapter)
		return -EOPNOTSUPP;

	if (!nbl_tc_is_valid_netdev(priv->netdev, &serv_mgt->net_resource_mgt->netdev_ops))
		return -EOPNOTSUPP;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param)
		return -ENOMEM;
	nbl_debug(common, NBL_DEBUG_FLOW, "tc flow del cls, cookie=%lx\n", f->cookie);
	param->key.cookie = f->cookie;

	ret = disp_ops->del_tc_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), param);
	kfree(param);

	return ret;
}

static int nbl_serv_stats_cls_flower(struct nbl_netdev_priv *priv, struct flow_cls_offload *f)
{
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(priv->adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_stats_param param = {0};
	int ret = 0;

	if (!priv->netdev || !priv->adapter)
		return -EOPNOTSUPP;

	if (!tc_can_offload(priv->netdev))
		return -EOPNOTSUPP;

	if (!nbl_tc_is_valid_netdev(priv->netdev, &serv_mgt->net_resource_mgt->netdev_ops))
		return -EOPNOTSUPP;

	param.f = f;

	ret = disp_ops->query_tc_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &param);

	return ret;
}

static int
nbl_serv_setup_tc_cls_flower(struct nbl_netdev_priv *priv,
			     struct flow_cls_offload *cls_flower)
{
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(priv->adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u16 eswitch_mode = NBL_ESWITCH_NONE;

	eswitch_mode = disp_ops->get_eswitch_mode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (eswitch_mode != NBL_ESWITCH_OFFLOADS)
		return -EINVAL;

	switch (cls_flower->command) {
	case FLOW_CLS_REPLACE:
		return nbl_serv_add_cls_flower(priv, cls_flower);
	case FLOW_CLS_DESTROY:
		return nbl_serv_del_cls_flower(priv, cls_flower);
	case FLOW_CLS_STATS:
		return nbl_serv_stats_cls_flower(priv, cls_flower);
	default:
		return -EOPNOTSUPP;
	}
}

int nbl_serv_setup_tc_block_cb(enum tc_setup_type type, void *type_data, void *cb_priv)
{
	struct nbl_netdev_priv *priv = cb_priv;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return nbl_serv_setup_tc_cls_flower(priv, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

int nbl_serv_indr_setup_tc_block_cb(enum tc_setup_type type, void *type_data, void *cb_priv)
{
	struct nbl_indr_dev_priv *indr_priv = cb_priv;
	struct nbl_netdev_priv *priv = indr_priv->dev_priv;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return nbl_serv_setup_tc_cls_flower(priv, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

