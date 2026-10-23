// SPDX-License-Identifier: GPL-2.0
#include <net/vxlan.h>
#include <net/route.h>
#include <linux/if_vlan.h>
#include <linux/udp.h>
#include <linux/phy.h>
#include "nbl_resource.h"
#include "nbl_service.h"
#include "nbl_tc_tun.h"

static int nbl_copy_tun_info(const struct ip_tunnel_info *tun_info,
			     struct nbl_rule_action *rule_act)
{
	size_t tun_size;

	if (tun_info->options_len)
		tun_size = sizeof(*tun_info) + tun_info->options_len;
	else
		tun_size = sizeof(*tun_info);

	rule_act->tunnel = kzalloc(tun_size, GFP_KERNEL);
	if (!rule_act->tunnel)
		return -ENOMEM;

	memcpy(rule_act->tunnel, tun_info, tun_size);

	return 0;
}

/* only support vxlan currently */
static struct nbl_tc_tunnel *nbl_tc_get_tunnel(struct net_device *tunnel_dev)
{
	if (netif_is_vxlan(tunnel_dev))
		return &vxlan_tunnel;
	else
		return NULL;
}

static int nbl_tc_tun_gen_tunnel_header_vxlan(char buf[], u8 *ip_proto,
					      const struct ip_tunnel_key *tun_key)
{
	__be32 tun_id = tunnel_id_to_key32(tun_key->tun_id);
	struct udphdr *udp = (struct udphdr *)(buf);
	struct vxlanhdr *vxh;

	vxh = (struct vxlanhdr *)((char *)udp + sizeof(struct udphdr));
	*ip_proto = IPPROTO_UDP;

	udp->dest = tun_key->tp_dst;
	vxh->vx_flags = VXLAN_HF_VNI;
	vxh->vx_vni = vxlan_vni_field(tun_id);

	return 0;
}

static int nbl_tc_tun_get_vxlan_hdr_len(void)
{
	return sizeof(struct vxlanhdr);
}

static void nbl_tc_tun_route_cleanup(struct nbl_tc_tunnel_route_info *tun_route_info)
{
	if (tun_route_info->n)
		neigh_release(tun_route_info->n);
	if (tun_route_info->real_out_dev)
		dev_put(tun_route_info->real_out_dev);
}

static int nbl_route_lookup(const struct nbl_common_info *common,
			    struct net_device *encap_mirred_dev,
			    struct nbl_tc_tunnel_route_info *tun_route_info,
			    struct nbl_serv_netdev_ops *netdev_ops,
			    u32 skprio)
{
	int ret = 0;
	struct net_device *out_dev;
	struct net_device *real_out_dev;
	struct net_device *parent_dev, *parent_parent;
	struct neighbour *n;
	struct dst_entry *dst;
	struct rtable *rt = NULL;
	u8 vlan_num = 0;
	bool is_ip6 = tun_route_info->is_ip6;

	if (is_ip6) {
		dst = ipv6_stub->ipv6_dst_lookup_flow(dev_net(encap_mirred_dev), NULL,
						      &tun_route_info->fl.fl6, NULL);
		if (IS_ERR(dst))
			return (int)PTR_ERR(dst);
	} else {
		rt = ip_route_output_key(dev_net(encap_mirred_dev), &tun_route_info->fl.fl4);
		if (IS_ERR(rt))
			return (int)PTR_ERR(rt);
		dst = &rt->dst;
		if (rt->rt_type != RTN_UNICAST) {
			ret = -ENETUNREACH;
			nbl_err(common, NBL_DEBUG_FLOW, "get route table failed, the route type is not unicast.");
			goto err;
		}
	}

	out_dev = dst->dev;
	if (is_vlan_dev(out_dev)) {
		vlan_num = 1;
		parent_dev = vlan_dev_real_dev(out_dev);
		real_out_dev = vlan_dev_real_dev(out_dev);
		if (is_vlan_dev(parent_dev)) {
			if (common->product_type == NBL_LEONIS_TYPE) {
				nbl_debug(common, NBL_DEBUG_FLOW, "ipv%u encap out dev is %s, parent_dev:%s is vlan, not support two vlan\n",
					  is_ip6 ? 6 : 4, out_dev->name,
					parent_dev ? parent_dev->name : "NULL");
				ret = -EOPNOTSUPP;
				goto err;
			} else {
				parent_parent = vlan_dev_real_dev(parent_dev);
				if (is_vlan_dev(parent_parent)) {
					nbl_err(common, NBL_DEBUG_FLOW, "ipv%u encap out dev is %s,parent_dev:%s parent_parent:%s, real_out_dev:%s, not support two vlan.\n",
						is_ip6 ? 6 : 4, out_dev->name,
						parent_dev ? parent_dev->name : "NULL",
						parent_parent ? parent_parent->name : "NULL",
						real_out_dev ? real_out_dev->name : "NULL");
					ret = -EOPNOTSUPP;
					goto err;
				}
				tun_route_info->out_dev_parent = parent_dev;
				vlan_num = 2;
			}
		}

		if (vlan_num == 2)
			real_out_dev = vlan_dev_real_dev(parent_dev);
		tun_route_info->vlan_num = vlan_num;
		tun_route_info->ovlan_id = vlan_dev_vlan_id(out_dev);
		tun_route_info->ovlan_pcp =
			(u8)(vlan_dev_get_egress_qos_mask(out_dev, skprio) >> VLAN_PRIO_SHIFT);
		if (vlan_num == 2) {
			tun_route_info->ivlan_id = vlan_dev_vlan_id(out_dev);
			tun_route_info->ivlan_pcp =
				(u8)(vlan_dev_get_egress_qos_mask(out_dev, skprio) >>
										VLAN_PRIO_SHIFT);
			tun_route_info->ovlan_id = vlan_dev_vlan_id(parent_dev);
			tun_route_info->ovlan_pcp =
				(u8)(vlan_dev_get_egress_qos_mask(parent_dev, skprio) >>
										VLAN_PRIO_SHIFT);
		}
		nbl_debug(common, NBL_DEBUG_FLOW, "ipv%u encap out dev is %s, real_out_dev:%s, ivlan_pcp:%u, ivlan_id:%u, ovlan_pcp:%u, ovlan_id:%u, vlan_num:%u\n",
			  is_ip6 ? 6 : 4, out_dev->name, real_out_dev ? real_out_dev->name : "NULL",
			  tun_route_info->ivlan_pcp, tun_route_info->ivlan_id,
			  tun_route_info->ovlan_pcp, tun_route_info->ovlan_id,
			  tun_route_info->vlan_num);
	} else {
		real_out_dev = out_dev;
	}

	if (!netif_is_lag_master(real_out_dev) &&
	    real_out_dev->netdev_ops != netdev_ops->pf_netdev_ops &&
	    real_out_dev->netdev_ops != netdev_ops->rep_netdev_ops) {
		nbl_info(common, NBL_DEBUG_FLOW, "encap out dev is %s, not ours, not support\n",
			 out_dev->name);
		ret = -EOPNOTSUPP;
		goto err;
	}

	dev_hold(real_out_dev);
	if (!tun_route_info->ttl)
		tun_route_info->ttl =
			is_ip6 ? (u8)ip6_dst_hoplimit(dst) : (u8)ip4_dst_hoplimit(dst);

	nbl_debug(common, NBL_DEBUG_FLOW, "route lookup: dst->dev:%s, dst->ops:%p, real_dev:%s, ttl:%u",
		  dst->dev ? dst->dev->name : "null",
		  dst->ops, real_out_dev ? real_out_dev->name : "NULL",
		  tun_route_info->ttl);

	n = is_ip6 ? dst_neigh_lookup(dst, &tun_route_info->fl.fl6.daddr)
		   : dst_neigh_lookup(dst, &tun_route_info->fl.fl4.daddr);
	if (!n) {
		ret = -ENONET;
		nbl_info(common, NBL_DEBUG_FLOW, "get neigh failed.");
		goto dev_release;
	}

	dst_release(dst);
	tun_route_info->out_dev = out_dev;
	tun_route_info->real_out_dev = real_out_dev;
	tun_route_info->n = n;

	return 0;

dev_release:
	dev_put(real_out_dev);
err:
	dst_release(dst);
	return ret;
}

static char *nbl_tc_tun_gen_eth_hdr(char *buf, struct net_device *dev,
				    const unsigned char *hw_dst, u16 proto,
				    const struct nbl_common_info *common)
{
	struct ethhdr *eth = (struct ethhdr *)buf;
	char *ip;

	ether_addr_copy(eth->h_dest, hw_dst);
	ether_addr_copy(eth->h_source, dev->dev_addr);
	if (is_vlan_dev(dev)) {
		struct vlan_hdr *vlan =
			(struct vlan_hdr *)((char *)eth + sizeof(struct ethhdr));

		ip = (char *)vlan + sizeof(struct vlan_hdr);
		eth->h_proto = vlan_dev_vlan_proto(dev);
		vlan->h_vlan_TCI = htons(vlan_dev_vlan_id(dev));
		vlan->h_vlan_encapsulated_proto = htons(proto);
		nbl_debug(common, NBL_DEBUG_FLOW, "output is vlan dev: vlan_TCI:0x%x, vlan_proto:0x%x, eth_proto:0x%x",
			  vlan->h_vlan_TCI, vlan->h_vlan_encapsulated_proto,
			  eth->h_proto);
	} else {
		eth->h_proto = htons(proto);
		ip = (char *)eth + sizeof(struct ethhdr);
	}

	return ip;
}

static int nbl_tc_tun_create_header_ipv4_leonis(const struct nbl_common_info *common,
						struct nbl_rule_action *rule_act,
						unsigned char *hw_dst,
						struct nbl_tc_tunnel_route_info *tun_route_info,
						struct nbl_encap_key *key)
{
	int ret = 0;
	struct iphdr *ip;
	struct udphdr *udp;
	struct vxlanhdr *vxh;
	u8 total_len = 0, eth_len = 0, l4_len = 0;
	const struct ip_tunnel_key *tun_key = &key->ip_tun_key;

	/* add ether header */
	ip = (struct iphdr *)nbl_tc_tun_gen_eth_hdr((char *)rule_act->encap_buf,
				tun_route_info->out_dev, hw_dst, ETH_P_IP, common);

	total_len += sizeof(struct ethhdr);
	if (is_vlan_dev(tun_route_info->out_dev)) {
		rule_act->encap_idx_info.info.vlan_offset = total_len - 2;
		total_len += sizeof(struct vlan_hdr);
	}

	eth_len = total_len;
	rule_act->encap_idx_info.info.l4_ck_mod = NBL_FLOW_L4_CK_NO_MODIFY;
	rule_act->encap_idx_info.info.phid2_offset = total_len;

	/* add ip header */
	ip->tos = tun_key->tos;
	ip->version = NBL_FLOW_IPV4;
	ip->ihl = NBL_FLOW_IHL;
	ip->frag_off = NBL_FLOW_DF;
	ip->ttl = tun_route_info->ttl;
	ip->saddr = tun_route_info->fl.fl4.saddr;
	ip->daddr = tun_route_info->fl.fl4.daddr;

	rule_act->encap_idx_info.info.len_en0 = 1;
	rule_act->encap_idx_info.info.len_offset0 = total_len + NBL_FLOW_IPV4_LEN_OFFSET;
	rule_act->encap_idx_info.info.l3_ck_en = 1;
	rule_act->encap_idx_info.info.dscp_offset = (total_len + 1) * 8;
	total_len += sizeof(struct iphdr);

	/* add tunnel proto header */
	ret = ((struct nbl_tc_tunnel *)key->tc_tunnel)->generate_tunnel_hdr((char *)ip +
		sizeof(struct iphdr), &ip->protocol, &key->ip_tun_key);
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "nbl tc flow gen tun hdr err, ret:%d", ret);
		return ret;
	}

	rule_act->encap_idx_info.info.phid3_offset = total_len;
	rule_act->encap_idx_info.info.sport_offset = total_len;
	rule_act->encap_idx_info.info.len_en1 = 1;
	rule_act->encap_idx_info.info.len_offset1 = total_len + NBL_FLOW_UDP_LEN_OFFSET;
	rule_act->encap_idx_info.info.l4_ck_mod = NBL_FLOW_L4_CK_MODE_0;
	total_len += sizeof(struct udphdr);

	/* tnl info */
	rule_act->encap_idx_info.info.vni_offset = total_len + NBL_FLOW_VNI_OFFSET;
	total_len += ((struct nbl_tc_tunnel *)(key->tc_tunnel))->get_tun_hlen();

	ip->tot_len = total_len - eth_len;
	l4_len = (u8)(ip->tot_len - sizeof(struct iphdr));
	ip->tot_len = be16_to_cpu(ip->tot_len);

	udp = (struct udphdr *)((char *)ip + sizeof(struct iphdr));
	vxh = (struct vxlanhdr *)((char *)udp + sizeof(struct udphdr));

	if (udp)
		udp->len = be16_to_cpu(l4_len);

	rule_act->encap_idx_info.info.tnl_len = total_len;
	rule_act->encap_size = total_len;
	rule_act->vni = be32_to_cpu(vxh->vx_vni);

	nbl_debug(common, NBL_DEBUG_FLOW, "leonis create ipv4 tnl header ok, encap_len:%d",
		  total_len);

	return ret;
}

static int nbl_tc_tun_create_header_draco(struct nbl_tc_flow_param *param,
					  struct nbl_rule_action *rule_act,
					  unsigned char *hw_dst,
					  struct nbl_tc_tunnel_route_info *tun_route,
					  struct nbl_encap_key *key)
{
	int ret = 0;
	struct nbl_dispatch_mgt *disp_mgt = NBL_SERV_MGT_TO_DISP_PRIV(param->serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(param->serv_mgt);
	struct nbl_tc_tun_create_header_param hdr_param = {
		.rule_act = rule_act,
		.hw_dst = hw_dst,
		.tun_route = tun_route,
		.key = key,
	};

	ret = disp_ops->tc_tun_create_header(disp_mgt, &hdr_param);

	return ret;
}

static int nbl_tc_tun_create_header_ipv4(struct nbl_rule_action *rule_act,
					 struct nbl_tc_flow_param *param,
					 struct net_device *encap_mirred_dev,
					 struct nbl_encap_key *key)
{
	int ret = 0;
	struct nbl_common_info *common = param->common;
	const struct ip_tunnel_key *tun_key = &key->ip_tun_key;
	struct nbl_serv_netdev_ops *netdev_ops = &param->serv_mgt->net_resource_mgt->netdev_ops;
	struct nbl_tc_tunnel_route_info tun_route_info;

	unsigned char hw_dst[ETH_ALEN];
	u8 nud_state;

	memset(&tun_route_info, 0, sizeof(tun_route_info));
	memset(hw_dst, 0, sizeof(hw_dst));
	tun_route_info.fl.fl4.flowi4_tos = tun_key->tos;
	tun_route_info.fl.fl4.flowi4_proto = IPPROTO_UDP;
	tun_route_info.fl.fl4.fl4_dport = tun_key->tp_dst;
	tun_route_info.fl.fl4.daddr = tun_key->u.ipv4.dst;
	tun_route_info.fl.fl4.saddr = tun_key->u.ipv4.src;
	tun_route_info.ttl = tun_key->ttl;
	tun_route_info.common = common;

	ret = nbl_route_lookup(common, encap_mirred_dev, &tun_route_info, netdev_ops,
			       rt_tos2priority(tun_key->tos));
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW,
			 "get route failed in create encap head v4, encap_dev:%s, ret %d",
			 encap_mirred_dev->name, ret);
		return ret;
	}

	rule_act->tc_tun_encap_out_dev = tun_route_info.real_out_dev;

	/* cpoy mac */
	read_lock_bh(&tun_route_info.n->lock);
	nud_state = tun_route_info.n->nud_state;
	ether_addr_copy(hw_dst, tun_route_info.n->ha);
	read_unlock_bh(&tun_route_info.n->lock);

	if (common->product_type == NBL_LEONIS_TYPE)
		ret = nbl_tc_tun_create_header_ipv4_leonis(common, rule_act, hw_dst,
							   &tun_route_info, key);
	else
		ret = nbl_tc_tun_create_header_draco(param, rule_act, hw_dst, &tun_route_info, key);

	if (!(nud_state & NUD_VALID))
		neigh_event_send(tun_route_info.n, NULL);

	nbl_tc_tun_route_cleanup(&tun_route_info);

	return ret;
}

static int nbl_tc_tun_create_header_ipv6_leonis(const struct nbl_common_info *common,
						struct nbl_rule_action *rule_act,
						unsigned char *hw_dst,
						struct nbl_tc_tunnel_route_info *tun_route,
						struct nbl_encap_key *key)
{
	int ret = 0;
	u8 total_len = 0, eth_len = 0, l4_len = 0;
	const struct ip_tunnel_key *tun_key = &key->ip_tun_key;
	struct ipv6hdr *ip;
	struct udphdr *udp;
	struct vxlanhdr *vxh;

	/* add ether header */
	ip = (struct ipv6hdr *)nbl_tc_tun_gen_eth_hdr((char *)rule_act->encap_buf,
				tun_route->out_dev, hw_dst, ETH_P_IPV6, common);

	total_len += sizeof(struct ethhdr);
	if (is_vlan_dev(tun_route->out_dev)) {
		rule_act->encap_idx_info.info.vlan_offset = total_len - 2;
		total_len += sizeof(struct vlan_hdr);
	}

	eth_len = total_len;
	rule_act->encap_idx_info.info.l4_ck_mod = NBL_FLOW_L4_CK_NO_MODIFY;
	rule_act->encap_idx_info.info.phid2_offset = total_len;

	/* add ip header */
	ip6_flow_hdr(ip, tun_key->tos, 0);
	ip->hop_limit = tun_route->ttl;
	ip->saddr = tun_route->fl.fl6.saddr;
	ip->daddr = tun_route->fl.fl6.daddr;

	rule_act->encap_idx_info.info.len_en0 = 1;
	rule_act->encap_idx_info.info.len_offset0 = total_len + NBL_FLOW_IPV6_LEN_OFFSET;
	rule_act->encap_idx_info.info.dscp_offset = (total_len * 8) + 4;
	total_len += sizeof(struct ipv6hdr);

	/* add tunnel proto header */
	ret = ((struct nbl_tc_tunnel *)key->tc_tunnel)->generate_tunnel_hdr((char *)ip +
		sizeof(struct ipv6hdr), &ip->nexthdr, &key->ip_tun_key);
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "nbl tc flow gen v6 tun hdr err, ret:%d", ret);
		return ret;
	}

	rule_act->encap_idx_info.info.phid3_offset = total_len;
	rule_act->encap_idx_info.info.sport_offset = total_len;
	rule_act->encap_idx_info.info.len_en1 = 1;
	rule_act->encap_idx_info.info.len_offset1 = total_len + NBL_FLOW_UDP_LEN_OFFSET;
	rule_act->encap_idx_info.info.l4_ck_mod = NBL_FLOW_L4_CK_MODE_1;
	total_len += sizeof(struct udphdr);

	/* tnl info */
	rule_act->encap_idx_info.info.vni_offset = total_len + NBL_FLOW_VNI_OFFSET;
	total_len += ((struct nbl_tc_tunnel *)(key->tc_tunnel))->get_tun_hlen();

	ip->payload_len = total_len - eth_len;
	l4_len = (u8)(ip->payload_len - sizeof(struct ipv6hdr));
	ip->payload_len = be16_to_cpu(l4_len);

	udp = (struct udphdr *)((char *)ip + sizeof(struct ipv6hdr));
	vxh = (struct vxlanhdr *)((char *)udp + sizeof(struct udphdr));

	if (udp)
		udp->len = be16_to_cpu(l4_len);

	rule_act->encap_idx_info.info.tnl_len = total_len;
	rule_act->encap_size = total_len;
	rule_act->vni = be32_to_cpu(vxh->vx_vni);

	nbl_debug(common, NBL_DEBUG_FLOW, "leonis create ipv6 header ok: encap_len:%d", total_len);

	return ret;
}

static int nbl_tc_tun_create_header_ipv6(struct nbl_rule_action *rule_act,
					 struct nbl_tc_flow_param *param,
					 struct net_device *encap_mirred_dev,
					 struct nbl_encap_key *key)
{
	int ret = 0;
	struct nbl_common_info *common = param->common;
	const struct ip_tunnel_key *tun_key = &key->ip_tun_key;
	struct nbl_serv_netdev_ops *netdev_ops = &param->serv_mgt->net_resource_mgt->netdev_ops;
	struct nbl_tc_tunnel_route_info tun_route_info;
	unsigned char hw_dst[ETH_ALEN];
	u8 nud_state;

	memset(&tun_route_info, 0, sizeof(tun_route_info));
	memset(hw_dst, 0, sizeof(hw_dst));
	tun_route_info.fl.fl6.flowlabel = ip6_make_flowinfo(RT_TOS(tun_key->tos), tun_key->label);
	tun_route_info.fl.fl6.fl6_dport = tun_key->tp_dst;
	tun_route_info.fl.fl6.fl6_sport = tun_key->tp_src;
	tun_route_info.fl.fl6.daddr = tun_key->u.ipv6.dst;
	tun_route_info.fl.fl6.saddr = tun_key->u.ipv6.src;
	tun_route_info.ttl = tun_key->ttl;
	tun_route_info.is_ip6 = true;
	tun_route_info.common = common;

	ret = nbl_route_lookup(common, encap_mirred_dev, &tun_route_info, netdev_ops,
			       rt_tos2priority(tun_key->tos));
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW,
			 "get route failed in create encap head v6, encap_dev:%s, ret %d",
			 encap_mirred_dev->name, ret);
		return ret;
	}

	rule_act->tc_tun_encap_out_dev = tun_route_info.real_out_dev;

	/* copy mac */
	read_lock_bh(&tun_route_info.n->lock);
	nud_state = tun_route_info.n->nud_state;
	ether_addr_copy(hw_dst, tun_route_info.n->ha);
	read_unlock_bh(&tun_route_info.n->lock);

	if (common->product_type == NBL_LEONIS_TYPE)
		ret = nbl_tc_tun_create_header_ipv6_leonis(common, rule_act, hw_dst,
							   &tun_route_info, key);
	else
		ret = nbl_tc_tun_create_header_draco(param, rule_act, hw_dst, &tun_route_info, key);

	if (!(nud_state & NUD_VALID))
		neigh_event_send(tun_route_info.n, NULL);

	nbl_tc_tun_route_cleanup(&tun_route_info);

	return ret;
}

int nbl_tc_tun_parse_encap_info(struct nbl_rule_action *rule_act,
				struct nbl_tc_flow_param *param,
				struct net_device *encap_mirred_dev)
{
	int ret = 0;
	const struct nbl_common_info *common = param->common;
	struct nbl_dispatch_mgt *disp_mgt;
	struct nbl_dispatch_ops *disp_ops;
	unsigned short ip_family;
	bool is_encap_find = false;

	ret = nbl_copy_tun_info(param->tunnel, rule_act);
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "alloc tunnel_info failed, ret %d\n", ret);
		return ret;
	}

	ip_family = ip_tunnel_info_af(rule_act->tunnel);
	memcpy(&rule_act->encap_key.ip_tun_key, &rule_act->tunnel->key,
	       sizeof(rule_act->encap_key.ip_tun_key));
	rule_act->encap_key.tc_tunnel = nbl_tc_get_tunnel(encap_mirred_dev);
	if (!rule_act->encap_key.tc_tunnel) {
		nbl_err(common, NBL_DEBUG_FLOW, "unsupport tunnel type: %s",
			encap_mirred_dev->rtnl_link_ops->kind);
		ret = -EOPNOTSUPP;
		goto malloc_err;
	}

	disp_mgt = NBL_SERV_MGT_TO_DISP_PRIV(param->serv_mgt);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(param->serv_mgt);
	is_encap_find = disp_ops->tc_tun_encap_lookup(disp_mgt, rule_act, param);
	if (is_encap_find)
		goto parse_encap_finish;

	if (ip_family == AF_INET)
		ret = nbl_tc_tun_create_header_ipv4(rule_act, param,
						    encap_mirred_dev,
						    &rule_act->encap_key);
	else
		ret = nbl_tc_tun_create_header_ipv6(rule_act, param,
						    encap_mirred_dev,
						    &rule_act->encap_key);
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW, "create tnl header failed, ret %d!", ret);
		goto malloc_err;
	}

	ret = disp_ops->tc_tun_encap_add(disp_mgt, rule_act);
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW, "add tnl encap hash failed, ret %d!", ret);
		goto malloc_err;
	}

	nbl_debug(common, NBL_DEBUG_FLOW, "parse tnl encap finish");

parse_encap_finish:
	kfree(rule_act->tunnel);
	rule_act->encap_parse_ok = true;
	return ret;

malloc_err:
	kfree(rule_act->tunnel);

	return ret;
}

struct nbl_tc_tunnel vxlan_tunnel = {
	.tunnel_type = NBL_TC_TUNNEL_TYPE_VXLAN,
	.generate_tunnel_hdr = nbl_tc_tun_gen_tunnel_header_vxlan,
	.get_tun_hlen = nbl_tc_tun_get_vxlan_hdr_len,
};

