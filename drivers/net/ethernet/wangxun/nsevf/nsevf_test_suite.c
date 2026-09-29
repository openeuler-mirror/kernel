// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include <net/gre.h>
#include <net/vxlan.h>

#include "nsevf_prototype.h"

void nsevf_locate_final_l3_l4_hdr(struct sk_buff *skb,
				  void **ret_l4_hdr, /* tcp or udp */
				  void **ret_l3_hdr, void **ret_1st_vlan_hdr,
				  u16 *l3_proto, u8 *l4_proto)
{
	struct ethhdr *o_eh = NULL;
	struct vlan_hdr *o_vh = NULL;
	int i = 0;

	struct iphdr *o_iph = NULL;
	struct ipv6hdr *o_ip6h = NULL;

	struct tcphdr *tcph = NULL; /* most inner */

	struct udphdr *o_udph = NULL;

	struct vxlanhdr *vxh = NULL;
	struct gre_base_hdr *greh = NULL;

	struct iphdr *i_iph = NULL;
	struct ipv6hdr *i_ip6h = NULL;

	struct ethhdr *i_eh = NULL;

	*l3_proto = 0;
	*l4_proto = 0;

	o_eh = (struct ethhdr *)skb_mac_header(skb);
	if (!o_eh)
		return;

	if (o_eh->h_proto == cpu_to_be16(ETH_P_8021Q) ||
	    o_eh->h_proto == cpu_to_be16(ETH_P_8021AD)) {
		o_vh = (struct vlan_hdr *)(o_eh + 1);

		if (ret_1st_vlan_hdr)
			*ret_1st_vlan_hdr = (void *)o_vh;

		for (i = 0; i < 8; i++) {
			if (o_vh->h_vlan_encapsulated_proto !=
				    cpu_to_be16(ETH_P_8021Q) &&
			    o_vh->h_vlan_encapsulated_proto !=
				    cpu_to_be16(ETH_P_8021AD)) {
				break;
			}
			o_vh += 1; /* nested VLAN */
		}
	}

	if (o_eh->h_proto == cpu_to_be16(ETH_P_IP) ||
	    (o_vh &&
	     o_vh->h_vlan_encapsulated_proto == cpu_to_be16(ETH_P_IP))) {
		if (o_vh)
			o_iph = (struct iphdr *)(o_vh + 1);
		else
			o_iph = (struct iphdr *)(o_eh + 1);

		*l3_proto = ETH_P_IP;
		*l4_proto = o_iph->protocol;

		if (ip_is_fragment(o_iph))
			return;

		/* the following "o_iph + 1" are not accurate, not consider possible IPv4 options.
		 *
		 * anyhow, this is only for simple debug.
		 */

		if (o_iph->protocol == IPPROTO_TCP) { //ip4-tcp

			tcph = (struct tcphdr *)(o_iph + 1);

			/* FOUND */
			*ret_l4_hdr = (void *)tcph;
			*ret_l3_hdr = (void *)o_iph;

			return;
		} else if (o_iph->protocol ==
			   IPPROTO_UDP) { //ip4-udp (maybe vxlan, check later)
			o_udph = (struct udphdr *)(o_iph + 1);

			*ret_l3_hdr = (void *)
				o_iph; /* set it in advance, may be a plain UDP packet */
		} else if (o_iph->protocol == IPPROTO_ICMP) {
			/* FOUND */
			*ret_l4_hdr = (void *)(o_iph + 1);
			*ret_l3_hdr = (void *)o_iph;

			return;
		} else if (o_iph->protocol == IPPROTO_IPIP) { //ip4-ip4
			i_iph = (struct iphdr *)(o_iph + 1);
		} else if (o_iph->protocol == IPPROTO_IPV6) { //ip4-ip6
			i_ip6h = (struct ipv6hdr *)(o_iph + 1);
		} else if (o_iph->protocol ==
			   IPPROTO_GRE) { //ip4-gre (check inner later)
			greh = (struct gre_base_hdr *)(o_iph + 1);
		} else {
			return;
		}
	} else if (o_eh->h_proto == cpu_to_be16(ETH_P_IPV6) ||
		   (o_vh && o_vh->h_vlan_encapsulated_proto ==
				    cpu_to_be16(ETH_P_IPV6))) {
		if (o_vh)
			o_ip6h = (struct ipv6hdr *)(o_vh + 1);
		else
			o_ip6h = (struct ipv6hdr *)(o_eh + 1);

		*l3_proto = ETH_P_IPV6;
		*l4_proto = o_ip6h->nexthdr;

		if (o_ip6h->nexthdr == IPPROTO_TCP) { //ip6-tcp

			tcph = (struct tcphdr *)(o_ip6h + 1);

			/* FOUND */
			*ret_l4_hdr = (void *)tcph;
			*ret_l3_hdr = (void *)o_ip6h;

			return;
		} else if (o_ip6h->nexthdr ==
			   IPPROTO_UDP) { //ip6-udp (maybe vxlan, check later)
			o_udph = (struct udphdr *)(o_ip6h + 1);

			*ret_l3_hdr = (void *)
				o_ip6h; /* set it in advance, may be a plain UDP packet */
		} else if (o_ip6h->nexthdr == IPPROTO_ICMPV6) { //ip6-icmp

			/* FOUND */
			*ret_l4_hdr = (void *)(o_ip6h + 1);
			*ret_l3_hdr = (void *)o_ip6h;

			return;
		} else if (o_ip6h->nexthdr == IPPROTO_IPIP) { //ip6-ip4
			i_iph = (struct iphdr *)(o_ip6h + 1);
		} else if (o_ip6h->nexthdr == IPPROTO_IPV6) { //ip6-ip6
			i_ip6h = (struct ipv6hdr *)(o_ip6h + 1);
		} else if (o_ip6h->nexthdr ==
			   IPPROTO_GRE) { //ip6-gre (check inner later)
			greh = (struct gre_base_hdr *)(o_ip6h + 1);
		} else {
			return;
		}
	} else {
		return;
	}

	if (i_iph || i_ip6h) { //ip4-ip4, ip4-ip6, ip6-ip4, ip6-ip4

found_inner_l3:
		if (i_iph && (i_iph->protocol == IPPROTO_TCP ||
			      i_iph->protocol == IPPROTO_UDP ||
			      i_iph->protocol == IPPROTO_ICMP)) {
			if (ip_is_fragment(i_iph))
				return;

			/* TCP and UDP destination ports have the same offset. */
			tcph = (struct tcphdr *)(i_iph + 1);

			/* FOUND */
			*ret_l4_hdr = (void *)tcph;
			*ret_l3_hdr = (void *)i_iph;

			*l3_proto = ETH_P_IP;
			*l4_proto = i_iph->protocol;

			return;
		} else if (i_ip6h && (i_ip6h->nexthdr == IPPROTO_TCP ||
				      i_ip6h->nexthdr == IPPROTO_UDP ||
				      i_ip6h->nexthdr == IPPROTO_ICMPV6)) {
			/* TCP and UDP destination ports have the same offset. */
			tcph = (struct tcphdr *)(i_ip6h + 1);

			/* FOUND */
			*ret_l4_hdr = (void *)tcph;
			*ret_l3_hdr = (void *)i_ip6h;

			*l3_proto = ETH_P_IPV6;
			*l4_proto = i_ip6h->nexthdr;

			return;
		} else {
			return;
		}
	} else if (o_udph) { //outter UDP, check if it is plain UDP, or vxlan
		if (o_udph->dest ==
			    cpu_to_be16(4789) || //vxlan port defined in RFC
		    o_udph->dest == cpu_to_be16(4790) || //vxlan-gpe
		    o_udph->dest ==
			    cpu_to_be16(8472)) { //linux 'vxlan_port' defined in vxlan.c

			vxh = (struct vxlanhdr *)(o_udph + 1);
			i_eh = (struct ethhdr *)(vxh + 1);

found_inner_l2:
			if (i_eh->h_proto == cpu_to_be16(ETH_P_IP)) {
				i_iph = (struct iphdr *)(i_eh + 1);
				goto found_inner_l3;
			} else if (i_eh->h_proto == cpu_to_be16(ETH_P_IPV6)) {
				i_ip6h = (struct ipv6hdr *)(i_eh + 1);
				goto found_inner_l3;
			} else {
				return;
			}
		} else { /* Plain UDP */
			/* TCP and UDP destination ports have the same offset. */
			tcph = (struct tcphdr *)o_udph;

			/* FOUND */
			*ret_l4_hdr = (void *)tcph;

			return;
		}
	} else if (greh) { //ip4-gre, ip6-gre
		if (greh->protocol == cpu_to_be16(ETH_P_IP)) {
			i_iph = (struct iphdr *)(greh + 1);
			goto found_inner_l3;
		} else if (greh->protocol == cpu_to_be16(ETH_P_IPV6)) {
			i_ip6h = (struct ipv6hdr *)(greh + 1);
			goto found_inner_l3;
		} else if (greh->protocol == cpu_to_be16(ETH_P_TEB)) {
			i_eh = (struct ethhdr *)(greh + 1);
			goto found_inner_l2;
		} else {
			return;
		}
	}
}
