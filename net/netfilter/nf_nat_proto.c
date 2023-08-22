// SPDX-License-Identifier: GPL-2.0-only
/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 */

#include <linux/types.h>
#include <linux/init.h>
#include <linux/ipv6.h>
#include <linux/netfilter_ipv6.h>
#include <net/checksum.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/xfrm.h>
#include <net/ipv6.h>

static void nf_nat_ipv4_csum_recalc(struct sk_buff *skb,
				    u8 proto, void *data, __sum16 *check,
				    int datalen, int oldlen)
{
	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		const struct iphdr *iph = ip_hdr(skb);

		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_headroom(skb) + skb_network_offset(skb) +
				  ip_hdrlen(skb);
		skb->csum_offset = (void *)check - data;
		*check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, datalen,
					    proto, 0);
	} else {
		inet_proto_csum_replace2(check, skb,
					 htons(oldlen), htons(datalen), true);
	}
}

#if IS_ENABLED(CONFIG_IPV6)
static void nf_nat_ipv6_csum_recalc(struct sk_buff *skb,
				    u8 proto, void *data, __sum16 *check,
				    int datalen, int oldlen)
{
	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		const struct ipv6hdr *ipv6h = ipv6_hdr(skb);

		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_headroom(skb) + skb_network_offset(skb) +
				  (data - (void *)skb->data);
		skb->csum_offset = (void *)check - data;
		*check = ~csum_ipv6_magic(&ipv6h->saddr, &ipv6h->daddr,
					  datalen, proto, 0);
	} else {
		inet_proto_csum_replace2(check, skb,
					 htons(oldlen), htons(datalen), true);
	}
}
#endif

void nf_nat_csum_recalc(struct sk_buff *skb,
			u8 nfproto, u8 proto, void *data, __sum16 *check,
			int datalen, int oldlen)
{
	switch (nfproto) {
	case NFPROTO_IPV4:
		nf_nat_ipv4_csum_recalc(skb, proto, data, check,
					datalen, oldlen);
		return;
#if IS_ENABLED(CONFIG_IPV6)
	case NFPROTO_IPV6:
		nf_nat_ipv6_csum_recalc(skb, proto, data, check,
					datalen, oldlen);
		return;
#endif
	}

	WARN_ON_ONCE(1);
}
