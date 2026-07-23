// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/zxdh_auxiliary_bus.h>
#include <linux/dinghai/driver.h>
#include <net/devlink.h>
#include <net/udp_tunnel.h>
#include <linux/dinghai/devlink.h>
#include <linux/dinghai/dh_cmd.h>
#include <linux/netdevice.h>
#include <linux/dinghai/en_sf.h>
#include <linux/etherdevice.h>
#include <linux/dinghai/helper.h>
#include <linux/dinghai/zxdh_compat.h>
#include <linux/if_bridge.h>
#include "en_aux.h"
#include "en_ethtool/ethtool.h"
#include "en_np/table/include/dpp_tbl_api.h"
#include "en_np/table/include/dpp_tbl_comm.h"
#include "en_aux/en_aux_events.h"
#include "en_aux/en_aux_eq.h"
#include "en_aux/en_aux_cmd.h"
#include "msg_common.h"
#include "en_pf.h"
#include "en_aux/en_aux_ioctl.h"
#include "slib.h"
#include <linux/dinghai/lag.h>
#ifdef ZXDH_MSGQ
#include "en_aux/priv_queue.h"
#endif
#include "en_aux/en_1588_pkt_proc.h"
#include "en_aux/en_aux_cmd.h"
#include "zxdh_tools/zxdh_tools_netlink.h"
#include <linux/jhash.h>
#include "en_pf/msg_func.h"
#include "bonding/zxdh_lag.h"
#ifdef ZXDH_DCBNL_OPEN
#include "en_aux/dcbnl/en_dcbnl.h"
#endif
#include <linux/umh.h>

#define IS_1588_MESSAGE 0
#define IS_NOT_1588_MESSAGE 1
#define IS_LB_PKT 0
#define IS_NOT_LB_PKT 1
#define ETHER_MAC_LEN 6
#define ETHER_TYPE_LEN 2
#define IP_PROT_OFFSET 9
#define IPV4_HDR_LEN 20
#define UDP_HDR_LEN 8
#define ETH_LEN 42

#define KERNEL_PF_FC 92500
#define KERNEL_PF_FC_1 23750

static struct work_struct work_cfg_del = { 0 };
static u8 card_num;
const u8 BOND_MCAST_ADDR[ETH_ALEN] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x02 };
static unsigned int mac_hash(struct zxdh_ipv6_mac_tbl *mac_tbl, const u8 *mac_addr);
u32 max_pairs = ZXDH_MQ_PAIRS_NUM;
module_param(max_pairs, uint, 0644);
MODULE_PARM_DESC(max_pairs, "Max queue pairs");

MODULE_LICENSE("Dual BSD/GPL");

s32 zxdh_port_enable(struct zxdh_en_device *en_dev, bool enable)
{
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->vqmb_port_ctl)
		return 0;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF)
		return zxdh_vf_egr_port_attr_set(en_dev, SRIOV_VPORT_IS_UP, enable, 0);

	if (en_dev->is_hwbond || en_dev->ops->is_special_bond(en_dev->parent))
		dpp_uplink_phy_attr_set(&pf_info, en_dev->phy_port, UPLINK_PHY_PORT_IS_UP, enable);

	if (en_dev->link_down_on_close)
		zxdh_spm_port_enable_cfg(en_dev, enable);
	return dpp_vport_attr_set(&pf_info, SRIOV_VPORT_IS_UP, enable);
}

static s32 en_open(struct net_device *netdev, bool boot)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 i = 0;
	s32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	LOG_INFO("zxdh_en_open start\n");
	mutex_lock(&en_priv->lock);

	set_bit(ZXDH_DEVICE_STATE_OPENED, &en_dev->state);

	for (i = 0; i < en_dev->max_vq_pairs; i++) {
		if (i < en_dev->curr_queue_pairs) {
			/* Make sure we have some buffers: if oom use wq */
			if (!try_fill_recv(&en_dev->rq[i], GFP_KERNEL))
				schedule_delayed_work(&en_dev->refill, 0);
		}

		err = xdp_rxq_info_reg(&en_dev->rq[i].xdp_rxq, netdev, i,
				       en_dev->rq[i].napi.napi_id);
		if (err < 0) {
			mutex_unlock(&en_priv->lock);
			LOG_ERR("xdp_rxq_info_reg failed\n");
			return err;
		}

		err = xdp_rxq_info_reg_mem_model(&en_dev->rq[i].xdp_rxq, MEM_TYPE_PAGE_SHARED,
						 NULL);
		if (err < 0) {
			mutex_unlock(&en_priv->lock);
			LOG_ERR("xdp_rxq_info_reg_mem_model failed\n");
			xdp_rxq_info_unreg(&en_dev->rq[i].xdp_rxq);
			return err;
		}

		virtnet_napi_enable(en_dev->rq[i].vq, &en_dev->rq[i].napi);
		virtnet_napi_tx_enable(netdev, en_dev->sq[i].vq, &en_dev->sq[i].napi);
	}

	mutex_unlock(&en_priv->lock);

	if (boot) {
#ifdef ZXDH_CONFIG_SPECIAL_SQ_EN
		err = zxdh_flow_map_init(en_priv);
		if (err)
			LOG_ERR("zxdh_flow_map_init failed\n");
#endif
	}

	if (!en_dev->link_up) {
		if (!en_dev->link_down_on_close)
			return 0;
	}

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	if (!en_dev->ops->is_bond(en_dev->parent))
		return zxdh_port_enable(en_dev, TRUE);

	if (en_dev->link_down_on_close)
		zxdh_spm_port_enable_cfg(en_dev, 1);

	err = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_IS_UP, 1);
	if (err != 0) {
		LOG_ERR("dpp_vport_attr_set bond pf failed\n");
		return err;
	}

	return zxdh_uplink_phy_attr_set(&pf_info, en_dev->phy_port, UPLINK_PHY_PORT_IS_UP, 1);
}

s32 zxdh_en_open(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	return en_open(netdev, true);
}

static s32 en_phyport_close(struct zxdh_en_device *en_dev)
{
	struct dpp_pf_info_t pf_info = { 0 };
	s32 err = 0;

	if (!en_dev->link_up) {
		if (!en_dev->link_down_on_close)
			return 0;
	}

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	if (!en_dev->ops->is_bond(en_dev->parent))
		return zxdh_port_enable(en_dev, FALSE);

	if (en_dev->link_down_on_close)
		zxdh_spm_port_enable_cfg(en_dev, 0);

	err = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_IS_UP, 0);
	if (err != 0) {
		LOG_ERR("dpp_vport_attr_set bond pf failed\n");
		return err;
	}

	return zxdh_uplink_phy_attr_set(&pf_info, en_dev->phy_port, UPLINK_PHY_PORT_IS_UP, 0);
}

s32 zxdh_en_close(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 i = 0;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;

	if (!test_bit(ZXDH_DEVICE_STATE_OPENED, &en_dev->state))
		return 0;
	mutex_lock(&en_priv->lock);
	clear_bit(ZXDH_DEVICE_STATE_OPENED, &en_dev->state);

	/* Make sure refill_work doesn't re-enable napi! */
	cancel_delayed_work_sync(&en_dev->refill);

	for (i = 0; i < en_dev->max_vq_pairs; i++) {
		xdp_rxq_info_unreg(&en_dev->rq[i].xdp_rxq);
		napi_disable(&en_dev->rq[i].napi);
		virtnet_napi_tx_disable(&en_dev->sq[i].napi);
	}
	mutex_unlock(&en_priv->lock);

#ifdef ZXDH_CONFIG_SPECIAL_SQ_EN
	zxdh_flow_map_cleanup(en_priv);
#endif

	return en_phyport_close(en_dev);
}

void pkt_transport_protocol_parse(s8 next_protocol, struct zxdh_net_hdr_tx *hdr)
{
	if (next_protocol == IPPROTO_UDP)
		hdr->pipd_hdr.pi_hdr.pt.type_ctx.pkt_code = PCODE_UDP;
	else if (next_protocol == IPPROTO_TCP)
		hdr->pipd_hdr.pi_hdr.pt.type_ctx.pkt_code = PCODE_TCP;
	else
		hdr->pipd_hdr.pi_hdr.pt.type_ctx.pkt_code = PCODE_IP;
}

void pkt_protocol_parse(struct sk_buff *skb, struct zxdh_net_hdr_tx *hdr, s32 flag)
{
	struct ethhdr *mach = NULL;
	struct iphdr *ipv4h = NULL;
	struct ipv6hdr *ipv6h = NULL;
	struct vlan_hdr *vlanhdr = NULL;
	struct vlan_hdr vh = { 0 };
	u16 l3_protocol = 0;
	unsigned int offset = 0;

	if (flag == 0) {
		if (skb->protocol == htons(ETH_P_IP)) {
			ipv4h = (struct iphdr *)skb_network_header(skb);
			hdr->pipd_hdr.pi_hdr.pt.type_ctx.ip_type = IPV4_TYPE;
			pkt_transport_protocol_parse(ipv4h->protocol, hdr);
		} else if (skb->protocol == htons(ETH_P_IPV6)) {
			ipv6h = (struct ipv6hdr *)skb_network_header(skb);
			hdr->pipd_hdr.pi_hdr.pt.type_ctx.ip_type = IPV6_TYPE;
			pkt_transport_protocol_parse(ipv6h->nexthdr, hdr);
		} else {
			hdr->pipd_hdr.pi_hdr.pt.type_ctx.ip_type = NOT_IP_TYPE;
			hdr->pipd_hdr.pi_hdr.pt.type_ctx.pkt_code = PCODE_NO_IP;
		}
	} else {
		mach = (struct ethhdr *)skb_inner_mac_header(skb);
		if (mach->h_proto == htons(ETH_P_8021Q) || mach->h_proto == htons(ETH_P_8021AD)) {
			offset = skb_inner_network_offset(skb);
			vlanhdr = skb_header_pointer(skb, offset - sizeof(vh), sizeof(vh), &vh);
			if (unlikely(!vlanhdr)) {
				LOG_ERR("zxdh_en_send error: skb_header_pointer failed\n");
				return;
			}
			l3_protocol = vlanhdr->h_vlan_encapsulated_proto;
		}

		if (mach->h_proto == htons(ETH_P_IP) || l3_protocol == htons(ETH_P_IP)) {
			ipv4h = (struct iphdr *)skb_inner_network_header(skb);
			hdr->pipd_hdr.pi_hdr.pt.type_ctx.ip_type = IPV4_TYPE;
			pkt_transport_protocol_parse(ipv4h->protocol, hdr);
		} else if ((mach->h_proto == htons(ETH_P_IPV6)) ||
			   (l3_protocol == htons(ETH_P_IPV6))) {
			ipv6h = (struct ipv6hdr *)skb_inner_network_header(skb);
			hdr->pipd_hdr.pi_hdr.pt.type_ctx.ip_type = IPV6_TYPE;
			pkt_transport_protocol_parse(ipv6h->nexthdr, hdr);
		} else {
			hdr->pipd_hdr.pi_hdr.pt.type_ctx.ip_type = NOT_IP_TYPE;
			hdr->pipd_hdr.pi_hdr.pt.type_ctx.pkt_code = PCODE_NO_IP;
		}
	}
}

s32 vxlan_tso_cksum(struct sk_buff *skb)
{
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} out_ip, in_ip;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		unsigned char *hdr;
	} out_l4;
	unsigned char *out_trans_start = 0;
	unsigned short out_udp_len_temp = 0;
	struct vlan_hdr *vlanhdr = NULL;
	struct vlan_hdr vh = { 0 };
	u16 l3_protocol = skb->protocol;

	if (skb->protocol == htons(ETH_P_8021Q) || skb->protocol == htons(ETH_P_8021AD)) {
		vlanhdr = skb_header_pointer(skb, ETH_HLEN, sizeof(vh), &vh);
		if (!vlanhdr)
			return -1;
		l3_protocol = vlanhdr->h_vlan_encapsulated_proto;
	}

	out_ip.hdr = skb_network_header(skb);
	out_l4.hdr = skb_transport_header(skb);
	if (l3_protocol == htons(ETH_P_IP))
		out_trans_start = (unsigned char *)&out_ip.v4->saddr;
	else if (l3_protocol == htons(ETH_P_IPV6))
		out_trans_start = (unsigned char *)&out_ip.v6->saddr;
	else
		return -1;

	out_l4.udp->check = 0;
	out_udp_len_temp = out_l4.udp->len;
	out_l4.udp->len = 0;
	in_ip.hdr = skb_inner_network_header(skb);
	out_l4.udp->check =
		csum_fold(csum_partial(out_trans_start, in_ip.hdr - out_trans_start, 0));
	out_l4.udp->len = out_udp_len_temp;

	return 0;
}

s32 zxdh_tx_checksum_offload(struct zxdh_en_device *en_dev, struct sk_buff *skb,
			     struct zxdh_net_hdr_tx *hdr)
{
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (skb->encapsulation == 1) {
		hdr->pipd_hdr.pi_hdr.bttl_pi_len = ENABLE_PI_FLAG_32B;
		hdr->pipd_hdr.pd_hdr.ol_flag |= htons(0x1 << OUTER_IP_CHECKSUM_OFFSET);
		hdr->pipd_hdr.pd_hdr.ol_flag |= htons(0x1 << NP_IS_VXLAN_FLAG);
		pkt_protocol_parse(skb, hdr, 1);
		hdr->pipd_hdr.pi_hdr.hdr_l3_offset =
			htons(en_dev->hdr_len + skb_inner_network_offset(skb));
		hdr->pipd_hdr.pi_hdr.hdr_l4_offset =
			htons(en_dev->hdr_len + skb_inner_transport_offset(skb));

		if ((skb_shinfo(skb)->gso_size != 0) && (vxlan_tso_cksum(skb) == 0))
			hdr->pipd_hdr.pd_hdr.ol_flag |= htons(0x1 << NP_VXLAN_UDP_CHCKSUM_ENABLE);
	}

	hdr->pipd_hdr.pi_hdr.pkt_action_flag1 |= htons(0x1 << INNER_IP_CHECKSUM_OFFSET);
	hdr->pipd_hdr.pi_hdr.pkt_action_flag2 |= 0x1 << INNER_L4_CHECKSUM_OFFSET;
	return 0;
}

static int pipd_hdr_validate_vlan(struct zxdh_en_device *en_dev, struct sk_buff *skb,
				  struct zxdh_net_hdr_tx *hdr)
{
	if (skb && skb_vlan_tag_present(skb)) {
		hdr->pipd_hdr.pd_hdr.ctci = htons(skb_vlan_tag_get(skb));
		hdr->pipd_hdr.pd_hdr.ol_flag |= htons(TXCAP_CTAG_INSERT_EN_BIT);
		en_dev->hw_stats.netdev_stats.tx_added_vlan_packets++;
	}
	return 0;
}

static int pd_hdr_validate_vlan(struct zxdh_en_device *en_dev, struct sk_buff *skb,
				struct zxdh_net_hdr_tx *hdr)
{
	if (skb && skb_vlan_tag_present(skb)) {
		hdr->pd_hdr.ctci = htons(skb_vlan_tag_get(skb));
		hdr->pd_hdr.ol_flag |= htons(TXCAP_CTAG_INSERT_EN_BIT);
		en_dev->hw_stats.netdev_stats.tx_added_vlan_packets++;
	}
	return 0;
}

s32 pipd_net_hdr_from_skb(struct zxdh_en_device *en_dev, struct sk_buff *skb,
			  struct zxdh_net_hdr_tx *hdr, bool is_lb)
{
	u32 gso_type = 0;
	u16 mss = 0;

	hdr->tx_port = TX_PORT_DTP;
	hdr->pipd_hdr.pi_hdr.bttl_pi_len = DISABLE_PI_FIELD_PARSE + ENABLE_PI_FLAG_32B;
	hdr->pipd_hdr.pi_hdr.pt.type_ctx.pkt_src = PKT_SRC_CPU;
	hdr->pipd_hdr.pi_hdr.eth_port_id = INVALID_ETH_PORT_ID;

	pipd_hdr_validate_vlan(en_dev, skb, hdr);

	mss = skb_shinfo(skb)->gso_size;
	gso_type = skb_shinfo(skb)->gso_type;
	if (gso_type & SKB_GSO_TCPV4) {
		mss = (mss > 0) ? min(skb_shinfo(skb)->gso_size,
				      (u16)(en_dev->netdev->mtu - IP_BASE_HLEN - TCP_BASE_HLEN)) :
					(u16)(en_dev->netdev->mtu - IP_BASE_HLEN - TCP_BASE_HLEN);
		hdr->pipd_hdr.pi_hdr.pkt_action_flag1 |=
			htons((mss / ETH_MTU_4B_UNIT) + NOT_IP_FRG_CSUM_FLAG);
		hdr->pipd_hdr.pi_hdr.pkt_action_flag2 |= TCP_FRG_CSUM_FLAG;
	} else if (gso_type & SKB_GSO_TCPV6) {
		mss = (mss > 0) ? min(skb_shinfo(skb)->gso_size,
				      (u16)(en_dev->netdev->mtu - IPV6_BASE_HLEN - TCP_BASE_HLEN)) :
					(u16)(en_dev->netdev->mtu - IPV6_BASE_HLEN - TCP_BASE_HLEN);
		hdr->pipd_hdr.pi_hdr.pkt_action_flag1 |=
			htons((mss / ETH_MTU_4B_UNIT) + NOT_IP_FRG_CSUM_FLAG);
		hdr->pipd_hdr.pi_hdr.pkt_action_flag2 |= TCP_FRG_CSUM_FLAG;
	} else if (gso_type &
		   (SKB_GSO_UDP | SKB_GSO_UDP_L4 | SKB_GSO_UDP_TUNNEL | SKB_GSO_UDP_TUNNEL_CSUM)) {
		hdr->pipd_hdr.pi_hdr.pkt_action_flag1 =
			htons((u16)(en_dev->netdev->mtu / ETH_MTU_4B_UNIT) + IP_FRG_CSUM_FLAG);
		hdr->pipd_hdr.pi_hdr.pkt_action_flag2 |= NOT_TCP_FRG_CSUM_FLAG;
	} else {
		hdr->pipd_hdr.pi_hdr.pkt_action_flag1 |=
			htons((en_dev->netdev->mtu / ETH_MTU_4B_UNIT) + NOT_IP_FRG_CSUM_FLAG);
		hdr->pipd_hdr.pi_hdr.pkt_action_flag2 |= NOT_TCP_FRG_CSUM_FLAG;
	}
#ifdef CONFIG_INET

	if (is_lb == IS_LB_PKT)
		hdr->pipd_hdr.pd_hdr.ol_flag |= htons(LB_EN);
#endif

	if (en_dev->netdev->features & NETIF_F_HW_CSUM)
		zxdh_tx_checksum_offload(en_dev, skb, hdr);

	if ((en_dev->ops->is_bond(en_dev->parent) || en_dev->ops->is_special_bond(en_dev->parent) ||
	     en_dev->is_hwbond) &&
	    (skb->protocol == htons(ETH_P_SLOW) || skb->protocol == htons(ETH_P_PAUSE))) {
		hdr->pipd_hdr.pd_hdr.ol_flag |= htons(PANELID_EN);
		hdr->pipd_hdr.pd_hdr.panel_id = en_dev->phy_port;
	}

#ifdef ZXDH_DCBNL_OPEN
	if (skb->sk)
		hdr->pipd_hdr.pd_hdr.ol_flag |= htons(ZXDH_DCBNL_SET_SK_PRIO(skb->sk->sk_priority));
#endif

	return 0;
}

s32 pd_net_hdr_from_skb(struct zxdh_en_device *en_dev, struct sk_buff *skb,
			struct zxdh_net_hdr_tx *hdr, bool is_lb)
{
	hdr->tx_port = TX_PORT_NP;

	pd_hdr_validate_vlan(en_dev, skb, hdr);

#ifdef CONFIG_INET

	if (is_lb == IS_LB_PKT)
		hdr->pd_hdr.ol_flag |= htons(LB_EN);
#endif

	if ((en_dev->ops->is_bond(en_dev->parent) || en_dev->is_hwbond) &&
	    (skb->protocol == htons(ETH_P_SLOW) || skb->protocol == htons(ETH_P_PAUSE))) {
		hdr->pd_hdr.ol_flag |= htons(PANELID_EN);
		hdr->pd_hdr.panel_id = en_dev->phy_port;
	}

#ifdef ZXDH_DCBNL_OPEN
	if (skb->sk)
		hdr->pd_hdr.ol_flag |= htons(ZXDH_DCBNL_SET_SK_PRIO(skb->sk->sk_priority));

#endif

	return 0;
}

s32 net_hdr_from_skb(struct zxdh_en_device *en_dev, struct sk_buff *skb,
		     struct zxdh_net_hdr_tx *hdr, bool is_lb)
{
	memset(hdr, 0, en_dev->hdr_len);
	hdr->pd_len = en_dev->hdr_len / HDR_2B_UNIT;

	if (en_dev->delay_statistics_enable)
		pkt_delay_statistics_proc(skb, hdr, en_dev);

	if (en_dev->dtp_drs_offload == true)
		pipd_net_hdr_from_skb(en_dev, skb, hdr, is_lb);
	else
		pd_net_hdr_from_skb(en_dev, skb, hdr, is_lb);

	return 0;
}

void zxdh_netdev_features_over_dtp(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	en_dev->dtp_drs_offload = false;

	if ((netdev->features & NETIF_F_TSO) || (netdev->features & NETIF_F_TSO6) ||
	    (netdev->features & NETIF_F_HW_CSUM) ||
	    (netdev->features & NETIF_F_GSO_UDP_TUNNEL_CSUM)) {
		en_dev->dtp_drs_offload = true;
	}
	LOG_DEBUG(
		"dtp_drs_offload=%d. TSO:%lld, TSO6:%lld, HWCSUM:%lld, GSO_UDP_TUNNEL_CSUM:%lld\n",
		en_dev->dtp_drs_offload, netdev->features & NETIF_F_TSO,
		netdev->features & NETIF_F_TSO6, netdev->features & NETIF_F_HW_CSUM,
		netdev->features & NETIF_F_GSO_UDP_TUNNEL_CSUM);

	if (en_dev->dtp_drs_offload)
		en_dev->hdr_len = sizeof(struct zxdh_net_hdr_tx);
	else
		en_dev->hdr_len = sizeof(struct zxdh_net_hdr_tx) - sizeof(struct pi_hdr);
}

s32 is_udp_loopback_pkt(u8 *pData)
{
	u16 eth_type_lay3 = ntohs(*((u16 *)(pData + (2 * ETHER_MAC_LEN)))); /* get Eth Type */
	u8 eth_type_lay4 = 0;
	struct zxdh_ehdr *zxdhh = NULL;

	if (eth_type_lay3 != ETH_P_IP)
		return 1;

	eth_type_lay4 = *(pData + (2 * ETHER_MAC_LEN) + ETHER_TYPE_LEN + IP_PROT_OFFSET);
	if (eth_type_lay4 != IPPROTO_UDP)
		return 1;

	zxdhh = (struct zxdh_ehdr *)(pData + (2 * ETHER_MAC_LEN) + ETHER_TYPE_LEN + IPV4_HDR_LEN +
				     UDP_HDR_LEN);
	if (zxdhh->magic != cpu_to_be64(ZXDH_TEST_MAGIC))
		return 1;
	LOG_DEBUG("it is udp lb pkt\n");
	return 0;
}

s32 xmit_skb(struct net_device *netdev, struct send_queue *sq, struct sk_buff *skb)
{
	struct zxdh_net_hdr_tx *hdr = NULL;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 num_sg = 0;
	uint hdr_len = en_dev->hdr_len;
	bool can_push = false;
	u8 *hdr_buf = sq->hdr_buf;
	u8 *pData = NULL;
	u8 *ptpHdr = NULL;
	u8 ts_offset = 0;
	struct zxdh_net_1588_hdr *hdr_1588 = NULL;
	struct zxdh_net_1588_nopi_hdr *hdr_1588_nopi = NULL;
	s32 ret = 0;
	s32 is_1588_flag = IS_NOT_1588_MESSAGE;
	s32 is_lb = IS_NOT_LB_PKT;

	CHECK_EQUAL_ERR(skb, NULL, -EADDRNOTAVAIL, "skb is null\n");
	pData = skb->data;
	CHECK_EQUAL_ERR(pData, NULL, -EADDRNOTAVAIL, "skb->data is null\n");

	/* Determine if it is a 1588 message */
	if (en_dev->enable_1588 == true) {
		is_1588_flag = get_hdr_point(pData, &ts_offset, &ptpHdr);
		if (is_1588_flag == IS_1588_MESSAGE) {
			LOG_DEBUG("pkt_1588_proc_xmit dtp offload %d\n", en_dev->dtp_drs_offload);
			if (en_dev->dtp_drs_offload == true)
				hdr_len = sizeof(struct zxdh_net_1588_hdr);
			else
				hdr_len = sizeof(struct zxdh_net_1588_nopi_hdr);
		}
	}

#ifdef CONFIG_INET
	/* Determine if it is a udp lb test message*/
	if (en_dev->local_lb_enable == true) {
		if (is_udp_loopback_pkt(pData) == IS_LB_PKT)
			is_lb = IS_LB_PKT;
	}
#endif

	can_push = en_dev->any_header_sg && !((unsigned long)skb->data & (__alignof__(*hdr) - 1)) &&
		   !skb_header_cloned(skb) && skb_headroom(skb) >= hdr_len;
	if (can_push) {
		hdr = (struct zxdh_net_hdr_tx *)(skb->data - hdr_len);
	} else {
		hdr_buf += sq->hdr_idx * HDR_BUFFER_LEN;
		memset(hdr_buf, 0, HDR_BUFFER_LEN);
		hdr = (struct zxdh_net_hdr_tx *)(hdr_buf);
		sq->hdr_idx++;
		sq->hdr_idx = sq->hdr_idx % en_dev->eth_config.tx_queue_size;
	}

	if (net_hdr_from_skb(en_dev, skb, hdr, is_lb))
		return -EPROTO;

	if (en_dev->enable_1588 == true) {
		if (is_1588_flag == IS_1588_MESSAGE) {
			if (en_dev->dtp_drs_offload == true) {
				hdr->pd_len = sizeof(struct zxdh_net_1588_hdr) / HDR_2B_UNIT;
				hdr_1588 = (struct zxdh_net_1588_hdr *)hdr;

				memset(&(hdr_1588->pd_1588), 0, sizeof(struct zxdh_1588_pd_tx));

				hdr_1588->pd_1588.ts_offset = ts_offset;
				ret = pkt_1588_proc_xmit(skb, &(hdr_1588->pd_1588),
							 en_dev->clock_no, en_dev, ptpHdr);
				if (ret != 0) {
					DEBUG_1588(
						"dev %s vport 0x%x pkt_1588_proc_xmit ERR, ret: %d\n",
						en_dev->netdev->name, en_dev->vport, ret);
				}
				DEBUG_1588("NET HDR:");
				DEBUG_1588_DATA((u8 *)hdr_1588, sizeof(struct zxdh_net_1588_hdr));
			} else {
				hdr->pd_len = sizeof(struct zxdh_net_1588_nopi_hdr) / HDR_2B_UNIT;
				hdr_1588_nopi = (struct zxdh_net_1588_nopi_hdr *)hdr;
				memset(&(hdr_1588_nopi->pd_1588), 0,
				       sizeof(struct zxdh_1588_pd_tx));
				hdr_1588_nopi->pd_1588.ts_offset = ts_offset;
				ret = pkt_1588_proc_xmit(skb, &hdr_1588_nopi->pd_1588,
							 en_dev->clock_no, en_dev, ptpHdr);
				if (ret != 0) {
					LOG_ERR("dev %s vport 0x%x pkt_1588_proc_xmit, ret:%d\n",
						en_dev->netdev->name, en_dev->vport, ret);
					return ret;
				}
				DEBUG_1588("NET HDR:");
				DEBUG_1588_DATA((u8 *)hdr_1588_nopi,
						sizeof(struct zxdh_net_1588_nopi_hdr));
			}
		}
		DEBUG_1588("skb->data:");
		DEBUG_1588_DATA((u8 *)skb->data, skb->len);
	}

	sg_init_table(sq->sg, skb_shinfo(skb)->nr_frags + (can_push ? 1 : 2));
	if (can_push) {
		__skb_push(skb, hdr_len);
		num_sg = skb_to_sgvec(skb, sq->sg, 0, skb->len);
		if (unlikely(num_sg < 0))
			return num_sg;
		/* Pull header back to avoid skew in tx bytes calculations. */
		__skb_pull(skb, hdr_len);
	} else {
		sg_set_buf(sq->sg, hdr, hdr_len);
		num_sg = skb_to_sgvec(skb, sq->sg + 1, 0, skb->len);
		if (unlikely(num_sg < 0))
			return num_sg;
		num_sg++;
	}

	return zxdh_virtqueue_add_outbuf(sq->vq, sq->sg, num_sg, skb, GFP_ATOMIC);
}

netdev_tx_t zxdh_en_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 qnum = skb_get_queue_mapping(skb);
	struct send_queue *sq = &en_dev->sq[qnum];
	s32 err = 0;
	struct netdev_queue *txq = netdev_get_tx_queue(netdev, qnum);
	bool kick = !netdev_xmit_more();
	bool use_napi = sq->napi.weight;

	/* Free up any pending old buffers before queueing new ones. */
	do {
		if (use_napi)
			zxdh_virtqueue_disable_cb(sq->vq);

		free_old_xmit_skbs(netdev, sq, false);

	} while (use_napi && kick && unlikely(!zxdh_virtqueue_enable_cb_delayed(sq->vq)));

	/* timestamp packet in software */
	skb_tx_timestamp(skb);

	/* Try to transmit */
	err = xmit_skb(netdev, sq, skb);

	/* This should not happen! */
	if (unlikely(err)) {
		netdev->stats.tx_fifo_errors++;
		netdev->stats.tx_errors++;
		if (net_ratelimit())
			LOG_WARN("unexpected TXQ (%d) queue failure: %d\n", qnum, err);

		netdev->stats.tx_dropped++;
		en_dev->hw_stats.q_stats[qnum].q_tx_dropped++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (sq->vq->num_free < 2 + MAX_SKB_FRAGS) {
		netif_stop_subqueue(netdev, qnum);
		en_dev->hw_stats.q_stats[qnum].q_tx_stopped++;
		if (!use_napi && unlikely(!zxdh_virtqueue_enable_cb_delayed(sq->vq))) {
			/* More just got used, free them then recheck. */
			free_old_xmit_skbs(netdev, sq, false);
			if (sq->vq->num_free >= 2 + MAX_SKB_FRAGS) {
				netif_start_subqueue(netdev, qnum);
				zxdh_virtqueue_disable_cb(sq->vq);
			}
		}
	}

	if (kick || netif_xmit_stopped(txq)) {
		if (virtqueue_kick_prepare_packed(sq->vq) && zxdh_virtqueue_notify(sq->vq)) {
			u64_stats_update_begin(&sq->stats.syncp);
			sq->stats.kicks++;
			u64_stats_update_end(&sq->stats.syncp);
		}
	}

	return NETDEV_TX_OK;
}

static inline unsigned int u64_stats_fetch_begin_irq(const struct u64_stats_sync *syncp)
{
	return u64_stats_fetch_begin(syncp);
}

static inline bool u64_stats_fetch_retry_irq(const struct u64_stats_sync *syncp, unsigned int start)
{
	return u64_stats_fetch_retry(syncp, start);
}

#ifdef HAVE_NDO_GET_STATS64
#ifdef HAVE_VOID_NDO_GET_STATS64
static void zxdh_en_get_netdev_stats_struct(struct net_device *netdev,
					    struct rtnl_link_stats64 *stats)
#else
static struct rtnl_link_stats64 *zxdh_en_get_netdev_stats_struct(struct net_device *netdev,
								 struct rtnl_link_stats64 *stats)
#endif
{
#ifdef HAVE_VOID_NDO_GET_STATS64
	struct zxdh_en_device *en_dev = netdev_priv(netdev);
	struct receive_queue *rq = NULL;
	struct send_queue *sq = NULL;
	u32 start = 0;
	u32 i = 0;
	u64 tpackets = 0;
	u64 tbytes = 0;
	u64 rpackets = 0;
	u64 rbytes = 0;
	u64 rdrops = 0;
	u32 loop_cnt = en_dev->max_queue_pairs;
	s32 ret = 0;
	struct zxdh_en_vport_np_stats *np_stats = &en_dev->hw_stats.vport_stats.np_stats;
	u32 vf_id = GET_VFID(en_dev->vport);
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	if (en_dev->device_state != ZXDH_DEVICE_STATE_INTERNAL_ERROR) {
		ret = zxdh_mac_stats_get(en_dev);
		if (ret != 0) {
			LOG_ERR("zxdh_mac_stats_get failed, ret: %d\n", ret);
			return;
		}
	}

	if (en_dev->ops->is_bond(en_dev->parent)) {
		stats->rx_packets = en_dev->hw_stats.phy_stats.rx_packets_phy;
		stats->rx_bytes = en_dev->hw_stats.phy_stats.rx_bytes_phy;
		stats->rx_errors = en_dev->hw_stats.phy_stats.rx_error_phy;
		stats->rx_dropped = en_dev->hw_stats.phy_stats.rx_drop_phy;
		stats->tx_packets = en_dev->hw_stats.phy_stats.tx_packets_phy;
		stats->tx_bytes = en_dev->hw_stats.phy_stats.tx_bytes_phy;
		stats->tx_errors = en_dev->hw_stats.phy_stats.tx_error_phy;
		stats->tx_dropped = en_dev->hw_stats.phy_stats.tx_drop_phy;
		return;
	}

#ifdef ZXDH_MSGQ
	if (NEED_MSGQ(en_dev))
		loop_cnt--;
#endif

	for (i = 0; i < loop_cnt; ++i) {
		sq = &en_dev->sq[i];
		rq = &en_dev->rq[i];

		do {
			start = u64_stats_fetch_begin_irq(&sq->stats.syncp);
			tpackets = sq->stats.packets;
			tbytes = sq->stats.bytes;
		} while (u64_stats_fetch_retry_irq(&sq->stats.syncp, start));

		do {
			start = u64_stats_fetch_begin_irq(&rq->stats.syncp);
			rpackets = rq->stats.packets;
			rbytes = rq->stats.bytes;
			rdrops = rq->stats.drops;
		} while (u64_stats_fetch_retry_irq(&rq->stats.syncp, start));

		stats->rx_packets += rpackets;
		stats->rx_bytes += rbytes;
		stats->rx_dropped += rdrops;
		stats->tx_packets += tpackets;
		stats->tx_bytes += tbytes;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		if (en_dev->device_state != ZXDH_DEVICE_STATE_INTERNAL_ERROR)
			dpp_stat_MTU_packet_msg_rx_cnt_get(&pf_info, vf_id, NP_GET_PKT_CNT,
							   &(np_stats->rx_vport_mtu_drop_bytes),
							   &(np_stats->rx_vport_mtu_drop_packets));
		stats->rx_errors = netdev->stats.rx_errors +
				   en_dev->hw_stats.phy_stats.rx_error_phy +
				   np_stats->rx_vport_mtu_drop_packets;
		stats->tx_errors = netdev->stats.tx_errors + en_dev->hw_stats.phy_stats.tx_drop_phy;
	} else {
		stats->rx_errors = netdev->stats.rx_errors;
		stats->tx_errors = netdev->stats.tx_errors;
	}
	stats->tx_dropped = netdev->stats.tx_dropped;
	stats->tx_carrier_errors = netdev->stats.tx_carrier_errors;
	return;
#else
	return stats;
#endif
}
#endif /* HAVE_VOID_NDO_GET_STATS_64 */

static void zxdh_en_set_rx_mode(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->ops->is_bond(en_dev->parent))
		return;
	if (en_dev->init_comp_flag != AUX_INIT_COMPLETED)
		return;
	queue_work(en_priv->events->wq, &en_dev->rx_mode_set_work);
}

bool is_standard_predefined_ipv6_multicast_mac(const u8 *mac)
{
	return ((mac[0] == 0x33) && (mac[1] == 0x33) && (mac[2] == 0x00));
}

bool zxdh_check_special_addr(const u8 *addr)
{
	if (ether_addr_equal(BOND_MCAST_ADDR, addr) ||
	    is_standard_predefined_ipv6_multicast_mac(addr)) {
		return true;
	}
	return false;
}

static int zxdh_addr_sync(struct net_device *netdev, const u8 *addr, struct mac_queue *add_queue)
{
	if (!zxdh_check_special_addr(addr))
		return 0;

	if (add_queue->count >= DEV_MULTICAST_MAX_NUM) {
		LOG_ERR("mac num is larger max size\n");
		return -1;
	}

	ether_addr_copy(add_queue->addr[add_queue->count], addr);
	add_queue->count++;

	return 0;
}

static int zxdh_addr_unsync(struct net_device *netdev, const u8 *addr, struct mac_queue *del_queue)
{
	if (!zxdh_check_special_addr(addr))
		return 0;

	if (del_queue->count >= DEV_MULTICAST_MAX_NUM) {
		LOG_ERR("mac num is larger max size\n");
		return -1;
	}

	ether_addr_copy(del_queue->addr[del_queue->count], addr);
	del_queue->count++;

	return 0;
}

static int __hw_addr_del_entry(struct netdev_hw_addr_list *list, struct netdev_hw_addr *ha,
			       bool global, bool sync)
{
	if (global && !ha->global_use)
		return -ENOENT;

	if (sync && !ha->synced)
		return -ENOENT;

	if (global)
		ha->global_use = false;

	if (sync)
		ha->synced--;

	if (--ha->refcount)
		return 0;

	rb_erase(&ha->node, &list->tree);
	list_del_rcu(&ha->list);
	kfree_rcu(ha, rcu_head);
	list->count--;
	return 0;
}

static int
zxdh_hw_addr_sync_dev(struct netdev_hw_addr_list *list, struct net_device *dev,
		      int (*sync)(struct net_device *, const unsigned char *, struct mac_queue *),
		      int (*unsync)(struct net_device *, const unsigned char *, struct mac_queue *),
		      struct mac_queue *add_queue, struct mac_queue *del_queue)
{
	struct netdev_hw_addr *ha, *tmp;
	int err;

	list_for_each_entry_safe(ha, tmp, &list->list, list) {
		if (!ha->sync_cnt || ha->refcount != 1)
			continue;

		if (unsync && unsync(dev, ha->addr, del_queue))
			continue;

		if (zxdh_check_special_addr(ha->addr)) {
			ha->sync_cnt--;
			__hw_addr_del_entry(list, ha, false, false);
		}
	}

	list_for_each_entry_safe(ha, tmp, &list->list, list) {
		if (ha->sync_cnt)
			continue;

		err = sync(dev, ha->addr, add_queue);
		if (err)
			return err;

		if (zxdh_check_special_addr(ha->addr)) {
			ha->sync_cnt++;
			ha->refcount++;
		}
	}

	return 0;
}

static int
zxdh_dev_mc_sync(struct net_device *dev,
		 int (*sync)(struct net_device *, const unsigned char *, struct mac_queue *),
		 int (*unsync)(struct net_device *, const unsigned char *, struct mac_queue *),
		 struct mac_queue *add_queue, struct mac_queue *del_queue)
{
	LOG_DEBUG("%s is called", dev->name);
	return zxdh_hw_addr_sync_dev(&dev->mc, dev, sync, unsync, add_queue, del_queue);
}

static int zxdh_handle_mc_operation(struct zxdh_en_device *en_dev, struct dpp_pf_info_t *pf_info,
				    const u8 *addr, bool is_add)
{
	int err = 0;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		if (is_add) {
			err = dpp_multi_mac_add_member(pf_info, addr);
			if (err != 0) {
				LOG_ERR("dpp_multi_mac_add_member failed:0x%x\n", err);
				return err;
			}
		} else {
			err = dpp_multi_mac_del_member(pf_info, addr);
			if (err != 0) {
				LOG_ERR("dpp_multi_mac_del_member failed:0x%x\n", err);
				return err;
			}
		}
	} else {
		if (is_add) {
			err = zxdh_vf_dpp_add_lacp_mac(en_dev, addr);
			if (err != 0) {
				LOG_ERR("zxdh_vf_dpp_add_mac failed:0x%x\n", err);
				return err;
			}
		} else {
			err = zxdh_vf_dpp_del_lacp_mac(en_dev, addr);
			if (err != 0) {
				LOG_ERR("zxdh_vf_dpp_del_mac failed:0x%x\n", err);
				return err;
			}
		}
	}

	return 0;
}

static int zxdh_dev_mc_proc(struct zxdh_en_device *en_dev, struct dpp_pf_info_t *pf_info,
			    struct mac_queue *add_queue, struct mac_queue *del_queue)
{
	s32 err = 0;
	u8 i = 0;

	for (i = 0; i < add_queue->count; i++) {
		err = zxdh_handle_mc_operation(en_dev, pf_info, add_queue->addr[i], true);
		if (err != 0)
			return err;
		en_dev->curr_multicast_num++;
	}

	for (i = 0; i < del_queue->count; i++) {
		err = zxdh_handle_mc_operation(en_dev, pf_info, del_queue->addr[i], false);
		if (err != 0)
			return err;
		en_dev->curr_multicast_num--;
	}

	return 0;
}

s32 zxdh_dev_promisc_sync(struct zxdh_en_device *en_dev)
{
	bool promisc_changed = !!(en_dev->netdev->flags & IFF_PROMISC);
	bool allmulti_changed = !!(en_dev->netdev->flags & IFF_ALLMULTI);
	bool is_pf = en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF;
	struct dpp_pf_info_t pf_info = {
		.slot = en_dev->slot_id,
		.vport = en_dev->vport,
	};

	if ((en_dev->promisc_enabled == promisc_changed) &&
	    (en_dev->allmulti_enabled == allmulti_changed))
		return 0;

	LOG_DEBUG("promisc_changed: %d, allmulti_changed: %d\n", promisc_changed, allmulti_changed);
	en_dev->promisc_enabled = promisc_changed;
	en_dev->allmulti_enabled = allmulti_changed;

	if (!promisc_changed && allmulti_changed) {
		if (is_pf)
			return dpp_vport_mc_promisc_set(&pf_info, 1);
		else
			return zxdh_vf_port_promisc_set(en_dev, ZXDH_ALLMULTI_MODE, 1, 0);
	}

	if (is_pf) {
		dpp_vport_uc_promisc_set(&pf_info, en_dev->promisc_enabled);
		dpp_vport_promisc_en_set(&pf_info, en_dev->promisc_enabled);
		dpp_vport_mc_promisc_set(&pf_info, en_dev->promisc_enabled);
	} else {
		return zxdh_vf_port_promisc_set(en_dev, ZXDH_PROMISC_MODE, promisc_changed, 1);
	}

	return 0;
}

void rx_mode_set_handler(struct work_struct *work)
{
	struct zxdh_en_device *en_dev = container_of(work, struct zxdh_en_device, rx_mode_set_work);
	s32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct mac_queue add_queue = { 0 };
	struct mac_queue del_queue = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	netif_addr_lock_bh(en_dev->netdev);
	zxdh_dev_mc_sync(en_dev->netdev, zxdh_addr_sync, zxdh_addr_unsync, &add_queue, &del_queue);
	netif_addr_unlock_bh(en_dev->netdev);

	err = zxdh_dev_mc_proc(en_dev, &pf_info, &add_queue, &del_queue);
	if (err != 0)
		LOG_ERR("zxdh_dev_mc_proc err:0x%x\n", err);

	err = zxdh_dev_promisc_sync(en_dev);
	if (err != 0)
		LOG_ERR("zxdh_dev_promisc_sync err:0x%x\n", err);
}

void zxdh_netdev_addr_set(struct net_device *dev, const u8 *addr)
{
	struct zxdh_en_priv *en_priv = netdev_priv(dev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	dev_addr_set(dev, addr);
	ether_addr_copy(en_dev->eth_config.dev_addr, dev->dev_addr);
}

static int zxdh_en_set_mac(struct net_device *netdev, void *p)
{
	struct sockaddr *addr = (struct sockaddr *)p;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;
	struct netdev_hw_addr *ha = NULL;
	bool delete_flag = true;
	bool add_flag = true;
	s32 ret = 0;
	u16 sriov_vlan_tpid = 0;
	u16 sriov_vlan_id = 0;
	u16 current_vport = 0;
	u16 vport = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	if (!is_valid_ether_addr(addr->sa_data)) {
		LOG_INFO("invalid mac address %pM\n", addr->sa_data);
		return -EADDRNOTAVAIL;
	}

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;
	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR) {
		LOG_INFO("update %s mac %p in INTERNAL_ERROR\n", netdev->name, addr->sa_data);
		zxdh_netdev_addr_set(netdev, addr->sa_data);
		return -ENXIO;
	}

	if (ether_addr_equal(netdev->dev_addr, addr->sa_data)) {
		if ((!en_dev->ops->is_bond(en_dev->parent)) &&
		    (!ether_addr_equal(en_dev->last_np_mac_addr.sa_data, netdev->dev_addr))) {
			zxdh_netdev_addr_set(netdev, en_dev->last_np_mac_addr.sa_data);
			goto continue_run;
		}
		LOG_INFO("already using mac address %pM\n", addr->sa_data);
		return 0;
	}
continue_run:
	list_for_each_entry(ha, &netdev->uc.list, list) {
		if (!memcmp(ha->addr, netdev->dev_addr, netdev->addr_len))
			delete_flag = false;

		if (!memcmp(ha->addr, addr->sa_data, netdev->addr_len))
			add_flag = false;
	}

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->ops->is_bond(en_dev->parent)) {
		zxdh_netdev_addr_set(netdev, addr->sa_data);
		return 0;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		vport = pf_info.vport;
		ret = dpp_unicast_mac_search(&pf_info, addr->sa_data, sriov_vlan_tpid,
					     sriov_vlan_id, &current_vport);
		if (!ret && vport == current_vport) {
			return 0;
		} else if (!ret && vport != current_vport) {
			LOG_ERR("Mac already exists\n");
			return -EEXIST;
		} else if (ret && ret != DPP_HASH_RC_SRH_FAIL) {
			LOG_ERR("dpp_unicast_mac_search failed, ret:%d\n", ret);
			return -1;
		}

		if (delete_flag) {
			ret = dpp_del_mac(&pf_info, netdev->dev_addr, sriov_vlan_tpid,
					  sriov_vlan_id);
			if (ret != 0) {
				LOG_ERR("pf del mac failed, retval: %d\n", ret);
				return -1;
			}
		}

		if (add_flag) {
			ret = dpp_add_mac(&pf_info, addr->sa_data, sriov_vlan_tpid, sriov_vlan_id);
			if (ret != 0) {
				LOG_ERR("pf add mac failed: %d\n", ret);
				return -1;
			}
		}

		LOG_DEBUG("set pf new mac address %pM\n", addr->sa_data);
		zxdh_netdev_addr_set(netdev, addr->sa_data);
	} else {
		ret = zxdh_vf_dpp_dump_mac(en_dev, addr->sa_data);
		if (ret != 0) {
			LOG_ERR("Mac already exists");
			return -EEXIST;
		}

		ret = zxdh_vf_dpp_del_mac(en_dev, netdev->dev_addr, UNFILTER_MAC, delete_flag);
		if (ret != 0) {
			LOG_ERR("zxdh vf dpp del mac failed: %d\n", ret);
			return -1;
		}

		if (add_flag) {
			ret = zxdh_vf_dpp_add_mac(en_dev, addr->sa_data, UNFILTER_MAC);
			if (ret != 0) {
				LOG_ERR("zxdh vf dpp add mac failed: %d\n", ret);
				return -1;
			}
			en_dev->ops->set_mac(en_dev->parent, addr->sa_data);
		}

		LOG_DEBUG("set vf new mac address %pM\n", addr->sa_data);
		zxdh_netdev_addr_set(netdev, addr->sa_data);
	}
	ether_addr_copy(en_dev->last_np_mac_addr.sa_data, en_dev->netdev->dev_addr);
	LOG_DEBUG("update last_np_mac_addr %pM\n", en_dev->last_np_mac_addr.sa_data);
	return ret;
}

s32 zxdh_en_config_mtu_to_np(struct net_device *netdev, s32 mtu_value)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (!zxdh_en_is_panel_port(en_dev))
		return ret;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		dpp_uplink_phy_attr_set(&pf_info, en_dev->phy_port,
					UPLINK_PHY_PORT_MTU_OFFLOAD_ENABLE, 1);
		dpp_uplink_phy_attr_set(&pf_info, en_dev->phy_port, UPLINK_PHY_PORT_MTU, mtu_value);
		ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_MTU_OFFLOAD_EN_OFF, 1);
		if (ret != 0) {
			LOG_ERR("zxdh_pf_egr_port_attr_set config mtu enable failed: %d\n", ret);
			return ret;
		}
		ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_MTU, mtu_value);
		if (ret != 0) {
			LOG_ERR("zxdh_pf_egr_port_attr_set config mtu value failed: %d\n", ret);
			return ret;
		}
	} else {
		ret = zxdh_vf_egr_port_attr_set(en_dev, SRIOV_VPORT_MTU_OFFLOAD_EN_OFF, 1, 0);
		if (ret != 0) {
			LOG_ERR("zxdh_vf_egr_port_attr_set config mtu enable failed: %d\n", ret);
			return ret;
		}
		ret = zxdh_vf_egr_port_attr_set(en_dev, SRIOV_VPORT_MTU, mtu_value, 0);
		if (ret != 0) {
			LOG_ERR("zxdh_vf_egr_port_attr_set config mut value failed: %d\n", ret);
			return ret;
		}
	}

	return 0;
}

static int zxdh_en_change_mtu(struct net_device *netdev, int new_mtu)
{
	s32 ret = 0;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	if ((new_mtu < ETH_MIN_MTU) || (new_mtu > ZXDH_MAX_MTU)) {
		LOG_ERR("changing MTU over %d-%d\n", ETH_MIN_MTU, ZXDH_MAX_MTU);
		return -EINVAL;
	}
	LOG_DEBUG("changing MTU from %d to %d\n", netdev->mtu, new_mtu);

	netdev->mtu = new_mtu;

	ret = zxdh_en_config_mtu_to_np(netdev, new_mtu);
	if (ret != 0) {
		LOG_ERR("zxdh_en_config_mtu_to_np failed: %d\n", ret);
		return -1;
	}

	return 0;
}

#ifdef HAVE_TX_TIMEOUT_TXQUEUE
static void zxdh_en_tx_timeout(struct net_device *netdev, unsigned int txqueue)
{
}
#else
static void zxdh_en_tx_timeout(struct net_device *netdev)
{
}
#endif

#ifdef HAVE_VLAN_RX_REGISTER
static void zxdh_en_vlan_rx_register(struct net_device *netdev, struct vlan_group *grp)
{
}
#endif

static int __maybe_unused vf_vlan_rx_add_vid(struct net_device *netdev, u16 vid)
{
	int ret = 0;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_VLAN_FILTER_ADD;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.rx_vid_add_msg.vlan_id = vid;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0 || msg->reps.flag != ZXDH_REPS_SUCC) {
		LOG_ERR("pcieid:0x%x send msg to pf add vlan:%d failed! ret = %d, flag = 0x%x\n",
			en_dev->pcie_id, vid, ret, msg->reps.flag);
		kfree(msg);
		return -1;
	}
	kfree(msg);
	return 0;
}

int vlan_set_bit(u16 vlan_id, void *bit_map)
{
	u8 *bitmap = 0;
	u16 byte_index = 0;
	u8 bit_index = 0;

	LOG_DEBUG("lan_set_bit, id:%d.\n", vlan_id);
	if (!bit_map)
		return -1;
	if (vlan_id >= VLAN_BITMAP_LENGTH)
		return -2;

	bitmap = (u8 *)bit_map;
	byte_index = vlan_id / BIT_NUM_PER_BYTE;
	bit_index = vlan_id % BIT_NUM_PER_BYTE;

	bitmap[byte_index] |= (1 << bit_index);

	return 0;
}

int vlan_reset_bit(u16 vlan_id, void *bit_map)
{
	u8 *bitmap = 0;
	u16 byte_index = 0;
	u8 bit_index = 0;

	LOG_DEBUG("lan_reset_bit, id:%d.\n", vlan_id);

	if (!bit_map)
		return -1;
	if (vlan_id >= VLAN_BITMAP_LENGTH)
		return -2;

	bitmap = (u8 *)bit_map;
	byte_index = vlan_id / BIT_NUM_PER_BYTE;
	bit_index = vlan_id % BIT_NUM_PER_BYTE;

	bitmap[byte_index] &= ~(1 << bit_index);

	return 0;
}

#if defined(HAVE_INT_NDO_VLAN_RX_ADD_VID) && defined(NETIF_F_HW_VLAN_CTAG_RX)
static int zxdh_en_vlan_rx_add_vid(struct net_device *netdev, __always_unused __be16 proto, u16 vid)
{
	int retval = 0;
	struct zxdh_en_priv *zxdev = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &zxdev->edev;
	struct dpp_pf_info_t pf_info = { 0 };

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (vid > MAX_VLAN_ID) {
		LOG_ERR("vlan id:%d input is err!\n", vid);
		return -EINVAL;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) {
		retval = vf_vlan_rx_add_vid(netdev, vid);
		goto exit;
	}

	retval = dpp_add_vlan_filter(&pf_info, vid);
	if (retval) {
		LOG_ERR("failed to add vlan: %d\n", vid);
		goto exit;
	}
	LOG_INFO("pf add vlan %d succeed, retval %d.\n", vid, retval);

exit:
	if (!retval)
		retval = vlan_set_bit(vid, en_dev->eth_config.vlan_trunk_bitmap);

	return retval;
}
#elif defined(HAVE_INT_NDO_VLAN_RX_ADD_VID) && !defined(NETIF_F_HW_VLAN_CTAG_RX)
static int zxdh_en_vlan_rx_add_vid(struct net_device *netdev, u16 vid)
{
	return 0;
}
#else
static void zxdh_en_vlan_rx_add_vid(struct net_device *netdev, u16 vid)
{
}
#endif

static int vf_vlan_rx_del_vid(struct net_device *netdev, u16 vid)
{
	int ret = 0;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	msg->payload.hdr.op_code = ZXDH_VLAN_FILTER_DEL;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.rx_vid_del_msg.vlan_id = vid;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0 || msg->reps.flag != ZXDH_REPS_SUCC) {
		LOG_ERR("pcieid:0x%x send msg to pf del vlan:%d failed! ret = %d, flag = 0x%x\n",
			en_dev->pcie_id, vid, ret, msg->reps.flag);
		kfree(msg);
		return -1;
	}
	kfree(msg);
	return 0;
}

#if defined(HAVE_INT_NDO_VLAN_RX_ADD_VID) && defined(NETIF_F_HW_VLAN_CTAG_RX)
static int zxdh_en_vlan_rx_kill_vid(struct net_device *netdev, __always_unused __be16 proto,
				    u16 vid)
{
	int retval = 0;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dpp_pf_info_t pf_info = { 0 };

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (vid > MAX_VLAN_ID) {
		LOG_ERR("vlan id:%d input is err!\n", vid);
		return -EINVAL;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) { /* VF */
		retval = vf_vlan_rx_del_vid(netdev, vid);
		goto exit;
	}

	retval = dpp_del_vlan_filter(&pf_info, vid);
	if (retval) {
		LOG_ERR("failed to del vlan: %d\n", vid);
		goto exit;
	}
	LOG_INFO("pf del vlan %d succeed.\n", vid);

exit:
	if (!retval)
		retval = vlan_reset_bit(vid, en_dev->eth_config.vlan_trunk_bitmap);

	return retval;
}
#elif defined(HAVE_INT_NDO_VLAN_RX_ADD_VID) && !defined(NETIF_F_HW_VLAN_CTAG_RX)
static int zxdh_en_vlan_rx_kill_vid(struct net_device *netdev, u16 vid)
{
	return 0;
}
#else
static void zxdh_en_vlan_rx_kill_vid(struct net_device *netdev, u16 vid)
{
}
#endif

static int zxdh_en_xdp_set(struct net_device *dev, struct bpf_prog *prog,
			   struct netlink_ext_ack *extack)
{
	unsigned long max_sz = PAGE_SIZE - sizeof(struct padded_zxdh_net_hdr);
	struct zxdh_en_priv *en_priv = netdev_priv(dev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct bpf_prog *old_prog = NULL;
	u16 xdp_qp = 0;
	u16 curr_qp = 0;
	int i = 0;

	if ((dev->features & NETIF_F_GRO_HW) || (dev->features & NETIF_F_HW_CSUM)) {
		LOG_ERR("Can't set XDP, disable GRO_HW/CSUM first\n");
		return -EOPNOTSUPP;
	}

	if (en_dev->mergeable_rx_bufs && !en_dev->any_header_sg) {
		LOG_ERR("XDP expects header/data in single page\n");
		return -EINVAL;
	}

	if (dev->mtu > max_sz) {
		LOG_ERR("MTU too large to enable XDP\n");
		netdev_warn(dev, "XDP requires MTU less than %lu\n", max_sz);
		return -EINVAL;
	}

	curr_qp = en_dev->curr_queue_pairs - en_dev->xdp_queue_pairs;
	if (prog)
		xdp_qp = 0; //nr_cpu_ids

	/* XDP requires extra queues for XDP_TX */
	if (curr_qp + xdp_qp > en_dev->max_vq_pairs) {
		netdev_warn_once(
			dev,
			"XDP request %i but max is %i.XDP_TX and XDP_REDIRECT operate in locked tx.\n",
			curr_qp + xdp_qp, en_dev->max_vq_pairs);
		xdp_qp = 0;
	}

	old_prog = rtnl_dereference(en_dev->rq[0].xdp_prog);
	if (!prog && !old_prog)
		return 0;

	if (prog)
		bpf_prog_add(prog, en_dev->max_vq_pairs - 1);

	/* Make sure NAPI is not using any XDP TX queues for RX. */
	if (netif_running(dev)) {
		for (i = 0; i < en_dev->max_vq_pairs; i++) {
			napi_disable(&en_dev->rq[i].napi);
			virtnet_napi_tx_disable(&en_dev->sq[i].napi);
		}
	}

	en_dev->xdp_enabled = !!prog;
	for (i = 0; i < en_dev->max_vq_pairs; i++)
		rcu_assign_pointer(en_dev->rq[i].xdp_prog, prog);

	for (i = 0; i < en_dev->max_vq_pairs; i++) {
		if (old_prog)
			bpf_prog_put(old_prog);
		if (netif_running(dev)) {
			virtnet_napi_enable(en_dev->rq[i].vq, &en_dev->rq[i].napi);
			virtnet_napi_tx_enable(dev, en_dev->sq[i].vq, &en_dev->sq[i].napi);
		}
	}

	return 0;
}

int zxdh_en_xdp(struct net_device *dev, struct netdev_bpf *xdp)
{
	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return zxdh_en_xdp_set(dev, xdp->prog, xdp->extack);
	default:
		return -EINVAL;
	}
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void zxdh_en_netpoll(struct net_device *netdev)
{
}
#endif

#ifdef HAVE_SETUP_TC
int zxdh_en_setup_tc(struct net_device *netdev, u8 tc)
{
	return 0;
}

#ifdef NETIF_F_HW_TC
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
static int __zxdh_en_setup_tc(struct net_device *netdev, enum tc_setup_type type, void *type_data)
#elif defined(HAVE_NDO_SETUP_TC_CHAIN_INDEX)
static int __zxdh_en_setup_tc(struct net_device *netdev, u32 handle, u32 chain_index, __be16 proto,
			      struct tc_to_netdev *tc)
#else
static int __zxdh_en_setup_tc(struct net_device *netdev, u32 handle, __be16 proto,
			      struct tc_to_netdev *tc)
#endif
{
	return 0;
}
#endif
#endif

static s32 zxdh_dtp_offload_set(struct zxdh_en_device *en_dev, struct dpp_pf_info_t *pf_info)
{
	struct zxdh_sriov_vport_t port_attr_entry = { 0 };
	s32 ret = 0;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		ret = dpp_vport_attr_get(pf_info, &port_attr_entry);
		if (ret != 0) {
			LOG_ERR("dpp_vport_attr_get failed: %d\n", ret);
			return ret;
		}

		if (!port_attr_entry.lro_offload && !port_attr_entry.ip_recombine_offload &&
		    !port_attr_entry.ip_checksum_offload &&
		    !port_attr_entry.tcp_udp_checksum_offload)
			ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_ACCELERATOR_OFFLOAD_FLAG, 0);
		else
			ret = dpp_vport_attr_set(pf_info, SRIOV_VPORT_ACCELERATOR_OFFLOAD_FLAG, 1);

		return ret;
	}

	ret = zxdh_vf_egr_port_attr_get(en_dev, &port_attr_entry);
	if (ret != 0) {
		LOG_ERR("dpp_vport_attr_get failed: %d\n", ret);
		return ret;
	}

	if (!port_attr_entry.lro_offload && !port_attr_entry.ip_recombine_offload &&
	    !port_attr_entry.ip_checksum_offload && !port_attr_entry.tcp_udp_checksum_offload)
		ret = zxdh_vf_egr_port_attr_set(en_dev, SRIOV_VPORT_ACCELERATOR_OFFLOAD_FLAG, 0, 0);
	else
		ret = zxdh_vf_egr_port_attr_set(en_dev, SRIOV_VPORT_ACCELERATOR_OFFLOAD_FLAG, 1, 0);

	return ret;
}

static s32 set_feature_rx_checksum(struct zxdh_en_device *en_dev, bool enable)
{
	int en_value = enable ? 1 : 0;
	struct dpp_pf_info_t pf_info = { 0 };
	s32 ret = 0;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_IP_CHKSUM, enable);
		if (ret != 0) {
			LOG_ERR("SRIOV_VPORT_IP_CHKSUM set failed: %d\n", ret);
			return ret;
		}
		ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_TCP_UDP_CHKSUM, enable);
		if (ret != 0) {
			LOG_ERR("SRIOV_VPORT_TCP_UDP_CHKSUM set failed: %d\n", ret);
			return ret;
		}
	} else if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) {
		ret = zxdh_vf_egr_port_attr_set(en_dev, SRIOV_VPORT_IP_CHKSUM, en_value, 0);
		if (ret != 0) {
			LOG_ERR("SRIOV_VPORT_IP_CHKSUM set failed: %d\n", ret);
			return ret;
		}
		ret = zxdh_vf_egr_port_attr_set(en_dev, SRIOV_VPORT_TCP_UDP_CHKSUM, en_value, 0);
		if (ret != 0) {
			LOG_ERR("SRIOV_VPORT_TCP_UDP_CHKSUM set failed: %d\n", ret);
			return ret;
		}
	}

	return zxdh_dtp_offload_set(en_dev, &pf_info);
}

static int set_feature_tx_checksum(struct zxdh_en_device *en_dev, bool enable)
{
	return 0;
}

static int set_feature_tso(struct zxdh_en_device *en_dev, bool enable)
{
	return 0;
}

static int set_feature_tso6(struct zxdh_en_device *en_dev, bool enable)
{
	return 0;
}

static int set_feature_vxlan_checksum(struct zxdh_en_device *en_dev, bool enable)
{
	int ret = 0;
	int en_value = enable ? 1 : 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_OUTER_IP_CHECKSUM_OFFLOAD, enable);
		if (ret != 0) {
			LOG_ERR("zxdh set vxlan rx checksum failed!\n");
			return ret;
		}
	} else if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) {
		ret = zxdh_vf_egr_port_attr_set(en_dev, SRIOV_VPORT_OUTER_IP_CHECKSUM_OFFLOAD,
						en_value, 0);
		if (ret != 0) {
			LOG_ERR("zxdh_vf_egr_port_attr_set vxlan rx checksum failed!\n");
			return ret;
		}
	}

	return ret;
}

s32 set_feature_rxhash(struct zxdh_en_device *en_dev, bool enable)
{
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF)
		return dpp_vport_rss_en_set(&pf_info, enable);

	return zxdh_vf_rss_en_set(en_dev, enable);
}

s32 set_feature_ntuple(struct zxdh_en_device *en_dev, bool enable)
{
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF)
		return dpp_vport_fd_en_set(&pf_info, enable);

	return zxdh_vf_fd_en_set(en_dev, enable);
}

static s32 set_vf_cvlan_filter(struct zxdh_en_device *en_dev, bool enable)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}
	msg->payload.hdr.op_code = ZXDH_VLAN_FILTER_SET;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.vlan_filter_set_msg.enable = enable;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0 || msg->reps.flag != ZXDH_REPS_SUCC) {
		LOG_ERR("pcieid:0x%x msg to pf set vlan :%s failed! ret %d, flag 0x%x\n",
			en_dev->pcie_id, enable ? "enable" : "disable", ret, msg->reps.flag);
	}

	kfree(msg);
	return ret;
}

int zxdh_pf_switch_business_vlan(struct dpp_pf_info_t *pf_info, u8 type, u32 wanted_feature)
{
	int ret = 0;
	struct zxdh_vqm_vfid_vlan_t vf_vlan_attr = { 0 };
	bool old_vport_bit = 0;
	bool wanted_vport_bit = 0;
	u32 *changed_vlan_attr = NULL;

	if (type >= sizeof(vf_vlan_attr) / sizeof(vf_vlan_attr.rsv)) {
		LOG_ERR("%s para type err: %u.\n", __func__, type);
		return -1;
	}
	changed_vlan_attr = (u32 *)&vf_vlan_attr + type;

	ret = dpp_vqm_vfid_vlan_get(pf_info, &vf_vlan_attr);
	if (ret != 0) {
		LOG_ERR("dpp_vqm_vfid_vlan_get failed: %d.\n", ret);
		return -1;
	}

	old_vport_bit = vf_vlan_attr.sriov_business_qinq_vlan_strip_offload |
			vf_vlan_attr.sriov_business_vlan_filter |
			vf_vlan_attr.sriov_business_vlan_strip_offload;

	*changed_vlan_attr = wanted_feature;

	wanted_vport_bit = vf_vlan_attr.sriov_business_qinq_vlan_strip_offload |
			   vf_vlan_attr.sriov_business_vlan_filter |
			   vf_vlan_attr.sriov_business_vlan_strip_offload;

	ret = dpp_vqm_vfid_vlan_set(pf_info, type, wanted_feature);
	if (ret != 0) {
		LOG_ERR("dpp_vqm_vfid_vlan_set, ret: %d\n", ret);
		return -1;
	}

	if (!(old_vport_bit ^ wanted_vport_bit))
		return 0;

	ret = dpp_vport_business_vlan_offload_en_set(pf_info, wanted_vport_bit);
	if (ret != 0) {
		LOG_ERR("dpp_vport_business_vlan_offload_en_set, ret: %d\n", ret);
		return -1;
	}
	return 0;
}

static int set_feature_cvlan_filter(struct zxdh_en_device *en_dev, bool enable)
{
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF)
		return set_vf_cvlan_filter(en_dev, enable);

	return zxdh_pf_switch_business_vlan(&pf_info, VLAN_SRIOV_BUSINESS_VLAN_FILTER, enable);
}

static int __maybe_unused set_feature_svlan_filter(struct zxdh_en_device *en_dev, bool enable)
{
	int ret = 0;

	return ret;
}

int set_vf_qinq_tpid(struct zxdh_en_device *en_dev, u16 tpid)
{
	union zxdh_msg *msg = NULL;
	int ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -1;
	}

	msg->payload.hdr.op_code = ZXDH_SET_TPID;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.tpid_cfg_msg.tpid = tpid;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0 || msg->reps.flag != ZXDH_REPS_SUCC) {
		LOG_ERR("pcieid:0x%x send msg to vfs set tpid: 0x%x failed! ret = %d.\n",
			en_dev->pcie_id, tpid, ret);
		kfree(msg);
		return -EINVAL;
	}

	kfree(msg);
	return 0;
}

static int set_vf_vlan_strip(struct zxdh_en_device *en_dev, bool enable, u8 flag)
{
	union zxdh_msg *msg = NULL;
	int ret = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}
	msg->payload.hdr.op_code = ZXDH_VLAN_OFFLOAD_SET;
	msg->payload.hdr.vport = en_dev->vport;
	msg->payload.hdr.pcie_id = en_dev->pcie_id;
	msg->payload.vlan_strip_msg.enable = enable;
	msg->payload.vlan_strip_msg.flag = flag;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (ret != 0 || msg->reps.flag != ZXDH_REPS_SUCC) {
		LOG_ERR("pcieid:0x%x send msg to vfs set vlan:%s failed! ret %d, flag 0x%x\n",
			en_dev->pcie_id, enable ? "enable" : "disable", ret, msg->reps.flag);
		ret = -EINVAL;
	}

	kfree(msg);
	return ret;
}

static int set_feature_vlan_strip(struct zxdh_en_device *en_dev, bool enable)
{
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		return zxdh_pf_switch_business_vlan(&pf_info,
						    VLAN_SRIOV_BUSINESS_VLAN_STRIP_OFFLIAD, enable);
	}

	return set_vf_vlan_strip(en_dev, enable, VLAN_STRIP_MSG_TYPE);
}

static int set_feature_qinq_strip(struct zxdh_en_device *en_dev, bool enable)
{
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		return zxdh_pf_switch_business_vlan(
			&pf_info, VLAN_SRIOV_BUSINESS_QINQ_VLAN_STRIP_OFFLOAD, enable);
	}

	return set_vf_vlan_strip(en_dev, enable, QINQ_STRIP_MSG_TYPE);
}

static s32 set_feature_lro(struct zxdh_en_device *en_dev, bool enable)
{
	u32 en_value = enable ? 1 : 0;
	struct dpp_pf_info_t pf_info = { 0 };
	s32 ret = 0;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_IPV4_TCP_ASSEMBLE, en_value);
		if (ret != 0) {
			LOG_ERR("SRIOV_VPORT_IPV4_TCP_ASSEMBLE set failed: %d\n", ret);
			return ret;
		}
		ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_IPV6_TCP_ASSEMBLE, en_value);
		if (ret != 0) {
			LOG_ERR("SRIOV_VPORT_IPV6_TCP_ASSEMBLE set failed: %d\n", ret);
			return ret;
		}
	} else {
		ret = zxdh_vf_egr_port_attr_set(en_dev, SRIOV_VPORT_IPV4_TCP_ASSEMBLE, en_value, 0);
		if (ret != 0) {
			LOG_ERR("SRIOV_VPORT_IPV4_TCP_ASSEMBLE set failed: %d\n", ret);
			return ret;
		}
		ret = zxdh_vf_egr_port_attr_set(en_dev, SRIOV_VPORT_IPV6_TCP_ASSEMBLE, en_value, 0);
		if (ret != 0) {
			LOG_ERR("SRIOV_VPORT_IPV6_TCP_ASSEMBLE set failed: %d\n", ret);
			return ret;
		}
	}

	return zxdh_dtp_offload_set(en_dev, &pf_info);
}

static const struct {
	netdev_features_t feature;
	zxdh_feature_handler handler;
} feature_handlers[] = {
	{ NETIF_F_RXCSUM, set_feature_rx_checksum },
	{ NETIF_F_HW_CSUM, set_feature_tx_checksum },
	{ NETIF_F_TSO, set_feature_tso },
	{ NETIF_F_TSO6, set_feature_tso6 },
	{ NETIF_F_GSO_UDP_TUNNEL_CSUM, set_feature_vxlan_checksum },
	{ NETIF_F_RXHASH, set_feature_rxhash },
	{ NETIF_F_LRO, set_feature_lro },
	{ NETIF_F_NTUPLE, set_feature_ntuple },
	{ NETIF_F_HW_VLAN_CTAG_RX, set_feature_vlan_strip },
	{ NETIF_F_HW_VLAN_STAG_RX, set_feature_qinq_strip },
	{ NETIF_F_HW_VLAN_CTAG_FILTER, set_feature_cvlan_filter },
};

s32 zxdh_en_sync_features(struct zxdh_en_device *en_dev, netdev_features_t want_features)
{
	s32 err = 0;
	s32 i = 0;
	netdev_features_t feature;
	bool enable;

	for (i = 0; i < ARRAY_SIZE(feature_handlers); i++) {
		feature = feature_handlers[i].feature;
		enable = !!(want_features & feature);

		if (feature_handlers[i].handler)
			err = feature_handlers[i].handler(en_dev, enable);
		if (err) {
			LOG_ERR("%s feature %pNF (%#llx) failed %d\n",
				enable ? "Enable" : "Disable", &feature, feature, err);
			break;
		}
	}

	zxdh_netdev_features_over_dtp(en_dev->netdev);
	return err;
}

s32 zxdh_en_set_features(struct net_device *netdev, netdev_features_t wanted_features)
{
	const netdev_features_t changes = wanted_features ^ netdev->features;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 err = 0;
	s32 ret = 0;
	s32 i = 0;
	netdev_features_t feature;
	bool enable;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	if (en_dev->xdp_enabled) {
		LOG_ERR("XDP is enabled, can't change features\n");
		return -EBUSY;
	}

	for (i = 0; i < ARRAY_SIZE(feature_handlers); i++) {
		feature = feature_handlers[i].feature;

		if (!(changes & feature))
			continue;

		enable = !!(wanted_features & feature);

		if (feature_handlers[i].handler) {
			LOG_DEBUG("%s feature %pNF (%#llx), err %d\n",
				  enable ? "Enable" : "Disable", &feature, feature, err);
			err = feature_handlers[i].handler(en_dev, enable);
		}
		if (err) {
			ret |= err;
			continue;
		}
		netdev->features = enable ? (netdev->features | feature) :
						  (netdev->features & ~feature);
	}

	zxdh_netdev_features_over_dtp(netdev);
	return ret;
}

static u32 list_hw_addr_create(struct netdev_hw_addr_list *list, const u8 *addr, s32 addr_len,
			       u8 addr_type, bool global, bool sync, struct rb_node *parent,
			       struct rb_node **ins_point)
{
	struct netdev_hw_addr *ha = NULL;

	ha = kzalloc(sizeof(struct netdev_hw_addr), GFP_KERNEL);
	if (!ha) {
		LOG_ERR("Kzalloc struct netdev_hw_addr failed\n");
		return 1;
	}

	memcpy(ha->addr, addr, addr_len);
	ha->type = addr_type;
	ha->refcount = 1;
	ha->global_use = global;
	ha->synced = sync ? 1 : 0;
	ha->sync_cnt = 0;

	rb_link_node(&ha->node, parent, ins_point);
	rb_insert_color(&ha->node, &list->tree);
	list_add_tail_rcu(&ha->list, &list->list);
	list->count++;

	return 0;
}

static u32 list_hw_addr_del(struct netdev_hw_addr_list *list, struct netdev_hw_addr *ha)
{
	s32 refcount = ha->refcount;

	if (--refcount)
		return 1;

	rb_erase(&ha->node, &list->tree);

	list_del_rcu(&ha->list);

	kfree_rcu(ha, rcu_head);
	list->count--;

	return 0;
}

bool is_this_mac_exist(struct net_device *netdev, const u8 *addr, struct netdev_hw_addr **ha,
		       struct rb_node ***ins_point, struct rb_node **parent)
{
	bool isexist = false;
	struct netdev_hw_addr *entry = NULL;
	unsigned char addr_type;
	int diff;

	if (is_unicast_ether_addr(addr)) {
		addr_type = NETDEV_HW_ADDR_T_UNICAST;
		*ins_point = &netdev->uc.tree.rb_node;
	} else {
		addr_type = NETDEV_HW_ADDR_T_MULTICAST;
		*ins_point = &netdev->mc.tree.rb_node;
	}

	netif_addr_lock_bh(netdev);

	while (**ins_point) {
		entry = rb_entry(**ins_point, struct netdev_hw_addr, node);
		diff = memcmp(addr, entry->addr, netdev->addr_len);
		if (!diff)
			diff = memcmp(&addr_type, &entry->type, sizeof(addr_type));

		*parent = **ins_point;
		if (diff < 0) {
			*ins_point = &((*parent)->rb_left);
		} else if (diff > 0) {
			*ins_point = &((*parent)->rb_right);
		} else {
			isexist = true;
			*ha = entry;
			goto out;
		}
	}

out:
	if (!isexist)
		*ha = NULL;

	netif_addr_unlock_bh(netdev);

	return isexist;
}

s32 zxdh_dev_list_addr_add(struct net_device *netdev, const u8 *addr, struct rb_node *parent,
			   struct rb_node **ins_point)
{
	s32 err = 0;

	netif_addr_lock_bh(netdev);

	if (is_unicast_ether_addr(addr) || is_link_local_ether_addr(addr)) {
		err = list_hw_addr_create(&netdev->uc, addr, netdev->addr_len,
					  NETDEV_HW_ADDR_T_UNICAST, false, false, parent,
					  ins_point);
		if (err != 0)
			LOG_ERR("list_hw_addr_create failed\n");
	} else {
		err = list_hw_addr_create(&netdev->mc, addr, netdev->addr_len,
					  NETDEV_HW_ADDR_T_MULTICAST, false, false, parent,
					  ins_point);
		if (err != 0)
			LOG_ERR("list_hw_addr_create failed\n");
	}

	netif_addr_unlock_bh(netdev);

	return err;
}

s32 zxdh_dev_list_addr_del(struct net_device *netdev, const u8 *addr)
{
	struct netdev_hw_addr *ha = NULL;
	s32 err = 0;

	netif_addr_lock_bh(netdev);

	if (is_unicast_ether_addr(addr) || is_link_local_ether_addr(addr)) {
		list_for_each_entry(ha, &netdev->uc.list, list) {
			if ((!memcmp(ha->addr, addr, netdev->addr_len)) &&
			    (ha->type == NETDEV_HW_ADDR_T_UNICAST)) {
				err = list_hw_addr_del(&netdev->uc, ha);
				if (err != 0)
					LOG_ERR("list_hw_addr_del failed\n");
				goto out;
			}
		}
	} else {
		list_for_each_entry(ha, &netdev->mc.list, list) {
			if ((!memcmp(ha->addr, addr, netdev->addr_len)) &&
			    (ha->type == NETDEV_HW_ADDR_T_MULTICAST)) {
				err = list_hw_addr_del(&netdev->mc, ha);
				if (err != 0)
					LOG_ERR("list_hw_addr_del failed\n");
				goto out;
			}
		}
	}

out:

	netif_addr_unlock_bh(netdev);

	return err;
}

#ifdef MAC_CONFIG_DEBUG
s32 zxdh_pf_dump_all_mac(struct zxdh_en_device *en_dev)
{
	struct MAC_VPORT_INFO *unicast_mac_arry = NULL;
	struct MAC_VPORT_INFO *multicast_mac_arry = NULL;
	u32 current_unicast_num = 0;
	u32 current_multicast_num = 0;
	s32 err = 1;
	s32 i = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	unicast_mac_arry = kzalloc(sizeof(*unicast_mac_arry) * UNICAST_MAX_NUM, GFP_KERNEL);
	if (!unicast_mac_arry) {
		LOG_ERR("kzalloc unicast_mac_arry failed\n");
		return err;
	}

	multicast_mac_arry = kzalloc(sizeof(multicast_mac_arry) * MULTICAST_MAX_NUM, GFP_KERNEL);
	if (!multicast_mac_arry) {
		LOG_ERR("kzalloc multicast_mac_arry failed\n");
		goto out1;
	}

	err = dpp_unicast_mac_dump(&pf_info, unicast_mac_arry, &current_unicast_num);
	if (err != 0) {
		LOG_ERR("dpp_unicast_mac_dump failed, ret:%d\n", err);
		goto out2;
	}

	err = dpp_multicast_mac_dump(&pf_info, multicast_mac_arry, &current_multicast_num);
	if (err != 0) {
		LOG_ERR("dpp_multicast_mac_dump failed\n");
		goto out2;
	}

	for (i = 0; i < current_unicast_num; ++i) {
		LOG_INFO("unicast_mac_arry[%d].vport is %#x\n", i, unicast_mac_arry[i].vport);
		LOG_INFO("unicast_mac_arry[%d].mac is %pM\n", i, unicast_mac_arry[i].addr);
	}
	for (i = 0; i < current_multicast_num; ++i) {
		LOG_INFO("multicast_mac_arry[%d].vport is %#x\n", i, multicast_mac_arry[i].vport);
		LOG_INFO("multicast_mac_arry[%d].mac is %pM\n", i, multicast_mac_arry[i].addr);
	}

out2:
	kfree(multicast_mac_arry);

out1:
	kfree(unicast_mac_arry);

	return err;
}
#endif /* MAC_CONFIG_DEBUG */

s32 unicast_mac_add(struct zxdh_en_device *en_dev, struct net_device *dev, const u8 *addr,
		    u16 flags)
{
	struct netdev_hw_addr *ha = NULL;
	s32 err = 0;
	struct MAC_VPORT_INFO *p_mac_arr = NULL;
	u32 p_mac_num = 0;
	u16 current_vport = 0;
	u16 sriov_vlan_tpid = 0;
	u16 sriov_vlan_id = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct rb_node **ins_point = NULL, *parent = NULL;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->curr_unicast_num >= DEV_UNICAST_MAX_NUM - 1) {
		LOG_ERR("curr_unicast_num is beyond maximum\n");
		return -ENOSPC;
	}

	if (is_this_mac_exist(dev, addr, &ha, &ins_point, &parent)) {
		LOG_DEBUG("Mac already exists\n");
		if (!(flags & NLM_F_EXCL))
			return 0;
		return -EEXIST;
	}

	if (!memcmp(addr, dev->dev_addr, dev->addr_len))
		goto out;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		err = dpp_unicast_mac_dump(&pf_info, p_mac_arr, &p_mac_num);
		if (err != 0) {
			LOG_ERR("dpp_unicast_mac_dump failed, ret:%d\n", err);
			return -1;
		}
		LOG_DEBUG("p_mac_num is %d\n", p_mac_num);

		if (p_mac_num >= UNICAST_MAX_NUM) {
			LOG_ERR("curr_all_unicast_num is beyond maximum\n");
			return -ENOSPC;
		}

		err = dpp_unicast_mac_search(&pf_info, addr, sriov_vlan_tpid, sriov_vlan_id,
					     &current_vport);
		if (err == 0) {
			LOG_DEBUG("Mac already exists\n");
			return -EEXIST;
		} else if (err != DPP_HASH_RC_SRH_FAIL) {
			LOG_ERR("dpp_unicast_mac_search failed, ret:%d\n", err);
			return -1;
		}

		err = dpp_add_mac(&pf_info, addr, sriov_vlan_tpid, sriov_vlan_id);
		if (err != 0) {
			LOG_ERR("dpp_add_mac failed, ret:%d\n", err);
			return -1;
		}
	} else {
		err = zxdh_vf_dpp_add_mac(en_dev, addr, FILTER_MAC);
		if (err != 0) {
			if (err == ZXDH_REPS_BEYOND_MAC) {
				LOG_ERR("curr_all_unicast_num is beyond maximum\n");
				return -ENOSPC;
			} else if (err == ZXDH_REPS_EXIST_MAC) {
				LOG_DEBUG("Mac already exists\n");
				return -EEXIST;
			}
			LOG_ERR("zxdh_vf_dpp_add_mac failed, ret:%d\n", err);
			return -1;
		}
	}

out:

	err = zxdh_dev_list_addr_add(dev, addr, parent, ins_point);
	if (err != 0) {
		LOG_ERR("zxdh_dev_list_addr_add failed, ret:%d\n", err);
		return -1;
	}
	en_dev->curr_unicast_num++;
	LOG_DEBUG("curr_unicast_num is %d\n", en_dev->curr_unicast_num);
	return err;
}

bool is_ipv6_multicast_mac(const u8 *mac)
{
	return ((mac[0] == 0x33) && (mac[1] == 0x33) && (mac[2] == 0xff));
}

bool ipv6_mac_refcount_get(struct zxdh_en_device *en_dev, const u8 *ip6mac, s32 *ipv6_mac_refconut)
{
	u32 mac_hash_val = 0;
	struct zxdh_ipv6_mac_tbl *ip6mac_tbl = en_dev->ops->get_ip6mac_tbl(en_dev->parent);
	struct zxdh_ipv6_mac_entry *ce = NULL;
	struct zxdh_ipv6_mac_entry *cte = NULL;

	if (!ip6mac_tbl) {
		LOG_ERR("ip6mac_tbl is NULL\n");
		return -ENXIO;
	}

	mac_hash_val = mac_hash(ip6mac_tbl, ip6mac);

	mutex_lock(&ip6mac_tbl->mlock);

	list_for_each_entry(cte, &ip6mac_tbl->hash_list[mac_hash_val], list) {
		if (memcmp(cte->ipv6_mac, ip6mac, ETH_ALEN) == 0) {
			ce = cte;
			*ipv6_mac_refconut = refcount_read(&ce->refcnt);
			mutex_unlock(&ip6mac_tbl->mlock);
			return true;
		}
	}
	mutex_unlock(&ip6mac_tbl->mlock);
	return false;
}

s32 multicast_mac_add_operate(struct zxdh_en_device *en_dev, const u8 *addr, u16 flags,
			      struct netdev_hw_addr *ha)
{
	s32 ipv6_mac_refconut = 0;

	if (!ipv6_mac_refcount_get(en_dev, addr, &ipv6_mac_refconut))
		goto exist_flag;

	if (ipv6_mac_refconut == ha->refcount) {
		++ha->refcount;
		LOG_INFO("ipv6_mac_refconut == ha->refcount\n");
		return 0;
	}

	if (ipv6_mac_refconut < ha->refcount) {
		LOG_INFO("ipv6_mac_refconut < ha->refcount\n");
		goto exist_flag;
	}
	LOG_ERR("ipv6_mac_refconut[%d] < ha->refcount[%d]\n", ipv6_mac_refconut, ha->refcount);
	return -1;

exist_flag:
	if (!(flags & NLM_F_EXCL))
		return 0;
	return -EEXIST;
}

s32 multicast_mac_add(struct zxdh_en_device *en_dev, struct net_device *dev, const u8 *addr,
		      u16 flags)
{
	struct netdev_hw_addr *ha = NULL;
	s64 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct rb_node **ins_point = NULL, *parent = NULL;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->curr_multicast_num >= DEV_MULTICAST_MAX_NUM) {
		LOG_ERR("curr_multicast_num is beyond maximum\n");
		return -ENOSPC;
	}

	if (is_this_mac_exist(dev, addr, &ha, &ins_point, &parent)) {
		if (!is_ipv6_multicast_mac(addr)) {
			LOG_DEBUG("Mac already exists\n");
			if (!(flags & NLM_F_EXCL))
				return 0;
			return -EEXIST;
		}

		if (!ha) {
			LOG_ERR("ha is NULL");
			return -1;
		}

		return multicast_mac_add_operate(en_dev, addr, flags, ha);
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		err = dpp_multi_mac_add_member(&pf_info, addr);
		if (err != 0) {
			if (err == DPP_RC_TBL_IS_FULL) {
				LOG_ERR("multicast mac beyond all mac num\n");
				return -ENOSPC;
			}
			LOG_ERR("dpp_multi_mac_add_member failed\n");
			return -1;
		}
	} else {
		err = zxdh_vf_dpp_add_mac(en_dev, addr, FILTER_MAC);
		if (err != 0) {
			if (err == ZXDH_REPS_BEYOND_MAC) {
				LOG_ERR("multicast mac is beyond all mac num\n");
				return -ENOSPC;
			}
			LOG_ERR("zxdh_vf_dpp_add_mac failed, ret:%lld\n", err);
			return -1;
		}
	}

	err = zxdh_dev_list_addr_add(dev, addr, parent, ins_point);
	if (err != 0) {
		LOG_ERR("zxdh_dev_list_addr_add failed, ret:%lld\n", err);
		return -1;
	}
	en_dev->curr_multicast_num++;
	LOG_DEBUG("curr_multicast_num is %d\n", en_dev->curr_multicast_num);
	return 0;
}

s32 unicast_mac_del(struct zxdh_en_device *en_dev, struct net_device *dev, const u8 *addr)
{
	struct netdev_hw_addr *ha = NULL;
	s32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	u16 sriov_vlan_tpid = 0;
	u16 sriov_vlan_id = 0;
	struct rb_node **ins_point = NULL, *parent = NULL;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->curr_unicast_num <= 0) {
		LOG_ERR("curr_unicast_num is less than 0\n");
		return -ENOENT;
	}

	if (!is_this_mac_exist(dev, addr, &ha, &ins_point, &parent)) {
		LOG_DEBUG("Mac is not exists\n");
		return -ENOENT;
	}

	if (!memcmp(addr, dev->dev_addr, dev->addr_len))
		goto out;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		err = dpp_del_mac(&pf_info, addr, sriov_vlan_tpid, sriov_vlan_id);
		if (err) {
			LOG_ERR("dpp_del_mac failed, ret:%d\n", err);
			return -1;
		}
		LOG_DEBUG("dpp_del_mac succeed\n");
	} else {
		err = zxdh_vf_dpp_del_mac(en_dev, addr, FILTER_MAC, true);
		if (err) {
			LOG_ERR("zxdh_vf_dpp_del_mac failed, ret:%d\n", err);
			return -1;
		}
		LOG_DEBUG("zxdh_vf_dpp_del_mac succeed\n");
	}

out:

	err = zxdh_dev_list_addr_del(dev, addr);
	if (err) {
		LOG_ERR("zxdh_dev_list_addr_del failed, ret:%d\n", err);
		return -1;
	}
	en_dev->curr_unicast_num--;
	LOG_DEBUG("curr_unicast_num is %d\n", en_dev->curr_unicast_num);
	return err;
}

s32 multicast_mac_del_operate(struct zxdh_en_device *en_dev, const u8 *addr,
			      struct netdev_hw_addr *ha)
{
	s32 ipv6_mac_refconut = 0;

	if (!ipv6_mac_refcount_get(en_dev, addr, &ipv6_mac_refconut))
		return 0;

	if (ipv6_mac_refconut == ha->refcount) {
		LOG_INFO("ipv6_mac_refconut == ha->refcount");
		return -1;
	}

	if ((ipv6_mac_refconut < ha->refcount) && (ipv6_mac_refconut > 0)) {
		--ha->refcount;
		LOG_INFO("ipv6_mac_refconut < ha->refcount");
		return -1;
	}
	LOG_ERR("ipv6_mac_refconut[%d] < ha->refcount[%d]", ipv6_mac_refconut, ha->refcount);
	return -1;
}

s32 multicast_mac_del(struct zxdh_en_device *en_dev, struct net_device *dev, const u8 *addr)
{
	struct netdev_hw_addr *ha = NULL;
	s32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct rb_node **ins_point = NULL, *parent = NULL;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (!is_this_mac_exist(dev, addr, &ha, &ins_point, &parent)) {
		LOG_DEBUG("Mac is not exists\n");
		return -ENOENT;
	}

	if (!ha) {
		LOG_ERR("ha is NULL");
		return -1;
	}

	if (is_ipv6_multicast_mac(addr)) {
		err = multicast_mac_del_operate(en_dev, addr, ha);
		if (err != 0) {
			LOG_DEBUG("Mac is not permitted del\n");
			return 0;
		}
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		err = dpp_multi_mac_del_member(&pf_info, addr);
		if (err != 0) {
			LOG_ERR("dpp_multi_mac_del_member failed, ret:%d\n", err);
			return -1;
		}
		LOG_DEBUG("dpp_multi_mac_del_member succeed\n");
	} else {
		err = zxdh_vf_dpp_del_mac(en_dev, addr, FILTER_MAC, true);
		if (err != 0) {
			LOG_ERR("zxdh_vf_dpp_del_mac failed, ret:%d\n", err);
			return -1;
		}
	}

	err = zxdh_dev_list_addr_del(dev, addr);
	if (err != 0) {
		LOG_ERR("zxdh_dev_list_addr_del failed, ret:%d\n", err);
		return -1;
	}
	en_dev->curr_multicast_num--;
	LOG_DEBUG("curr_multicast_num is %d\n", en_dev->curr_multicast_num);
	return err;
}

static unsigned int mac_hash(struct zxdh_ipv6_mac_tbl *mac_tbl, const u8 *mac_addr)
{
	unsigned int mact_size_half = mac_tbl->ip6mact_size / 2;
	u32 mac_part1 = (mac_addr[0] << 24) | (mac_addr[1] << 16) | (mac_addr[2] << 8) |
			mac_addr[3];
	u32 mac_part2 = (mac_addr[4] << 8) | mac_addr[5];

	u32 xor = mac_part1 ^ mac_part2;

	return (jhash_1word(xor, 0) % mact_size_half);
}

s32 zxdh_ip6mac_to_np(struct zxdh_en_device *en_dev, struct zxdh_ipv6_mac_tbl *ip6mac_tbl,
		      const u8 *ip6mac, u8 action)
{
	s32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	switch (action) {
	case ADD_IP6MAC: {
		if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
			err = dpp_multi_mac_add_member(&pf_info, ip6mac);
			if (err != 0)
				LOG_ERR("dpp_multi_mac_add_member failed, err:%d\n", err);
		} else {
			err = zxdh_vf_dpp_add_ipv6_mac(en_dev, ip6mac);
			if (err != 0)
				LOG_ERR("zxdh_vf_dpp_add_ipv6_mac failed, err:%d\n", err);
		}
		break;
	}
	case DEL_IP6MAC: {
		if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
			err = dpp_multi_mac_del_member(&pf_info, ip6mac);
			if (err != 0)
				LOG_ERR("dpp_multi_mac_del_member failed, err:%d\n", err);
		} else {
			err = zxdh_vf_dpp_del_ipv6_mac(en_dev, ip6mac);
			if (err != 0)
				LOG_ERR("zxdh_vf_dpp_del_ipv6_mac failed, err:%d\n", err);
		}
		break;
	}
	}
	return err;
}

s32 zxdh_ip4mac_to_np(struct zxdh_en_device *en_dev, const u8 *ip4mac, u8 action)
{
	s32 err = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	switch (action) {
	case NETDEV_UP: {
		if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
			err = dpp_multi_mac_add_member(&pf_info, ip4mac);
			if (err != 0)
				LOG_ERR("pf config ipv4 mac failed, err:%d\n", err);
		} else {
			err = zxdh_vf_dpp_add_ipv6_mac(en_dev, ip4mac);
			if (err != 0)
				LOG_ERR("vf config ipv4 mac failed, err:%d\n", err);
		}
		break;
	}
	case NETDEV_DOWN: {
		if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
			err = dpp_multi_mac_del_member(&pf_info, ip4mac);
			if (err != 0)
				LOG_ERR("vf del ipv4 mac failed, err:%d\n", err);
		} else {
			err = zxdh_vf_dpp_del_ipv6_mac(en_dev, ip4mac);
			if (err != 0)
				LOG_ERR("vf del ipv4 mac failed, err:%d\n", err);
		}
		break;
	}
	}
	return err;
}

s32 zxdh_ip6mac_add(struct zxdh_en_device *en_dev, const u32 *addr6, const u8 *ip6mac)
{
	s32 err = 0;
	unsigned int mac_hash_val;
	struct zxdh_ipv6_mac_tbl *ip6mac_tbl = en_dev->ops->get_ip6mac_tbl(en_dev->parent);
	struct zxdh_ipv6_mac_entry *ce, *cte;

	if (!ip6mac_tbl) {
		LOG_ERR("ip6mac_tbl is NULL\n");
		return -ENXIO;
	}

	if (en_dev->curr_multicast_num >= DEV_MULTICAST_MAX_NUM) {
		LOG_ERR("curr_multicast_num is beyond maximum\n");
		return -ENOSPC;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		mutex_lock(&ip6mac_tbl->mlock);
		err = zxdh_ip6mac_to_np(en_dev, ip6mac_tbl, ip6mac, ADD_IP6MAC);
		if (err != 0) {
			mutex_unlock(&ip6mac_tbl->mlock);
			return err;
		}
	} else {
		err = zxdh_ip6mac_to_np(en_dev, ip6mac_tbl, ip6mac, ADD_IP6MAC);
		if (err != 0)
			return err;
		mutex_lock(&ip6mac_tbl->mlock);
	}

	mac_hash_val = mac_hash(ip6mac_tbl, ip6mac);

	list_for_each_entry(cte, &ip6mac_tbl->hash_list[mac_hash_val], list) {
		if (memcmp(cte->ipv6_mac, ip6mac, ETH_ALEN) == 0) {
			ce = cte;
			refcount_inc(&ce->refcnt);
			DH_LOG_DEBUG(MODULE_PF,
				     "Eth:%s, Increase Multicast MAC Address(%pM) refcnt:%d\n",
				     en_dev->netdev->name, ip6mac, refcount_read(&ce->refcnt));
			mutex_unlock(&ip6mac_tbl->mlock);
			return 0;
		}
	}

	if (list_empty(&ip6mac_tbl->ip6mac_free_head)) {
		if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
			err = zxdh_ip6mac_to_np(en_dev, ip6mac_tbl, ip6mac, DEL_IP6MAC);
			mutex_unlock(&ip6mac_tbl->mlock);
		} else {
			mutex_unlock(&ip6mac_tbl->mlock);
			err = zxdh_ip6mac_to_np(en_dev, ip6mac_tbl, ip6mac, DEL_IP6MAC);
		}
		LOG_ERR("ip6mac_tbl overflow, can't add; del mac from NP, ret:%d\n", err);
		return -ENOMEM;
	}
	ce = list_first_entry(&ip6mac_tbl->ip6mac_free_head, struct zxdh_ipv6_mac_entry, list);
	list_del(&ce->list);
	INIT_LIST_HEAD(&ce->list);
	spin_lock_init(&ce->lock);
	refcount_set(&ce->refcnt, 0);
	list_add_tail(&ce->list, &ip6mac_tbl->hash_list[mac_hash_val]);
	memcpy(ce->ipv6_mac, ip6mac, ETH_ALEN);
	refcount_set(&ce->refcnt, 1);
	mutex_unlock(&ip6mac_tbl->mlock);
	en_dev->curr_multicast_num++;
	DH_LOG_DEBUG(MODULE_PF, "curr_multicast_num is %d\n", en_dev->curr_multicast_num);
	DH_LOG_DEBUG(MODULE_PF, "Eth:%s, Add New Multicast MAC Address: %pM, refcnt:%d\n",
		     en_dev->netdev->name, ip6mac, refcount_read(&ce->refcnt));

	return 0;
}

s32 zxdh_ip4mac_add(struct zxdh_en_device *en_dev, const u8 *ip4mac, u8 action)
{
	struct net_device *netdev = en_dev->netdev;
	struct netdev_hw_addr *entry = NULL;
	s32 err = 0;

	if (en_dev->curr_multicast_num >= DEV_MULTICAST_MAX_NUM) {
		LOG_ERR("curr_multicast_num is beyond maximum\n");
		return -ENOSPC;
	}

	list_for_each_entry(entry, &netdev->mc.list, list) {
		if ((!memcmp(entry->addr, ip4mac, ETH_ALEN)) &&
		    (entry->type == NETDEV_HW_ADDR_T_MULTICAST)) {
			LOG_DEBUG("entry->refcount is %d\n", entry->refcount);
			if (entry->refcount > 1) {
				LOG_INFO("MAC:%pM already config to np\n", ip4mac);
				return NOTIFY_OK;
			}
		}
	}

	err = zxdh_ip4mac_to_np(en_dev, ip4mac, action);
	if (err != 0)
		return err;

	en_dev->curr_multicast_num++;
	LOG_DEBUG("curr_multicast_num is %d\n", en_dev->curr_multicast_num);
	return 0;
}

/* Work queue handler for IPv6 MAC deletion using dynamic work items */
void zxdh_ip6mac_del_work_handler(struct work_struct *work)
{
	struct zxdh_ip6mac_work_item *work_item =
		container_of(work, struct zxdh_ip6mac_work_item, work);
	struct zxdh_en_device *en_dev = work_item->en_dev;

	zxdh_ip6mac_del(en_dev, work_item->data.addr6, work_item->data.ip6mac);
	kfree(work_item);
}

/* Safe version of zxdh_ip6mac_del that handles atomic context with dynamic work items */
s32 zxdh_ip6mac_del_safe(struct zxdh_en_device *en_dev, const u32 *addr6, const u8 *ip6mac)
{
	struct zxdh_ip6mac_work_item *work_item;
	struct zxdh_en_priv *en_priv = container_of(en_dev, struct zxdh_en_priv, edev);
	/* Allocate work item dynamically - each call gets its own work item with embedded data */
	work_item = kmalloc(sizeof(struct zxdh_ip6mac_work_item), GFP_ATOMIC);
	if (!work_item)
		return -ENOMEM;
	INIT_WORK(&work_item->work, zxdh_ip6mac_del_work_handler);
	work_item->en_dev = en_dev;
	zte_memcpy_s(work_item->data.addr6, addr6, sizeof(work_item->data.addr6));
	zte_memcpy_s(work_item->data.ip6mac, ip6mac, sizeof(work_item->data.ip6mac));

	if (!queue_work(en_priv->events->wq, &work_item->work)) {
		kfree(work_item);
		return -EBUSY;
	}

	return 0;
}

/* Work queue handler for IPv6 MAC addition using dynamic work items */
void zxdh_ip6mac_add_work_handler(struct work_struct *work)
{
	struct zxdh_ip6mac_work_item *work_item =
		container_of(work, struct zxdh_ip6mac_work_item, work);
	struct zxdh_en_device *en_dev = work_item->en_dev;

	zxdh_ip6mac_add(en_dev, work_item->data.addr6, work_item->data.ip6mac);
	kfree(work_item);
}

/* Safe version of zxdh_ip6mac_add that handles atomic context with dynamic work items */
s32 zxdh_ip6mac_add_safe(struct zxdh_en_device *en_dev, const u32 *addr6, const u8 *ip6mac)
{
	struct zxdh_ip6mac_work_item *work_item;
	struct zxdh_en_priv *en_priv = container_of(en_dev, struct zxdh_en_priv, edev);

	work_item = kmalloc(sizeof(*work_item), GFP_ATOMIC);
	if (!work_item)
		return -ENOMEM;
	INIT_WORK(&work_item->work, zxdh_ip6mac_add_work_handler);
	work_item->en_dev = en_dev;
	zte_memcpy_s(work_item->data.addr6, addr6, sizeof(work_item->data.addr6));
	zte_memcpy_s(work_item->data.ip6mac, ip6mac, sizeof(work_item->data.ip6mac));

	if (!queue_work(en_priv->events->wq, &work_item->work)) {
		kfree(work_item);
		return -EBUSY;
	}

	return 0;
}

s32 zxdh_ip6mac_del(struct zxdh_en_device *en_dev, const u32 *addr6, const u8 *ip6mac)
{
	s32 err = 0;
	struct zxdh_ipv6_mac_tbl *ip6mac_tbl = en_dev->ops->get_ip6mac_tbl(en_dev->parent);
	struct zxdh_ipv6_mac_entry *ce, *cte;
	unsigned int mac_hash_val;
	s32 refcnt = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	if (!ip6mac_tbl) {
		LOG_ERR("ip6mac_tbl is NULL");
		return -ENXIO;
	}

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	mac_hash_val = mac_hash(ip6mac_tbl, ip6mac);

	mutex_lock(&ip6mac_tbl->mlock);
	list_for_each_entry(cte, &ip6mac_tbl->hash_list[mac_hash_val], list) {
		if (memcmp(cte->ipv6_mac, ip6mac, ETH_ALEN) == 0) {
			ce = cte;
			goto found;
		}
	}
	DH_LOG_DEBUG(MODULE_PF, "Don't Found Multicast MAC Address: %pM in Hash List\n", ip6mac);

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		err = zxdh_ip6mac_to_np(en_dev, ip6mac_tbl, ip6mac, DEL_IP6MAC);
		mutex_unlock(&ip6mac_tbl->mlock);
	} else {
		mutex_unlock(&ip6mac_tbl->mlock);
		err = zxdh_ip6mac_to_np(en_dev, ip6mac_tbl, ip6mac, DEL_IP6MAC);
	}
	return err;

found:
	spin_lock_bh(&ce->lock);
	if (!refcount_dec_and_test(&ce->refcnt)) {
		DH_LOG_DEBUG(MODULE_PF, "Eth:%s, Decrease Multicast MAC Address(%pM) refcnt:%d\n",
			     en_dev->netdev->name, ip6mac, refcount_read(&ce->refcnt));
		spin_unlock_bh(&ce->lock);
		mutex_unlock(&ip6mac_tbl->mlock);
		return err;
	}

	list_del(&ce->list);
	INIT_LIST_HEAD(&ce->list);
	list_add_tail(&ce->list, &ip6mac_tbl->ip6mac_free_head);
	refcnt = refcount_read(&ce->refcnt);
	spin_unlock_bh(&ce->lock);
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		err = zxdh_ip6mac_to_np(en_dev, ip6mac_tbl, ip6mac, DEL_IP6MAC);
		mutex_unlock(&ip6mac_tbl->mlock);
	} else {
		mutex_unlock(&ip6mac_tbl->mlock);
		err = zxdh_ip6mac_to_np(en_dev, ip6mac_tbl, ip6mac, DEL_IP6MAC);
	}
	en_dev->curr_multicast_num--;
	DH_LOG_DEBUG(MODULE_PF, "curr_multicast_num is %d\n", en_dev->curr_multicast_num);
	DH_LOG_DEBUG(MODULE_PF,
		     "Eth:%s, Del Multicast MAC Address: %pM Completely, refcnt:%d, np ret:%d\n",
		     en_dev->netdev->name, ip6mac, refcnt, err);
	return err;
}

s32 zxdh_ip4mac_del(struct zxdh_en_device *en_dev, const u8 *ip4mac, u8 action)
{
	s32 err = 0;
	struct netdev_hw_addr *entry = NULL;
	struct net_device *netdev = en_dev->netdev;

	list_for_each_entry(entry, &netdev->mc.list, list) {
		if ((!memcmp(entry->addr, ip4mac, ETH_ALEN)) &&
		    (entry->type == NETDEV_HW_ADDR_T_MULTICAST)) {
			LOG_DEBUG("entry->refcount is %d\n", entry->refcount);
			if (entry->refcount > 0) {
				LOG_INFO("MAC:%pM is used by other dev or operation\n", ip4mac);
				return NOTIFY_OK;
			}
		}
	}

	err = zxdh_ip4mac_to_np(en_dev, ip4mac, action);
	if (err != 0)
		return err;

	en_dev->curr_multicast_num--;
	LOG_INFO("curr_multicast_num is %d\n", en_dev->curr_multicast_num);
	return err;
}

s32 zxdh_pf_add_vf_unicast_mac(struct zxdh_en_device *en_dev, struct dhtool_set_vf_mac_msg *msg)
{
	struct zxdh_vf_item *vf_item = NULL;
	u16 current_vport = 0;
	s32 ret = 0;
	u32 i = 0;
	u16 sriov_vlan_tpid = 0;
	u16 sriov_vlan_id = 0;
	u32 p_mac_num = 0;
	u32 max_unicast_num = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_l2_fwd_key *l2_entry = NULL;
	struct MAC_VPORT_INFO *p_mac_arr = NULL;

	LOG_INFO("%s is called\n", __func__);

	if (!en_dev->ops->get_vf_is_probe(en_dev->parent, msg->mac_config.target_vf)) {
		LOG_ERR("vf(%u) is not probed\n", msg->mac_config.target_vf);
		return VF_ERROR;
	}

	vf_item = en_dev->ops->get_vf_item(en_dev->parent, msg->mac_config.target_vf);
	if (IS_ERR_OR_NULL(vf_item)) {
		LOG_ERR("get_vf(%u)_item failed\n", msg->mac_config.target_vf);
		return MAC_CONFIG_FAILED;
	}

	mutex_lock(&vf_item->lock);
	pf_info.slot = en_dev->slot_id;
	pf_info.vport = vf_item->vport;

	LOG_DEBUG("unicast_add_count is %u\n", msg->mac_config.unicast_add_count);
	LOG_DEBUG("vf_item->vf_mac_info.current_unicast_num is %u\n",
		  vf_item->vf_mac_info.current_unicast_num);

	if ((vf_item->vf_mac_info.current_unicast_num + msg->mac_config.unicast_add_count) >
	    VF_MAX_UNICAST_MAC) {
		LOG_ERR("current mac num beyond 128\n");
		mutex_unlock(&vf_item->lock);
		return UNICAST_MAC_NUM_BEYOND_MAXNUM;
	}

	ret = dpp_unicast_mac_dump(&pf_info, p_mac_arr, &p_mac_num);
	if (ret != 0) {
		LOG_ERR("dpp_unicast_mac_dump failed\n");
		mutex_unlock(&vf_item->lock);
		return ret;
	}
	LOG_DEBUG("p_mac_num is %d\n", p_mac_num);

	ret = dpp_unicast_mac_max_get(&pf_info, &max_unicast_num);
	if (ret != 0) {
		LOG_ERR("dpp_unicast_mac_max_get failed %u\n", max_unicast_num);
		mutex_unlock(&vf_item->lock);
		return MAC_CONFIG_FAILED;
	}

	if ((p_mac_num + msg->mac_config.unicast_add_count) > max_unicast_num) {
		LOG_ERR("dpp_unicast_mac_dump failed\n");
		mutex_unlock(&vf_item->lock);
		return UNICAST_MAC_NUM_BEYOND_MAXNUM;
	}

	sriov_vlan_tpid = vf_item->vlan_proto;
	sriov_vlan_id = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);

	pf_info.vport = vf_item->vport;

	for (i = 0; i < msg->mac_config.unicast_add_count; i++) {
		ret = dpp_unicast_mac_search(&pf_info,
					     msg->mac_config.unicast_mac_array[i].mac_addr,
					     sriov_vlan_tpid, sriov_vlan_id, &current_vport);
		if (!ret) {
			if (current_vport == vf_item->vport) {
				continue;
			} else {
				LOG_ERR("Mac:%pM Already exists in other vf\n",
					msg->mac_config.unicast_mac_array[i].mac_addr);
				mutex_unlock(&vf_item->lock);
				return MAC_ALREADY_EXISTS_IN_OTHER_VF;
			}
		}
	}

	l2_entry = kzalloc(sizeof(struct zxdh_l2_fwd_key) * msg->mac_config.unicast_add_count,
			   GFP_KERNEL);
	if (!l2_entry) {
		LOG_ERR("l2_entry malloc fialed\n");
		mutex_unlock(&vf_item->lock);
		return MAC_CONFIG_FAILED;
	}
	for (i = 0; i < msg->mac_config.unicast_add_count; i++) {
		memcpy(l2_entry[i].dmac_addr, msg->mac_config.unicast_mac_array[i].mac_addr,
		       ETH_ALEN);
		l2_entry[i].sriov_vlan_id = sriov_vlan_id;
		l2_entry[i].sriov_vlan_tpid = sriov_vlan_tpid;
	}

	ret = dpp_batch_add_unicast_mac(&pf_info, msg->mac_config.unicast_add_count, l2_entry);
	if (ret != 0) {
		kfree(l2_entry);
		LOG_ERR("config unicast mac failed\n");
		mutex_unlock(&vf_item->lock);
		return MAC_CONFIG_FAILED;
	}

	for (i = 0; i < msg->mac_config.unicast_add_count; i++)
		zxdh_vf_item_mac_add(vf_item, l2_entry[i].dmac_addr, 1);

	LOG_DEBUG("current_unicast_num is %u\n", vf_item->vf_mac_info.current_unicast_num);
	kfree(l2_entry);
	mutex_unlock(&vf_item->lock);
	return ret;
}

s32 zxdh_pf_add_vf_multicast_mac(struct zxdh_en_device *en_dev, struct dhtool_set_vf_mac_msg *msg)
{
	struct zxdh_vf_item *vf_item = NULL;
	u32 ret = 0;
	u32 i = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct MacAddress *hash_entry = NULL;

	LOG_INFO("%s is called\n", __func__);

	pf_info.slot = en_dev->slot_id;

	if (!en_dev->ops->get_vf_is_probe(en_dev->parent, msg->mac_config.target_vf)) {
		LOG_ERR("vf(%u) is not probed\n", msg->mac_config.target_vf);
		return VF_ERROR;
	}

	vf_item = en_dev->ops->get_vf_item(en_dev->parent, msg->mac_config.target_vf);
	if (IS_ERR_OR_NULL(vf_item)) {
		LOG_ERR("get_vf(%u)_item failed\n", msg->mac_config.target_vf);
		return MAC_CONFIG_FAILED;
	}

	mutex_lock(&vf_item->lock);
	pf_info.slot = en_dev->slot_id;
	pf_info.vport = vf_item->vport;

	if ((vf_item->vf_mac_info.current_multicast_num + msg->mac_config.multicast_add_count) >
	    VF_MAX_MULTICAST_MAC) {
		LOG_ERR("current multicast mac num beyond 32\n");
		mutex_unlock(&vf_item->lock);
		return MULTICAST_MAC_NUM_BEYOND_MAXNUM;
	}

	hash_entry = kzalloc(sizeof(struct MacAddress) * msg->mac_config.multicast_add_count,
			     GFP_KERNEL);
	if (!hash_entry) {
		LOG_ERR("hash_entry malloc failed\n");
		mutex_unlock(&vf_item->lock);
		return MAC_CONFIG_FAILED;
	}
	for (i = 0; i < msg->mac_config.multicast_add_count; i++) {
		memcpy(hash_entry[i].mac_addr, msg->mac_config.multicast_mac_array[i].mac_addr,
		       ETH_ALEN);
	}

	ret = dpp_batch_add_multicast_mac(&pf_info, msg->mac_config.multicast_add_count,
					  hash_entry);
	if (ret != 0) {
		kfree(hash_entry);
		mutex_unlock(&vf_item->lock);
		if (ret == DPP_RC_TBL_IS_FULL) {
			LOG_ERR("current multicast mac num PF beyond mac\n");
			return MULTICAST_MAC_NUM_BEYOND_MAXNUM;
		}
		LOG_ERR("multicast config failed\n");
		return MAC_CONFIG_FAILED;
	}

	for (i = 0; i < msg->mac_config.multicast_add_count; i++)
		zxdh_vf_item_mac_add(vf_item, hash_entry[i].mac_addr, 1);

	LOG_DEBUG("current_multicast_num is %u\n", vf_item->vf_mac_info.current_multicast_num);
	kfree(hash_entry);
	mutex_unlock(&vf_item->lock);
	return MAC_CONFIG_SUCCESS;
}

s32 zxdh_pf_del_vf_unicast_mac(struct zxdh_en_device *en_dev, struct dhtool_set_vf_mac_msg *msg)
{
	struct zxdh_l2_fwd_key *l2_entry = NULL;
	struct zxdh_vf_item *vf_item = NULL;
	u16 current_vport = 0;
	s32 ret = 0;
	u32 i = 0;
	u16 sriov_vlan_tpid = 0;
	u16 sriov_vlan_id = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	LOG_INFO("%s is called\n", __func__);

	if (!en_dev->ops->get_vf_is_probe(en_dev->parent, msg->mac_config.target_vf)) {
		LOG_ERR("vf(%u) is not probed\n", msg->mac_config.target_vf);
		return VF_ERROR;
	}

	vf_item = en_dev->ops->get_vf_item(en_dev->parent, msg->mac_config.target_vf);
	if (IS_ERR_OR_NULL(vf_item)) {
		LOG_ERR("get_vf(%u)_item failed\n", msg->mac_config.target_vf);
		return MAC_CONFIG_FAILED;
	}

	mutex_lock(&vf_item->lock);

	sriov_vlan_tpid = vf_item->vlan_proto;
	sriov_vlan_id = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = vf_item->vport;

	for (i = 0; i < msg->mac_config.unicast_del_count; i++) {
		ret = dpp_unicast_mac_search(&pf_info,
					     msg->mac_config.unicast_mac_array[i].mac_addr,
					     sriov_vlan_tpid, sriov_vlan_id, &current_vport);
		if ((!ret) && (current_vport == vf_item->vport)) {
			continue;
		} else {
			LOG_INFO("Mac:%pM not exists\n",
				 msg->mac_config.unicast_mac_array[i].mac_addr);
			mutex_unlock(&vf_item->lock);
			return MAC_CONFIG_SUCCESS;
		}
	}

	l2_entry = kzalloc(sizeof(struct zxdh_l2_fwd_key) * msg->mac_config.unicast_del_count,
			   GFP_KERNEL);
	if (!l2_entry) {
		LOG_ERR("l2_entry kzalloc failed\n");
		mutex_unlock(&vf_item->lock);
		return MAC_CONFIG_FAILED;
	}
	for (i = 0; i < msg->mac_config.unicast_del_count; i++) {
		memcpy(l2_entry[i].dmac_addr, msg->mac_config.unicast_mac_array[i].mac_addr,
		       ETH_ALEN);
		l2_entry[i].sriov_vlan_id = sriov_vlan_id;
		l2_entry[i].sriov_vlan_tpid = sriov_vlan_tpid;
	}

	ret = dpp_batch_del_unicast_mac(&pf_info, msg->mac_config.unicast_del_count, l2_entry);
	if (ret != 0) {
		kfree(l2_entry);
		mutex_unlock(&vf_item->lock);
		LOG_ERR("del unicast failed\n");
		return MAC_CONFIG_FAILED;
	}

	for (i = 0; i < msg->mac_config.unicast_del_count; i++)
		zxdh_vf_item_mac_del(vf_item, l2_entry[i].dmac_addr);

	LOG_DEBUG("current_unicast_num is %u\n", vf_item->vf_mac_info.current_unicast_num);
	kfree(l2_entry);
	mutex_unlock(&vf_item->lock);
	return MAC_CONFIG_SUCCESS;
}

s32 zxdh_pf_del_vf_multicast_mac(struct zxdh_en_device *en_dev, struct dhtool_set_vf_mac_msg *msg)
{
	struct zxdh_vf_item *vf_item = NULL;
	s32 ret = 0;
	u32 i = 0;
	u32 j = 0;
	u32 is_exists = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct MacAddress *hash_entry = NULL;

	LOG_INFO("%s is called\n", __func__);

	if (!en_dev->ops->get_vf_is_probe(en_dev->parent, msg->mac_config.target_vf)) {
		LOG_ERR("vf(%u) is not probed\n", msg->mac_config.target_vf);
		return VF_ERROR;
	}

	vf_item = en_dev->ops->get_vf_item(en_dev->parent, msg->mac_config.target_vf);
	if (IS_ERR_OR_NULL(vf_item)) {
		LOG_ERR("get_vf(%u)_item failed\n", msg->mac_config.target_vf);
		return MAC_CONFIG_FAILED;
	}

	mutex_lock(&vf_item->lock);
	pf_info.slot = en_dev->slot_id;
	pf_info.vport = vf_item->vport;

	for (i = 0; i < msg->mac_config.multicast_del_count; i++) {
		for (j = 0; j < VF_MAX_MULTICAST_MAC; j++) {
			if (ether_addr_equal(msg->mac_config.multicast_mac_array[i].mac_addr,
					     vf_item->vf_mac_info.multicast_mac[j].mac_addr)) {
				is_exists = 1;
			}
		}
		if (is_exists != 1) {
			LOG_INFO("multicast mac:%pM not exists\n",
				 msg->mac_config.multicast_mac_array[i].mac_addr);
			mutex_unlock(&vf_item->lock);
			return MAC_CONFIG_SUCCESS;
		}
	}

	hash_entry = kzalloc(sizeof(*hash_entry) * msg->mac_config.multicast_del_count, GFP_KERNEL);
	if (!hash_entry) {
		LOG_ERR("hash_entry kzalloc failed\n");
		mutex_unlock(&vf_item->lock);
		return MAC_CONFIG_FAILED;
	}
	for (i = 0; i < msg->mac_config.multicast_del_count; i++)
		memcpy(hash_entry[i].mac_addr, msg->mac_config.multicast_mac_array[i].mac_addr,
		       ETH_ALEN);

	ret = dpp_batch_del_multicast_mac(&pf_info, msg->mac_config.multicast_del_count,
					  hash_entry);
	if (ret != 0) {
		kfree(hash_entry);
		mutex_unlock(&vf_item->lock);
		LOG_ERR("del multicast failed\n");
		return MAC_CONFIG_FAILED;
	}

	for (i = 0; i < msg->mac_config.multicast_del_count; i++)
		zxdh_vf_item_mac_del(vf_item, hash_entry[i].mac_addr);

	LOG_DEBUG("current_multicast_num is %u\n", vf_item->vf_mac_info.current_multicast_num);
	kfree(hash_entry);
	mutex_unlock(&vf_item->lock);
	return MAC_CONFIG_SUCCESS;
}

void vf_item_unicast_mac_transfer(struct zxdh_vf_item *src_vf_item,
				  struct zxdh_vf_item *dst_vf_item)
{
	s32 i = 0;
	s32 j = 0;

	for (i = 0; i < VF_MAX_UNICAST_MAC; i++) {
		if (is_zero_ether_addr(src_vf_item->vf_mac_info.unicast_mac[i].mac_addr))
			continue;

		for (j = 0; j < VF_MAX_UNICAST_MAC; j++) {
			if (!is_zero_ether_addr(dst_vf_item->vf_mac_info.unicast_mac[j].mac_addr)) {
				if (ether_addr_equal(
					    src_vf_item->vf_mac_info.unicast_mac[i].mac_addr,
					    dst_vf_item->vf_mac_info.unicast_mac[j].mac_addr)) {
					break;
				}
			}
		}

		zxdh_vf_item_mac_add(dst_vf_item, src_vf_item->vf_mac_info.unicast_mac[i].mac_addr,
				     1);
	}
}

void vf_item_multicast_mac_transfer(struct zxdh_vf_item *src_vf_item,
				    struct zxdh_vf_item *dst_vf_item)
{
	s32 i = 0;
	s32 j = 0;

	for (i = 0; i < VF_MAX_MULTICAST_MAC; i++) {
		if (is_zero_ether_addr(src_vf_item->vf_mac_info.multicast_mac[i].mac_addr))
			continue;

		for (j = 0; j < VF_MAX_MULTICAST_MAC; j++) {
			if (!is_zero_ether_addr(
				    dst_vf_item->vf_mac_info.multicast_mac[j].mac_addr)) {
				if (ether_addr_equal(
					    src_vf_item->vf_mac_info.multicast_mac[i].mac_addr,
					    dst_vf_item->vf_mac_info.multicast_mac[j].mac_addr)) {
					break;
				}
			}
		}

		zxdh_vf_item_mac_add(dst_vf_item,
				     src_vf_item->vf_mac_info.multicast_mac[i].mac_addr, 1);
	}
}

void vf_item_mac_print(struct zxdh_vf_item *vf_item, u32 vf_id)
{
	s32 i = 0;

	for (i = 0; i < VF_MAX_UNICAST_MAC; i++) {
		if (!is_zero_ether_addr(vf_item->vf_mac_info.unicast_mac[i].mac_addr)) {
			LOG_DEBUG("the %u unicast mac is %pM\n", i,
				  vf_item->vf_mac_info.unicast_mac[i].mac_addr);
		}
	}

	for (i = 0; i < VF_MAX_MULTICAST_MAC; i++) {
		if (!is_zero_ether_addr(vf_item->vf_mac_info.multicast_mac[i].mac_addr)) {
			LOG_DEBUG("the %u multicast mac is %pM\n", i,
				  vf_item->vf_mac_info.multicast_mac[i].mac_addr);
		}
	}

	LOG_INFO("print %u mac success\n", vf_id);
}

s32 MulticastType_get(u8 *mac_addr)
{
	if (mac_addr[0] == 0x33 && mac_addr[1] == 0x33)
		return 0;
	else if (mac_addr[0] == 0x01 && mac_addr[1] == 0x00 && mac_addr[2] == 0x5e)
		return 0;
	return -1;
}

s32 ip4_ip6_multicast_mac_del(struct zxdh_en_device *en_dev, struct zxdh_vf_item *src_vf_item,
			      u32 src_vf)
{
	struct dhtool_set_vf_mac_msg msg = { 0 };
	s32 i = 0;
	s32 ret = 0;

	msg.mac_config.target_vf = src_vf;

	for (i = 0; i < VF_MAX_MULTICAST_MAC; i++) {
		if ((MulticastType_get(src_vf_item->vf_mac_info.multicast_mac[i].mac_addr) == 0) &&
		    (src_vf_item->vf_mac_info.multicast_mac[i].dhtool_mac_set_flag == 0)) {
			memcpy(msg.mac_config
				       .multicast_mac_array[msg.mac_config.multicast_del_count]
				       .mac_addr,
			       src_vf_item->vf_mac_info.multicast_mac[i].mac_addr, ETH_ALEN);
			msg.mac_config.multicast_del_count++;
		}
	}

	if (msg.mac_config.multicast_del_count != 0) {
		ret = zxdh_pf_del_vf_multicast_mac(en_dev, &msg);
		if (ret != 0) {
			LOG_ERR("zxdh_pf_del_vf_multicast_mac failed  before transfer\n");
			return MAC_CONFIG_FAILED;
		}
	}
	return 0;
}

s32 local_host_unciast_del(struct zxdh_en_device *en_dev, struct zxdh_vf_item *src_vf_item,
			   u32 src_vf)
{
	struct dhtool_set_vf_mac_msg msg = { 0 };
	s32 ret = 0;

	memcpy(msg.mac_config.unicast_mac_array[0].mac_addr,
	       src_vf_item->vf_mac_info.unicast_mac[0].mac_addr, ETH_ALEN);
	msg.mac_config.target_vf = src_vf;
	msg.mac_config.unicast_del_count = 1;

	ret = zxdh_pf_del_vf_unicast_mac(en_dev, &msg);
	if (ret != 0) {
		LOG_ERR("del mac before transfer failed\n");
		return MAC_CONFIG_FAILED;
	}

	memset(src_vf_item->vf_mac_info.unicast_mac[0].mac_addr, 0, ETH_ALEN);
	src_vf_item->vf_mac_info.current_unicast_num--;

	return 0;
}

s32 zxdh_pf_transfer_vf_mac(struct zxdh_en_device *en_dev, u32 src_vf, u32 dst_vf)
{
	struct zxdh_vf_item *src_vf_item = NULL;
	struct zxdh_vf_item *dst_vf_item = NULL;
	struct dpp_pf_info_t src_pf_info = { 0 };
	struct dpp_pf_info_t dst_pf_info = { 0 };
	s32 ret = 0;

	if (!en_dev->ops->get_vf_is_probe(en_dev->parent, src_vf)) {
		LOG_ERR("vf(%u) is not probed\n", src_vf);
		return VF_ERROR;
	}

	if (!en_dev->ops->get_vf_is_probe(en_dev->parent, dst_vf)) {
		LOG_ERR("vf(%u) is not probed\n", dst_vf);
		return VF_ERROR;
	}

	src_vf_item = en_dev->ops->get_vf_item(en_dev->parent, src_vf);
	if (IS_ERR_OR_NULL(src_vf_item)) {
		LOG_ERR("get_vf(%u)_item failed\n", src_vf);
		return MAC_CONFIG_FAILED;
	}
	src_pf_info.slot = en_dev->slot_id;
	src_pf_info.vport = src_vf_item->vport;

	dst_vf_item = en_dev->ops->get_vf_item(en_dev->parent, dst_vf);
	if (IS_ERR_OR_NULL(dst_vf_item)) {
		LOG_ERR("get_vf(%u)_item failed\n", dst_vf);
		return MAC_CONFIG_FAILED;
	}
	dst_pf_info.slot = en_dev->slot_id;
	dst_pf_info.vport = dst_vf_item->vport;

	ret = local_host_unciast_del(en_dev, src_vf_item, src_vf);
	if (ret != 0) {
		LOG_ERR("del local mac failed\n");
		return MAC_CONFIG_FAILED;
	}

	ret = ip4_ip6_multicast_mac_del(en_dev, src_vf_item, src_vf);
	if (ret != 0) {
		LOG_ERR("ip4_ip6_multicast_mac_del failed\n");
		return MAC_CONFIG_FAILED;
	}

	mutex_lock(&src_vf_item->lock);
	mutex_lock(&dst_vf_item->lock);

	if (src_vf_item->vf_mac_info.current_multicast_num != 0) {
		ret = dpp_multicast_mac_transfer(&src_pf_info, &dst_pf_info);
		if (ret != 0) {
			LOG_ERR("dpp_multicast_mac_transfer from %u to %u failed\n", src_vf,
				dst_vf);
			mutex_unlock(&dst_vf_item->lock);
			mutex_unlock(&src_vf_item->lock);
			return MULTICAST_MAC_TRANSFER_FAILED;
		}
	}

	if (src_vf_item->vf_mac_info.current_unicast_num != 0) {
		ret = dpp_unicast_mac_transfer(&src_pf_info, &dst_pf_info);
		if (ret != 0) {
			LOG_ERR("dpp_unicast_mac_transfer from %u to %u failed\n", src_vf, dst_vf);
			mutex_unlock(&dst_vf_item->lock);
			mutex_unlock(&src_vf_item->lock);
			return UNICAST_MAC_TRANSFER_FAILED;
		}
	}

	vf_item_unicast_mac_transfer(src_vf_item, dst_vf_item);
	vf_item_multicast_mac_transfer(src_vf_item, dst_vf_item);

	memset(&src_vf_item->vf_mac_info, 0, sizeof(src_vf_item->vf_mac_info));

	LOG_DEBUG("src_vf(%u) current unicast mac num is %u\n", src_vf,
		  src_vf_item->vf_mac_info.current_unicast_num);
	LOG_DEBUG("src_vf(%u) current multicast mac num is %u\n", src_vf,
		  src_vf_item->vf_mac_info.current_multicast_num);
	LOG_DEBUG("dst_vf(%u) current unicast mac num is %u\n", dst_vf,
		  dst_vf_item->vf_mac_info.current_unicast_num);
	LOG_DEBUG("dst_vf(%u) current multicast mac num is %u\n", dst_vf,
		  dst_vf_item->vf_mac_info.current_multicast_num);

	vf_item_mac_print(src_vf_item, src_vf);
	vf_item_mac_print(dst_vf_item, dst_vf);

	mutex_unlock(&dst_vf_item->lock);
	mutex_unlock(&src_vf_item->lock);

	return MAC_CONFIG_SUCCESS;
}

s32 zxdh_en_set_vepa(struct zxdh_en_device *en_dev, bool setting)
{
	struct zxdh_vf_item *vf_item = NULL;
	bool vepa = false;
	u16 vf_idx = 0;
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	vepa = en_dev->ops->get_vepa(en_dev->parent);
	if (setting == vepa) {
		LOG_ERR("vport(0x%x) is now %s mode\n", en_dev->vport, vepa ? "vepa" : "veb");
		return 0;
	}

	en_dev->ops->set_vepa(en_dev->parent, setting);
	ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_VEPA_EN_OFF, (u32)setting);
	if (ret != 0) {
		LOG_ERR("Failed to setup vport(0x%x) %s mode, ret: %d\n", en_dev->vport,
			setting ? "vepa" : "veb", ret);
		return ret;
	}

	for (vf_idx = 0; vf_idx < ZXDH_VF_NUM_MAX; vf_idx++) {
		vf_item = en_dev->ops->get_vf_item(en_dev->parent, vf_idx);
		if (IS_ERR_OR_NULL(vf_item))
			break;

		if (vf_item->is_probed) {
			pf_info.vport = vf_item->vport;
			ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_VEPA_EN_OFF, (u32)setting);
			if (ret != 0) {
				LOG_ERR("Failed to setup vport(0x%x) %s mode, ret: %d\n",
					vf_item->vport, setting ? "vepa" : "veb", ret);
				return ret;
			}
			LOG_DEBUG("Configure vport(0x%x) to %s mode\n", vf_item->vport,
				  setting ? "vepa" : "veb");
		}
	}

	LOG_INFO("Configure vport(0x%x) to %s mode\n", en_dev->vport, setting ? "vepa" : "veb");

	return ret;
}

#ifdef HAVE_FDB_OPS
static int zxdh_en_ndo_fdb_add(struct ndmsg *ndm, struct nlattr *tb[], struct net_device *dev,
			       const unsigned char *addr, u16 vid, u16 flags,
			       struct netlink_ext_ack *extack)
{
	struct zxdh_en_priv *en_priv = netdev_priv(dev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 err = 0;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;

	LOG_DEBUG("vport is %#x\n", en_dev->vport);
	LOG_DEBUG("addr is %pM\n", addr);
	LOG_DEBUG("ndm_state is %u\n", ndm->ndm_state);

	if (ndm->ndm_state && !(ndm->ndm_state & NUD_PERMANENT)) {
		LOG_ERR("FDB only supports static addresses\n");
		return -EINVAL;
	}

	if (is_zero_ether_addr(addr)) {
		LOG_ERR("Invalid mac\n");
		return -EINVAL;
	}

	if (is_unicast_ether_addr(addr) || is_link_local_ether_addr(addr)) {
		err = unicast_mac_add(en_dev, dev, addr, flags);
		if (err != 0) {
			LOG_ERR("unicast_mac_add failed");
			return err;
		}
	} else if (is_multicast_ether_addr(addr)) {
		err = multicast_mac_add(en_dev, dev, addr, flags);
		if (err != 0) {
			LOG_ERR("multicast_mac_add failed");
			return err;
		}
	} else {
		err = -EINVAL;
	}

#ifdef MAC_CONFIG_DEBUG
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		err = zxdh_pf_dump_all_mac(en_dev);
		if (err != 0) {
			LOG_INFO("zxdh_pf_dump_all_mac failed, ret:%d\n", err);
			return -1;
		}
	}
#endif /* MAC_CONFIG_DEBUG */

	return err;
}

#ifdef HAVE_NDO_FEATURES_CHECK
static netdev_features_t zxdh_en_features_check(struct sk_buff *skb, struct net_device *dev,
						netdev_features_t features)
{
	return features;
}
#endif /* HAVE_NDO_FEATURES_CHECK */

static int zxdh_en_ndo_fdb_del(struct ndmsg *ndm, struct nlattr **nla, struct net_device *dev,
			       const unsigned char *addr, u16 vid, struct netlink_ext_ack *ack)
{
	struct zxdh_en_priv *en_priv = netdev_priv(dev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 err = 0;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;

	LOG_DEBUG("the vport is %#x", en_dev->vport);
	LOG_DEBUG("the addr is %pM\n", addr);
	LOG_DEBUG("ndm_state is %u,\n", ndm->ndm_state);

	if (!(ndm->ndm_state & NUD_PERMANENT)) {
		LOG_ERR("FDB only supports static addresses\n");
		return -EINVAL;
	}

	if (is_zero_ether_addr(addr)) {
		LOG_ERR("Invalid mac address\n");
		return -EINVAL;
	}

	if (is_unicast_ether_addr(addr) || is_link_local_ether_addr(addr)) {
		err = unicast_mac_del(en_dev, dev, addr);
		if (err != 0) {
			LOG_ERR("unicast_mac_del failed\n");
			return err;
		}
	} else if (is_multicast_ether_addr(addr)) {
		err = multicast_mac_del(en_dev, dev, addr);
		if (err != 0) {
			LOG_ERR("multicast_mac_del failed\n");
			return err;
		}
	} else {
		return -EINVAL;
	}

#ifdef MAC_CONFIG_DEBUG
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		err = zxdh_pf_dump_all_mac(en_dev);
		if (err != 0) {
			LOG_ERR("zxdh_pf_dump_all_mac failed, ret:%d\n", err);
			return -1;
		}
	}
#endif /* MAC_CONFIG_DEBUG */

	return err;
}

#ifdef HAVE_BRIDGE_ATTRIBS
static int zxdh_en_ndo_bridge_setlink(struct net_device *dev, struct nlmsghdr *nlh, u16 flags,
				      struct netlink_ext_ack *extack)
{
	struct zxdh_en_priv *en_priv = netdev_priv(dev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct nlattr *attr = NULL;
	struct nlattr *br_spec = NULL;
	s32 rem = 0;
	u16 mode = BRIDGE_MODE_UNDEF;
	bool setting = false;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return -EOPNOTSUPP;

	br_spec = nlmsg_find_attr(nlh, sizeof(struct ifinfomsg), IFLA_AF_SPEC);
	if (!br_spec)
		return -EINVAL;

	nla_for_each_nested(attr, br_spec, rem) {
		if (nla_type(attr) != IFLA_BRIDGE_MODE)
			continue;

		if (nla_len(attr) < sizeof(mode))
			return -EINVAL;

		mode = nla_get_u16(attr);
		if (mode > BRIDGE_MODE_VEPA)
			return -EINVAL;
		break;
	}

	if (mode == BRIDGE_MODE_UNDEF)
		return -EINVAL;

	setting = (mode == BRIDGE_MODE_VEPA) ? 1 : 0;

	return zxdh_en_set_vepa(en_dev, setting);
}

#ifdef HAVE_NDO_BRIDGE_GETLINK_NLFLAGS
static int zxdh_en_ndo_bridge_getlink(struct sk_buff *skb, u32 pid, u32 seq, struct net_device *dev,
				      u32 __always_unused filter_mask, int nlflags)
#elif defined(HAVE_BRIDGE_FILTER)
static int zxdh_en_ndo_bridge_getlink(struct sk_buff *skb, u32 pid, u32 seq, struct net_device *dev,
				      u32 __always_unused filter_mask)
#else
static int zxdh_en_ndo_bridge_getlink(struct sk_buff *skb, u32 pid, u32 seq, struct net_device *dev)
#endif /* NDO_BRIDGE_STUFF */
{
	struct zxdh_en_priv *en_priv = netdev_priv(dev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u8 mode = 0;
	bool vepa = false;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return -EOPNOTSUPP;

	vepa = en_dev->ops->get_vepa(en_dev->parent);
	mode = vepa ? BRIDGE_MODE_VEPA : BRIDGE_MODE_VEB;

	return ndo_dflt_bridge_getlink(skb, pid, seq, dev, mode, 0, 0, nlflags, filter_mask, NULL);
}
#endif /* HAVE_BRIDGE_ATTRIBS */
#endif /* HAVE_FDB_OPS */

static s32 zxdh_pf_notify_vf_set_link_state(struct zxdh_en_device *en_dev, int vf_idx, bool link_up)
{
	s32 retval = 0;
	u16 func_no = 0;
	u16 pf_no = FIND_PF_ID(en_dev->pcie_id);
	u8 link_info = 0;
	u8 link_up_val = 0;
	u8 phyport_val = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -ENOMEM;
	}
	msg->payload.hdr_to_agt.op_code = AGENT_DEV_STATUS_NOTIFY;
	msg->payload.hdr_to_agt.pcie_id = en_dev->pcie_id;

	func_no = GET_FUNC_NO(pf_no, vf_idx);
	LOG_DEBUG("vf_idx:%d, func_no=0x%x\n", vf_idx, func_no);
	msg->payload.pcie_msix_msg.func_no[msg->payload.pcie_msix_msg.num++] = func_no;
	if (en_dev->ops->is_bond(en_dev->parent)) {
		link_up_val = link_up ? 1 : 0;
		phyport_val = en_dev->ops->get_pf_phy_port(en_dev->parent);
		link_info = (phyport_val & 0x0F) << 4 | (link_up_val & 0x0F);
		LOG_DEBUG("phyport and link_up need write to VQM, val: 0x%x\n", link_info);
		en_dev->ops->set_vf_link_info(en_dev->parent, vf_idx, link_info);
	} else {
		en_dev->ops->set_vf_link_info(en_dev->parent, vf_idx, link_up ? 1 : 0);
	}
	LOG_DEBUG("msg->pcie_msix_msg.num:%d\n", msg->payload.pcie_msix_msg.num);
	retval = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (retval != 0)
		LOG_ERR("failed to update VF link info\n");
	kfree(msg);
	return retval;
}

static s32 zxdh_pf_set_vf_link_state(struct zxdh_en_device *en_dev, int vf_idx, int link_status)
{
	s32 retval = 0;
	struct zxdh_vf_item *vf_item = NULL;
	bool pf_link_up = en_dev->ops->get_pf_link_up(en_dev->parent);

	vf_item = en_dev->ops->get_vf_item(en_dev->parent, vf_idx);
	switch (link_status) {
	case IFLA_VF_LINK_STATE_AUTO:
		LOG_DEBUG("[SET_VF_LINK_STATE]--NDO set VF %d link state auto\n", vf_idx);
		vf_item->link_forced = FALSE;
		vf_item->link_up = pf_link_up;
		break;
	case IFLA_VF_LINK_STATE_ENABLE:
		LOG_DEBUG("[SET_VF_LINK_STATE]--NDO set VF %d link state enable\n", vf_idx);
		vf_item->link_forced = TRUE;
		vf_item->link_up = TRUE;
		break;
	case IFLA_VF_LINK_STATE_DISABLE:
		LOG_DEBUG("[SET_VF_LINK_STATE]--NDO set VF %d link state disable\n", vf_idx);
		vf_item->link_forced = TRUE;
		vf_item->link_up = FALSE;
		break;
	default:
		LOG_ERR("[SET_VF_LINK_STATE]--NDO set VF %d - invalid link status %d\n", vf_idx,
			link_status);
		return -EINVAL;
	}
	LOG_DEBUG("vf_item->is_probed: %s\n", vf_item->is_probed ? "TRUE" : "FALSE");
	if (vf_item->is_probed) {
		/* Notify the VF of its new link state */
		retval = zxdh_pf_notify_vf_set_link_state(en_dev, vf_idx, vf_item->link_up);
		if (retval) {
			LOG_ERR("[SET_VF_LINK_STATE]--Failed to set VF %d link state %d\n", vf_idx,
				vf_item->link_up);
			return retval;
		}
	}
	return retval;
}

int zxdh_en_ndo_set_vf_link_state(struct net_device *netdev, int vf_idx, int link_status)
{
	int num_vfs = 0;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct pci_dev *pdev = NULL;
	struct dh_core_dev *dh_dev = NULL;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	dh_dev = en_dev->parent;
	pdev = en_dev->ops->get_pdev(dh_dev);
	num_vfs = pci_num_vf(pdev);
	if ((vf_idx < 0) || (vf_idx >= num_vfs)) {
		LOG_ERR("[SET_VF_LINK_STATE]--NDO set VF link - invalid VF idx: %d\n", vf_idx);
		return -EINVAL;
	}
	return zxdh_pf_set_vf_link_state(en_dev, vf_idx, link_status);
}

static int zxdh_enable_sriov_vlan_tbl(struct dpp_pf_info_t *pf_info, u16 vlan_tci, u16 vlan_proto)
{
	int ret = 0;

	ret = dpp_vport_vlan_offload_en_set(pf_info, 1);
	if (ret != 0)
		return ret;

	dpp_vqm_vfid_vlan_set(pf_info, VLAN_SRIOV_VLAN_TCI, vlan_tci);

	dpp_vqm_vfid_vlan_set(pf_info, VLAN_SRIOV_VLAN_TPID, vlan_proto);

	return 0;
}

static int zxdh_disable_sriov_vlan_tbl(struct dpp_pf_info_t *pf_info)
{
	int ret = 0;

	ret = dpp_vport_vlan_offload_en_set(pf_info, 0);
	if (ret != 0)
		return ret;

	dpp_vqm_vfid_vlan_set(pf_info, VLAN_SRIOV_VLAN_TCI, 0);

	dpp_vqm_vfid_vlan_set(pf_info, VLAN_SRIOV_VLAN_TPID, 0);

	return 0;
}

static s32 zxdh_handle_mac_operations(struct dpp_pf_info_t *pf_info,
				      struct MAC_VPORT_INFO *unicast_mac_arry,
				      u32 current_unicast_num, struct zxdh_vf_item *vf_item,
				      u16 new_vlan_tci, u16 vlan_proto, int add)
{
	s32 retval = 0;
	u32 i = 0;

	for (i = 0; i < current_unicast_num; i++) {
		if (vf_item->vport == unicast_mac_arry[i].vport) {
			if (add)
				retval = dpp_add_mac(pf_info, unicast_mac_arry[i].addr,
						     htons(vlan_proto), new_vlan_tci);
			else
				retval = dpp_del_mac(pf_info, unicast_mac_arry[i].addr,
						     unicast_mac_arry[i].sriov_vlan_tpid,
						     unicast_mac_arry[i].sriov_vlan_id);

			if (retval != 0)
				return retval;
		}
	}
	return 0;
}

static s32 zxdh_pf_set_vf_port_vlan(struct zxdh_en_device *en_dev, int vf_idx, u16 vid, u8 qos,
				    u16 vlan_proto)
{
	s32 retval = 0;
	u32 i = 0;
	struct zxdh_vf_item *vf_item = NULL;
	struct dpp_pf_info_t pf_info = { 0 };
	u16 new_vlan_tci = ZXDH_VLAN_TCI_GEN(vid, qos);
	u16 old_vlan_tci = 0;
	struct MAC_VPORT_INFO *unicast_mac_arry = NULL;
	u32 current_unicast_num = 0;
	u16 current_vport = 0;
	struct zxdh_vf_item *cur_vf_item = NULL;
	struct pci_dev *pdev = NULL;
	u16 num_vfs = 0;

	pdev = en_dev->ops->get_pdev(en_dev->parent);
	num_vfs = pci_num_vf(pdev);
	if (num_vfs == 0) {
		LOG_ERR("vf is disable, vf number:%d\n", num_vfs);
		return -ENODEV;
	}

	vf_item = en_dev->ops->get_vf_item(en_dev->parent, vf_idx);
	old_vlan_tci = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);
	if (new_vlan_tci == 0)
		vlan_proto = 0;

	if (new_vlan_tci == old_vlan_tci && vf_item->vlan_proto == htons(vlan_proto))
		return 0;

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	unicast_mac_arry = kzalloc(sizeof(*unicast_mac_arry) * UNICAST_MAX_NUM, GFP_KERNEL);
	if (!unicast_mac_arry) {
		LOG_ERR("kzalloc unicast_mac_arry failed\n");
		return -ENOMEM;
	}

	mutex_lock(&vf_item->lock);
	retval = dpp_unicast_mac_dump(&pf_info, unicast_mac_arry, &current_unicast_num);
	if (retval != 0) {
		LOG_ERR("dpp_unicast_mac_dump failed, ret:%d\n", retval);
		retval = -1;
		goto out_free;
	}

	for (i = 0; i < current_unicast_num; i++) {
		if (vf_item->vport == unicast_mac_arry[i].vport) {
			retval = dpp_unicast_mac_search(&pf_info, unicast_mac_arry[i].addr,
							htons(vlan_proto), new_vlan_tci,
							&current_vport);
			if ((retval == 0) && (vf_item->vport != current_vport)) {
				LOG_ERR("modify vlan failed, Mac+vlan is exists: vport=0x%04x\n",
					current_vport);
				LOG_ERR("new_vlan_tci=%d; htons(vlan_proto)=%d\n", new_vlan_tci,
					htons(vlan_proto));
				LOG_ERR("mac = %x %x %x %x %x %x\n", unicast_mac_arry[i].addr[0],
					unicast_mac_arry[i].addr[1], unicast_mac_arry[i].addr[2],
					unicast_mac_arry[i].addr[3], unicast_mac_arry[i].addr[4],
					unicast_mac_arry[i].addr[5]);
				retval = -EEXIST;
				goto out_free;
			} else if ((retval != 0) && (retval != DPP_HASH_RC_SRH_FAIL)) {
				LOG_ERR("dpp_unicast_mac_search failed, ret:%d\n", retval);
				retval = -1;
				goto out_free;
			}
		}
	}

	if (vf_item->pf_set_mac) {
		retval = dpp_unicast_mac_search(&pf_info, vf_item->mac, htons(vlan_proto),
						new_vlan_tci, &current_vport);
		if ((retval == 0) && (current_vport != vf_item->vport)) {
			LOG_ERR("modify vlan failed [Itm Mac]+[vlan] is exists np:vport=0x%04x\n",
				current_vport);
			LOG_ERR("new_vlan_tci=%d; htons(vlan_proto)=%d\n", new_vlan_tci,
				htons(vlan_proto));
			LOG_ERR("mac = %x %x %x %x %x %x\n", vf_item->mac[0], vf_item->mac[1],
				vf_item->mac[2], vf_item->mac[3], vf_item->mac[4], vf_item->mac[5]);
			retval = -EEXIST;
			goto out_free;
		} else if ((retval != 0) && (retval != DPP_HASH_RC_SRH_FAIL)) {
			LOG_ERR("dpp_unicast_mac_search failed, ret:%d\n", retval);
			retval = -1;
			goto out_free;
		}

		for (i = 0; i < num_vfs; i++) {
			if (i == vf_idx)
				continue;
			cur_vf_item = en_dev->ops->get_vf_item(en_dev->parent, i);
			if (IS_ERR_OR_NULL(cur_vf_item)) {
				LOG_ERR("Failed to get vf_item, vf_idx:%d\n", i);
				retval = -EEXIST;
				goto out_free;
			}

			if (ether_addr_equal(cur_vf_item->mac, vf_item->mac) &&
			    ((ZXDH_VLAN_TCI_GEN(cur_vf_item->vlan, cur_vf_item->qos) ==
			      new_vlan_tci) &&
			     (cur_vf_item->vlan_proto == htons(vlan_proto)))) {
				LOG_ERR("modify vlan failed, Mac+vlan exists: vport=0x%04x\n",
					current_vport);
				LOG_ERR("new_vlan_tci=%d; htons(vlan_proto)=%d\n", new_vlan_tci,
					htons(vlan_proto));
				LOG_ERR("mac = %x %x %x %x %x %x\n", vf_item->mac[0],
					vf_item->mac[1], vf_item->mac[2], vf_item->mac[3],
					vf_item->mac[4], vf_item->mac[5]);
				retval = -EEXIST;
				goto out_free;
			}
		}
	}

	pf_info.vport = vf_item->vport;

	if (vid) {
		if (en_dev->ops->get_vf_is_probe(en_dev->parent, vf_idx)) {
			retval = zxdh_handle_mac_operations(&pf_info, unicast_mac_arry,
							    current_unicast_num, vf_item,
							    old_vlan_tci, vlan_proto, 0);
			if (retval != 0) {
				LOG_ERR("del handle mac operations failed: %d\n", retval);
				retval = -1;
				goto out_free;
			}

			retval = zxdh_handle_mac_operations(&pf_info, unicast_mac_arry,
							    current_unicast_num, vf_item,
							    new_vlan_tci, vlan_proto, 1);
			if (retval != 0) {
				LOG_ERR("add handle mac operations failed: %d\n", retval);
				retval = -1;
				goto out_free;
			}
		}

		retval = zxdh_enable_sriov_vlan_tbl(&pf_info, new_vlan_tci, htons(vlan_proto));
		if (retval != 0) {
			LOG_ERR("zxdh_enable_sriov_vlan_tbl, retval: %d\n", retval);
			retval = -1;
			goto out_free;
		}
	} else {
		if (en_dev->ops->get_vf_is_probe(en_dev->parent, vf_idx)) {
			retval = zxdh_handle_mac_operations(&pf_info, unicast_mac_arry,
							    current_unicast_num, vf_item,
							    old_vlan_tci, vlan_proto, 0);
			if (retval != 0) {
				LOG_ERR("dpp del all unicast mac failed: %d\n", retval);
				retval = -1;
				goto out_free;
			}

			retval = zxdh_handle_mac_operations(&pf_info, unicast_mac_arry,
							    current_unicast_num, vf_item, 0, 0, 1);
			if (retval != 0) {
				LOG_ERR("dpp add all unicast mac failed: %d\n", retval);
				retval = -1;
				goto out_free;
			}
		}

		retval = zxdh_disable_sriov_vlan_tbl(&pf_info);
		if (retval != 0) {
			LOG_ERR("zxdh_disable_sriov_vlan_tbl failed: %d\n", retval);
			retval = -1;
			goto out_free;
		}
	}

	vf_item->vlan = vid;
	vf_item->qos = qos;
	vf_item->vlan_proto = htons(vlan_proto);

out_free:
	mutex_unlock(&vf_item->lock);
	kfree(unicast_mac_arry);
	return retval;
}

int zxdh_en_ndo_set_vf_mac(struct net_device *netdev, int vf_id, u8 *mac)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_vf_item *vf_item = NULL;
	struct zxdh_vf_item *cur_vf_item = NULL;
	s32 retval = 0;
	u8 i = 0;
	u16 sriov_vlan_tpid = 0;
	u16 sriov_vlan_id = 0;
	u16 current_vport = 0;
	u16 num_vfs = 0;
	struct pci_dev *pdev = NULL;
	struct dpp_pf_info_t pf_info = { 0 };

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	LOG_DEBUG("[SET_VF_MAC]--setting MAC %pM on VF %d\n", mac, vf_id);
	pdev = en_dev->ops->get_pdev(en_dev->parent);
	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	num_vfs = pci_num_vf(pdev);
	if (num_vfs == 0) {
		LOG_ERR("vf is disable, vf number:%d\n", num_vfs);
		return -ENODEV;
	}

	vf_item = en_dev->ops->get_vf_item(en_dev->parent, vf_id);
	if (IS_ERR_OR_NULL(vf_item))
		return -ENODEV;

	if (is_multicast_ether_addr(mac)) {
		LOG_ERR("Invalid Ethernet address %pM for VF %d\n", mac, vf_id);
		return -EINVAL;
	}

	if (is_zero_ether_addr(mac)) {
		vf_item->pf_set_mac = false;
		ether_addr_copy(vf_item->mac, mac);
		return 0;
	}

	mutex_lock(&vf_item->lock);
	sriov_vlan_tpid = vf_item->vlan_proto;
	sriov_vlan_id = ZXDH_VLAN_TCI_GEN(vf_item->vlan, vf_item->qos);
	retval = dpp_unicast_mac_search(&pf_info, mac, sriov_vlan_tpid, sriov_vlan_id,
					&current_vport);
	if ((retval == 0) && (current_vport == vf_item->vport)) {
		mutex_unlock(&vf_item->lock);
		return 0;
	} else if ((retval == 0) && (current_vport != vf_item->vport)) {
		LOG_ERR("Mac Already exists\n");
		mutex_unlock(&vf_item->lock);
		return -EEXIST;
	} else if ((retval != 0) && (retval != DPP_HASH_RC_SRH_FAIL)) {
		LOG_ERR("dpp_unicast_mac_search failed, ret:%d\n", retval);
		mutex_unlock(&vf_item->lock);
		return -1;
	}

	for (i = 0; i < num_vfs; i++) {
		if (i == vf_id)
			continue;
		cur_vf_item = en_dev->ops->get_vf_item(en_dev->parent, i);
		if (IS_ERR_OR_NULL(cur_vf_item)) {
			LOG_ERR("Failed to get vf_item, vf_id:%d\n", i);
			mutex_unlock(&vf_item->lock);
			return -ENODEV;
		}

		if (ether_addr_equal(cur_vf_item->mac, mac) &&
		    ((ZXDH_VLAN_TCI_GEN(cur_vf_item->vlan, cur_vf_item->qos) == sriov_vlan_id) &&
		     (cur_vf_item->vlan_proto == vf_item->vlan_proto))) {
			LOG_INFO("Mac already exists vf %d\n", i);
			mutex_unlock(&vf_item->lock);
			return -EEXIST;
		}
	}

	if (!en_dev->ops->get_vf_is_probe(en_dev->parent, vf_id))
		goto set_flag;

	en_dev->ops->set_vf_mac(en_dev->parent, mac, vf_id);

set_flag:
	vf_item = en_dev->ops->get_vf_item(en_dev->parent, vf_id);
	vf_item->pf_set_mac = true;
	ether_addr_copy(vf_item->mac, mac);
	mutex_unlock(&vf_item->lock);
	return 0;
}

#ifdef IFLA_VF_VLAN_INFO_MAX
int zxdh_en_ndo_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id, u8 qos,
				 __be16 vlan_proto)
#else
int zxdh_en_ndo_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id, u8 qos)
#endif /* IFLA_VF_VLAN_INFO_MAX */
{
	int num_vfs = 0;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct pci_dev *pdev = NULL;
	struct dh_core_dev *dh_dev = NULL;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	/* Comparing with the mellnox network card, it only supports the configuration of cvlan*/
	if (vlan_proto != htons(ETH_P_8021Q) && vlan_proto != htons(ETH_P_8021AD))
		return -EPROTONOSUPPORT;

	dh_dev = en_dev->parent;
	pdev = en_dev->ops->get_pdev(dh_dev);
	num_vfs = pci_num_vf(pdev);
	if (vf_id >= num_vfs || vlan_id > MAX_VLAN_ID || qos > MAX_QOS_ID) {
		LOG_ERR("[SET+VF_VLAN]--NDO set VF vlan - invalid VF idx: %d\n", vf_id);
		return -EINVAL;
	}
	return zxdh_pf_set_vf_port_vlan(en_dev, vf_id, vlan_id, qos, vlan_proto);
}

int zxdh_en_ndo_set_vf_bw(struct net_device *netdev, int vf_id, int min_tx_rate, int max_tx_rate)
{
	return 0;
}

int zxdh_en_ndo_get_vf_config(struct net_device *netdev, int vf_idx, struct ifla_vf_info *ivi)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_vf_item *vf_item = NULL;

	vf_item = en_dev->ops->get_vf_item(en_dev->parent, vf_idx);
	if (IS_ERR_OR_NULL(vf_item)) {
		LOG_ERR("Failed to get vf_item, vf_idx:%d\n", vf_idx);
		return PTR_ERR(vf_item);
	}

	ivi->vf = vf_idx;

	ether_addr_copy(ivi->mac, vf_item->mac);

#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
	ivi->max_tx_rate = vf_item->max_tx_rate;
	ivi->min_tx_rate = vf_item->min_tx_rate;
#else
	ivi->tx_rate = vf_item->max_tx_rate;
#endif

	ivi->vlan = vf_item->vlan;
	ivi->qos = vf_item->qos;
	ivi->vlan_proto = htons(vf_item->vlan_proto);

#ifdef HAVE_NDO_SET_VF_LINK_STATE
	if (vf_item->link_forced == false)
		ivi->linkstate = IFLA_VF_LINK_STATE_AUTO;
	else if (vf_item->link_up == true)
		ivi->linkstate = IFLA_VF_LINK_STATE_ENABLE;
	else
		ivi->linkstate = IFLA_VF_LINK_STATE_DISABLE;
#endif

#ifdef HAVE_VF_SPOOFCHK_CONFIGURE
	ivi->spoofchk = vf_item->spoofchk;
#endif

#ifdef HAVE_NDO_SET_VF_TRUST
	ivi->trusted = vf_item->trusted;
#endif

	return 0;
}

int zxdh_en_ndo_set_vf_spoofchk(struct net_device *netdev, int vf_idx, bool enable)
{
	int ret = 0;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_vf_item *vf_item = NULL;
	struct dpp_pf_info_t pf_info = { 0 };

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	vf_item = en_dev->ops->get_vf_item(en_dev->parent, vf_idx);
	if (IS_ERR_OR_NULL(vf_item)) {
		LOG_ERR("Failed to get vf_item, vf_idx:%d\n", vf_idx);
		return PTR_ERR(vf_item);
	}

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = vf_item->vport;
	vf_item->spoofchk = enable;
	LOG_DEBUG("vf %d spoof check is %s\n", vf_idx, vf_item->spoofchk ? "on" : "off");
	if (vf_item->is_probed) {
		ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_SPOOFCHK_EN_OFF, enable);
		if (ret) {
			LOG_ERR("[SET_VF_SPOOFCHK]--Failed to set vf %d spookchk %s\n", vf_idx,
				enable ? "on" : "off");
			return -1;
		}
	}
	return ret;
}

#ifdef HAVE_NDO_SET_VF_TRUST
int zxdh_en_ndo_set_vf_trust(struct net_device *netdev, int vf_idx, bool setting)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_vf_item *vf_item = NULL;
	struct dpp_pf_info_t pf_info = { 0 };

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	vf_item = en_dev->ops->get_vf_item(en_dev->parent, vf_idx);
	if (IS_ERR_OR_NULL(vf_item)) {
		LOG_ERR("Failed to get vf_item, vf_idx:%d\n", vf_idx);
		return PTR_ERR(vf_item);
	}

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = vf_item->vport;
	vf_item->trusted = setting;
	LOG_DEBUG("VF %u is now %strusted\n", vf_idx, setting ? "" : "un");
	if (vf_item->is_probed && !vf_item->trusted) {
		LOG_DEBUG("vport[0x%x] promisc and allmulti off\n", vf_item->vport);
		vf_item->promisc = false;
		vf_item->mc_promisc = false;
		dpp_vport_uc_promisc_set(&pf_info, vf_item->promisc);
		dpp_vport_promisc_en_set(&pf_info, vf_item->promisc);
		dpp_vport_mc_promisc_set(&pf_info, vf_item->mc_promisc);
	}

	return 0;
}
#endif

int zxdh_en_ndo_set_tx_maxrate(struct net_device *netdev, int qid, u32 max_rate)
{
	int rtn = 0;
	struct zxdh_plcr_rate_limit_paras rate_limit_paras;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dh_core_dev *dh_dev = en_dev->parent;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev->parent);

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	PLCR_FUNC_DBG_ENTER();

	if (qid >= en_dev->curr_queue_pairs) {
		LOG_ERR("%s : invalid parameter qid=%d\n", __func__, qid);
		return -EINVAL;
	}

	rate_limit_paras.req_type = E_RATE_LIMIT_REQ_QUEUE_BYTE;
	rate_limit_paras.direction = E_RATE_LIMIT_TX;
	rate_limit_paras.mode = E_RATE_LIMIT_BYTE;
	rate_limit_paras.max_rate = max_rate;
	rate_limit_paras.min_rate = 0;
	rate_limit_paras.queue_id = qid;
	rate_limit_paras.vf_idx = PLCR_INVALID_PARAM;
	rate_limit_paras.vfid = PLCR_INVALID_PARAM;
	rate_limit_paras.group_id = PLCR_INVALID_PARAM;

	rtn = zxdh_plcr_unified_set_rate_limit(pf_dev, &rate_limit_paras);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	PLCR_LOG_INFO("The maxrate of tx-%d has been set to %dMbit/s\n", qid, max_rate);

	rtn = zxdh_vqm_vf_set_rate_limit(pf_dev, qid, 0);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}
	if (max_rate < 4000) {
		rtn = zxdh_vqm_vf_set_rate_limit(pf_dev, qid, max_rate);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}

		PLCR_LOG_INFO(
			"The Rate of VF item:%d has been set to: Max Tx Rate: %dMbit/s in vqm\n",
			qid, max_rate);
	}
	return rtn;
}

int zxdh_en_ndo_set_vf_rate(struct net_device *netdev, int vf_id, int min_tx_rate, int max_tx_rate)
{
	int rtn;
	struct zxdh_plcr_rate_limit_paras rate_limit_paras;

	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dh_core_dev *dh_dev = en_dev->parent;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev->parent);
	struct zxdh_vf_item *vf_item = NULL;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return -ENXIO;
	PLCR_FUNC_DBG_ENTER();

	rate_limit_paras.req_type = E_RATE_LIMIT_REQ_VF_BYTE;
	rate_limit_paras.direction = E_RATE_LIMIT_TX;
	rate_limit_paras.mode = E_RATE_LIMIT_BYTE;
	rate_limit_paras.max_rate = max_tx_rate;
	rate_limit_paras.min_rate = min_tx_rate;
	rate_limit_paras.queue_id = PLCR_INVALID_PARAM;
	rate_limit_paras.vf_idx = vf_id;
	rate_limit_paras.vfid = PLCR_INVALID_PARAM;
	rate_limit_paras.group_id = PLCR_INVALID_PARAM;

	vf_item = en_dev->ops->get_vf_item(en_dev->parent, vf_id);
	if (IS_ERR_OR_NULL(vf_item)) {
		LOG_ERR("Failed to get vf_item, vf_idx:%d\n", vf_id);
		return PTR_ERR(vf_item);
	}
	vf_item->min_tx_rate = min_tx_rate;
	vf_item->max_tx_rate = max_tx_rate;

	if (!en_dev->ops->get_vf_is_probe(en_dev->parent, vf_id)) {
		LOG_INFO("%s, vf %d is not probed\n", __func__, vf_id);
		return 0;
	}

	rtn = zxdh_plcr_unified_set_rate_limit(pf_dev, &rate_limit_paras);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	PLCR_LOG_INFO(
		"The Rate of VF%d has been set to: Min Tx Rate: %dMbit/s, Max Tx Rate: %dMbit/s\n",
		vf_id, min_tx_rate, max_tx_rate);

	rtn = zxdh_vqm_vf_set_rate_limit(pf_dev, vf_item->vport, 0);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}
	if (max_tx_rate < 4000) {
		rtn = zxdh_vqm_vf_set_rate_limit(pf_dev, vf_item->vport, max_tx_rate);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}

		PLCR_LOG_INFO(
			"The Rate of VF item:%d has been set to: Max Tx Rate: %dMbit/s in vqm\n",
			vf_item->vport, max_tx_rate);
	}

	return rtn;
}

const struct net_device_ops zxdh_netdev_ops = {
	.ndo_open = zxdh_en_open,
	.ndo_stop = zxdh_en_close,
	.ndo_start_xmit = zxdh_en_xmit,

	.ndo_get_stats64 = zxdh_en_get_netdev_stats_struct,
	.ndo_set_rx_mode = zxdh_en_set_rx_mode,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_mac_address = zxdh_en_set_mac,

	.ndo_change_mtu = zxdh_en_change_mtu,

	.ndo_eth_ioctl = zxdh_en_ioctl,
	.ndo_siocdevprivate = zxdh_en_private_ioctl,

#ifdef ZXDH_CONFIG_SPECIAL_SQ_EN
	.ndo_select_queue = zxdh_en_select_queue,
#endif
#ifdef ZXDH_PLCR_OPEN
	.ndo_set_tx_maxrate = zxdh_en_ndo_set_tx_maxrate,
#endif
	.ndo_tx_timeout = zxdh_en_tx_timeout,

#ifdef HAVE_VLAN_RX_REGISTER
	.ndo_vlan_rx_register = zxdh_en_vlan_rx_register,
#endif
	.ndo_vlan_rx_add_vid = zxdh_en_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = zxdh_en_vlan_rx_kill_vid,
	.ndo_bpf = zxdh_en_xdp,
	.ndo_xdp_xmit = zxdh_en_xdp_xmit,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = zxdh_en_netpoll,
#endif

#ifdef HAVE_SETUP_TC
#ifdef NETIF_F_HW_TC
	.ndo_setup_tc = __zxdh_en_setup_tc,
#else
	.ndo_setup_tc = zxdh_en_setup_tc,
#endif /* NETIF_F_HW_TC */
#endif /* HAVE_SETUP_TC */

#ifdef IFLA_VF_MAX
	.ndo_set_vf_mac = zxdh_en_ndo_set_vf_mac,
#ifdef HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SET_VF_VLAN
	.extended.ndo_set_vf_vlan = zxdh_en_ndo_set_vf_port_vlan,
#else
	.ndo_set_vf_vlan = zxdh_en_ndo_set_vf_port_vlan,
#endif
#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
#ifdef ZXDH_PLCR_OPEN
	.ndo_set_vf_rate = zxdh_en_ndo_set_vf_rate,
#else
	.ndo_set_vf_rate = zxdh_en_ndo_set_vf_bw,
#endif
#else
	.ndo_set_vf_rate = zxdh_en_ndo_set_vf_bw,
#endif
	.ndo_get_vf_config = zxdh_en_ndo_get_vf_config,
#ifdef HAVE_VF_SPOOFCHK_CONFIGURE
	.ndo_set_vf_spoofchk = zxdh_en_ndo_set_vf_spoofchk,
#endif
#ifdef HAVE_NDO_SET_VF_TRUST
#ifdef HAVE_RHEL7_NET_DEVICE_OPS_EXT
	.extended.ndo_set_vf_trust = zxdh_en_ndo_set_vf_trust,
#else
	.ndo_set_vf_trust = zxdh_en_ndo_set_vf_trust,
#endif /* HAVE_RHEL7_NET_DEVICE_OPS_EXT */
#endif /* HAVE_NDO_SET_VF_TRUST */
#endif /* IFLA_VF_MAX */

#ifdef HAVE_UDP_ENC_RX_OFFLOAD
#ifdef HAVE_VXLAN_RX_OFFLOAD
#if IS_ENABLED(CONFIG_VXLAN)
	.ndo_add_vxlan_port = zxdh_en_add_vxlan_port,
	.ndo_del_vxlan_port = zxdh_en_del_vxlan_port,
#endif
#endif /* HAVE_VXLAN_RX_OFFLOAD */

#ifdef HAVE_GENEVE_RX_OFFLOAD
#if IS_ENABLED(CONFIG_GENEVE)
	.ndo_add_geneve_port = zxdh_en_add_geneve_port,
	.ndo_del_geneve_port = zxdh_en_del_geneve_port,
#endif
#endif /* HAVE_GENEVE_RX_OFFLOAD */
#endif /* HAVE_UDP_ENC_RX_OFFLOAD */

	.ndo_set_features = zxdh_en_set_features,

#ifdef HAVE_FDB_OPS
	.ndo_fdb_add = zxdh_en_ndo_fdb_add,
	.ndo_fdb_del = zxdh_en_ndo_fdb_del,
#ifdef HAVE_NDO_FEATURES_CHECK
	.ndo_features_check = zxdh_en_features_check,
#endif /* HAVE_NDO_FEATURES_CHECK */
#ifdef HAVE_BRIDGE_ATTRIBS
	.ndo_bridge_getlink = zxdh_en_ndo_bridge_getlink,
	.ndo_bridge_setlink = zxdh_en_ndo_bridge_setlink,
#endif /* HAVE_BRIDGE_ATTRIBS */
#endif /* HAVE_FDB_OPS */

#ifdef HAVE_RHEL6_NET_DEVICE_OPS_EXT
};

/* RHEL6 keeps these operations in a separate structure */
static const struct net_device_ops_ext zxdh_netdev_ops_ext = {
	.size = sizeof(struct net_device_ops_ext),
#endif /* HAVE_RHEL6_NET_DEVICE_OPS_EXT */

#ifdef HAVE_NDO_SET_FEATURES
	.ndo_set_features = zxdh_en_set_features,
#endif /* HAVE_NDO_SET_FEATURES */

#ifdef HAVE_NDO_SET_VF_LINK_STATE
	.ndo_set_vf_link_state = zxdh_en_ndo_set_vf_link_state,
#endif
};

static void priv_flags_init(struct zxdh_en_priv *priv)
{
	priv->edev.pflags = 0;

	priv->edev.pflags |= BIT(ZXDH_PFLAG_ENABLE_LLDP);
	priv->edev.pflags |= BIT(ZXDH_PFLAG_HARDWARE_BOND_PRIMARY);
	priv->edev.pflags |= BIT(ZXDH_PFLAG_PCIE_AER_CPL_TIMEOUT);
}

static s32 get_max_num_qs(struct zxdh_en_container *en_con)
{
	if (en_con->ops->is_nic(en_con->parent) || en_con->ops->is_special_bond(en_con->parent))
		return en_con->ops->get_qpairs(en_con->parent);

	return en_con->ops->is_bond(en_con->parent) ? ZXDH_BOND_ETH_MQ_PAIRS_NUM : max_pairs;
}

static s32 fw_version_init(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;
	u8 fw_version[ETHTOOL_FWVERS_LEN] = { 0 };
	u8 fw_version_len = 0;

	ret = zxdh_en_firmware_version_get(en_dev, fw_version, &fw_version_len);
	if (ret != 0) {
		LOG_ERR("zxdh_en_firmware_version_get err, ret %d!!!!\n", ret);
		return ret;
	}
	if (fw_version_len > ETHTOOL_FWVERS_LEN) {
		LOG_ERR("fw_version_len (%d) greater than 31!!!!\n", fw_version_len);
		return -1;
	}

	fw_version[ETHTOOL_FWVERS_LEN - 1] = '\0';
	en_dev->fw_version_len = ETHTOOL_FWVERS_LEN;
	memcpy(en_dev->fw_version, (u8 *)fw_version, en_dev->fw_version_len);
	LOG_INFO("fw_version:%s\n", en_dev->fw_version);

	return 0;
}

s32 zxdh_priv_init(struct zxdh_en_priv *priv, struct net_device *netdev)
{
	s32 ret = 0;
	struct zxdh_en_device *en_dev = &priv->edev;

	mutex_init(&priv->lock);
	priv_flags_init(priv);
	en_dev->msglevel = NETIF_MSG_LINK;

	en_dev->wol_support = WAKE_MAGIC;
	en_dev->wolopts = WAKE_MAGIC;

	ret = fw_version_init(en_dev);
	if (ret != 0) {
		LOG_ERR("fw_version_init err ret: %d\n", ret);
		return ret;
	}

	return 0;
}

struct net_device *zxdh_create_netdev(struct zxdh_en_container *en_con, u16 max_vq_pairs)
{
	struct net_device *netdev = NULL;
	struct zxdh_en_priv *en_priv = NULL;
	struct dh_core_dev *dh_dev = en_con->parent;

	netdev = alloc_etherdev_mqs(sizeof(struct zxdh_en_priv), max_vq_pairs, max_vq_pairs);
	if (unlikely(!netdev)) {
		LOG_ERR("alloc_etherdev_mqs() failed\n");
		return NULL;
	}

	en_priv = netdev_priv(netdev);

	en_priv->edev.parent = dh_dev;
	en_priv->edev.ops = en_con->ops;
	en_priv->edev.netdev = netdev;

	zxdh_priv_init(en_priv, netdev);

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);
	dev_net_set(netdev, dh_core_net(dh_dev));

	return netdev;
}

void zxdh_netdev_features_init(struct net_device *netdev)
{
	netdev->features |= NETIF_F_RXCSUM | NETIF_F_HW_CSUM | NETIF_F_TSO | NETIF_F_SG |
			    NETIF_F_GSO |
			    // NETIF_F_LRO |
			    NETIF_F_TSO6 | NETIF_F_GRO | NETIF_F_HW_VLAN_STAG_FILTER |
			    NETIF_F_GSO_UDP_TUNNEL | NETIF_F_GSO_UDP_TUNNEL_CSUM | NETIF_F_RXHASH;

	netdev->hw_features |=
		NETIF_F_RXCSUM | NETIF_F_HW_CSUM | NETIF_F_TSO | NETIF_F_SG | NETIF_F_GSO |
		NETIF_F_LRO | NETIF_F_TSO6 | NETIF_F_GRO | NETIF_F_HW_VLAN_STAG_FILTER |
		NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_GSO_UDP_TUNNEL | NETIF_F_GSO_UDP_TUNNEL_CSUM |
		NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_RX |
		NETIF_F_HW_VLAN_STAG_TX | NETIF_F_RXHASH | NETIF_F_NTUPLE;

	netdev->hw_enc_features |= NETIF_F_RXCSUM | NETIF_F_HW_CSUM | NETIF_F_GSO_UDP_TUNNEL_CSUM |
				   NETIF_F_GSO_UDP_TUNNEL | NETIF_F_TSO | NETIF_F_TSO6;

	netdev->vlan_features = NETIF_F_RXCSUM | NETIF_F_HW_CSUM | NETIF_F_GRO | NETIF_F_TSO |
				NETIF_F_SG | NETIF_F_TSO6 | NETIF_F_GSO_UDP_TUNNEL |
				NETIF_F_GSO_UDP_TUNNEL_CSUM | NETIF_F_LRO | NETIF_F_RXHASH;
}

extern const struct xfrmdev_ops zxdh_xfrmdev_ops;
static void zxdh_build_nic_netdev(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct dh_core_dev *dh_dev = en_priv->edev.parent;

	SET_NETDEV_DEV(netdev, &dh_dev->parent->pdev->dev);

	netdev->netdev_ops = &zxdh_netdev_ops;

#ifdef ZXDH_SEC

	netdev->features |= NETIF_F_HW_ESP;
	netdev->xfrmdev_ops = &zxdh_xfrmdev_ops;
#endif

#ifdef HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT
	zxdh_en_set_ethtool_ops_ext(netdev);
#else
	zxdh_en_set_ethtool_ops(netdev);
#endif /* HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT */

	zxdh_netdev_features_init(netdev);
}

s32 zxdh_en_bond_get_mac(struct net_device *netdev, u8 pannel_id, u8 *mac)
{
	s32 ret = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return -1;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_FLASH_MAC_READ;
	msg->payload.flash_read_msg.index = pannel_id;

	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_FLASH, msg, msg, &para);
	if (ret != 0) {
		LOG_ERR("en_dev->ops->msg_send_cmd failed: %d\n", ret);
		kfree(msg);
		return ret;
	}

	LOG_INFO("bond get mac %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		 msg->reps.flash_mac_read_msg.mac[0], msg->reps.flash_mac_read_msg.mac[1],
		 msg->reps.flash_mac_read_msg.mac[2], msg->reps.flash_mac_read_msg.mac[3],
		 msg->reps.flash_mac_read_msg.mac[4], msg->reps.flash_mac_read_msg.mac[5]);

	ether_addr_copy(mac, msg->reps.flash_mac_read_msg.mac);
	kfree(msg);
	return ret;
}

s32 zxdh_mac_addr_init(struct net_device *netdev)
{
	u8 mac[6] = { 0 };
	u8 pannel_id = 0;
	s32 ret = 0;
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->ops->is_bond(en_dev->parent)) {
		pannel_id = en_dev->pannel_id;
		ret = zxdh_en_bond_get_mac(netdev, pannel_id, mac);
		if (ret != 0)
			LOG_ERR("zxdh_en_bond_mac_get failed: %d\n", ret);
	} else {
		en_dev->ops->get_mac(en_dev->parent, mac);
	}

	if (!is_valid_ether_addr(mac)) {
		get_random_bytes(mac, 6);
		mac[0] &= 0xfe;
		LOG_INFO("set random mac %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0], mac[1], mac[2],
			 mac[3], mac[4], mac[5]);
	}
	LOG_INFO("set mac %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0], mac[1], mac[2], mac[3], mac[4],
		 mac[5]);
	zxdh_netdev_addr_set(netdev, mac);

	return ret;
}

s32 zxdh_status_init(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->ops->if_init(en_dev->parent))
		zxdh_vp_reset(netdev);

	/* Disable VQ/configuration callbacks. */
	zxdh_vp_disable_cbs(netdev);

	zxdh_add_status(netdev, ZXDH_CONFIG_S_ACKNOWLEDGE);

	zxdh_add_status(netdev, ZXDH_CONFIG_S_DRIVER);

	/* fix features, not set features*/
	zxdh_pf_features_init(netdev);

	might_sleep();
	zxdh_add_status(netdev, ZXDH_CONFIG_S_FEATURES_OK);
	if (!zxdh_has_status(netdev, ZXDH_CONFIG_S_FEATURES_OK)) {
		LOG_ERR("device refuses features ok\n");
		return -ENODEV;
	}

	return 0;
}

void zxdh_device_ready(struct net_device *netdev)
{
	zxdh_vp_enable_cbs(netdev);

	zxdh_add_status(netdev, ZXDH_CONFIG_S_DRIVER_OK);
}

void zxdh_link_state_notify_kernel(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->link_up) {
		netif_carrier_off(netdev);
		udelay(10);
		netif_carrier_on(netdev);
	} else {
		netif_carrier_on(netdev);
		udelay(10);
		netif_carrier_off(netdev);
	}
}

s32 aux_get_bond_attrs(struct zxdh_en_device *en_dev, struct zxdh_lag_attrs *attr)
{
	*attr = (struct zxdh_lag_attrs){
		.pannel_id = en_dev->pannel_id,
		.vport = en_dev->vport,
		.slot_id = en_dev->slot_id,
		.qid[0] = en_dev->phy_index[0],
		.qid[1] = en_dev->phy_index[1],
		.pcie_id = en_dev->pcie_id,
		.phy_port = en_dev->phy_port,
	};

	LOG_INFO("bond pf: pannel %hu, vport 0x%hx, phy_qid[0] %u, phy_qid[1] %u, pcie id 0x%x\n",
		 attr->pannel_id, attr->vport, attr->qid[0], attr->qid[1], attr->pcie_id);

	return 0;
}

void aux_set_netdev_name(struct net_device *netdev, u16 pannel_id)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dh_core_dev *dh_dev = en_dev->parent;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev->parent);

	if (en_dev->ops->is_bond(en_dev->parent)) {
		netdev->dev_port = pannel_id + 1;
	} else if ((pf_dev->board_type == DH_STDA) || (pf_dev->board_type == DH_STD_E312S) ||
		   (pf_dev->board_type == DH_STD_E312S_D)) {
		if (!en_dev->is_multi_ep)
			return;

		netdev->dev_id = ((en_dev->pcie_id & 0xFF) | ((en_dev->panel_id & 0x01) << 8)) &
				 ~(1 << 9);

		netdev->dev_id |= ((en_dev->pcie_id & (1 << 11)) >> 2);
		LOG_INFO("board_type: %d,netdev->dev_id: %#x\n", pf_dev->board_type,
			 netdev->dev_id);
	}
}

s32 ptp_set_pf_uplink_vfid(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	en_dev->vf_1588_call_np_num = PTP_PORT_VFID_SET;
	LOG_INFO("vport: 0x%x, IS_PF: %d VFID %u", en_dev->vport, IS_PF(en_dev->vport),
		 VQM_VFID(en_dev->vport));
	if (IS_PF(en_dev->vport)) {
		ret = dpp_ptp_port_vfid_set(&pf_info, VQM_VFID(en_dev->vport));
		if (ret != 0) {
			LOG_ERR("dpp_ptp_port_vfid_set failed!!!\n");
			return -1;
		}
	}
	return 0;
}

s32 ptp_set_pf_tc_enable(struct zxdh_en_device *en_dev, u32 tc_enable)
{
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	en_dev->ptp_tc_enable_opt = tc_enable;
	LOG_DEBUG("ptp_tc_enable_opt = %u\n", en_dev->ptp_tc_enable_opt);

	en_dev->vf_1588_call_np_num = PTP_TC_ENABLE_SET;

	if (IS_PF(en_dev->vport)) {
		ret = dpp_ptp_tc_enable_set(&pf_info, en_dev->ptp_tc_enable_opt);
		if (ret != 0) {
			LOG_ERR("dpp_ptp_tc_enable_set failed!!!\n");
			return -1;
		}
	}
	return 0;
}

s32 zxdh_en_mtu_init(struct net_device *netdev)
{
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = ZXDH_MAX_MTU;

	return zxdh_en_config_mtu_to_np(netdev, ZXDH_DEFAULT_MTU);
}

void zxdh_cap_pkt_init(struct zxdh_en_device *en_dev)
{
	en_dev->pkt_save_file.log_file = NULL;
	en_dev->pkt_save_file.enable_pkt_num_mode = 0;
	en_dev->pkt_save_file.pkt_file_size = 0;
	en_dev->pkt_save_file.pkt_set_count = 0;
	en_dev->pkt_save_file.is_stop = 0;
	en_dev->pkt_save_file.pkt_rbuf_idx = 0;
	en_dev->pkt_save_file.ubuf_idx = 0;
	en_dev->pkt_save_file.pkt_cur_num = 0;
	memset(en_dev->pkt_save_file.file_path, 0, sizeof(en_dev->pkt_save_file.file_path));
	en_dev->pkt_save_file.file_pos = 0;
	en_dev->pkt_save_file.total_written_bytes = 0;
	en_dev->pkt_dev_flag = 0;
	en_dev->pkt_dev_speed = ZXDH_PKT_INIT_SPEED;
	en_dev->pkt_file_num = 0;
	en_dev->pkt_cap_switch = 0;
	en_dev->pkt_save_file_flag = 0;
	en_dev->pkt_addr_marked = 0;
}

s32 zxdh_hash_id_init(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;

	if (en_dev->ops->get_dev_type(en_dev->parent) == ZXDH_DEV_UPF) {
		en_dev->hash_search_idx = 2;
	} else if (en_dev->ops->get_dev_type(en_dev->parent) == ZXDH_DEV_NE0) {
		en_dev->hash_search_idx = 0;
	} else if (en_dev->ops->get_dev_type(en_dev->parent) == ZXDH_DEV_NE1) {
		en_dev->hash_search_idx = 1;
	} else if (!en_dev->ops->is_bond(en_dev->parent)) {
		ret = zxdh_hash_id_get(en_dev);
		if (ret != 0) {
			LOG_ERR("zxdh_hash_id_get failed: %d\n", ret);
			return -1;
		}
	}

	return 0;
}

u32 pcie_id2vfid_for_pf(u16 pcie_id)
{
	u8 ep_id = (pcie_id >> 12) & 0x7;
	u8 pf_id = (pcie_id >> 8) & 0x7;

	return (ep_id * 8 + pf_id + 1152);
}

void zxdh_cfg_vqm_vf_fc_kbps(struct zxdh_en_device *en_dev, u32 pf_fc_val)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(en_dev->parent->parent);
	u32 vqm_vfid = 0xffff;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return;
	}
	vqm_vfid = pcie_id2vfid_for_pf(pf_dev->pcie_id);
	if (vqm_vfid >= 0xffff) {
		LOG_ERR("vfid(%u) is invalid!\n", vqm_vfid);
		kfree(msg);
		return;
	}
	msg->vqm_msg.vqm_vfid = (u16)vqm_vfid;
	msg->vqm_msg.opcode = OPCODE_SET;
	msg->vqm_msg.cmd = VQM_VF_FC_CMD;
	msg->vqm_msg.vqm_vf_fc.pps = 0;
	msg->vqm_msg.vqm_vf_fc.kbps = pf_fc_val;
	err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_CFG_VQM, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("send vf fc msg to riscv failed!\n");
	} else {
		if (msg->vqm_reps.check_result != 0xaa)
			pr_err("cfg vqm vf(%u) rate %ukbps failed!\n", vqm_vfid, pf_fc_val);
		else
			pr_info("cfg vqm vf(%u) rate %ukbps success.\n", vqm_vfid, pf_fc_val);
	}
	kfree(msg);
}

void zxdh_set_pf_fc(struct zxdh_en_device *en_dev)
{
	u32 pf_fc_val = 0;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return;

	if (en_dev->ops->is_pf_rate_enable(en_dev->parent, &pf_fc_val)) {
		LOG_INFO("pf rate: %uMbps\n", pf_fc_val);
		if (pf_fc_val == KERNEL_PF_FC || pf_fc_val == KERNEL_PF_FC_1)
			zxdh_cfg_vqm_vf_fc_kbps(en_dev, pf_fc_val * 1000);
	} else {
		LOG_INFO("pf rate: disable\n");
	}
}

void zxdh_del_pf_fc(struct zxdh_en_device *en_dev)
{
	u32 pf_fc_val = 0;

	if (en_dev->quick_remove)
		return;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF)
		return;

	if (en_dev->ops->is_pf_rate_enable(en_dev->parent, &pf_fc_val)) {
		if (pf_fc_val == KERNEL_PF_FC || pf_fc_val == KERNEL_PF_FC_1)
			zxdh_cfg_vqm_vf_fc_kbps(en_dev, 0);
	}
}

static void enable_1588_init(struct zxdh_en_device *en_dev)
{
	union zxdh_msg *msg = NULL;
	s32 ret = 0;
	struct zxdh_bar_extra_para para = { 0 };
	struct dpp_pf_info_t dpp_pf_info = {
		.slot = en_dev->slot_id,
		.vport = en_dev->vport,
	};

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	en_dev->enable_1588 = false;
	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
		if (!msg) {
			LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
			return;
		}

		msg->payload.vf_1588_enable.proc_cmd = ZXDH_VF_1588_ENABLE_SET;
		msg->payload.hdr.op_code = ZXDH_VF_1588_ENABLE;
		msg->payload.hdr.vport = en_dev->vport;
		msg->payload.hdr.pcie_id = en_dev->pcie_id;
		msg->payload.vf_1588_enable.enable_1588_vf = (u32) false;
		ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						&para);
		if (ret != 0) {
			LOG_ERR("zxdh_send_command_to_pf failed: %d\n", ret);
			kfree(msg);
			return;
		}

		kfree(msg);
		return;
	}

	ret = dpp_vport_attr_set(&dpp_pf_info, SRIOV_VPORT_1588_EN, (u32) false);
	if (ret != 0) {
		LOG_ERR("dpp_vport_attr_set SRIOV_VPORT_1588_EN failed, ret:%d\n", ret);
		return;
	}
}

static s32 zxdh_en_dev_probe(struct zxdh_auxiliary_device *adev,
			     const struct zxdh_auxiliary_device_id *id)
{
	struct zxdh_en_container *en_container = container_of(adev, struct zxdh_en_container, adev);
	struct net_device *netdev = NULL;
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_lag_attrs lag_attrs;
	s32 err = 0;
	s32 vqs_channel_num = 0;
	u32 phcidx = 0xff;
	u16 max_vq_pairs = 0;
	u8 link_up = 0;
	u8 carrier_status = 0;

	LOG_INFO("aux level start\n");
	mutex_lock(&en_container->parent->lock);

	max_vq_pairs = get_max_num_qs(en_container);
	netdev = zxdh_create_netdev(en_container, max_vq_pairs);
	if (unlikely(!netdev)) {
		LOG_ERR("zxdh_create_netdev is null\n");
		err = -ENOMEM;
		goto err_create_netdev;
	}

	zxdh_build_nic_netdev(netdev);

	dev_set_drvdata(&adev->dev, netdev_priv(netdev));

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;
	en_dev->dmadev = en_dev->ops->get_dma_dev(en_dev->parent);
	en_dev->channels_num = en_dev->ops->get_channels_num(en_dev->parent);
	en_dev->ops->set_rdma_netdev(en_dev->parent, netdev);
	en_dev->curr_unicast_num = 1;
	en_dev->curr_multicast_num = 0;
	en_dev->init_comp_flag = AUX_INIT_INCOMPLETED;
	en_dev->delay_statistics_enable = 0;
	en_dev->phy_port = INVALID_PHY_PORT;
	en_dev->link_down_on_close = false;
	en_dev->time_sync_done = false;

	en_dev->max_vq_pairs = max_vq_pairs;
#ifdef CONFIG_INET
	en_dev->local_lb_enable = false;
#endif
	en_dev->board_type = en_dev->ops->get_board_type(en_dev->parent);

	vqs_channel_num = en_dev->ops->create_vqs_channels(en_dev->parent, en_dev);
	if (vqs_channel_num < 0) {
		LOG_ERR("create_vqs_channels failed, vqs_channel_num: %d\n", vqs_channel_num);
		err = vqs_channel_num;
		goto err_create_vqs_channels;
	}

	err = dh_aux_eq_table_init(en_priv);
	if (err != 0) {
		LOG_ERR("Failed to alloc IRQs: %d\n", err);
		goto err_eq_table_init;
	}

	err = dh_aux_events_init(en_priv);
	if (err != 0) {
		LOG_ERR("dh_aux_events_init failed: %d\n", err);
		goto err_events_init;
	}

	err = dh_aux_eq_table_create(en_priv);
	if (err != 0) {
		LOG_ERR("Failed to alloc EQs: %d\n", err);
		goto err_eq_table_create;
	}

	err = zxdh_status_init(netdev);
	if (err != 0) {
		LOG_ERR("zxdh_status_init failed: %d\n", err);
		goto err_status_init;
	}

	en_dev->ep_bdf = en_dev->ops->get_epbdf(en_dev->parent);
	en_dev->vport = en_dev->ops->get_vport(en_dev->parent);
	en_dev->pcie_id = en_dev->ops->get_pcie_id(en_dev->parent);
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF)
		en_dev->slot_id = en_dev->ops->get_slot_id(en_dev->parent);
	LOG_INFO("ep_bdf: 0x%x, vport: 0x%x, pcie_id: %d, slot_id: %d. is_bond %d\n",
		 en_dev->ep_bdf, en_dev->vport, en_dev->pcie_id, en_dev->slot_id,
		 en_dev->ops->is_bond(en_dev->parent));
	if (!en_dev->ops->is_bond(en_dev->parent)) {
		en_dev->spec_sbdf = en_dev->ops->get_spec_sbdf(en_dev->parent);
		en_dev->is_hwbond =
			en_dev->ops->is_hwbond(en_dev->parent, en_dev->is_hwbond, FALSE);
		en_dev->is_rdma_aux_plug = en_dev->ops->is_rdma_aux_plug(
			en_dev->parent, en_dev->is_rdma_aux_plug, FALSE);
		en_dev->is_primary_port = en_dev->ops->is_primary_port(
			en_dev->parent, en_dev->is_primary_port, FALSE);
		en_dev->is_multi_ep = en_dev->ops->is_multi_ep(en_dev->parent);
		ZXDH_SET_PFLAG(en_dev->pflags, ZXDH_PFLAG_HARDWARE_BOND, en_dev->is_hwbond ? 1 : 0);
		ZXDH_SET_PFLAG(en_dev->pflags, ZXDH_PFLAG_HARDWARE_BOND_PRIMARY,
			       en_dev->is_primary_port ? 1 : 0);
	}
#ifdef ZXDH_MSGQ
	if (IS_MSGQ_DEV(en_dev))
		en_dev->need_msgq = true;
#endif
	en_dev->eth_config.rx_queue_size = ZXDH_PF_DEFAULT_DESC_NUM(en_dev);
	en_dev->eth_config.tx_queue_size = ZXDH_PF_DEFAULT_DESC_NUM(en_dev);

	zxdh_set_pf_fc(en_dev);

	err = zxdh_vqs_init(netdev);
	if (err != 0) {
		LOG_ERR("zxdh_vqs_init failed: %d\n", err);
		goto err_vqs_init;
	}

	if (en_dev->ops->is_drs_sec_enable(en_dev->parent)) {
		err = zxdh_sec_vqs_init(netdev);
		if (err != 0) {
			LOG_ERR("zxdh_sec_vqs_init failed\n");
			goto err_sec_vqs_init;
		}
	}

	err = zxdh_hash_id_init(en_dev);
	if (err != 0) {
		LOG_ERR("zxdh_hash_id_init failed: %d\n", err);
		goto err_do_vqs_free;
	}

	err = zxdh_panel_id_init(en_dev);
	if (err != 0) {
		LOG_ERR("zxdh_panel_id_init failed: %d\n", err);
		goto err_do_vqs_free;
	}
	en_dev->eth_config.hash_func = ZXDH_FUNC_CRC32;
	en_dev->eth_config.hash_mode = ZXDH_NET_RX_FLOW_HASH_SDFNT;
	en_dev->eth_config.curr_combined = en_dev->curr_queue_pairs;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		zxdh_cap_pkt_init(en_dev);
		if (en_dev->ops->is_bond(en_dev->parent)) {
			err = zxdh_aux_alloc_pannel(en_dev);
			if (err != 0) {
				LOG_ERR("zxdh_aux_alloc_pannel failed: %d\n", err);
				goto err_do_vqs_free;
			}
		} else if (zxdh_en_is_panel_port(en_dev)) {
			err = zxdh_phyport_get(en_dev);
			if (err != 0) {
				LOG_ERR("zxdh_phyport_get failed: %d\n", err);
				goto err_do_vqs_free;
			}
		}

		err = zxdh_mac_addr_init(netdev);
		if (err != 0) {
			LOG_ERR("zxdh_mac_addr_init failed: %d\n", err);
			goto err_mac_addr_init;
		}

		en_dev->wolopts = WAKE_MAGIC;
		err = zxdh_pf_port_init(en_dev, true);
		if (err != 0) {
			LOG_ERR("zxdh_pf_port_init failed: %d\n", err);
			goto err_mac_addr_init;
		}
	} else {
		err = zxdh_vf_dpp_port_init(en_dev);
		if (err != 0) {
			LOG_ERR("zxdh_vf_dpp_port_init failed: %d\n", err);
			goto err_mac_addr_init;
		}
	}
	enable_1588_init(en_dev);

	if (!en_dev->ops->is_bond(en_dev->parent)) {
		netdev->priv_flags &= ~IFF_RXFH_CONFIGURED;
		err = zxdh_num_channels_changed(en_dev, en_dev->curr_queue_pairs);
		if (err != 0) {
			LOG_ERR("zxdh_num_channels_changed failed: %d\n", err);
			goto err_do_vport_free;
		}

		err = zxdh_en_sync_features(en_dev, netdev->features);
		ZXDH_CHECK_RET_GOTO_ERR(err, err_do_rxfh_free, "zxdh_en_sync_features failed: %d\n",
					err);
	}

	zxdh_device_ready(netdev);

	err = zxdh_en_mtu_init(netdev);
	if (err != 0) {
		LOG_ERR("zxdh_en_mtu_init failed: %d\n", err);
		goto err_do_rxfh_free;
	}

	en_dev->hw_stats.q_stats =
		kmalloc_array(en_dev->max_vq_pairs, sizeof(struct zxdh_en_queue_stats), GFP_KERNEL);
	if (unlikely(!en_dev->hw_stats.q_stats)) {
		LOG_ERR("hw_stats.q_stats kmalloc failed\n");
		goto err_do_rxfh_free;
	}
	memset(en_dev->hw_stats.q_stats, 0,
	       en_dev->max_vq_pairs * sizeof(struct zxdh_en_queue_stats));

	if (!en_dev->ops->is_bond(en_dev->parent)) {
		err = zxdh_hardware_bond_init(netdev);
		if (err != 0) {
			LOG_ERR("zxdh_hardware_bond_init failed, %d\n", err);
			goto err_hardware_bond_init;
		}
	}

	memset(&en_dev->pre_stats, 0, sizeof(struct zxdh_en_vport_stats));
	en_dev->last_tx_vport_ssvpc_packets = 0;

	err = zxdh_en_vport_pre_stats_get(en_dev);
	if (err != 0)
		LOG_ERR("get vport pre stats failed, %d\n", err);

	aux_set_netdev_name(netdev, en_dev->pannel_id);
	err = register_netdev(netdev);
	if (err != 0) {
		LOG_ERR("register_netdev failed, %d\n", err);
		goto err_register_netdev;
	}

	zxdh_link_state_notify_kernel(netdev);

	if (en_dev->ops->is_bond(en_dev->parent)) {
		aux_get_bond_attrs(en_dev, &lag_attrs);
		err = zxdh_ldev_add_netdev(en_container->parent, en_dev->pannel_id, netdev,
					   &lag_attrs);
		if (err != 0)
			goto err_ldev_add_netdev;
	}

#ifdef ZXDH_PLCR_OPEN
	err = zxdh_plcr_init(en_priv);
	if (err != 0)
		LOG_ERR("zxdh_plcr_init failed, %d\n", err);
#endif

	err = dh_aux_vxlan_netdev_notifier_init(en_priv);
	if (err != 0) {
		LOG_ERR("dh_aux_vxlan_netdev_notifier_init failed: %d\n", err);
		goto err_vxlan_netdev_notifier_init;
	}

	err = dh_aux_ipv6_notifier_init(en_priv);
	if (err != 0) {
		LOG_ERR("dh_aux_ipv6_notifier_init failed: %d\n", err);
		goto err_ipv6_notifier_init;
	}
#ifdef ZXDH_MSGQ
	if (NEED_MSGQ(en_dev)) {
		err = zxdh_msgq_init(en_dev);
		if (err) {
			LOG_ERR("zxdh_msgq_init failed: %d\n", err);
			goto err_msgq_init;
		}
	}
#endif

	if ((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) &&
	    (zxdh_en_is_panel_port(en_dev))) {
		zxdh_dcbnl_set_tm_pport_mcode_gate_close(netdev);
#ifdef ZXDH_DCBNL_OPEN
		err = zxdh_dcbnl_initialize(netdev);
		if (err != 0)
			LOG_ERR("zxdh_dcbnl_initialize failed: %d\n", err);
#endif
	}

	en_dev->ops->set_bond_num(en_dev->parent, true);

	en_dev->init_comp_flag = AUX_INIT_COMPLETED;
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		en_dev->autoneg_enable = AUTONEG_ENABLE;
		err = zxdh_en_phyport_init(en_dev);
		if (err != 0) {
			LOG_ERR("zxdh_en_phyport_init failed: %d\n", err);
			goto err_phyport_init;
		}
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		if (zxdh_get_ptp_clock_index(en_dev, &phcidx))
			LOG_ERR("%s: aux dev get phc fail\n", netdev->name);
		en_dev->clock_no = phcidx;
		if (!en_dev->ops->is_bond(en_dev->parent)) {
			if (ptp_set_pf_uplink_vfid(en_dev))
				LOG_ERR("%s: set ptp l2 vfid fail\n", netdev->name);

			if (ptp_set_pf_tc_enable(en_dev, 0))
				LOG_ERR("%s: set tc enable fail\n", netdev->name);
		}
	}

	en_dev->ops->set_init_comp_flag(en_dev->parent, 1);
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) {
		carrier_status = netif_carrier_ok(en_dev->netdev) ? 1 : 0;
		en_dev->ops->get_link_info_from_vqm(en_dev->parent, &link_up);
		link_up = link_up == 0 ? 0 : 1;
		LOG_INFO("VF device: %s vqm_link_state %d vs kernel_link_state %d\n",
			 pci_name(en_dev->ops->get_pdev(en_dev->parent)), link_up, carrier_status);
		if (link_up != carrier_status) {
			LOG_INFO(
				"VF device: %s vqm_link_state %d not equal to kernel_link_state %d\n",
				pci_name(en_dev->ops->get_pdev(en_dev->parent)), link_up,
				carrier_status);
			dh_eq_async_link_info_int_process(en_priv);
		}
	}
	card_num++;

	dh_ip_mac_init(en_priv);
	mutex_unlock(&en_container->parent->lock);
	LOG_INFO("%s: aux level completed\n", netdev->name);

	return 0;

err_phyport_init:
	en_dev->ops->set_bond_num(en_dev->parent, false);
#ifdef ZXDH_DCBNL_OPEN
	zxdh_dcbnl_ets_uninit(netdev);
#endif
#ifdef ZXDH_MSGQ
	if (NEED_MSGQ(en_dev))
		zxdh_msgq_exit(en_dev);
err_msgq_init:
#endif
	dh_inet6_addr_change_notifier_unregister(&(en_dev->ipv6_notifier));
err_ipv6_notifier_init:
	dh_vxlan_netdev_change_notifier_unregister(&(en_dev->vxlan_notifier));
err_vxlan_netdev_notifier_init:
#ifdef ZXDH_PLCR_OPEN
	zxdh_plcr_uninit(en_priv);
#endif
	if (en_dev->ops->is_bond(en_dev->parent)) {
		aux_get_bond_attrs(en_dev, &lag_attrs);
		zxdh_ldev_remove_netdev(en_dev->parent, netdev, &lag_attrs);
	}
err_ldev_add_netdev:
	unregister_netdev(netdev);
err_register_netdev:
	if (!en_dev->ops->is_bond(en_dev->parent))
		zxdh_hardware_bond_uninit(netdev);
err_hardware_bond_init:
	kfree(en_dev->hw_stats.q_stats);
err_do_rxfh_free:
	if (!en_dev->ops->is_bond(en_dev->parent))
		zxdh_rxfh_del(en_dev);
err_do_vport_free:
	zxdh_vport_uninit(netdev);
err_mac_addr_init:
	if (en_dev->ops->is_bond(en_dev->parent))
		en_dev->ops->release_port(en_dev->parent, en_dev->pannel_id);
err_do_vqs_free:
	if (en_dev->ops->is_drs_sec_enable(en_dev->parent))
		zxdh_sec_vqs_uninit(netdev, ZXDH_SEC_QUEUES_NUM(en_dev));
err_sec_vqs_init:
	zxdh_vqs_uninit(netdev);
err_vqs_init:
	zxdh_del_pf_fc(en_dev);
	zxdh_add_status(netdev, ZXDH_CONFIG_S_FAILED);
err_status_init:
	dh_aux_eq_table_destroy(en_priv);
err_eq_table_create:
	dh_aux_events_uninit(en_priv);
err_events_init:
	dh_aux_eq_table_cleanup(en_priv);
err_eq_table_init:
	en_dev->ops->destroy_vqs_channels(en_dev->parent);
err_create_vqs_channels:
	free_netdev(netdev);
err_create_netdev:
	mutex_unlock(&en_container->parent->lock);
	return -EPERM;
}

static s32 eth_pflags_config_recover(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u8 i = 0;
	s32 err = 0;

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF)
		return 0;

	ZXDH_SET_PFLAG(en_dev->pflags, ZXDH_PFLAG_ENABLE_SSHD, 0);
	ZXDH_SET_PFLAG(en_dev->pflags, ZXDH_PFLAG_IP, 0);
	err = zxdh_dual_tor_label_get(en_dev);
	if (err == 1)
		en_dev->pflags |= BIT(ZXDH_PFLAG_DUAL_TOR_CTRL);
	else if (err == 0)
		en_dev->pflags &= ~BIT(ZXDH_PFLAG_DUAL_TOR_CTRL);

	for (i = 0; i < ZXDH_NUM_PFLAGS; ++i) {
		if (i == ZXDH_PFLAG_ENABLE_SSHD || i == ZXDH_PFLAG_ETS_SWITCH ||
		    i == ZXDH_PFLAG_PCIE_AER_CPL_TIMEOUT || i == ZXDH_PFLAG_PCIE_HP_IRQ_CTRL)
			continue;
		err = zxdh_pflags_update(netdev, i, en_dev->pflags & BIT(i));
		if (err) {
			HEAL_ERR("%s zxdh_pflags_update[%d] failed: %d\n", netdev->name, i, err);
			return err;
		}
	}

	return 0;
}

static void zxdh_init_stats(struct zxdh_en_device *en_dev)
{
	s32 err = 0;
	s32 i = 0;

	memset(&en_dev->hw_stats.netdev_stats, 0, sizeof(struct zxdh_en_netdev_stats));
	memset(&en_dev->hw_stats.vport_stats, 0, sizeof(struct zxdh_en_vport_stats));
	memset(&en_dev->hw_stats.phy_stats, 0, sizeof(struct zxdh_en_phy_stats));
	memset(&en_dev->hw_stats.udp_stats, 0, sizeof(struct zxdh_en_udp_phy_stats));
	memset(&en_dev->pre_stats, 0, sizeof(struct zxdh_en_vport_stats));
	memset(en_dev->hw_stats.q_stats, 0,
	       en_dev->max_vq_pairs * sizeof(struct zxdh_en_queue_stats));
	en_dev->last_tx_vport_ssvpc_packets = 0;

	err = zxdh_en_vport_pre_stats_get(en_dev);
	if (err != 0)
		LOG_ERR("get vport pre stats failed, %d\n", err);

	for (i = 0; i < en_dev->max_queue_pairs; i++) {
		memset(&en_dev->rq[i].stats, 0, sizeof(struct virtnet_rq_stats));
		memset(&en_dev->sq[i].stats, 0, sizeof(struct virtnet_sq_stats));
	}
}

s32 zxdh_aux_load(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct net_device *netdev = en_dev->netdev;
	struct zxdh_lag_attrs lag_attrs;
	s32 err = 0;
	s32 vqs_channel_num = 0;

	LOG_INFO("%s aux level load start\n", netdev->name);

	mutex_lock(&en_dev->parent->lock);
	if (en_dev->parent->driver_process == ZXDH_REMOVE)
		goto unlock;

	vqs_channel_num = en_dev->ops->create_vqs_channels(en_dev->parent, en_dev);
	if (vqs_channel_num < 0) {
		HEAL_ERR("%s create_vqs_channels failed, vqs_channel_num: %d\n", netdev->name,
			 vqs_channel_num);
		goto unlock;
	}

	err = dh_aux_eq_table_create(en_priv);
	if (err != 0) {
		HEAL_ERR("%s Failed to alloc EQs: %d\n", netdev->name, err);
		goto err_eq_table_create;
	}

	err = zxdh_status_init(netdev);
	if (err != 0) {
		HEAL_ERR("%s zxdh_status_init failed: %d\n", netdev->name, err);
		goto err_status_init;
	}

	zxdh_set_pf_fc(en_dev);
	err = zxdh_vqs_init(netdev);
	if (err != 0) {
		HEAL_ERR("%s zxdh_vqs_init failed: %d\n", netdev->name, err);
		goto err_vqs_init;
	}

	if (en_dev->ops->is_drs_sec_enable(en_dev->parent)) {
		err = zxdh_sec_vqs_init(netdev);
		if (err != 0) {
			HEAL_ERR("%s zxdh_sec_vqs_init failed\n", netdev->name);
			goto err_sec_vqs_init;
		}
	}

	zxdh_device_ready(netdev);

	err = zxdh_port_init(netdev);
	if (err != 0) {
		HEAL_ERR("%s zxdh_port_init failed: %d\n", netdev->name, err);
		goto err_port_init;
	}

	if (en_dev->ops->is_bond(en_dev->parent)) {
		aux_get_bond_attrs(en_dev, &lag_attrs);
		err = zxdh_ldev_add_netdev(en_dev->parent, en_dev->pannel_id, netdev, &lag_attrs);
		if (err != 0) {
			HEAL_ERR("%s zxdh_ldev_add_netdev failed: %d\n", netdev->name, err);
			goto err_ldev_add_netdev;
		}
	}

#ifdef ZXDH_MSGQ
	if (NEED_MSGQ(en_dev)) {
		err = zxdh_msgq_init(en_dev);
		if (err) {
			HEAL_ERR("%s zxdh_msgq_init failed: %d\n", netdev->name, err);
			goto err_msgq_init;
		}
	}
#endif
	en_dev->init_comp_flag = AUX_INIT_COMPLETED;
	zxdh_init_stats(en_dev);
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF)
		dh_eq_async_link_info_int_process(en_priv);
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		err = zxdh_recover_hwbond_in_reload(en_dev->netdev);
		if (err != 0) {
			HEAL_ERR("zxdh_recover_hwbond_in_reload failed: %d\n", err);
			goto err_phyport_init;
		}
		err = zxdh_en_phyport_init(en_dev);
		if (err != 0) {
			HEAL_ERR("%s zxdh_en_phyport_init failed: %d\n", netdev->name, err);
			goto err_phyport_init;
		}
	}
	en_dev->ops->set_init_comp_flag(en_dev->parent, 1);
	en_dev->fast_unload = false;
	en_dev->ops->set_bond_num(en_dev->parent, true);
	mutex_unlock(&en_dev->parent->lock);

	en_dev->curr_queue_pairs = en_dev->eth_config.curr_combined;
	if (netif_running(netdev))
		en_open(netdev, false);
	else
		en_phyport_close(en_dev);
	netif_tx_wake_all_queues(netdev);
	en_dev->device_state = ZXDH_DEVICE_STATE_UP;
	eth_pflags_config_recover(en_dev->netdev);

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF)
		mod_timer(&en_dev->service_riscv_timer, jiffies);
	return 0;

err_phyport_init:
#ifdef ZXDH_MSGQ
	if (NEED_MSGQ(en_dev))
		zxdh_msgq_exit(en_dev);
#endif
err_msgq_init:
	if (en_dev->ops->is_bond(en_dev->parent)) {
		aux_get_bond_attrs(en_dev, &lag_attrs);
		zxdh_ldev_remove_netdev(en_dev->parent, netdev, &lag_attrs);
	}
err_ldev_add_netdev:
	zxdh_vport_uninit(netdev);
err_port_init:
	if (en_dev->ops->is_drs_sec_enable(en_dev->parent))
		zxdh_sec_vqs_uninit(netdev, ZXDH_SEC_QUEUES_NUM(en_dev));
err_sec_vqs_init:
	zxdh_vqs_uninit(netdev);
err_vqs_init:
	zxdh_del_pf_fc(en_dev);
	zxdh_add_status(netdev, ZXDH_CONFIG_S_FAILED);
err_status_init:
	dh_aux_eq_table_destroy(en_priv);
err_eq_table_create:
	en_dev->ops->destroy_vqs_channels(en_dev->parent);
unlock:
	mutex_unlock(&en_dev->parent->lock);
	return -EPERM;
}

static void del_cfg_shell_script(struct work_struct *work)
{
	static const char command[] = "/etc/zxdh_cfg/smart_nic_cfg_proc.sh";
	static const char *const argv[] = { command, "d", NULL };
	static const char *const envp[] = { "HOME=/", "TERM=linux",
					    "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/bin", NULL };
	s32 ret = 0;

	ret = call_usermodehelper(command, (char **)argv, (char **)envp, UMH_WAIT_PROC);
	if (ret < 0)
		pr_err("Failed to execute smart_nic_cfg_del.sh(err:%d)\n", ret);
	else
		pr_info("smart_nic_cfg_del.sh executed successfully,ret:%d\n", ret);
}

void zxdh_aux_unload(struct zxdh_en_priv *en_priv)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct net_device *netdev = en_dev->netdev;
	struct zxdh_lag_attrs lag_attrs;
	u16 i = 0;

	if (test_bit(ZXDH_DEVICE_STATE_OPENED, &en_dev->state)) {
		mutex_lock(&en_priv->lock);
		cancel_delayed_work_sync(&en_dev->refill);

		for (i = 0; i < en_dev->max_vq_pairs; i++) {
			xdp_rxq_info_unreg(&en_dev->rq[i].xdp_rxq);
			napi_disable(&en_dev->rq[i].napi);
			virtnet_napi_tx_disable(&en_dev->sq[i].napi);
		}
		mutex_unlock(&en_priv->lock);
	}

	mutex_lock(&en_dev->parent->lock);
	if (en_dev->parent->driver_process == ZXDH_REMOVE) {
		mutex_unlock(&en_dev->parent->lock);
		return;
	}
	en_dev->parent->driver_process = ZXDH_UNLOAD;
	en_dev->init_comp_flag = AUX_INIT_INCOMPLETED;
	en_dev->ops->set_init_comp_flag(en_dev->parent, 0);
	en_dev->ops->set_bond_num(en_dev->parent, false);
	en_dev->fast_unload = true;

#ifdef ZXDH_MSGQ
	if (NEED_MSGQ(en_dev))
		zxdh_msgq_exit(en_dev);
#endif
	if (en_dev->ops->is_bond(en_dev->parent)) {
		aux_get_bond_attrs(en_dev, &lag_attrs);
		zxdh_ldev_remove_netdev(en_dev->parent, netdev, &lag_attrs);
	}

	if (en_dev->ops->is_drs_sec_enable(en_dev->parent))
		zxdh_sec_vqs_uninit(netdev, ZXDH_SEC_QUEUES_NUM(en_dev));

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF)
		zxdh_cap_pkt_uninit(en_dev, false);

	synchronize_net();
	zxdh_vqs_uninit(netdev);

	en_dev->ops->destroy_vqs_channels(en_dev->parent);
	mutex_unlock(&en_dev->parent->lock);
}

static s32 zxdh_en_dev_remove(struct zxdh_auxiliary_device *adev)
{
	struct zxdh_en_priv *en_priv = (struct zxdh_en_priv *)dev_get_drvdata(&adev->dev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct net_device *netdev = en_dev->netdev;
	struct zxdh_lag_attrs lag_attrs;

	LOG_INFO("%s: aux level start\n", netdev->name);
	if (!en_dev->ops->get_rp_link_status(en_dev->parent)) {
		en_dev->quick_remove = true;
		LOG_INFO("%s: quick_remove start\n", netdev->name);
	}

	mutex_lock(&en_dev->parent->lock);
	en_dev->ops->set_init_comp_flag(en_dev->parent, 0);
	en_dev->parent->driver_process = ZXDH_REMOVE;
	en_dev->init_comp_flag = AUX_INIT_INCOMPLETED;
	mutex_unlock(&en_dev->parent->lock);

	en_dev->ops->set_bond_num(en_dev->parent, false);
#ifdef ZXDH_DCBNL_OPEN
	zxdh_dcbnl_ets_uninit(netdev);
#endif

#ifdef ZXDH_MSGQ
	if (!en_dev->fast_unload) {
		if (NEED_MSGQ(en_dev))
			zxdh_msgq_exit(en_dev);
	}
#endif
	dh_vxlan_netdev_change_notifier_unregister(&(en_dev->vxlan_notifier));
	dh_inet6_addr_change_notifier_unregister(&(en_dev->ipv6_notifier));

#ifdef ZXDH_PLCR_OPEN
	zxdh_plcr_uninit(en_priv);
#endif

	if (en_dev->ops->is_bond(en_dev->parent)) {
		if (!en_dev->fast_unload) {
			aux_get_bond_attrs(en_dev, &lag_attrs);
			zxdh_ldev_remove_netdev(en_dev->parent, netdev, &lag_attrs);
		}
	} else {
		zxdh_hardware_bond_uninit(netdev);
	}

	unregister_netdev(netdev);
	kfree(en_dev->hw_stats.q_stats);

	if (!en_dev->fast_unload) {
		if (!en_dev->ops->is_bond(en_dev->parent))
			zxdh_rxfh_del(en_dev);

		zxdh_vport_uninit(netdev);
		if (en_dev->ops->is_drs_sec_enable(en_dev->parent))
			zxdh_sec_vqs_uninit(netdev, ZXDH_SEC_QUEUES_NUM(en_dev));

		zxdh_vqs_uninit(netdev);
		zxdh_del_pf_fc(en_dev);
		zxdh_add_status(netdev, ZXDH_CONFIG_S_FAILED);
		dh_aux_eq_table_destroy(en_priv);
	}

	dh_aux_events_uninit(en_priv);
	dh_aux_eq_table_cleanup(en_priv);
	if (!en_dev->fast_unload)
		en_dev->ops->destroy_vqs_channels(en_dev->parent);
	if (en_dev->ops->is_bond(en_dev->parent))
		en_dev->ops->release_port(en_dev->parent, en_dev->pannel_id);
	mutex_destroy(&en_priv->lock);
	free_netdev(netdev);

	card_num--;
	if (card_num == 0) {
		INIT_WORK(&work_cfg_del, del_cfg_shell_script);
		queue_work(system_wq, &work_cfg_del);
	}

	LOG_INFO("aux level completed\n");

	return 0;
}

static void zxdh_en_dev_shutdown(struct zxdh_auxiliary_device *adev)
{
	LOG_INFO("aux level start\n");
	zxdh_en_dev_remove(adev);
	LOG_INFO("aux level completed\n");
};

static const struct zxdh_auxiliary_device_id zxdh_en_dev_id_table[] = {
	{
		.name = ZXDH_PF_NAME "." ZXDH_EN_DEV_ID_NAME,
	},
	{},
};

MODULE_DEVICE_TABLE(zxdh_auxiliary, zxdh_en_dev_id_table);

static struct zxdh_auxiliary_driver zxdh_en_driver = {
	.name = ZXDH_EN_DEV_ID_NAME,
	.probe = zxdh_en_dev_probe,
	.remove = zxdh_en_dev_remove,
	.shutdown = zxdh_en_dev_shutdown,
	.id_table = zxdh_en_dev_id_table,
};

s32 zxdh_en_driver_register(void)
{
	s32 err = 0;

	if ((max_pairs == 0) || (max_pairs >= ZXDH_MAX_PAIRS_NUM)) {
		LOG_INFO("max_pairs %u parameter is a invalid value, use the default value %u\n",
			 max_pairs, ZXDH_MQ_PAIRS_NUM);
		max_pairs = ZXDH_MQ_PAIRS_NUM;
	}

	err = zxdh_auxiliary_driver_register(&zxdh_en_driver);
	if (err != 0) {
		LOG_ERR("zxdh_auxiliary_driver_register failed: %d\n", err);
		goto err_aux_register;
	}

	err = dh_aux_msg_recv_func_register();
	if (err != 0) {
		LOG_ERR("dh_aux_msg_recv_func_register failed: %d\n", err);
		goto err_msg_recv_register;
	}

	err = zxdh_tools_netlink_register();
	if (err != 0) {
		LOG_ERR("zxdh_tools_msg_family register error failed: %d\n", err);
		goto err_netlink_register;
	}

	zxdh_lag_lock_init();
	LOG_INFO("all driver insmod completed\n");

	return 0;

err_netlink_register:
	dh_aux_msg_recv_func_unregister();
err_msg_recv_register:
	zxdh_auxiliary_driver_unregister(&zxdh_en_driver);
err_aux_register:
	return err;
}

void zxdh_en_driver_unregister(void)
{
	LOG_INFO("driver rmmod start\n");
	zxdh_lag_lock_deinit();
	zxdh_tools_netlink_unregister();
	dh_aux_msg_recv_func_unregister();
	zxdh_auxiliary_driver_unregister(&zxdh_en_driver);
}
