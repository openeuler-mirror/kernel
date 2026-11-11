// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_flow.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_com_ioctl.h"
#include "sxe2_ioctl_chnl.h"
#include "sxe2_com_flow.h"
#include "sxe2_drv_cmd.h"
#include "sxe2_mbx_public.h"
#include "sxe2_switch.h"

static u32 sxe2_com_flow_rss_flow_id;

static s32 sxe2_com_flow_vsi_id_change(struct sxe2_adapter *adapter, u16 id_in_dev,
				       u16 *id_in_pf)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi = NULL;
	*id_in_pf = 0xffff;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, id_in_dev);
	if (!vsi) {
		LOG_ERROR_BDF("failed to get vsi[%u]\n", id_in_dev);
		ret = -EINVAL;
		mutex_unlock(&adapter->vsi_ctxt.lock);
		goto l_end;
	}
	*id_in_pf = vsi->id_in_pf;
	mutex_unlock(&adapter->vsi_ctxt.lock);
l_end:
	return ret;
}

static s32 sxe2_com_flow_switch_meta(struct sxe2_adapter *adapter, u16 rule_vsi_id,
				     struct sxe2_drv_flow_filter_req_ext *req,
				     struct sxe2_user_cpx_fltr *fltr)
{
	s32 ret = 0;

	if (req->meta.switch_src_direct == SXE2_FLOW_SW_DIRECT_RX)
		fltr->src_type = SXE2_SRC_TYPE_RX;
	else
		fltr->src_type = SXE2_SRC_TYPE_TX;

	if (req->meta.switch_pattern_dup_allow == SXE2_FLOW_SW_PATTERN_ONLY)
		fltr->backup_type = SXE2_RULE_BACKUP_T_NO;
	else if (req->meta.switch_pattern_dup_allow == SXE2_FLOW_SW_PATTERN_FIRST)
		fltr->backup_type = SXE2_RULE_BACKUP_T_FIRST;
	else
		fltr->backup_type = SXE2_RULE_BACKUP_T_LAST;

	fltr->prio = req->meta.flow_prio;

	fltr->src_vsi_id = req->meta.flow_src_vsi;

	fltr->rule_vsi_id = rule_vsi_id;

	if (req->meta.tunnel_type == SXE2_FLOW_TUNNEL_TYPE_NONE) {
		fltr->tunnel_type = SXE2_TNL_ALL;
	} else if (req->meta.tunnel_type == SXE2_FLOW_TUNNEL_TYPE_VXLAN) {
		fltr->tunnel_type = SXE2_TNL_VXLAN;
	} else if (req->meta.tunnel_type == SXE2_FLOW_TUNNEL_TYPE_GENEVE) {
		fltr->tunnel_type = SXE2_TNL_GENEVE;
	} else if (req->meta.tunnel_type == SXE2_FLOW_TUNNEL_TYPE_GRE) {
		fltr->tunnel_type = SXE2_TNL_GRETAP;
	} else if (req->meta.tunnel_type == SXE2_FLOW_TUNNEL_TYPE_GTPU) {
		fltr->tunnel_type = SXE2_TNL_GTPU;
	} else if (req->meta.tunnel_type == SXE2_FLOW_TUNNEL_TYPE_GTPC) {
		fltr->tunnel_type = SXE2_TNL_GTPC;
	} else {
		ret = -EINVAL;
		goto l_end;
	}

	LOG_DEBUG_BDF("meta src_type[%d],backup_type[%d],prio[%d],src_vsi[%d],rule_vsi[%d]\n",
		      fltr->src_type, fltr->backup_type, fltr->prio, fltr->src_vsi_id,
		      fltr->rule_vsi_id);

l_end:
	return ret;
}

static s32 sxe2_com_flow_switch_pattern_outer(struct sxe2_adapter *adapter,
					      const struct sxe2_flow_pattern_ext *pattern_out,
					      struct sxe2_user_cpx_fltr *fltr)
{
	s32 ret = 0;
	struct sxe2_tcf_key_item *item;
	const struct sxe2_flow_item_ext *it;
	DECLARE_BITMAP(map_spec, SXE2_FLOW_FLD_ID_MAX);

	bitmap_zero(map_spec, SXE2_FLOW_FLD_ID_MAX);
	if (test_bit(SXE2_FLOW_HDR_ETH, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_ETH);
		if (it && test_bit(SXE2_FLOW_FLD_ID_ETH_DA, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_DMAC];
			memcpy(item->value.hdr.eth_hdr.dst_addr,
			       it->val.eth.dst_addr, ETH_ALEN);
			memcpy(item->mask.hdr.eth_hdr.dst_addr,
			       it->mask.eth.dst_addr, ETH_ALEN);
			set_bit(SXE2_FLOW_FLD_ID_ETH_DA, map_spec);
			LOG_DEBUG_BDF("prot_type %d, dmac[%pM], mask[%pM]\n", item->type,
				      it->val.eth.dst_addr,
				      it->mask.eth.dst_addr);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ETH_SA, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_SMAC];
			memcpy(item->value.hdr.eth_hdr.src_addr,
			       it->val.eth.src_addr, ETH_ALEN);
			memcpy(item->mask.hdr.eth_hdr.src_addr,
			       it->mask.eth.src_addr, ETH_ALEN);
			set_bit(SXE2_FLOW_FLD_ID_ETH_SA, map_spec);
			LOG_DEBUG_BDF("prot_type %d, smac[%pM], mask[%pM]\n", item->type,
				      it->val.eth.src_addr,
				      it->mask.eth.src_addr);
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_ETH_TYPE, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_ETYPE];
			item->value.hdr.ethertype.ethtype_id =
					it->val.eth.ether_type;
			item->mask.hdr.ethertype.ethtype_id =
					it->mask.eth.ether_type;
			set_bit(SXE2_FLOW_FLD_ID_ETH_TYPE, map_spec);
			LOG_DEBUG_BDF("prot_type %d, ether_type[%d], mask[%d]\n",
				      item->type, it->val.eth.ether_type,
				      it->mask.eth.ether_type);
		}
	}
	if (test_bit(SXE2_FLOW_HDR_VLAN, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_VLAN);
		if (it && test_bit(SXE2_FLOW_FLD_ID_S_TPID, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_VLAN_EX];
			item->value.hdr.vlan_hdr.type = it->val.vlan.type;
			item->mask.hdr.vlan_hdr.type = it->mask.vlan.type;
			set_bit(SXE2_FLOW_FLD_ID_S_TPID, map_spec);
			LOG_DEBUG_BDF("prot_type %d, vlan_tpid[%d], mask[%d]\n",
				      item->type, it->val.vlan.type,
				      it->mask.vlan.type);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_S_VID, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_VLAN_EX];
			item->value.hdr.vlan_hdr.vlan = it->val.vlan.vlan;
			item->mask.hdr.vlan_hdr.vlan = it->mask.vlan.vlan;
			set_bit(SXE2_FLOW_FLD_ID_S_VID, map_spec);
			LOG_DEBUG_BDF("prot_type %d, vlan_id[%d], mask[%d]\n", item->type,
				      it->val.vlan.vlan,
				      it->mask.vlan.vlan);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_S_TCI, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_VLAN_EX];
			item->value.hdr.vlan_hdr.vlan = it->val.vlan.vlan;
			item->mask.hdr.vlan_hdr.vlan = it->mask.vlan.vlan;
			set_bit(SXE2_FLOW_FLD_ID_S_TCI, map_spec);
			LOG_DEBUG_BDF("prot_type %d, vlan_tci[%d], mask[%d]\n",
				      item->type, it->val.vlan.vlan,
				      it->mask.vlan.vlan);
		}
	}
	if (test_bit(SXE2_FLOW_HDR_QINQ, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_QINQ);
		if (it && test_bit(SXE2_FLOW_FLD_ID_C_TPID, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_VLAN];
			item->value.hdr.vlan_hdr.type = it->val.qinq.type;
			item->mask.hdr.vlan_hdr.type = it->mask.qinq.type;
			set_bit(SXE2_FLOW_FLD_ID_C_TPID, map_spec);
			LOG_DEBUG_BDF("prot_type %d, cvlan_tpid[%d], mask[%d]\n",
				      item->type, it->val.qinq.type,
				      it->mask.qinq.type);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_C_VID, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_VLAN];
			item->value.hdr.vlan_hdr.vlan = it->val.qinq.vlan;
			item->mask.hdr.vlan_hdr.vlan = it->mask.qinq.vlan;
			set_bit(SXE2_FLOW_FLD_ID_C_VID, map_spec);
			LOG_DEBUG_BDF("prot_type %d, cvlan_id[%d], mask[%d]\n",
				      item->type, it->val.qinq.vlan,
				      it->mask.qinq.vlan);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_C_TCI, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_VLAN];
			item->value.hdr.vlan_hdr.vlan = it->val.qinq.vlan;
			item->mask.hdr.vlan_hdr.vlan = it->mask.qinq.vlan;
			set_bit(SXE2_FLOW_FLD_ID_C_TCI, map_spec);
			LOG_DEBUG_BDF("prot_type %d, cvlan_tci[%d], mask[%d]\n",
				      item->type, it->val.qinq.vlan,
				      it->mask.qinq.vlan);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_IPV4, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_IPV4);
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_SA, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_IPV4_SADDR];
			item->value.hdr.ipv4_hdr.saddr =
					it->val.ipv4.saddr;
			item->mask.hdr.ipv4_hdr.saddr = it->mask.ipv4.saddr;
			set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, map_spec);
			LOG_DEBUG_BDF("prot_type %d, saddr[%d], mask[0x%x]\n", item->type,
				      it->val.ipv4.saddr,
				      it->mask.ipv4.saddr);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_DA, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_IPV4_DADDR];
			item->value.hdr.ipv4_hdr.daddr =
					it->val.ipv4.daddr;
			item->mask.hdr.ipv4_hdr.daddr = it->mask.ipv4.daddr;
			set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, map_spec);
			LOG_DEBUG_BDF("prot_type %d, daddr[%d], mask[0x%x]\n", item->type,
				      it->val.ipv4.daddr,
				      it->mask.ipv4.daddr);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_TOS, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_IPV4_TOS];
			item->value.hdr.ipv4_hdr.tos = it->val.ipv4.tos;
			item->mask.hdr.ipv4_hdr.tos = it->mask.ipv4.tos;
			set_bit(SXE2_FLOW_FLD_ID_IPV4_TOS, map_spec);
			LOG_DEBUG_BDF("prot_type %d, tos[%d], mask[0x%x]\n", item->type,
				      it->val.ipv4.tos,
				      it->mask.ipv4.tos);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_TTL, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_IPV4_TTL];
			item->value.hdr.ipv4_hdr.ttl = it->val.ipv4.ttl;
			item->mask.hdr.ipv4_hdr.ttl = it->mask.ipv4.ttl;
			set_bit(SXE2_FLOW_FLD_ID_IPV4_TTL, map_spec);
			LOG_DEBUG_BDF("prot_type %d, ttl[%d], mask[0x%x]\n", item->type,
				      it->val.ipv4.ttl,
				      it->mask.ipv4.ttl);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_PROT, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_IPV4_PROT];
			item->value.hdr.ipv4_hdr.protocol =
					it->val.ipv4.protocol;
			item->mask.hdr.ipv4_hdr.protocol =
					it->mask.ipv4.protocol;
			set_bit(SXE2_FLOW_FLD_ID_IPV4_PROT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, ipv4_protocol[%d], mask[0x%x]\n",
				      item->type, it->val.ipv4.protocol,
				      it->mask.ipv4.protocol);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_IPV6, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_IPV6);
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_SA, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_IPV6_SADDR];
			memcpy(item->value.hdr.ipv6_hdr.saddr,
			       it->val.ipv6.saddr, SXE2_IPV6_ADDR_LENGTH);
			memcpy(item->mask.hdr.ipv6_hdr.saddr,
			       it->mask.ipv6.saddr, SXE2_IPV6_ADDR_LENGTH);
			set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, map_spec);
			LOG_DEBUG_BDF("prot_type %d,saddr[0x%x:%x:%x:%x],mask[0x%x:%x:%x:%x]\n",
				      item->type, it->val.ipv6.saddr32[0],
				      it->val.ipv6.saddr32[1],
				      it->val.ipv6.saddr32[2],
				      it->val.ipv6.saddr32[3],
				      it->mask.ipv6.saddr32[0],
				      it->mask.ipv6.saddr32[1],
				      it->mask.ipv6.saddr32[2],
				      it->mask.ipv6.saddr32[3]);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_DA, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_IPV6_DADDR];
			memcpy(item->value.hdr.ipv6_hdr.daddr,
			       it->val.ipv6.daddr, SXE2_IPV6_ADDR_LENGTH);
			memcpy(item->mask.hdr.ipv6_hdr.daddr,
			       it->mask.ipv6.daddr, SXE2_IPV6_ADDR_LENGTH);
			set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, map_spec);
			LOG_DEBUG_BDF("prot_type %d, daddr[0x%x:%x:%x:%x],mask[0x%x:%x:%x:%x]\n",
				      item->type, it->val.ipv6.daddr32[0],
				      it->val.ipv6.daddr32[1],
				      it->val.ipv6.daddr32[2],
				      it->val.ipv6.daddr32[3],
				      it->mask.ipv6.daddr32[0],
				      it->mask.ipv6.daddr32[1],
				      it->mask.ipv6.daddr32[2],
				      it->mask.ipv6.daddr32[3]);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_TCP, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_TCP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_LAST_TCP_SPORT];
			item->value.hdr.tcp_hdr.source =
					it->val.tcp.source;
			item->mask.hdr.tcp_hdr.source = it->mask.tcp.source;
			set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, tcp sport[%d], mask[0x%x]\n",
				      item->type, it->val.tcp.source,
				      it->mask.tcp.source);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_LAST_TCP_DPORT];
			item->value.hdr.tcp_hdr.dest = it->val.tcp.dest;
			item->mask.hdr.tcp_hdr.dest = it->mask.tcp.dest;
			set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, tcp dport[%d], mask[0x%x]\n",
				      item->type, it->val.tcp.dest,
				      it->mask.tcp.dest);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_TCP_FLAGS, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_LAST_TCP_FLAGS];
			item->value.hdr.tcp_hdr.flag = it->val.tcp.flag;
			item->mask.hdr.tcp_hdr.flag = it->mask.tcp.flag;
			set_bit(SXE2_FLOW_FLD_ID_TCP_FLAGS, map_spec);
			LOG_DEBUG_BDF("prot_type %d, tcp flags[0x%x], mask[0x%x]\n",
				      item->type, it->val.tcp.flag,
				      it->mask.tcp.flag);
		}
	}
	if (test_bit(SXE2_FLOW_HDR_UDP, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_UDP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_UDP_SPORT];
			item->value.hdr.udp_hdr.source =
					it->val.udp.source;
			item->mask.hdr.udp_hdr.source = it->mask.udp.source;
			set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, udp sport[%d], mask[0x%x]\n",
				      item->type, it->val.udp.source,
				      it->mask.udp.source);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_OUTER_UDP_DPORT];
			item->value.hdr.udp_hdr.dest = it->val.udp.dest;
			item->mask.hdr.udp_hdr.dest = it->mask.udp.dest;
			set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, udp dport[%d], mask[0x%x]\n",
				      item->type, it->val.udp.dest,
				      it->mask.udp.dest);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_GENEVE, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_GENEVE);
		if (it && test_bit(SXE2_FLOW_FLD_ID_GENEVE_VNI, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_GENEVE_ENC_ID];
			item->value.hdr.udp_tnl_hdr.vni =
					it->val.geneve.vni;
			item->mask.hdr.udp_tnl_hdr.vni =
					it->mask.geneve.vni;
			set_bit(SXE2_FLOW_FLD_ID_GENEVE_VNI, map_spec);
			LOG_DEBUG_BDF("prot_type %d, geneve vni[%u], mask[0x%x]\n",
				      item->type, it->val.geneve.vni,
				      it->mask.geneve.vni);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_VXLAN, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_VXLAN);
		if (it && test_bit(SXE2_FLOW_FLD_ID_VXLAN_VNI, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_VXLAN_ENC_ID];
			item->value.hdr.udp_tnl_hdr.vni =
					it->val.vxlan.vni;
			item->mask.hdr.udp_tnl_hdr.vni = it->mask.vxlan.vni;
			set_bit(SXE2_FLOW_FLD_ID_VXLAN_VNI, map_spec);
			LOG_DEBUG_BDF("prot_type %d, vxlan vni[%u], mask[0x%x]\n",
				      item->type, it->val.vxlan.vni,
				      it->mask.vxlan.vni);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_GTPU, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_GTPU);
		if (it && test_bit(SXE2_FLOW_FLD_ID_GTPU_TEID, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_GTPU];
			item->value.hdr.gtpu_hdr.teid = it->val.gtpu.teid;
			item->mask.hdr.gtpu_hdr.teid = it->mask.gtpu.teid;
			set_bit(SXE2_FLOW_FLD_ID_GTPU_TEID, map_spec);
			LOG_DEBUG_BDF("prot_type %d, gtpu teid[%u], mask[0x%x]\n",
				      item->type, it->val.gtpu.teid,
				      it->mask.gtpu.teid);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_GRE, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_GRE);
		if (it && test_bit(SXE2_FLOW_FLD_ID_NVGRE_TNI, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_NVGRE_ENC_ID];
			item->value.hdr.nvgre_hdr.tni = it->val.nvgre.tni;
			item->mask.hdr.nvgre_hdr.tni = it->mask.nvgre.tni;
			set_bit(SXE2_FLOW_FLD_ID_NVGRE_TNI, map_spec);
			LOG_DEBUG_BDF("prot_type %d, nvgre vni[%u], mask[0x%x]\n",
				      item->type, it->val.nvgre.tni,
				      it->mask.nvgre.tni);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_SCTP, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_SCTP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_LAST_SCTP_SPORT];
			item->value.hdr.sctp_hdr.src_port =
					it->val.sctp.src_port;
			item->mask.hdr.sctp_hdr.src_port =
					it->mask.sctp.src_port;
			set_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, sctp sport[%d], mask[0x%x]\n",
				      item->type, it->val.sctp.src_port,
				      it->mask.sctp.src_port);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_LAST_SCTP_DPORT];
			item->value.hdr.sctp_hdr.dst_port =
					it->val.sctp.dst_port;
			item->mask.hdr.sctp_hdr.dst_port =
					it->mask.sctp.dst_port;
			set_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, sctp dport[%d], mask[0x%x]\n",
				      item->type, it->val.sctp.dst_port,
				      it->mask.sctp.dst_port);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_ICMPV6_ND, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_ICMPV6_ND);
		if (it && test_bit(SXE2_FLOW_FLD_ID_ICMPV6_ND_TYPE, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_ICMPV6_ND_TYPE];
			item->value.hdr.icmpv6_nd_hdr.type = it->val.icmpv6_nd.type;
			item->mask.hdr.icmpv6_nd_hdr.type = it->mask.icmpv6_nd.type;
			set_bit(SXE2_FLOW_FLD_ID_ICMPV6_ND_TYPE, map_spec);
			LOG_DEBUG_BDF("prot_type %d, icmpv6 nd type[%d], mask[0x%x]\n",
				      item->type, it->val.icmpv6_nd.type,
				      it->mask.icmpv6_nd.type);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ICMPV6_ND_TARGET, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_ICMPV6_ND_TARGET];
			memcpy(item->value.hdr.icmpv6_nd_hdr.target,
			       it->val.icmpv6_nd.target, SXE2_IPV6_ADDR_LENGTH);
			memcpy(item->mask.hdr.icmpv6_nd_hdr.target,
			       it->mask.icmpv6_nd.target, SXE2_IPV6_ADDR_LENGTH);
			set_bit(SXE2_FLOW_FLD_ID_ICMPV6_ND_TARGET, map_spec);
			LOG_DEBUG_BDF("prot_type %d, icmpv6 nd target[%pI6], mask[%pI6]\n",
				      item->type, it->val.icmpv6_nd.target,
				      it->mask.icmpv6_nd.target);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_ESP, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_ESP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_ESP_SPI, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_ESP_SPI];
			item->value.hdr.esp_hdr.spi = it->val.esp.spi;
			item->mask.hdr.esp_hdr.spi = it->mask.esp.spi;
			set_bit(SXE2_FLOW_FLD_ID_ESP_SPI, map_spec);
			LOG_DEBUG_BDF("prot_type %d, esp spi[%u], mask[0x%x]\n",
				      item->type, it->val.esp.spi,
				      it->mask.esp.spi);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ESP_SEQ, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_ESP_SEQ];
			item->value.hdr.esp_hdr.seq = it->val.esp.seq;
			item->mask.hdr.esp_hdr.seq = it->mask.esp.seq;
			set_bit(SXE2_FLOW_FLD_ID_ESP_SEQ, map_spec);
			LOG_DEBUG_BDF("prot_type %d, esp seq[%u], mask[0x%x]\n",
				      item->type, it->val.esp.seq,
				      it->mask.esp.seq);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ESP_NATT_SPI, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_ESP_NATT_SPI];
			item->value.hdr.esp_hdr.spi = it->val.esp.spi;
			item->mask.hdr.esp_hdr.spi = it->mask.esp.spi;
			set_bit(SXE2_FLOW_FLD_ID_ESP_NATT_SPI, map_spec);
			LOG_DEBUG_BDF("prot_type %d, esp natt spi[%u], mask[0x%x]\n",
				      item->type, it->val.esp.spi,
				      it->mask.esp.spi);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ESP_NATT_SEQ, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_ESP_NATT_SEQ];
			item->value.hdr.esp_hdr.seq = it->val.esp.seq;
			item->mask.hdr.esp_hdr.seq = it->mask.esp.seq;
			set_bit(SXE2_FLOW_FLD_ID_ESP_NATT_SEQ, map_spec);
			LOG_DEBUG_BDF("prot_type %d, esp natt seq[%u], mask[0x%x]\n",
				      item->type, it->val.esp.seq,
				      it->mask.esp.seq);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_ICMP, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_ICMP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_ICMP_TYPE, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_ICMP_TYPE];
			item->value.hdr.icmp_hdr.type = it->val.icmp.type;
			item->mask.hdr.icmp_hdr.type = it->mask.icmp.type;
			set_bit(SXE2_FLOW_FLD_ID_ICMP_TYPE, map_spec);
			LOG_DEBUG_BDF("prot_type %d, icmp type[%d], mask[0x%x]\n",
				      item->type, it->val.icmp.type,
				      it->mask.icmp.type);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ICMP_CODE, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_ICMP_CODE];
			item->value.hdr.icmp_hdr.code = it->val.icmp.code;
			item->mask.hdr.icmp_hdr.code = it->mask.icmp.code;
			set_bit(SXE2_FLOW_FLD_ID_ICMP_CODE, map_spec);
			LOG_DEBUG_BDF("prot_type %d, icmp code[%d], mask[0x%x]\n",
				      item->type, it->val.icmp.code,
				      it->mask.icmp.code);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ICMP_IDENT, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_ICMP_IDENT];
			item->value.hdr.icmp_hdr.ident = it->val.icmp.ident;
			item->mask.hdr.icmp_hdr.ident = it->mask.icmp.ident;
			set_bit(SXE2_FLOW_FLD_ID_ICMP_IDENT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, icmp ident[%u], mask[0x%x]\n",
				      item->type, it->val.icmp.ident,
				      it->mask.icmp.ident);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_IPV_FRAG, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_IPV_FRAG);
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_FRAG_NEXT_HDR, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_IPV6_FRAG_NEXT_HDR];
			item->value.hdr.ipv6_frag_hdr.next_hdr = it->val.ipv6_frag.next_hdr;
			item->mask.hdr.ipv6_frag_hdr.next_hdr = it->mask.ipv6_frag.next_hdr;
			set_bit(SXE2_FLOW_FLD_ID_IPV6_FRAG_NEXT_HDR, map_spec);
			LOG_DEBUG_BDF("prot_type %d, ipv6 frag next_hdr[%d], mask[0x%x]\n",
				      item->type, it->val.ipv6_frag.next_hdr,
				      it->mask.ipv6_frag.next_hdr);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_FRAG_DATA, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_IPV6_FRAG_DATA];
			item->value.hdr.ipv6_frag_hdr.frag_data = it->val.ipv6_frag.frag_data;
			item->mask.hdr.ipv6_frag_hdr.frag_data = it->mask.ipv6_frag.frag_data;
			set_bit(SXE2_FLOW_FLD_ID_IPV6_FRAG_DATA, map_spec);
			LOG_DEBUG_BDF("prot_type %d, ipv6 frag data[%u], mask[0x%x]\n",
				      item->type, it->val.ipv6_frag.frag_data,
				      it->mask.ipv6_frag.frag_data);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_ID, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_IPV6_FRAG_ID];
			item->value.hdr.ipv6_frag_hdr.ident = it->val.ipv6_frag.ident;
			item->mask.hdr.ipv6_frag_hdr.ident = it->mask.ipv6_frag.ident;
			set_bit(SXE2_FLOW_FLD_ID_IPV6_ID, map_spec);
			LOG_DEBUG_BDF("prot_type %d, ipv6 frag id[%u], mask[0x%x]\n",
				      item->type, it->val.ipv6_frag.ident,
				      it->mask.ipv6_frag.ident);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_GRE, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_GRE);
		if (it && test_bit(SXE2_FLOW_FLD_ID_GRE_PROTO, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_GRE_PROTOCOL];
			item->value.hdr.gre_hdr.protocol = it->val.gre.protocol;
			item->mask.hdr.gre_hdr.protocol = it->mask.gre.protocol;
			set_bit(SXE2_FLOW_FLD_ID_GRE_PROTO, map_spec);
			LOG_DEBUG_BDF("prot_type %d, gre protocol[%u], mask[0x%x]\n",
				      item->type, it->val.gre.protocol,
				      it->mask.gre.protocol);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_GTPC, pattern_out->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_out, SXE2_FLOW_HDR_GTPC);
		if (it && test_bit(SXE2_FLOW_FLD_ID_GTPU_TEID, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_GTPC];
			item->value.hdr.gtpc_hdr.teid = it->val.gtpc.teid;
			item->mask.hdr.gtpc_hdr.teid = it->mask.gtpc.teid;
			set_bit(SXE2_FLOW_FLD_ID_GTPU_TEID, map_spec);
			LOG_DEBUG_BDF("prot_type %d, gtpc teid[%u], mask[0x%x]\n",
				      item->type, it->val.gtpc.teid,
				      it->mask.gtpc.teid);
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_GTPC_FLAG, pattern_out->map_spec)) {
			item = &fltr->items[SXE2_GTPC];
			item->value.hdr.gtpc_hdr.flags = it->val.gtpc.flag;
			item->mask.hdr.gtpc_hdr.flags = it->mask.gtpc.flag;
			set_bit(SXE2_FLOW_FLD_ID_GTPC_FLAG, map_spec);
			LOG_DEBUG_BDF("prot_type %d, gtpc flags[0x%x], mask[0x%x]\n",
				      item->type, it->val.gtpc.flag,
				      it->mask.gtpc.flag);
		}
	}

	if (!bitmap_equal(pattern_out->map_spec, map_spec, SXE2_FLOW_FLD_ID_MAX)) {
		ret = -EINVAL;
		goto l_end;
	}
l_end:
	return ret;
}

static s32 sxe2_com_flow_switch_pattern_inner(struct sxe2_adapter *adapter,
					      const struct sxe2_flow_pattern_ext *pattern_in,
					      struct sxe2_user_cpx_fltr *fltr)
{
	s32 ret = 0;
	struct sxe2_tcf_key_item *item;
	const struct sxe2_flow_item_ext *it;
	DECLARE_BITMAP(map_spec, SXE2_FLOW_FLD_ID_MAX);

	bitmap_zero(map_spec, SXE2_FLOW_FLD_ID_MAX);
	if (test_bit(SXE2_FLOW_HDR_ETH, pattern_in->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_in, SXE2_FLOW_HDR_ETH);
		if (it && test_bit(SXE2_FLOW_FLD_ID_ETH_DA, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_INNER_DMAC];
			memcpy(item->value.hdr.eth_hdr.dst_addr,
			       it->val.eth.dst_addr, ETH_ALEN);
			memcpy(item->mask.hdr.eth_hdr.dst_addr,
			       it->mask.eth.dst_addr, ETH_ALEN);
			set_bit(SXE2_FLOW_FLD_ID_ETH_DA, map_spec);
			LOG_DEBUG_BDF("prot_type %d, dmac[%pM], mask[%pM]\n", item->type,
				      it->val.eth.dst_addr,
				      it->mask.eth.dst_addr);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ETH_SA, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_INNER_SMAC];
			memcpy(item->value.hdr.eth_hdr.src_addr,
			       it->val.eth.src_addr, ETH_ALEN);
			memcpy(item->mask.hdr.eth_hdr.src_addr,
			       it->mask.eth.src_addr, ETH_ALEN);
			set_bit(SXE2_FLOW_FLD_ID_ETH_SA, map_spec);
			LOG_DEBUG_BDF("prot_type %d, smac[%pM], mask[%pM]\n", item->type,
				      it->val.eth.src_addr,
				      it->mask.eth.src_addr);
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_ETH_TYPE, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_INNER_ETYPE];
			item->value.hdr.ethertype.ethtype_id =
					it->val.eth.ether_type;
			item->mask.hdr.ethertype.ethtype_id =
					it->mask.eth.ether_type;
			set_bit(SXE2_FLOW_FLD_ID_ETH_TYPE, map_spec);
			LOG_DEBUG_BDF("prot_type %d, ether_type[%d], mask[%d]\n",
				      item->type, it->val.eth.ether_type,
				      it->mask.eth.ether_type);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_IPV4, pattern_in->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_in, SXE2_FLOW_HDR_IPV4);
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_SA, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_INNER_IPV4_SADDR];
			item->value.hdr.ipv4_hdr.saddr = it->val.ipv4.saddr;
			item->mask.hdr.ipv4_hdr.saddr = it->mask.ipv4.saddr;
			set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, map_spec);
			LOG_DEBUG_BDF("prot_type %d, saddr[%d], mask[0x%x]\n", item->type,
				      it->val.ipv4.saddr,
				      it->mask.ipv4.saddr);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_DA, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_INNER_IPV4_DADDR];
			item->value.hdr.ipv4_hdr.daddr = it->val.ipv4.daddr;
			item->mask.hdr.ipv4_hdr.daddr = it->mask.ipv4.daddr;
			set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, map_spec);
			LOG_DEBUG_BDF("prot_type %d, daddr[%d], mask[0x%x]\n", item->type,
				      it->val.ipv4.daddr,
				      it->mask.ipv4.daddr);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_TOS, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_INNER_IPV4_TOS];
			item->value.hdr.ipv4_hdr.tos = it->val.ipv4.tos;
			item->mask.hdr.ipv4_hdr.tos = it->mask.ipv4.tos;
			set_bit(SXE2_FLOW_FLD_ID_IPV4_TOS, map_spec);
			LOG_DEBUG_BDF("prot_type %d, tos[%d], mask[0x%x]\n", item->type,
				      it->val.ipv4.tos,
				      it->mask.ipv4.tos);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_TTL, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_INNER_IPV4_TTL];
			item->value.hdr.ipv4_hdr.ttl = it->val.ipv4.ttl;
			item->mask.hdr.ipv4_hdr.ttl = it->mask.ipv4.ttl;
			set_bit(SXE2_FLOW_FLD_ID_IPV4_TTL, map_spec);
			LOG_DEBUG_BDF("prot_type %d, ttl[%d], mask[0x%x]\n", item->type,
				      it->val.ipv4.ttl,
				      it->mask.ipv4.ttl);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_PROT, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_INNER_IPV4_PROT];
			item->value.hdr.ipv4_hdr.protocol =
				it->val.ipv4.protocol;
			item->mask.hdr.ipv4_hdr.protocol =
				it->mask.ipv4.protocol;
			set_bit(SXE2_FLOW_FLD_ID_IPV4_PROT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, ipv4_protocol[%d], mask[0x%x]\n",
				      item->type, it->val.ipv4.protocol,
					it->mask.ipv4.protocol);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_IPV6, pattern_in->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_in, SXE2_FLOW_HDR_IPV6);
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_SA, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_INNER_IPV6_SADDR];
			memcpy(item->value.hdr.ipv6_hdr.saddr,
			       it->val.ipv6.saddr, SXE2_IPV6_ADDR_LENGTH);
			memcpy(item->mask.hdr.ipv6_hdr.saddr,
			       it->mask.ipv6.saddr, SXE2_IPV6_ADDR_LENGTH);
			set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, map_spec);
			LOG_DEBUG_BDF("prot_type %d, saddr[0x%x:%x:%x:%x],mask[0x%x:%x:%x:%x]\n",
				      item->type, it->val.ipv6.saddr32[0],
				      it->val.ipv6.saddr32[1],
				      it->val.ipv6.saddr32[2],
				      it->val.ipv6.saddr32[3],
				      it->mask.ipv6.saddr32[0],
				      it->mask.ipv6.saddr32[1],
				      it->mask.ipv6.saddr32[2],
				      it->mask.ipv6.saddr32[3]);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_DA, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_INNER_IPV6_DADDR];
			memcpy(item->value.hdr.ipv6_hdr.daddr,
			       it->val.ipv6.daddr, SXE2_IPV6_ADDR_LENGTH);
			memcpy(item->mask.hdr.ipv6_hdr.daddr,
			       it->mask.ipv6.daddr, SXE2_IPV6_ADDR_LENGTH);
			set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, map_spec);
			LOG_DEBUG_BDF("prot_type %d, daddr[0x%x:%x:%x:%x],mask[0x%x:%x:%x:%x]\n",
				      item->type, it->val.ipv6.daddr32[0],
				      it->val.ipv6.daddr32[1],
				      it->val.ipv6.daddr32[2],
				      it->val.ipv6.daddr32[3],
				      it->mask.ipv6.daddr32[0],
				      it->mask.ipv6.daddr32[1],
				      it->mask.ipv6.daddr32[2],
				      it->mask.ipv6.daddr32[3]);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_TCP, pattern_in->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_in, SXE2_FLOW_HDR_TCP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_LAST_TCP_SPORT];
			item->value.hdr.tcp_hdr.source = it->val.tcp.source;
			item->mask.hdr.tcp_hdr.source = it->mask.tcp.source;
			set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, tcp sport[%d], mask[0x%x]\n",
				      item->type, it->val.tcp.source,
				      it->mask.tcp.source);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_LAST_TCP_DPORT];
			item->value.hdr.tcp_hdr.dest = it->val.tcp.dest;
			item->mask.hdr.tcp_hdr.dest = it->mask.tcp.dest;
			set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, tcp dport[%d], mask[0x%x]\n",
				      item->type, it->val.tcp.dest,
				      it->mask.tcp.dest);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_TCP_FLAGS, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_LAST_TCP_FLAGS];
			item->value.hdr.tcp_hdr.flag = it->val.tcp.flag;
			item->mask.hdr.tcp_hdr.flag = it->mask.tcp.flag;
			set_bit(SXE2_FLOW_FLD_ID_TCP_FLAGS, map_spec);
			LOG_DEBUG_BDF("prot_type %d, tcp flags[0x%x], mask[0x%x]\n",
				      item->type, it->val.tcp.flag,
				      it->mask.tcp.flag);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_UDP, pattern_in->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_in, SXE2_FLOW_HDR_UDP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_INNER_UDP_SPORT];
			item->value.hdr.udp_hdr.source = it->val.udp.source;
			item->mask.hdr.udp_hdr.source = it->mask.udp.source;
			set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, udp sport[%d], mask[0x%x]\n",
				      item->type, it->val.udp.source,
				      it->mask.udp.source);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_INNER_UDP_DPORT];
			item->value.hdr.udp_hdr.dest = it->val.udp.dest;
			item->mask.hdr.udp_hdr.dest = it->mask.udp.dest;
			set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, udp dport[%d], mask[0x%x]\n",
				      item->type, it->val.udp.dest,
				      it->mask.udp.dest);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_SCTP, pattern_in->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_in, SXE2_FLOW_HDR_SCTP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_LAST_SCTP_SPORT];
			item->value.hdr.sctp_hdr.src_port =
					it->val.sctp.src_port;
			item->mask.hdr.sctp_hdr.src_port =
					it->mask.sctp.src_port;
			set_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, sctp sport[%d], mask[0x%x]\n",
				      item->type, it->val.sctp.src_port,
				      it->mask.sctp.src_port);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_LAST_SCTP_DPORT];
			item->value.hdr.sctp_hdr.dst_port =
					it->val.sctp.dst_port;
			item->mask.hdr.sctp_hdr.dst_port =
					it->mask.sctp.dst_port;
			set_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, sctp dport[%d], mask[0x%x]\n",
				      item->type, it->val.sctp.dst_port,
				      it->mask.sctp.dst_port);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_ICMPV6_ND, pattern_in->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_in, SXE2_FLOW_HDR_ICMPV6_ND);
		if (it && test_bit(SXE2_FLOW_FLD_ID_ICMPV6_ND_TYPE, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_ICMPV6_ND_TYPE];
			item->value.hdr.icmpv6_nd_hdr.type = it->val.icmpv6_nd.type;
			item->mask.hdr.icmpv6_nd_hdr.type = it->mask.icmpv6_nd.type;
			set_bit(SXE2_FLOW_FLD_ID_ICMPV6_ND_TYPE, map_spec);
			LOG_DEBUG_BDF("prot_type %d, icmpv6 nd type[%d], mask[0x%x]\n",
				      item->type, it->val.icmpv6_nd.type,
				      it->mask.icmpv6_nd.type);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ICMPV6_ND_TARGET, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_ICMPV6_ND_TARGET];
			memcpy(item->value.hdr.icmpv6_nd_hdr.target,
			       it->val.icmpv6_nd.target, SXE2_IPV6_ADDR_LENGTH);
			memcpy(item->mask.hdr.icmpv6_nd_hdr.target,
			       it->mask.icmpv6_nd.target, SXE2_IPV6_ADDR_LENGTH);
			set_bit(SXE2_FLOW_FLD_ID_ICMPV6_ND_TARGET, map_spec);
			LOG_DEBUG_BDF("prot_type %d, icmpv6 nd target[%pI6], mask[%pI6]\n",
				      item->type, it->val.icmpv6_nd.target,
				      it->mask.icmpv6_nd.target);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_ESP, pattern_in->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_in, SXE2_FLOW_HDR_ESP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_ESP_SPI, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_ESP_SPI];
			item->value.hdr.esp_hdr.spi = it->val.esp.spi;
			item->mask.hdr.esp_hdr.spi = it->mask.esp.spi;
			set_bit(SXE2_FLOW_FLD_ID_ESP_SPI, map_spec);
			LOG_DEBUG_BDF("prot_type %d, esp spi[%u], mask[0x%x]\n",
				      item->type, it->val.esp.spi,
				      it->mask.esp.spi);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ESP_SEQ, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_ESP_SEQ];
			item->value.hdr.esp_hdr.seq = it->val.esp.seq;
			item->mask.hdr.esp_hdr.seq = it->mask.esp.seq;
			set_bit(SXE2_FLOW_FLD_ID_ESP_SEQ, map_spec);
			LOG_DEBUG_BDF("prot_type %d, esp seq[%u], mask[0x%x]\n",
				      item->type, it->val.esp.seq,
				      it->mask.esp.seq);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ESP_NATT_SPI, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_ESP_NATT_SPI];
			item->value.hdr.esp_hdr.spi = it->val.esp.spi;
			item->mask.hdr.esp_hdr.spi = it->mask.esp.spi;
			set_bit(SXE2_FLOW_FLD_ID_ESP_NATT_SPI, map_spec);
			LOG_DEBUG_BDF("prot_type %d, esp natt spi[%u], mask[0x%x]\n",
				      item->type, it->val.esp.spi,
				      it->mask.esp.spi);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ESP_NATT_SEQ, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_ESP_NATT_SEQ];
			item->value.hdr.esp_hdr.seq = it->val.esp.seq;
			item->mask.hdr.esp_hdr.seq = it->mask.esp.seq;
			set_bit(SXE2_FLOW_FLD_ID_ESP_NATT_SEQ, map_spec);
			LOG_DEBUG_BDF("prot_type %d, esp natt seq[%u], mask[0x%x]\n",
				      item->type, it->val.esp.seq,
				      it->mask.esp.seq);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_ICMP, pattern_in->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_in, SXE2_FLOW_HDR_ICMP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_ICMP_TYPE, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_ICMP_TYPE];
			item->value.hdr.icmp_hdr.type = it->val.icmp.type;
			item->mask.hdr.icmp_hdr.type = it->mask.icmp.type;
			set_bit(SXE2_FLOW_FLD_ID_ICMP_TYPE, map_spec);
			LOG_DEBUG_BDF("prot_type %d, icmp type[%d], mask[0x%x]\n",
				      item->type, it->val.icmp.type,
				      it->mask.icmp.type);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ICMP_CODE, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_ICMP_CODE];
			item->value.hdr.icmp_hdr.code = it->val.icmp.code;
			item->mask.hdr.icmp_hdr.code = it->mask.icmp.code;
			set_bit(SXE2_FLOW_FLD_ID_ICMP_CODE, map_spec);
			LOG_DEBUG_BDF("prot_type %d, icmp code[%d], mask[0x%x]\n",
				      item->type, it->val.icmp.code,
				      it->mask.icmp.code);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_ICMP_IDENT, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_ICMP_IDENT];
			item->value.hdr.icmp_hdr.ident = it->val.icmp.ident;
			item->mask.hdr.icmp_hdr.ident = it->mask.icmp.ident;
			set_bit(SXE2_FLOW_FLD_ID_ICMP_IDENT, map_spec);
			LOG_DEBUG_BDF("prot_type %d, icmp ident[%u], mask[0x%x]\n",
				      item->type, it->val.icmp.ident,
				      it->mask.icmp.ident);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_IPV_FRAG, pattern_in->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_in, SXE2_FLOW_HDR_IPV_FRAG);
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_FRAG_NEXT_HDR, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_IPV6_FRAG_NEXT_HDR];
			item->value.hdr.ipv6_frag_hdr.next_hdr = it->val.ipv6_frag.next_hdr;
			item->mask.hdr.ipv6_frag_hdr.next_hdr = it->mask.ipv6_frag.next_hdr;
			set_bit(SXE2_FLOW_FLD_ID_IPV6_FRAG_NEXT_HDR, map_spec);
			LOG_DEBUG_BDF("prot_type %d, ipv6 frag next_hdr[%d], mask[0x%x]\n",
				      item->type, it->val.ipv6_frag.next_hdr,
				      it->mask.ipv6_frag.next_hdr);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_FRAG_DATA, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_IPV6_FRAG_DATA];
			item->value.hdr.ipv6_frag_hdr.frag_data = it->val.ipv6_frag.frag_data;
			item->mask.hdr.ipv6_frag_hdr.frag_data = it->mask.ipv6_frag.frag_data;
			set_bit(SXE2_FLOW_FLD_ID_IPV6_FRAG_DATA, map_spec);
			LOG_DEBUG_BDF("prot_type %d, ipv6 frag data[%u], mask[0x%x]\n",
				      item->type, it->val.ipv6_frag.frag_data,
				      it->mask.ipv6_frag.frag_data);
		}

		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_ID, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_IPV6_FRAG_ID];
			item->value.hdr.ipv6_frag_hdr.ident = it->val.ipv6_frag.ident;
			item->mask.hdr.ipv6_frag_hdr.ident = it->mask.ipv6_frag.ident;
			set_bit(SXE2_FLOW_FLD_ID_IPV6_ID, map_spec);
			LOG_DEBUG_BDF("prot_type %d, ipv6 frag id[%u], mask[0x%x]\n",
				      item->type, it->val.ipv6_frag.ident,
				      it->mask.ipv6_frag.ident);
		}
	}

	if (test_bit(SXE2_FLOW_HDR_GRE, pattern_in->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern_in, SXE2_FLOW_HDR_GRE);
		if (it && test_bit(SXE2_FLOW_FLD_ID_GRE_PROTO, pattern_in->map_spec)) {
			item = &fltr->items[SXE2_GRE_PROTOCOL];
			item->value.hdr.gre_hdr.protocol = it->val.gre.protocol;
			item->mask.hdr.gre_hdr.protocol = it->mask.gre.protocol;
			set_bit(SXE2_FLOW_FLD_ID_GRE_PROTO, map_spec);
			LOG_DEBUG_BDF("prot_type %d, gre protocol[%u], mask[0x%x]\n",
				      item->type, it->val.gre.protocol,
				      it->mask.gre.protocol);
		}
	}

	if (!bitmap_equal(pattern_in->map_spec, map_spec, SXE2_FLOW_FLD_ID_MAX)) {
		ret = -EINVAL;
		goto l_end;
	}
l_end:
	return ret;
}

static s32 sxe2_com_flow_switch_pattern_post_proc(struct sxe2_user_cpx_fltr *fltr)
{
	struct sxe2_tcf_key_item *item;
	u16 i, j;

	for (i = 0; i < SXE2_PROT_FIELD_LAST; i++) {
		item = &fltr->items[i];
		for (j = 0; j < ARRAY_SIZE(item->mask.raw); j++)
			item->value.raw[j] = item->value.raw[j] & item->mask.raw[j];
	}
	return 0;
}

static s32 sxe2_com_flow_switch_action(struct sxe2_adapter *adapter,
				       struct sxe2_flow_action *flow_action,
				       u16 rule_vsi_id, struct sxe2_user_cpx_fltr *fltr)
{
	s32 ret = 0;
	u8 cnt = 0;

	fltr->dst_vsi_id = rule_vsi_id;
	if (test_bit(SXE2_FLOW_ACTION_DROP, flow_action->act_types)) {
		fltr->action = SXE2_DROP_PACKET;
		cnt++;
	}
	if (test_bit(SXE2_FLOW_ACTION_QUEUE, flow_action->act_types)) {
		fltr->action = SXE2_FWD_TO_Q;
		fltr->dst_vsi_id = flow_action->queue.vsi_index;
		fltr->dst_queue_id = flow_action->queue.q_index;
		fltr->dst_queue_high = true;
		cnt++;
	}
	if (test_bit(SXE2_FLOW_ACTION_Q_REGION, flow_action->act_types)) {
		fltr->action = SXE2_FWD_TO_QGRP;
		fltr->dst_vsi_id = flow_action->q_region.vsi_index;
		fltr->dst_queue_id = flow_action->q_region.q_index;
		fltr->dst_queue_group = flow_action->q_region.region;
		fltr->dst_queue_high = true;
		cnt++;
	}
	if (test_bit(SXE2_FLOW_ACTION_TO_VSI, flow_action->act_types)) {
		fltr->dst_vsi_id = flow_action->vsi.vsi_index;
		fltr->action = SXE2_FWD_TO_VSI;
		cnt++;
	}
	if (test_bit(SXE2_FLOW_ACTION_TO_VSI_LIST, flow_action->act_types)) {
		fltr->action = SXE2_FWD_TO_VSI_LIST;
		memcpy(fltr->dst_vsi_map, flow_action->vsi_list.vsi_list_map,
		       sizeof(fltr->dst_vsi_map));
		cnt++;
	}
	if (cnt > 1)
		ret = -EINVAL;

	LOG_DEBUG_BDF("action %d,dst_vsi_id[%d],dst_queue_id[%d],dst_queue_group[%d]\n",
		      fltr->action, fltr->dst_vsi_id, fltr->dst_queue_id,
		      fltr->dst_queue_group);
	return ret;
}

static s32 sxe2_com_flow_switch_filter(struct sxe2_adapter *adapter, u16 rule_vsi_id,
				       bool is_add, struct sxe2_drv_flow_filter_req_ext *req)
{
	struct sxe2_user_cpx_fltr *user_cpx_fltr;
	s32 ret = 0;

	user_cpx_fltr = kzalloc(sizeof(*user_cpx_fltr), GFP_KERNEL);
	if (!user_cpx_fltr) {
		LOG_ERROR_BDF("alloc memory failed, size %ld\n", sizeof(*user_cpx_fltr));
		ret = -ENOMEM;
		goto l_end;
	}
	user_cpx_fltr->adapter = adapter;

	ret = sxe2_com_flow_switch_meta(adapter, rule_vsi_id, req, user_cpx_fltr);
	if (ret) {
		LOG_ERROR_BDF("switch meta error, ret=%d\n", ret);
		goto l_end;
	}

	ret = sxe2_com_flow_switch_pattern_outer(adapter, &req->pattern_outer,
						 user_cpx_fltr);
	if (ret) {
		LOG_ERROR_BDF("switch pattern outer error, ret=%d\n", ret);
		goto l_end;
	}

	ret = sxe2_com_flow_switch_pattern_inner(adapter, &req->pattern_inner,
						 user_cpx_fltr);
	if (ret) {
		LOG_ERROR_BDF("switch pattern inner error, ret=%d\n", ret);
		goto l_end;
	}

	ret = sxe2_com_flow_switch_pattern_post_proc(user_cpx_fltr);
	if (ret) {
		LOG_ERROR_BDF("switch pattern post proc error, ret=%d\n", ret);
		goto l_end;
	}

	ret = sxe2_com_flow_switch_action(adapter, &req->action, rule_vsi_id,
					  user_cpx_fltr);
	if (ret) {
		LOG_ERROR_BDF("switch action error, ret=%d\n", ret);
		goto l_end;
	}

	ret = sxe2_ucmd_complex_fltr_proc(user_cpx_fltr, is_add);
	if (ret)
		LOG_ERROR_BDF("switch complex rule config failed, ret=%d\n", ret);

l_end:
	kfree(user_cpx_fltr);
	return ret;
}

static s32 sxe2_com_flow_switch_filter_add(struct sxe2_adapter *adapter, u16 rule_vsi_id,
					   struct sxe2_drv_flow_filter_req_ext *req,
					   struct sxe2_drv_flow_filter_resp *resp)
{
	s32 ret = 0;
	static u32 flow_id;

	ret = sxe2_com_flow_switch_filter(adapter, rule_vsi_id, true, req);
	if (!ret) {
		resp->flow_id = flow_id;
		resp->engine_type = SXE2_FLOW_ENGINE_SWITCH;
		flow_id++;
	}

	return ret;
}

static s32 sxe2_com_flow_switch_filter_del(struct sxe2_adapter *adapter, u16 rule_vsi_id,
					   struct sxe2_drv_flow_filter_req_ext *req)
{
	return sxe2_com_flow_switch_filter(adapter, rule_vsi_id, false, req);
}

static void sxe2_com_fnav_fld_convert_msg(unsigned long *flds,
					  struct sxe2_fnav_comm_proto_hdr *proto_hdr)
{
	u32 tmp_flds[BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX)];
	u32 i = 0;

	bitmap_to_arr32(tmp_flds, flds, SXE2_FLOW_FLD_ID_MAX);

	for (i = 0; i < BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX); i++)
		proto_hdr->flds[i] = cpu_to_le32(tmp_flds[i]);
}

static s32
sxe2_com_flow_fnav_filter_add_pattern(struct sxe2_fnav_comm_proto_hdr *proto_hdr,
				      const struct sxe2_flow_pattern_ext *pattern,
				      u8 is_inner)
{
	u8 cnt = 0;
	u8 tunnel_level = is_inner ? SXE2_FNAV_TUNNEL_INNER : SXE2_FNAV_TUNNEL_OUTER;
	struct sxe2_fnav_comm_proto_hdr *hdr = &proto_hdr[cnt];
	const struct sxe2_flow_item_ext *it;
	DECLARE_BITMAP(flds, SXE2_FLOW_FLD_ID_MAX);

	if (test_bit(SXE2_FLOW_HDR_ETH, pattern->hdrs)) {
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_ETH);
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_ETH;
		hdr->tunnel_level = tunnel_level;
		bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
		if (it && test_bit(SXE2_FLOW_FLD_ID_ETH_DA, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_ETH_DA, flds);
			memcpy(hdr->eth.dst, it->val.eth.dst_addr,
			       SXE2_FNAV_ETH_ADDR_LEN);
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_ETH_SA, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_ETH_SA, flds);
			memcpy(hdr->eth.src, it->val.eth.src_addr,
			       SXE2_FNAV_ETH_ADDR_LEN);
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_ETH_TYPE, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_ETH_TYPE, flds);
			hdr->eth.etype = it->val.eth.ether_type;
		}
		sxe2_com_fnav_fld_convert_msg(flds, hdr);
	}
	if (test_bit(SXE2_FLOW_HDR_VLAN, pattern->hdrs)) {
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_VLAN;
		hdr->tunnel_level = tunnel_level;
		bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_VLAN);
		if (it && test_bit(SXE2_FLOW_FLD_ID_S_TPID, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_S_TPID, flds);
			hdr->vlan.vlan_type = it->val.vlan.type;
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_S_TCI, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_S_TCI, flds);
			hdr->vlan.vlan_tci = it->val.vlan.vlan;
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_S_VID, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_S_VID, flds);
			hdr->vlan.vlan_vid = it->val.vlan.vlan;
		}
		sxe2_com_fnav_fld_convert_msg(flds, hdr);
	}

	if (test_bit(SXE2_FLOW_HDR_QINQ, pattern->hdrs)) {
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_VLAN;
		hdr->tunnel_level = tunnel_level;
		bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_QINQ);
		if (it && test_bit(SXE2_FLOW_FLD_ID_C_TPID, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_C_TPID, flds);
			hdr->vlan.vlan_type = it->val.qinq.type;
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_C_TCI, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_C_TCI, flds);
			hdr->vlan.vlan_tci = it->val.qinq.vlan;
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_C_VID, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_C_VID, flds);
			hdr->vlan.vlan_vid = it->val.qinq.vlan;
		}
		sxe2_com_fnav_fld_convert_msg(flds, hdr);
	}

	if (test_bit(SXE2_FLOW_HDR_IPV4, pattern->hdrs)) {
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_IPV4;
		hdr->tunnel_level = tunnel_level;
		bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_IPV4);
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_SA, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, flds);
			hdr->ipv4.saddr = it->val.ipv4.saddr;
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_DA, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, flds);
			hdr->ipv4.daddr = it->val.ipv4.daddr;
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_TOS, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_IPV4_TOS, flds);
			hdr->ipv4.tos = it->val.ipv4.tos;
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_TTL, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_IPV4_TTL, flds);
			hdr->ipv4.ttl = it->val.ipv4.ttl;
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV4_PROT, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_IPV4_PROT, flds);
			hdr->ipv4.proto = it->val.ipv4.protocol;
		}
		sxe2_com_fnav_fld_convert_msg(flds, hdr);
	}

	if (test_bit(SXE2_FLOW_HDR_IPV6, pattern->hdrs)) {
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_IPV6;
		hdr->tunnel_level = tunnel_level;
		bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_IPV6);
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_SA, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, flds);
			memcpy(hdr->ipv6.src_ip, it->val.ipv6.saddr,
			       SXE2_IPV6_ADDR_LENGTH);
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_DA, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, flds);
			memcpy(hdr->ipv6.dst_ip, it->val.ipv6.daddr,
			       SXE2_IPV6_ADDR_LENGTH);
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_DSCP, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_IPV6_DSCP, flds);
			hdr->ipv6.tc = (be32_to_cpu(it->val.ipv6.pri_ver_flow) >>
				       SXE2_IPV6_TC_SHIFT) &
				       SXE2_IPV6_TC_MASK;
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_TTL, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_IPV6_TTL, flds);
			hdr->ipv6.hlim = it->val.ipv6.hop_limit;
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_IPV6_PROT, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_IPV6_PROT, flds);
			hdr->ipv6.proto = it->val.ipv6.nexthdr;
		}
		sxe2_com_fnav_fld_convert_msg(flds, hdr);
	}
	if (test_bit(SXE2_FLOW_HDR_IPV_FRAG, pattern->hdrs)) {
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_IPV_FRAG;
		hdr->tunnel_level = tunnel_level;
	}
	if (test_bit(SXE2_FLOW_HDR_IPV_OTHER, pattern->hdrs)) {
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_IPV_OTHER;
		hdr->tunnel_level = tunnel_level;
	}

	if (test_bit(SXE2_FLOW_HDR_TCP, pattern->hdrs)) {
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_TCP;
		hdr->tunnel_level = tunnel_level;
		bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_TCP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, flds);
			hdr->l4.src_port = it->val.tcp.source;
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, flds);
			hdr->l4.dst_port = it->val.tcp.dest;
		}
		sxe2_com_fnav_fld_convert_msg(flds, hdr);
	}
	if (test_bit(SXE2_FLOW_HDR_UDP, pattern->hdrs)) {
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_UDP;
		hdr->tunnel_level = tunnel_level;
		bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_UDP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, flds);
			hdr->l4.src_port = it->val.udp.source;
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, flds);
			hdr->l4.dst_port = it->val.udp.dest;
		}
		sxe2_com_fnav_fld_convert_msg(flds, hdr);
	}
	if (test_bit(SXE2_FLOW_HDR_SCTP, pattern->hdrs)) {
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_SCTP;
		hdr->tunnel_level = tunnel_level;
		bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_SCTP);
		if (it && test_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, flds);
			hdr->l4.src_port = it->val.sctp.src_port;
		}
		if (it && test_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, flds);
			hdr->l4.dst_port = it->val.sctp.dst_port;
		}
		sxe2_com_fnav_fld_convert_msg(flds, hdr);
	}
	if (test_bit(SXE2_FLOW_HDR_GENEVE, pattern->hdrs)) {
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_GENEVE;
		hdr->tunnel_level = tunnel_level;
		bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_GENEVE);
		if (it && test_bit(SXE2_FLOW_FLD_ID_GENEVE_VNI, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_GENEVE_VNI, flds);
			hdr->geneve.vni = it->val.geneve.vni;
		}
		sxe2_com_fnav_fld_convert_msg(flds, hdr);
	}
	if (test_bit(SXE2_FLOW_HDR_VXLAN, pattern->hdrs)) {
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_VXLAN;
		hdr->tunnel_level = tunnel_level;
		bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_VXLAN);
		if (it && test_bit(SXE2_FLOW_FLD_ID_VXLAN_VNI, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_VXLAN_VNI, flds);
			hdr->vxlan.vni = it->val.vxlan.vni;
		}
		sxe2_com_fnav_fld_convert_msg(flds, hdr);
	}
	if (test_bit(SXE2_FLOW_HDR_GTPU, pattern->hdrs)) {
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_GTPU;
		hdr->tunnel_level = tunnel_level;
		bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_GTPU);
		if (it && test_bit(SXE2_FLOW_FLD_ID_GTPU_TEID, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_GTPU_TEID, flds);
			hdr->gtpu.teid = it->val.gtpu.teid;
		}
		sxe2_com_fnav_fld_convert_msg(flds, hdr);
	}
	if (test_bit(SXE2_FLOW_HDR_GRE, pattern->hdrs)) {
		hdr = &proto_hdr[cnt];
		cnt++;
		hdr->type = SXE2_FLOW_HDR_GRE;
		hdr->tunnel_level = tunnel_level;
		bitmap_zero(flds, SXE2_FLOW_FLD_ID_MAX);
		it = sxe2_flow_pattern_ext_item_find(pattern, SXE2_FLOW_HDR_GRE);
		if (it && test_bit(SXE2_FLOW_FLD_ID_NVGRE_TNI, pattern->map_spec)) {
			set_bit(SXE2_FLOW_FLD_ID_NVGRE_TNI, flds);
			hdr->gre.tni = it->val.nvgre.tni;
		}
		sxe2_com_fnav_fld_convert_msg(flds, hdr);
	}
	return cnt;
}

static s32 sxe2_com_flow_fnav_filter_add_action(struct sxe2_fnav_comm_action *action,
						struct sxe2_flow_action *flow_action,
						u16 *dst_vsi_id)
{
	u8 cnt = 0;

	if (test_bit(SXE2_FLOW_ACTION_QUEUE, flow_action->act_types)) {
		if (cnt >= SXE2_FNAV_MAX_NUM_ACTIONS)
			return -EINVAL;
		*dst_vsi_id = flow_action->queue.vsi_index;
		action[cnt].type = cpu_to_le32(SXE2_FNAV_ACTION_QUEUE);
		action[cnt].act_queue.q_index = cpu_to_le16(flow_action->queue.q_index);
		cnt++;
	}
	if (test_bit(SXE2_FLOW_ACTION_Q_REGION, flow_action->act_types)) {
		if (cnt >= SXE2_FNAV_MAX_NUM_ACTIONS)
			return -EINVAL;
		*dst_vsi_id =  flow_action->q_region.vsi_index;
		action[cnt].type = cpu_to_le32(SXE2_FNAV_ACTION_Q_REGION);
		action[cnt].act_q_region.q_index = cpu_to_le16(flow_action->q_region.q_index);
		action[cnt].act_q_region.region = flow_action->q_region.region;
		cnt++;
	}
	if (test_bit(SXE2_FLOW_ACTION_MARK, flow_action->act_types)) {
		if (cnt >= SXE2_FNAV_MAX_NUM_ACTIONS)
			return -EINVAL;
		action[cnt].type = cpu_to_le32(SXE2_FNAV_ACTION_MARK);
		action[cnt].act_mark.mark_id = cpu_to_le32(flow_action->mark.mark_id);
		cnt++;
	}
	if (test_bit(SXE2_FLOW_ACTION_COUNT, flow_action->act_types)) {
		if (cnt >= SXE2_FNAV_MAX_NUM_ACTIONS)
			return -EINVAL;
		action[cnt].type = cpu_to_le32(SXE2_FNAV_ACTION_COUNT);
		action[cnt].act_count.stat_ctrl = cpu_to_le32(flow_action->count.stat_ctrl);
		action[cnt].act_count.stat_index = cpu_to_le32(flow_action->count.stat_index);
		cnt++;
	}
	if (test_bit(SXE2_FLOW_ACTION_PASSTHRU, flow_action->act_types)) {
		if (cnt >= SXE2_FNAV_MAX_NUM_ACTIONS)
			return -EINVAL;
		*dst_vsi_id = flow_action->passthru.vsi_index;
		action[cnt].type = cpu_to_le32(SXE2_FNAV_ACTION_PASSTHRU);
		cnt++;
	}
	if (test_bit(SXE2_FLOW_ACTION_DROP, flow_action->act_types)) {
		if (cnt >= SXE2_FNAV_MAX_NUM_ACTIONS)
			return -EINVAL;
		action[cnt].type = cpu_to_le32(SXE2_FNAV_ACTION_DROP);
		cnt++;
	}
	if (test_bit(SXE2_FLOW_ACTION_TO_VSI, flow_action->act_types))
		*dst_vsi_id = flow_action->vsi.vsi_index;

	return cnt;
}

static s32 sxe2_com_flow_fnav_filter_add(struct sxe2_adapter *adapter, u16 rule_vsi_id,
					 struct sxe2_drv_flow_filter_req_ext *req,
					 struct sxe2_drv_flow_filter_resp *resp)
{
	u16 src_vsi_id = cpu_to_le16(req->meta.flow_src_vsi);
	u16 dst_vsi_id = cpu_to_le16(req->meta.flow_src_vsi);
	struct sxe2_fnav_comm_full_msg filter_msg = {0};
	u32 flow_id = 0;
	u8 hdr_cnt_out = 0;
	u8 hdr_cnt_in = 0;
	s32 action_cnt = 0;
	s32 ret = 0;

	filter_msg.filter_loc = cpu_to_le32(0xffffffff);
	filter_msg.flow_type = cpu_to_le16(req->meta.flow_type);

	if (bitmap_weight(req->pattern_inner.hdrs, SXE2_FLOW_HDR_MAX) +
			    bitmap_weight(req->pattern_outer.hdrs, SXE2_FLOW_HDR_MAX) >
	    SXE2_FNAV_MAX_NUM_PROTO_HDRS) {
		LOG_ERROR_BDF("too many proto hdrs, outer hdrs=%u, inner hdrs=%u\n",
			      bitmap_weight(req->pattern_outer.hdrs, SXE2_FLOW_HDR_MAX),
			      bitmap_weight(req->pattern_inner.hdrs, SXE2_FLOW_HDR_MAX));
		ret = -EINVAL;
		goto l_end;
	}

	hdr_cnt_out = sxe2_com_flow_fnav_filter_add_pattern(filter_msg.proto_hdr,
							    &req->pattern_outer, false);
	hdr_cnt_in = sxe2_com_flow_fnav_filter_add_pattern(&filter_msg.proto_hdr[hdr_cnt_out],
							   &req->pattern_inner, true);
	if (hdr_cnt_in + hdr_cnt_out > SXE2_FNAV_MAX_NUM_PROTO_HDRS) {
		LOG_ERROR_BDF("too many proto hdrs, hdr_cnt_out=%u, hdr_cnt_in=%u\n",
			      hdr_cnt_out, hdr_cnt_in);
		ret = -EINVAL;
		goto l_end;
	}
	if (hdr_cnt_in > 0)
		filter_msg.tunn_flag = cpu_to_le32(SXE2_FNAV_TUN_FLAG_TUNNEL);
	else
		filter_msg.tunn_flag = cpu_to_le32(SXE2_FNAV_TUN_FLAG_NO_TUNNEL);

	filter_msg.proto_cnt = hdr_cnt_out + hdr_cnt_in;

	action_cnt = sxe2_com_flow_fnav_filter_add_action(filter_msg.action, &req->action,
							  &dst_vsi_id);
	if (action_cnt < 0) {
		LOG_ERROR_BDF("too many actions, action_cnt=%d\n", action_cnt);
		ret = action_cnt;
		goto l_end;
	}
	if (action_cnt > SXE2_FNAV_MAX_NUM_ACTIONS) {
		LOG_ERROR_BDF("too many actions, action_cnt=%u\n", action_cnt);
		ret = -EINVAL;
		goto l_end;
	}
	filter_msg.action_cnt = (u8)action_cnt;

	ret = sxe2_com_flow_vsi_id_change(adapter, src_vsi_id, &src_vsi_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_com_flow_vsi_id_change failed, ret=%d\n", ret);
		goto l_end;
	}
	ret = sxe2_com_flow_vsi_id_change(adapter, dst_vsi_id, &dst_vsi_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_com_flow_vsi_id_change failed, ret=%d\n", ret);
		goto l_end;
	}
	ret = sxe2_com_flow_vsi_id_change(adapter, rule_vsi_id, &rule_vsi_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_com_flow_vsi_id_change failed, ret=%d\n", ret);
		goto l_end;
	}
	ret = sxe2_comm_add_fnav_filter(adapter, src_vsi_id, dst_vsi_id, rule_vsi_id,
					&filter_msg, &flow_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_comm_add_fnav_filter failed, ret=%d\n", ret);
		goto l_end;
	}
	resp->flow_id = flow_id;
	resp->engine_type = SXE2_FLOW_ENGINE_FNAV;
l_end:
	return ret;
}

static s32 sxe2_com_flow_acl_filter_add(struct sxe2_adapter *adapter, u16 rule_vsi_id,
					struct sxe2_drv_flow_filter_req_ext *req,
				 struct sxe2_drv_flow_filter_resp *resp)
{
	s32 ret = 0;
	u32 flow_id = 0;
	u16 ori_vsi_id = cpu_to_le16(req->meta.flow_src_vsi);

	if (!test_bit(SXE2_FLAG_ACL_CAPABLE, adapter->flags)) {
		LOG_INFO_BDF("acl not supported.\n");
		return -EOPNOTSUPP;
	}

	ret = sxe2_com_flow_vsi_id_change(adapter, ori_vsi_id, &ori_vsi_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_com_flow_vsi_id_change failed, ret=%d\n", ret);
		goto l_end;
	}
	ret = sxe2_com_flow_vsi_id_change(adapter, rule_vsi_id, &rule_vsi_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_com_flow_vsi_id_change failed, ret=%d\n", ret);
		goto l_end;
	}

	ret = sxe2_com_add_acl_filter(adapter, ori_vsi_id, rule_vsi_id, req->meta.flow_type,
				      &req->pattern_outer, &req->action, &flow_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_comm_add_fnav_filter failed, ret=%d\n", ret);
		goto l_end;
	}

	resp->flow_id = flow_id;
	resp->engine_type = SXE2_FLOW_ENGINE_ACL;
l_end:
	return ret;
}

static s32 sxe2_com_flow_rss_filter_add(struct sxe2_adapter *adapter, u16 rule_vsi_id,
					struct sxe2_drv_flow_filter_req_ext *req,
					struct sxe2_drv_flow_filter_resp *resp)
{
	s32 ret = 0;
	struct sxe2_rss_hash_cfg hash_cfg;
	struct sxe2_flow_action_rss *rss = &req->action.rss;

	(void)memset(&hash_cfg, 0, sizeof(hash_cfg));

	if (!test_bit(SXE2_FLOW_ACTION_RSS, req->action.act_types)) {
		ret = -EINVAL;
		LOG_ERROR_BDF("rss action is not set\n");
		goto l_end;
	}
	if (rss->func != SXE2_RSS_HASH_FUNC_XOR) {
		hash_cfg.hdr_type = rss->hdr_type;
		if (rss->func == SXE2_RSS_HASH_FUNC_TOEPLITZ) {
			hash_cfg.symm = 0;
		} else if (rss->func == SXE2_RSS_HASH_FUNC_SYM_TOEPLITZ) {
			hash_cfg.symm = 1;
		} else {
			ret = -EINVAL;
			LOG_ERROR_BDF("invalid rss hash func %u\n", rss->func);
			goto l_end;
		}
		if (rss->is_inner) {
			bitmap_copy(hash_cfg.headers, rss->hdr_in, SXE2_FLOW_HDR_MAX);
		} else {
			bitmap_copy(hash_cfg.headers, rss->hdr_out, SXE2_FLOW_HDR_MAX);
			clear_bit(SXE2_FLOW_HDR_QINQ, hash_cfg.headers);
		}
		bitmap_copy(hash_cfg.hash_flds, rss->fld, SXE2_FLOW_FLD_ID_MAX);

		ret = sxe2_com_flow_vsi_id_change(adapter, rule_vsi_id, &rule_vsi_id);
		if (ret) {
			LOG_ERROR_BDF("sxe2_com_flow_vsi_id_change failed, ret=%d\n",
				      ret);
			goto l_end;
		}

		ret = sxe2_add_rss_flow(&adapter->rss_flow_ctxt, rule_vsi_id, &hash_cfg);
		if (ret) {
			LOG_ERROR_BDF("sxe2_add_rss_flow failed, ret=%d\n", ret);
			goto l_end;
		}
	}

	sxe2_com_flow_rss_flow_id++;
	resp->flow_id = sxe2_com_flow_rss_flow_id;
	resp->engine_type = SXE2_FLOW_ENGINE_RSS;

l_end:
	return ret;
}

static bool sxe2_com_flow_switch_only_fld(const struct sxe2_flow_pattern_ext *pattern)
{
	return find_next_bit(pattern->map_spec, SXE2_FLOW_FLD_ID_MAX,
			     SXE2_FLOW_FLD_ID_ESP_SPI) < SXE2_FLOW_FLD_ID_MAX;
}

static s32 sxe2_com_flow_legacy_to_ext_one(struct sxe2_adapter *adapter,
					   const struct sxe2_flow_pattern *in,
					   struct sxe2_flow_pattern_ext *out)
{
	static const struct sxe2_com_flow_legacy_hdr_map {
		enum sxe2_flow_hdr type;
		u16 off;
		u16 len;
	} legacy_map[] = {
		{ SXE2_FLOW_HDR_ETH,	 offsetof(struct sxe2_flow_item, eth),
		  sizeof(((struct sxe2_flow_item *)0)->eth) },
		{ SXE2_FLOW_HDR_VLAN,	 offsetof(struct sxe2_flow_item, vlan),
		  sizeof(((struct sxe2_flow_item *)0)->vlan) },
		{ SXE2_FLOW_HDR_QINQ,	 offsetof(struct sxe2_flow_item, qinq),
		  sizeof(((struct sxe2_flow_item *)0)->qinq) },
		{ SXE2_FLOW_HDR_IPV4,	 offsetof(struct sxe2_flow_item, ipv4),
		  sizeof(((struct sxe2_flow_item *)0)->ipv4) },
		{ SXE2_FLOW_HDR_IPV6,	 offsetof(struct sxe2_flow_item, ipv6),
		  sizeof(((struct sxe2_flow_item *)0)->ipv6) },
		{ SXE2_FLOW_HDR_TCP,	 offsetof(struct sxe2_flow_item, tcp),
		  sizeof(((struct sxe2_flow_item *)0)->tcp) },
		{ SXE2_FLOW_HDR_UDP,	 offsetof(struct sxe2_flow_item, udp),
		  sizeof(((struct sxe2_flow_item *)0)->udp) },
		{ SXE2_FLOW_HDR_SCTP,	 offsetof(struct sxe2_flow_item, sctp),
		  sizeof(((struct sxe2_flow_item *)0)->sctp) },
		{ SXE2_FLOW_HDR_GTPU,	 offsetof(struct sxe2_flow_item, gtpu),
		  sizeof(((struct sxe2_flow_item *)0)->gtpu) },
		{ SXE2_FLOW_HDR_VXLAN,	 offsetof(struct sxe2_flow_item, vxlan),
		  sizeof(((struct sxe2_flow_item *)0)->vxlan) },
		{ SXE2_FLOW_HDR_GENEVE,	 offsetof(struct sxe2_flow_item, geneve),
		  sizeof(((struct sxe2_flow_item *)0)->geneve) },
		{ SXE2_FLOW_HDR_GRE,	 offsetof(struct sxe2_flow_item, nvgre),
		  sizeof(((struct sxe2_flow_item *)0)->nvgre) },
	};
	DECLARE_BITMAP(known, SXE2_FLOW_HDR_MAX);
	DECLARE_BITMAP(unknown, SXE2_FLOW_HDR_MAX);
	struct sxe2_flow_item_ext *slot;
	u8 i;

	bitmap_zero(known, SXE2_FLOW_HDR_MAX);
	for (i = 0; i < ARRAY_SIZE(legacy_map); i++)
		set_bit(legacy_map[i].type, known);

	set_bit(SXE2_FLOW_HDR_IPV_FRAG, known);
	set_bit(SXE2_FLOW_HDR_IPV_OTHER, known);
	set_bit(SXE2_FLOW_HDR_ETH_NON_IP, known);

	bitmap_andnot(unknown, in->hdrs, known, SXE2_FLOW_HDR_MAX);
	if (!bitmap_empty(unknown, SXE2_FLOW_HDR_MAX)) {
		LOG_ERROR_BDF("legacy pattern has non-legacy hdr bits\n");
		return -EINVAL;
	}

	bitmap_copy(out->hdrs, in->hdrs, SXE2_FLOW_HDR_MAX);
	bitmap_copy(out->map_spec, in->map_spec, SXE2_FLOW_FLD_ID_MAX);
	bitmap_copy(out->map_mask, in->map_mask, SXE2_FLOW_FLD_ID_MAX);
	out->rss_type_allow = in->rss_type_allow;

	for (i = 0; i < ARRAY_SIZE(legacy_map); i++) {
		if (!test_bit(legacy_map[i].type, in->hdrs))
			continue;

		if (out->nr_items >= SXE2_FLOW_ITEM_MAX) {
			LOG_ERROR_BDF("legacy pattern overflow ext slots\n");
			return -EINVAL;
		}

		slot = &out->item[out->nr_items++];
		slot->type = legacy_map[i].type;
		memcpy(&slot->val, (const u8 *)&in->item_spec + legacy_map[i].off,
		       legacy_map[i].len);
		memcpy(&slot->mask, (const u8 *)&in->item_mask + legacy_map[i].off,
		       legacy_map[i].len);
	}

	return 0;
}

static s32 sxe2_com_flow_ext_pattern_check(struct sxe2_adapter *adapter,
					   const struct sxe2_flow_pattern_ext *p)
{
	u8 i;

	for (i = 0; i < p->nr_items && i < SXE2_FLOW_ITEM_MAX; i++) {
		if (p->item[i].type >= SXE2_FLOW_HDR_MAX ||
		    !test_bit(p->item[i].type, p->hdrs)) {
			LOG_ERROR_BDF("ext item %u type %d invalid\n",
				      i, p->item[i].type);
			return -EINVAL;
		}
	}

	return 0;
}

static s32 sxe2_com_flow_fnav_filter_del(struct sxe2_adapter *adapter, u16 rule_vsi_id,
					 struct sxe2_drv_flow_filter_req_ext *req);
static s32 sxe2_com_flow_acl_filter_del(struct sxe2_adapter *adapter, u16 rule_vsi_id,
					struct sxe2_drv_flow_filter_req_ext *req);
static s32 sxe2_com_flow_rss_filter_del(struct sxe2_adapter *adapter, u16 rule_vsi_id,
					struct sxe2_drv_flow_filter_req_ext *req);

static s32 sxe2_com_flow_filter_add_dispatch(struct sxe2_adapter *adapter,
					     u16 rule_vsi_id,
					     struct sxe2_drv_flow_filter_req_ext *req,
					     struct sxe2_drv_flow_filter_resp *resp)
{
	s32 ret;

	if (req->engine_type == SXE2_FLOW_ENGINE_RSS) {
		ret = sxe2_com_flow_rss_filter_add(adapter, rule_vsi_id, req, resp);
	} else if (req->engine_type == SXE2_FLOW_ENGINE_FNAV) {
		ret = sxe2_com_flow_fnav_filter_add(adapter, rule_vsi_id, req, resp);
	} else if (req->engine_type == SXE2_FLOW_ENGINE_SWITCH) {
		ret = sxe2_com_flow_switch_filter_add(adapter, rule_vsi_id, req, resp);
	} else if (req->engine_type == SXE2_FLOW_ENGINE_ACL) {
		ret = sxe2_com_flow_acl_filter_add(adapter, rule_vsi_id, req, resp);
	} else {
		LOG_ERROR_BDF("invalid flow engine type %d\n", req->engine_type);
		ret = -EINVAL;
	}

	return ret;
}

static s32 sxe2_com_flow_filter_del_dispatch(struct sxe2_adapter *adapter,
					     u16 rule_vsi_id,
					     struct sxe2_drv_flow_filter_req_ext *req)
{
	s32 ret;

	if (req->engine_type == SXE2_FLOW_ENGINE_RSS) {
		ret = sxe2_com_flow_rss_filter_del(adapter, rule_vsi_id, req);
	} else if (req->engine_type == SXE2_FLOW_ENGINE_FNAV) {
		ret = sxe2_com_flow_fnav_filter_del(adapter, rule_vsi_id, req);
	} else if (req->engine_type == SXE2_FLOW_ENGINE_SWITCH) {
		ret = sxe2_com_flow_switch_filter_del(adapter, rule_vsi_id, req);
	} else if (req->engine_type == SXE2_FLOW_ENGINE_ACL) {
		ret = sxe2_com_flow_acl_filter_del(adapter, rule_vsi_id, req);
	} else {
		LOG_ERROR_BDF("invalid flow engine type %d\n", req->engine_type);
		ret = -EINVAL;
	}

	return ret;
}

s32 sxe2_com_flow_filter_add(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			     struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_flow_filter_req_ext *req_ext = NULL;
	struct sxe2_drv_flow_filter_req *req;
	struct sxe2_drv_flow_filter_resp resp = {0};
	u16 rule_vsi_id = 0;
	s32 ret = 0;

	req = (struct sxe2_drv_flow_filter_req *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_free_req;
	}
	rule_vsi_id = req->meta.flow_rule_vsi;

	req_ext = kzalloc(sizeof(*req_ext), GFP_KERNEL);
	if (!req_ext) {
		LOG_ERROR_BDF("alloc memory failed, size %lu\n", sizeof(*req_ext));
		ret = -ENOMEM;
		goto l_free_req;
	}
	req_ext->flow_id = req->flow_id;
	req_ext->engine_type = req->engine_type;
	memcpy(&req_ext->meta, &req->meta, sizeof(req_ext->meta));
	memcpy(&req_ext->action, &req->action, sizeof(req_ext->action));

	ret = sxe2_com_flow_legacy_to_ext_one(adapter, &req->pattern_outer,
					      &req_ext->pattern_outer);
	if (ret) {
		LOG_ERROR_BDF("failed to convert outer pattern, ret=%d\n", ret);
		goto l_free;
	}

	ret = sxe2_com_flow_legacy_to_ext_one(adapter, &req->pattern_inner,
					      &req_ext->pattern_inner);
	if (ret) {
		LOG_ERROR_BDF("failed to convert inner pattern, ret=%d\n", ret);
		goto l_free;
	}

	if (req_ext->engine_type != SXE2_FLOW_ENGINE_SWITCH &&
	    (sxe2_com_flow_switch_only_fld(&req_ext->pattern_outer) ||
	     sxe2_com_flow_switch_only_fld(&req_ext->pattern_inner))) {
		LOG_ERROR_BDF("engine %d lacks extended fld support\n",
			      req_ext->engine_type);
		ret = -EOPNOTSUPP;
		goto l_free;
	}

	ret = sxe2_com_flow_filter_add_dispatch(adapter, rule_vsi_id, req_ext, &resp);
	if (ret)
		goto l_free;

	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%lu\n", sizeof(resp));
		ret = -EFAULT;
		goto l_free;
	}
l_free:
	kfree(req_ext);
l_free_req:
	kfree(req);
	return ret;
}

s32 sxe2_com_flow_filter_add_ext(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				 struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_flow_filter_resp_ext resp_ext = {0};
	struct sxe2_drv_flow_filter_resp resp = {0};
	struct sxe2_drv_flow_filter_req_ext *req_ext = NULL;
	u16 rule_vsi_id = 0;
	s32 ret = 0;

	if (cmd_buf->req_len < sizeof(*req_ext)) {
		LOG_ERROR_BDF("EXT add req_len too small: %u < %zu\n",
			      cmd_buf->req_len, sizeof(*req_ext));
		ret = -EINVAL;
		goto l_end;
	}

	req_ext = (struct sxe2_drv_flow_filter_req_ext *)
		  sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req_ext) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req_ext));
		ret = -EFAULT;
		goto l_end;
	}

	req_ext->flow_id = le32_to_cpu(req_ext->flow_id);
	req_ext->engine_type = le32_to_cpu(req_ext->engine_type);
	rule_vsi_id = req_ext->meta.flow_rule_vsi;

	ret = sxe2_com_flow_ext_pattern_check(adapter, &req_ext->pattern_outer);
	if (ret)
		goto l_free;

	ret = sxe2_com_flow_ext_pattern_check(adapter, &req_ext->pattern_inner);
	if (ret)
		goto l_free;

	if (req_ext->engine_type != SXE2_FLOW_ENGINE_SWITCH &&
	    (sxe2_com_flow_switch_only_fld(&req_ext->pattern_outer) ||
	     sxe2_com_flow_switch_only_fld(&req_ext->pattern_inner))) {
		LOG_ERROR_BDF("engine %d lacks extended fld support\n",
			      req_ext->engine_type);
		ret = -EOPNOTSUPP;
		goto l_free;
	}

	ret = sxe2_com_flow_filter_add_dispatch(adapter, rule_vsi_id, req_ext, &resp);
	if (ret)
		goto l_free;

	resp_ext.engine_type = cpu_to_le32(resp.engine_type);
	resp_ext.flow_id = cpu_to_le32(resp.flow_id);

	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp_ext, sizeof(resp_ext), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%lu\n", sizeof(resp_ext));
		ret = -EFAULT;
		goto l_free;
	}
l_free:
	kfree(req_ext);
l_end:
	return ret;
}

static s32 sxe2_com_flow_fnav_filter_del(struct sxe2_adapter *adapter, u16 rule_vsi_id,
					 struct sxe2_drv_flow_filter_req_ext *req)
{
	s32 ret = 0;

	ret = sxe2_com_flow_vsi_id_change(adapter, rule_vsi_id, &rule_vsi_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_com_flow_vsi_id_change failed, ret=%d\n", ret);
		goto l_end;
	}
	ret = sxe2_fnav_del_filter_by_flow_id(adapter, rule_vsi_id, req->flow_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_fnav_del_filter_by_flow_id failed, ret=%d\n", ret);
		goto l_end;
	}
l_end:
	return ret;
}

static s32 sxe2_com_flow_acl_filter_del(struct sxe2_adapter *adapter, u16 rule_vsi_id,
					struct sxe2_drv_flow_filter_req_ext *req)
{
	s32 ret = 0;

	ret = sxe2_com_flow_vsi_id_change(adapter, rule_vsi_id, &rule_vsi_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_com_flow_vsi_id_change failed, ret=%d\n", ret);
		goto l_end;
	}
	ret = sxe2_com_flow_acl_filter_del_by_flow_id(adapter, rule_vsi_id, req->flow_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_com_flow_acl_filter_del_by_flow_id failed, ret=%d\n", ret);
		goto l_end;
	}
l_end:
	return ret;
}

static s32 sxe2_com_flow_rss_filter_del(struct sxe2_adapter *adapter, u16 rule_vsi_id,
					struct sxe2_drv_flow_filter_req_ext *req)
{
	s32 ret = 0;
	struct sxe2_rss_hash_cfg hash_cfg;
	struct sxe2_flow_action_rss *rss = &req->action.rss;

	(void)memset(&hash_cfg, 0, sizeof(hash_cfg));

	if (!test_bit(SXE2_FLOW_ACTION_RSS, req->action.act_types)) {
		ret = -EINVAL;
		LOG_ERROR_BDF("rss action is not set\n");
		goto l_end;
	}
	if (rss->func != SXE2_RSS_HASH_FUNC_XOR) {
		hash_cfg.hdr_type = rss->hdr_type;
		if (rss->func == SXE2_RSS_HASH_FUNC_TOEPLITZ) {
			hash_cfg.symm = 0;
		} else if (rss->func == SXE2_RSS_HASH_FUNC_SYM_TOEPLITZ) {
			hash_cfg.symm = 1;
		} else {
			ret = -EINVAL;
			LOG_ERROR_BDF("invalid rss hash func %u\n", rss->func);
			goto l_end;
		}

		if (rss->is_inner) {
			bitmap_copy(hash_cfg.headers, rss->hdr_in, SXE2_FLOW_HDR_MAX);
		} else {
			bitmap_copy(hash_cfg.headers, rss->hdr_out, SXE2_FLOW_HDR_MAX);
			clear_bit(SXE2_FLOW_HDR_QINQ, hash_cfg.headers);
		}
		bitmap_copy(hash_cfg.hash_flds, rss->fld, SXE2_FLOW_FLD_ID_MAX);

		ret = sxe2_com_flow_vsi_id_change(adapter, rule_vsi_id, &rule_vsi_id);
		if (ret) {
			LOG_ERROR_BDF("sxe2_com_flow_vsi_id_change failed, ret=%d\n", ret);
			goto l_end;
		}
		ret = sxe2_rss_rem_cfg(&adapter->rss_flow_ctxt, rule_vsi_id, &hash_cfg);
		if (ret) {
			if (ret == -ENOENT) {
				ret = 0;
				LOG_INFO_BDF("rss cfg not found\n");
				goto l_end;
			}
			LOG_ERROR_BDF("sxe2_rss_rem_cfg failed, ret=%d\n", ret);
			goto l_end;
		}
	}
l_end:
	return ret;
}

s32 sxe2_com_flow_filter_del(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			     struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_flow_filter_req_ext *req_ext = NULL;
	struct sxe2_drv_flow_filter_req *req;
	u16 rule_vsi_id = 0;
	s32 ret = 0;

	req = (struct sxe2_drv_flow_filter_req *)sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_free_req;
	}
	rule_vsi_id = req->meta.flow_rule_vsi;

	req_ext = kzalloc(sizeof(*req_ext), GFP_KERNEL);
	if (!req_ext) {
		LOG_ERROR_BDF("alloc memory failed, size %lu\n", sizeof(*req_ext));
		ret = -ENOMEM;
		goto l_free_req;
	}
	req_ext->flow_id = req->flow_id;
	req_ext->engine_type = req->engine_type;
	memcpy(&req_ext->meta, &req->meta, sizeof(req_ext->meta));
	memcpy(&req_ext->action, &req->action, sizeof(req_ext->action));

	ret = sxe2_com_flow_legacy_to_ext_one(adapter, &req->pattern_outer,
					      &req_ext->pattern_outer);
	if (ret) {
		LOG_ERROR_BDF("failed to convert outer pattern, ret=%d\n", ret);
		goto l_free;
	}

	ret = sxe2_com_flow_legacy_to_ext_one(adapter, &req->pattern_inner,
					      &req_ext->pattern_inner);
	if (ret) {
		LOG_ERROR_BDF("failed to convert inner pattern, ret=%d\n", ret);
		goto l_free;
	}

	if (req_ext->engine_type != SXE2_FLOW_ENGINE_SWITCH &&
	    (sxe2_com_flow_switch_only_fld(&req_ext->pattern_outer) ||
	     sxe2_com_flow_switch_only_fld(&req_ext->pattern_inner))) {
		LOG_ERROR_BDF("engine %d lacks extended fld support\n",
			      req_ext->engine_type);
		ret = -EOPNOTSUPP;
		goto l_free;
	}

	ret = sxe2_com_flow_filter_del_dispatch(adapter, rule_vsi_id, req_ext);
l_free:
	kfree(req_ext);
l_free_req:
	kfree(req);
	return ret;
}

s32 sxe2_com_flow_filter_del_ext(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				 struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_flow_filter_req_ext *req_ext = NULL;
	u16 rule_vsi_id = 0;
	s32 ret = 0;

	if (cmd_buf->req_len < sizeof(*req_ext)) {
		LOG_ERROR_BDF("EXT del req_len too small: %u < %zu\n",
			      cmd_buf->req_len, sizeof(*req_ext));
		ret = -EINVAL;
		goto l_end;
	}

	req_ext = (struct sxe2_drv_flow_filter_req_ext *)
		  sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req_ext) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req_ext));
		ret = -EFAULT;
		goto l_end;
	}

	req_ext->flow_id = le32_to_cpu(req_ext->flow_id);
	req_ext->engine_type = le32_to_cpu(req_ext->engine_type);
	rule_vsi_id = req_ext->meta.flow_rule_vsi;

	ret = sxe2_com_flow_ext_pattern_check(adapter, &req_ext->pattern_outer);
	if (ret)
		goto l_free;

	ret = sxe2_com_flow_ext_pattern_check(adapter, &req_ext->pattern_inner);
	if (ret)
		goto l_free;

	if (req_ext->engine_type != SXE2_FLOW_ENGINE_SWITCH &&
	    (sxe2_com_flow_switch_only_fld(&req_ext->pattern_outer) ||
	     sxe2_com_flow_switch_only_fld(&req_ext->pattern_inner))) {
		LOG_ERROR_BDF("engine %d lacks extended fld support\n",
			      req_ext->engine_type);
		ret = -EOPNOTSUPP;
		goto l_free;
	}

	ret = sxe2_com_flow_filter_del_dispatch(adapter, rule_vsi_id, req_ext);
l_free:
	kfree(req_ext);
l_end:
	return ret;
}

s32 sxe2_com_flow_fnav_stat_alloc(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				  struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;
	struct sxe2_drv_flow_fnav_get_stat_id_resp resp = {0};
	u16 rule_vsi_id;
	u16 stat_index = 0;
	bool need_update = false;
	struct sxe2_drv_flow_fnav_get_stat_id_req *req;

	req = (struct sxe2_drv_flow_fnav_get_stat_id_req *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_end;
	}

	ret = sxe2_com_flow_vsi_id_change(adapter, cmd_buf->vsi_id, &rule_vsi_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_com_flow_vsi_id_change failed, ret=%d\n", ret);
		goto l_end;
	}

	need_update = req->need_update;
	ret = sxe2_fnav_stat_idx_alloc(adapter, rule_vsi_id, &stat_index,
				       need_update, true);
	if (ret) {
		LOG_ERROR_BDF("sxe2_fnav_stat_idx_alloc_with_lock failed, ret=%d\n", ret);
		goto l_end;
	}
	resp.stat_id = stat_index;
	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%lu\n", sizeof(resp));
		ret = -EFAULT;
		goto l_end;
	}
l_end:
	kfree(req);
	return ret;
}

s32 sxe2_com_flow_fnav_stat_free(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				 struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;
	struct sxe2_drv_flow_fnav_free_stat_id_req *req;

	req = (struct sxe2_drv_flow_fnav_free_stat_id_req *)
		sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_end;
	}

	ret = sxe2_fnav_stat_idx_free_with_lock(adapter, req->stat_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_fnav_stat_idx_free_with_lock failed, ret=%d\n", ret);
		goto l_end;
	}
l_end:
	kfree(req);
	return ret;
}

s32 sxe2_com_flow_fnav_stat_query(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				  struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;
	struct sxe2_drv_flow_fnav_query_stat_resp resp = {0};

	u64 hits = 0;
	u64 bytes = 0;

	struct sxe2_cmd_params cmd_fw = {};
	struct sxe2_fwc_fnav_stats_req req_fw = {};
	struct sxe2_fwc_fnav_stats_resp resp_fw = {};
	struct sxe2_drv_flow_fnav_query_stat_req *req;

	req = (struct sxe2_drv_flow_fnav_query_stat_req *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_end;
	}

	req_fw.is_clear = (u8)req->is_clear;
	req_fw.counter_idx = cpu_to_le16(req->stat_id);
	req_fw.bank_type = SXE2_FNAV_COUNTER_BANK_ALL;

	sxe2_cmd_params_dflt_fill(&cmd_fw, SXE2_CMD_FNAV_STATS_GET, &req_fw,
				  sizeof(req_fw), &resp_fw, sizeof(resp_fw));
	ret = sxe2_cmd_fw_exec(adapter, &cmd_fw);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav get state failed, stat_id=%u, ret=%d",
			      req->stat_id, ret);
	} else {
		switch (req->stat_ctrl) {
		case SXE2_FNAV_STAT_ENA_PKTS:
			hits += le64_to_cpu(resp_fw.stats[0]);
			break;
		case SXE2_FNAV_STAT_ENA_BYTES:
			bytes += le64_to_cpu(resp_fw.stats[0]);
			break;
		case SXE2_FNAV_STAT_ENA_ALL:
			hits += le64_to_cpu(resp_fw.stats[0]);
			bytes += le64_to_cpu(resp_fw.stats[1]);
			break;
		default:
			break;
		}
	}
	resp.stat_hits = hits;
	resp.stat_bytes = bytes;
	resp.stat_index = req->stat_id;

	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%lu\n", sizeof(resp));
		ret = -EFAULT;
		goto l_end;
	}
l_end:
	kfree(req);
	return ret;
}

s32 sxe2_com_flow_acl_stat_alloc(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				 struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;
	struct sxe2_drv_flow_fnav_get_stat_id_resp resp = {0};
	u16 rule_vsi_id;
	u16 stat_index = 0;
	bool need_update = false;
	struct sxe2_drv_flow_fnav_get_stat_id_req *req;

	req = (struct sxe2_drv_flow_fnav_get_stat_id_req *)
	       sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_end;
	}

	ret = sxe2_com_flow_vsi_id_change(adapter, cmd_buf->vsi_id, &rule_vsi_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_com_flow_vsi_id_change failed, ret=%d\n", ret);
		goto l_end;
	}

	need_update = req->need_update;
	ret = sxe2_acl_stat_idx_alloc_with_lock(adapter, rule_vsi_id, &stat_index,
						need_update);
	if (ret) {
		LOG_ERROR_BDF("sxe2_fnav_stat_idx_alloc_with_lock failed, ret=%d\n", ret);
		goto l_end;
	}
	resp.stat_id = stat_index;
	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%lu\n", sizeof(resp));
		ret = -EFAULT;
		goto l_end;
	}
l_end:
	kfree(req);
	return ret;
}

s32 sxe2_com_flow_acl_stat_free(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;
	struct sxe2_drv_flow_fnav_free_stat_id_req *req;

	req = (struct sxe2_drv_flow_fnav_free_stat_id_req *)
		sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_end;
	}

	ret = sxe2_acl_stat_idx_free_with_lock(adapter, req->stat_id);
	if (ret) {
		LOG_ERROR_BDF("sxe2_acl_stat_idx_free_with_lock failed, ret=%d\n", ret);
		goto l_end;
	}
l_end:
	kfree(req);
	return ret;
}

s32 sxe2_com_flow_acl_stat_query(struct sxe2_adapter *adapter,
				 struct sxe2_obj *obj,
		struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;
	struct sxe2_drv_acl_query_stat_resp resp = {0};
	u64 hits = 0;
	u64 bytes = 0;
	struct sxe2_cmd_params cmd_fw = {};
	struct sxe2_fwc_acl_stats_req req_fw = {};
	struct sxe2_fwc_acl_stats_resp resp_fw = {};
	struct sxe2_drv_acl_query_stat_req *req;

	req = (struct sxe2_drv_acl_query_stat_req *)
		sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n",
			      sizeof(struct sxe2_drv_acl_query_stat_req));
		ret = -EFAULT;
		goto l_end;
	}

	req_fw.counter_idx = cpu_to_le16(req->stat_id);
	req_fw.is_clear = (u8)req->is_clear;

	sxe2_cmd_params_dflt_fill(&cmd_fw, SXE2_CMD_ACL_STATS_GET, &req_fw,
				  sizeof(req_fw), &resp_fw, sizeof(resp_fw));
	ret = sxe2_cmd_fw_exec(adapter, &cmd_fw);
	if (ret) {
		LOG_ERROR_BDF("ACL stats get failed, stat_id=%u, ret=%d",
			      req->stat_id, ret);
	} else {
		switch (req->stat_ctrl) {
		case SXE2_FNAV_STAT_ENA_PKTS:
			hits = le64_to_cpu(resp_fw.pkt_cnt);
			break;
		case SXE2_FNAV_STAT_ENA_BYTES:
			bytes = le64_to_cpu(resp_fw.byte_cnt);
			break;
		case SXE2_FNAV_STAT_ENA_ALL:
			hits = le64_to_cpu(resp_fw.pkt_cnt);
			bytes = le64_to_cpu(resp_fw.byte_cnt);
			break;
		default:
			break;
		}
	}
	resp.stat_hits = hits;
	resp.stat_bytes = bytes;
	resp.stat_index = req->stat_id;

	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp,
				       sizeof(struct sxe2_drv_acl_query_stat_resp), obj) != 0) {
		LOG_ERROR_BDF("copy_to_user failed, len=%lu\n",
			      sizeof(struct sxe2_drv_acl_query_stat_resp));
		ret = -EFAULT;
		goto l_end;
	}
l_end:
	kfree(req);
	return ret;
}
