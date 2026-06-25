// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_dfx.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_common.h"
#include "sxe2_cmd.h"
#include "sxe2_log.h"
#include "sxe2_dfx.h"

static void rxft_action_type_analysis(struct sxe2_adapter *adapter, u32 ac_type)
{
	switch (ac_type) {
	case 0:
		LOG_DEV_INFO("action_type 0    : \t"
			     "To Tx MAC(contain LAN TX / RDMA TX / MNG TX)\r\n");
		break;
	case 1:
		LOG_DEV_INFO("action_type 1    : \t"
			     "Tx or Rx pkt with drop flag set by switch or acl\r\n");
		break;
	case 2:
		LOG_DEV_INFO("action_type 2    : Tx first action is to MNG\r\n");
		break;
	case 3:
		LOG_DEV_INFO("action_type 3    : Tx first action is to RDMA Rx\r\n");
		break;
	case 4:
		LOG_DEV_INFO("action_type 4    : Tx first action is to LAN Rx\r\n");
		break;
	case 5:
		LOG_DEV_INFO("action_type 5    : Tx first action is to FD program\r\n");
		break;
	case 6:
		LOG_DEV_INFO("action_type 6    : \t"
			     "Tx first action is to mirror(contain ingress/egress/event)\r\n");
		break;
	case 7:
		LOG_DEV_INFO("action_type 7    : Tx first action is RDMA TX multicast loopback\t"
			     "(RDMA TX multicast table hit)\r\n");
		break;
	case 8:
		LOG_DEV_INFO("action_type 8    : To vsi\r\n");
		break;
	case 9:
		LOG_DEV_INFO("action_type 9    : To vsi queue or queue region\r\n");
		break;
	case 10:
		LOG_DEV_INFO("action_type 10   : Execute FD program\r\n");
		break;
	case 11:
		LOG_DEV_INFO("action_type 11   : LAN RX multicast list\r\n");
		break;
	case 12:
		LOG_DEV_INFO("action_type 12   : LAN RX mirror list\r\n");
		break;
	case 13:
		LOG_DEV_INFO("action_type 13   : RDMA multicast list\r\n");
		break;
	case 14:
		LOG_DEV_INFO("action_type 14   : To RDMA Rx dst qpn\r\n");
		break;
	case 15:
		LOG_DEV_INFO("action_type 15   : \t"
			     "Original received network packet lookup table\r\n");
		break;
	case 16:
		LOG_DEV_INFO("action_type 16   : PFR/VFR/VMR\r\n");
		break;
	default:
		LOG_DEV_INFO("action_type %u error!!!\r\n", ac_type);
		break;
	}
}

static void ppe_info_protocol_id_convert(struct sxe2_rxft_dbg_ppe_info_action_type_1 *ppe_info,
					 union sxe2_rxft_ppe_protocol_info *prot_info)
{
	prot_info[0].reg.protocol_id = ppe_info->protocol_id0;
	prot_info[0].reg.protocol_offset =
		(u32)(ppe_info->protocol_offset0_6_0 |
		      (ppe_info->protocol_offset0_7 << (u32)7));
	prot_info[1].reg.protocol_id	 = ppe_info->protocol_id1;
	prot_info[1].reg.protocol_offset = ppe_info->protocol_offset1;
	prot_info[2].reg.protocol_id	 = ppe_info->protocol_id2;
	prot_info[2].reg.protocol_offset =
		(u32)(ppe_info->protocol_offset2_6_0 |
		      (ppe_info->protocol_offset2_7 << (u32)7));
	prot_info[3].reg.protocol_id	 = ppe_info->protocol_id3;
	prot_info[3].reg.protocol_offset = ppe_info->protocol_offset3;
	prot_info[4].reg.protocol_id	 = ppe_info->protocol_id4;
	prot_info[4].reg.protocol_offset =
		(u32)(ppe_info->protocol_offset4_6_0 |
		      (ppe_info->protocol_offset4_7 << (u32)7));
	prot_info[5].reg.protocol_id	 = ppe_info->protocol_id5;
	prot_info[5].reg.protocol_offset = ppe_info->protocol_offset5;
	prot_info[6].reg.protocol_id	 = ppe_info->protocol_id6;
	prot_info[6].reg.protocol_offset =
		(u32)(ppe_info->protocol_offset6_6_0 |
		      (ppe_info->protocol_offset6_7 << (u32)7));
	prot_info[7].reg.protocol_id	 = ppe_info->protocol_id7;
	prot_info[7].reg.protocol_offset = ppe_info->protocol_offset7;
	prot_info[8].reg.protocol_id	 = ppe_info->protocol_id8;
	prot_info[8].reg.protocol_offset =
		(u32)(ppe_info->protocol_offset8_6_0 |
		      (ppe_info->protocol_offset8_7 << (u32)7));
	prot_info[9].reg.protocol_id	 = ppe_info->protocol_id9;
	prot_info[9].reg.protocol_offset = ppe_info->protocol_offset9;
	prot_info[10].reg.protocol_id	 = ppe_info->protocol_id10;
	prot_info[10].reg.protocol_offset =
		(u32)(ppe_info->protocol_offset10_6_0 |
		      (ppe_info->protocol_offset10_7 << (u32)7));
	prot_info[11].reg.protocol_id	  = ppe_info->protocol_id11;
	prot_info[11].reg.protocol_offset = ppe_info->protocol_offset11;
	prot_info[12].reg.protocol_id	  = ppe_info->protocol_id12;
	prot_info[12].reg.protocol_offset =
		(u32)(ppe_info->protocol_offset12_6_0 |
		      (ppe_info->protocol_offset12_7 << (u32)7));
	prot_info[13].reg.protocol_id	  = ppe_info->protocol_id13;
	prot_info[13].reg.protocol_offset = ppe_info->protocol_offset13;
	prot_info[14].reg.protocol_id	  = ppe_info->protocol_id14;
	prot_info[14].reg.protocol_offset =
		(u32)(ppe_info->protocol_offset14_6_0 |
		      (ppe_info->protocol_offset14_7 << (u32)7));
	prot_info[15].reg.protocol_id	  = ppe_info->protocol_id15;
	prot_info[15].reg.protocol_offset = ppe_info->protocol_offset15;
}

static void rxft_ppe_info_common_analysis(struct sxe2_adapter *adapter,
					  u32 *pdata)
{
	int i;
	struct sxe2_rxft_dbg_ppe_info_action_type_1 ppe_info;
	union sxe2_rxft_ppe_protocol_info prot_info[16];

	(void)memset(&prot_info, 0,
		     sizeof(union sxe2_rxft_ppe_protocol_info) * 16);
	(void)memset(&ppe_info, 0,
		     sizeof(struct sxe2_rxft_dbg_ppe_info_action_type_1));
	(void)memcpy(&ppe_info, pdata,
		     sizeof(struct sxe2_rxft_dbg_ppe_info_action_type_1));

	LOG_DEV_INFO("action_prio      = 0x%x\r\n", ppe_info.action_pro);
	LOG_DEV_INFO("pkt_tc           = 0x%x\r\n", ppe_info.pkt_tc);
	LOG_DEV_INFO("port             = 0x%x\r\n", ppe_info.port);
	LOG_DEV_INFO("pkt_len          = 0x%x\r\n", ppe_info.pkt_len);
	LOG_DEV_INFO("src_pf           = 0x%x\r\n", ppe_info.src_pf);
	LOG_DEV_INFO("src_vf           = 0x%x\r\n",
		     ppe_info.src_vf_1_0 | (ppe_info.srx_vf_7_2 << 2));
	LOG_DEV_INFO("src_txvsi        = 0x%x\r\n", ppe_info.src_txvsi);
	LOG_DEV_INFO("src_pf_vf_vm_flg = 0x%x\r\n", ppe_info.src_pf_vf_vm_flg);
	LOG_DEV_INFO("pkt_type         = 0x%x\r\n", ppe_info.pkt_type);
	LOG_DEV_INFO("dst_pf           = 0x%x\r\n", ppe_info.dst_pf);
	LOG_DEV_INFO("dst_vf           = 0x%x\r\n",
		     ppe_info.dst_vf_5_0 | (ppe_info.dst_vf_7_6 << 6));
	LOG_DEV_INFO("dst_vsi          = 0x%x\r\n", ppe_info.dst_vsi);
	LOG_DEV_INFO("dst_pf_vf_vm_flg = 0x%x\r\n", ppe_info.dst_pf_vf_vm_flg);
	LOG_DEV_INFO("up               = 0x%x\r\n", ppe_info.up);
	LOG_DEV_INFO("tcp_syn          = 0x%x\r\n", ppe_info.tcp_syn);
	LOG_DEV_INFO("tcp_ack          = 0x%x\r\n", ppe_info.tcp_ack);
	LOG_DEV_INFO("tcp_rst          = 0x%x\r\n", ppe_info.tcp_rst);
	LOG_DEV_INFO("tcp_fin          = 0x%x\r\n", ppe_info.tcp_fin);
	LOG_DEV_INFO("l2_mac_err       = 0x%x\r\n", ppe_info.l2_mac_err);
	LOG_DEV_INFO("bypass_sw        = 0x%x\r\n", ppe_info.bypass_switch);
	LOG_DEV_INFO("bypass_acl       = 0x%x\r\n", ppe_info.bypass_acl);
	LOG_DEV_INFO("bypass_rxft      = 0x%x\r\n", ppe_info.bypass_rxft);
	LOG_DEV_INFO("drop             = 0x%x\r\n", ppe_info.drop);
	LOG_DEV_INFO("parser_abort     = 0x%x\r\n", ppe_info.parser_abort);
	LOG_DEV_INFO("malicious_abort  = 0x%x\r\n", ppe_info.malicious_abort);

	if (ppe_info.packet_source_type == 0) {
		LOG_DEV_INFO("pkt_src_type     = 0x0, receive - from lan\r\n");
	} else if (ppe_info.packet_source_type == 1) {
		LOG_DEV_INFO("pkt_src_type     = 0x1, loopback - from host\r\n");
	} else if (ppe_info.packet_source_type == 2) {
		LOG_DEV_INFO("pkt_src_type     = 0x2, loopback - from mng\r\n");
	} else if (ppe_info.packet_source_type == 3) {
		LOG_DEV_INFO("pkt_src_type     = 0x3, transmit\r\n");
		if (ppe_info.pkt_source == 0)
			LOG_DEV_INFO("pkt_src          = 0x0, lan tx\r\n");
		else if (ppe_info.pkt_source == 1)
			LOG_DEV_INFO("pkt_src          = 0x1, rdma tx\r\n");
		else if (ppe_info.pkt_source == 2)
			LOG_DEV_INFO("pkt_src          = 0x2, bmc-mng tx\r\n");
		else if (ppe_info.pkt_source == 3)
			LOG_DEV_INFO("pkt_src          = 0x3, miniSOC-mng tx\r\n");
	}

	LOG_DEV_INFO("fd_program       = 0x%x\r\n", ppe_info.fd_program);
	LOG_DEV_INFO("fd_program_dummy = 0x%x\r\n", ppe_info.fd_program_dummy);
	LOG_DEV_INFO("lan_tx_sw        = 0x%x\r\n", ppe_info.lan_tx_sw);
	LOG_DEV_INFO("rdma_tx_swap     = 0x%x\r\n", ppe_info.rdma_tx_swap);

	if (ppe_info.pkt_dest == 0)
		LOG_DEV_INFO("pkt_dest         = 0x0, lan tx/rx\r\n");
	else if (ppe_info.pkt_dest == 1)
		LOG_DEV_INFO("pkt_dest         = 0x1, rdma\r\n");
	else if (ppe_info.pkt_dest == 2)
		LOG_DEV_INFO("pkt_dest         = 0x2, mng\r\n");
	else if (ppe_info.pkt_dest == 3)
		LOG_DEV_INFO("pkt_dest         = 0x3, bfde\r\n");

	LOG_DEV_INFO("icrc_err         = 0x%x\r\n", ppe_info.icrc_err);
	LOG_DEV_INFO("ipeh             = 0x%x\r\n", ppe_info.ipeh);
	LOG_DEV_INFO("esp              = 0x%x\r\n", ppe_info.esp);
	LOG_DEV_INFO("mpls             = 0x%x\r\n", ppe_info.mpls);
	LOG_DEV_INFO("fragment         = 0x%x\r\n", ppe_info.fragment);
	LOG_DEV_INFO("checksum_offload = 0x%x\r\n", ppe_info.checksum_offload);
	LOG_DEV_INFO("ipe              = 0x%x\r\n", ppe_info.ipe);
	LOG_DEV_INFO("l4e              = 0x%x\r\n", ppe_info.l4e);
	LOG_DEV_INFO("eipe             = 0x%x\r\n", ppe_info.eipe);
	LOG_DEV_INFO("eudpe            = 0x%x\r\n", ppe_info.eudpe);
	LOG_DEV_INFO("mac_in_mac       = 0x%x\r\n", ppe_info.mac_in_mac);
	LOG_DEV_INFO("pkt_err          = 0x%x\r\n", ppe_info.pkt_err);
	LOG_DEV_INFO("mirr_id          = 0x%x\r\n", ppe_info.mirr_id);

	if (ppe_info.mirr_type == 0)
		LOG_DEV_INFO("mirr_type        = 0x0, ingress mirror\r\n");
	else if (ppe_info.mirr_type == 1)
		LOG_DEV_INFO("mirr_type        = 0x1, egress mirror\r\n");
	else if (ppe_info.mirr_type == 2)
		LOG_DEV_INFO("mirr_type        = 0x2, event mirror\r\n");
	else if (ppe_info.mirr_type == 3)
		LOG_DEV_INFO("mirr_type        = 0x3, rsv\r\n");

	LOG_DEV_INFO("multicast_copy   = 0x%x\r\n", ppe_info.multicast_copy);

	if (ppe_info.umbcast == 0)
		LOG_DEV_INFO("umbcast          = 0x0, unicast\r\n");
	else if (ppe_info.umbcast == 1)
		LOG_DEV_INFO("umbcast          = 0x1, multicast\r\n");
	else if (ppe_info.umbcast == 2)
		LOG_DEV_INFO("umbcast          = 0x2, broadcast\r\n");
	else if (ppe_info.umbcast == 3)
		LOG_DEV_INFO("umbcast          = 0x3, mirror\r\n");

	switch (ppe_info.tunnel_type) {
	case 0:
		LOG_DEV_INFO("tunnel_type      = 0, non tunnel pkt\r\n");
		break;
	case 1:
		LOG_DEV_INFO("tunnel_type      = 1, Rsv\r\n");
		break;
	case 2:
		LOG_DEV_INFO("tunnel_type      = 2, IPv4-in-IPv4\r\n");
		break;
	case 3:
		LOG_DEV_INFO("tunnel_type      = 3, IPv4-in-IPv6\r\n");
		break;
	case 4:
		LOG_DEV_INFO("tunnel_type      = 4, IPv6-in-IPv4\r\n");
		break;
	case 5:
		LOG_DEV_INFO("tunnel_type      = 5, IPv6-in-IPv6\r\n");
		break;
	case 6:
		LOG_DEV_INFO("tunnel_type      = 6, NSH\r\n");
		break;
	case 7:
		LOG_DEV_INFO("tunnel_type      = 7, VXLAN(MAC-in-UDP)\r\n");
		break;
	case 8:
		LOG_DEV_INFO("tunnel_type      = 8, VXLAN(GPE)\r\n");
		break;
	case 9:
		LOG_DEV_INFO("tunnel_type      = 9, GRE\r\n");
		break;
	case 10:
		LOG_DEV_INFO("tunnel_type      = 10, Geneve\r\n");
		break;
	case 11:
		LOG_DEV_INFO("tunnel_type      = 11, MPLSoGRE\r\n");
		break;
	case 12:
		LOG_DEV_INFO("tunnel_type      = 12, MPLSoUDP\r\n");
		break;
	case 13:
		LOG_DEV_INFO("tunnel_type      = 13, IPSEC NAT-T\r\n");
		break;
	case 14:
		LOG_DEV_INFO("tunnel_type      = 14, GTP\r\n");
		break;
	case 15:
		LOG_DEV_INFO("tunnel_type      = 15, ETH-in-IPv6(SRv6)\r\n");
		break;
	case 16:
		LOG_DEV_INFO("tunnel_type      = 16, Teredo(IPv6-in-UDP)\r\n");
		break;
	case 17:
		LOG_DEV_INFO("tunnel_type      = 17, L2TP-in-UDP\r\n");
		break;
	case 18:
		LOG_DEV_INFO("tunnel_type      = 18, SDN\r\n");
		break;
	default:
		LOG_DEV_INFO("tunnel_type      = %d, not defined\r\n",
			     ppe_info.tunnel_type);
		break;
	}

	LOG_DEV_INFO("oam              = 0x%x\r\n", ppe_info.oam);
	LOG_DEV_INFO("flow_id_vld      = 0x%x\r\n", ppe_info.flow_id_vld);
	LOG_DEV_INFO("acl_hit          = 0x%x\r\n", ppe_info.acl_hit);
	LOG_DEV_INFO("macsec_err       = 0x%x\r\n", ppe_info.macsec_err);
	LOG_DEV_INFO("first_action     = 0x%x\r\n", ppe_info.first_action);
	LOG_DEV_INFO("last_action      = 0x%x\r\n", ppe_info.last_action);
	LOG_DEV_INFO("last_mc_pkt      = 0x%x\r\n", ppe_info.last_mc_pkt);

	ppe_info_protocol_id_convert(&ppe_info, prot_info);

	LOG_DEV_INFO("protocol_id_num  = 0x%x\r\n", ppe_info.protocol_id_num);
	for (i = 0; i < ppe_info.protocol_id_num; i++) {
		LOG_DEV_INFO("protocol_id[%d] = %3d, offset : %d\r\n", i,
			     prot_info[i].reg.protocol_id,
			     prot_info[i].reg.protocol_offset);
	}
}

static void rxft_ppe_info_common_tail_analysis(struct sxe2_adapter *adapter,
					       u32 *pdata)
{
	struct sxe2_rxft_dbg_ppe_info_action_type_1 ppe_info;

	(void)memset(&ppe_info, 0,
		     sizeof(struct sxe2_rxft_dbg_ppe_info_action_type_1));
	(void)memcpy(&ppe_info, pdata,
		     sizeof(struct sxe2_rxft_dbg_ppe_info_action_type_1));

	LOG_DEV_INFO("sdf_hash         = 0x%x\r\n", ppe_info.sdf_hash);
	LOG_DEV_INFO("sdf_pri          = 0x%x\r\n", ppe_info.sdf_pri);
	LOG_DEV_INFO("fd_prog_drop     = 0x%x\r\n", ppe_info.fd_prog_drop);
	LOG_DEV_INFO("trace_level      = 0x%x\r\n", ppe_info.trace_level);
	LOG_DEV_INFO("pkt_src_bfd      = 0x%x\r\n", ppe_info.pkt_src_bfd);
	LOG_DEV_INFO("to_host          = 0x%x\r\n", ppe_info.to_host);
	LOG_DEV_INFO("to_mng           = 0x%x\r\n", ppe_info.to_mng);
	LOG_DEV_INFO("to_lan           = 0x%x\r\n", ppe_info.to_lan);
	LOG_DEV_INFO("to_roce          = 0x%x\r\n", ppe_info.to_roce);
}

static void rxft_ppe_info_actype9_analysis(struct sxe2_adapter *adapter,
					   u32 *pdata)
{
	u32 tmp[10] = { 0 };
	struct sxe2_rxft_dbg_ppe_info_action_type_9 ppe_info;

	(void)memset(&ppe_info, 0,
		     sizeof(struct sxe2_rxft_dbg_ppe_info_action_type_9));
	(void)memcpy(&ppe_info, pdata,
		     sizeof(struct sxe2_rxft_dbg_ppe_info_action_type_9));

	rxft_ppe_info_common_analysis(adapter, pdata);

	LOG_DEV_INFO("sw_profile_id    = 0x%x\r\n", ppe_info.sw_profile_id);
	tmp[2] = (u32)(ppe_info.acl_profile_id_1_0 |
		       (ppe_info.acl_profile_id_6_2 << (u32)2));
	LOG_DEV_INFO("acl_profile_id   = 0x%x\r\n", tmp[2]);
	LOG_DEV_INFO("fd_profile_id    = 0x%x\r\n", ppe_info.fd_profile_id);
	LOG_DEV_INFO("flow_id          = 0x%x\r\n", ppe_info.flow_id);
	LOG_DEV_INFO("flow_id_pri      = 0x%x\r\n", ppe_info.flow_id_pri);
	tmp[3] = (u32)(ppe_info.queue_buf_num_0 |
		       (ppe_info.queue_buf_num_10_1 << (u32)1));
	LOG_DEV_INFO("queue_buf_num    = 0x%x\r\n", tmp[3]);
	LOG_DEV_INFO("toqueue          = 0x%x\r\n", ppe_info.toqueue);

	if (ppe_info.queue_hit_flag & 0x1)
		LOG_DEV_INFO("queue_hit_flag[0] vld , fd default action hit\r\n");
	else if (ppe_info.queue_hit_flag & 0x2)
		LOG_DEV_INFO("queue_hit_flag[1] vld , fd kt/fkot hit\r\n");
	else if (ppe_info.queue_hit_flag & 0x4)
		LOG_DEV_INFO("queue_hit_flag[2] vld , acl hit\r\n");
	else if (ppe_info.queue_hit_flag & 0x8)
		LOG_DEV_INFO("queue_hit_flag[3] vld , sw hit\r\n");

	if (ppe_info.queue_sel_result == 0)
		LOG_DEV_INFO("queue_sel_result = 0x0, queue/queue region non select\r\n");
	else if (ppe_info.queue_sel_result == 1)
		LOG_DEV_INFO("queue_sel_result = 0x1, queue/queue region from fd\r\n");
	else if (ppe_info.queue_sel_result == 2)
		LOG_DEV_INFO("queue_sel_result = 0x2, queue/queue region from acl\r\n");
	else if (ppe_info.queue_sel_result == 3)
		LOG_DEV_INFO("queue_sel_result = 0x3, queue/queue region from sw\r\n");
}

static void rxft_ppe_info_actype1_analysis(struct sxe2_adapter *adapter,
					   u32 *pdata)
{
	u32 tmp[10] = { 0 };
	struct sxe2_rxft_dbg_ppe_info_action_type_1 ppe_info;

	(void)memset(&ppe_info, 0,
		     sizeof(struct sxe2_rxft_dbg_ppe_info_action_type_1));
	(void)memcpy(&ppe_info, pdata,
		     sizeof(struct sxe2_rxft_dbg_ppe_info_action_type_1));

	rxft_ppe_info_common_analysis(adapter, pdata);

	LOG_DEV_INFO("sw_profile_id    = 0x%x\r\n", ppe_info.sw_profile_id);
	tmp[2] = (u32)(ppe_info.acl_profile_id_1_0 |
		       (ppe_info.acl_profile_id_6_2 << (u32)2));
	LOG_DEV_INFO("acl_profile_id   = 0x%x\r\n", tmp[2]);
	LOG_DEV_INFO("fd_profile_id    = 0x%x\r\n", ppe_info.fd_profile_id);
	LOG_DEV_INFO("flow_id          = 0x%x\r\n", ppe_info.flow_id);
	LOG_DEV_INFO("flow_id_pri      = 0x%x\r\n", ppe_info.flow_id_pri);
}

static void rxft_ppe_info_actype10_analysis(struct sxe2_adapter *adapter,
					    u32 *pdata)
{
	u32 tmp[10] = { 0 };
	struct sxe2_rxft_dbg_ppe_info_action_type_10 ppe_info;

	(void)memset(&ppe_info, 0,
		     sizeof(struct sxe2_rxft_dbg_ppe_info_action_type_10));
	(void)memcpy(&ppe_info, pdata,
		     sizeof(struct sxe2_rxft_dbg_ppe_info_action_type_10));

	rxft_ppe_info_common_analysis(adapter, pdata);

	LOG_DEV_INFO("sw_profile_id    = 0x%x\r\n", ppe_info.sw_profile_id);
	tmp[2] = (u32)(ppe_info.acl_profile_id_1_0 |
		       (ppe_info.acl_profile_id_6_2 << (u32)2));
	LOG_DEV_INFO("acl_profile_id   = 0x%x\r\n", tmp[2]);
	LOG_DEV_INFO("fd_profile_id    = 0x%x\r\n", ppe_info.fd_profile_id);
	LOG_DEV_INFO("flow_id          = 0x%x\r\n", ppe_info.flow_id);
	LOG_DEV_INFO("flow_id_pri      = 0x%x\r\n", ppe_info.flow_id_pri);
	tmp[3] = (u32)(ppe_info.qindex_0 | (ppe_info.qindex_10_1 << (u32)1));
	LOG_DEV_INFO("fd_desc_q_index       = 0x%x\r\n", tmp[3]);
	LOG_DEV_INFO("fd_desc_comp_queue    = 0x%x\r\n", ppe_info.comp_queue);
	LOG_DEV_INFO("fd_desc_comp_report   = 0x%x\r\n", ppe_info.comp_report);
	LOG_DEV_INFO("fd_desc_fd_space      = 0x%x\r\n", ppe_info.fd_space);
	LOG_DEV_INFO("fd_desc_stat_cnt      = 0x%x\r\n", ppe_info.stat_cnt);
	LOG_DEV_INFO("fd_desc_stat_ena      = 0x%x\r\n", ppe_info.stat_ena);
	LOG_DEV_INFO("fd_desc_evict_ena     = 0x%x\r\n", ppe_info.evict_ena);
	LOG_DEV_INFO("fd_desc_to_queue      = 0x%x\r\n", ppe_info.to_queue);
	LOG_DEV_INFO("fd_desc_to_queue_prio = 0x%x\r\n",
		     ppe_info.to_queue_prio);
	LOG_DEV_INFO("fd_desc_fd_flow_id    = 0x%x\r\n", ppe_info.fd_flow_id);
	LOG_DEV_INFO("fd_desc_pcmd          = 0x%x\r\n", ppe_info.pcmd);
	LOG_DEV_INFO("fd_desc_fd_vsi        = 0x%x\r\n", ppe_info.fd_vsi);
	LOG_DEV_INFO("fd_desc_swap          = 0x%x\r\n", ppe_info.swap);
	LOG_DEV_INFO("fd_desc_fdid_prio     = 0x%x\r\n", ppe_info.fdid_prio);
	LOG_DEV_INFO("fd_desc_fdid_did      = 0x%x\r\n", ppe_info.fdid_did);
	tmp[4] = (u32)(ppe_info.fdid_0 | (ppe_info.fdid_31_1 << (u32)1));
	LOG_DEV_INFO("fd_desc_fdid          = 0x%x\r\n", tmp[4]);
}

static void rxft_ppe_info_actype14_analysis(struct sxe2_adapter *adapter,
					    u32 *pdata)
{
	struct sxe2_rxft_dbg_ppe_info_action_type_14 ppe_info;

	(void)memset(&ppe_info, 0,
		     sizeof(struct sxe2_rxft_dbg_ppe_info_action_type_14));
	(void)memcpy(&ppe_info, pdata,
		     sizeof(struct sxe2_rxft_dbg_ppe_info_action_type_14));

	rxft_ppe_info_common_analysis(adapter, pdata);

	LOG_DEV_INFO("rh ip offset     = 0x%x\r\n", ppe_info.rh_ip_offset);
	LOG_DEV_INFO("rh vlan offset   = 0x%x\r\n",
		     ppe_info.rh_vlan_offset1_0 |
			     (ppe_info.rh_vlan_offset7_2 << 2));
	LOG_DEV_INFO("rh vlan vld      = 0x%x\r\n", ppe_info.rh_vlan_vld);
	LOG_DEV_INFO("rh dqpn          = 0x%x\r\n", ppe_info.rh_dqpn);
	LOG_DEV_INFO("dst_rdma_mc_num  = 0x%x\r\n",
		     ppe_info.dst_rdma_mc_num_0 |
			     (ppe_info.dst_rdma_mc_num_12_1 << 1));
	LOG_DEV_INFO("rdma_mc_cnt      = 0x%x\r\n", ppe_info.rdma_mc_cnt);
}

static void rxft_ppe_info_analysis(struct sxe2_adapter *adapter, u32 *data)
{
	u32 action_type;

	action_type = data[0] & 0x1f;
	rxft_action_type_analysis(adapter, action_type);
	switch (action_type) {
	case 0:
	case 1:
	case 2:
	case 4:
	case 5:
	case 8:
	case 15:
		rxft_ppe_info_actype1_analysis(adapter, data);
		break;
	case 9:
		rxft_ppe_info_actype9_analysis(adapter, data);
		break;
	case 10:
		rxft_ppe_info_actype10_analysis(adapter, data);
		break;
	case 3:
	case 7:
	case 13:
	case 14:
		rxft_ppe_info_actype14_analysis(adapter, data);
		break;
	default:
		LOG_DEV_INFO("action type = %d, analysis not supported yet \r\n",
			     action_type);
		break;
	}

	rxft_ppe_info_common_tail_analysis(adapter, data);
}

STATIC void sxe2_rxft_ppe_info_analysis(struct sxe2_adapter *adapter,
					struct sxe2_rxft_ppe_info *ppe_info)
{
	int i;

	for (i = 0; i < SXE2_RXFT_PPE_INFO_TYPE_MAX; i++) {
		switch (i) {
		case SXE2_RXFT_PPE_INFO_TX_IN:
			LOG_DEV_INFO("RXFT TX INGRESS PPE INFO : \r\n");
			break;
		case SXE2_RXFT_PPE_INFO_TX_EX:
			LOG_DEV_INFO("RXFT TX EGRESS PPE INFO : \r\n");
			break;
		case SXE2_RXFT_PPE_INFO_RX_IN:
			LOG_DEV_INFO("RXFT RX INGRESS PPE INFO : \r\n");
			break;
		case SXE2_RXFT_PPE_INFO_RX_EX:
			LOG_DEV_INFO("RXFT RX EGRESS PPE INFO : \r\n");
			break;
		case SXE2_RXFT_PPE_INFO_LP_IN:
			LOG_DEV_INFO("RXFT LP INGRESS PPE INFO : \r\n");
			break;
		case SXE2_RXFT_PPE_INFO_LP_EX:
			LOG_DEV_INFO("RXFT LP EGRESS PPE INFO : \r\n");
			break;
		default:
			LOG_DEV_INFO("ERROR TYPE : %u\r\n", i);
			break;
		}
		rxft_ppe_info_analysis(adapter, ppe_info->info[i].data);
	}
}

void sxe2_fwc_rxft_ppe_info(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_rxft_ppe_info ppe_info;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RXFT_PPE_INFO, NULL, 0,
				  &ppe_info,
				  sizeof(struct sxe2_rxft_ppe_info));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_DEV_ERR("rxft ppe info cmd fail, ret=%d\n", ret);
		return;
	}

	LOG_DEV_INFO("****rxft ppe info start****");

	sxe2_rxft_ppe_info_analysis(adapter, &ppe_info);

	LOG_DEV_INFO("****rxft ppe info end****");
}

STATIC void sxe2_ppe_dfx_dump(struct sxe2_adapter *adapter,
			      struct sxe2_fwc_ppe_dfx *ppe_dfx)
{
	u8 i;
	struct sxe2_fwc_txpa_dfx *txpa;
	struct sxe2_fwc_rxpa_dfx *rxpa;

	LOG_DEV_INFO("TXPA DFX\n");
	for (i = 0; i < 4; i++) {
		txpa = &ppe_dfx->txpa[i];
		LOG_DEV_INFO("  txpa[%u].in_all = %u (include drop/err)\n", i, txpa->txpa_in_all);
		LOG_DEV_INFO("  txpa[%u].out_all = %u\n", i, txpa->txpa_out_all);
		LOG_DEV_INFO("  txpa[%u].in_drop = %u\n", i, txpa->txpa_in_drop);
		LOG_DEV_INFO("  txpa[%u].out_drop = %u\n", i, txpa->txpa_out_drop);
		LOG_DEV_INFO("  txpa[%u].in_err = %u\n", i, txpa->txpa_in_err);
		LOG_DEV_INFO("  txpa[%u].out_err = %u\n", i, txpa->txpa_out_err);
	}

	LOG_DEV_INFO("TXFB DFX\n");
	LOG_DEV_INFO("  txfb.in_all = %u (include in_drop)\n", ppe_dfx->txfb.txfb_in_all);
	LOG_DEV_INFO("  txfb.in_drop = %u\n", ppe_dfx->txfb.txfb_in_drop);
	LOG_DEV_INFO("  txfb.out_all = %u (include out_drop)\n", ppe_dfx->txfb.txfb_out_all);
	LOG_DEV_INFO("  txfb.out_drop = %u\n", ppe_dfx->txfb.txfb_out_drop);
	LOG_DEV_INFO("  txfb.internal_drop = %u\n", ppe_dfx->txfb.txfb_internal_drop);

	LOG_DEV_INFO("RXPA DFX\n");
	for (i = 0; i < 4; i++) {
		rxpa = &ppe_dfx->rxpa[i];
		LOG_DEV_INFO("  rxpa[%u].in_all = %u (include drop/err)\n", i, rxpa->rxpa_in_all);
		LOG_DEV_INFO("  rxpa[%u].out_all = %u\n", i, rxpa->rxpa_out_all);
		LOG_DEV_INFO("  rxpa[%u].in_drop = %u\n", i, rxpa->rxpa_in_drop);
		LOG_DEV_INFO("  rxpa[%u].out_drop = %u\n", i, rxpa->rxpa_out_drop);
		LOG_DEV_INFO("  rxpa[%u].in_err = %u\n", i, rxpa->rxpa_in_err);
		LOG_DEV_INFO("  rxpa[%u].out_err = %u\n", i, rxpa->rxpa_out_err);
	}

	LOG_DEV_INFO("RXFB DFX\n");
	LOG_DEV_INFO("  rxfb.tx_in_all = %u (include tx_in_drop)\n", ppe_dfx->rxfb.rxfb_tx_in_all);
	LOG_DEV_INFO("  rxfb.tx_in_drop = %u\n", ppe_dfx->rxfb.rxfb_tx_in_drop);
	LOG_DEV_INFO("  rxfb.rx_in_all = %u (include rx_in_drop)\n", ppe_dfx->rxfb.rxfb_rx_in_all);
	LOG_DEV_INFO("  rxfb.rx_in_drop = %u\n", ppe_dfx->rxfb.rxfb_rx_in_drop);
	LOG_DEV_INFO("  rxfb.out_all = %u (include out_drop)\n", ppe_dfx->rxfb.rxfb_out_all);
	LOG_DEV_INFO("  rxfb.out_drop = %u\n", ppe_dfx->rxfb.rxfb_out_drop);
	LOG_DEV_INFO("  rxfb.internal_drop = %u\n", ppe_dfx->rxfb.rxfb_internal_drop);

	LOG_DEV_INFO("SWITCH DFX\n");
	LOG_DEV_INFO("  switch.tx_all = %u (include tx_drop)\n", ppe_dfx->sw.tx_all);
	LOG_DEV_INFO("  switch.tx_drop = %u\n", ppe_dfx->sw.tx_drop);
	LOG_DEV_INFO("  switch.rx_all = %u (include rx_drop)\n", ppe_dfx->sw.rx_all);
	LOG_DEV_INFO("  switch.rx_drop = %u\n", ppe_dfx->sw.rx_drop);

	LOG_DEV_INFO("RXFT DFX\n");
	LOG_DEV_INFO("  rxft.tx_in_all = %u (include tx_in_drop)\n", ppe_dfx->rxft.tx_in_all);
	LOG_DEV_INFO("  rxft.tx_in_drop = %u\n", ppe_dfx->rxft.tx_in_drop);
	LOG_DEV_INFO("  rxft.tx_out_all = %u (include tx_out_drop)\n", ppe_dfx->rxft.tx_out_all);
	LOG_DEV_INFO("  rxft.tx_out_drop = %u\n", ppe_dfx->rxft.tx_out_drop);
	LOG_DEV_INFO("  rxft.rx_in_all = %u (include rx_in_drop)\n", ppe_dfx->rxft.rx_in_all);
	LOG_DEV_INFO("  rxft.rx_in_drop = %u\n", ppe_dfx->rxft.rx_in_drop);
	LOG_DEV_INFO("  rxft.rx_out_all = %u (include rx_out_drop)\n", ppe_dfx->rxft.rx_out_all);
	LOG_DEV_INFO("  rxft.rx_out_drop = %u\n", ppe_dfx->rxft.rx_out_drop);
	LOG_DEV_INFO("  rxft.lp_in_all = %u (include lp_in_drop)\n", ppe_dfx->rxft.lp_in_all);
	LOG_DEV_INFO("  rxft.lp_in_drop = %u\n", ppe_dfx->rxft.lp_in_drop);
	LOG_DEV_INFO("  rxft.lp_out_all = %u (include lp_out_drop)\n", ppe_dfx->rxft.lp_out_all);
	LOG_DEV_INFO("  rxft.lp_out_drop = %u\n", ppe_dfx->rxft.lp_out_drop);
}

void sxe2_fwc_ppe_dfx_show(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };
	struct sxe2_fwc_ppe_dfx ppe_dfx;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_GET_PPE_DFX, NULL, 0,
				  &ppe_dfx,
				  sizeof(struct sxe2_fwc_ppe_dfx));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_DEV_ERR("ppe dfx cmd fail, ret=%d\n", ret);
		return;
	}

	LOG_DEV_INFO("****ppe dfx start****");

	sxe2_ppe_dfx_dump(adapter, &ppe_dfx);

	LOG_DEV_INFO("****ppe dfx end****");
}
