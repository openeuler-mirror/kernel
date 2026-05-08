// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_fnav.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/jhash.h>
#include <linux/bitmap.h>
#include "sxe2_common.h"
#include "sxe2_cmd.h"
#include "sxe2_log.h"
#include "sxe2_fnav.h"
#include "sxe2_mbx_msg.h"
#include "sxe2_arfs.h"
#include "sxe2_tx.h"

#define SXE2_FNAV_FLD_OFF(m) offsetof(struct sxe2_fnav_filter_full_key, m)

#define SXE2_U8_MASK (0xFF)
#define SXE2_U16_MASK (0xFFFF)
#define SXE2_FNAV_TUN_DISSECT_CNT (2)
#define SXE2_FNAV_NO_TUN_DISSECT_CNT (1)
#define SXE2_FNAV_IPV4_PKT_FLAG_MF_OFFSET (20)

#define SXE2_VXLAN_UDP_DST_PORT (4789)

struct sxe2_fnav_fld_info {
	u32 off;
	u32 off_inner;
	u8 len;
	u8 disp;
	u16 mask;
};

static const struct sxe2_fnav_fld_info sxe2_flds_info[SXE2_FLOW_FLD_ID_MAX] = {
		[SXE2_FLOW_FLD_ID_ETH_TYPE] = {.off = SXE2_FNAV_FLD_OFF(eth.h_proto),
					       .off_inner =
						 SXE2_FNAV_FLD_OFF(eth_inner.h_proto),
					       .len = 2,
					       .disp = 0,
					       .mask = 0},
		[SXE2_FLOW_FLD_ID_ETH_SA] = {.off = SXE2_FNAV_FLD_OFF(eth.h_source),
					     .off_inner =
							SXE2_FNAV_FLD_OFF(eth_inner.h_source),
					     .len = 6,
					     .disp = 0,
					     .mask = 0},
		[SXE2_FLOW_FLD_ID_ETH_DA] = {.off = SXE2_FNAV_FLD_OFF(eth.h_dest),
					     .off_inner =
							SXE2_FNAV_FLD_OFF(eth_inner.h_dest),
					     .len = 6,
					     .disp = 0,
					     .mask = 0},
		[SXE2_FLOW_FLD_ID_S_TCI] = {
				 .off = SXE2_FNAV_FLD_OFF(ext_data.s_vlan_tci),
				 .off_inner =
					SXE2_FNAV_FLD_OFF(ext_data_inner.s_vlan_tci),
				 .len = 2,
				 .disp = 0,
				 .mask = 0},
		[SXE2_FLOW_FLD_ID_C_TCI] = {
				 .off = SXE2_FNAV_FLD_OFF(ext_data.c_vlan_tci),
				 .off_inner =
					SXE2_FNAV_FLD_OFF(ext_data_inner.c_vlan_tci),
				 .len = 2,
				 .disp = 0,
				 .mask = 0},
		[SXE2_FLOW_FLD_ID_IPV4_SA] = {.off = SXE2_FNAV_FLD_OFF(ip.v4.src_ip),
					      .off_inner =
							SXE2_FNAV_FLD_OFF(ip_inner.v4.src_ip),
					      .len = 4,
					      .disp = 0,
					      .mask = 0},
		[SXE2_FLOW_FLD_ID_IPV4_DA] = {.off = SXE2_FNAV_FLD_OFF(ip.v4.dst_ip),
					      .off_inner =
							SXE2_FNAV_FLD_OFF(ip_inner.v4.dst_ip),
					      .len = 4,
					      .disp = 0,
					      .mask = 0},
		[SXE2_FLOW_FLD_ID_IPV4_TOS] = {.off = SXE2_FNAV_FLD_OFF(ip.v4.tos),
					       .off_inner =
							SXE2_FNAV_FLD_OFF(ip_inner.v4.tos),
					       .len = 1,
					       .disp = 0,
					       .mask = 0x00ff},
		[SXE2_FLOW_FLD_ID_IPV4_PROT] = {
				 .off = SXE2_FNAV_FLD_OFF(ip.v4.proto),
				 .off_inner = SXE2_FNAV_FLD_OFF(ip_inner.v4.proto),
				 .len = 1,
				 .disp = 0,
				 .mask = 0x00ff},
		[SXE2_FLOW_FLD_ID_IPV4_TTL] = {.off = SXE2_FNAV_FLD_OFF(ip.v4.ttl),
					       .off_inner =
							SXE2_FNAV_FLD_OFF(ip_inner.v4.ttl),
					       .len = 1,
					       .disp = 8,
					       .mask = 0xff00},
		[SXE2_FLOW_FLD_ID_IPV6_SA] = {.off = SXE2_FNAV_FLD_OFF(ip.v6.src_ip),
					      .off_inner =
							SXE2_FNAV_FLD_OFF(ip_inner.v6.src_ip),
					      .len = 16,
					      .disp = 0,
					      .mask = 0},
		[SXE2_FLOW_FLD_ID_IPV6_DA] = {.off = SXE2_FNAV_FLD_OFF(ip.v6.dst_ip),
					      .off_inner =
							SXE2_FNAV_FLD_OFF(ip_inner.v6.dst_ip),
					      .len = 16,
					      .disp = 0,
					      .mask = 0},
		[SXE2_FLOW_FLD_ID_IPV6_DSCP] = {.off = SXE2_FNAV_FLD_OFF(ip.v6.tc),
						.off_inner =
							SXE2_FNAV_FLD_OFF(ip_inner.v6.tc),
						.len = 1,
						.disp = 4,
						.mask = 0x0ff0},
		[SXE2_FLOW_FLD_ID_IPV6_PROT] = {
				 .off = SXE2_FNAV_FLD_OFF(ip.v6.proto),
				 .off_inner = SXE2_FNAV_FLD_OFF(ip_inner.v6.proto),
				 .len = 1,
				 .disp = 8,
				 .mask = 0xff00},
		[SXE2_FLOW_FLD_ID_IPV6_TTL] = {.off = SXE2_FNAV_FLD_OFF(ip.v6.hlim),
					       .off_inner = SXE2_FNAV_FLD_OFF(ip_inner.v6.hlim),
					       .len = 1,
					       .disp = 0,
					       .mask = 0x00ff},
		[SXE2_FLOW_FLD_ID_TCP_SRC_PORT] = {
				 .off = SXE2_FNAV_FLD_OFF(l4.src_port),
				 .off_inner = SXE2_FNAV_FLD_OFF(l4_inner.src_port),
				 .len = 2,
				 .disp = 0,
				 .mask = 0},
		[SXE2_FLOW_FLD_ID_TCP_DST_PORT] = {
				 .off = SXE2_FNAV_FLD_OFF(l4.dst_port),
				 .off_inner = SXE2_FNAV_FLD_OFF(l4_inner.dst_port),
				 .len = 2,
				 .disp = 0,
				 .mask = 0},
		[SXE2_FLOW_FLD_ID_UDP_SRC_PORT] = {
				 .off = SXE2_FNAV_FLD_OFF(l4.src_port),
				 .off_inner = SXE2_FNAV_FLD_OFF(l4_inner.src_port),
				 .len = 2,
				 .disp = 0,
				 .mask = 0},
		[SXE2_FLOW_FLD_ID_UDP_DST_PORT] = {
				 .off = SXE2_FNAV_FLD_OFF(l4.dst_port),
				 .off_inner = SXE2_FNAV_FLD_OFF(l4_inner.dst_port),
				 .len = 2,
				 .disp = 0,
				 .mask = 0},
		[SXE2_FLOW_FLD_ID_SCTP_SRC_PORT] = {
				 .off = SXE2_FNAV_FLD_OFF(l4.src_port),
				 .off_inner = SXE2_FNAV_FLD_OFF(l4_inner.src_port),
				 .len = 2,
				 .disp = 0,
				 .mask = 0},
		[SXE2_FLOW_FLD_ID_SCTP_DST_PORT] = {
				 .off = SXE2_FNAV_FLD_OFF(l4.dst_port),
				 .off_inner = SXE2_FNAV_FLD_OFF(l4_inner.dst_port),
				 .len = 2,
				 .disp = 0,
				 .mask = 0},
		[SXE2_FLOW_FLD_ID_VXLAN_VNI] = {
				 .off = SXE2_FNAV_FLD_OFF(tunnel_data.vxlan_vni),
				 .off_inner =
					SXE2_FNAV_FLD_OFF(tunnel_data.vxlan_vni),
				 .len = 4,
				 .disp = 0,
				 .mask = 0},
		[SXE2_FLOW_FLD_ID_S_TPID] = {
				 .off = SXE2_FNAV_FLD_OFF(ext_data.vlan_type),
				 .off_inner =
					SXE2_FNAV_FLD_OFF(ext_data_inner.vlan_type),
				 .len = 2,
				 .disp = 0,
				 .mask = 0},
		[SXE2_FLOW_FLD_ID_C_TPID] = {
				 .off = SXE2_FNAV_FLD_OFF(ext_data.vlan_type),
				 .off_inner =
					SXE2_FNAV_FLD_OFF(ext_data_inner.vlan_type),
				 .len = 2,
				 .disp = 0,
				 .mask = 0},
		[SXE2_FLOW_FLD_ID_S_VID] = {
				 .off = SXE2_FNAV_FLD_OFF(ext_data.s_vlan_vid),
				 .off_inner =
					SXE2_FNAV_FLD_OFF(ext_data_inner.s_vlan_vid),
				 .len = 2,
				 .disp = 0,
				 .mask = 0x0fff},
		[SXE2_FLOW_FLD_ID_C_VID] = {
				 .off = SXE2_FNAV_FLD_OFF(ext_data.c_vlan_vid),
				 .off_inner =
					SXE2_FNAV_FLD_OFF(ext_data_inner.c_vlan_vid),
				 .len = 2,
				 .disp = 0,
				 .mask = 0x0fff},
		[SXE2_FLOW_FLD_ID_GENEVE_VNI] = {
				 .off = SXE2_FNAV_FLD_OFF(tunnel_data.geneve_vni),
				 .off_inner =
				 SXE2_FNAV_FLD_OFF(tunnel_data.geneve_vni),
				 .len = 4,
				 .disp = 0,
				 .mask = 0},
		[SXE2_FLOW_FLD_ID_GTPU_TEID] = {
				 .off = SXE2_FNAV_FLD_OFF(tunnel_data.gtpu_teid),
				 .off_inner =
					SXE2_FNAV_FLD_OFF(tunnel_data.gtpu_teid),
				 .len = 4,
				 .disp = 0,
				 .mask = 0},
		[SXE2_FLOW_FLD_ID_NVGRE_TNI] = {
				 .off = SXE2_FNAV_FLD_OFF(tunnel_data.gre_tni),
				 .off_inner = SXE2_FNAV_FLD_OFF(tunnel_data.gre_tni),
				 .len = 4,
				 .disp = 0,
				 .mask = 0},
};

static const u8 sxe2_fnav_eth_pkt[22] = {0x00};

static const u8 sxe2_fnav_tcp4_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x50, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00};

static const u8 sxe2_fnav_udp4_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
};

static const u8 sxe2_fnav_sctp4_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x20, 0x00, 0x00,
		0x40, 0x00, 0x40, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 sxe2_fnav_ip4_pkt[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				       0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
				       0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40,
				       0x00, 0x40, 0x10, 0x00, 0x00, 0x00, 0x00,
				       0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const u8 sxe2_fnav_tcp6_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x86, 0xDD, 0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x50, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 sxe2_fnav_udp6_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x86, 0xDD, 0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
};

static const u8 sxe2_fnav_sctp6_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x86, 0xDD, 0x60, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x84, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 sxe2_fnav_ip6_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x86, 0xDD, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3B, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 sxe2_fnav_udp4_vxlan_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x4e, 0x00, 0x00,
		0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
};

static const u8 sxe2_fnav_ipv6_gre_tun_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x3a,
		0x2f, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x58};

static const u8 sxe2_fnav_tcp4_tun_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x5a, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x20,
		0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 sxe2_fnav_udp4_tun_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x4e, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
};

static const u8 sxe2_fnav_sctp4_tun_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x52, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x84, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 sxe2_fnav_ip4_tun_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x46, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 sxe2_fnav_tcp6_tun_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x6e, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0xdd, 0x60, 0x00,
		0x00, 0x00, 0x00, 0x14, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x20, 0x00, 0x00,
		0x00, 0x00, 0x00,
};

static const u8 sxe2_fnav_udp6_tun_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x62, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0xdd, 0x60, 0x00,
		0x00, 0x00, 0x00, 0x08, 0x11, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
};

static const u8 sxe2_fnav_sctp6_tun_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x66, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0xdd, 0x60, 0x00,
		0x00, 0x00, 0x00, 0x0c, 0x84, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 sxe2_fnav_ip6_tun_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x5a, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0xdd, 0x60, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x3b, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 sxe2_fnav_ip4_frag_pkt[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					    0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
					    0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x20,
					    0x00, 0x40, 0x10, 0x00, 0x00, 0x00, 0x00,
					    0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const u8 sxe2_fnav_ip6_frag_pkt[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x86, 0xDD, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3B,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const struct sxe2_fnav_base_pkt sxe2_fnav_pkt[] = {
		{
				SXE2_FNAV_FLOW_TYPE_ETH,
				sizeof(sxe2_fnav_eth_pkt),
				sxe2_fnav_eth_pkt,
				sizeof(sxe2_fnav_eth_pkt),
				sxe2_fnav_eth_pkt,
		},
		{
				SXE2_FNAV_FLOW_TYPE_IPV4_TCP,
				sizeof(sxe2_fnav_tcp4_pkt),
				sxe2_fnav_tcp4_pkt,
				sizeof(sxe2_fnav_tcp4_tun_pkt),
				sxe2_fnav_tcp4_tun_pkt,
		},
		{
				SXE2_FNAV_FLOW_TYPE_IPV4_UDP,
				sizeof(sxe2_fnav_udp4_pkt),
				sxe2_fnav_udp4_pkt,
				sizeof(sxe2_fnav_udp4_tun_pkt),
				sxe2_fnav_udp4_tun_pkt,
		},
		{
				SXE2_FNAV_FLOW_TYPE_IPV4_SCTP,
				sizeof(sxe2_fnav_sctp4_pkt),
				sxe2_fnav_sctp4_pkt,
				sizeof(sxe2_fnav_sctp4_tun_pkt),
				sxe2_fnav_sctp4_tun_pkt,
		},
		{
				SXE2_FNAV_FLOW_TYPE_IPV4_OTHER,
				sizeof(sxe2_fnav_ip4_pkt),
				sxe2_fnav_ip4_pkt,
				sizeof(sxe2_fnav_ip4_tun_pkt),
				sxe2_fnav_ip4_tun_pkt,
		},
		{
				SXE2_FNAV_FLOW_TYPE_IPV6_TCP,
				sizeof(sxe2_fnav_tcp6_pkt),
				sxe2_fnav_tcp6_pkt,
				sizeof(sxe2_fnav_tcp6_tun_pkt),
				sxe2_fnav_tcp6_tun_pkt,
		},
		{
				SXE2_FNAV_FLOW_TYPE_IPV6_UDP,
				sizeof(sxe2_fnav_udp6_pkt),
				sxe2_fnav_udp6_pkt,
				sizeof(sxe2_fnav_udp6_tun_pkt),
				sxe2_fnav_udp6_tun_pkt,
		},
		{
				SXE2_FNAV_FLOW_TYPE_IPV6_SCTP,
				sizeof(sxe2_fnav_sctp6_pkt),
				sxe2_fnav_sctp6_pkt,
				sizeof(sxe2_fnav_sctp6_tun_pkt),
				sxe2_fnav_sctp6_tun_pkt,
		},
		{
				SXE2_FNAV_FLOW_TYPE_IPV6_OTHER,
				sizeof(sxe2_fnav_ip6_pkt),
				sxe2_fnav_ip6_pkt,
				sizeof(sxe2_fnav_ip6_tun_pkt),
				sxe2_fnav_ip6_tun_pkt,
		},
		{
				SXE2_FNAV_FLOW_TYPE_FRAG_IPV4,
				sizeof(sxe2_fnav_ip4_frag_pkt),
				sxe2_fnav_ip4_frag_pkt,
				sizeof(sxe2_fnav_ip4_frag_pkt),
				sxe2_fnav_ip4_frag_pkt,
		},
		{
				SXE2_FNAV_FLOW_TYPE_FRAG_IPV6,
				sizeof(sxe2_fnav_ip6_frag_pkt),
				sxe2_fnav_ip6_frag_pkt,
				sizeof(sxe2_fnav_ip6_frag_pkt),
				sxe2_fnav_ip6_frag_pkt,
		},
};

#define SXE2_FNAV_PKT_NUM ARRAY_SIZE(sxe2_fnav_pkt)

void sxe2_fnav_flow_ctxt_init(struct sxe2_adapter *adapter)
{
	sxe2_flow_ppp_comm_ctxt_init(&adapter->fnav_ctxt.fnav_flow_ctxt.ppp,
				     adapter, SXE2_HW_BLOCK_ID_FNAV);
}

static void sxe2_fnav_flow_ctxt_deinit(struct sxe2_adapter *adapter)
{
	sxe2_flow_ppp_comm_ctxt_deinit(&adapter->fnav_ctxt.fnav_flow_ctxt.ppp);
}

void sxe2_fnav_enter_reset(struct sxe2_adapter *adapter, bool to_reset)
{
	mutex_lock(&adapter->fnav_ctxt.fnav_state_lock);
	if (to_reset)
		adapter->fnav_ctxt.state = SXE2_FNAV_STATE_RESET;
	else
		adapter->fnav_ctxt.state = SXE2_FNAV_STATE_READY;
	mutex_unlock(&adapter->fnav_ctxt.fnav_state_lock);
}

struct sxe2_fnav_flow_cfg *
sxe2_fnav_find_flow_cfg_by_flow_type(struct sxe2_vsi *vsi,
				     enum sxe2_fnav_flow_type flow_type)
{
	struct sxe2_fnav_flow_cfg *flow_cfg = NULL;
	struct sxe2_fnav_flow_cfg *flow_cfg_find = NULL;

	list_for_each_entry(flow_cfg, &vsi->fnav.flow_cfg_list, l_node) {
		if (flow_type == flow_cfg->flow_type) {
			flow_cfg_find = flow_cfg;
			break;
		}
		if (flow_type < flow_cfg->flow_type)
			break;
	}

	return flow_cfg_find;
}

STATIC void sxe2_fnav_flow_cfg_add_list(struct sxe2_vsi *vsi,
					struct sxe2_fnav_flow_cfg *flow_cfg)
{
	struct sxe2_fnav_flow_cfg *flow_tmp, *pre = NULL;
	struct sxe2_vsi_fnav *vsi_fnav = &vsi->fnav;

	list_for_each_entry(flow_tmp, &vsi_fnav->flow_cfg_list, l_node) {
		if (flow_tmp->flow_type >= flow_cfg->flow_type)
			break;
		pre = flow_tmp;
	}

	if (pre)
		list_add(&flow_cfg->l_node, &pre->l_node);
	else
		list_add(&flow_cfg->l_node, &vsi_fnav->flow_cfg_list);
}

void sxe2_fnav_flow_ctxt_clean(struct sxe2_adapter *adapter)
{
	u32 i, j;
	struct sxe2_vsi *vsi;
	struct sxe2_fnav_flow_cfg *flow_cfg = NULL;

	sxe2_flow_ppp_comm_ctxt_clean(&adapter->fnav_ctxt.fnav_flow_ctxt.ppp);

	for (i = 0; i < adapter->vsi_ctxt.cnt; i++) {
		vsi = adapter->vsi_ctxt.vsi[i];
		if (vsi && sxe2_vsi_rxft_support_get(vsi)) {
			mutex_lock(&vsi->fnav.flow_cfg_lock);
			list_for_each_entry(flow_cfg, &vsi->fnav.flow_cfg_list,
					    l_node) {
				for (j = 0; j < SXE2_FNAV_SEG_MAX; j++) {
					if (flow_cfg->seg[j])
						flow_cfg->seg[j]->flow_ptr = NULL;
				}
			}
			mutex_unlock(&vsi->fnav.flow_cfg_lock);
		}
	}

	adapter->fnav_ctxt.space_bcnt = 0;
	adapter->fnav_ctxt.space_gcnt = 0;
}

static void sxe2_fnav_filter_ctxt_init(struct sxe2_adapter *adapter)
{
	u32 i;
	struct sxe2_fnav_context *fnav_ctxt = &adapter->fnav_ctxt;

	fnav_ctxt->pkt_err_cnt = 0;
	fnav_ctxt->space_gcnt = 0;
	fnav_ctxt->space_bcnt = 0;

	for (i = 0; i < SXE2_FNAV_FLTR_HLIST_CNT; i++)
		INIT_HLIST_HEAD(&fnav_ctxt->filter_hlist[i]);

	fnav_ctxt->state = SXE2_FNAV_STATE_READY;
	mutex_init(&fnav_ctxt->fnav_state_lock);
	mutex_init(&fnav_ctxt->fnav_space_lock);
	mutex_init(&fnav_ctxt->filter_lock);
}

s32 sxe2_flow_fnav_update_hw_prof_fv_mask(struct sxe2_ppp_common_ctxt *ppp_ctxt,
					  u8 prof_id, u16 *masks)
{
	struct sxe2_adapter *adapter = ppp_ctxt->adapter;
	s32 ret = 0;
	u32 mask_sel = 0;
	u16 i;

	for (i = 0; i < ppp_ctxt->hw_fv_num; i++) {
		if (masks[i] && masks[i] != SXE2_U16_MASK)
			mask_sel |= (u32)BIT(i);
	}

	if (mask_sel == 0)
		goto l_end;

	ret = sxe2_flow_update_fv_mask_sel(ppp_ctxt, prof_id, mask_sel);
	if (ret)
		LOG_ERROR_BDF("failed to update fv mask sel.\n");

l_end:
	return ret;
}

static void sxe2_fnav_filter_ctxt_deinit(struct sxe2_adapter *adapter)
{
	struct sxe2_fnav_context *fnav_ctxt = &adapter->fnav_ctxt;

	fnav_ctxt->state = SXE2_FNAV_STATE_UNINIT;
	mutex_destroy(&fnav_ctxt->fnav_state_lock);
	mutex_destroy(&fnav_ctxt->fnav_space_lock);
	mutex_destroy(&fnav_ctxt->filter_lock);
}

void sxe2_fnav_ctxt_init(struct sxe2_adapter *adapter)
{
	clear_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags);
	if (adapter->caps_ctxt.fnav_space_bsize > 0 ||
	    adapter->caps_ctxt.fnav_space_gsize > 0) {
		set_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags);
	}
	sxe2_fnav_flow_ctxt_init(adapter);
	sxe2_fnav_filter_ctxt_init(adapter);
	sxe2_fnav_stat_ctxt_init(adapter);
}

void sxe2_fnav_ctxt_deinit(struct sxe2_adapter *adapter)
{
	sxe2_fnav_filter_ctxt_deinit(adapter);
	sxe2_fnav_flow_ctxt_deinit(adapter);
	sxe2_fnav_stat_ctxt_deinit(adapter);
	clear_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags);
}

bool sxe2_fnav_flow_seg_compare(struct sxe2_fnav_flow_seg *seg_a,
				struct sxe2_fnav_flow_seg *seg_b)
{
	u8 i = 0;

	if (seg_a->is_tunnel != seg_b->is_tunnel)
		return false;

	if (!bitmap_equal(seg_a->headers, seg_b->headers, SXE2_FLOW_HDR_MAX))
		return false;

	if (!bitmap_equal(seg_a->fields, seg_b->fields, SXE2_FLOW_FLD_ID_MAX))
		return false;

	if (seg_a->raw_cnt != seg_b->raw_cnt)
		return false;

	for (i = 0; i < seg_a->raw_cnt; i++) {
		if (seg_a->raw[i].offset != seg_b->raw[i].offset)
			return false;
		if (seg_a->raw[i].len != seg_b->raw[i].len)
			return false;
	}

	return true;
}

static void sxe2_fnav_gen_dissector_info(struct sxe2_flow_dissector_info *dissectors,
					 u8 dissectors_cnt,
					 struct sxe2_fnav_flow_seg *seg)
{
	u64 i;
	struct sxe2_flow_dissector_info *dissector;

	dissector = &dissectors[dissectors_cnt - 1];

	for_each_set_bit(i, seg->fields, SXE2_FLOW_FLD_ID_MAX) {
		sxe2_flow_set_diss_fld(dissector, (enum sxe2_flow_fld_id)i,
				       SXE2_U16_MASK, SXE2_U16_MASK, SXE2_U16_MASK);
	}

	bitmap_or(dissector->headers, dissector->headers, seg->headers,
		  SXE2_FLOW_HDR_MAX);

	for (i = 0; i < seg->raw_cnt; i++) {
		sxe2_flow_add_diss_raw(dissector, seg->raw[i].offset, SXE2_U16_MASK,
				       SXE2_U16_MASK, seg->raw[i].len);
	}
}

STATIC struct sxe2_flow_info_node *
sxe2_fnav_hw_flow_add(struct sxe2_adapter *adapter, struct sxe2_fnav_flow_seg *segs,
		      s32 *result)
{
	s32 ret = 0;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_ppp_common_ctxt *ppp_ctxt =
			&adapter->fnav_ctxt.fnav_flow_ctxt.ppp;
	struct sxe2_flow_dissector_info *dissectors = NULL;
	bool is_tunnel = segs->is_tunnel;
	u8 dissectors_cnt = is_tunnel ? SXE2_FNAV_TUN_DISSECT_CNT
				      : SXE2_FNAV_NO_TUN_DISSECT_CNT;
	struct sxe2_flow_info_node *flow = NULL;
	u16 i = 0;
	struct sxe2_fnav_flow_seg *seg = NULL;

	dissectors = devm_kcalloc(dev, dissectors_cnt, sizeof(*dissectors),
				  GFP_KERNEL);
	if (!dissectors)
		goto l_end;

	for (i = 0; i < dissectors_cnt; i++) {
		seg = &segs[i];
		LOG_DEV_DEBUG("add a flow, header:0x%lX, field[0]:0x%lX, is_tun:%d.\n",
			      seg->headers[0], seg->fields[0], seg->is_tunnel);
		sxe2_fnav_gen_dissector_info(dissectors, (u8)(i + 1), seg);
	}

	flow = sxe2_find_flow(ppp_ctxt, dissectors, dissectors_cnt);
	if (flow) {
		LOG_DEBUG_BDF("find a flow with seg cfg.\n");
		goto l_end;
	}

	ret = sxe2_flow_creat(ppp_ctxt, dissectors, dissectors_cnt, &flow);
	if (ret) {
		LOG_ERROR_BDF("create a flow with seg cfg failed, ret:%d\n", ret);
		*result = ret;
	}

l_end:
	if (dissectors)
		devm_kfree(dev, dissectors);

	return flow;
}

STATIC bool sxe2_fnav_flow_segs_compare(struct sxe2_fnav_flow_seg *seg_a,
					struct sxe2_fnav_flow_seg *seg_b, u8 seg_cnt)
{
	u8 i = 0;

	for (i = 0; i < seg_cnt; i++) {
		if (!sxe2_fnav_flow_seg_compare(&seg_a[i], &seg_b[i]))
			return false;
	}
	return true;
}

s32 sxe2_fnav_hw_flow_del(struct sxe2_adapter *adapter,
			  struct sxe2_flow_info_node *flow)
{
	s32 ret = 0;
	struct sxe2_ppp_common_ctxt *ppp_ctxt =
			&adapter->fnav_ctxt.fnav_flow_ctxt.ppp;

	if (!flow)
		return 0;

	if (bitmap_empty((unsigned long *)flow->used_vsi, SXE2_MAX_VSI_NUM))
		ret = sxe2_flow_delete(ppp_ctxt, flow);

	return ret;
}

STATIC bool sxe2_eth_fnav_support_flow_type(enum sxe2_fnav_flow_type flow_type)
{
	bool is_support = false;

	switch (flow_type) {
	case SXE2_FNAV_FLOW_TYPE_ETH:
	case SXE2_FNAV_FLOW_TYPE_IPV4_OTHER:
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
	case SXE2_FNAV_FLOW_TYPE_IPV4_SCTP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_OTHER:
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_SCTP:
		is_support = true;
		break;
	default:
		break;
	}
	return is_support;
}

STATIC bool sxe2_fnav_filter_multi_vsi_dup(struct sxe2_adapter *adapter,
					   struct sxe2_fnav_filter *filter,
					   struct sxe2_fnav_flow_cfg *flow_cfg)
{
	bool is_dup = false;
	struct sxe2_vsi *other_vsi = NULL;
	u16 other_vsi_id;
	u16 other_filter_cnt = 0;

	if (!sxe2_eth_fnav_support_flow_type(filter->flow_type))
		goto l_end;

	if (flow_cfg->self_vsi_used.vsi_id_sw == filter->rule_vsi_sw) {
		other_vsi_id = flow_cfg->peer_vsi_used.vsi_id_sw;
		other_filter_cnt = flow_cfg->peer_vsi_used.filter_cnt;
	} else {
		other_vsi_id = flow_cfg->self_vsi_used.vsi_id_sw;
		other_filter_cnt = flow_cfg->self_vsi_used.filter_cnt;
	}

	if (other_vsi_id != SXE2_INVAL_U16 && other_filter_cnt != 0)
		other_vsi = adapter->vsi_ctxt.vsi[other_vsi_id];

	if (!other_vsi)
		goto l_end;

	if (sxe2_comm_fnav_filter_search_for_dup(other_vsi, filter)) {
		LOG_ERROR_BDF("sxe2 fnav vsi:%u has dup filter with other vsi:%u\n",
			      filter->rule_vsi_sw, other_vsi_id);
		is_dup = true;
	}
l_end:
	return is_dup;
}

s32 sxe2_fnav_flow_cfg_add(struct sxe2_vsi *vsi, struct sxe2_fnav_flow_cfg *flow_cfg,
			   struct sxe2_fnav_flow_seg *seg)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	s32 ret = 0;
	s32 ret_tmp = 0;
	struct sxe2_ppp_common_ctxt *ppp_ctxt =
			&adapter->fnav_ctxt.fnav_flow_ctxt.ppp;
	enum sxe2_fnav_flow_type flow_type = flow_cfg->flow_type;
	u8 level = seg->is_tunnel ? SXE2_FNAV_SEG_TUN : SXE2_FNAV_SEG_NON_TUN;
	struct sxe2_fnav_flow_seg *seg_old = flow_cfg->seg[level];
	struct sxe2_flow_info_node *flow;
	u8 seg_cnt = seg->is_tunnel ? 2 : 1;

	if (seg_old) {
		if (sxe2_fnav_flow_segs_compare(seg_old, seg, seg_cnt)) {
			LOG_INFO_BDF("both segs are same, flow_type:%d, tun:%d.\n",
				     flow_type, seg->is_tunnel);
			return -EEXIST;
		}

		if (flow_cfg->filter_cnt[level] != 0 ||
		    sxe2_arfs_flow_cfg_used(adapter, vsi->id_in_pf, flow_type)) {
			LOG_ERROR_BDF("filter_cnt(%u) is not zero or arfs is using this flow\n",
				      flow_cfg->filter_cnt[level]);
			return -EINVAL;
		}

		ret = sxe2_fnav_flow_cfg_del(adapter, flow_cfg, seg->is_tunnel);
		if (ret) {
			LOG_ERROR_BDF("flow cfg del failed, ret:%d\n", ret);
			return ret;
		}
	}

	flow = sxe2_fnav_hw_flow_add(adapter, seg, &ret_tmp);
	if (!flow) {
		LOG_ERROR_BDF("fnav hw flow add failed, ret:%d\n", ret_tmp);
		ret = ret_tmp ? ret_tmp : -EIO;
		goto flow_add_failed;
	}

	ret = sxe2_flow_assoc_vsi_fnav(ppp_ctxt, flow, vsi->id_in_pf, flow_type);
	if (ret) {
		LOG_ERROR_BDF("fnav hw flow associate main vsi failed, ret:%d\n",
			      ret);
		goto assoc_main_vsi_failed;
	}

	set_bit(vsi->id_in_pf, seg->vsis);
	seg->flow_ptr = flow;
	flow_cfg->seg[level] = seg;

	return 0;

assoc_main_vsi_failed:
	(void)sxe2_fnav_hw_flow_del(adapter, flow);
flow_add_failed:
	return ret;
}

s32 sxe2_fnav_flow_cfg_del(struct sxe2_adapter *adapter,
			   struct sxe2_fnav_flow_cfg *flow_cfg, bool is_tunnel)
{
	s32 ret = 0;
	u64 vsi_sw_id;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_ppp_common_ctxt *ppp_ctxt =
			&adapter->fnav_ctxt.fnav_flow_ctxt.ppp;
	u8 level = is_tunnel ? SXE2_FNAV_SEG_TUN : SXE2_FNAV_SEG_NON_TUN;
	struct sxe2_flow_info_node *flow;

	if (!flow_cfg->seg[level])
		return 0;

	if (!flow_cfg->seg[level]->flow_ptr)
		return 0;

	flow = flow_cfg->seg[level]->flow_ptr;

	for_each_set_bit(vsi_sw_id, flow_cfg->seg[level]->vsis, SXE2_MAX_VSI_NUM) {
		ret = sxe2_flow_disassoc_vsi(ppp_ctxt, flow, (u16)vsi_sw_id);
		if (ret) {
			LOG_ERROR_BDF("fnav hw flow disassociate vsi failed,\t"
				      "vsi_sw_id:%u ret:%d\n",
				      (u16)vsi_sw_id, ret);
			goto l_end;
		}
		clear_bit((u16)vsi_sw_id, flow_cfg->seg[level]->vsis);
	}

	ret = sxe2_fnav_hw_flow_del(adapter, flow);
	if (ret) {
		LOG_ERROR_BDF("fnav hw flow del failed, vsi_sw_id:%u ret:%d\n",
			      (u16)vsi_sw_id, ret);
		goto l_end;
	}

	devm_kfree(dev, flow_cfg->seg[level]);
	flow_cfg->seg[level] = NULL;

l_end:
	return ret;
}

STATIC s32 sxe2_fnav_flow_cfg_replay(struct sxe2_adapter *adapter,
				     struct sxe2_fnav_flow_seg *seg)
{
	s32 ret = 0;
	s32 ret_tmp = 0;
	u64 i;
	struct sxe2_ppp_common_ctxt *ppp_ctxt =
			&adapter->fnav_ctxt.fnav_flow_ctxt.ppp;
	struct sxe2_flow_info_node *flow;

	flow = sxe2_fnav_hw_flow_add(adapter, seg, &ret_tmp);
	if (!flow) {
		LOG_ERROR_BDF("fnav hw flow add failed, ret:%d\n", ret_tmp);
		ret = ret_tmp ? ret_tmp : -EIO;
		goto flow_add_failed;
	}

	for_each_set_bit(i, seg->vsis, SXE2_MAX_VSI_NUM) {
		ret = sxe2_flow_assoc_vsi(ppp_ctxt, flow, (u16)i);
		if (ret) {
			LOG_ERROR_BDF("fnav hw flow associate vsi[%u] failed, ret:%d\n",
				      (u16)i, ret);
			goto assoc_vsi_failed;
		}
	}

	seg->flow_ptr = flow;

	return 0;

assoc_vsi_failed:
	(void)sxe2_fnav_hw_flow_del(adapter, flow);
flow_add_failed:
	return ret;
}

static s32
sxe2_fnav_default_flow_seg_fill_by_type(enum sxe2_fnav_flow_type flow_type,
					struct sxe2_fnav_flow_seg *seg)
{
	switch (flow_type) {
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
		set_bit(SXE2_FLOW_HDR_ETH, seg->headers);
		set_bit(SXE2_FLOW_HDR_IPV4, seg->headers);
		set_bit(SXE2_FLOW_HDR_TCP, seg->headers);
		set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, seg->fields);
		set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, seg->fields);
		set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, seg->fields);
		set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, seg->fields);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
		set_bit(SXE2_FLOW_HDR_ETH, seg->headers);
		set_bit(SXE2_FLOW_HDR_IPV4, seg->headers);
		set_bit(SXE2_FLOW_HDR_UDP, seg->headers);
		set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, seg->fields);
		set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, seg->fields);
		set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, seg->fields);
		set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, seg->fields);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
		set_bit(SXE2_FLOW_HDR_ETH, seg->headers);
		set_bit(SXE2_FLOW_HDR_IPV6, seg->headers);
		set_bit(SXE2_FLOW_HDR_TCP, seg->headers);
		set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, seg->fields);
		set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, seg->fields);
		set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, seg->fields);
		set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, seg->fields);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
		set_bit(SXE2_FLOW_HDR_ETH, seg->headers);
		set_bit(SXE2_FLOW_HDR_IPV6, seg->headers);
		set_bit(SXE2_FLOW_HDR_UDP, seg->headers);
		set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, seg->fields);
		set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, seg->fields);
		set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, seg->fields);
		set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, seg->fields);
		break;
	default:
		LOG_ERROR("flow type is not supported.");
		return -EINVAL;
	}

	seg->is_tunnel = false;

	return 0;
}

static s32 sxe2_fnav_default_flow_set_by_type(struct sxe2_vsi *vsi,
					      enum sxe2_fnav_flow_type flow_type)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	s32 ret = 0;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_fnav_flow_seg *seg = NULL;
	struct sxe2_fnav_flow_cfg *flow_cfg = NULL;
	bool new_alloc_flow = false;

	flow_cfg = sxe2_fnav_find_flow_cfg_by_flow_type(vsi, flow_type);
	if (flow_cfg) {
		if (flow_cfg->seg[SXE2_FNAV_SEG_NON_TUN] ||
		    flow_cfg->seg[SXE2_FNAV_SEG_TUN]) {
			ret = -EINVAL;
			goto l_end;
		}
	} else {
		flow_cfg = devm_kzalloc(dev, sizeof(*flow_cfg), GFP_KERNEL);
		flow_cfg->flow_type = flow_type;
		flow_cfg->peer_vsi_used.vsi_id_sw =
				SXE2_INVAL_U16;
		flow_cfg->peer_vsi_used.filter_cnt = 0;
		flow_cfg->self_vsi_used.vsi_id_sw = vsi->id_in_pf;
		flow_cfg->self_vsi_used.filter_cnt = 0;
		new_alloc_flow = true;
	}

	LOG_INFO_BDF("add default fnav cfg, flow type: %d\n", flow_type);

	seg = devm_kzalloc(dev, sizeof(*seg), GFP_KERNEL);
	if (!seg) {
		ret = -ENOMEM;
		goto l_free;
	}

	ret = sxe2_fnav_default_flow_seg_fill_by_type(flow_type, seg);

	if (ret) {
		LOG_ERROR_BDF("default flow seg fill failed, ret:%d\n", ret);
		goto l_free;
	}

	ret = sxe2_fnav_flow_cfg_add(vsi, flow_cfg, seg);
	if (ret) {
		LOG_ERROR_BDF("outer rule add failed, ret:%d\n", ret);
		goto l_free;
	}

	if (!ret) {
		flow_cfg->full_match = true;
		if (new_alloc_flow)
			sxe2_fnav_flow_cfg_add_list(vsi, flow_cfg);
	} else {
		if (new_alloc_flow)
			devm_kfree(dev, flow_cfg);
	}

	goto l_end;

l_free:
	if (seg)
		devm_kfree(dev, seg);
l_end:
	return ret;
}

s32 sxe2_fnav_default_flow_set(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;

	mutex_lock(&vsi->fnav.flow_cfg_lock);

	ret = sxe2_fnav_default_flow_set_by_type(vsi, SXE2_FNAV_FLOW_TYPE_IPV4_TCP);
	if (ret)
		LOG_WARN_BDF("tcp4 flow full match set failed, ret:%d\n", ret);

	ret = sxe2_fnav_default_flow_set_by_type(vsi, SXE2_FNAV_FLOW_TYPE_IPV4_UDP);
	if (ret)
		LOG_WARN_BDF("udp4 flow full match set failed, ret:%d\n", ret);

	ret = sxe2_fnav_default_flow_set_by_type(vsi, SXE2_FNAV_FLOW_TYPE_IPV6_TCP);
	if (ret)
		LOG_WARN_BDF("tcp6 flow full match set failed, ret:%d\n", ret);

	ret = sxe2_fnav_default_flow_set_by_type(vsi, SXE2_FNAV_FLOW_TYPE_IPV6_UDP);
	if (ret)
		LOG_WARN_BDF("udp6 flow full match set failed, ret:%d\n", ret);

	mutex_unlock(&vsi->fnav.flow_cfg_lock);
	return ret;
}

bool sxe2_fnav_flow_sup_arfs(enum sxe2_fnav_flow_type flow_type)
{
	switch (flow_type) {
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
		return true;
	default:
		return false;
	}
}

void sxe2_fnav_filter_hash(struct sxe2_fnav_filter *filter)
{
	u32 hash = 0;
	u16 offset = 0;
	u8 hash_fld[SXE2_FNAV_HASH_FLD_MAX_SIZE];

	if (filter->hashed)
		return;

	switch (filter->flow_type) {
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
	case SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_TCP:
	case SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP:
		memcpy(hash_fld + offset, &filter->full_key.ip.v4.src_ip,
		       SXE2_FNAV_IPV4_ADDR_SIZE);
		offset += SXE2_FNAV_IPV4_ADDR_SIZE;
		memcpy(hash_fld + offset, &filter->full_key.ip.v4.dst_ip,
		       SXE2_FNAV_IPV4_ADDR_SIZE);
		offset += SXE2_FNAV_IPV4_ADDR_SIZE;
		memcpy(hash_fld + offset, &filter->full_key.l4.src_port,
		       SXE2_FNAV_L4_PORT_SIZE);
		offset += SXE2_FNAV_L4_PORT_SIZE;
		memcpy(hash_fld + offset, &filter->full_key.l4.dst_port,
		       SXE2_FNAV_L4_PORT_SIZE);
		offset += SXE2_FNAV_L4_PORT_SIZE;
		hash = jhash(hash_fld, SXE2_FNAV_IP4_HASH_FLD_SIZE, 0);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
	case SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_TCP:
	case SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_UDP:
		memcpy(hash_fld + offset, &filter->full_key.ip.v6.src_ip,
		       SXE2_FNAV_IPV6_ADDR_SIZE);
		offset += SXE2_FNAV_IPV6_ADDR_SIZE;
		memcpy(hash_fld + offset, &filter->full_key.ip.v6.dst_ip,
		       SXE2_FNAV_IPV6_ADDR_SIZE);
		offset += SXE2_FNAV_IPV6_ADDR_SIZE;
		memcpy(hash_fld + offset, &filter->full_key.l4.src_port,
		       SXE2_FNAV_L4_PORT_SIZE);
		offset += SXE2_FNAV_L4_PORT_SIZE;
		memcpy(hash_fld + offset, &filter->full_key.l4.dst_port,
		       SXE2_FNAV_L4_PORT_SIZE);
		offset += SXE2_FNAV_L4_PORT_SIZE;
		hash = jhash(hash_fld, SXE2_FNAV_IP6_HASH_FLD_SIZE, 0);
		break;
	default:
		break;
	}

	filter->hash_val = hash;
	filter->hashed = true;
}

void sxe2_fnav_flow_cfg_free(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_fnav_flow_cfg *flow_cfg, *cfg_tmp;
	u16 j = 0;

	mutex_lock(&vsi->fnav.flow_cfg_lock);

	list_for_each_entry_safe(flow_cfg, cfg_tmp, &vsi->fnav.flow_cfg_list, l_node) {
		for (j = 0; j < SXE2_FNAV_SEG_MAX; j++) {
			if (flow_cfg->seg[j]) {
				devm_kfree(dev, flow_cfg->seg[j]);
				flow_cfg->seg[j] = NULL;
			}
			flow_cfg->filter_cnt[j] = 0;
		}
		list_del(&flow_cfg->l_node);
		devm_kfree(dev, flow_cfg);
	}

	mutex_unlock(&vsi->fnav.flow_cfg_lock);
}

s32 sxe2_fnav_flow_cfg_clear_by_vsi(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	u16 vsi_sw_idx = vsi->id_in_pf;
	s32 ret = 0;
	u32 j;
	struct sxe2_ppp_common_ctxt *ppp_ctxt =
			&adapter->fnav_ctxt.fnav_flow_ctxt.ppp;
	u16 vsig_idx;
	bool only_vsi;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_fnav_flow_cfg *flow_cfg, *cfg_tmp;

	ret = sxe2_flow_find_vsig_with_vsi(ppp_ctxt, vsi_sw_idx, &vsig_idx);
	if (ret != 0)
		goto l_end;

	if (vsig_idx == SXE2_PPP_DEFAULT_VSIG_IDX)
		goto l_delete;

	only_vsi = (ppp_ctxt->vsig[vsig_idx].vsi_cnt == 1);
	if (!only_vsi) {
		ret = sxe2_flow_cfg_clear_muti_vsi_in_vsig(adapter, ppp_ctxt,
							   vsi_sw_idx);
		if (ret)
			goto l_end;
		else
			goto l_delete;
	}

	mutex_lock(&vsi->fnav.flow_cfg_lock);
	list_for_each_entry_safe(flow_cfg, cfg_tmp, &vsi->fnav.flow_cfg_list, l_node) {
		for (j = 0; j < SXE2_FNAV_SEG_MAX; j++) {
			ret = sxe2_fnav_flow_cfg_del(adapter, flow_cfg, j);
			if (ret) {
				mutex_unlock(&vsi->fnav.flow_cfg_lock);
				LOG_ERROR_BDF("flow cfg del failed, j:%u\n", j);
				goto l_end;
			}
		}
		list_del(&flow_cfg->l_node);
		devm_kfree(dev, flow_cfg);
	}
	mutex_unlock(&vsi->fnav.flow_cfg_lock);

l_end:
	return ret;
l_delete:
	sxe2_fnav_flow_cfg_free(vsi);
	goto l_end;
}

s32 sxe2_pf_eth_fnav_init(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi = NULL;

	if (sxe2_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return 0;

	vsi = adapter->vsi_ctxt.main_vsi;
	adapter->arfs_ctxt.vsi_id_in_pf = vsi->id_in_pf;

	ret = sxe2_ctrl_vsi_init(adapter);
	if (ret) {
		LOG_DEV_ERR("ctrl vsi init failed, ret=%d\n", ret);
		goto l_end;
	}

	if (test_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags)) {
		ret = sxe2_fnav_default_flow_set(adapter);
		if (ret)
			LOG_DEV_WARN("fnav default flow set failed, ret=%d\n", ret);
		sxe2_fnav_reserve_stat_idx_alloc(adapter);
	}
l_end:
	return ret;
}

void sxe2_pf_eth_fnav_deinit(struct sxe2_adapter *adapter)
{
	if (sxe2_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return;

	(void)sxe2_pf_fnav_flow_cfg_clear(adapter);
	sxe2_ctrl_vsi_deinit(adapter);
}

s32 sxe2_pf_eth_fnav_rebuild(struct sxe2_adapter *adapter)
{
	s32 ret = 0;

	if (sxe2_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return 0;

	ret = sxe2_vsi_rebuild_by_type(adapter, SXE2_VSI_T_CTRL, true);
	if (ret) {
		LOG_DEV_ERR("ctrl vsi rebuild failed, ret:%d\n", ret);
		goto l_end;
	}

	ret = sxe2_vsi_enable_by_type(adapter, SXE2_VSI_T_CTRL);
	if (ret) {
		LOG_DEV_ERR("sxe2_vsi_enable_by_type failed, ret:%d\n", ret);
		goto l_end;
	}

	if (test_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags)) {
		ret = sxe2_fnav_rule_reply(adapter);
		if (ret) {
			LOG_DEV_ERR("fnav rule failed, ret:%d\n", ret);
			goto l_end;
		}
	}

	LOG_INFO_BDF("sxe2 pf eth fnav rebuild done. ret:%d.\n", ret);

l_end:
	return ret;
}

s32 sxe2_pf_fnav_flow_cfg_clear(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	u32 j = 0;
	u32 filter_cnt = 0;
	struct sxe2_vsi *vsi = NULL;
	struct sxe2_fnav_flow_cfg *flow_cfg, *cfg_tmp;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	if (sxe2_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return 0;

	vsi = adapter->vsi_ctxt.main_vsi;

	mutex_lock(&vsi->fnav.flow_cfg_lock);
	list_for_each_entry(flow_cfg, &vsi->fnav.flow_cfg_list, l_node) {
		filter_cnt += flow_cfg->filter_cnt[SXE2_FNAV_SEG_NON_TUN];
		filter_cnt += flow_cfg->filter_cnt[SXE2_FNAV_SEG_TUN];
	}
	mutex_unlock(&vsi->fnav.flow_cfg_lock);
	if (filter_cnt == 0) {
		ret = sxe2_fnav_flow_cfg_clear_by_vsi(vsi);
		if (ret)
			LOG_ERROR_BDF("sxe2 pf fnav flow cfg clear batch failed.\n");
		goto l_end;
	}

	mutex_lock(&vsi->fnav.flow_cfg_lock);
	list_for_each_entry_safe(flow_cfg, cfg_tmp, &vsi->fnav.flow_cfg_list, l_node) {
		filter_cnt = 0;
		for (j = 0; j < SXE2_FNAV_SEG_MAX; j++) {
			filter_cnt += flow_cfg->filter_cnt[j];
			if (flow_cfg->filter_cnt[j] == 0) {
				ret = sxe2_fnav_flow_cfg_del(adapter, flow_cfg, j);
				if (ret) {
					mutex_unlock(&vsi->fnav.flow_cfg_lock);
					LOG_ERROR_BDF("flow cfg del failed, j:%u\n",
						      j);
					goto l_end;
				}
			}
		}

		if (filter_cnt == 0) {
			list_del(&flow_cfg->l_node);
			devm_kfree(dev, flow_cfg);
		}
	}
	mutex_unlock(&vsi->fnav.flow_cfg_lock);

l_end:
	return ret;
}

STATIC s32 sxe2_fnav_inputset_fill(struct sxe2_adapter *adapter,
				   struct sxe2_fnav_flow_seg *segs,
				   struct sxe2_fnav_filter *filter)
{
	s32 ret = 0;
	u32 off = 0;
	u64 fld = 0;
	struct sxe2_fnav_flow_seg *seg = NULL;
	u8 *inputset = filter->inputset;
	__be16 *val;
	u16 val_tmp;
	__be16 val_tmp_be;
	u16 def_mask_id = 0;
	u16 def_fv_id = 0;
	u8 def_mask_cnt = adapter->fnav_ctxt.fnav_flow_ctxt.ppp.hw_fv_mask_num;
	u8 seg_cnt = 0;
	u8 i = 0;
	u32 fld_off = 0;
	DECLARE_BITMAP(fields, SXE2_FLOW_FLD_ID_MAX);

	if (!segs) {
		LOG_ERROR_BDF("flow cfg is NULL.\n");
		return -EINVAL;
	}

	if (segs->is_tunnel)
		seg_cnt = 2;
	else
		seg_cnt = 1;

	for (i = 0; i < seg_cnt; i++) {
		seg = &segs[i];
		bitmap_zero(fields, SXE2_FLOW_FLD_ID_MAX);
		bitmap_copy(fields, seg->fields, SXE2_FLOW_FLD_ID_MAX);

		for_each_set_bit(fld, fields, SXE2_FLOW_FLD_ID_MAX) {
			fld_off = i ? sxe2_flds_info[fld].off_inner
				    : sxe2_flds_info[fld].off;
			if (sxe2_flds_info[fld].mask) {
				ret = sxe2_flow_default_mask_get(SXE2_HW_BLOCK_ID_FNAV,
								 adapter,
								 (enum sxe2_flow_fld_id)fld,
								 &def_mask_id, &def_fv_id);
				if (ret) {
					LOG_ERROR_BDF("failed to parse default mask.\n");
					goto l_end;
				}
				val = (__be16 *)(inputset + ((u64)def_fv_id * 2));
				if (sxe2_flds_info[fld].len == 2) {
					val_tmp_be = *((u16 *)((u8 *)(&filter->full_key) +
							       fld_off));
					val_tmp_be = val_tmp_be &
						     cpu_to_be16(sxe2_flds_info[fld]
										 .mask);
					*val = val_tmp_be;
				} else {
					val_tmp = *((u16 *)((u8 *)(&filter->full_key) +
							    fld_off));
					val_tmp = val_tmp
						  << sxe2_flds_info[fld].disp;
					val_tmp = val_tmp & sxe2_flds_info[fld].mask;
					*val = cpu_to_be16(val_tmp);
				}
			} else {
				if ((u32)(off + sxe2_flds_info[fld].len) >
				    (u32)(((u16)SXE2_FNAV_INPUT_CNT - def_mask_cnt) *
					  (u8)SXE2_FLOW_FV_SIZE)) {
					ret = -ENOSPC;
					LOG_ERROR_BDF("used inputset out of max limit, len=%u.\n",
						      off + sxe2_flds_info[fld].len);
					goto l_end;
				}
				memcpy(inputset + off,
				       ((u8 *)&filter->full_key) + fld_off,
				       sxe2_flds_info[fld].len);
				off += sxe2_flds_info[fld].len;
			}
			clear_bit((int)fld, fields);
		}
	}

	if (filter->full_key.has_flex_filed) {
		if ((u32)(off + sizeof(filter->full_key.flex_word)) >
		    (u32)(((u16)SXE2_FNAV_INPUT_CNT - def_mask_cnt) *
			  (u16)SXE2_FLOW_FV_SIZE)) {
			ret = -ENOSPC;
			LOG_ERROR_BDF("used inputset out of max limit, len=%lu.\n",
				      off + sizeof(filter->full_key.flex_word));
			goto l_end;
		}
		memcpy(inputset + off, &filter->full_key.flex_word,
		       sizeof(filter->full_key.flex_word));
	}

l_end:
	return ret;
}

s32 sxe2_fnav_filter_inputset_fill(struct sxe2_vsi *vsi,
				   struct sxe2_fnav_filter *filter,
				   struct sxe2_fnav_flow_cfg *flow_cfg)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	s32 ret = 0;
	struct sxe2_fnav_flow_seg *segs = NULL;

	if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_TUNNEL)
		segs = flow_cfg->seg[SXE2_FNAV_SEG_TUN];
	else
		segs = flow_cfg->seg[SXE2_FNAV_SEG_NON_TUN];

	ret = sxe2_fnav_inputset_fill(adapter, segs, filter);
	return ret;
}

STATIC s32 sxe2_fwc_fnav_filter_update(struct sxe2_adapter *adapter,
				       struct sxe2_fnav_flow_cfg *flow_cfg,
				       struct sxe2_fnav_filter *filter, bool is_add,
				       bool tun)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_fwc_fnav_kt_resp kt_resp = {0};
	struct sxe2_fwc_fnav_kt_entry entry = {0};
	struct sxe2_fnav_flow_seg *seg = NULL;
	u8 level = tun ? (SXE2_FNAV_TUN_DISSECT_CNT - 1)
		       : (SXE2_FNAV_NO_TUN_DISSECT_CNT - 1);
	u8 space;

	space = tun ? filter->tunn_fd_space : filter->fd_space;

	seg = flow_cfg->seg[level];
	if (!seg || !seg->flow_ptr) {
		ret = -EINVAL;
		LOG_ERROR_BDF("seg or seh->flow_ptr is NULL. filter_loc: %u,\t"
			      "flow_type: %d, is_add: %d, tun: %d\n",
			      filter->filter_loc, filter->flow_type, is_add, tun);
		goto l_out;
	}

	entry.is_add = (u8)is_add;
	entry.prof_id = (u8)(seg->flow_ptr->prof_id);
	entry.ori_vsi = cpu_to_le16(filter->ori_vsi_hw);
	memcpy(entry.inputset, filter->inputset,
	       SXE2_FNAV_INPUT_CNT * SXE2_FLOW_FV_SIZE);
	entry.vsi = cpu_to_le16(filter->dst_vsi_hw);
	entry.fdid = cpu_to_le32(filter->filter_loc);
	entry.fdid_prio = filter->fdid_prio;
	entry.flow_id = cpu_to_le16((u16)filter->flow_type);
	entry.toq_prio = filter->act_prio;
	entry.drop = filter->act_type == SXE2_FNAV_ACT_DROP ? 1 : 0;
	entry.qindex = cpu_to_le16(filter->q_index);
	entry.stat_cnt = cpu_to_le16(filter->stat_index);
	entry.stat_ena = filter->stat_ctrl;
	entry.to_queue = filter->q_region;
	entry.fd_space = space;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FNAV_FILTER_UPDATE, &entry,
				  sizeof(entry), &kt_resp, sizeof(kt_resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("update fnav filter failed, is_add:%d, tun:%d, ret:%d\n",
			      is_add, tun, ret);
	} else {
		adapter->fnav_ctxt.space_bcnt =
				(u16)(le32_to_cpu(kt_resp.bcnt_global));
		adapter->fnav_ctxt.space_gcnt = (u16)(le32_to_cpu(kt_resp.gcnt_pf));
	}

l_out:
	return ret;
}

enum sxe2_fnav_flow_type
sxe2_arfs_flow_to_fnav_flow(enum sxe2_fnav_flow_type flow_type)
{
	switch (flow_type) {
	case SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_TCP:
		return SXE2_FNAV_FLOW_TYPE_IPV4_TCP;
	case SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP:
		return SXE2_FNAV_FLOW_TYPE_IPV4_UDP;
	case SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_TCP:
		return SXE2_FNAV_FLOW_TYPE_IPV6_TCP;
	case SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_UDP:
		return SXE2_FNAV_FLOW_TYPE_IPV6_UDP;
	default:
		return flow_type;
	}
}

s32 sxe2_pf_fnav_hw_filter_update(struct sxe2_vsi *vsi,
				  struct sxe2_fnav_filter *filter, bool is_add,
				  bool is_update,
				  enum sxe2_fnav_filter_update_type update_type)
{
	struct sxe2_fnav_flow_cfg *flow_cfg = NULL;
	s32 ret = 0;
	enum sxe2_fnav_flow_type flow_type;

	if (!vsi)
		return 0;

	if (update_type == SXE2_FNAV_FILTER_UPDATE_ADMIN) {
		flow_type = sxe2_arfs_flow_to_fnav_flow(filter->flow_type);
		flow_cfg = sxe2_fnav_find_flow_cfg_by_flow_type(vsi, flow_type);
		if (!flow_cfg) {
			ret = -EINVAL;
			goto l_end;
		}
		ret = sxe2_fnav_hw_filter_update_with_admin(vsi, filter, flow_cfg,
							    is_add, false);
		if (ret)
			goto l_end;
		if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY) {
			ret = sxe2_fnav_hw_filter_update_with_admin(vsi,
								    filter,
								    flow_cfg,
								    is_add,
								    true);
			if (ret && is_add)
				(void)sxe2_fnav_hw_filter_update_with_admin(vsi,
									    filter,
									    flow_cfg,
									    false,
									    false);
		}
	} else {
		ret = sxe2_fnav_hw_filter_update_with_pkt(vsi, filter, is_add,
							  is_update, false);
		if (ret)
			goto l_end;
		if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY) {
			ret = sxe2_fnav_hw_filter_update_with_pkt(vsi,
								  filter,
								  is_add,
								  is_update,
								  true);
			if (ret && is_add && !is_update)
				(void)sxe2_fnav_hw_filter_update_with_pkt(vsi,
									  filter,
									  false,
									  false,
									  false);
		}
	}

l_end:
	return ret;
}

s32 sxe2_fnav_hw_filter_update_with_admin(struct sxe2_vsi *vsi,
					  struct sxe2_fnav_filter *filter,
					  struct sxe2_fnav_flow_cfg *flow_cfg,
					  bool is_add, bool is_tunn)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	s32 ret = 0;
	u8 fd_space;

	mutex_lock(&adapter->fnav_ctxt.fnav_space_lock);

	if (is_add) {
		if (adapter->fnav_ctxt.space_gcnt < vsi->fnav.space_gsize)
			fd_space = SXE2_FNAV_FD_SPACE_FROM_GUAR;
		else
			fd_space = SXE2_FNAV_FD_SPACE_FROM_BEST_EFFORT;

		if (is_tunn)
			filter->tunn_fd_space = fd_space;
		else
			filter->fd_space = fd_space;
	} else {
		fd_space = is_tunn ? filter->tunn_fd_space : filter->fd_space;
	}

	ret = sxe2_fwc_fnav_filter_update(adapter, flow_cfg, filter, is_add,
					  is_tunn);

	mutex_unlock(&adapter->fnav_ctxt.fnav_space_lock);

	return ret;
}

STATIC void sxe2_fnav_get_prgm_desc(struct sxe2_adapter *adapter,
				    struct sxe2_fnav_filter *filter,
				    struct sxe2_tx_fnav_desc *desc, bool is_add,
				    bool is_tunn)
{
	u64 qword;
	u8 space;

	space = is_tunn ? filter->tunn_fd_space : filter->fd_space;

	qword = (((u64)(filter->q_index)) << SXE2_FNAV_TX_DESC_QW0_Q_INDEX_SHIFT) &
		SXE2_FNAV_TX_DESC_QW0_Q_INDEX_MASK;
	qword |= (0ULL << SXE2_FNAV_TX_DESC_QW0_COMP_Q_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW0_COMP_Q_MASK;
	qword |= (SXE2_FNAV_TX_DESC_QW0_COMP_RPT_FAIL
		  << SXE2_FNAV_TX_DESC_QW0_COMP_RPT_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW0_COMP_RPT_MASK;
	qword |= (((u64)(space)) << SXE2_FNAV_TX_DESC_QW0_FD_SPACE_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW0_FD_SPACE_MASK;
	qword |= (((u64)(filter->stat_index))
		  << SXE2_FNAV_TX_DESC_QW0_STAT_CNT_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW0_STAT_CNT_MASK;
	qword |= (SXE2_FNAV_TX_DESC_QW0_STAT_ENA_PKTS
		  << SXE2_FNAV_TX_DESC_QW0_STAT_ENA_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW0_STAT_ENA_MASK;
	qword |= (0ULL << SXE2_FNAV_TX_DESC_QW0_EVICT_ENA_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW0_EVICT_ENA_MASK;
	qword |= (((u64)(filter->q_region)) << SXE2_FNAV_TX_DESC_QW0_TOQ_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW0_TOQ_MASK;
	qword |= (((u64)(filter->act_prio))
		  << SXE2_FNAV_TX_DESC_QW0_TOQ_PRIO_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW0_TOQ_PRIO_MASK;
	qword |= (((u64)(filter->act_type == SXE2_FNAV_ACT_DROP ? 1ULL : 0ULL))
		  << SXE2_FNAV_TX_DESC_QW0_DROP_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW0_DROP_MASK;
	qword |= (((u64)(filter->flow_type))
		  << SXE2_FNAV_TX_DESC_QW0_FLOW_ID_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW0_FLOW_ID_MASK;
	desc->qidx_compq_space_stat = cpu_to_le64(qword);

	qword = (SXE2_TX_DESC_DTYPE_FLTR_PROG << SXE2_FNAV_TX_DESC_QW1_DTYPE_SHIFT) &
		SXE2_FNAV_TX_DESC_QW1_DTYPE_MASK;
	qword |= ((is_add ? SXE2_FNAV_TX_DESC_QW1_PCMD_UPDATE
			  : SXE2_FNAV_TX_DESC_QW1_PCMD_REMOVE)
		  << SXE2_FNAV_TX_DESC_QW1_PCMD_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW1_PCMD_MASK;
	qword |= (((u64)(filter->dst_vsi_hw))
		  << SXE2_FNAV_TX_DESC_QW1_FD_VSI_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW1_FD_VSI_MASK;
	qword |= (0ULL << SXE2_FNAV_TX_DESC_QW1_SWAP_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW1_SWAP_MASK;
	qword |= (((u64)(filter->fdid_prio))
		  << SXE2_FNAV_TX_DESC_QW1_FDID_PRIO_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW1_FDID_PRIO_MASK;
	qword |= (SXE2_FNAV_TX_DESC_QW1_FDID_MDID_FNAV
		  << SXE2_FNAV_TX_DESC_QW1_FDID_MDID_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW1_FDID_MDID_MASK;
	qword |= (((u64)(filter->filter_loc)) << SXE2_FNAV_TX_DESC_QW1_FDID_SHIFT) &
		 SXE2_FNAV_TX_DESC_QW1_FDID_MASK;
	desc->dtype_cmd_vsi_fdid = cpu_to_le64(qword);
}

STATIC void sxe2_pkt_insert_ipv6_addr(u8 *pkt, int offset, __be32 *addr)
{
	int idx;

	for (idx = 0; idx < SXE2_IPV6_ADDR_LEN_TO_U32; idx++)
		memcpy(pkt + offset + idx * sizeof(*addr), &addr[idx],
		       sizeof(*addr));
}

STATIC void sxe2_pkt_insert_u8(u8 *pkt, int offset, u8 data)
{
	memcpy(pkt + offset, &data, sizeof(data));
}

STATIC void sxe2_pkt_insert_u8_tc(u8 *pkt, int offset, u8 data)
{
	u8 high, low;

	high = (data >> 4) + (*(pkt + offset) & 0xF0);
	memcpy(pkt + offset, &high, sizeof(high));

	low = (*(pkt + offset + 1) & 0x0F) + ((data & 0x0F) << 4);
	memcpy(pkt + offset + 1, &low, sizeof(low));
}

STATIC void sxe2_pkt_insert_u16(u8 *pkt, int offset, __be16 data)
{
	memcpy(pkt + offset, &data, sizeof(data));
}

STATIC void sxe2_pkt_insert_u32(u8 *pkt, int offset, __be32 data)
{
	memcpy(pkt + offset, &data, sizeof(data));
}

STATIC void sxe2_pkt_insert_mac_addr(u8 *pkt, u8 *addr)
{
	ether_addr_copy(pkt, addr);
}

STATIC enum sxe2_fnav_flow_type
sxe2_flow_type_translate_type(struct sxe2_fnav_filter *filter)
{
	enum sxe2_fnav_flow_type flow;

	if (filter->flow_type == SXE2_FNAV_FLOW_TYPE_IPV4_OTHER) {
		switch (filter->full_key.ip.v4.proto) {
		case IPPROTO_TCP:
			flow = SXE2_FNAV_FLOW_TYPE_IPV4_TCP;
			break;
		case IPPROTO_UDP:
			flow = SXE2_FNAV_FLOW_TYPE_IPV4_UDP;
			break;
		case IPPROTO_SCTP:
			flow = SXE2_FNAV_FLOW_TYPE_IPV4_SCTP;
			break;
		default:
			flow = SXE2_FNAV_FLOW_TYPE_IPV4_OTHER;
			break;
		}
	} else if (filter->flow_type == SXE2_FNAV_FLOW_TYPE_IPV6_OTHER) {
		switch (filter->full_key.ip.v6.proto) {
		case IPPROTO_TCP:
			flow = SXE2_FNAV_FLOW_TYPE_IPV6_TCP;
			break;
		case IPPROTO_UDP:
			flow = SXE2_FNAV_FLOW_TYPE_IPV6_UDP;
			break;
		case IPPROTO_SCTP:
			flow = SXE2_FNAV_FLOW_TYPE_IPV6_SCTP;
			break;
		default:
			flow = SXE2_FNAV_FLOW_TYPE_IPV6_OTHER;
			break;
		}
	} else if (filter->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_TCP) {
		flow = SXE2_FNAV_FLOW_TYPE_IPV4_TCP;
	} else if (filter->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_UDP) {
		flow = SXE2_FNAV_FLOW_TYPE_IPV4_UDP;
	} else if (filter->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_TCP) {
		flow = SXE2_FNAV_FLOW_TYPE_IPV6_TCP;
	} else if (filter->flow_type == SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_UDP) {
		flow = SXE2_FNAV_FLOW_TYPE_IPV6_UDP;
	} else {
		flow = filter->flow_type;
	}
	return flow;
}

STATIC void sxe2_pkt_insert_by_flow_eth(struct sxe2_fnav_filter *filter, bool frag,
					u8 *loc)
{
	sxe2_pkt_insert_mac_addr(loc, filter->full_key.eth.h_dest);
	sxe2_pkt_insert_mac_addr(loc + ETH_ALEN, filter->full_key.eth.h_source);
	if (filter->full_key.ext_data.s_vlan_tci ||
	    filter->full_key.ext_data.vlan_type) {
		sxe2_pkt_insert_u16(loc, SXE2_ETH_TYPE_F_OFFSET,
				    filter->full_key.ext_data.vlan_type);
		sxe2_pkt_insert_u16(loc, SXE2_ETH_VLAN_TCI_OFFSET,
				    filter->full_key.ext_data.s_vlan_tci);
		sxe2_pkt_insert_u16(loc, SXE2_ETH_TYPE_VLAN_OFFSET,
				    filter->full_key.eth.h_proto);
	} else {
		sxe2_pkt_insert_u16(loc, SXE2_ETH_TYPE_F_OFFSET,
				    filter->full_key.eth.h_proto);
	}
}

STATIC void sxe2_pkt_insert_by_flow_ipv4_tcp(struct sxe2_fnav_filter *filter,
					     bool frag, u8 *loc)
{
	sxe2_pkt_insert_u32(loc, SXE2_IPV4_SRC_ADDR_OFFSET,
			    filter->full_key.ip.v4.src_ip);
	sxe2_pkt_insert_u16(loc, SXE2_IPV4_TCP_SRC_PORT_OFFSET,
			    filter->full_key.l4.src_port);
	sxe2_pkt_insert_u32(loc, SXE2_IPV4_DST_ADDR_OFFSET,
			    filter->full_key.ip.v4.dst_ip);
	sxe2_pkt_insert_u16(loc, SXE2_IPV4_TCP_DST_PORT_OFFSET,
			    filter->full_key.l4.dst_port);
	sxe2_pkt_insert_u8(loc, SXE2_IPV4_TOS_OFFSET, filter->full_key.ip.v4.tos);
	if (filter->full_key.ip.v4.ttl) {
		sxe2_pkt_insert_u8(loc, SXE2_IPV4_TTL_OFFSET,
				   filter->full_key.ip.v4.ttl);
	} else {
		sxe2_pkt_insert_u8(loc, SXE2_IPV4_TTL_OFFSET, SXE2_U8_MASK);
	}
	sxe2_pkt_insert_mac_addr(loc, filter->full_key.ext_data.dst_mac);
	if (frag)
		loc[SXE2_FNAV_IPV4_PKT_FLAG_MF_OFFSET] = SXE2_FNAV_IPV4_PKT_FLAG_MF;
}

STATIC void sxe2_pkt_insert_by_flow_ipv4_udp(struct sxe2_fnav_filter *filter,
					     bool frag, u8 *loc)
{
	sxe2_pkt_insert_u32(loc, SXE2_IPV4_SRC_ADDR_OFFSET,
			    filter->full_key.ip.v4.src_ip);
	sxe2_pkt_insert_u16(loc, SXE2_IPV4_UDP_SRC_PORT_OFFSET,
			    filter->full_key.l4.src_port);
	sxe2_pkt_insert_u32(loc, SXE2_IPV4_DST_ADDR_OFFSET,
			    filter->full_key.ip.v4.dst_ip);
	sxe2_pkt_insert_u16(loc, SXE2_IPV4_UDP_DST_PORT_OFFSET,
			    filter->full_key.l4.dst_port);
	sxe2_pkt_insert_u8(loc, SXE2_IPV4_TOS_OFFSET, filter->full_key.ip.v4.tos);
	if (filter->full_key.ip.v4.ttl) {
		sxe2_pkt_insert_u8(loc, SXE2_IPV4_TTL_OFFSET,
				   filter->full_key.ip.v4.ttl);
	} else {
		sxe2_pkt_insert_u8(loc, SXE2_IPV4_TTL_OFFSET, SXE2_U8_MASK);
	}
	sxe2_pkt_insert_mac_addr(loc, filter->full_key.ext_data.dst_mac);
	sxe2_pkt_insert_mac_addr(loc + ETH_ALEN, filter->full_key.ext_data.src_mac);
}

STATIC void sxe2_pkt_insert_by_flow_ipv4_sctp(struct sxe2_fnav_filter *filter,
					      bool frag, u8 *loc)
{
	sxe2_pkt_insert_u32(loc, SXE2_IPV4_SRC_ADDR_OFFSET,
			    filter->full_key.ip.v4.src_ip);
	sxe2_pkt_insert_u16(loc, SXE2_IPV4_SCTP_SRC_PORT_OFFSET,
			    filter->full_key.l4.src_port);
	sxe2_pkt_insert_u32(loc, SXE2_IPV4_DST_ADDR_OFFSET,
			    filter->full_key.ip.v4.dst_ip);
	sxe2_pkt_insert_u16(loc, SXE2_IPV4_SCTP_DST_PORT_OFFSET,
			    filter->full_key.l4.dst_port);
	sxe2_pkt_insert_u8(loc, SXE2_IPV4_TOS_OFFSET, filter->full_key.ip.v4.tos);
	if (filter->full_key.ip.v4.ttl) {
		sxe2_pkt_insert_u8(loc, SXE2_IPV4_TTL_OFFSET,
				   filter->full_key.ip.v4.ttl);
	} else {
		sxe2_pkt_insert_u8(loc, SXE2_IPV4_TTL_OFFSET, SXE2_U8_MASK);
	}
	sxe2_pkt_insert_mac_addr(loc, filter->full_key.ext_data.dst_mac);
}

STATIC void sxe2_pkt_insert_by_flow_ipv4_other(struct sxe2_fnav_filter *filter,
					       bool frag, u8 *loc)
{
	sxe2_pkt_insert_u32(loc, SXE2_IPV4_SRC_ADDR_OFFSET,
			    filter->full_key.ip.v4.src_ip);
	sxe2_pkt_insert_u32(loc, SXE2_IPV4_DST_ADDR_OFFSET,
			    filter->full_key.ip.v4.dst_ip);
	sxe2_pkt_insert_u8(loc, SXE2_IPV4_TOS_OFFSET, filter->full_key.ip.v4.tos);
	if (filter->full_key.ip.v4.ttl) {
		sxe2_pkt_insert_u8(loc, SXE2_IPV4_TTL_OFFSET,
				   filter->full_key.ip.v4.ttl);
	} else {
		sxe2_pkt_insert_u8(loc, SXE2_IPV4_TTL_OFFSET, SXE2_U8_MASK);
	}
	sxe2_pkt_insert_u8(loc, SXE2_IPV4_PROTO_OFFSET,
			   filter->full_key.ip.v4.proto);
	sxe2_pkt_insert_mac_addr(loc, filter->full_key.ext_data.dst_mac);
}

STATIC void sxe2_pkt_insert_by_flow_ipv6_tcp(struct sxe2_fnav_filter *filter,
					     bool frag, u8 *loc)
{
	sxe2_pkt_insert_ipv6_addr(loc, SXE2_IPV6_SRC_ADDR_OFFSET,
				  filter->full_key.ip.v6.src_ip);
	sxe2_pkt_insert_ipv6_addr(loc, SXE2_IPV6_DST_ADDR_OFFSET,
				  filter->full_key.ip.v6.dst_ip);
	sxe2_pkt_insert_u16(loc, SXE2_IPV6_TCP_SRC_PORT_OFFSET,
			    filter->full_key.l4.src_port);
	sxe2_pkt_insert_u16(loc, SXE2_IPV6_TCP_DST_PORT_OFFSET,
			    filter->full_key.l4.dst_port);
	sxe2_pkt_insert_u8_tc(loc, SXE2_IPV6_TC_OFFSET, filter->full_key.ip.v6.tc);
	if (filter->full_key.ip.v6.hlim) {
		sxe2_pkt_insert_u8(loc, SXE2_IPV6_HLIM_OFFSET,
				   filter->full_key.ip.v6.hlim);
	} else {
		sxe2_pkt_insert_u8(loc, SXE2_IPV6_HLIM_OFFSET, 1);
	}
	sxe2_pkt_insert_mac_addr(loc, filter->full_key.ext_data.dst_mac);
}

STATIC void sxe2_pkt_insert_by_flow_ipv6_udp(struct sxe2_fnav_filter *filter,
					     bool frag, u8 *loc)
{
	sxe2_pkt_insert_ipv6_addr(loc, SXE2_IPV6_SRC_ADDR_OFFSET,
				  filter->full_key.ip.v6.src_ip);
	sxe2_pkt_insert_ipv6_addr(loc, SXE2_IPV6_DST_ADDR_OFFSET,
				  filter->full_key.ip.v6.dst_ip);
	sxe2_pkt_insert_u16(loc, SXE2_IPV6_UDP_SRC_PORT_OFFSET,
			    filter->full_key.l4.src_port);
	sxe2_pkt_insert_u16(loc, SXE2_IPV6_UDP_DST_PORT_OFFSET,
			    filter->full_key.l4.dst_port);
	sxe2_pkt_insert_u8_tc(loc, SXE2_IPV6_TC_OFFSET, filter->full_key.ip.v6.tc);
	if (filter->full_key.ip.v6.hlim) {
		sxe2_pkt_insert_u8(loc, SXE2_IPV6_HLIM_OFFSET,
				   filter->full_key.ip.v6.hlim);
	} else {
		sxe2_pkt_insert_u8(loc, SXE2_IPV6_HLIM_OFFSET, 1);
	}
	sxe2_pkt_insert_mac_addr(loc, filter->full_key.ext_data.dst_mac);
}

STATIC void sxe2_pkt_insert_by_flow_ipv6_sctp(struct sxe2_fnav_filter *filter,
					      bool frag, u8 *loc)
{
	sxe2_pkt_insert_ipv6_addr(loc, SXE2_IPV6_SRC_ADDR_OFFSET,
				  filter->full_key.ip.v6.src_ip);
	sxe2_pkt_insert_ipv6_addr(loc, SXE2_IPV6_DST_ADDR_OFFSET,
				  filter->full_key.ip.v6.dst_ip);
	sxe2_pkt_insert_u16(loc, SXE2_IPV6_SCTP_SRC_PORT_OFFSET,
			    filter->full_key.l4.src_port);
	sxe2_pkt_insert_u16(loc, SXE2_IPV6_SCTP_DST_PORT_OFFSET,
			    filter->full_key.l4.dst_port);
	sxe2_pkt_insert_u8_tc(loc, SXE2_IPV6_TC_OFFSET, filter->full_key.ip.v6.tc);
	if (filter->full_key.ip.v6.hlim) {
		sxe2_pkt_insert_u8(loc, SXE2_IPV6_HLIM_OFFSET,
				   filter->full_key.ip.v6.hlim);
	} else {
		sxe2_pkt_insert_u8(loc, SXE2_IPV6_HLIM_OFFSET, 1);
	}
	sxe2_pkt_insert_mac_addr(loc, filter->full_key.ext_data.dst_mac);
}

STATIC void sxe2_pkt_insert_by_flow_ipv6_other(struct sxe2_fnav_filter *filter,
					       bool frag, u8 *loc)
{
	sxe2_pkt_insert_ipv6_addr(loc, SXE2_IPV6_SRC_ADDR_OFFSET,
				  filter->full_key.ip.v6.src_ip);
	sxe2_pkt_insert_ipv6_addr(loc, SXE2_IPV6_DST_ADDR_OFFSET,
				  filter->full_key.ip.v6.dst_ip);
	sxe2_pkt_insert_u8_tc(loc, SXE2_IPV6_TC_OFFSET, filter->full_key.ip.v6.tc);
	if (filter->full_key.ip.v6.hlim) {
		sxe2_pkt_insert_u8(loc, SXE2_IPV6_HLIM_OFFSET,
				   filter->full_key.ip.v6.hlim);
	} else {
		sxe2_pkt_insert_u8(loc, SXE2_IPV6_HLIM_OFFSET, 1);
	}
	sxe2_pkt_insert_u8(loc, SXE2_IPV6_PROTO_OFFSET,
			   filter->full_key.ip.v6.proto);
	sxe2_pkt_insert_mac_addr(loc, filter->full_key.ext_data.dst_mac);
}

STATIC int sxe2_pkt_insert_by_flow(enum sxe2_fnav_flow_type flow,
				   struct sxe2_fnav_filter *filter, bool frag,
				   u8 *loc)
{
	switch (flow) {
	case SXE2_FNAV_FLOW_TYPE_ETH:
		sxe2_pkt_insert_by_flow_eth(filter, frag, loc);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
		sxe2_pkt_insert_by_flow_ipv4_tcp(filter, frag, loc);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
		sxe2_pkt_insert_by_flow_ipv4_udp(filter, frag, loc);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_SCTP:
		sxe2_pkt_insert_by_flow_ipv4_sctp(filter, frag, loc);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_OTHER:
		sxe2_pkt_insert_by_flow_ipv4_other(filter, frag, loc);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
		sxe2_pkt_insert_by_flow_ipv6_tcp(filter, frag, loc);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
		sxe2_pkt_insert_by_flow_ipv6_udp(filter, frag, loc);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_SCTP:
		sxe2_pkt_insert_by_flow_ipv6_sctp(filter, frag, loc);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_OTHER:
		sxe2_pkt_insert_by_flow_ipv6_other(filter, frag, loc);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

s32 sxe2_fnav_gen_prgm_pkt(struct sxe2_adapter *adapter,
			   struct sxe2_fnav_filter *filter, u8 *pkt, bool frag,
			   bool tun)
{
	enum sxe2_fnav_flow_type flow;
	u8 *loc_inner = NULL;
	u8 *loc;
	u16 idx;
	u32 tunn_outer_len;
	s32 ret;

	flow = sxe2_flow_type_translate_type(filter);
	for (idx = 0; idx < SXE2_FNAV_PKT_NUM; idx++) {
		if (sxe2_fnav_pkt[idx].flow_type == flow)
			break;
	}
	if (idx == SXE2_FNAV_PKT_NUM)
		return -EINVAL;

	if (!tun) {
		switch (flow) {
		default:
			memcpy(pkt, sxe2_fnav_pkt[idx].pkt,
			       sxe2_fnav_pkt[idx].pkt_len);
			break;
		}
		loc = pkt;
	} else {
		if (!sxe2_fnav_pkt[idx].tun_pkt)
			return -EINVAL;
		switch (flow) {
		case SXE2_FNAV_FLOW_TYPE_IPV4_OTHER:
		case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
		case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
		case SXE2_FNAV_FLOW_TYPE_IPV4_SCTP:
		case SXE2_FNAV_FLOW_TYPE_ETH:
			tunn_outer_len = sizeof(sxe2_fnav_udp4_vxlan_pkt);
			memcpy(pkt, sxe2_fnav_udp4_vxlan_pkt, tunn_outer_len);
			loc_inner = &pkt[tunn_outer_len];
			memcpy(loc_inner, sxe2_fnav_pkt[idx].pkt,
			       sxe2_fnav_pkt[idx].pkt_len);
			sxe2_pkt_insert_u16(pkt,
					    SXE2_IPV4_OUTER_LEN_OFFSET,
					    cpu_to_be16((u16)(tunn_outer_len +
							      sxe2_fnav_pkt[idx].pkt_len -
							      SXE2_FNAV_ETH_LEN)));
			sxe2_pkt_insert_u16(pkt,
					    SXE2_IPV4_UDP_LEN_OFFSET,
					    cpu_to_be16((u16)(sxe2_fnav_pkt[idx].pkt_len +
					    SXE2_FNAV_VXLAN_UDP_LEN)));
			sxe2_pkt_insert_u16(pkt,
					    SXE2_IPV4_UDP_DST_PORT_OFFSET,
					    cpu_to_be16((u16)(SXE2_VXLAN_UDP_DST_PORT)));
			loc = loc_inner;
			break;
		case SXE2_FNAV_FLOW_TYPE_IPV6_OTHER:
		case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
		case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
		case SXE2_FNAV_FLOW_TYPE_IPV6_SCTP:
			tunn_outer_len = sizeof(sxe2_fnav_ipv6_gre_tun_pkt);
			memcpy(pkt, sxe2_fnav_ipv6_gre_tun_pkt, tunn_outer_len);
			loc_inner = &pkt[tunn_outer_len];
			memcpy(loc_inner, sxe2_fnav_pkt[idx].pkt,
			       sxe2_fnav_pkt[idx].pkt_len);
			sxe2_pkt_insert_u16(pkt, SXE2_IPV4_OUTER_LEN_OFFSET,
					    cpu_to_be16(sxe2_fnav_pkt[idx].pkt_len +
							SXE2_FNAV_GRE_HEADER_LEN));
			loc = loc_inner;
			break;

		default:
			return -EINVAL;
		}
	}

	ret = sxe2_pkt_insert_by_flow(flow, filter, frag, loc);
	if (ret)
		return ret;

	if (filter->full_key.has_flex_filed) {
		loc = pkt;
		sxe2_pkt_insert_u16(loc, filter->full_key.flex_offset,
				    filter->full_key.flex_word);
	}

	return 0;
}

STATIC s32 sxe2_fnav_packet_xmit(struct sxe2_adapter *adapter,
				 struct sxe2_fnav_filter *filter, bool is_add,
				 bool tun)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_tx_fnav_desc desc;
	struct sxe2_vsi *ctrl_vsi;
	u8 *pkt;
	s32 ret;

	ctrl_vsi = adapter->vsi_ctxt.ctrl_vsi;
	if (!ctrl_vsi)
		return -EINVAL;

	pkt = devm_kzalloc(dev, SXE2_FNAV_MAX_RAW_PKT_SIZE, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

	sxe2_fnav_get_prgm_desc(adapter, filter, &desc, is_add, tun);
	ret = sxe2_fnav_gen_prgm_pkt(adapter, filter, pkt, false, tun);
	if (ret)
		goto l_free;

	ret = sxe2_prgm_fnav_fltr(ctrl_vsi, &desc, pkt);
	if (ret)
		goto l_free;

	return 0;

l_free:
	devm_kfree(dev, pkt);
	return ret;
}

s32 sxe2_fnav_hw_filter_update_with_pkt(struct sxe2_vsi *vsi,
					struct sxe2_fnav_filter *filter, bool is_add,
					bool is_update, bool is_tunn)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	s32 ret = 0;
	u8 fd_space;

	mutex_lock(&adapter->fnav_ctxt.fnav_space_lock);

	if (is_add && !is_update) {
		if (adapter->fnav_ctxt.space_gcnt < vsi->fnav.space_gsize)
			fd_space = SXE2_FNAV_FD_SPACE_FROM_GUAR;
		else
			fd_space = SXE2_FNAV_FD_SPACE_FROM_BEST_EFFORT;

		if (is_tunn)
			filter->tunn_fd_space = fd_space;
		else
			filter->fd_space = fd_space;
	} else {
		fd_space = is_tunn ? filter->tunn_fd_space : filter->fd_space;
	}

	ret = sxe2_fnav_packet_xmit(adapter, filter, is_add, is_tunn);
	if (ret == 0 && !is_update) {
		if (is_add) {
			if (fd_space == SXE2_FNAV_FD_SPACE_FROM_GUAR)
				adapter->fnav_ctxt.space_gcnt++;
			else
				adapter->fnav_ctxt.space_bcnt++;
		} else {
			if (fd_space == SXE2_FNAV_FD_SPACE_FROM_GUAR)
				adapter->fnav_ctxt.space_gcnt--;
			else
				adapter->fnav_ctxt.space_bcnt--;
		}
	}

	mutex_unlock(&adapter->fnav_ctxt.fnav_space_lock);

	return ret;
}

STATIC s32 sxe2_fnav_flow_update_after_filter_del(struct sxe2_vsi *vsi,
						  struct sxe2_fnav_flow_cfg *flow_cfg)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	s32 ret = 0;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	if (flow_cfg->filter_cnt[SXE2_FNAV_SEG_TUN] == 0) {
		ret = sxe2_fnav_flow_cfg_del(adapter, flow_cfg, true);
		if (ret) {
			LOG_WARN_BDF("delete hw filter failed, ret:%d\n", ret);
			goto l_end;
		}
	}

	if (vsi->id_in_pf == adapter->arfs_ctxt.vsi_id_in_pf &&
	    flow_cfg->filter_cnt[SXE2_FNAV_SEG_TUN] == 0 &&
	    flow_cfg->filter_cnt[SXE2_FNAV_SEG_NON_TUN] == 0) {
		(void)sxe2_fnav_default_flow_recovery_by_type(vsi, flow_cfg);

	} else if (flow_cfg->filter_cnt[SXE2_FNAV_SEG_NON_TUN] == 0) {
		ret = sxe2_fnav_flow_cfg_del(adapter, flow_cfg, false);
		if (ret) {
			LOG_WARN_BDF("delete hw filter failed, ret:%d\n", ret);
			goto l_end;
		}
	}

	if (!flow_cfg->full_match &&
	    flow_cfg->filter_cnt[SXE2_FNAV_SEG_TUN] == 0 &&
	    flow_cfg->filter_cnt[SXE2_FNAV_SEG_NON_TUN] == 0) {
		list_del(&flow_cfg->l_node);
		devm_kfree(dev, flow_cfg);
	}

l_end:
	return ret;
}

STATIC s32 sxe2_fnav_action_to_vf_all_filter_del(struct sxe2_vsi *vsi,
						 struct sxe2_vf_node *vf_node)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = NULL;
	struct sxe2_fnav_filter *filter, *tmp;
	u16 i = 0;
	u16 vf_vsi_id;

	if (!vsi)
		return ret;

	adapter = vsi->adapter;
	for (i = 0; i < SXE2_VF_TYPE_NR; i++) {
		vf_vsi_id = vf_node->vsi_id[i];
		mutex_lock(&adapter->fnav_ctxt.filter_lock);
		list_for_each_entry_safe(filter, tmp, &vsi->fnav.filter_list, l_node) {
			if (filter->ori_vsi_hw != filter->dst_vsi_hw &&
			    filter->dst_vsi_hw == vf_vsi_id) {
				ret = sxe2_fnav_filter_del(vsi, filter);
				if (ret) {
					LOG_ERROR_BDF("sxe2 fnav delete filter\t"
						      "failed, ori_vsi_id=%u,\t"
						      "dst_vsi_hw=%u, ret:%d\n",
						      filter->ori_vsi_hw,
						      filter->dst_vsi_hw, ret);
				}
			}
		}
		mutex_unlock(&adapter->fnav_ctxt.filter_lock);
	}
	return ret;
}

s32 sxe2_fwc_fnav_hw_clear(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FNAV_HW_CLEAR, NULL, 0, NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("clear fnav hw filter failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_fnav_switch(struct sxe2_adapter *adapter, bool is_enable)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi = NULL;

	if (sxe2_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return 0;

	vsi = adapter->vsi_ctxt.main_vsi;
	mutex_lock(&adapter->fnav_ctxt.fnav_state_lock);
	if (adapter->fnav_ctxt.state != SXE2_FNAV_STATE_READY) {
		ret = -EBUSY;
		goto l_end;
	}

	if (is_enable) {
		if (!test_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags)) {
			(void)sxe2_fnav_default_flow_set(adapter);
			(void)sxe2_arfs_enable(adapter);
			set_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags);
		}
		goto l_end;
	}

	if (!test_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags))
		goto l_end;

	ret = sxe2_fnav_del_filter_by_vsi(vsi);
	if (ret) {
		LOG_ERROR_BDF("delete all filter failed, ret:%d", ret);
		goto l_end;
	}

	sxe2_arfs_disable(adapter);

	ret = sxe2_pf_fnav_flow_cfg_clear(adapter);
	if (ret) {
		LOG_ERROR_BDF("clear flow cfg failed, ret:%d", ret);
		goto l_end;
	}

	clear_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags);

l_end:
	mutex_unlock(&adapter->fnav_ctxt.fnav_state_lock);
	return ret;
}

u32 sxe2_fnav_max_filter_cnt_get_by_vsi(struct sxe2_vsi *vsi)
{
	return vsi->fnav.space_gsize + vsi->fnav.space_bsize;
}

struct sxe2_fnav_filter *
sxe2_fnav_find_filter_by_loc_unlock(struct sxe2_vsi_fnav *vsi_fnav, u32 loc)
{
	struct sxe2_fnav_filter *filter_tmp = NULL;
	struct sxe2_fnav_filter *filter_find = NULL;

	list_for_each_entry(filter_tmp, &vsi_fnav->filter_list, l_node) {
		if (loc == filter_tmp->filter_loc) {
			filter_find = filter_tmp;
			break;
		}
		if (loc < filter_tmp->filter_loc)
			break;
	}

	return filter_find;
}

struct sxe2_fnav_filter *sxe2_fnav_find_filter_by_loc_lock(struct sxe2_vsi *vsi,
							   u32 loc)
{
	struct sxe2_fnav_filter *filter_tmp = NULL;
	struct sxe2_fnav_filter *filter_find = NULL;
	struct sxe2_adapter *adapter = vsi->adapter;

	mutex_lock(&adapter->fnav_ctxt.filter_lock);
	list_for_each_entry(filter_tmp, &vsi->fnav.filter_list, l_node) {
		if (loc == filter_tmp->filter_loc) {
			filter_find = filter_tmp;
			break;
		}
		if (loc < filter_tmp->filter_loc)
			break;
	}
	mutex_unlock(&adapter->fnav_ctxt.filter_lock);

	return filter_find;
}

STATIC bool sxe2_fnav_filter_cmp(struct sxe2_fnav_filter *fltr_a,
				 struct sxe2_fnav_filter *fltr_b)
{
	if (fltr_a->flow_type != fltr_b->flow_type)
		return false;

	if (!(fltr_a->full_key.has_flex_filed == fltr_b->full_key.has_flex_filed &&
	      fltr_a->full_key.flex_offset == fltr_b->full_key.flex_offset &&
	      fltr_a->full_key.flex_word == fltr_b->full_key.flex_word))
		return false;

	if (memcmp(&fltr_a->full_key.eth, &fltr_b->full_key.eth,
		   sizeof(fltr_a->full_key.eth)))
		return false;
	if (memcmp(&fltr_a->full_key.eth_inner, &fltr_b->full_key.eth_inner,
		   sizeof(fltr_a->full_key.eth_inner)))
		return false;
	if (memcmp(&fltr_a->full_key.ip, &fltr_b->full_key.ip,
		   sizeof(fltr_a->full_key.ip)))
		return false;
	if (memcmp(&fltr_a->full_key.ip_inner, &fltr_b->full_key.ip_inner,
		   sizeof(fltr_a->full_key.ip_inner)))
		return false;
	if (memcmp(&fltr_a->full_key.l4, &fltr_b->full_key.l4,
		   sizeof(fltr_a->full_key.l4)))
		return false;
	if (memcmp(&fltr_a->full_key.l4_inner, &fltr_b->full_key.l4_inner,
		   sizeof(fltr_a->full_key.l4_inner)))
		return false;
	if (memcmp(&fltr_a->full_key.ext_data, &fltr_b->full_key.ext_data,
		   sizeof(fltr_a->full_key.ext_data)))
		return false;
	if (memcmp(&fltr_a->full_key.ext_data_inner, &fltr_b->full_key.ext_data_inner,
		   sizeof(fltr_a->full_key.ext_data_inner)))
		return false;
	if (memcmp(&fltr_a->full_key.tunnel_data, &fltr_b->full_key.tunnel_data,
		   sizeof(fltr_a->full_key.tunnel_data)))
		return false;

	return true;
}

bool sxe2_fnav_filter_cmp_with_flow_type(struct sxe2_fnav_filter *fltr_a,
					 struct sxe2_fnav_filter *fltr_b)
{
	enum sxe2_fnav_flow_type flow_type = fltr_a->flow_type;

	if (fltr_a->flow_type != fltr_b->flow_type)
		return false;

	if (!(fltr_a->full_key.has_flex_filed == fltr_b->full_key.has_flex_filed &&
	      fltr_a->full_key.flex_offset == fltr_b->full_key.flex_offset &&
	      fltr_a->full_key.flex_word == fltr_b->full_key.flex_word))
		return false;

	switch (flow_type) {
	case SXE2_FNAV_FLOW_TYPE_ETH:
		if (fltr_a->full_key.ext_data.vlan_type ==
				    fltr_b->full_key.ext_data.vlan_type &&
		    fltr_a->full_key.ext_data.s_vlan_tci ==
				    fltr_b->full_key.ext_data.s_vlan_tci &&
		    !memcmp(&fltr_a->full_key.eth, &fltr_b->full_key.eth,
			    sizeof(fltr_a->full_key.eth)))
			return true;
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
	case SXE2_FNAV_FLOW_TYPE_IPV4_SCTP:
		if (fltr_a->full_key.l4.dst_port == fltr_b->full_key.l4.dst_port &&
		    fltr_a->full_key.l4.src_port == fltr_b->full_key.l4.src_port &&
		    fltr_a->full_key.ip.v4.dst_ip == fltr_b->full_key.ip.v4.dst_ip &&
		    fltr_a->full_key.ip.v4.src_ip == fltr_b->full_key.ip.v4.src_ip &&
		    fltr_a->full_key.ip.v4.tos == fltr_b->full_key.ip.v4.tos)
			return true;
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_OTHER:
		if (fltr_a->full_key.ip.v4.dst_ip == fltr_b->full_key.ip.v4.dst_ip &&
		    fltr_a->full_key.ip.v4.src_ip == fltr_b->full_key.ip.v4.src_ip &&
		    fltr_a->full_key.ip.v4.proto == fltr_b->full_key.ip.v4.proto &&
		    fltr_a->full_key.ip.v4.tos == fltr_b->full_key.ip.v4.tos)
			return true;
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
	case SXE2_FNAV_FLOW_TYPE_IPV6_SCTP:
		if (fltr_a->full_key.l4.dst_port == fltr_b->full_key.l4.dst_port &&
		    fltr_a->full_key.l4.src_port == fltr_b->full_key.l4.src_port &&
		    !memcmp(fltr_a->full_key.ip.v6.dst_ip,
			    fltr_b->full_key.ip.v6.dst_ip,
			    sizeof(fltr_a->full_key.ip.v6.dst_ip)) &&
		    !memcmp(fltr_a->full_key.ip.v6.src_ip,
			    fltr_b->full_key.ip.v6.src_ip,
			    sizeof(fltr_a->full_key.ip.v6.src_ip)) &&
		    fltr_a->full_key.ip.v6.tc == fltr_b->full_key.ip.v6.tc)
			return true;
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_OTHER:
		if (!memcmp(fltr_a->full_key.ip.v6.dst_ip,
			    fltr_b->full_key.ip.v6.dst_ip,
			    sizeof(fltr_a->full_key.ip.v6.dst_ip)) &&
		    !memcmp(fltr_a->full_key.ip.v6.src_ip,
			    fltr_b->full_key.ip.v6.src_ip,
			    sizeof(fltr_a->full_key.ip.v6.src_ip)) &&
		    fltr_a->full_key.ip.v6.tc == fltr_b->full_key.ip.v6.tc &&
		    fltr_a->full_key.ip.v6.proto == fltr_b->full_key.ip.v6.proto)
			return true;
		break;
	default:
		break;
	}
	return false;
}

STATIC bool sxe2_fnav_support_full_match(enum sxe2_fnav_flow_type flow_type)
{
	if ((flow_type == SXE2_FNAV_FLOW_TYPE_IPV4_TCP ||
	     flow_type == SXE2_FNAV_FLOW_TYPE_IPV4_UDP ||
	     flow_type == SXE2_FNAV_FLOW_TYPE_IPV6_TCP ||
	     flow_type == SXE2_FNAV_FLOW_TYPE_IPV6_UDP)) {
		return true;
	}

	return false;
}

bool sxe2_fnav_flow_cfg_full_match(struct sxe2_adapter *adapter,
				   enum sxe2_fnav_flow_type flow_type)
{
	struct sxe2_fnav_flow_cfg *flow_cfg = NULL;
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;

	if (!vsi)
		return false;

	flow_cfg = sxe2_fnav_find_flow_cfg_by_flow_type(vsi, flow_type);
	if (!flow_cfg)
		return false;

	return flow_cfg->full_match;
}

s32 sxe2_fnav_default_flow_recovery_by_type(struct sxe2_vsi *vsi,
					    struct sxe2_fnav_flow_cfg *flow_cfg)
{
	s32 ret = 0;
	enum sxe2_fnav_flow_type flow_type = flow_cfg->flow_type;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (sxe2_fnav_support_full_match(flow_type) && flow_cfg->full_match &&
	    test_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags)) {
		goto l_end;
	}

	ret = sxe2_fnav_flow_cfg_del(adapter, flow_cfg, false);
	if (ret) {
		LOG_ERROR_BDF("delete outer flow_cfg[%d] failed, ret:%d.\n",
			      flow_type, ret);
		goto l_end;
	}

	if (sxe2_fnav_support_full_match(flow_type) &&
	    test_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags)) {
		ret = sxe2_fnav_default_flow_set_by_type(vsi, flow_type);
		if (ret) {
			LOG_WARN_BDF("flow_cfg[%d] full match set failed, ret:%d\n",
				     flow_type, ret);
		}
	}

l_end:
	return ret;
}

s32 sxe2_fnav_del_filter_by_loc(struct sxe2_vsi *vsi, u32 loc)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	s32 ret = -ENOENT;
	struct sxe2_fnav_filter *filter;

	mutex_lock(&adapter->fnav_ctxt.filter_lock);
	filter = sxe2_fnav_find_filter_by_loc_unlock(&vsi->fnav, loc);
	if (filter) {
		ret = sxe2_fnav_filter_del(vsi, filter);
		if (ret)
			LOG_ERROR_BDF("sxe2 fnav delete filter failed, loc=%d, ret:%d\n",
				      loc, ret);
	}

	mutex_unlock(&adapter->fnav_ctxt.filter_lock);
	return ret;
}

static s32 sxe2_fnav_flow_replay(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	s32 ret = 0;
	u32 j;
	struct sxe2_fnav_flow_seg *seg;
	struct sxe2_fnav_flow_cfg *flow_tmp = NULL;

	mutex_lock(&vsi->fnav.flow_cfg_lock);

	list_for_each_entry(flow_tmp, &vsi->fnav.flow_cfg_list, l_node) {
		for (j = 0; j < SXE2_FNAV_SEG_MAX; j++) {
			seg = flow_tmp->seg[j];
			if (seg) {
				ret = sxe2_fnav_flow_cfg_replay(adapter, seg);
				if (ret) {
					LOG_ERROR_BDF("flow cfg replay failed,\t"
						      "flow_type:%u, level:%u\n",
						      flow_tmp->flow_type, j);
					goto l_end;
				}
			}
		}
	}

l_end:
	mutex_unlock(&vsi->fnav.flow_cfg_lock);
	return ret;
}

s32 sxe2_fnav_filter_replay(struct sxe2_vsi *vsi, bool to_vf)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	s32 ret = 0;
	struct sxe2_fnav_filter *filter = NULL;

	mutex_lock(&adapter->fnav_ctxt.filter_lock);
	list_for_each_entry(filter, &vsi->fnav.filter_list, l_node) {
		if ((to_vf && filter->ori_vsi_hw == filter->dst_vsi_hw) ||
		    (!to_vf && filter->ori_vsi_hw != filter->dst_vsi_hw)) {
			continue;
		}

		ret = sxe2_pf_fnav_hw_filter_update(vsi, filter, true, false,
						    SXE2_FNAV_FILTER_UPDATE_ADMIN);
		if (ret) {
			LOG_ERROR_BDF("add hw filter failed, ret:%d\n", ret);
			goto l_unlock;
		}
	}

l_unlock:
	mutex_unlock(&adapter->fnav_ctxt.filter_lock);
	return ret;
}

s32 sxe2_fnav_rule_reply(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;
	s32 ret = 0;

	if (!vsi)
		return 0;

	ret = sxe2_fnav_flow_replay(vsi);
	if (ret) {
		LOG_DEV_ERR("fnav flow replay failed, ret: %d\n", ret);
		goto l_end;
	}

	(void)sxe2_fnav_default_flow_set(adapter);

	ret = sxe2_fnav_filter_replay(vsi, false);
	if (ret)
		LOG_DEV_ERR("fnav filter replay failed, ret: %d\n", ret);

l_end:
	return ret;
}

void sxe2_fwc_fnav_trace_trigger(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FNAV_TRACE_TRIGGER, NULL, 0, NULL,
				  0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("fnav trace trigger cmd fail, ret=%d\n", ret);
}

STATIC void
sxe2_fnav_recorder1_hit_info_first(struct sxe2_adapter *adapter,
				   struct sxe2_fnav_hit_info *hit_info,
				   struct sxe2_fnav_addition_info *addition_info)
{
	int i;
	u32 tmp[10] = {0};
	u32 inputset[16] = {0};

	LOG_DEV_INFO("fd trace1 hit info : \r\n");
	LOG_DEV_INFO("entry_vld = 0x%x\r\n", hit_info->entry_vld);

	LOG_DEV_INFO("hit_flg   = 0x%x\r\n", hit_info->hit_flg);
	LOG_DEV_INFO("ck1       = 0x%x\r\n", hit_info->ck1);
	LOG_DEV_INFO("ht_index1 = 0x%x\r\n", hit_info->ht_index1);

	tmp[0] = (u32)(hit_info->ck2_3_0 | (hit_info->ck2_12_4 << 4));
	LOG_DEV_INFO("ck2       = 0x%x\r\n", tmp[0]);
	LOG_DEV_INFO("ht_index2 = 0x%x\r\n", hit_info->ht_index2);
	LOG_DEV_INFO("ht1_avl   = 0x%x\r\n", hit_info->ht1_avl);

	tmp[1] = (u32)(hit_info->ht2_avl_3_0 | (hit_info->ht2_avl_7_4 << 4));
	LOG_DEV_INFO("ht2_avl   = 0x%x\r\n", tmp[1]);
	LOG_DEV_INFO("kt_index  = 0x%x\r\n", hit_info->kt_index);

	LOG_DEV_INFO("qindex    = 0x%x\r\n", hit_info->qindex);

	tmp[2] = (u32)(hit_info->stat_0 | (hit_info->stat_13_1 << 1));
	LOG_DEV_INFO("stat      = 0x%x\r\n", tmp[2]);
	LOG_DEV_INFO("stat_ena  = 0x%x\r\n", hit_info->stat_ena);
	LOG_DEV_INFO("evict_ena = 0x%x\r\n", hit_info->evict_ena);
	LOG_DEV_INFO("to_queue  = 0x%x\r\n", hit_info->toqueue);
	LOG_DEV_INFO("to_queue_prio = 0x%x\r\n", hit_info->toqueue_prio);
	LOG_DEV_INFO("ad_drop   = 0x%x\r\n", hit_info->ad_drop);

	tmp[3] = (u32)(hit_info->fdid_8_0 | (hit_info->fdid_31_9 << 9));
	LOG_DEV_INFO("fdid      = 0x%x\r\n", tmp[3]);
	LOG_DEV_INFO("fdid_prio = 0x%x\r\n", hit_info->fdid_prio);

	tmp[4] = (u32)(hit_info->flow_id_5_0 | (hit_info->flow_id_15_6 << 6));
	LOG_DEV_INFO("flow_id   = 0x%x\r\n", tmp[4]);
	LOG_DEV_INFO("ad_fd_vsi = 0x%x\r\n", hit_info->ad_fd_vsi);
	LOG_DEV_INFO("gl_space  = 0x%x\r\n", hit_info->gl_space);
	LOG_DEV_INFO("pf_space  = 0x%x\r\n", hit_info->pf_space);
	LOG_DEV_INFO("vsi_spcae = 0x%x\r\n", hit_info->vsi_space);

	tmp[5] = (u32)(hit_info->profile_id_4_0 | (hit_info->profile_id_6_5 << 5));
	LOG_DEV_INFO("profile_id   = 0x%x\r\n", tmp[5]);
	LOG_DEV_INFO("vsi          = 0x%x\r\n", hit_info->vsi);

	inputset[0] = (hit_info->inset_26_0 << 5) |
		      ((hit_info->inset_58_27 & 0xf8000000) >> 27);
	inputset[1] = ((hit_info->inset_58_27 & 0x7ffffff) << 5) |
		      ((hit_info->inset_90_59 & 0xf8000000) >> 27);
	inputset[2] = ((hit_info->inset_90_59 & 0x7ffffff) << 5) |
		      ((hit_info->inset_122_91 & 0xf8000000) >> 27);
	inputset[3] = ((hit_info->inset_122_91 & 0x7ffffff) << 5) |
		      ((hit_info->inset_154_123 & 0xf8000000) >> 27);
	inputset[4] = ((hit_info->inset_154_123 & 0x7ffffff) << 5) |
		      ((hit_info->inset_186_155 & 0xf8000000) >> 27);
	inputset[5] = ((hit_info->inset_186_155 & 0x7ffffff) << 5) |
		      ((hit_info->inset_218_187 & 0xf8000000) >> 27);
	inputset[6] = ((hit_info->inset_218_187 & 0x7ffffff) << 5) |
		      ((hit_info->inset_250_219 & 0xf8000000) >> 27);
	inputset[7] = ((hit_info->inset_250_219 & 0x7ffffff) << 5) |
		      ((hit_info->inset_282_251 & 0xf8000000) >> 27);
	inputset[8] = ((hit_info->inset_282_251 & 0x7ffffff) << 5) |
		      ((hit_info->inset_314_283 & 0xf8000000) >> 27);
	inputset[9] = ((hit_info->inset_314_283 & 0x7ffffff) << 5) |
		      ((hit_info->inset_346_315 & 0xf8000000) >> 27);
	inputset[10] = ((hit_info->inset_346_315 & 0x7ffffff) << 5) |
		       ((hit_info->inset_378_347 & 0xf8000000) >> 27);
	inputset[11] = ((hit_info->inset_378_347 & 0x7ffffff) << 5) |
		       ((hit_info->inset_410_379 & 0xf8000000) >> 27);
	inputset[12] = ((hit_info->inset_410_379 & 0x7ffffff) << 5) |
		       ((hit_info->inset_442_411 & 0xf8000000) >> 27);
	inputset[13] = ((hit_info->inset_442_411 & 0x7ffffff) << 5) |
		       ((hit_info->inset_474_443 & 0xf8000000) >> 27);
	inputset[14] = ((hit_info->inset_474_443 & 0x7ffffff) << 5) |
		       ((hit_info->inset_506_475 & 0xf8000000) >> 27);
	inputset[15] = ((hit_info->inset_506_475 & 0x7ffffff) << 5) |
		       hit_info->inset_511_507;

	for (i = 0; i < 16; i++) {
		LOG_DEV_INFO("inputset[%02d] = 0x%04x\r\n", 2 * i,
			     (inputset[i] >> 16) & 0xffff);
		LOG_DEV_INFO("inputset[%02d] = 0x%04x\r\n", 2 * i + 1,
			     inputset[i] & 0xffff);
	}
}

STATIC void
sxe2_fnav_recorder1_hit_info_detail(struct sxe2_adapter *adapter,
				    struct sxe2_fnav_hit_info *hit_info,
				    struct sxe2_fnav_addition_info *addition_info)
{
	u32 tmp[10] = {0};

	switch (hit_info->fail_sts) {
	case 0:
		LOG_DEV_INFO("fail_sts   = 0 : fd hit / edit fd table succ\r\n");
		break;
	case 1:
		LOG_DEV_INFO("fail_sts   = 1 : config not enabled\r\n");
		break;
	case 2:
		LOG_DEV_INFO("fail_sts   = 2 : no global/pf/vsi config space left\r\n");
		break;
	case 3:
		LOG_DEV_INFO("fail_sts   = 3 : FD prog pkt dropped by sw/acl, or\t"
			     "internal serious conflict occurred\r\n");
		break;
	case 4:
		LOG_DEV_INFO("fail_sts   = 4 : entry not exist, delete fail\r\n");
		break;
	case 5:
		LOG_DEV_INFO("fail_sts   = 5 : entry exist, add fail\r\n");
		break;
	case 6:
		LOG_DEV_INFO("fail_sts   = 6 : bucket and fkot both full\r\n");
		break;
	case 7:
		LOG_DEV_INFO("fail_sts   = 7 : rxft bypass\r\n");
		break;
	}

	switch (hit_info->cmd) {
	case 0:
		LOG_DEV_INFO("cmd        = 0 : idle state\r\n");
		break;
	case 1:
		LOG_DEV_INFO("cmd        = 1 : init table\r\n");
		break;
	case 2:
		LOG_DEV_INFO("cmd        = 2 : fd program packet add table\r\n");
		break;
	case 3:
		LOG_DEV_INFO("cmd        = 3 : fd program packet del table\r\n");
		break;
	case 4:
		LOG_DEV_INFO("cmd        = 4 : firmware add table\r\n");
		break;
	case 5:
		LOG_DEV_INFO("cmd        = 5 : firmware del table\r\n");
		break;
	case 6:
		LOG_DEV_INFO("cmd        = 6 : tcp fin/rst del table\r\n");
		break;
	case 7:
		LOG_DEV_INFO("cmd        = 7 : hardware pfr/vmr del table\r\n");
		break;
	case 8:
		LOG_DEV_INFO("cmd        = 8 : firmware pfr/vmr del table\r\n");
		break;
	case 9:
		LOG_DEV_INFO("cmd        = 9 : hardware search table\r\n");
		break;
	case 10:
		LOG_DEV_INFO("cmd        = 10 : firmware search table\r\n");
		break;
	case 11:
		LOG_DEV_INFO("cmd        = 11 : firmware write table(designated address)\r\n");
		break;
	case 12:
		LOG_DEV_INFO("cmd        = 12 : firmware read table\r\n");
		break;
	}
	tmp[6] = (u32)(hit_info->thread_id_5_0 | (hit_info->thread_id_6 << 6));
	LOG_DEV_INFO("thread_id     = 0x%x\r\n", tmp[6]);
	LOG_DEV_INFO("pf            = 0x%x\r\n", hit_info->pf);
	LOG_DEV_INFO("vf_vm         = 0x%x\r\n", hit_info->vf_vm);
	LOG_DEV_INFO("function_type = 0x%x\r\n", hit_info->function_type);
	LOG_DEV_INFO("bypass_ft     = 0x%x\r\n", hit_info->bypass_ft);
	switch (hit_info->pcmd) {
	case 0:
		LOG_DEV_INFO("pcmd          = 0, update table(no matter exist)\r\n");
		break;
	case 1:
		LOG_DEV_INFO("pcmd          = 1, delete table\r\n");
		break;
	case 2:
		LOG_DEV_INFO("pcmd          = 2, add table\r\n");
		break;
	case 3:
		LOG_DEV_INFO("pcmd          = 3, subsitute table(if not exist, will fail)\r\n");
		break;
	}
	LOG_DEV_INFO("comp_report   = 0x%x\r\n", hit_info->comp_report);
	LOG_DEV_INFO("fd_vsi        = 0x%x\r\n", hit_info->fd_vsi);
	LOG_DEV_INFO("comp_queue    = 0x%x\r\n", hit_info->comp_queue);
	LOG_DEV_INFO("not_enabled   = 0x%x\r\n", hit_info->not_enabled);
	LOG_DEV_INFO("bad_profileid = 0x%x\r\n", hit_info->bad_profile_id);
	LOG_DEV_INFO("drop          = 0x%x\r\n", hit_info->drop);
	LOG_DEV_INFO("round_drop    = 0x%x\r\n", hit_info->round_drop);
	LOG_DEV_INFO("round_cnt     = 0x%x\r\n", hit_info->round_cnt);
}

STATIC void
sxe2_fnav_recorder1_additon_info(struct sxe2_adapter *adapter,
				 struct sxe2_fnav_addition_info *addition_info)
{
	LOG_DEV_INFO("fd trace1 addition info : \r\n");
	LOG_DEV_INFO("fd_profile_id     = 0x%x\r\n", addition_info->fd_profile_id);
	if (addition_info->hit_flg & 0x1)
		LOG_DEV_INFO("queue_hit_flag[0] vld , fd default action hit\r\n");
	else if (addition_info->hit_flg & 0x2)
		LOG_DEV_INFO("queue_hit_flag[1] vld , fd kt/fkot hit\r\n");
	else if (addition_info->hit_flg & 0x4)
		LOG_DEV_INFO("queue_hit_flag[2] vld , acl hit\r\n");
	else if (addition_info->hit_flg & 0x8)
		LOG_DEV_INFO("queue_hit_flag[3] vld , sw hit\r\n");
	else
		LOG_DEV_INFO("queue_hit_flag no vld , no fd/sw/acl select\r\n");

	if (addition_info->rlt_sel == 0)
		LOG_DEV_INFO("queue_sel_result = 0x0, queue/queue region non select\r\n");
	else if (addition_info->rlt_sel == 1)
		LOG_DEV_INFO("queue_sel_result = 0x1, queue/queue region from fd\r\n");
	else if (addition_info->rlt_sel == 2)
		LOG_DEV_INFO("queue_sel_result = 0x2, queue/queue region from acl/sw\r\n");

	LOG_DEV_INFO("dst_vsi           = 0x%x\r\n", addition_info->dst_vsi);

	LOG_DEV_INFO("rlt_queue         = 0x%x\r\n",
		     addition_info->rlt_queue_8_0 |
				     (addition_info->rlt_queue_10_9 << 9));
	LOG_DEV_INFO("rlt_toqueue       = 0x%x\r\n", addition_info->rlt_toqueue);
	LOG_DEV_INFO("rlt_toqueue_pri   = 0x%x\r\n", addition_info->rlt_toqueue_pri);
	LOG_DEV_INFO("drop              = 0x%x\r\n", addition_info->drop);
	LOG_DEV_INFO("cmd               = 0x%x\r\n", addition_info->cmd);
	LOG_DEV_INFO("bypass_absq       = 0x%x\r\n", addition_info->bypass_absq);
	LOG_DEV_INFO("fd_search_ena     = 0x%x\r\n", addition_info->fd_search_ena);
	LOG_DEV_INFO("pkt_id            = 0x%x\r\n", addition_info->pkt_id);
	LOG_DEV_INFO("deflt_qindx_pri   = 0x%x\r\n", addition_info->deflt_qindx_pri);
	LOG_DEV_INFO("sa_toqueue_pri    = 0x%x\r\n", addition_info->sa_toqueue_pri);
	LOG_DEV_INFO("search_rss_fs_hit = 0x%x\r\n",
		     addition_info->search_rss_fs_hit);
	LOG_DEV_INFO("bypass_rss        = 0x%x\r\n", addition_info->bypass_rss);
}

STATIC void
sxe2_fnav_recorder1_hit_info(struct sxe2_adapter *adapter,
			     struct sxe2_fnav_hit_info *hit_info,
			     struct sxe2_fnav_addition_info *addition_info)
{
	if (hit_info) {
		sxe2_fnav_recorder1_hit_info_first(adapter, hit_info, addition_info);
		sxe2_fnav_recorder1_hit_info_detail(adapter, hit_info,
						    addition_info);
	}

	if (addition_info)
		sxe2_fnav_recorder1_additon_info(adapter, addition_info);
}

void sxe2_fwc_fnav_trace_recorder(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_fnav_trace_recorder recorder = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FNAV_TRACE_RECORDER, NULL, 0,
				  &recorder,
				  sizeof(struct sxe2_fnav_trace_recorder));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("fnav trace recorder cmd fail, ret=%d\n", ret);
		return;
	}

	LOG_DEV_INFO("****fnav trace recorder start****");
	LOG_DEV_INFO("status0: %u\n", recorder.trace_status0);
	LOG_DEV_INFO("status1: %u\n", recorder.trace_status1);
	if (recorder.trace_status1 == 0) {
		sxe2_fnav_recorder1_hit_info(adapter, &recorder.hit_info,
					     &recorder.addition_info);
	}
	LOG_DEV_INFO("status2: %u\n", recorder.trace_status2);
	LOG_DEV_INFO("****fnav trace recorder end****");
}

void sxe2_fwc_fnav_hw_sts(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_fnav_hit_info hit_info = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FNAV_HW_STS, NULL, 0, &hit_info,
				  sizeof(struct sxe2_fnav_hit_info));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("fnav hw sts cmd fail, ret=%d\n", ret);
		return;
	}

	LOG_DEV_INFO("****fnav hw sts start****");

	sxe2_fnav_recorder1_hit_info(adapter, &hit_info, NULL);

	LOG_DEV_INFO("****fnav hw sts end****");
}

s32 sxe2_fwc_fnav_space_cnt_get(struct sxe2_adapter *adapter, u16 vsi_id,
				u32 *gcnt_global, u32 *bcnt_global, u32 *gcnt_pf,
				u32 *bcnt_pf, u32 *gcnt_vsi, u32 *bcnt_vsi)
{
	s32 ret;
	struct sxe2_fnav_space_cnt space_cnt = {0};
	struct sxe2_cmd_params cmd = {};

	space_cnt.vsi_id = cpu_to_le16(vsi_id);
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FNAV_SPACE_CNT_GET, &space_cnt,
				  sizeof(space_cnt), &space_cnt, sizeof(space_cnt));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("sxe2 fnav get global space cnt failed, ret=%d\n",
			      ret);
		ret = -EIO;
		goto l_end;
	}

	*gcnt_global = le32_to_cpu(space_cnt.gcnt_global);
	*bcnt_global = le32_to_cpu(space_cnt.bcnt_global);
	*gcnt_pf = le32_to_cpu(space_cnt.gcnt_pf);
	*bcnt_pf = le32_to_cpu(space_cnt.bcnt_pf);
	*gcnt_vsi = le32_to_cpu(space_cnt.gcnt_vsi);
	*bcnt_vsi = le32_to_cpu(space_cnt.bcnt_vsi);

l_end:
	return ret;
}

u32 sxe2_fnav_num_avail_filter(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	u32 bcnt_global = 0;
	u32 gcnt_global = 0;
	u32 bcnt_pf = 0;
	u32 gcnt_pf = 0;
	u32 bcnt_vsi = 0;
	u32 gcnt_vsi = 0;
	s32 ret = 0;
	u32 avail_cnt = 0;

	ret = sxe2_fwc_fnav_space_cnt_get(adapter, vsi->idx_in_dev, &gcnt_global,
					  &bcnt_global, &gcnt_pf, &bcnt_pf,
					  &gcnt_vsi, &bcnt_vsi);
	if (ret) {
		LOG_ERROR_BDF("sxe2 fnav get space cnt failed, ret=%d.\n", ret);
		goto l_end;
	}

	adapter->fnav_ctxt.space_bcnt = (u16)bcnt_global;
	adapter->fnav_ctxt.space_gcnt = (u16)gcnt_pf;

	if (vsi->type == SXE2_VSI_T_VF || vsi->type == SXE2_VSI_T_DPDK_VF)
		avail_cnt = vsi->fnav.space_bsize - bcnt_global;
	else
		avail_cnt = vsi->fnav.space_bsize - bcnt_global +
			    vsi->fnav.space_gsize - gcnt_pf;

	LOG_DEBUG_BDF("space bsize=%u, space gsize=%u, bcnt_global =%u, gcnt=%u, ret=%d.\n",
		      vsi->fnav.space_bsize, vsi->fnav.space_gsize, bcnt_global,
		      gcnt_pf, ret);

l_end:
	return avail_cnt;
}

s32 sxe2_fnav_ptg_parse_from_ddp(u8 *data, u16 cnt, u16 base_id,
				 struct sxe2_adapter *adapter)
{
	u16 i = 0;
	u16 j = 0;
	u16 table_idx = 0;
	s32 ret = 0;
	u16 per_size = 0;
	u16 ddp_max_cnt;
	u8 port_idx = adapter->port_idx;

	per_size = sizeof(struct sxe2_ddp_rxft_ptg);
	ddp_max_cnt = (SXE2_MAX_PTYPE_NUM * SXE2_MAX_CDID_NUM) / per_size;
	if (!data || base_id >= ddp_max_cnt || cnt > ddp_max_cnt) {
		LOG_ERROR_BDF("sxe2 fnav ptg parse from ddp failed, port_idx=%u !\n",
			      port_idx);
		ret = -EINVAL;
		goto l_end;
	}

	table_idx = (u16)((u32)base_id * per_size);
	for (i = 0; i < cnt; i++) {
		for (j = 0; j < per_size; j++) {
			if (table_idx >= (port_idx * SXE2_MAX_PTYPE_NUM) &&
			    table_idx < ((port_idx + 1) * SXE2_MAX_PTYPE_NUM)) {
				adapter->fnav_ctxt.fnav_flow_ctxt.ppp
						.pt_to_grp[table_idx %
							   SXE2_MAX_PTYPE_NUM]
						.idx = *data;
			}
			table_idx++;
			data++;
		}
	}
	LOG_INFO_BDF("sxe2 fnav ptg parse from ddp, port_idx=%u !\n", port_idx);

l_end:
	return ret;
}

s32 sxe2_fnav_mask_parse_from_ddp(u8 *data, u16 cnt, u16 base_id,
				  struct sxe2_adapter *adapter)
{
	struct sxe2_ddp_fnav_mask *ddp_mask = NULL;
	u16 i = 0;
	u16 j = 0;
	u16 mask_idx = 0;
	s32 ret = 0;

	if (!data || base_id >= SXE2_MAX_FV_MASK ||
	    ((base_id + cnt) > SXE2_MAX_FV_MASK)) {
		ret = -EINVAL;
		goto l_end;
	}

	for (i = 0; i < cnt; i++) {
		mask_idx = base_id + i;
		ddp_mask = (struct sxe2_ddp_fnav_mask *)data;

		adapter->fnav_ctxt.fnav_flow_ctxt.ppp.fv_mask[mask_idx].mask =
				ddp_mask->val;
		adapter->fnav_ctxt.fnav_flow_ctxt.ppp.fv_mask[mask_idx].mask_idx =
				mask_idx;

		bitmap_zero(adapter->fnav_ctxt.fnav_flow_ctxt.ppp.fv_mask[mask_idx]
					    .filds,
			    SXE2_FLOW_FLD_ID_MAX);

		for (j = 0; j < min_t(u16, SXE2_FLD_BIT, SXE2_FLD_WIDTH); j++) {
			if (ddp_mask->fldbit_l & BIT(j))
				set_bit(j, adapter->fnav_ctxt.fnav_flow_ctxt.ppp
							   .fv_mask[mask_idx]
							   .filds);
		}

		for (j = 0; j < min_t(u16, (SXE2_FLOW_FLD_ID_MAX - SXE2_FLD_BIT),
				      SXE2_FLD_WIDTH);
		     j++) {
			if (ddp_mask->fldbit_h & BIT(j))
				set_bit(j + SXE2_FLD_BIT,
					adapter->fnav_ctxt.fnav_flow_ctxt.ppp
							.fv_mask[mask_idx]
							.filds);
		}
		data += sizeof(struct sxe2_ddp_fnav_mask);
	}

l_end:
	return ret;
}

s32 sxe2_fnav_stat_idx_alloc_with_lock(struct sxe2_adapter *adapter, u16 vsi_id,
				       u16 *stat_index, bool need_update)
{
	struct sxe2_fnav_stat_node *stat_node = NULL;
	struct sxe2_fnav_stat_node *tmp, *pre = NULL;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	s32 ret = 0;
	u16 stat_base_id = adapter->fnav_ctxt.fnav_stat_ctxt.stat_base;
	u16 stat_num = adapter->fnav_ctxt.fnav_stat_ctxt.stat_num;
	u16 count = adapter->fnav_ctxt.fnav_stat_ctxt.stat_cnt;
	u16 new_index = stat_base_id;

	if (count >= stat_num)
		return -ENOMEM;

	mutex_lock(&adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_lock);
	list_for_each_entry(tmp, &adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_list, l_node) {
		if (tmp->stat_index > new_index)
			break;
		else if (tmp->stat_index == new_index)
			new_index++;

		pre = tmp;
	}

	stat_node = devm_kzalloc(dev, sizeof(*stat_node), GFP_KERNEL);
	if (!stat_node) {
		LOG_ERROR_BDF("no memory.\n");
		ret = -ENOMEM;
		goto l_end;
	}
	stat_node->stat_index = new_index;
	stat_node->vsi_id = vsi_id;
	stat_node->need_update = need_update;
	if (pre) {
		list_add(&stat_node->l_node, &pre->l_node);
	} else {
		list_add(&stat_node->l_node,
			 &adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_list);
	}
	adapter->fnav_ctxt.fnav_stat_ctxt.stat_cnt++;
	*stat_index = new_index;

l_end:
	mutex_unlock(&adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_lock);
	return ret;
}

s32 sxe2_fnav_stat_idx_free_with_lock(struct sxe2_adapter *adapter, u16 stat_index)
{
	struct sxe2_fnav_stat_node *stat_node = NULL;
	struct sxe2_fnav_stat_node *tmp = NULL;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	s32 ret = 0;
	u16 stat_base_id = adapter->fnav_ctxt.fnav_stat_ctxt.stat_base;
	u16 stat_num = adapter->fnav_ctxt.fnav_stat_ctxt.stat_num;
	struct sxe2_fwc_fnav_stats_resp resp = {};

	if (stat_index < stat_base_id || stat_index >= stat_base_id + stat_num)
		return -EINVAL;

	ret = sxe2_fnav_hw_stats_get(adapter, stat_index, true,
				     SXE2_FNAV_COUNTER_BANK_ALL, &resp);
	if (ret) {
		LOG_ERROR_BDF("sxe2 fnav now has valid stat index! idx: %u\n",
			      stat_index);
		goto l_end;
	}

	mutex_lock(&adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_lock);
	list_for_each_entry_safe(stat_node, tmp,
				 &adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_list,
				 l_node) {
		if (stat_node->stat_index == stat_index) {
			list_del(&stat_node->l_node);
			devm_kfree(dev, stat_node);
			break;
		}
	}
	adapter->fnav_ctxt.fnav_stat_ctxt.stat_cnt--;
	mutex_unlock(&adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_lock);

l_end:
	return ret;
}

STATIC void sxe2_fnav_stat_idx_sw_clear(struct sxe2_adapter *adapter)
{
	struct sxe2_fnav_stat_node *stat_node = NULL;
	struct sxe2_fnav_stat_node *tmp = NULL;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	mutex_lock(&adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_lock);
	list_for_each_entry_safe(stat_node, tmp,
				 &adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_list,
				 l_node) {
		list_del(&stat_node->l_node);
		devm_kfree(dev, stat_node);
	}
	adapter->fnav_ctxt.fnav_stat_ctxt.stat_cnt = 0;
	mutex_unlock(&adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_lock);
}

void sxe2_fnav_reserve_stat_idx_alloc(struct sxe2_adapter *adapter)
{
	u32 i = 0;
	u16 stat_idx = 0;

	for (i = 0; i < SXE2_FNAV_STAT_PF_MAX; i++) {
		(void)sxe2_fnav_stat_idx_alloc_with_lock(adapter,
							 adapter->vsi_ctxt.main_vsi->id_in_pf,
							 &stat_idx, false);
		adapter->fnav_ctxt.fnav_stat_ctxt.stat_rsv_idx[i] = stat_idx;
	}
}

void sxe2_fnav_stat_ctxt_init(struct sxe2_adapter *adapter)
{
	u32 i = 0;
	struct sxe2_fnav_stat_ctxt *stat_ctxt = &adapter->fnav_ctxt.fnav_stat_ctxt;

	mutex_init(&stat_ctxt->fnav_stat_lock);
	stat_ctxt->stat_base = adapter->caps_ctxt.fnav_stat_base;
	stat_ctxt->stat_num = adapter->caps_ctxt.fnav_stat_num;
	INIT_LIST_HEAD(&stat_ctxt->fnav_stat_list);
	for (i = 0; i < SXE2_FNAV_STAT_PF_MAX; i++)
		stat_ctxt->stat_rsv_idx[i] = SXE2_FNAV_INVALID_STAT_IDX;
	memset(stat_ctxt->vsi_fnav_match, 0, sizeof(stat_ctxt->vsi_fnav_match));
}

void sxe2_fnav_stat_ctxt_deinit(struct sxe2_adapter *adapter)
{
	u32 i = 0;
	struct sxe2_fnav_stat_ctxt *stat_ctxt = &adapter->fnav_ctxt.fnav_stat_ctxt;

	sxe2_fnav_stat_idx_sw_clear(adapter);

	for (i = 0; i < SXE2_FNAV_STAT_PF_MAX; i++)
		stat_ctxt->stat_rsv_idx[i] = SXE2_FNAV_INVALID_STAT_IDX;

	mutex_destroy(&stat_ctxt->fnav_stat_lock);
}

void sxe2_fnav_xlt2_dump(struct sxe2_adapter *adapter)
{
	sxe2_flow_xlt2_dump(&adapter->fnav_ctxt.fnav_flow_ctxt.ppp);
}

void sxe2_fnav_vsig_dump(struct sxe2_adapter *adapter)
{
	sxe2_flow_vsig_dump(&adapter->fnav_ctxt.fnav_flow_ctxt.ppp);
}

void sxe2_fnav_prof_dump(struct sxe2_adapter *adapter)
{
	sxe2_flow_prof_dump(&adapter->fnav_ctxt.fnav_flow_ctxt.ppp);
}

void sxe2_fnav_mask_dump(struct sxe2_adapter *adapter)
{
	sxe2_flow_mask_dump(&adapter->fnav_ctxt.fnav_flow_ctxt.ppp);
}

void sxe2_fnav_stats_dump(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	u32 gl_bcnt = 0;
	u32 gl_gcnt = 0;
	u32 pf_bcnt = 0;
	u32 pf_gcnt = 0;
	u32 vsi_bcnt = 0;
	u32 vsi_gcnt = 0;

	LOG_DEV_INFO("fnav stats dump start\n");

	ret = sxe2_fwc_fnav_space_cnt_get(adapter,
					  adapter->vsi_ctxt.main_vsi->idx_in_dev,
					  &gl_gcnt,
					  &gl_bcnt, &pf_gcnt, &pf_bcnt,
					  &vsi_gcnt, &vsi_bcnt);
	if (ret) {
		LOG_DEV_ERR("read space failed, ret %d\n", ret);
		goto l_end;
	}

	LOG_DEV_INFO("fnav gsize: %u, bsize: %u, gcnt: %u, bcnt: %u\n",
		     adapter->vsi_ctxt.main_vsi->fnav.space_gsize,
		     adapter->vsi_ctxt.main_vsi->fnav.space_bsize,
		     adapter->fnav_ctxt.space_gcnt, adapter->fnav_ctxt.space_bcnt);
	LOG_DEV_INFO("fnav global space gcnt: %u, bcnt: %u\n", gl_gcnt, gl_bcnt);
	LOG_DEV_INFO("fnav pf space gcnt: %u, bcnt: %u\n", pf_gcnt, pf_bcnt);
	LOG_DEV_INFO("fnav vsi space gcnt: %u, bcnt: %u\n", vsi_gcnt, vsi_bcnt);
	LOG_DEV_INFO("fnav pkt error cnt: %llu\n", adapter->fnav_ctxt.pkt_err_cnt);

l_end:
	LOG_DEV_INFO("fnav stats dump end\n");
}

void sxe2_comm_fnav_msg_convert_fld(unsigned long *flds,
				    struct sxe2_fnav_comm_proto_hdr *proto_hdr)
{
	DECLARE_BITMAP(tmp_flds_bit, SXE2_FLOW_FLD_ID_MAX);
	u32 tmp_flds[BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX)];
	u32 i = 0;

	bitmap_zero(tmp_flds_bit, SXE2_FLOW_FLD_ID_MAX);
	for (i = 0; i < BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX); i++)
		tmp_flds[i] = le32_to_cpu(proto_hdr->flds[i]);

	bitmap_from_arr32(tmp_flds_bit, tmp_flds, SXE2_FLOW_FLD_ID_MAX);

	bitmap_or(flds, flds, tmp_flds_bit, SXE2_FLOW_FLD_ID_MAX);
}

STATIC s32 sxe2_fnav_flow_cfg_update(struct sxe2_vsi *vsi,
				     struct sxe2_fnav_flow_cfg *flow_cfg,
				     struct sxe2_fnav_flow_seg *segs_tmp,
				     bool is_tunnel)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	int ret = 0;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_fnav_flow_seg *segs = NULL;

	segs = devm_kzalloc(dev, sizeof(*segs) * SXE2_FNAV_SEG_MAX, GFP_KERNEL);
	if (!segs) {
		LOG_ERROR_BDF("no memory for seg.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	if (is_tunnel)
		memcpy(segs, segs_tmp, sizeof(*segs) * SXE2_FNAV_SEG_MAX);
	else
		memcpy(segs, segs_tmp,
		       sizeof(*segs));

	segs->is_tunnel = is_tunnel;

	ret = sxe2_fnav_flow_cfg_add(vsi, flow_cfg, segs);
	if (ret == -EEXIST) {
		goto l_free;
	} else if (ret) {
		LOG_ERROR_BDF("tunnel rule add failed, ret:%d, vsi id=%u.\n", ret,
			      vsi->id_in_pf);
		goto l_free;
	}

l_end:
	return ret;
l_free:
	if (segs)
		devm_kfree(dev, segs);

	goto l_end;
}

STATIC void sxe2_fnav_hlist_add_for_arfs(struct sxe2_adapter *adapter,
					 struct sxe2_fnav_filter *filter)
{
	u16 vsi_id = filter->ori_vsi_sw;
	u16 arfs_vsi_id = adapter->arfs_ctxt.vsi_id_in_pf;

	if (vsi_id == arfs_vsi_id) {
		if (sxe2_fnav_flow_sup_arfs(filter->flow_type)) {
			sxe2_fnav_filter_hash(filter);
			hlist_add_head(&filter->hl_node,
				       &adapter->fnav_ctxt.filter_hlist
							[filter->hash_val &
							 SXE2_FNAV_FLTR_HLIST_MASK]);
		}
	}
}

STATIC void sxe2_fnav_hlist_del_for_arfs(struct sxe2_adapter *adapter,
					 struct sxe2_fnav_filter *filter)
{
	u16 vsi_id = filter->ori_vsi_sw;
	u16 arfs_vsi_id = adapter->arfs_ctxt.vsi_id_in_pf;

	if (vsi_id == arfs_vsi_id) {
		if (sxe2_fnav_flow_sup_arfs(filter->flow_type)) {
			hlist_del(&filter->hl_node);
			if (filter->conflict)
				sxe2_monitor_work_schedule(adapter);
		}
	}
}

STATIC bool sxe2_fnav_flow_parse_full_match(struct sxe2_vsi *vsi,
					    struct sxe2_fnav_filter *filter,
					    struct sxe2_fnav_flow_seg *segs)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	bool full_match = false;
	DECLARE_BITMAP(full_match_flds, SXE2_FLOW_FLD_ID_MAX);

	if (vsi->id_in_pf != adapter->arfs_ctxt.vsi_id_in_pf)
		goto l_end;

	if (!sxe2_fnav_support_full_match(filter->flow_type))
		goto l_end;

	if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_TUNNEL)
		goto l_end;

	if (filter->full_key.has_flex_filed)
		goto l_end;

	switch (filter->flow_type) {
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
		bitmap_zero(full_match_flds, SXE2_FLOW_FLD_ID_MAX);
		set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, full_match_flds);
		set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, full_match_flds);
		set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, full_match_flds);
		set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, full_match_flds);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
		bitmap_zero(full_match_flds, SXE2_FLOW_FLD_ID_MAX);
		set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, full_match_flds);
		set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, full_match_flds);
		set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, full_match_flds);
		set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, full_match_flds);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
		bitmap_zero(full_match_flds, SXE2_FLOW_FLD_ID_MAX);
		set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, full_match_flds);
		set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, full_match_flds);
		set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, full_match_flds);
		set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, full_match_flds);
		break;
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
		bitmap_zero(full_match_flds, SXE2_FLOW_FLD_ID_MAX);
		set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, full_match_flds);
		set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, full_match_flds);
		set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, full_match_flds);
		set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, full_match_flds);
		break;
	default:
		break;
	}

	if (bitmap_equal(full_match_flds, segs->fields, SXE2_FLOW_FLD_ID_MAX))
		full_match = true;

l_end:
	return full_match;
}

STATIC struct sxe2_fnav_flow_cfg *
sxe2_fnav_flow_update_before_filter_add(struct sxe2_vsi *vsi,
					struct sxe2_fnav_filter *filter,
					struct sxe2_fnav_flow_seg *segs, s32 *result)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	int ret = 0;
	enum sxe2_fnav_flow_type flow_type;
	struct sxe2_fnav_flow_cfg *flow_cfg = NULL;
	bool outer_new = false;
	bool full_match;
	bool new_alloc_flow = false;
	struct sxe2_fnav_flow_cfg *flow_cfg_out = NULL;

	flow_type = filter->flow_type;
	if (flow_type == SXE2_FNAV_FLOW_TYPE_NONE) {
		LOG_ERROR_BDF("invalid flow type %d, vsi id=%u .\n", flow_type,
			      vsi->id_in_pf);
		ret = -EINVAL;
		goto l_end;
	}

	full_match = sxe2_fnav_flow_parse_full_match(vsi, filter, segs);

	flow_cfg = sxe2_fnav_find_flow_cfg_by_flow_type(vsi, flow_type);
	if (!flow_cfg) {
		flow_cfg = devm_kzalloc(dev, sizeof(*flow_cfg), GFP_KERNEL);
		flow_cfg->flow_type = flow_type;
		flow_cfg->peer_vsi_used.vsi_id_sw =
				SXE2_INVAL_U16;
		flow_cfg->peer_vsi_used.filter_cnt = 0;
		flow_cfg->self_vsi_used.vsi_id_sw = vsi->id_in_pf;
		flow_cfg->self_vsi_used.filter_cnt = 0;
		new_alloc_flow = true;
	}

	if (sxe2_fnav_filter_multi_vsi_dup(adapter, filter, flow_cfg)) {
		ret = -EEXIST;
		goto l_end;
	}

	if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_NO_TUNNEL ||
	    filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY) {
		ret = sxe2_fnav_flow_cfg_update(vsi, flow_cfg, segs, false);
		if (ret == 0) {
			outer_new = true;
		} else if (ret == -EEXIST) {
			LOG_INFO_BDF("no tunnel rule exist, flow type=%d vsi id=%u.\n",
				     flow_type, vsi->id_in_pf);
			ret = 0;
		} else if (ret) {
			LOG_ERROR_BDF("no tunnel rule add failed, ret:%d, vsi id=%u.\n",
				      ret, vsi->id_in_pf);
			goto l_free;
		}
	}

	if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_TUNNEL ||
	    filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY) {
		if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY)
			memset(segs, 0, sizeof(struct sxe2_fnav_flow_seg));
		ret = sxe2_fnav_flow_cfg_update(vsi, flow_cfg, segs, true);
		if (ret == -EEXIST) {
			LOG_DEBUG_BDF("tunnel rule exist.\n");
			ret = 0;
		} else if (ret) {
			if (outer_new)
				(void)sxe2_fnav_flow_cfg_del(adapter, flow_cfg,
							     false);
			LOG_ERROR_BDF("tunnel rule add failed, ret:%d\n", ret);
			goto l_free;
		}
	}

	flow_cfg->full_match = full_match;
	if (new_alloc_flow)
		sxe2_fnav_flow_cfg_add_list(vsi, flow_cfg);

	flow_cfg_out = flow_cfg;
	goto l_end;

l_free:
	if (new_alloc_flow)
		devm_kfree(dev, flow_cfg);
l_end:
	*result = ret;
	return flow_cfg_out;
}

void sxe2_fnav_filter_add_list_by_loc(struct sxe2_vsi *vsi,
				      struct sxe2_fnav_filter *filter)
{
	struct sxe2_fnav_filter *filter_tmp, *pre = NULL;
	struct sxe2_vsi_fnav *vsi_fnav = &vsi->fnav;

	list_for_each_entry(filter_tmp, &vsi_fnav->filter_list, l_node) {
		if (filter_tmp->filter_loc >= filter->filter_loc)
			break;
		pre = filter_tmp;
	}

	if (pre)
		list_add(&filter->l_node, &pre->l_node);
	else
		list_add(&filter->l_node, &vsi_fnav->filter_list);

	vsi_fnav->filter_cnt++;
}

STATIC void sxe2_fnav_filter_add_list(struct sxe2_vsi *vsi,
				      struct sxe2_fnav_filter *filter, u32 *id)
{
	struct sxe2_fnav_filter *filter_tmp, *pre = NULL;
	u32 flow_id = 0;
	struct sxe2_vsi_fnav *vsi_fnav = &vsi->fnav;

	flow_id = (u32)find_first_zero_bit(vsi_fnav->flow_ids,
					   SXE2_FNAV_MAX_FILTERS);
	set_bit((int)flow_id, vsi_fnav->flow_ids);
	*id = flow_id;
	filter->vsi_flow_id = flow_id;

	list_for_each_entry(filter_tmp, &vsi_fnav->filter_list, l_node) {
		if (filter_tmp->vsi_flow_id >= filter->vsi_flow_id)
			break;
		pre = filter_tmp;
	}
	if (pre)
		list_add(&filter->l_node, &pre->l_node);
	else
		list_add(&filter->l_node, &vsi_fnav->filter_list);

	vsi_fnav->filter_cnt++;
}

STATIC s32 sxe2_comm_fnav_hw_filter_update(struct sxe2_vsi *vsi,
					   struct sxe2_fnav_filter *filter,
					   struct sxe2_fnav_flow_cfg *flow_cfg)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_NO_TUNNEL ||
	    filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY) {
		ret = sxe2_fnav_hw_filter_update_with_admin(vsi, filter, flow_cfg,
							    true, false);
		if (ret) {
			if (ret == -ENOSPC)
				LOG_ERROR_BDF("add hw filter failed, no space left\n");
			else
				LOG_ERROR_BDF("add hw filter failed, ret:%d\n", ret);

			goto l_unlock;
		}
		flow_cfg->filter_cnt[SXE2_FNAV_SEG_NON_TUN]++;
		if (filter->rule_vsi_sw != vsi->id_in_pf) {
			flow_cfg->peer_vsi_used.vsi_id_sw = filter->rule_vsi_sw;
			flow_cfg->peer_vsi_used.filter_cnt++;
		} else {
			flow_cfg->self_vsi_used.vsi_id_sw = filter->rule_vsi_sw;
			flow_cfg->self_vsi_used.filter_cnt++;
		}
	}

	if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_TUNNEL ||
	    filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY) {
		ret = sxe2_fnav_hw_filter_update_with_admin(vsi, filter, flow_cfg,
							    true, true);
		if (ret) {
			if (ret == -ENOSPC)
				LOG_ERROR_BDF("add hw filter failed, no space left\n");
			else
				LOG_ERROR_BDF("add hw filter failed, ret:%d\n", ret);

			if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY) {
				(void)sxe2_fnav_hw_filter_update_with_admin(vsi,
									    filter,
									    flow_cfg,
									    false,
									    false);
				flow_cfg->filter_cnt[SXE2_FNAV_SEG_NON_TUN]--;
			}
			goto l_unlock;
		}
		flow_cfg->filter_cnt[SXE2_FNAV_SEG_TUN]++;
	}

	sxe2_fnav_hlist_add_for_arfs(adapter, filter);

l_unlock:
	return ret;
}

struct sxe2_fnav_filter *
sxe2_comm_fnav_filter_search_for_dup(struct sxe2_vsi *vsi,
				     struct sxe2_fnav_filter *filter)
{
	bool ret;
	struct sxe2_fnav_filter *filter_tmp = NULL;
	struct sxe2_fnav_filter *filter_find = NULL;

	list_for_each_entry(filter_tmp, &vsi->fnav.filter_list, l_node) {
		ret = sxe2_fnav_filter_cmp(filter, filter_tmp);
		if (ret) {
			filter_find = filter_tmp;
			break;
		}
	}

	return filter_find;
}

s32 sxe2_fnav_filter_add_hw(struct sxe2_vsi *vsi, struct sxe2_fnav_filter *filter,
			    struct sxe2_fnav_flow_seg *segs)
{
	struct sxe2_adapter *adapter = NULL;
	s32 ret = 0;
	struct sxe2_fnav_flow_cfg *flow_cfg = NULL;

	if (!vsi) {
		ret = -EINVAL;
		LOG_ERROR_BDF("sxe2 fnav filter add failed, vsi is invalid.\n");
		goto l_end;
	}

	adapter = vsi->adapter;

	mutex_lock(&vsi->fnav.flow_cfg_lock);

	flow_cfg = sxe2_fnav_flow_update_before_filter_add(vsi, filter, segs, &ret);
	if (!flow_cfg) {
		LOG_ERROR_BDF("sxe2 fnav flow cfg update before add fail ret: %d !\t"
			      "vsi type: %u, idx: %u\n",
			      ret, vsi->type, vsi->id_in_pf);
		goto l_unlock;
	}

	ret = sxe2_fnav_filter_inputset_fill(vsi, filter, flow_cfg);
	if (ret) {
		ret = -EINVAL;
		LOG_ERROR_BDF("sxe2 fnav inputset fill fail ret: %d ! vsi type: %u,\t"
			      "idx: %u\n",
			      ret, vsi->type, vsi->id_in_pf);
		goto l_unlock;
	}

	ret = sxe2_comm_fnav_hw_filter_update(vsi, filter, flow_cfg);
	if (ret) {
		(void)sxe2_fnav_flow_update_after_filter_del(vsi, flow_cfg);
		LOG_ERROR_BDF("sxe2 fnav update filter fail ret: %d ! vsi type: %u,\t"
			      "idx: %u\n",
			      ret, vsi->type, vsi->id_in_pf);
	}

l_unlock:
	mutex_unlock(&vsi->fnav.flow_cfg_lock);
l_end:
	return ret;
}

s32 sxe2_fnav_filter_del_hw(struct sxe2_vsi *vsi, struct sxe2_fnav_filter *filter)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_fnav_flow_cfg *flow_cfg = NULL;
	enum sxe2_fnav_flow_type flow_type;

	if (!filter)
		goto l_end;

	mutex_lock(&vsi->fnav.flow_cfg_lock);

	flow_type = sxe2_arfs_flow_to_fnav_flow(filter->flow_type);
	flow_cfg = sxe2_fnav_find_flow_cfg_by_flow_type(vsi, flow_type);
	if (!flow_cfg)
		goto l_unlock;

	if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_NO_TUNNEL ||
	    filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY) {
		ret = sxe2_fnav_hw_filter_update_with_admin(vsi, filter, flow_cfg,
							    false, false);
		if (ret) {
			LOG_ERROR_BDF("sxe2 fnav delete outer hw filter failed, ret:%d\n",
				      ret);
			goto l_unlock;
		}
		flow_cfg->filter_cnt[SXE2_FNAV_SEG_NON_TUN]--;
		if (filter->rule_vsi_sw != vsi->id_in_pf)
			flow_cfg->peer_vsi_used.filter_cnt--;
		else
			flow_cfg->self_vsi_used.filter_cnt--;
	}
	if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_TUNNEL ||
	    filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY) {
		if (filter->tunn_flag) {
			ret = sxe2_fnav_hw_filter_update_with_admin(vsi, filter,
								    flow_cfg,
								    false, true);
			if (ret) {
				LOG_ERROR_BDF("sxe2 fnav del inner hw filter failed, ret:%d\n",
					      ret);
				goto l_unlock;
			}
		}
		flow_cfg->filter_cnt[SXE2_FNAV_SEG_TUN]--;
	}

	ret = sxe2_fnav_flow_update_after_filter_del(vsi, flow_cfg);
	if (ret) {
		LOG_ERROR_BDF("sxe2 fnav update flow cfg after del failed, ret:%d\n",
			      ret);
		goto l_unlock;
	}
	sxe2_fnav_hlist_del_for_arfs(adapter, filter);

l_unlock:
	mutex_unlock(&vsi->fnav.flow_cfg_lock);
l_end:
	return ret;
}

STATIC s32 sxe2_fnav_filter_del_sw(struct sxe2_vsi *vsi,
				   struct sxe2_fnav_filter *filter)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = NULL;
	struct sxe2_fnav_flow_cfg *flow_cfg = NULL;
	enum sxe2_fnav_flow_type flow_type;
	struct device *dev = NULL;
	u16 arfs_vsi_id;

	if (!filter || !vsi)
		goto l_end;

	adapter = vsi->adapter;
	dev = SXE2_ADAPTER_TO_DEV(adapter);
	arfs_vsi_id = adapter->arfs_ctxt.vsi_id_in_pf;

	mutex_lock(&vsi->fnav.flow_cfg_lock);
	flow_type = sxe2_arfs_flow_to_fnav_flow(filter->flow_type);
	flow_cfg = sxe2_fnav_find_flow_cfg_by_flow_type(vsi, flow_type);
	if (!flow_cfg)
		goto l_unlock;

	if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_NO_TUNNEL ||
	    filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY) {
		flow_cfg->filter_cnt[SXE2_FNAV_SEG_NON_TUN]--;
		if (filter->rule_vsi_sw != vsi->id_in_pf)
			flow_cfg->peer_vsi_used.filter_cnt--;
		else
			flow_cfg->self_vsi_used.filter_cnt--;
	}

	if (filter->tunn_flag == SXE2_FNAV_TUN_FLAG_TUNNEL ||
	    filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY)
		flow_cfg->filter_cnt[SXE2_FNAV_SEG_TUN]--;

	if (flow_cfg->filter_cnt[SXE2_FNAV_SEG_TUN] == 0 &&
	    flow_cfg->seg[SXE2_FNAV_SEG_TUN]) {
		devm_kfree(dev, flow_cfg->seg[SXE2_FNAV_SEG_TUN]);
		flow_cfg->seg[SXE2_FNAV_SEG_TUN] = NULL;
	}

	if (flow_cfg->filter_cnt[SXE2_FNAV_SEG_NON_TUN] == 0 &&
	    flow_cfg->seg[SXE2_FNAV_SEG_NON_TUN]) {
		devm_kfree(dev, flow_cfg->seg[SXE2_FNAV_SEG_NON_TUN]);
		flow_cfg->seg[SXE2_FNAV_SEG_NON_TUN] = NULL;
	}

	if (flow_cfg->filter_cnt[SXE2_FNAV_SEG_TUN] == 0 &&
	    flow_cfg->filter_cnt[SXE2_FNAV_SEG_NON_TUN] == 0) {
		list_del(&flow_cfg->l_node);
		devm_kfree(dev, flow_cfg);
	}

	if (filter->ori_vsi_sw == arfs_vsi_id &&
	    sxe2_fnav_flow_sup_arfs(filter->flow_type))
		hlist_del(&filter->hl_node);

l_unlock:
	mutex_unlock(&vsi->fnav.flow_cfg_lock);
l_end:
	return ret;
}

s32 sxe2_fnav_filter_del(struct sxe2_vsi *rule_vsi, struct sxe2_fnav_filter *filter)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = rule_vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u16 ori_vsi_id = 0;
	struct sxe2_vsi *ori_vsi = NULL;
	u32 flow_id = 0;

	ori_vsi_id = filter->ori_vsi_sw;
	flow_id = filter->vsi_flow_id;
	ori_vsi = adapter->vsi_ctxt.vsi[ori_vsi_id];

	if (!ori_vsi) {
		ret = -EINVAL;
		LOG_ERROR_BDF("sxe2 fnav del filter failed, ori vsi is null !!!,\t"
			      "ori_vsi_id=%u, rule_vsi_id=%u",
			      ori_vsi_id, rule_vsi->id_in_pf);
		goto l_delete;
	}

	ret = sxe2_fnav_filter_del_hw(ori_vsi, filter);
	if (ret) {
		LOG_ERROR_BDF("sxe2 fnav delete filter failed, flow_id=%u,\t"
			      "ori_vsi_id=%u, ret:%d\n",
			      flow_id, ori_vsi->id_in_pf, ret);
		goto l_end;
	}

l_delete:
	rule_vsi->fnav.filter_cnt--;
	list_del(&filter->l_node);
	devm_kfree(dev, filter);
	clear_bit((int)flow_id, rule_vsi->fnav.flow_ids);

l_end:
	return ret;
}

struct sxe2_fnav_filter *
sxe2_fnav_find_filter_by_flow_id_unlock(struct sxe2_vsi_fnav *vsi_fnav, u32 flow_id)
{
	struct sxe2_fnav_filter *filter_tmp = NULL;
	struct sxe2_fnav_filter *filter_find = NULL;

	list_for_each_entry(filter_tmp, &vsi_fnav->filter_list, l_node) {
		if (flow_id == filter_tmp->vsi_flow_id) {
			filter_find = filter_tmp;
			break;
		}
		if (flow_id < filter_tmp->vsi_flow_id)
			break;
	}

	return filter_find;
}

s32 sxe2_fnav_del_filter_by_flow_id(struct sxe2_adapter *adapter, u16 rule_vsi_id,
				    u32 flow_id)
{
	s32 ret = -ENOENT;
	struct sxe2_fnav_filter *filter = NULL;
	struct sxe2_vsi *rule_vsi = NULL;

	mutex_lock(&adapter->vsi_ctxt.lock);

	rule_vsi = adapter->vsi_ctxt.vsi[rule_vsi_id];

	mutex_lock(&adapter->fnav_ctxt.filter_lock);
	filter = sxe2_fnav_find_filter_by_flow_id_unlock(&rule_vsi->fnav, flow_id);
	if (filter) {
		ret = sxe2_fnav_filter_del(rule_vsi, filter);
		if (ret) {
			LOG_ERROR_BDF("sxe2 fnav delete filter failed, flow_id=%u,\t"
				      "rule_vsi_id=%u, ret:%d\n",
				      flow_id, rule_vsi_id, ret);
		}
	}

	mutex_unlock(&adapter->fnav_ctxt.filter_lock);

	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2_fnav_hw_stats_get(struct sxe2_adapter *adapter, u16 stat_index,
			   u32 is_clear, enum sxe2_fnav_counter_bank_type bank_type,
			   struct sxe2_fwc_fnav_stats_resp *resp)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_fnav_stats_req req = {};

	req.is_clear = (u8)is_clear;
	req.counter_idx = cpu_to_le16(stat_index);
	req.bank_type = (u8)bank_type;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FNAV_STATS_GET, &req, sizeof(req),
				  resp, sizeof(struct sxe2_fwc_fnav_stats_resp));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav get state failed, stat_index=%u, ret=%d",
			      stat_index, ret);
	}
	return ret;
}

void sxe2_fnav_match_stats_get(struct sxe2_adapter *adapter, u16 stat_index,
			       u16 vsi_id)
{
	s32 ret = 0;
	struct sxe2_fwc_fnav_stats_resp resp = {};
	u64 fnav_match = 0;

	if (stat_index == SXE2_FNAV_INVALID_STAT_IDX || vsi_id >= SXE2_MAX_VSI_NUM)
		return;

	ret = sxe2_fnav_hw_stats_get(adapter, stat_index, true,
				     SXE2_FNAV_COUNTER_BANK_0, &resp);
	if (!ret)
		fnav_match = le64_to_cpu(resp.stats[0]);

	adapter->fnav_ctxt.fnav_stat_ctxt.vsi_fnav_match[vsi_id] += fnav_match;
}

void sxe2_fnav_match_stats_update_batch(struct sxe2_adapter *adapter)
{
	struct sxe2_fnav_stat_node *stat_node = NULL;
	struct sxe2_fnav_stat_ctxt *stat_ctxt = &adapter->fnav_ctxt.fnav_stat_ctxt;
	u16 stat_cnt = 0;
	u32 req_size = 0;
	u32 rsp_size = 0;
	s32 ret = 0;
	u16 i = 0;
	u16 vsi_id = 0;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fwc_fnav_match_req_batch *req = NULL;
	struct sxe2_fwc_fnav_match_rsp_batch *rsp = NULL;

	mutex_lock(&adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_lock);

	list_for_each_entry(stat_node, &stat_ctxt->fnav_stat_list, l_node) {
		if (stat_node->need_update)
			stat_cnt++;
	}
	req_size = sizeof(struct sxe2_fwc_fnav_match_req_batch) +
		   stat_cnt * sizeof(struct sxe2_fwc_fnav_match_req);
	rsp_size = sizeof(struct sxe2_fwc_fnav_match_rsp_batch) +
		   stat_cnt * sizeof(u64);
	req = kzalloc(req_size, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto l_free;
	}
	rsp = kzalloc(rsp_size, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		goto l_free;
	}

	req->stat_cnt = cpu_to_le16(stat_cnt);
	req->is_clear = true;
	req->bank_type = (u8)SXE2_FNAV_COUNTER_BANK_0;
	list_for_each_entry(stat_node, &stat_ctxt->fnav_stat_list, l_node) {
		if (stat_node->need_update) {
			req->match_req[i].vsi_id = stat_node->vsi_id;
			req->match_req[i].stat_idx =
					cpu_to_le16(stat_node->stat_index);
			i++;
		}
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FNAV_MATCH_GET_BATCH, req, req_size,
				  rsp, rsp_size);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav get match batch failed, ret=%d", ret);
		goto l_free;
	}

	for (i = 0; i < stat_cnt; i++) {
		vsi_id = req->match_req[i].vsi_id;
		adapter->fnav_ctxt.fnav_stat_ctxt.vsi_fnav_match[vsi_id] +=
				le64_to_cpu(rsp->fnav_match[i]);
	}

l_free:
	kfree(req);
	kfree(rsp);
	mutex_unlock(&adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_lock);
}

STATIC s32 sxe2_fnav_stats_clear_by_vsi(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_fnav_stat_node *stat_node = NULL;
	struct sxe2_fnav_stat_node *tmp = NULL;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	s32 ret = 0;
	u16 vsi_id = vsi->id_in_pf;
	struct sxe2_fwc_fnav_stats_resp resp = {};

	mutex_lock(&adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_lock);

	list_for_each_entry_safe(stat_node, tmp,
				 &adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_list,
				 l_node) {
		if (stat_node->vsi_id == vsi_id) {
			ret = sxe2_fnav_hw_stats_get(adapter,
						     stat_node->stat_index, true,
						     SXE2_FNAV_COUNTER_BANK_ALL, &resp);
			if (ret) {
				LOG_ERROR_BDF("sxe2 fnav stats clear failed,\t"
					      "stat_index=%u, ret=%d",
					      stat_node->stat_index, ret);
				break;
			}
			list_del(&stat_node->l_node);
			devm_kfree(dev, stat_node);
			adapter->fnav_ctxt.fnav_stat_ctxt.stat_cnt--;
		}
	}

	mutex_unlock(&adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_lock);
	return ret;
}

void sxe2_fnav_stats_free_by_vsi(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_fnav_stat_node *stat_node = NULL;
	struct sxe2_fnav_stat_node *tmp = NULL;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u16 vsi_id = vsi->id_in_pf;

	mutex_lock(&adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_lock);

	list_for_each_entry_safe(stat_node, tmp,
				 &adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_list,
				 l_node) {
		if (stat_node->vsi_id == vsi_id) {
			list_del(&stat_node->l_node);
			devm_kfree(dev, stat_node);
			adapter->fnav_ctxt.fnav_stat_ctxt.stat_cnt--;
		}
	}

	mutex_unlock(&adapter->fnav_ctxt.fnav_stat_ctxt.fnav_stat_lock);
}

s32 sxe2_fnav_del_filter_by_vsi(struct sxe2_vsi *rule_vsi)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = rule_vsi->adapter;
	struct sxe2_fnav_filter *filter, *tmp;

	mutex_lock(&adapter->fnav_ctxt.filter_lock);
	list_for_each_entry_safe(filter, tmp, &rule_vsi->fnav.filter_list, l_node) {
		ret = sxe2_fnav_filter_del(rule_vsi, filter);
		if (ret) {
			LOG_ERROR_BDF("sxe2 vf fdir delete filter failed,\t"
				      "rule_vsi_id=%u, ret:%d\n",
				      rule_vsi->id_in_pf, ret);
			break;
		}
	}
	mutex_unlock(&adapter->fnav_ctxt.filter_lock);
	return ret;
}

void sxe2_fnav_filter_free_by_vsi(struct sxe2_vsi *vsi)
{
	struct sxe2_vsi_fnav *vsi_fnav = NULL;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_fnav_filter *filter, *tmp;
	struct sxe2_vsi *ori_vsi = NULL;

	vsi_fnav = &vsi->fnav;
	mutex_lock(&adapter->fnav_ctxt.filter_lock);
	list_for_each_entry_safe(filter, tmp, &vsi_fnav->filter_list, l_node) {
		ori_vsi = adapter->vsi_ctxt.vsi[filter->ori_vsi_sw];
		(void)sxe2_fnav_filter_del_sw(ori_vsi, filter);
		list_del(&filter->l_node);
		devm_kfree(dev, filter);
	}
	vsi_fnav->filter_cnt = 0;
	mutex_unlock(&adapter->fnav_ctxt.filter_lock);

	bitmap_zero(vsi_fnav->flow_ids, SXE2_FNAV_MAX_FILTERS);
}

void sxe2_fnav_clean_by_vsi(struct sxe2_vsi *vsi, bool need_clear_hw)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (!vsi)
		return;

	if (need_clear_hw) {
		ret = sxe2_fnav_del_filter_by_vsi(vsi);
		if (ret)
			LOG_ERROR_BDF("sxe2 fnav clean filter del failed, vsi_id:%d ret:%d !\n",
				      vsi->id_in_pf, ret);

		ret = sxe2_fnav_stats_clear_by_vsi(vsi);
		if (ret)
			LOG_ERROR_BDF("sxe2 fnav clean fnav stat idx fail vsi_id:%d ret:%d !\n",
				      vsi->id_in_pf, ret);

	} else {
		sxe2_fnav_stats_free_by_vsi(vsi);
		sxe2_fnav_filter_free_by_vsi(vsi);
		sxe2_fnav_flow_cfg_free(vsi);
	}

	LOG_INFO_BDF("sxe2 fnav clean is done, vsi_id=%u, vsi_type=%u, clear_hw=%u.\n",
		     vsi->id_in_pf, vsi->type, need_clear_hw);
}

void sxe2_fnav_vf_cfg_clear(struct sxe2_adapter *adapter)
{
	struct sxe2_vf_node *vf_node;
	struct sxe2_vsi *dpdk_pf_vsi = NULL;
	struct sxe2_vsi *main_vsi = adapter->vsi_ctxt.main_vsi;
	u16 vf_idx;

	sxe2_for_each_vf(adapter, vf_idx)
	{
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		mutex_lock(&adapter->vsi_ctxt.lock);
		vf_node = SXE2_VF_NODE(adapter, vf_idx);
		if (sxe2_com_mode_get(adapter) != SXE2_COM_MODULE_KERNEL) {
			dpdk_pf_vsi = sxe2_vsi_get_by_type_unlock(adapter,
								  SXE2_VSI_T_DPDK_PF);
			if (dpdk_pf_vsi)
				(void)sxe2_fnav_action_to_vf_all_filter_del(dpdk_pf_vsi,
									    vf_node);
		}
		if (main_vsi)
			(void)sxe2_fnav_action_to_vf_all_filter_del(main_vsi,
								    vf_node);
		mutex_unlock(&adapter->vsi_ctxt.lock);
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	}

	memset(adapter->fnav_ctxt.fnav_stat_ctxt.vsi_fnav_match, 0,
	       sizeof(adapter->fnav_ctxt.fnav_stat_ctxt.vsi_fnav_match));
}

STATIC void sxe2_fnav_stat_ctrl_convert(enum sxe2_fnav_stat_ctrl_type ori_stat_ctrl,
					u32 *stat_ctrl)
{
	switch (ori_stat_ctrl) {
	case SXE2_FNAV_STAT_ENA_NONE:
		*stat_ctrl = SXE2_FNAV_TX_DESC_QW0_STAT_ENA_NONE;
		break;
	case SXE2_FNAV_STAT_ENA_PKTS:
		*stat_ctrl = SXE2_FNAV_TX_DESC_QW0_STAT_ENA_PKTS;
		break;
	case SXE2_FNAV_STAT_ENA_BYTES:
		*stat_ctrl = SXE2_FNAV_TX_DESC_QW0_STAT_ENA_BYTES;
		break;
	case SXE2_FNAV_STAT_ENA_ALL:
		*stat_ctrl = SXE2_FNAV_TX_DESC_QW0_STAT_ENA_ALL;
		break;
	default:
		*stat_ctrl = SXE2_FNAV_TX_DESC_QW0_STAT_ENA_NONE;
		break;
	}
}

STATIC s32 sxe2_comm_fnav_parse_action(struct sxe2_fnav_filter *filter,
				       struct sxe2_fnav_comm_full_msg *full_msg)
{
	enum sxe2_fnav_act_type act_type = 0;
	enum sxe2_fnav_stat_ctrl_type ctrl_type = 0;
	u32 stat_ctrl = 0;
	u32 dest_num = 0;
	u32 mark_num = 0;
	s32 ret = 0;
	u32 i = 0;

	if (full_msg->action_cnt > SXE2_FNAV_MAX_NUM_ACTIONS)
		return -EINVAL;

	for (i = 0; i < full_msg->action_cnt; i++) {
		act_type = le32_to_cpu(full_msg->action[i].type);
		switch (act_type) {
		case SXE2_FNAV_ACTION_DROP:
			dest_num++;
			filter->act_type = SXE2_FNAV_ACT_DROP;
			break;
		case SXE2_FNAV_ACTION_PASSTHRU:
			dest_num++;
			filter->act_type = SXE2_FNAV_ACT_OTHER;
			filter->act_prio = SXE2_FNAV_TX_DESC_QW0_TOQ_PRIO_ZERO;
			break;
		case SXE2_FNAV_ACTION_QUEUE:
			dest_num++;
			filter->act_type = SXE2_FNAV_ACT_QINDEX;
			filter->q_index =
				le16_to_cpu(full_msg->action[i].act_queue.q_index);
			break;
		case SXE2_FNAV_ACTION_Q_REGION:
			dest_num++;
			filter->act_type = SXE2_FNAV_ACT_QGROUP;
			filter->q_index =
				le16_to_cpu(full_msg->action[i].act_q_region.q_index);
			filter->q_region = full_msg->action[i].act_q_region.region;
			break;
		case SXE2_FNAV_ACTION_MARK:
			mark_num++;
			filter->filter_loc =
				le32_to_cpu(full_msg->action[i].act_mark.mark_id);
			filter->fdid_prio = SXE2_FNAV_TX_DESC_QW1_FDID_PRIO_THREE;
			break;
		case SXE2_FNAV_ACTION_COUNT:
			ctrl_type = le32_to_cpu(full_msg->action[i].act_count.stat_ctrl);
			sxe2_fnav_stat_ctrl_convert(ctrl_type, &stat_ctrl);
			filter->stat_ctrl = (u8)stat_ctrl;
			filter->stat_index =
				(u16)(le32_to_cpu(full_msg->action[i].act_count.stat_index));
			break;
		default:
			return -EINVAL;
		}
	}
	if (dest_num == 0 || dest_num >= 2)
		return -EINVAL;

	if (mark_num >= 2)
		return -EINVAL;

	return ret;
}

STATIC s32 sxe2_comm_fnav_parse_proto(struct sxe2_fnav_filter *filter,
				      struct sxe2_fnav_comm_full_msg *full_msg)
{
	struct sxe2_fnav_comm_proto_hdr *hdr;
	enum sxe2_flow_hdr hdr_type = 0;
	s32 ret = 0;
	u32 i = 0;
	DECLARE_BITMAP(flds_bit, SXE2_FLOW_FLD_ID_MAX);

	if (full_msg->proto_cnt > SXE2_FNAV_MAX_NUM_PROTO_HDRS)
		return -EINVAL;

	for (i = 0; i < full_msg->proto_cnt; i++) {
		hdr = &full_msg->proto_hdr[i];
		hdr_type = hdr->type;
		switch (hdr_type) {
		case SXE2_FLOW_HDR_ETH:
			if (hdr->tunnel_level == SXE2_FNAV_TUNNEL_INNER) {
				filter->full_key.eth_inner.h_proto = hdr->eth.etype;
				(void)memcpy(filter->full_key.eth_inner.h_source,
					     &hdr->eth.src, sizeof(hdr->eth.src));
				(void)memcpy(filter->full_key.eth_inner.h_dest,
					     &hdr->eth.dst, sizeof(hdr->eth.dst));
			} else {
				filter->full_key.eth.h_proto = hdr->eth.etype;
				(void)memcpy(filter->full_key.eth.h_source,
					     &hdr->eth.src, sizeof(hdr->eth.src));
				(void)memcpy(filter->full_key.eth.h_dest,
					     &hdr->eth.dst, sizeof(hdr->eth.dst));
			}
			break;
		case SXE2_FLOW_HDR_IPV4:
			if (hdr->tunnel_level == SXE2_FNAV_TUNNEL_INNER) {
				filter->full_key.ip_inner.v4.src_ip =
						hdr->ipv4.saddr;
				filter->full_key.ip_inner.v4.dst_ip =
						hdr->ipv4.daddr;
				filter->full_key.ip_inner.v4.tos = hdr->ipv4.tos;
				filter->full_key.ip_inner.v4.proto = hdr->ipv4.proto;
				filter->full_key.ip_inner.v4.ttl = hdr->ipv4.ttl;
			} else {
				filter->full_key.ip.v4.src_ip = hdr->ipv4.saddr;
				filter->full_key.ip.v4.dst_ip = hdr->ipv4.daddr;
				filter->full_key.ip.v4.tos = hdr->ipv4.tos;
				filter->full_key.ip.v4.proto = hdr->ipv4.proto;
				filter->full_key.ip.v4.ttl = hdr->ipv4.ttl;
			}
			break;
		case SXE2_FLOW_HDR_IPV6:
			bitmap_zero(flds_bit, SXE2_FLOW_FLD_ID_MAX);
			sxe2_comm_fnav_msg_convert_fld(flds_bit, hdr);
			if (hdr->tunnel_level == SXE2_FNAV_TUNNEL_INNER) {
				(void)memcpy(filter->full_key.ip_inner.v6.src_ip,
					     &hdr->ipv6.src_ip,
					     sizeof(hdr->ipv6.src_ip));
				(void)memcpy(filter->full_key.ip_inner.v6.dst_ip,
					     &hdr->ipv6.dst_ip,
					     sizeof(hdr->ipv6.dst_ip));
				filter->full_key.ip_inner.v6.tc = hdr->ipv6.tc;
				filter->full_key.ip_inner.v6.proto = hdr->ipv6.proto;
				filter->full_key.ip_inner.v6.hlim = hdr->ipv6.hlim;
				if ((!test_bit(SXE2_FLOW_FLD_ID_IPV6_PROT,
					       flds_bit)) &&
				    filter->flow_type ==
						    SXE2_FNAV_FLOW_TYPE_IPV6_OTHER) {
					filter->full_key.ip_inner.v6.proto =
							IPPROTO_NONE;
				}
			} else {
				(void)memcpy(filter->full_key.ip.v6.src_ip,
					     &hdr->ipv6.src_ip,
					     sizeof(hdr->ipv6.src_ip));
				(void)memcpy(filter->full_key.ip.v6.dst_ip,
					     &hdr->ipv6.dst_ip,
					     sizeof(hdr->ipv6.dst_ip));
				filter->full_key.ip.v6.tc = hdr->ipv6.tc;
				filter->full_key.ip.v6.proto = hdr->ipv6.proto;
				filter->full_key.ip.v6.hlim = hdr->ipv6.hlim;
				if ((!test_bit(SXE2_FLOW_FLD_ID_IPV6_PROT,
					       flds_bit)) &&
				    filter->flow_type ==
						    SXE2_FNAV_FLOW_TYPE_IPV6_OTHER) {
					filter->full_key.ip.v6.proto = IPPROTO_NONE;
				}
			}
			break;
		case SXE2_FLOW_HDR_TCP:
		case SXE2_FLOW_HDR_UDP:
		case SXE2_FLOW_HDR_SCTP:
			if (hdr->tunnel_level == SXE2_FNAV_TUNNEL_INNER) {
				filter->full_key.l4_inner.src_port =
						hdr->l4.src_port;
				filter->full_key.l4_inner.dst_port =
						hdr->l4.dst_port;
			} else {
				filter->full_key.l4.src_port = hdr->l4.src_port;
				filter->full_key.l4.dst_port = hdr->l4.dst_port;
			}
			break;
		case SXE2_FLOW_HDR_VLAN:
			bitmap_zero(flds_bit, SXE2_FLOW_FLD_ID_MAX);
			sxe2_comm_fnav_msg_convert_fld(flds_bit, hdr);
			if (hdr->tunnel_level == SXE2_FNAV_TUNNEL_INNER) {
				if (test_bit(SXE2_FLOW_FLD_ID_S_TCI, flds_bit))
					filter->full_key.ext_data_inner.s_vlan_tci =
							hdr->vlan.vlan_tci;
				else if (test_bit(SXE2_FLOW_FLD_ID_C_TCI, flds_bit))
					filter->full_key.ext_data_inner.c_vlan_tci =
							hdr->vlan.vlan_tci;
				else if (test_bit(SXE2_FLOW_FLD_ID_S_VID, flds_bit))
					filter->full_key.ext_data_inner.s_vlan_vid =
							hdr->vlan.vlan_vid;
				else if (test_bit(SXE2_FLOW_FLD_ID_C_VID, flds_bit))
					filter->full_key.ext_data_inner.c_vlan_vid =
							hdr->vlan.vlan_vid;

				filter->full_key.ext_data_inner.vlan_type =
						hdr->vlan.vlan_type;
			} else {
				if (test_bit(SXE2_FLOW_FLD_ID_S_TCI, flds_bit))
					filter->full_key.ext_data.s_vlan_tci =
							hdr->vlan.vlan_tci;
				else if (test_bit(SXE2_FLOW_FLD_ID_C_TCI, flds_bit))
					filter->full_key.ext_data.c_vlan_tci =
							hdr->vlan.vlan_tci;
				else if (test_bit(SXE2_FLOW_FLD_ID_S_VID, flds_bit))
					filter->full_key.ext_data.s_vlan_vid =
							hdr->vlan.vlan_vid;
				else if (test_bit(SXE2_FLOW_FLD_ID_C_VID, flds_bit))
					filter->full_key.ext_data.c_vlan_vid =
							hdr->vlan.vlan_vid;

				filter->full_key.ext_data.vlan_type =
						hdr->vlan.vlan_type;
			}
			break;
		case SXE2_FLOW_HDR_VXLAN:
			filter->full_key.tunnel_data.vxlan_vni = hdr->vxlan.vni;
			break;
		case SXE2_FLOW_HDR_GENEVE:
			filter->full_key.tunnel_data.geneve_vni = hdr->geneve.vni;
			break;
		case SXE2_FLOW_HDR_GTPU:
			filter->full_key.tunnel_data.gtpu_teid = hdr->gtpu.teid;
			break;
		case SXE2_FLOW_HDR_GRE:
			filter->full_key.tunnel_data.gre_tni = hdr->gre.tni;
			break;
		case SXE2_FLOW_HDR_IPV_FRAG:
		case SXE2_FLOW_HDR_IPV_OTHER:
			break;
		default:
			return -EINVAL;
		}
	}
	return ret;
}

STATIC s32 sxe2_comm_fnav_filter_parse(struct sxe2_adapter *adapter,
				       struct sxe2_fnav_filter *filter,
				       u16 ori_vsi_id, u16 dst_vsi_id,
				       u16 rule_vsi_id,
				       struct sxe2_fnav_comm_full_msg *full_msg)
{
	s32 ret = 0;

	if (!adapter->vsi_ctxt.vsi[ori_vsi_id] ||
	    !adapter->vsi_ctxt.vsi[dst_vsi_id] ||
	    adapter->vsi_ctxt.vsi[ori_vsi_id]->idx_in_dev >= SXE2_VSI_NUM ||
	    adapter->vsi_ctxt.vsi[dst_vsi_id]->idx_in_dev >= SXE2_VSI_NUM) {
		return -EINVAL;
	}

	filter->ori_vsi_sw = ori_vsi_id;
	filter->ori_vsi_hw = adapter->vsi_ctxt.vsi[ori_vsi_id]->idx_in_dev;
	filter->dst_vsi_hw = adapter->vsi_ctxt.vsi[dst_vsi_id]->idx_in_dev;
	filter->rule_vsi_sw = rule_vsi_id;

	filter->flow_type = le32_to_cpu(full_msg->flow_type);

	ret = sxe2_comm_fnav_parse_proto(filter, full_msg);
	if (ret)
		return ret;

	if (full_msg->filter_loc != SXE2_VF_FNAV_INVALID_LOC) {
		filter->filter_loc = le32_to_cpu(full_msg->filter_loc);
		filter->fdid_prio = SXE2_FNAV_TX_DESC_QW1_FDID_PRIO_THREE;
	}

	filter->tunn_flag = (u8)(le32_to_cpu(full_msg->tunn_flag));

	filter->full_key.has_flex_filed =
			full_msg->usr_data.has_flex_filed == 1 ? true : false;
	filter->full_key.flex_offset = full_msg->usr_data.flex_offset;
	filter->full_key.flex_word = full_msg->usr_data.flex_word;

	filter->act_prio = SXE2_FNAV_TX_DESC_QW0_TOQ_PRIO_THREE;
	filter->complete_report = SXE2_FNAV_TX_DESC_QW0_COMP_RPT_FAIL;

	filter->fd_space = (u8)SXE2_FNAV_FD_SPACE_FROM_BEST_EFFORT;
	filter->tunn_fd_space = (u8)SXE2_FNAV_FD_SPACE_FROM_BEST_EFFORT;

	ret = sxe2_comm_fnav_parse_action(filter, full_msg);
	if (ret)
		return ret;

	INIT_HLIST_NODE(&filter->hl_node);

	LOG_INFO_BDF("sxe2 fnav parse patter success, flow type=%d, ori_vsi=%u, dst_vsi=%u,\n"
		     "act type=%d, q index=%u, loc=%u, hash flex=%u, tunn_flag=%u.\n",
		     filter->flow_type, filter->ori_vsi_hw, filter->dst_vsi_hw,
		     filter->act_type, filter->q_index, filter->filter_loc,
		     filter->full_key.has_flex_filed, filter->tunn_flag);

	return 0;
}

void sxe2_eth_fnav_outer_hdr_set_eth(enum sxe2_fnav_flow_type flow_type,
				     struct sxe2_fnav_flow_seg *seg_outer)
{
	if (sxe2_eth_fnav_support_flow_type(flow_type))
		set_bit(SXE2_FLOW_HDR_ETH, seg_outer->headers);
}

STATIC void sxe2_comm_fnav_seg_parse(struct sxe2_vsi *rule_vsi,
				     struct sxe2_fnav_comm_full_msg *full_msg,
				     struct sxe2_fnav_flow_seg *segs)
{
	struct sxe2_fnav_flow_seg *seg_outer = NULL;
	struct sxe2_fnav_flow_seg *seg_inner = NULL;
	struct sxe2_fnav_comm_proto_hdr *hdr = NULL;
	enum sxe2_flow_hdr hdr_type = 0;
	u32 i = 0;

	memset(segs, 0, sizeof(struct sxe2_fnav_flow_seg) * SXE2_FNAV_SEG_MAX);
	seg_outer = &segs[0];
	seg_inner = &segs[1];

	for (i = 0; i < full_msg->proto_cnt; i++) {
		hdr = &full_msg->proto_hdr[i];
		hdr_type = le32_to_cpu(hdr->type);
		if (hdr->tunnel_level == SXE2_FNAV_TUNNEL_OUTER ||
		    hdr->tunnel_level == SXE2_FNAV_TUNNEL_ANY) {
			set_bit((int)hdr_type, seg_outer->headers);
			sxe2_comm_fnav_msg_convert_fld(seg_outer->fields, hdr);
		}
		if (hdr->tunnel_level == SXE2_FNAV_TUNNEL_INNER ||
		    hdr->tunnel_level == SXE2_FNAV_TUNNEL_ANY) {
			set_bit((int)hdr_type, seg_inner->headers);
			sxe2_comm_fnav_msg_convert_fld(seg_inner->fields, hdr);
		}
	}

	if (rule_vsi->type == SXE2_VSI_T_VF)
		sxe2_eth_fnav_outer_hdr_set_eth(le32_to_cpu(full_msg->flow_type),
						seg_outer);

	if (full_msg->usr_data.has_flex_filed) {
		seg_outer->raw[0].offset = full_msg->usr_data.flex_offset;
		seg_outer->raw[0].len = SXE2_FNAV_FLEX_WROD_SIZE;
		seg_outer->raw_cnt = 1;

		seg_inner->raw[0].offset = full_msg->usr_data.flex_offset;
		seg_inner->raw[0].len = SXE2_FNAV_FLEX_WROD_SIZE;
		seg_inner->raw_cnt = 1;
	}
}

s32 sxe2_comm_add_fnav_filter(struct sxe2_adapter *adapter, u16 ori_vsi_id,
			      u16 dst_vsi_id, u16 rule_vsi_id,
			      struct sxe2_fnav_comm_full_msg *full_msg, u32 *flow_id)
{
	s32 ret = 0;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct sxe2_vsi *ori_vsi = NULL;
	struct sxe2_vsi *rule_vsi = NULL;
	struct sxe2_fnav_filter *filter = NULL;
	struct sxe2_fnav_flow_seg segs[SXE2_FNAV_SEG_MAX];
	u32 need_filter = 0;
	struct sxe2_fnav_filter *dup_filter = NULL;

	mutex_lock(&adapter->vsi_ctxt.lock);
	ori_vsi = adapter->vsi_ctxt.vsi[ori_vsi_id];
	rule_vsi = adapter->vsi_ctxt.vsi[rule_vsi_id];

	if (!ori_vsi || !rule_vsi) {
		LOG_ERROR_BDF("vsi is null.\n");
		ret = -EINVAL;
		goto l_end;
	}

	filter = devm_kzalloc(dev, sizeof(*filter), GFP_KERNEL);
	if (!filter) {
		LOG_ERROR_BDF("no memory.\n");
		ret = -ENOMEM;
		goto l_end;
	}

	ret = sxe2_comm_fnav_filter_parse(adapter, filter, ori_vsi_id, dst_vsi_id,
					  rule_vsi_id, full_msg);
	if (ret) {
		LOG_ERROR_BDF("sxe2 fnav parse pattern fail ret: %d ! vsi type: %u, idx: %u\n",
			      ret, rule_vsi->type, rule_vsi->id_in_pf);
		goto l_end;
	}

	need_filter = filter->tunn_flag == SXE2_FNAV_TUN_FLAG_ANY ? 2 : 1;
	if (sxe2_fnav_num_avail_filter(ori_vsi) < need_filter) {
		LOG_ERROR_BDF("sxe2 fnav do not has avail filter.\n");
		ret = -ENOSPC;
		goto l_end;
	}

	mutex_lock(&adapter->fnav_ctxt.filter_lock);

	dup_filter = sxe2_comm_fnav_filter_search_for_dup(rule_vsi, filter);
	if (dup_filter && dup_filter->ori_vsi_hw == filter->ori_vsi_hw) {
		LOG_ERROR_BDF("sxe2 fnav has dup filter.\n");
		ret = -EEXIST;
		goto l_unlock;
	}

	sxe2_comm_fnav_seg_parse(rule_vsi, full_msg, segs);

	ret = sxe2_fnav_filter_add_hw(ori_vsi, filter, segs);
	if (ret) {
		LOG_ERROR_BDF("sxe2 fnav add filter fail ret: %d ! vsi type: %u, idx: %u\n",
			      ret, rule_vsi->type, rule_vsi->id_in_pf);
		goto l_unlock;
	}

	sxe2_fnav_filter_add_list(rule_vsi, filter, flow_id);

l_unlock:
	mutex_unlock(&adapter->fnav_ctxt.filter_lock);
l_end:
	if (ret && filter)
		devm_kfree(dev, filter);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}
