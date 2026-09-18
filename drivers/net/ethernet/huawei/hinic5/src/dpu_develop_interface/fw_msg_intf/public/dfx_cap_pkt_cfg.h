/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : dfx_cap_pkt_cfg.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : capture packet config
 */

#ifndef SML_TABLE_CAP_PKT_CFG_H
#define SML_TABLE_CAP_PKT_CFG_H

#include "typedef.h"

/**
 * Struct name:    sml_glb_tbl_cap_pkt_cfg_s
 * Structure type of the @brief microcode capture packet information
 * Data structure of the index 4 table in the Description: global configuration table
 */
typedef struct tag_sml_glb_tbl_cap_pkt_cfg {
	struct {
#if (BYTE_ORDER == BIG_ENDIAN)
	u32 cap_en : 1;
	u32 function_id : 1;
	u32 sip : 1;
	u32 dip : 1;
	u32 seid : 1;
	u32 deid : 1;
	u32 sport : 1;
	u32 dport : 1;
	u32 vni : 1;
	u32 vlan : 1;
	u32 len : 1;
	u32 port_id : 1;
	u32 upi : 1;
	u32 sjetty : 1;
	u32 opcode : 1;
	u32 dst_qpn : 1;
	u32 txrx : 1;    // UB: when mask not configured, capture both tx and rx; RoCE: when mask not configured, only capture tx by default
	u32 mac : 1;
	u32 next_ext_hdr : 1;   // Externally presented as protocol-defined bth_rsvd7, current implementation is next_ext_hdr
	u32 rsvd : 13;
#else
	u32 rsvd : 13;
	u32 next_ext_hdr : 1;
	u32 mac : 1;
	u32 txrx : 1;
	u32 dst_qpn : 1;
	u32 opcode : 1;
	u32 sjetty : 1;
	u32 upi : 1;
	u32 port_id : 1;
	u32 len : 1;
	u32 vlan : 1;
	u32 vni : 1;
	u32 dport : 1;
	u32 sport : 1;
	u32 deid : 1;
	u32 seid : 1;
	u32 dip : 1;
	u32 sip : 1;
	u32 function_id : 1;
	u32 cap_en : 1;
#endif
	} mask;

	union {
	struct {
		u32 sip_seid0;    // ip: ip layer, eid: tp layer
		u32 sip_seid1;    // ip: ip layer, eid: tp layer
		u32 sip_seid2;    // ip: ip layer, eid: tp layer
		u32 sip_seid3;    // ip: ip layer, eid: tp layer
	};
	struct {
		u8 mac[6]; // only used by 1872
		u8 rsv3[10];
	};
	u32 sip_seid[4];
	};

	union {
	struct {
		u32 dip_deid0;
		u32 dip_deid1;
		u32 dip_deid2;
		u32 dip_deid3;
	};
	u32 dip_deid[4];
	};

#if (BYTE_ORDER == BIG_ENDIAN)
	u32 function_id : 12;
	u32 vlan : 12;
	u32 len : 8;
#else
	u32 len : 8;            // capture packet length
	u32 vlan : 12;          // link layer
	u32 function_id : 12;   // vf id
#endif

#if (BYTE_ORDER == BIG_ENDIAN)
	u32 sport : 16;
	u32 dport : 16;
#else
	u32 dport : 16;     // tcp/udp layer
	u32 sport : 16;
#endif

#if (BYTE_ORDER == BIG_ENDIAN)
	u32 port_id : 3;
	u32 ip_type : 1;    // 0 ipv4  1 ipv6
	u32 report_host_id      : 3;
	u32 report_function_id  : 5;  // PF
	u32 report_ep           : 3;
	u32 report_cos          : 3;
	u32 txrx : 2;        // 0: rx capture 1: tx capture 2: capture both tx and rx
	u32 rsv : 12;
#else
	u32 rsv : 12;
	u32 txrx : 2;
	u32 report_cos          : 3;
	u32 report_ep           : 3;
	u32 report_function_id  : 5;  // PF
	u32 report_host_id      : 3;
	u32 ip_type : 1;    // 0 ipv4  1 ipv6
	u32 port_id : 3;    // physical network port
#endif

	u32 upi_vni;            // tp layer upi or vxlan, ub does not support vxlan

#if (BYTE_ORDER == BIG_ENDIAN)
	u32 sjetty_id   : 20;
	u32 opcode : 8;
	u32 rsv2 : 4;
#else
	u32 rsv2 : 4;
	u32 opcode : 8;
	u32 sjetty_id   : 20;          // ta layer local jetty/jfs id
#endif

	u32 dst_qpn;

#if (BYTE_ORDER == BIG_ENDIAN)
	u32 next_ext_hdr : 7;
	u32 rsv4 : 25;
#else
	u32 rsv4 : 25;
	u32 next_ext_hdr : 7;
#endif
} sml_glb_tbl_cap_pkt_cfg_s;

#endif /* SML_TABLE_CAP_PKT_CFG_H */
