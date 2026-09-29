// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_tc_lib.h"
#include "mce_lib.h"
#include "mce_fltr.h"
#include "mce_pattern.h"
#include "mce_parse.h"
#include "mce_switch.h"
#include "mce_fdir_flow.h"
#include "mce_profile_mask.h"

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)

struct mce_profile_options_mask {
	u64 options;

	u32 field_mask;
};

#define MCE_FIELD_M_IP4_SIP BIT(0)
#define MCE_FIELD_M_IP4_DIP BIT(1)
#define MCE_FIELD_M_IP6_SIP (BIT(0) | BIT(5))
#define MCE_FIELD_M_IP6_DIP (BIT(1) | BIT(6))
#define MCE_FIELD_M_L4_PROTO BIT(2)
#define MCE_FIELD_M_L4_SPORT BIT(2)
#define MCE_FIELD_M_L4_DPORT BIT(3)
#define MCE_FIELD_M_TEID BIT(4)
#define MCE_FIELD_M_DSCP BIT(4)
#define MCE_FIELD_M_VNI BIT(4)
#define MCE_FIELD_M_NVGRE_TNI BIT(4)
#define MCE_FIELD_M_ESP_SPI (BIT(2) | BIT(3))

#define MCE_FIELD_M_ETH_VLAN BIT(0)
#define MCE_FIELD_M_ETH_SMAC (BIT(1) | BIT(2))
#define MCE_FIELD_M_ETH_DMAC (BIT(3) | BIT(4))
#define MCE_FIELD_M_ETH_TYPE BIT(0)

static struct mce_profile_options_mask mce_dummy_todo[] = {
	{ 0, 0 },
};

static struct mce_profile_options_mask mce_ipv4_tcp_sync[] = {
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_TCP_DPORT, MCE_FIELD_M_L4_DPORT },
};

static struct mce_profile_options_mask mce_ipv4_tcp[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_TCP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_TCP_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};

static struct mce_profile_options_mask mce_ipv4_udp[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_UDP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_UDP_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};

static struct mce_profile_options_mask mce_ipv4_sctp[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_SCTP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_SCTP_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};

static struct mce_profile_options_mask mce_ipv4_esp[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_ESP_SPI, MCE_FIELD_M_ESP_SPI },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};

static struct mce_profile_options_mask mce_ipv4_pay[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_L4_PROTO, MCE_FIELD_M_L4_PROTO },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};

static struct mce_profile_options_mask mce_ipv4_frag[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_IPV4_FRAG, 0 },
};

static struct mce_profile_options_mask mce_ipv4_vxlan[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_VXLAN_VNI, MCE_FIELD_M_VNI },
};

static struct mce_profile_options_mask mce_ipv4_geneve[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GENEVE_VNI, MCE_FIELD_M_VNI },
};

static struct mce_profile_options_mask mce_ipv4_nvgre[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_NVGRE_TNI, MCE_FIELD_M_NVGRE_TNI },
};

static struct mce_profile_options_mask mce_ipv4_gtpu[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GTP_U_TEID, MCE_FIELD_M_TEID },
};

static struct mce_profile_options_mask mce_ipv4_gtpc[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GTP_C_TEID, MCE_FIELD_M_TEID },
};

static struct mce_profile_options_mask mce_ipv6_tcp_sync[] = {
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_TCP_DPORT, MCE_FIELD_M_L4_DPORT },
};

static struct mce_profile_options_mask mce_ipv6_tcp[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_TCP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_TCP_DPORT, MCE_FIELD_M_L4_DPORT },
};

static struct mce_profile_options_mask mce_ipv6_udp[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_UDP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_UDP_DPORT, MCE_FIELD_M_L4_DPORT },
};

static struct mce_profile_options_mask mce_ipv6_sctp[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_SCTP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_SCTP_DPORT, MCE_FIELD_M_L4_DPORT },
};

static struct mce_profile_options_mask mce_ipv6_esp[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_ESP_SPI, MCE_FIELD_M_ESP_SPI },
};

static struct mce_profile_options_mask mce_ipv6_pay[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_L4_PROTO, MCE_FIELD_M_L4_PROTO },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
};

static struct mce_profile_options_mask mce_ipv6_frag[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_IPV6_FRAG, 0 },
};

static struct mce_profile_options_mask mce_ipv6_vxlan[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_VXLAN_VNI, MCE_FIELD_M_VNI },
};

static struct mce_profile_options_mask mce_ipv6_geneve[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GENEVE_VNI, MCE_FIELD_M_VNI },
};

static struct mce_profile_options_mask mce_ipv6_nvgre[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_NVGRE_TNI, MCE_FIELD_M_NVGRE_TNI },
};

static struct mce_profile_options_mask mce_ipv6_gtpu[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GTP_U_TEID, MCE_FIELD_M_TEID },
};

static struct mce_profile_options_mask mce_ipv6_gtpc[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GTP_C_TEID, MCE_FIELD_M_TEID },
};

static struct mce_profile_options_mask mce_l2_eth[] = {
	{ MCE_OPT_VLAN_VID, MCE_FIELD_M_ETH_VLAN },
	{ MCE_OPT_SMAC, MCE_FIELD_M_ETH_SMAC },
	{ MCE_OPT_DMAC, MCE_FIELD_M_ETH_DMAC },
};

static struct mce_profile_options_mask mce_l2_ethtype[] = {
	{ MCE_OPT_ETHTYPE, MCE_FIELD_M_ETH_TYPE },
};

struct mce_profile_select_db {
	u64 profile_id;
	struct mce_profile_options_mask *options_list;
	u16 sup_options_num;
};

static struct mce_profile_select_db mce_profile_bitmask[] = {
	{ MCE_PTYPE_UNKNOWN, mce_dummy_todo,
	  ARRAY_SIZE(mce_dummy_todo) }, /* 0 */
	{ MCE_PTYPE_L2_ONLY, mce_l2_eth, ARRAY_SIZE(mce_l2_eth) }, /* 1 */
	{ MCE_PTYPE_TUN_INNER_L2_ONLY, mce_l2_eth,
	  ARRAY_SIZE(mce_l2_eth) }, /* 2 */
	{ MCE_PTYPE_TUN_OUTER_L2_ONLY, mce_l2_eth,
	  ARRAY_SIZE(mce_l2_eth) }, /* 3 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_FRAG, mce_ipv4_frag,
	  ARRAY_SIZE(mce_ipv4_frag) }, /* 4 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_FRAG, mce_ipv6_frag,
	  ARRAY_SIZE(mce_ipv6_frag) }, /* 5 */
	{ MCE_PTYPE_L2_ETHTYPE, mce_l2_ethtype,
	  ARRAY_SIZE(mce_l2_ethtype) }, /* 6 */
	{ MCE_PTYPE_TUN_INNER_L2_ETHTYPE, mce_l2_ethtype,
	  ARRAY_SIZE(mce_l2_ethtype) }, /* 7 */
	{ MCE_PTYPE_IPV4_FRAG, mce_ipv4_frag,
	  ARRAY_SIZE(mce_ipv4_frag) }, /* 8*/
	{ MCE_PTYPE_IPV4_TCP_SYNC, mce_ipv4_tcp_sync,
	  ARRAY_SIZE(mce_ipv4_tcp_sync) }, /* 9 */
	{ MCE_PTYPE_IPV4_TCP, mce_ipv4_tcp,
	  ARRAY_SIZE(mce_ipv4_tcp) }, /* 10 */
	{ MCE_PTYPE_IPV4_UDP, mce_ipv4_udp,
	  ARRAY_SIZE(mce_ipv4_udp) }, /* 11 */
	{ MCE_PTYPE_IPV4_SCTP, mce_ipv4_sctp,
	  ARRAY_SIZE(mce_ipv4_sctp) }, /* 12 */
	{ MCE_PTYPE_IPV4_ESP, mce_ipv4_esp,
	  ARRAY_SIZE(mce_ipv4_esp) }, /* 13 */
	{ MCE_PTYPE_IPV4_PAY, mce_ipv4_pay,
	  ARRAY_SIZE(mce_ipv4_pay) }, /* 14 */
	{ 0, NULL }, /* 15 */
	{ MCE_PTYPE_IPV6_FRAG, mce_ipv6_frag,
	  ARRAY_SIZE(mce_ipv6_frag) }, /* 16 */
	{ MCE_PTYPE_IPV6_TCP_SYNC, mce_ipv6_tcp_sync,
	  ARRAY_SIZE(mce_ipv6_tcp_sync) }, /* 17 */
	{ MCE_PTYPE_IPV6_TCP, mce_ipv6_tcp,
	  ARRAY_SIZE(mce_ipv6_tcp) }, /* 18 */
	{ MCE_PTYPE_IPV6_UDP, mce_ipv6_udp,
	  ARRAY_SIZE(mce_ipv6_udp) }, /* 19 */
	{ MCE_PTYPE_IPV6_SCTP, mce_ipv6_sctp,
	  ARRAY_SIZE(mce_ipv6_sctp) }, /* 20 */
	{ MCE_PTYPE_IPV6_ESP, mce_ipv6_esp,
	  ARRAY_SIZE(mce_ipv6_esp) }, /* 21 */
	{ MCE_PTYPE_IPV6_PAY, mce_ipv6_pay,
	  ARRAY_SIZE(mce_ipv6_pay) }, /* 22 */
	{ 0, NULL }, /* 23 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_PAY, mce_ipv4_pay,
	  ARRAY_SIZE(mce_ipv4_pay) }, /* 24 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_TCP, mce_ipv4_tcp,
	  ARRAY_SIZE(mce_ipv4_tcp) }, /* 25 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_UDP, mce_ipv4_udp,
	  ARRAY_SIZE(mce_ipv4_udp) }, /* 26 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_SCTP, mce_ipv4_sctp,
	  ARRAY_SIZE(mce_ipv4_sctp) }, /* 27 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_PAY, mce_ipv6_pay,
	  ARRAY_SIZE(mce_ipv6_pay) }, /* 28 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_TCP, mce_ipv6_tcp,
	  ARRAY_SIZE(mce_ipv6_tcp) }, /* 29 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_UDP, mce_ipv6_udp,
	  ARRAY_SIZE(mce_ipv6_udp) }, /* 30 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_SCTP, mce_ipv6_sctp,
	  ARRAY_SIZE(mce_ipv6_sctp) }, /* 31 */
	{ MCE_PTYPE_GTP_U_GPDU_IPV4, mce_ipv4_gtpu,
	  ARRAY_SIZE(mce_ipv4_gtpu) }, /* 32 */
	{ MCE_PTYPE_GTP_U_IPV4, mce_ipv4_gtpu,
	  ARRAY_SIZE(mce_ipv4_gtpu) }, /* 33 */
	{ MCE_PTYPE_GTP_C_TEID_IPV4, mce_ipv4_gtpc,
	  ARRAY_SIZE(mce_ipv4_gtpc) }, /* 34 */
	{ MCE_PTYPE_GTP_C_IPV4, mce_ipv4_udp,
	  ARRAY_SIZE(mce_ipv4_udp) }, /* 35 */
	{ MCE_PTYPE_GTP_U_GPDU_IPV6, mce_ipv6_gtpu,
	  ARRAY_SIZE(mce_ipv6_gtpu) }, /* 36 */
	{ MCE_PTYPE_GTP_U_IPV6, mce_ipv6_gtpu,
	  ARRAY_SIZE(mce_ipv6_gtpu) }, /* 37 */
	{ MCE_PTYPE_GTP_C_TEID_IPV6, mce_ipv6_gtpc,
	  ARRAY_SIZE(mce_ipv6_gtpc) }, /* 38 */
	{ MCE_PTYPE_GTP_C_IPV6, mce_ipv6_udp,
	  ARRAY_SIZE(mce_ipv6_udp) }, /* 39 */
	{ MCE_PTYPE_TUN_INNER_IPV4_FRAG, mce_ipv4_frag,
	  ARRAY_SIZE(mce_ipv4_frag) }, /* 40 */
	{ MCE_PTYPE_TUN_INNER_IPV4_TCP_SYNC, mce_ipv4_tcp_sync,
	  ARRAY_SIZE(mce_ipv4_tcp_sync) }, /* 41 */
	{ MCE_PTYPE_TUN_INNER_IPV4_TCP, mce_ipv4_tcp,
	  ARRAY_SIZE(mce_ipv4_tcp) }, /* 42 */
	{ MCE_PTYPE_TUN_INNER_IPV4_UDP, mce_ipv4_udp,
	  ARRAY_SIZE(mce_ipv4_udp) }, /* 43 */
	{ MCE_PTYPE_TUN_INNER_IPV4_SCTP, mce_ipv4_sctp,
	  ARRAY_SIZE(mce_ipv4_sctp) }, /* 44 */
	{ MCE_PTYPE_TUN_INNER_IPV4_ESP, mce_ipv4_esp,
	  ARRAY_SIZE(mce_ipv4_esp) }, /* 45 */
	{ MCE_PTYPE_TUN_INNER_IPV4_PAY, mce_ipv4_pay,
	  ARRAY_SIZE(mce_ipv4_pay) }, /* 46 */
	{ 0, NULL }, /* 47 */
	{ MCE_PTYPE_TUN_INNER_IPV6_FRAG, mce_ipv6_frag,
	  ARRAY_SIZE(mce_ipv6_frag) }, /* 48 */
	{ MCE_PTYPE_TUN_INNER_IPV6_TCP_SYNC, mce_ipv6_tcp_sync,
	  ARRAY_SIZE(mce_ipv6_tcp_sync) }, /* 49 */
	{ MCE_PTYPE_TUN_INNER_IPV6_TCP, mce_ipv6_tcp,
	  ARRAY_SIZE(mce_ipv6_tcp) }, /* 50 */
	{ MCE_PTYPE_TUN_INNER_IPV6_UDP, mce_ipv6_udp,
	  ARRAY_SIZE(mce_ipv6_udp) }, /* 51 */
	{ MCE_PTYPE_TUN_INNER_IPV6_SCTP, mce_ipv6_sctp,
	  ARRAY_SIZE(mce_ipv6_sctp) }, /* 52 */
	{ MCE_PTYPE_TUN_INNER_IPV6_ESP, mce_ipv6_esp,
	  ARRAY_SIZE(mce_ipv6_esp) }, /* 53 */
	{ MCE_PTYPE_TUN_INNER_IPV6_PAY, mce_ipv6_pay,
	  ARRAY_SIZE(mce_ipv6_pay) }, /* 54 */
	{ 0, NULL }, /* 55 */
	{ MCE_PTYPE_TUN_IPV4_VXLAN, mce_ipv4_vxlan,
	  ARRAY_SIZE(mce_ipv4_vxlan) }, /* 56 */
	{ MCE_PTYPE_TUN_IPV4_GENEVE, mce_ipv4_geneve,
	  ARRAY_SIZE(mce_ipv4_geneve) }, /* 57 */
	{ MCE_PTYPE_TUN_IPV4_GRE, mce_ipv4_nvgre,
	  ARRAY_SIZE(mce_ipv4_nvgre) }, /* 58 */
	{ 0, NULL }, /* 59 */
	{ MCE_PTYPE_TUN_IPV6_VXLAN, mce_ipv6_vxlan,
	  ARRAY_SIZE(mce_ipv6_vxlan) }, /* 60 */
	{ MCE_PTYPE_TUN_IPV6_GENEVE, mce_ipv6_geneve,
	  ARRAY_SIZE(mce_ipv6_geneve) }, /* 61 */
	{ MCE_PTYPE_TUN_IPV6_GRE, mce_ipv6_nvgre,
	  ARRAY_SIZE(mce_ipv6_nvgre) }, /* 62 */
};

struct mce_profile_field_mask {
	u64 options;
	u16 bit_val;
};

struct mce_field_mask {
	u16 offset;
	u16 key_off;
	u8 mask_block[16];
	u16 mask_wide;
	u64 mask_options;
};

static const struct mce_field_mask mce_eth_mask[] = {
	{
		__builtin_offsetof(struct mce_ether_meta, src_addr),
		4,
		"\xff\xff\xff\xff\xff\xff",
		6,
		MCE_OPT_SMAC,
	},
	{
		__builtin_offsetof(struct mce_ether_meta, dst_addr),
		10,
		"\xff\xff\xff\xff\xff\xff",
		6,
		MCE_OPT_DMAC,
	},
	{
		__builtin_offsetof(struct mce_ether_meta, ethtype_id),
		0,
		"\xff\xff",
		2,
		MCE_OPT_ETHTYPE,
	},
};

static const struct mce_field_mask mce_ipv4_mask[] = {
	{ __builtin_offsetof(struct mce_ipv4_meta, src_addr),
	  0,
	  { "\xff\xff\xff\xff" },
	  4,
	  MCE_OPT_IPV4_SIP },
	{ __builtin_offsetof(struct mce_ipv4_meta, dst_addr),
	  4,
	  { "\xff\xff\xff\xff" },
	  4,
	  MCE_OPT_IPV4_DIP },
	{ __builtin_offsetof(struct mce_ipv4_meta, protocol),
	  8,
	  { "\xff" },
	  1,
	  MCE_OPT_L4_PROTO },
	{
		__builtin_offsetof(struct mce_ipv4_meta, dscp),
		12,
		{ "\xfc" },
		1,
		MCE_OPT_IPV4_DSCP,
	},
	{
		__builtin_offsetof(struct mce_ipv4_meta, is_frag),
		0,
		{ "\x00" },
		1,
		MCE_OPT_IPV4_FRAG,
	},
};

static const struct mce_field_mask mce_tcp_mask[] = {
	{ __builtin_offsetof(struct mce_tcp_meta, src_port),
	  8,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_TCP_SPORT },
	{ __builtin_offsetof(struct mce_tcp_meta, dst_port),
	  10,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_TCP_DPORT },
};

static const struct mce_field_mask mce_udp_mask[] = {
	{ __builtin_offsetof(struct mce_udp_meta, src_port),
	  8,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_UDP_SPORT },
	{ __builtin_offsetof(struct mce_udp_meta, dst_port),
	  10,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_UDP_DPORT },
};

static const struct mce_field_mask mce_sctp_mask[] = {
	{ __builtin_offsetof(struct mce_sctp_meta, src_port),
	  8,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_SCTP_SPORT },
	{ __builtin_offsetof(struct mce_sctp_meta, dst_port),
	  10,
	  { "\xff\xff\xff\xff" },
	  2,
	  MCE_OPT_SCTP_DPORT },
};

static const struct mce_field_mask mce_ipv6_mask[] = {
	{ __builtin_offsetof(struct mce_ipv6_meta, src_addr),
	  0,
	  { "\xff\xff\xff\xff\xff\xff\xff\xff"
	    "\xff\xff\xff\xff\xff\xff\xff\xff" },
	  16,
	  MCE_OPT_IPV6_SIP },
	{ __builtin_offsetof(struct mce_ipv6_meta, dst_addr),
	  4,
	  { "\xff\xff\xff\xff\xff\xff\xff\xff"
	    "\xff\xff\xff\xff\xff\xff\xff\xff" },
	  16,
	  MCE_OPT_IPV6_DIP },
	{ __builtin_offsetof(struct mce_ipv6_meta, protocol),
	  8,
	  { "\xff" },
	  1,
	  MCE_OPT_L4_PROTO },
	{ __builtin_offsetof(struct mce_ipv6_meta, dscp),
	  12,
	  { "\xfc" },
	  1,
	  MCE_OPT_IPV6_DSCP },
	{
		__builtin_offsetof(struct mce_ipv6_meta, is_frag),
		0,
		{ "\x00" },
		1,
		MCE_OPT_IPV6_FRAG,
	},
};

static const struct mce_field_mask mce_esp_mask[] = {
	{ __builtin_offsetof(struct mce_esp_meta, spi),
	  8,
	  { "\xff\xff\xff\xff" },
	  4,
	  MCE_OPT_ESP_SPI },
};

static const struct mce_field_mask mce_vxlan_mask[] = {
	{ __builtin_offsetof(struct mce_vxlan_meta, vni),
	  12,
	  { "\xff\xff\xff\x00" },
	  4,
	  MCE_OPT_VXLAN_VNI },
};

static const struct mce_field_mask mce_geneve_mask[] = {
	{ __builtin_offsetof(struct mce_geneve_meta, vni),
	  12,
	  { "\xff\xff\xff\x00" },
	  4,
	  MCE_OPT_GENEVE_VNI },
};

static const struct mce_field_mask mce_nvgre_mask[] = {
	{ __builtin_offsetof(struct mce_nvgre_meta, key),
	  12,
	  { "\xff\xff\xff\x00" },
	  4,
	  MCE_OPT_NVGRE_TNI },
};

static const struct mce_field_mask mce_gtp_mask[] = {
	{ __builtin_offsetof(struct mce_gtp_meta, teid),
	  12,
	  { "\xff\xff\xff\xff" },
	  4,
	  MCE_OPT_GTP_U_TEID },
};

struct mce_field_mask_select_db {
	u16 type;
	const struct mce_field_mask *options_list;
	u16 sup_options_num;
};

static struct mce_field_mask_select_db mce_field_mask_db[] = {
	{ MCE_ETH_META, mce_eth_mask, ARRAY_SIZE(mce_eth_mask) },
	{ 0, NULL, 0 },
	{ MCE_IPV4_META, mce_ipv4_mask, ARRAY_SIZE(mce_ipv4_mask) },
	{ MCE_IPV6_META, mce_ipv6_mask, ARRAY_SIZE(mce_ipv6_mask) },
	{ 0, NULL, 0 },
	{ MCE_UDP_META, mce_udp_mask, ARRAY_SIZE(mce_udp_mask) },
	{ MCE_TCP_META, mce_tcp_mask, ARRAY_SIZE(mce_tcp_mask) },
	{ MCE_SCTP_META, mce_sctp_mask, ARRAY_SIZE(mce_sctp_mask) },
	{ MCE_ESP_META, mce_esp_mask, ARRAY_SIZE(mce_esp_mask) },
	{ MCE_VXLAN_META, mce_vxlan_mask, ARRAY_SIZE(mce_vxlan_mask) },
	{ MCE_GENEVE_META, mce_geneve_mask, ARRAY_SIZE(mce_geneve_mask) },
	{ MCE_NVGRE_META, mce_nvgre_mask, ARRAY_SIZE(mce_nvgre_mask) },
	{ MCE_GTPU_META, mce_gtp_mask, ARRAY_SIZE(mce_gtp_mask) },
	{ MCE_GTPC_META, mce_gtp_mask, ARRAY_SIZE(mce_gtp_mask) },
};

int mce_check_conflct_filed_bitmask(struct mce_hw_profile *profile,
				    struct mce_field_bitmask_info *mask_info)
{
	struct mce_field_bitmask_block *src, *dst;
	bool new_mask = false;
	int i = 0;

	if (mask_info->used_block != profile->mask_info->used_block)
		return -EINVAL;

	for (i = 0; i < mask_info->used_block; i++) {
		dst = &profile->mask_info->field_bitmask[i];
		src = &mask_info->field_bitmask[i];
		if (src->key_off != dst->key_off ||
		    src->mask != dst->mask ||
		    src->options != dst->options) {
			new_mask = true;
		}
	}
	if (new_mask)
		return -EINVAL;

	return 0;
}

static bool mce_fdir_profile_bitmask_match(struct mce_hw_profile *profile,
					   struct mce_field_bitmask_info *mask_info)
{
	if (!profile->mask_info && !mask_info)
		return true;

	if (!profile->mask_info || !mask_info)
		return false;

	return !mce_check_conflct_filed_bitmask(profile, mask_info);
}

int mce_prof_bitmask_alloc(struct mce_hw *hw,
			   struct mce_fdir_handle *handle,
			   struct mce_field_bitmask_info *mask_info)
{
	struct mce_field_bitmask_block *block;
	u64 field_bitmask_opt = 0;
	int i = 0, j = 0;

	for (i = 0; i < mask_info->used_block; i++) {
		block = &mask_info->field_bitmask[i];
		for (j = 0; j < 32; j++) {
			if (handle->field_mask[j].used) {
				if (handle->field_mask[j].key_off ==
					    block->key_off &&
				    handle->field_mask[j].mask ==
					    block->mask) {
					field_bitmask_opt |= BIT(j);
					handle->field_mask[j].ref_count++;
					break;
				}
			} else {
				handle->field_mask[j].key_off =
					block->key_off;
				handle->field_mask[j].mask = block->mask;
				handle->field_mask[j].used = 1;
				handle->field_mask[j].ref_count++;
				field_bitmask_opt |= BIT(j);
				hw->ops->fd_field_bitmask_setup(hw, &handle->field_mask[j], j);
				break;
			}
		}
	}

	return field_bitmask_opt;
}

static u64 mce_fdir_get_profile_field_mask(struct mce_fdir_filter *filter)
{
	struct mce_profile_select_db *profile_db = NULL;
	u32 profile_id = filter->profile_id;
	u64 options = filter->options;
	u64 fied_mask = 0;
	int bit_num = 0;
	int i, j, bit;

	profile_db = &mce_profile_bitmask[profile_id];
	bit_num = __user_popcount(options);
	fd_logd(LOG_FDIR_DEBUG, "profile_id:0x%x options:0x%llx bit_num:%d\n",
		profile_id, options, bit_num);

	for (i = 0; i < bit_num; i++) {
		bit = __ffs64(options);
		if (bit < 0)
			break;
		for (j = 0; j < profile_db->sup_options_num; j++) {
			if (BIT_ULL(bit) ==
			    profile_db->options_list[j].options) {
				fied_mask |=
					profile_db->options_list[j].field_mask;
			}
			fd_logd(LOG_FDIR_DEBUG,
				"profile_id:0x%x i:%d bit:%d j:%d db:0x%llx fied_mask:0x%llx\n",
			     profile_id, i, bit, j,
			     profile_db->options_list[j].options, fied_mask);
		}
		options &= ~BIT_ULL(bit);
	}
	return fied_mask;
}

int mce_conflict_profile_check(struct mce_fdir_handle *handle,
			       struct mce_fdir_filter *filter)
{
	u64 profile_id = filter->profile_id;
	struct mce_hw_profile *profile;
	u64 field_mask = 0;

	profile = handle->profiles[profile_id];
	if (!profile)
		return 0;

	if (profile->ref_cnt) {
		field_mask = mce_fdir_get_profile_field_mask(filter);
		if (profile->fied_mask == field_mask)
			return -EBUSY;
	} else {
		kfree(profile);
		handle->profiles[profile_id] = NULL;
	}
	return 0;
}

bool mce_fdir_profile_mask_conflict(struct mce_fdir_handle *handle,
				    struct mce_fdir_filter *filter)
{
	struct mce_hw_profile *profile;
	u64 field_mask;

	if (!handle || !filter || filter->profile_id >= 64)
		return true;

	profile = handle->profiles[filter->profile_id];
	if (!profile || !profile->ref_cnt)
		return false;

	field_mask = mce_fdir_get_profile_field_mask(filter);
	if (profile->fied_mask != field_mask)
		return true;

	return !mce_fdir_profile_bitmask_match(profile, filter->mask_info);
}

int mce_check_field_bitmask_valid(struct mce_lkup_meta *meta)
{
	union mce_flow_hdr *mask = &meta->mask;
	const struct mce_field_mask *field_opt;
	enum flow_meta_type type = meta->type;
	union mce_flow_hdr zero_mask = {};
	const char all_zero[256] = {};
	int i = 0, j = 0;
	u8 *ptr = NULL;
	u16 block = 0;

	if (meta->type >= MCE_META_TYPE_MAX)
		return 0;

	field_opt = mce_field_mask_db[type].options_list;
	if (!memcmp(&zero_mask, mask, sizeof(*mask)))
		return 0;
	ptr = (u8 *)mask;
	for (i = 0; i < mce_field_mask_db[type].sup_options_num;
	     i++, field_opt++) {
		if (!memcmp(all_zero, (ptr + field_opt->offset),
			    field_opt->mask_wide))
			continue;
		if (!memcmp((void const *)field_opt->mask_block,
			    (ptr + field_opt->offset),
			    field_opt->mask_wide))
			continue;
		if (field_opt->mask_wide > 1) {
			u16 *fv =
				(u16 *)(((u8 *)mask) + field_opt->offset);
			for (j = 0; j < field_opt->mask_wide / 2; j++) {
				if (fv[j] != 0xffff)
					block++;
			}
		} else {
			if (!memcmp((u8 *)mask + field_opt->offset,
				    &field_opt->mask_block, 1))
				continue;
			block++;
		}
	}

	return block;
}

int mce_fdir_field_mask_init(struct mce_lkup_meta *meta, u16 meta_num,
			     struct mce_field_bitmask_info *mask_info)
{
	struct mce_field_bitmask_block *block_mask = NULL;
	u16 field_size = 0, *fv, block = 0, type = 0;
	const struct mce_field_mask *field_opt;
	const char all_zero[256] = {};
	union mce_flow_hdr *mask;
	int i = 0, j = 0, k = 0;
	u8 *ptr = NULL;

	/* ipv6-[3] ipv6[2] ipv6[1]--- ipv6-sip[0] */
	/*                        |< 96 >|  32     */
	/*                        |   6   |   2    */
	/*                        | 128          | */
	/* 13 12 11 10 | 9 8 |765 432  | 1	0 |*/
	block_mask = mask_info->field_bitmask;
	for (i = 0; i < meta_num; i++) {
		type = meta[i].type;
		mask = &meta[i].mask;
		if (type == MCE_META_TYPE_MAX)
			continue;
		ptr = (u8 *)mask;
		field_size = mce_field_mask_db[type].sup_options_num;
		field_size *= sizeof(struct mce_field_mask);
		field_opt = mce_field_mask_db[type].options_list;
		for (j = 0; j < mce_field_mask_db[type].sup_options_num;
		     j++, field_opt++) {
			if (!memcmp(all_zero, (ptr + field_opt->offset),
				    field_opt->mask_wide))
				continue;
			if (!memcmp((void const *)field_opt->mask_block,
				    (ptr + field_opt->offset),
				    field_opt->mask_wide))
				continue;
			fv = (u16 *)(((u8 *)mask) + field_opt->offset);
			if (field_opt->mask_wide == 1) {
				block_mask->options = field_opt->mask_options;
				block_mask->key_off =
					field_opt->key_off;
				block_mask->mask = fv[0];
				block_mask++;
				block++;
			} else {
				u32 mask_wide = field_opt->mask_wide / 2;

				for (k = 0; k < mask_wide; k++) {
					if (fv[k] == 0xffff) {
						fd_logd(LOG_FDIR_DEBUG,
							"type:%d mask=0xffff\n",
						     type);
						continue;
					}

					fd_logd(LOG_FDIR_DEBUG,
						"type:%d field_opt->mask_wide %d fv 0x%.2x\n",
					     type, field_opt->mask_wide, fv[k]);
					block_mask->options =
						field_opt->mask_options;
					block_mask->key_off =
						field_opt->key_off + k * 2;
					fd_logd(LOG_FDIR_DEBUG,
						"type:%d base_key_off %d k %d\n",
					     type, block_mask->key_off, k);
					if (k > 1 &&
					    field_opt->mask_options == MCE_OPT_IPV6_SIP)
						block_mask->key_off += 12;
					if (k > 1 &&
					    field_opt->mask_options == MCE_OPT_IPV6_DIP)
						block_mask->key_off += 20;
					fd_logd(LOG_FDIR_DEBUG,
						"type:%d block_mask->key_off 0x%.2x\n",
					     type, block_mask->key_off);
					block_mask->mask = fv[k];
					block_mask++;
					block++;
				}
			}
		}
	}
	mask_info->used_block = block;

	return block;
}

struct mce_hw_profile *
mce_fdir_alloc_profile(struct mce_fdir_handle *handle,
		       struct mce_fdir_filter *filter)
{
	struct mce_hw_profile *profile = NULL;
	u32 profile_id = filter->profile_id;

	if (mce_conflict_profile_check(handle, filter))
		return NULL;

	profile = kzalloc(sizeof(*profile), GFP_KERNEL);
	if (!profile)
		return NULL;

	profile->profile_id = profile_id;
	profile->fied_mask = mce_fdir_get_profile_field_mask(filter);
	profile->options = filter->options;

#define MCE_PROFILE_NO_OPT \
	(MCE_OPT_TCP_SYNC | MCE_OPT_IPV4_FRAG | MCE_OPT_IPV6_FRAG)
	if (!profile->fied_mask && !(filter->options & MCE_PROFILE_NO_OPT)) {
		kfree(profile);
		return NULL;
	}
	return profile;
}

int mce_fdir_remove_profile(struct mce_hw *hw,
			    struct mce_fdir_handle *handle,
			    struct mce_fdir_filter *filter)
{
	struct mce_field_bitmask_info *mask_info;
	struct mce_field_bitmask_block *block;
	struct mce_hw_profile *profile = NULL;
	u16 profile_id = filter->profile_id;
	int i, j;

	profile = handle->profiles[profile_id];
	if (!profile) {
		dev_err(mce_hw_to_dev(hw),
			"%s: profile ptr is null, profile id:0x%x\n",
			__func__, profile_id);
		return -1;
	}

	/* clear mask profile data */
	mask_info = profile->mask_info;
	if (!mask_info) {
		/* maybe rules not used submask */
		goto no_mask_handle;
	}

	for (i = 0; i < mask_info->used_block; i++) {
		block = &mask_info->field_bitmask[i];
		for (j = 0; j < 32; j++) {
			if (!handle->field_mask[j].used)
				continue;
			if (handle->field_mask[j].key_off == block->key_off &&
			    handle->field_mask[j].mask == block->mask) {
				if (handle->field_mask[j].ref_count)
					handle->field_mask[j].ref_count--;
				if (handle->field_mask[j].ref_count == 0) {
					memset(&handle->field_mask[j], 0,
					       sizeof(struct mce_fdir_field_mask));
					hw->ops->fd_field_bitmask_setup(hw,
								&handle->field_mask[j], j);
				}
			}
		}
	}

	if (mask_info->ref_cnt)
		mask_info->ref_cnt--;
	if (mask_info->ref_cnt == 0) {
		hw->ops->fd_profile_field_bitmask_update(hw, profile_id, 0);
		kfree(mask_info->field_bitmask);
		kfree(mask_info);
		profile->mask_info = NULL;
		profile->bitmask_options = 0;
	}

no_mask_handle:
	if (profile->ref_cnt)
		profile->ref_cnt--;
	if (profile->ref_cnt == 0) {
		hw->ops->fd_profile_update(hw, profile, false);
		kfree(profile);
		profile = NULL;
		handle->profiles[profile_id] = NULL;
	}

	return 0;
}

int mce_fdir_restore_hw_profile(struct mce_pf *pf,
				struct mce_fdir_handle *handle,
				struct mce_fdir_filter *filter)
{
	struct mce_field_bitmask_info *mask_info;
	struct mce_hw_profile *profile = NULL;
	u16 profile_id = filter->profile_id;
	struct mce_hw *hw = &pf->hw;
	int i;

	profile = handle->profiles[profile_id];
	if (!profile) {
		dev_err(mce_hw_to_dev(hw),
			"%s: profile ptr is null, profile id:0x%x\n", __func__,
			profile_id);
		return -1;
	}

	if (profile->ref_cnt)
		hw->ops->fd_profile_update(hw, profile, true);

	mask_info = profile->mask_info;
	if (!mask_info)
		return 0;

	if (mask_info->ref_cnt)
		hw->ops->fd_profile_field_bitmask_update(hw, profile_id, profile->bitmask_options);

	for (i = 0; i < 32; i++) {
		if (handle->field_mask[i].used)
			hw->ops->fd_field_bitmask_setup(hw, &handle->field_mask[i], i);
	}
	return 0;
}

#endif /* CONFIG_NET_CLS_FLOWER */
