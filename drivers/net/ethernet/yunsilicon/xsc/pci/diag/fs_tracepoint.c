// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifdef CONFIG_XSC_TRACE_DEBUG

//#define CREATE_TRACE_POINTS

#include "fs_tracepoint.h"
#include <linux/stringify.h>
#include "common/xsc_eswitch.h"
#include "common/fs_core.h"

#define DECLARE_MASK_VAL(type, name) struct {type m; type v; } name
#define GET_MASKED_VAL(name) (name.m & name.v)

#define GET_MASK_VAL(name, type, mask, val, fld)	\
		(name.m = XSC_GET(type, mask, fld),	\
		 name.v = XSC_GET(type, val, fld),	\
		 name.m & name.v)
#define PRINT_MASKED_VAL(name, p, format) {		\
	if (name.m)			\
		trace_seq_printf(p, __stringify(name) "=" format " ", name.v); \
	}
#define PRINT_MASKED_VALP(name, cast, p, format) {	\
	if (name.m)			\
		trace_seq_printf(p, __stringify(name) "=" format " ",	       \
				 (cast)&name.v);\
	}

#define PRINT_L2_FIELD(type, field, p, fmt)				\
	do {								\
		DECLARE_MASK_VAL(type, field) = {			\
			.m = XSC_GET(fte_match_set_lyr_2_4, mask, field), \
			.v = XSC_GET(fte_match_set_lyr_2_4, value, field) }; \
		PRINT_MASKED_VAL(field, p, fmt);			\
	} while (0)

#define PRINT_MISC_FIELD(type, field, p, fmt)				\
	do {								\
		DECLARE_MASK_VAL(type, field) = {			\
			.m = XSC_GET(fte_match_set_misc, mask, field),	\
			.v = XSC_GET(fte_match_set_misc, value, field) }; \
		PRINT_MASKED_VAL(field, p, fmt);			\
	} while (0)

static void print_lyr_2_4_hdrs(struct trace_seq *p,
			       const u32 *mask, const u32 *value)
{
	DECLARE_MASK_VAL(u64, smac) = {
		.m = XSC_GET(fte_match_set_lyr_2_4, mask, src_mac) << 16,
		.v = XSC_GET(fte_match_set_lyr_2_4, value, src_mac) << 16 };
	DECLARE_MASK_VAL(u64, dmac) = {
		.m = XSC_GET(fte_match_set_lyr_2_4, mask, dst_mac) << 16,
		.v = XSC_GET(fte_match_set_lyr_2_4, value, dst_mac) << 16 };

	DECLARE_MASK_VAL(u16, ethertype) = {
		.m = XSC_GET(fte_match_set_lyr_2_4, mask, ethertype),
		.v = XSC_GET(fte_match_set_lyr_2_4, value, ethertype) };
	DECLARE_MASK_VAL(u8, ip_type) = {
		.m = XSC_GET(fte_match_set_lyr_2_4, mask, ip_type),
		.v = XSC_GET(fte_match_set_lyr_2_4, value, ip_type) };

	PRINT_MASKED_VALP(smac, u8 *, p, "%pM");
	PRINT_MASKED_VALP(dmac, u8 *, p, "%pM");

	PRINT_MASKED_VAL(ip_type, p, "%02x");

	PRINT_L2_FIELD(u8, tp_type, p, "%02x");
	PRINT_MASKED_VAL(ethertype, p, "%04x");
	PRINT_L2_FIELD(u16, ethertype, p, "%04x");
	PRINT_L2_FIELD(u8, dscp, p, "%02x");
	PRINT_L2_FIELD(u8, ttl_hoplimit, p, "%d");
	PRINT_L2_FIELD(u8, icmp_code, p, "%02x");
	PRINT_L2_FIELD(u8, icmp_type, p, "%02x");
	PRINT_L2_FIELD(u16, dport, p, "%u");
	PRINT_L2_FIELD(u16, sport, p, "%u");
	PRINT_L2_FIELD(u8, vlan_tpid, p, "%d");
	PRINT_L2_FIELD(u16, vlan_id, p, "%04x");
	PRINT_L2_FIELD(u8, vlan_pcp, p, "%x");
	PRINT_L2_FIELD(u8, cvlan_tpid, p, "%d");
	PRINT_L2_FIELD(u16, cvlan_id, p, "%04x");
	PRINT_L2_FIELD(u8, cvlan_pcp, p, "%x");

	if ((ethertype.m == 0xffff && ethertype.v == ETH_P_IP) ||
	    (ip_type.m == 0xf && ip_type.v == 4)) {
		DECLARE_MASK_VAL(u32, src_ipv4) = {
			.m = XSC_GET_BE(u32, fte_match_set_lyr_2_4, mask, ipv4.sip),
			.v = XSC_GET_BE(u32, fte_match_set_lyr_2_4, value, ipv4.sip) };
		DECLARE_MASK_VAL(u32, dst_ipv4) = {
			.m = XSC_GET_BE(u32, fte_match_set_lyr_2_4, mask, ipv4.dip),
			.v = XSC_GET_BE(u32, fte_match_set_lyr_2_4, value, ipv4.dip) };
		PRINT_MASKED_VALP(src_ipv4, typeof(&src_ipv4.v), p, "%pI4");
		PRINT_MASKED_VALP(dst_ipv4, typeof(&dst_ipv4.v), p, "%pI4");
	} else if ((ethertype.m == 0xffff && ethertype.v == ETH_P_IPV6) ||
		   (ip_type.m == 0xf && ip_type.v == 6)) {
		static const struct in6_addr full_ones = {
			.in6_u.u6_addr32 = {__constant_htonl(0xffffffff),
					    __constant_htonl(0xffffffff),
					    __constant_htonl(0xffffffff),
					    __constant_htonl(0xffffffff)},
		};
		DECLARE_MASK_VAL(struct in6_addr, src_ipv6);
		DECLARE_MASK_VAL(struct in6_addr, dst_ipv6);

		memcpy(src_ipv6.m.in6_u.u6_addr8,
		       XSC_ADDR_OF(fte_match_set_lyr_2_4, mask, ipv6.src_addr),
		       sizeof(src_ipv6.m));
		memcpy(dst_ipv6.m.in6_u.u6_addr8,
		       XSC_ADDR_OF(fte_match_set_lyr_2_4, mask, ipv6.dst_addr),
		       sizeof(dst_ipv6.m));
		memcpy(src_ipv6.v.in6_u.u6_addr8,
		       XSC_ADDR_OF(fte_match_set_lyr_2_4, value, ipv6.src_addr),
		       sizeof(src_ipv6.v));
		memcpy(dst_ipv6.v.in6_u.u6_addr8,
		       XSC_ADDR_OF(fte_match_set_lyr_2_4, value, ipv6.dst_addr),
		       sizeof(dst_ipv6.v));

		if (!memcmp(&src_ipv6.m, &full_ones, sizeof(full_ones)))
			trace_seq_printf(p, "src_ipv6=%pI6 ", &src_ipv6.v);
		if (!memcmp(&dst_ipv6.m, &full_ones, sizeof(full_ones)))
			trace_seq_printf(p, "dst_ipv6=%pI6 ", &dst_ipv6.v);
	}
}

static void print_misc_hdrs(struct trace_seq *p, const u32 *mask, const u32 *value)
{
	PRINT_MISC_FIELD(u16, vport, p, "%u");
	PRINT_MISC_FIELD(u16, vhca_id, p, "%u");
	PRINT_MISC_FIELD(u16, logical_in_port, p, "%u");
	PRINT_MISC_FIELD(u16, tag, p, "%u");
	PRINT_MISC_FIELD(u16, pkt_type, p, "%u");
	PRINT_MISC_FIELD(u16, member_bitmap, p, "%u");
	PRINT_MISC_FIELD(u16, tunnel_id, p, "%u");
	PRINT_MISC_FIELD(u16, tunnel_type, p, "%u");
	PRINT_MISC_FIELD(u16, udf0, p, "%u");
	PRINT_MISC_FIELD(u16, udf1, p, "%u");
	PRINT_MISC_FIELD(u16, udf2, p, "%u");
}

const char *parse_fs_hdrs(struct trace_seq *p,
			  u8 match_mask_enable,
			  const u32 *mask_outer,
			  const u32 *mask_misc,
			  const u32 *mask_inner,
			  const u32 *value_outer,
			  const u32 *value_misc,
			  const u32 *value_inner)
{
	const char *ret = trace_seq_buffer_ptr(p);

	if (match_mask_enable & (1 << XSC_MATCH_OUTER_HEADERS)) {
		trace_seq_printf(p, "[outer] ");
		print_lyr_2_4_hdrs(p, mask_outer, value_outer);
	}
	if (match_mask_enable & (1 << XSC_MATCH_MISC_PARAMETERS)) {
		trace_seq_printf(p, "[misc] ");
		print_misc_hdrs(p, mask_misc, value_misc);
	}
	if (match_mask_enable & (1 << XSC_MATCH_INNER_HEADERS)) {
		trace_seq_printf(p, "[inner] ");
		print_lyr_2_4_hdrs(p, mask_inner, value_inner);
	}
	trace_seq_putc(p, 0);
	return ret;
}

static const char *fs_dest_range_field_to_str(enum xsc_flow_dest_range_field field)
{
	switch (field) {
	case XSC_FLOW_DEST_RANGE_FIELD_PKT_LEN:
		return "packet len";
	default:
		return "unknown dest range field";
	}
}

const char *parse_fs_dst(struct trace_seq *p,
			 const struct xsc_flow_destination *dst,
			 u32 counter_id)
{
	const char *ret = trace_seq_buffer_ptr(p);

	switch (dst->type) {
	case XSC_FLOW_DESTINATION_TYPE_NONE:
		trace_seq_printf(p, "none\n");
		break;
	case XSC_FLOW_DESTINATION_TYPE_DEF_FLOW_TABLE:
		trace_seq_printf(p, "default flow rule\n");
		break;
	case XSC_FLOW_DESTINATION_TYPE_FLOW_CHAIN:
		if (dst->ft)
			trace_seq_printf(p, "flow chain=%d\n", dst->ft->chain);
		else
			trace_seq_printf(p, "flow chain invalid\n");
		break;
	case XSC_FLOW_DESTINATION_TYPE_UPLINK:
		trace_seq_printf(p, "uplink vport=%u vhca_id=%04x\n",
				 dst->vport.num, dst->vport.vhca_id);
		break;
	case XSC_FLOW_DESTINATION_TYPE_VPORT:
		trace_seq_printf(p, "vport=%u vhca_id=%04x\n",
				 dst->vport.num, dst->vport.vhca_id);
		break;
	case XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE:
		if (dst->ft)
			trace_seq_printf(p, "ft=%p\n", dst->ft);
		else
			trace_seq_printf(p, "ft=NULL\n");
		break;
	case XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE_NUM:
		trace_seq_printf(p, "ft_num=%u\n", dst->ft_num);
		break;
	case XSC_FLOW_DESTINATION_TYPE_TIR:
		trace_seq_printf(p, "tir=%u\n", dst->tir_num);
		break;
	case XSC_FLOW_DESTINATION_TYPE_FLOW_SAMPLER:
		trace_seq_printf(p, "sampler_id=%u\n", dst->sampler_id);
		break;
	case XSC_FLOW_DESTINATION_TYPE_COUNTER:
		trace_seq_printf(p, "counter_id=%u\n", counter_id);
		break;
	case XSC_FLOW_DESTINATION_TYPE_PORT:
		trace_seq_printf(p, "port\n");
		break;
	case XSC_FLOW_DESTINATION_TYPE_RANGE:
		trace_seq_printf(p, "field=%s min=%d max=%d\n",
				 fs_dest_range_field_to_str(dst->range.field),
				 dst->range.min, dst->range.max);
		break;
	case XSC_FLOW_DESTINATION_TYPE_TABLE_TYPE:
		trace_seq_printf(p, "flow_table_type=%u id:%u\n", dst->ft->type,
				 dst->ft->id);
		break;
	default:
		trace_seq_printf(p, "UNKNOWN TYPE %u\n", dst->type);
		break;
	}

	trace_seq_putc(p, 0);
	return ret;
}

EXPORT_TRACEPOINT_SYMBOL(xsc_fs_add_ft);
EXPORT_TRACEPOINT_SYMBOL(xsc_fs_del_ft);
EXPORT_TRACEPOINT_SYMBOL(xsc_fs_add_fg);
EXPORT_TRACEPOINT_SYMBOL(xsc_fs_del_fg);
EXPORT_TRACEPOINT_SYMBOL(xsc_fs_set_fte);
EXPORT_TRACEPOINT_SYMBOL(xsc_fs_del_fte);
EXPORT_TRACEPOINT_SYMBOL(xsc_fs_add_rule);
EXPORT_TRACEPOINT_SYMBOL(xsc_fs_del_rule);
#endif
