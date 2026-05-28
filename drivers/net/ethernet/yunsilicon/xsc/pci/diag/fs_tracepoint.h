/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#if !defined(_XSC_FS_TP_) || defined(TRACE_HEADER_MULTI_READ)
#define _XSC_FS_TP_

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>
#include "common/fs_core.h"
#include "common/fs_cmd.h"

#undef TRACE_SYSTEM
#define TRACE_SYSTEM xsc

#define __parse_fs_hdrs(match_mask_enable, mouter, mmisc, minner, vouter, \
			vinner, vmisc)					      \
	parse_fs_hdrs(p, match_mask_enable, mouter, mmisc, minner, vouter,\
		      vinner, vmisc)

const char *parse_fs_hdrs(struct trace_seq *p,
			  u8 match_mask_enable,
			  const u32 *mask_outer,
			  const u32 *mask_misc,
			  const u32 *mask_inner,
			  const u32 *value_outer,
			  const u32 *value_misc,
			  const u32 *value_inner);

const char *parse_fs_dst(struct trace_seq *p,
			 const struct xsc_flow_destination *dst,
			 u32 counter_id);

#define __parse_fs_dst(dst, counter_id) \
	parse_fs_dst(p, (const struct xsc_flow_destination *)dst, counter_id)

TRACE_EVENT(xsc_fs_add_ft,
	    TP_PROTO(const struct xsc_flow_table *ft),
	    TP_ARGS(ft),
	    TP_STRUCT__entry(
		__field(const struct xsc_flow_table *, ft)
		__field(u32, id)
		__field(u32, level)
		__field(u32, type)
	    ),
	    TP_fast_assign(
			   __entry->ft = ft;
			   __entry->id = ft->id;
			   __entry->level = ft->level;
			   __entry->type = ft->type;
	    ),
	    TP_printk("ft=%p id=%u level=%u type=%u\n",
		      __entry->ft, __entry->id, __entry->level, __entry->type)
	    );

TRACE_EVENT(xsc_fs_del_ft,
	    TP_PROTO(const struct xsc_flow_table *ft),
	    TP_ARGS(ft),
	    TP_STRUCT__entry(
		__field(const struct xsc_flow_table *, ft)
		__field(u32, id)
	    ),
	    TP_fast_assign(
			   __entry->ft = ft;
			   __entry->id = ft->id;

	    ),
	    TP_printk("ft=%p id=%u\n", __entry->ft, __entry->id)
	    );

TRACE_EVENT(xsc_fs_add_fg,
	    TP_PROTO(const struct xsc_flow_group *fg, const struct xsc_ifc_flow_attr *match_attr),
	    TP_ARGS(fg, match_attr),
	    TP_STRUCT__entry(
		__field(const struct xsc_flow_group *, fg)
		__field(const struct xsc_flow_table *, ft)
		__field(u32, start_index)
		__field(u32, end_index)
		__field(u32, id)
		__field(u8, mask_enable)
		__field(u16, vport)
		__field(u16, vhca_id)
		__field(u8, ingress)
		__field(u8, egress)
		__field(u8, chain_no)
		__field(u16, priority)
		__field(u8, dest_type)

		__array(u32, mask_outer, XSC_ST_SZ_DW(fte_match_set_lyr_2_4))
		__array(u32, mask_inner, XSC_ST_SZ_DW(fte_match_set_lyr_2_4))
		__array(u32, mask_misc, XSC_ST_SZ_DW(fte_match_set_misc))
	    ),
	    TP_fast_assign(
			   __entry->fg = fg;
			   fs_get_obj(__entry->ft, fg->node.parent);
			   __entry->start_index = be32_to_cpu(match_attr->start_flow_index);
			   __entry->end_index = be32_to_cpu(match_attr->end_flow_index);
			   __entry->id = fg->id;
			   __entry->mask_enable = fg->mask.match_mask_enable;

			   __entry->vport = be16_to_cpu(match_attr->vport);
			   __entry->vhca_id = be16_to_cpu(match_attr->vhca_id);
			   __entry->ingress = match_attr->ingress;
			   __entry->egress = match_attr->egress;
			   __entry->chain_no = match_attr->chain_no;
			   __entry->priority = be16_to_cpu(match_attr->priority);
			   __entry->dest_type = match_attr->dest_type;

			   memcpy(__entry->mask_outer,
				  XSC_ADDR_OF(fte_match_param, &fg->mask.match_mask, outer_headers),
				  sizeof(__entry->mask_outer));
			   memcpy(__entry->mask_inner,
				  XSC_ADDR_OF(fte_match_param, &fg->mask.match_mask, inner_headers),
				  sizeof(__entry->mask_inner));
			   memcpy(__entry->mask_misc,
				  XSC_ADDR_OF(fte_match_param, &fg->mask.match_mask, misc),
				  sizeof(__entry->mask_misc));

	    ),
	    TP_printk("fg=%p ft=%p id=%u start=%u end=%u bit_mask=%02x vport=%u vhca_id=%04x ingress=%u egress=%u chain=%u prio=%u dest_type=%u %s\n",
		      __entry->fg, __entry->ft, __entry->id,
		      __entry->start_index,
		      __entry->end_index, __entry->mask_enable,
		      __entry->vport, __entry->vhca_id,
		      __entry->ingress, __entry->egress,
		      __entry->chain_no, __entry->priority,
		      __entry->dest_type,
		      __parse_fs_hdrs(__entry->mask_enable,
				      __entry->mask_outer,
				      __entry->mask_misc,
				      __entry->mask_inner,
				      __entry->mask_outer,
				      __entry->mask_misc,
				      __entry->mask_inner))
	    );

TRACE_EVENT(xsc_fs_del_fg,
	    TP_PROTO(const struct xsc_flow_group *fg),
	    TP_ARGS(fg),
	    TP_STRUCT__entry(
		__field(const struct xsc_flow_group *, fg)
		__field(u32, id)
	    ),
	    TP_fast_assign(
			   __entry->fg = fg;
			   __entry->id = fg->id;

	    ),
	    TP_printk("fg=%p id=%u\n",
		      __entry->fg, __entry->id)
	    );

#define show_xsc_action_flags(x) \
	__print_flags(x, "|", \
		{XSC_FLOW_CONTEXT_ACTION_ALLOW,  "ALLOW"},\
		{XSC_FLOW_CONTEXT_ACTION_DROP,           "DROP"},\
		{XSC_FLOW_CONTEXT_ACTION_FWD_DEST,       "FWD"},\
		{XSC_FLOW_CONTEXT_ACTION_COUNT,  "CNT"},\
		{XSC_FLOW_CONTEXT_ACTION_PACKET_REFORMAT, "REFORMAT"},\
		{XSC_FLOW_CONTEXT_ACTION_DECAP,  "DECAP"},\
		{XSC_FLOW_CONTEXT_ACTION_MOD_HDR,        "MOD_HDR"},\
		{XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH,      "VLAN_PUSH"},\
		{XSC_FLOW_CONTEXT_ACTION_VLAN_POP,       "VLAN_POP"},\
		{XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH_2,    "VLAN_PUSH_2"},\
		{XSC_FLOW_CONTEXT_ACTION_VLAN_POP_2,     "VLAN_POP_2"},\
		{XSC_FLOW_CONTEXT_ACTION_FWD_NEXT_PRIO, "NEXT_PRIO"})

TRACE_EVENT(xsc_fs_set_fte,
	    TP_PROTO(const struct fs_fte *fte, int new_fte),
	    TP_ARGS(fte, new_fte),
	    TP_STRUCT__entry(
		__field(int, ops)
		__field(const struct fs_fte *, fte)
		__field(const struct xsc_flow_group *, fg)
		__field(u32, fte_index)
		__field(u32, group_index)
		__field(u32, flow_tag)
		__field(u32, flow_source)
		__field(u8,  mask_enable)
		__field(u32, action)
		__array(u32, mask_outer, XSC_ST_SZ_DW(fte_match_set_lyr_2_4))
		__array(u32, mask_inner, XSC_ST_SZ_DW(fte_match_set_lyr_2_4))
		__array(u32, mask_misc, XSC_ST_SZ_DW(fte_match_set_misc))
		__array(u32, value_outer, XSC_ST_SZ_DW(fte_match_set_lyr_2_4))
		__array(u32, value_inner, XSC_ST_SZ_DW(fte_match_set_lyr_2_4))
		__array(u32, value_misc, XSC_ST_SZ_DW(fte_match_set_misc))
	    ),
	    TP_fast_assign(
			   __entry->ops = new_fte;
			   __entry->fte = fte;
			   fs_get_obj(__entry->fg, fte->node.parent);
			   __entry->fte_index = fte->index;
			   __entry->group_index = __entry->fg->id;
			   __entry->flow_tag = fte->flow_context.flow_tag;
			   __entry->flow_source = fte->flow_context.flow_source;
			   __entry->mask_enable = __entry->fg->mask.match_mask_enable;
			   __entry->action = fte->action.action;
			   memcpy(__entry->mask_outer,
				  XSC_ADDR_OF(fte_match_param, &__entry->fg->mask.match_mask,
					      outer_headers),
				  sizeof(__entry->mask_outer));
			   memcpy(__entry->mask_inner,
				  XSC_ADDR_OF(fte_match_param, &__entry->fg->mask.match_mask,
					      inner_headers),
				  sizeof(__entry->mask_inner));
			   memcpy(__entry->mask_misc,
				  XSC_ADDR_OF(fte_match_param, &__entry->fg->mask.match_mask, misc),
				  sizeof(__entry->mask_misc));
			   memcpy(__entry->value_outer,
				  XSC_ADDR_OF(fte_match, &fte->val, match_value.outer_headers),
				  sizeof(__entry->value_outer));
			   memcpy(__entry->value_inner,
				  XSC_ADDR_OF(fte_match, &fte->val, match_value.inner_headers),
				  sizeof(__entry->value_inner));
			   memcpy(__entry->value_misc,
				  XSC_ADDR_OF(fte_match, &fte->val, match_value.misc),
				  sizeof(__entry->value_misc));
	    ),
	    TP_printk("op=%s fte=%p fg=%p fte_index=%u group_index=%u flow_tag=0x%x flow_source=%u action=<%s>  %s\n",
		      __entry->ops ? "add" : "set",
		      __entry->fte, __entry->fg, __entry->fte_index,
		      __entry->group_index, __entry->flow_tag,
		      __entry->flow_source,
		      show_xsc_action_flags(__entry->action),
		      __parse_fs_hdrs(__entry->mask_enable,
				      __entry->mask_outer,
				      __entry->mask_misc,
				      __entry->mask_inner,
				      __entry->value_outer,
				      __entry->value_misc,
				      __entry->value_inner))
	    );

TRACE_EVENT(xsc_fs_del_fte,
	    TP_PROTO(const struct fs_fte *fte),
	    TP_ARGS(fte),
	    TP_STRUCT__entry(
		__field(const struct fs_fte *, fte)
		__field(u32, index)
	    ),
	    TP_fast_assign(
			   __entry->fte = fte;
			   __entry->index = fte->index;

	    ),
	    TP_printk("fte=%p index=%u\n",
		      __entry->fte, __entry->index)
	    );

TRACE_EVENT(xsc_fs_add_rule,
	    TP_PROTO(const struct xsc_flow_rule *rule, u32 index),
	    TP_ARGS(rule, index),
	    TP_STRUCT__entry(
		__field(const struct xsc_flow_rule *, rule)
		__field(const struct fs_fte *, fte)
		__field(u32, index)
		__field(u32, dest_num)
		__field(u32, fwd_dest_num)
		__field(u32, counter_id)
		__field(u8, dest_type)
		__array(u8, destination, sizeof(struct xsc_flow_destination))
	    ),
	    TP_fast_assign(
		__entry->rule = rule;
		__entry->index = index;
		fs_get_obj(__entry->fte, rule->node.parent);
		__entry->dest_num = __entry->fte->dests_size;
		__entry->fwd_dest_num = __entry->fte->fwd_dests;
		__entry->dest_type = rule->dest_attr.type;
		memcpy(__entry->destination, &rule->dest_attr,
		       sizeof(__entry->destination));
		if (rule->dest_attr.type & XSC_FLOW_DESTINATION_TYPE_COUNTER)
			__entry->counter_id = rule->dest_attr.counter_id;
	    ),
	    TP_printk("rule=%p fte=%p index=% dest_num=%u fwd_dest_num=%u [dst_type=%u] %s\n",
		      __entry->rule, __entry->fte, __entry->index,
		      __entry->dest_num, __entry->fwd_dest_num,
		      __entry->dest_type,
		      __parse_fs_dst(__entry->destination, __entry->counter_id))
	    );

TRACE_EVENT(xsc_fs_del_rule,
	    TP_PROTO(const struct xsc_flow_rule *rule),
	    TP_ARGS(rule),
	    TP_STRUCT__entry(
		__field(const struct xsc_flow_rule *, rule)
		__field(const struct fs_fte *, fte)
	    ),
	    TP_fast_assign(
			   __entry->rule = rule;
			   fs_get_obj(__entry->fte, rule->node.parent);
	    ),
	    TP_printk("rule=%p fte=%p\n",
		      __entry->rule, __entry->fte)
	    );
#endif

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ./diag
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE fs_tracepoint
#include <trace/define_trace.h>
