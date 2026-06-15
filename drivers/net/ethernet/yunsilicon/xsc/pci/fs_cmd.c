// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/fs_core.h"
#include "common/fs_cmd.h"
#include "common/xsc_core.h"
#include "common/mod_hdr.h"
#include "fs_ft_pool.h"
#include "eswitch.h"
#include "xsc_flow.h"

static int xsc_flow_stub_update_root_ft(struct xsc_core_device *dev,
					struct xsc_flow_table *ft,
					u32 underlay_qpn,
					bool disconnect)
{
	return 0;
}

static int xsc_flow_stub_create_flow_table(struct xsc_core_device *dev,
					   struct xsc_flow_table *ft,
					   struct xsc_flow_table_attr *ft_attr,
					   struct xsc_flow_table *next_ft)
{
	int max_fte = ft_attr->max_fte;

	ft->max_fte = max_fte ? roundup_pow_of_two(max_fte) : 1;

	return 0;
}

static int xsc_flow_stub_destroy_flow_table(struct xsc_core_device *dev,
					    struct xsc_flow_table *ft)
{
	return 0;
}

static int xsc_flow_stub_modify_flow_table(struct xsc_core_device *dev,
					   struct xsc_flow_table *ft,
					   struct xsc_flow_table *next_ft)
{
	return 0;
}

static int xsc_flow_stub_create_group(struct xsc_core_device *dev,
				      struct xsc_flow_table *ft, u32 *in,
				      struct xsc_flow_group *fg)
{
	return 0;
}

static int xsc_flow_stub_destroy_group(struct xsc_core_device *dev,
				       struct xsc_flow_table *ft,
				       struct xsc_flow_group *fg)
{
	return 0;
}

static int xsc_flow_stub_create_fte(struct xsc_core_device *dev,
				    struct xsc_flow_table *ft,
				    struct xsc_flow_group *group,
				    struct fs_fte *fte)
{
	return 0;
}

static int xsc_flow_stub_update_fte(struct xsc_core_device *dev,
				    struct xsc_flow_table *ft,
				    struct xsc_flow_group *group,
				    int modify_mask,
				    struct fs_fte *fte)
{
	return -EOPNOTSUPP;
}

static int xsc_flow_stub_delete_fte(struct xsc_core_device *dev,
				    struct xsc_flow_table *ft,
				    struct fs_fte *fte)
{
	return 0;
}

static int xsc_flow_stub_packet_reformat_alloc(struct xsc_core_device *dev,
					       struct xsc_pkt_reformat_params *params,
					       enum xsc_flow_namespace_type namespace,
					       struct xsc_pkt_reformat *pkt_reformat)
{
	return 0;
}

static void xsc_flow_stub_packet_reformat_dealloc(struct xsc_core_device *dev,
						  struct xsc_pkt_reformat *pkt_reformat)
{
}

static int xsc_flow_stub_modify_header_alloc(struct xsc_core_device *dev,
					     u8 namespace, u8 num_actions,
					     void *modify_actions,
					     struct xsc_modify_hdr *modify_hdr)
{
	modify_hdr->id = 0;
	return 0;
}

static void xsc_flow_stub_modify_header_dealloc(struct xsc_core_device *dev,
						struct xsc_modify_hdr *modify_hdr)
{
}

static int xsc_flow_stub_set_peer(struct xsc_flow_root_namespace *ns,
				  struct xsc_flow_root_namespace *peer_ns,
				  u16 peer_vhca_id)
{
	return 0;
}

static int xsc_flow_stub_create_ns(struct xsc_flow_root_namespace *ns)
{
	return 0;
}

static int xsc_flow_stub_destroy_ns(struct xsc_flow_root_namespace *ns)
{
	return 0;
}

static u32 xsc_flow_stub_get_capabilities(struct xsc_core_device *dev,
					  enum fs_flow_table_type ft_type)
{
	return 0;
}

#ifdef CONFIG_XSC_OFFLOAD_COUNTER
int xsc_flow_fc_get_bulk_query_out_len(int bulk_len)
{
	return sizeof(struct xsc_ifc_query_flow_counter_mbox_out) +
		      bulk_len * sizeof(struct xsc_ifc_traffic_counter);
}

int xsc_flow_fc_bulk_alloc(struct xsc_core_device *dev,
			   enum xsc_fc_bulk_alloc_bitmask alloc_bitmask, u32 *id)
{
	return xsc_hflow_counter_bulk_alloc(dev, id,
					    XSC_FC_BULK_NUM_FCS(alloc_bitmask));
}

int xsc_flow_fc_alloc(struct xsc_core_device *dev, u32 *id)
{
	return xsc_flow_fc_bulk_alloc(dev, 0, id);
}

int xsc_flow_fc_free(struct xsc_core_device *dev, u32 id, u32 bulk_len)
{
	return xsc_hflow_counter_bulk_free(dev, id, bulk_len);
}

int xsc_flow_fc_bulk_query(struct xsc_core_device *dev, u32 base_id,
			   u32 bulk_len, u32 *out)
{
	return xsc_hflow_counter_bulk_query(dev, out, base_id, bulk_len);
}

int xsc_flow_fc_query(struct xsc_core_device *dev, u32 id,
		      u64 *packets, u64 *bytes, bool clear)
{
	int out_sz = xsc_flow_fc_get_bulk_query_out_len(1);
	void *query_out;
	void *stats;
	int ret;

	query_out = kzalloc(out_sz, GFP_KERNEL);
	if (!query_out)
		return -ENOMEM;

	ret = xsc_flow_fc_bulk_query(dev, id, 1, query_out);
	if (ret)
		goto out;

	stats = XSC_ADDR_OF(query_flow_counter_mbox_out, query_out,
			    flow_stats[0]);
	*packets = XSC_GET64(traffic_counter, stats, packets);
	*bytes = XSC_GET64(traffic_counter, stats, bytes);

out:
	kfree(query_out);
	return ret;
}
#endif

#ifdef CONFIG_XSC_OFFLOAD_TUN
static int xsc_flow_packet_reformat_alloc(struct xsc_flow_root_namespace *ns,
					  struct xsc_pkt_reformat_params *params,
					  enum xsc_flow_namespace_type namespace,
					  struct xsc_pkt_reformat *pkt_reformat)
{
	u32 out[XSC_ST_SZ_DW(alloc_packet_reformat_context_out)] = {};
	struct xsc_core_device *dev = ns->dev;
	struct xsc_eswitch *esw = dev->priv.eswitch;
	void *packet_reformat_context_in;
	int max_encap_size;
	void *reformat;
	int inlen;
	int err;
	u32 *in;

	if (namespace == XSC_FLOW_NAMESPACE_FDB ||
	    namespace == XSC_FLOW_NAMESPACE_FDB_BYPASS)
		max_encap_size = esw->esw_caps.max_encap_header_size);
	else
		max_encap_size = XSC_CAP_FLOWTABLE(dev, max_encap_header_size);

	if (params->size > max_encap_size) {
		xsc_core_warn(dev, "encap size %zd too big, max supported is %d\n",
			      params->size, max_encap_size);
		return -EINVAL;
	}

	in = kzalloc(XSC_ST_SZ_BYTES(alloc_packet_reformat_context_in) +
		     params->size, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	packet_reformat_context_in = XSC_ADDR_OF(alloc_packet_reformat_context_in,
						 in, packet_reformat_context);
	reformat = XSC_ADDR_OF(packet_reformat_context_in, packet_reformat_context_in,
			       reformat_data);
	inlen = reformat - (void *)in + params->size;

	XSC_SET(alloc_packet_reformat_context_in, in, opcode,
		XSC_CMD_OP_ALLOC_PACKET_REFORMAT_CONTEXT);
	XSC_SET(packet_reformat_context_in, packet_reformat_context_in,
		reformat_data_size, params->size);
	XSC_SET(packet_reformat_context_in, packet_reformat_context_in,
		reformat_type, params->type);
	XSC_SET(packet_reformat_context_in, packet_reformat_context_in,
		reformat_param_0, params->param_0);
	XSC_SET(packet_reformat_context_in, packet_reformat_context_in,
		reformat_param_1, params->param_1);
	if (params->data && params->size)
		memcpy(reformat, params->data, params->size);

	err = xsc_cmd_exec(dev, in, inlen, out, sizeof(out));

	pkt_reformat->id = XSC_GET(alloc_packet_reformat_context_out,
				   out, packet_reformat_id);
	pkt_reformat->owner = XSC_FLOW_RESOURCE_OWNER_FW;

	kfree(in);
	return err;
}

static void xsc_flow_packet_reformat_dealloc(struct xsc_flow_root_namespace *ns,
					     struct xsc_pkt_reformat *pkt_reformat)
{
	u32 in[XSC_ST_SZ_DW(dealloc_packet_reformat_context_in)] = {};
	struct xsc_core_device *dev = ns->dev;

	XSC_SET(dealloc_packet_reformat_context_in, in, opcode,
		XSC_CMD_OP_DEALLOC_PACKET_REFORMAT_CONTEXT);
	XSC_SET(dealloc_packet_reformat_context_in, in, packet_reformat_id,
		pkt_reformat->id);

	xsc_cmd_exec_in(dev, dealloc_packet_reformat_context, in);
}
#endif

static u32 xsc_flow_get_capabilities(struct xsc_core_device *dev,
				     enum fs_flow_table_type ft_type)
{
	struct xsc_eswitch *esw = dev->priv.eswitch;
	struct xsc_cmd_query_esw_cap_mbox_in in = {};
	struct xsc_cmd_query_esw_cap_mbox_out out = {};
	struct xsc_core_device *xdev = esw->dev;
	int ret = 0;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_ESW_CAP);
	in.cap_in.esw_rep_mode = XSC_REP_MODE_KERNEL;

	ret = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (ret || (out.hdr.status != 0 && out.hdr.status != XSC_CMD_STATUS_NOT_SUPPORTED)) {
		xsc_core_err(xdev, "failed to get esw offload capaiblity, err =%d out.status= %u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	memset(&esw->esw_caps, 0, sizeof(struct xsc_esw_caps));
	esw->esw_caps.pct_start = be16_to_cpu(out.cap_out.pct_start);
	esw->esw_caps.pct_end = be16_to_cpu(out.cap_out.pct_end);

	esw->esw_caps.large_group_num = be32_to_cpu(out.cap_out.large_group_num);
	esw->esw_caps.flow_counter_bulk_alloc = out.cap_out.flow_counter_bulk_alloc;
	esw->esw_caps.log_max_flow_counter_bulk = out.cap_out.log_max_flow_counter_bulk;

	return 0;
}

static int xsc_flow_mod_hdr_key(struct xsc_core_device *dev,
				struct xsc_ifc_action *actions,
				struct xsc_mod_hdr_handle *mh)
{
	struct xsc_ifc_set_action_in *action_in;
	struct xsc_ifc_modify_hdr *mod_hdr = &actions->modify_hdr;
	int smac_cnt = 0, dmac_cnt = 0;
	int sip_cnt = 0, dip_cnt = 0;
	int i, byte_cnt;

	action_in = (struct xsc_ifc_set_action_in *)((void *)mh + sizeof(*mh));
	for (i = 0; i < mh->key.num_actions; i++) {
		byte_cnt = action_in->length / 8;
		esw_debug(dev, "mod_action%d/%d: field=%d, length=%d, value=0x%04x\n",
			  i, mh->key.num_actions, action_in->field,
			  action_in->length, *(u32 *)action_in->data);

		switch (action_in->field) {
		case XSC_ACTION_SET_SRC_MAC:
			if (smac_cnt == 0)
				memcpy(&mod_hdr->src[2], action_in->data, byte_cnt);
			else
				memcpy(&mod_hdr->src[0], action_in->data, 2);
			smac_cnt++;
			break;
		case XSC_ACTION_SET_DST_MAC:
			if (dmac_cnt == 0)
				memcpy(&mod_hdr->dst[2], action_in->data, byte_cnt);
			else
				memcpy(&mod_hdr->dst[0], action_in->data, 2);
			dmac_cnt++;
			break;
		case XSC_ACTION_SET_SRC_IPV4:
			memcpy(&mod_hdr->src_addr, action_in->data, byte_cnt);
			break;
		case XSC_ACTION_SET_DST_IPV4:
			memcpy(&mod_hdr->dst_addr, action_in->data, byte_cnt);
			break;
		case XSC_ACTION_SET_SRC_IPV6:
			memcpy(&mod_hdr->ipv6_src[4 * (3 - sip_cnt)], action_in->data, byte_cnt);
			sip_cnt++;
			break;
		case XSC_ACTION_SET_DST_IPV6:
			memcpy(&mod_hdr->ipv6_dst[4 * (3 - dip_cnt)], action_in->data, byte_cnt);
			dip_cnt++;
			break;
		case XSC_ACTION_SET_TP_SPORT:
			memcpy(&mod_hdr->tp_sport, action_in->data, byte_cnt);
			break;
		case XSC_ACTION_SET_TP_DPORT:
			memcpy(&mod_hdr->tp_dport, action_in->data, byte_cnt);
			break;
		case XSC_ACTION_SET_VLAN_VID:
			memcpy(&actions->vlan.vid, action_in->data, byte_cnt);
			break;
		case XSC_ACTION_SET_VLAN_PCP:
			actions->vlan.pcp = *(u8 *)action_in->data;
			break;
		case XSC_ACTION_SET_DSCP:
			memcpy(&mod_hdr->dscp, action_in->data, byte_cnt);
			break;
		case XSC_ACTION_DEC_TTL:
			memcpy(&mod_hdr->time_to_live, action_in->data, byte_cnt);
			break;
		case XSC_ACTION_SET_IPV4_ECN:
		case XSC_ACTION_SET_IPV6_ECN:
			memcpy(&mod_hdr->ecn, action_in->data, byte_cnt);
			break;
		default:
			esw_err(dev, "tc action %d not support\n", action_in->field);
			return -EOPNOTSUPP;
		}

		XSC_IFC_ACTION_FLAG_SET(&actions->type_flag, action_in->field);
		++action_in;
	}
	return 0;
}

static int xsc_flow_set_fte(struct xsc_core_device *dev, struct xsc_flow_table *ft,
			    unsigned int group_id, struct fs_fte *fte)
{
	void *match_attr = XSC_ADDR_OF(fte_match, fte->val, attr);
	struct xsc_flow_rule *dst;
	struct xsc_ifc_action *actions;
	u32 flow_id = 0;
	u32 action;
	int err;

	actions = kvzalloc(sizeof(*actions), GFP_KERNEL);
	if (!actions)
		return -ENOMEM;

	XSC_SET(flow_attr, match_attr, table_id, ft->id);
	XSC_SET(flow_attr, match_attr, chain_no, ft->chain);
	XSC_SET(flow_attr, match_attr, group_id, group_id);
	if (fte->flow_context.flow_source == XSC_FLOW_CONTEXT_FLOW_SOURCE_UPLINK) {
		XSC_SET(flow_attr, match_attr, ingress, 1);
		XSC_SET_FTE_MATCH_ATTR(&(((struct xsc_ifc_flow_attr *)match_attr)->match_fields),
				       IN_PORT);
	} else {
		XSC_SET(flow_attr, match_attr, egress, 1);
	}

	action = fte->action.action;

	if (action & XSC_FLOW_CONTEXT_ACTION_DROP)
		XSC_IFC_ACTION_BIT_SET(&actions->type_flag, DROP);

	if (action & XSC_FLOW_CONTEXT_ACTION_PACKET_REFORMAT) {
		XSC_SET(flow_attr, match_attr, tnl_valid, 1);
		XSC_IFC_ACTION_BIT_SET(&actions->type_flag, ENCAP_VXLAN);
	}

	if (action & XSC_FLOW_CONTEXT_ACTION_DECAP)
		XSC_IFC_ACTION_BIT_SET(&actions->type_flag, DECAP_VXLAN);

	if (action & XSC_FLOW_CONTEXT_ACTION_VLAN_POP)
		XSC_IFC_ACTION_BIT_SET(&actions->type_flag, POP_VLAN);

	if (action & XSC_FLOW_CONTEXT_ACTION_VLAN_POP_2)
		XSC_IFC_ACTION_BIT_SET(&actions->type_flag, POP_CVLAN);

	if (action & XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH) {
		XSC_IFC_ACTION_BIT_SET(&actions->type_flag, PUSH_VLAN);
		memcpy(&actions->vlan, &fte->action.vlan[0], sizeof(struct xsc_ifc_vlan_info));
	}

	if (action & XSC_FLOW_CONTEXT_ACTION_VLAN_PUSH_2) {
		XSC_IFC_ACTION_BIT_SET(&actions->type_flag, PUSH_CVLAN);
		memcpy(&actions->cvlan, &fte->action.vlan[1], sizeof(struct xsc_ifc_vlan_info));
	}

	if (action & XSC_FLOW_CONTEXT_ACTION_MOD_HDR) {
		err = xsc_flow_mod_hdr_key(dev, actions, fte->action.mh);
		if (err)
			goto err_out;
	}

	if (fte->action.action & XSC_FLOW_CONTEXT_ACTION_FWD_DEST) {
		list_for_each_entry(dst, &fte->node.children, node.list) {
			enum xsc_flow_destination_type type = dst->dest_attr.type;

			switch (type) {
			case XSC_FLOW_DESTINATION_TYPE_NONE:
				continue;
			case XSC_FLOW_DESTINATION_TYPE_DEF_FLOW_TABLE:
				XSC_IFC_ACTION_BIT_SET(&actions->type_flag, UPCALL);
				actions->vhca_id = dst->dest_attr.vport.vhca_id;
				actions->vport = dst->dest_attr.vport.num;
				break;
			case XSC_FLOW_DESTINATION_TYPE_FLOW_CHAIN:
				XSC_IFC_ACTION_BIT_SET(&actions->type_flag, GOTO_CHAIN);
				actions->chain_no = dst->dest_attr.ft->chain;
				break;
			case XSC_FLOW_DESTINATION_TYPE_UPLINK:
				XSC_IFC_ACTION_BIT_SET(&actions->type_flag, DST_LAG);
				actions->vhca_id = dst->dest_attr.vport.vhca_id;
				actions->vport = dst->dest_attr.vport.num;
				break;
			case XSC_FLOW_DESTINATION_TYPE_VPORT:
				XSC_IFC_ACTION_BIT_SET(&actions->type_flag, DST_PORT);
				actions->vhca_id = dst->dest_attr.vport.vhca_id;
				actions->vport = dst->dest_attr.vport.num;
				break;
			case XSC_FLOW_DESTINATION_TYPE_COUNTER:
				XSC_IFC_ACTION_BIT_SET(&actions->type_flag, COUNTER);
				actions->counter = dst->dest_attr.counter_id;
				break;
			default:
				break;
			}
		}
	}

	if (fte->action.action & XSC_FLOW_CONTEXT_ACTION_EXECUTE_ASO) {
		err = -EOPNOTSUPP;
		esw_err(dev, "meter action is not supported\n");
		goto err_out;
	}

	esw_info(dev, "fte_action: flag=(0x%llx, 0x%llx), mirred=(%d, %d), chain=%d, counter=%d\n",
		 actions->type_flag.bits[0], actions->type_flag.bits[1],
		 actions->vport, actions->vhca_id, actions->chain_no,
		 actions->counter);
	esw_debug(dev,
		  "mod_hdr_action: mac=(%pM, %pM), port=(%d, %d), ipv4=(%pI4, %pI4), ipv6=(%pI6, %pI6)\n",
		  actions->modify_hdr.src, actions->modify_hdr.dst,
		  actions->modify_hdr.tp_sport, actions->modify_hdr.tp_dport,
		  &actions->modify_hdr.src_addr, &actions->modify_hdr.dst_addr,
		  actions->modify_hdr.ipv6_src, actions->modify_hdr.ipv6_dst);

	err = xsc_hflow_create_fte(dev, (struct xsc_ifc_fte_match *)fte->val,
				   actions, group_id, &flow_id);
	if (err == 0)
		fte->hw_index = flow_id;

err_out:
	kvfree(actions);
	esw_info(dev, "offload flow fte(index=%d, hw_index=%d), ret=%d\n",
		 fte->index, fte->hw_index, err);
	return err;
}

int xsc_flow_create_fte(struct xsc_core_device *dev, struct xsc_flow_table *ft,
			struct xsc_flow_group *group, struct fs_fte *fte)
{
	unsigned int group_id = group->id;

	return xsc_flow_set_fte(dev, ft, group_id, fte);
}

int xsc_flow_create_group(struct xsc_core_device *dev, struct xsc_flow_table *ft,
			  u32 *in, struct xsc_flow_group *fg)
{
	struct xsc_ifc_create_flow_group_in *group_in =
					(struct xsc_ifc_create_flow_group_in *)in;
	struct xsc_ifc_flow_attr *attr = &group_in->match_attr;

	if (attr->ingress)
		XSC_SET_FTE_MATCH_ATTR(&attr->match_fields, IN_PORT);

	return xsc_hflow_create_group(dev, ft, in, fg);
}

static const struct xsc_flow_cmds xsc_flow_fw_cmds = {
	.create_flow_table = xsc_flow_stub_create_flow_table,
	.destroy_flow_table = xsc_flow_stub_destroy_flow_table,
	.modify_flow_table = xsc_flow_stub_modify_flow_table,
	.create_flow_group = xsc_flow_create_group,
	.destroy_flow_group = xsc_hflow_destroy_group,
	.create_fte = xsc_flow_create_fte,
	.update_fte = xsc_flow_stub_update_fte,
	.delete_fte = xsc_hflow_delete_fte,
	.update_root_ft = xsc_flow_stub_update_root_ft,
	.packet_reformat_alloc = xsc_flow_stub_packet_reformat_alloc,
	.packet_reformat_dealloc = xsc_flow_stub_packet_reformat_dealloc,
	.modify_header_alloc = xsc_flow_stub_modify_header_alloc,
	.modify_header_dealloc = xsc_flow_stub_modify_header_dealloc,
	.set_peer = xsc_flow_stub_set_peer,
	.create_ns = xsc_flow_stub_create_ns,
	.destroy_ns = xsc_flow_stub_destroy_ns,
	.get_capabilities = xsc_flow_get_capabilities,
};

static const struct xsc_flow_cmds xsc_flow_cmd_stubs = {
	.create_flow_table = xsc_flow_stub_create_flow_table,
	.destroy_flow_table = xsc_flow_stub_destroy_flow_table,
	.modify_flow_table = xsc_flow_stub_modify_flow_table,
	.create_flow_group = xsc_flow_stub_create_group,
	.destroy_flow_group = xsc_flow_stub_destroy_group,
	.create_fte = xsc_flow_stub_create_fte,
	.update_fte = xsc_flow_stub_update_fte,
	.delete_fte = xsc_flow_stub_delete_fte,
	.update_root_ft = xsc_flow_stub_update_root_ft,
	.packet_reformat_alloc = xsc_flow_stub_packet_reformat_alloc,
	.packet_reformat_dealloc = xsc_flow_stub_packet_reformat_dealloc,
	.modify_header_alloc = xsc_flow_stub_modify_header_alloc,
	.modify_header_dealloc = xsc_flow_stub_modify_header_dealloc,
	.set_peer = xsc_flow_stub_set_peer,
	.create_ns = xsc_flow_stub_create_ns,
	.destroy_ns = xsc_flow_stub_destroy_ns,
	.get_capabilities = xsc_flow_stub_get_capabilities,
};

const struct xsc_flow_cmds *xsc_fs_cmd_get_fw_cmds(void)
{
	return &xsc_flow_fw_cmds;
}

static const struct xsc_flow_cmds *xsc_fs_cmd_get_stub_cmds(void)
{
	return &xsc_flow_cmd_stubs;
}

const struct xsc_flow_cmds *xsc_fs_cmd_get_default(enum fs_flow_table_type type)
{
	switch (type) {
	case FS_FT_FDB:
		return xsc_fs_cmd_get_fw_cmds();
	default:
		return xsc_fs_cmd_get_stub_cmds();
	}
}
