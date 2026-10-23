// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_fc_leonis.h"
#include "nbl_fc.h"

static inline void nbl_fc_get_cmd_hdr(struct nbl_fc_mgt *mgt)
{
	static const struct nbl_cmd_hdr g_cmd_hdr[] = {
		[NBL_ACL_STATID_READ] = {NBL_BLOCK_PPE, NBL_MODULE_ACL,
				NBL_TABLE_ACL_STATID, NBL_CMD_OP_READ},
		[NBL_ACL_FLOWID_READ] = {NBL_BLOCK_PPE, NBL_MODULE_ACL,
				NBL_TABLE_ACL_FLOWID, NBL_CMD_OP_READ}
	};
	memcpy(mgt->cmd_hdr, g_cmd_hdr, sizeof(g_cmd_hdr));
}

static void nbl_fc_get_spec_sz(u16 *hit_sz, u16 *bytes_sz)
{
	*hit_sz = NBL_SPEC_STAT_HIT_SIZE;
	*bytes_sz = NBL_SPEC_STAT_BYTES_SIZE;
}

static void nbl_fc_get_flow_sz(struct nbl_fc_mgt *mgt, u16 *hit_sz, u16 *bytes_sz)
{
	*hit_sz = NBL_FLOW_STAT_HIT_SIZE;
	*bytes_sz = NBL_FLOW_STAT_BYTES_SIZE;
}

static void nbl_fc_get_spec_stats(struct nbl_flow_counter *counter, u64 *pkts, u64 *bytes)
{
	NBL_GET_SPEC_STAT_HITS(counter->cache.packets, counter->lastpackets, pkts);
	NBL_GET_SPEC_STAT_BYTES(counter->cache.bytes, counter->lastbytes, bytes);
}

static void nbl_fc_get_flow_stats(struct nbl_fc_mgt *mgt, struct nbl_flow_counter *counter,
				  u64 *pkts, u64 *bytes)
{
	NBL_GET_FLOW_STAT_HITS(counter->cache.packets, counter->lastpackets, pkts);
	NBL_GET_FLOW_STAT_BYTES(counter->cache.bytes, counter->lastbytes, bytes);
}

static int nbl_fc_update_flow_stats(struct nbl_fc_mgt *mgt,
				    struct nbl_flow_query_counter *counter_array,
				    u32 flow_num, u32 clear, bool is_spec_id)
{
	int ret = 0;
	u32 idx = 0;
	u16 hit_size;
	u16 bytes_size;
	union nbl_cmd_acl_flowid_u fquery_out;
	union nbl_cmd_acl_statid_u squery_out;
	struct nbl_stats_data data_info = { 0 };
	struct nbl_cmd_content cmd = { 0 };
	struct nbl_cmd_hdr hdr = mgt->cmd_hdr[NBL_ACL_FLOWID_READ];

	memset(&fquery_out, 0, sizeof(fquery_out));
	memset(&squery_out, 0, sizeof(squery_out));

	cmd.out_va = &fquery_out;
	if (is_spec_id) {
		hdr = mgt->cmd_hdr[NBL_ACL_STATID_READ];
		cmd.out_va = &squery_out;
		mgt->fc_ops.get_spec_stat_sz(&hit_size, &bytes_size);
	} else {
		mgt->fc_ops.get_flow_stat_sz(mgt, &hit_size, &bytes_size);
	}

	cmd.in_va = counter_array->counter_id;
	cmd.in_params = (clear << NBL_FLOW_STAT_CLR_OFT) |
			((flow_num - 1) & NBL_FLOW_STAT_NUM_MASK);
	cmd.in_length = NBL_CMDQ_ACL_STAT_BASE_LEN;

	ret = nbl_tc_call_inst_cmdq(mgt->common->tc_inst_id, (void *)&hdr, (void *)&cmd);
	if (ret)
		goto cmd_send_error;

	/* clear no need update cache */
	if (clear) {
		nbl_debug(mgt->common, NBL_DEBUG_FLOW, "nbl flow fc flush hw-stats success");
		return 0;
	}

	for (idx = 0; idx < flow_num; idx++) {
		if (is_spec_id) {
			memcpy(&data_info.bytes, squery_out.info.all_data[idx].bytes, bytes_size);
			memcpy(&data_info.packets, &squery_out.info.all_data[idx].hits, hit_size);
		} else {
			memcpy(&data_info.bytes, fquery_out.info.all_data[idx].bytes, bytes_size);
			memcpy(&data_info.packets, &fquery_out.info.all_data[idx].hits, hit_size);
		}
		data_info.flow_id = counter_array->counter_id[idx];
		nbl_debug(mgt->common, NBL_DEBUG_FLOW, "nbl flow fc get %u-%lu: packets:%llu-bytes:%llu\n",
			  data_info.flow_id, counter_array->cookie[idx],
			  data_info.packets, data_info.bytes);
		ret = nbl_fc_set_stats(mgt, &data_info, counter_array->cookie[idx], is_spec_id);
		if (ret)
			goto set_stat_error;
	}

	return 0;

cmd_send_error:
	nbl_err(mgt->common, NBL_DEBUG_FLOW, "nbl flow fc get hw stats failed. ret %d", ret);
	return ret;

set_stat_error:
	nbl_debug(mgt->common, NBL_DEBUG_FLOW,
		  "nbl flow fc set flow stats failed. count_id:%u, cookie: %lu, ret(%u): %d",
		  counter_array->counter_id[idx], counter_array->cookie[idx], idx, ret);
	return ret;
}

static void nbl_fc_init_ops_leonis(struct nbl_fc_mgt *mgt)
{
	mgt->fc_ops.get_spec_stat_sz = &nbl_fc_get_spec_sz;
	mgt->fc_ops.get_flow_stat_sz = &nbl_fc_get_flow_sz;
	mgt->fc_ops.get_spec_stats = &nbl_fc_get_spec_stats;
	mgt->fc_ops.get_flow_stats = &nbl_fc_get_flow_stats;
	mgt->fc_ops.update_stats = &nbl_fc_update_flow_stats;
}

int nbl_fc_add_stats_leonis(void *priv, enum nbl_pp_fc_type fc_type, unsigned long cookie)
{
	return nbl_fc_add_stats(priv, fc_type, cookie);
}

int nbl_fc_del_stats_leonis(void *priv, unsigned long cookie)
{
	return nbl_fc_del_stats(priv, cookie);
}

int nbl_fc_setup_ops_leonis(struct nbl_resource_ops *res_ops)
{
	return nbl_fc_setup_ops(res_ops);
}

void nbl_fc_remove_ops_leonis(struct nbl_resource_ops *res_ops)
{
	return nbl_fc_remove_ops(res_ops);
}

int nbl_fc_mgt_start_leonis(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_fc_mgt **fc_mgt;
	struct device *dev;
	int ret = -ENOMEM;
	struct nbl_fc_mgt *mgt;
	struct nbl_phy_ops *phy_ops;
	struct nbl_common_info *common;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	common = NBL_RES_MGT_TO_COMMON(res_mgt);
	fc_mgt = &NBL_RES_MGT_TO_COUNTER_MGT(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	ret = phy_ops->init_acl_stats(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW, "nbl flow fc init phy-stats failed");
		return ret;
	}

	ret = nbl_fc_setup_mgt(dev, fc_mgt);
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW, "nbl flow fc init mgt failed");
		return ret;
	}

	mgt = (*fc_mgt);
	mgt->common = common;
	nbl_fc_init_ops_leonis(mgt);
	nbl_fc_get_cmd_hdr(mgt);
	return nbl_fc_mgt_start(mgt);
}

void nbl_fc_mgt_stop_leonis(struct nbl_resource_mgt *res_mgt)
{
	return nbl_fc_mgt_stop(res_mgt);
}
