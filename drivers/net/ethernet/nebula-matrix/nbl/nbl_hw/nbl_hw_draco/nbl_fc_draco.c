// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_fc_draco.h"
#include "nbl_fc.h"
#include "nbl_def_channel.h"

static void nbl_fc_get_spec_sz(u16 *hit_sz, u16 *bytes_sz)
{
	*hit_sz = NBL_DRACO_SPEC_STAT_HIT_SIZE;
	*bytes_sz = NBL_DRACO_SPEC_STAT_BYTES_SIZE;
}

static void nbl_fc_get_flow_sz(struct nbl_fc_mgt *mgt, u16 *hit_sz, u16 *bytes_sz)
{
	if (mgt->select_flow_stat_width72) {
		*hit_sz = NBL_DRACO_FLOW_STAT_WIDTH_72_HIT_SIZE;
		*bytes_sz = NBL_DRACO_FLOW_STAT_WIDTH_72_BYTES_SIZE;
	} else {
		*hit_sz = NBL_DRACO_FLOW_STAT_WIDTH_144_HIT_SIZE;
		*bytes_sz = NBL_DRACO_FLOW_STAT_WIDTH_144_BYTES_SIZE;
	}
}

static void nbl_fc_get_spec_stats(struct nbl_flow_counter *counter, u64 *pkts, u64 *bytes)
{
	NBL_DRACO_GET_SPEC_STAT_HITS(counter->cache.packets, counter->lastpackets, pkts);
	NBL_DRACO_GET_SPEC_STAT_BYTES(counter->cache.bytes, counter->lastbytes, bytes);
}

static void nbl_fc_get_flow_stats(struct nbl_fc_mgt *mgt, struct nbl_flow_counter *counter,
				  u64 *pkts, u64 *bytes)
{
	if (mgt->select_flow_stat_width72) {
		NBL_DRACO_GET_FLOW_WIDTH_72_STAT_HITS(counter->cache.packets,
						      counter->lastpackets, pkts);
		NBL_DRACO_GET_FLOW_WIDTH_72_STAT_BYTES(counter->cache.bytes,
						       counter->lastbytes, bytes);
	} else {
		NBL_DRACO_GET_FLOW_WIDTH_144_STAT_HITS(counter->cache.packets,
						       counter->lastpackets, pkts);
		NBL_DRACO_GET_FLOW_WIDTH_144_STAT_BYTES(counter->cache.bytes,
							counter->lastbytes, bytes);
	}
}

__maybe_unused static int nbl_draco_set_stats(struct nbl_fc_mgt *mgt,
				struct nbl_flow_query_counter *counter_array,
				u32 flow_num,
				enum nbl_counter_type counter_type,
				struct nbl_draco_flow_stat_width_72_cmd_resp *flow_resp_72,
				struct nbl_draco_flow_stat_width_144_cmd_resp *flow_resp_144,
				struct nbl_draco_spec_stat_cmd_resp *spec_resp,
				u16 bytes_size,
				u16 hit_size)
{
	int ret = 0;
	u32 idx;
	bool is_spec_id = (counter_type == NBL_FLOW_SPEC_COUNTER);
	struct nbl_stats_data data_info;

	memset(&data_info, 0, sizeof(data_info));

	for (idx = 0; idx < flow_num; idx++) {
		if (counter_type == NBL_FLOW_SPEC_COUNTER) {
			memcpy(&data_info.bytes, spec_resp->all_data[idx].bytes, bytes_size);
			memcpy(&data_info.packets, spec_resp->all_data[idx].hits, hit_size);
		} else if (counter_type == NBL_FLOW_WIDTH_72_COUNTER) {
			memcpy(&data_info.bytes, flow_resp_72->all_data[idx].bytes, bytes_size);
			memcpy(&data_info.packets, flow_resp_72->all_data[idx].hits, hit_size);
		} else {
			memcpy(&data_info.bytes, flow_resp_144->all_data[idx].bytes, bytes_size);
			memcpy(&data_info.packets, flow_resp_144->all_data[idx].hits, hit_size);
		}
		data_info.flow_id = counter_array->counter_id[idx];
		ret = nbl_fc_set_stats(mgt, &data_info, counter_array->cookie[idx], is_spec_id);
		if (ret)
			nbl_info(mgt->common, NBL_DEBUG_FLOW,
				 "[fc]-set flow stats failed,is_spec:%u, flow_id:%u, ret:%d",
				 is_spec_id, counter_array->counter_id[idx], ret);
	}

	return ret;
}

static int nbl_draco_flow_cmd_read_stats(struct nbl_fc_mgt *mgt,
					 struct nbl_flow_query_counter *counter_array,
					 u32 flow_num,
					 enum nbl_counter_type counter_type)
{
	int ret = 0;
	u8 idx = 0;
	u16 hit_size;
	u16 bytes_size;
	bool is_spec_id = (counter_type == NBL_FLOW_SPEC_COUNTER);
	struct nbl_draco_cmd_flow_stat_req stat_req;
	struct nbl_stats_data data;
	struct nbl_cmd_content cmd;
	struct nbl_cmd_hdr *hdr = &mgt->cmd_hdr[NBL_CMDQ_READ_SPEC_STAT];

	memset(&stat_req, 0, sizeof(stat_req));
	memset(&data, 0, sizeof(data));
	memset(&cmd, 0, sizeof(cmd));

	cmd.in_length = NBL_DRACO_CMDQ_ACL_STAT_BASE_LEN;
	stat_req.stat_num = flow_num & NBL_FLOW_STAT_NUM_MASK;
	for (idx = 0; idx < flow_num; idx++)
		stat_req.addrs[idx].addr = counter_array->counter_id[idx];

	cmd.in_va = &stat_req.addrs[1];
	cmd.in_params = *((u64 *)&stat_req);

	spin_lock(&mgt->resp_lock);
	memset(mgt->flow_resp_72, 0, sizeof(*mgt->flow_resp_72));
	memset(mgt->flow_resp_144, 0, sizeof(*mgt->flow_resp_144));
	memset(mgt->spec_resp, 0, sizeof(*mgt->spec_resp));
	cmd.out_va = mgt->spec_resp;

	if (counter_type != NBL_FLOW_SPEC_COUNTER) {
		mgt->fc_ops.get_flow_stat_sz(mgt, &hit_size, &bytes_size);
		hdr = &mgt->cmd_hdr[NBL_CMDQ_READ_FLOW_STAT];
		if (counter_type == NBL_FLOW_WIDTH_72_COUNTER)
			cmd.out_va = mgt->flow_resp_72;
		else
			cmd.out_va = mgt->flow_resp_144;
	} else {
		mgt->fc_ops.get_spec_stat_sz(&hit_size, &bytes_size);
	}

	ret = nbl_tc_call_inst_cmdq(mgt->common->tc_inst_id, (void *)hdr, (void *)&cmd);
	if (ret) {
		spin_unlock(&mgt->resp_lock);
		nbl_err(mgt->common, NBL_DEBUG_FLOW, "nbl fc get hw stats failed. ret %d", ret);
		return ret;
	}

	for (idx = 0; idx < flow_num; idx++) {
		if (counter_type == NBL_FLOW_SPEC_COUNTER) {
			memcpy(&data.bytes, mgt->spec_resp->all_data[idx].bytes, bytes_size);
			memcpy(&data.packets, mgt->spec_resp->all_data[idx].hits, hit_size);
		} else if (counter_type == NBL_FLOW_WIDTH_72_COUNTER) {
			memcpy(&data.bytes, mgt->flow_resp_72->all_data[idx].bytes, bytes_size);
			memcpy(&data.packets, mgt->flow_resp_72->all_data[idx].hits, hit_size);
		} else {
			memcpy(&data.bytes, mgt->flow_resp_144->all_data[idx].bytes, bytes_size);
			memcpy(&data.packets, mgt->flow_resp_144->all_data[idx].hits, hit_size);
		}
		data.flow_id = counter_array->counter_id[idx];
		ret = nbl_fc_set_stats(mgt, &data, counter_array->cookie[idx], is_spec_id);
		if (ret)
			nbl_info(mgt->common, NBL_DEBUG_FLOW,
				 "[fc]-set flow stats failed,is_spec:%u, flow_id:%u, ret:%d",
				 is_spec_id, counter_array->counter_id[idx], ret);
	}

	spin_unlock(&mgt->resp_lock);

	return ret;
}

static int nbl_draco_flow_cmd_clear_stats(struct nbl_fc_mgt *mgt,
					  struct nbl_flow_query_counter *counter_array,
					  u32 flow_num,
					  bool is_spec)
{
	int ret = 0;
	u32 idx = 0;
	struct nbl_draco_cmd_flow_stat_req stat_req;
	struct nbl_cmd_hdr *hdr = &mgt->cmd_hdr[NBL_CMDQ_CLEAR_SPEC_STAT];
	struct nbl_cmd_content cmd;
	enum nbl_counter_type counter_type;

	if (is_spec) {
		counter_type = NBL_FLOW_SPEC_COUNTER;
	} else {
		if (mgt->select_flow_stat_width72)
			counter_type = NBL_FLOW_WIDTH_72_COUNTER;
		else
			counter_type = NBL_FLOW_WIDTH_144_COUNTER;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.in_length = NBL_DRACO_CMDQ_ACL_STAT_BASE_LEN;
	stat_req.stat_num = flow_num & NBL_FLOW_STAT_NUM_MASK;
	for (idx = 0; idx < flow_num; idx++)
		stat_req.addrs[idx].addr = counter_array->counter_id[idx];

	cmd.in_va = &stat_req.addrs[1];
	cmd.in_params = *((u64 *)&stat_req);

	if (!is_spec)
		hdr = &mgt->cmd_hdr[NBL_CMDQ_CLEAR_FLOW_STAT];

	ret = nbl_tc_call_inst_cmdq(mgt->common->tc_inst_id, (void *)hdr, (void *)&cmd);
	if (ret)
		nbl_err(mgt->common, NBL_DEBUG_FLOW, "clear stats %d, flow num %d failed, addr %d, cmdq ret:%d\n",
			counter_type, flow_num, stat_req.addrs[0].addr, ret);
	else
		nbl_debug(mgt->common, NBL_DEBUG_FLOW, "clear stats %d, flow num %d success.\n",
			  counter_type, flow_num);

	return ret;
}

static int nbl_fc_update_flow_stats(struct nbl_fc_mgt *mgt,
				    struct nbl_flow_query_counter *counter_array,
				    u32 flow_num, u32 clear, bool is_spec_id)
{
	enum nbl_counter_type counter_type;

	if (is_spec_id) {
		counter_type = NBL_FLOW_SPEC_COUNTER;
	} else {
		if (mgt->select_flow_stat_width72)
			counter_type = NBL_FLOW_WIDTH_72_COUNTER;
		else
			counter_type = NBL_FLOW_WIDTH_144_COUNTER;
	}

	/* draco clear flow-stats in add */
	if (clear)
		return 0;

	return nbl_draco_flow_cmd_read_stats(mgt, counter_array, flow_num, counter_type);
}

static int nbl_fc_init_resp_data(struct nbl_fc_mgt *mgt)
{
	spin_lock_init(&mgt->resp_lock);
	mgt->spec_resp = kzalloc(sizeof(*mgt->spec_resp), GFP_KERNEL);
	if (!mgt->spec_resp)
		goto alloc_spec_resp_failed;

	mgt->flow_resp_72 = kzalloc(sizeof(*mgt->flow_resp_72), GFP_KERNEL);
	if (!mgt->flow_resp_72)
		goto alloc_resp_72_failed;

	mgt->flow_resp_144 = kzalloc(sizeof(*mgt->flow_resp_144), GFP_KERNEL);
	if (!mgt->flow_resp_144)
		goto alloc_resp_144_failed;

	return 0;

alloc_resp_144_failed:
	kfree(mgt->flow_resp_72);
alloc_resp_72_failed:
	kfree(mgt->spec_resp);
alloc_spec_resp_failed:
	nbl_err(mgt->common, NBL_DEBUG_FLOW, "nbl init fc resp data failed.");
	return -ENOMEM;
}

static void nbl_fc_free_resp_data(struct nbl_fc_mgt *mgt)
{
	kfree(mgt->spec_resp);
	kfree(mgt->flow_resp_72);
	kfree(mgt->flow_resp_144);
}

static void nbl_fc_init_ops_draco(struct nbl_fc_mgt *fc_mgt)
{
	fc_mgt->fc_ops.get_spec_stat_sz = &nbl_fc_get_spec_sz;
	fc_mgt->fc_ops.get_flow_stat_sz = &nbl_fc_get_flow_sz;
	fc_mgt->fc_ops.get_spec_stats = &nbl_fc_get_spec_stats;
	fc_mgt->fc_ops.get_flow_stats = &nbl_fc_get_flow_stats;
	fc_mgt->fc_ops.update_stats = &nbl_fc_update_flow_stats;
	fc_mgt->fc_ops.init_resp_data = &nbl_fc_init_resp_data;
	fc_mgt->fc_ops.free_resp_data = &nbl_fc_free_resp_data;
}

static inline void nbl_fc_get_cmd_hdr(struct nbl_fc_mgt *fc_mgt)
{
	struct nbl_cmd_hdr *hdr1, *hdr2, *hdr3, *hdr4;
	static const struct nbl_cmd_hdr g_cmd_hdr[] = {
		[NBL_CMDQ_READ_FLOW_STAT] = {NBL_BLOCK_PPE, NBL_CMDQ_MODULE_ACL,
				NBL_CMDQ_ACL_TBL_FLOW_STAT, NBL_CMDQ_ACL_OPCODE_READ},
		[NBL_CMDQ_READ_SPEC_STAT] = {NBL_BLOCK_PPE, NBL_CMDQ_MODULE_ACL,
				NBL_CMDQ_ACL_TBL_SPEC_STAT, NBL_CMDQ_ACL_OPCODE_READ},
		[NBL_CMDQ_CLEAR_FLOW_STAT] = {NBL_BLOCK_PPE, NBL_CMDQ_MODULE_ACL,
				NBL_CMDQ_ACL_TBL_FLOW_STAT, NBL_CMDQ_ACL_OPCODE_WRITE},
		[NBL_CMDQ_CLEAR_SPEC_STAT] = {NBL_BLOCK_PPE, NBL_CMDQ_MODULE_ACL,
				NBL_CMDQ_ACL_TBL_SPEC_STAT, NBL_CMDQ_ACL_OPCODE_WRITE}
	};
	memcpy(fc_mgt->cmd_hdr, g_cmd_hdr, sizeof(g_cmd_hdr));

	hdr1 = &fc_mgt->cmd_hdr[NBL_CMDQ_READ_FLOW_STAT];
	hdr2 = &fc_mgt->cmd_hdr[NBL_CMDQ_READ_SPEC_STAT];
	hdr3 = &fc_mgt->cmd_hdr[NBL_CMDQ_CLEAR_FLOW_STAT];
	hdr4 = &fc_mgt->cmd_hdr[NBL_CMDQ_CLEAR_SPEC_STAT];
}

int nbl_fc_add_stats_draco(void *priv, bool is_spec, u64 cookie,
			   u32 flow_id, u16 bind_car_id)
{
	int ret = 0;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_fc_mgt *fc_mgt = NBL_RES_MGT_TO_COUNTER_MGT(res_mgt);
	struct nbl_flow_query_counter counter_array = {.counter_id[0] = flow_id, };

	ret = nbl_draco_add_stats(priv, is_spec, cookie, flow_id, bind_car_id);
	if (ret >= 0)
		nbl_draco_flow_cmd_clear_stats(fc_mgt, &counter_array, 1, is_spec);

	return ret;
}

int nbl_fc_del_stats_draco(void *priv, bool is_spec, u64 cookie)
{
	return nbl_draco_del_stats(priv, is_spec, cookie);
}

int nbl_fc_mgt_start_draco(struct nbl_resource_mgt *res_mgt)
{
	int ret;
	struct nbl_fc_mgt **fc_mgt = &NBL_RES_MGT_TO_COUNTER_MGT(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	ret = nbl_fc_setup_mgt(dev, fc_mgt);
	if (ret) {
		nbl_info(common, NBL_DEBUG_FLOW, "nbl flow fc init mgt failed");
		return ret;
	}

	ret = phy_ops->get_acl_flow_stat_width(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	if (ret < 0) {
		nbl_err(common, NBL_DEBUG_FLOW, "fc init get flow stat width failed.");
		return ret;
	}

	(*fc_mgt)->select_flow_stat_width72 = ret;
	(*fc_mgt)->res_mgt = res_mgt;
	(*fc_mgt)->common = common;

	nbl_fc_init_ops_draco((*fc_mgt));

	nbl_fc_get_cmd_hdr((*fc_mgt));

	ret = nbl_fc_mgt_start((*fc_mgt));
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "fc init start failed, ret %d", ret);
		goto fc_start_err;
	}

	return ret;

fc_start_err:
	devm_kfree(dev, (*fc_mgt));
	return ret;
}

void nbl_fc_mgt_stop_draco(struct nbl_resource_mgt *res_mgt)
{
	return nbl_fc_mgt_stop(res_mgt);
}

int nbl_fc_setup_ops_draco(struct nbl_resource_ops *res_ops)
{
	return nbl_fc_setup_ops(res_ops);
}

void nbl_fc_remove_ops_draco(struct nbl_resource_ops *res_ops)
{
	return nbl_fc_remove_ops(res_ops);
}
