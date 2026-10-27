// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include "ub_cmdq.h"
#include "ub_cmd_ummu.h"
#include "ub_cmd.h"

#define UBCTL_CQE_SIZE 16
#define UBCTL_SCC_SZ_1M 0x100000
#define UBCTL_LINK_SIZE_MAX 10

struct ubctl_query_trace {
	u32 port_id;
	u32 index;
	u32 cur_count;
	u32 total_count;
	u32 data[];
};

struct ubctl_scc_data {
	u32 phy_addr_low;
	u32 phy_addr_high;
	u32 data_size;
	u32 rsv[3];
};

struct ubctl_msgq_to_user {
	u32 sq_pi;
	u32 sq_ci;
	u32 sq_dep;
	u32 sq_status;
	u32 sq_int_mask;
	u32 sq_int_status;
	u32 sq_int_ro;

	u32 rq_pi;
	u32 rq_ci;
	u32 rq_dep;
	u32 rq_entry_block_size;
	u32 rq_status;

	u32 cq_pi;
	u32 cq_ci;
	u32 cq_dep;
	u32 cq_status;
	u32 cq_int_mask;
	u32 cq_int_status;
	u32 cq_int_ro;

	u32 rsvd[5];
};

struct ubctl_msgq {
	u32 sq_base_addr_low;
	u32 sq_base_addr_high;
	u32 sq_pi;
	u32 sq_ci;
	u32 sq_dep;
	u32 sq_status;
	u32 sq_int_mask;
	u32 sq_int_status;
	u32 sq_int_ro;

	u32 rq_base_addr_low;
	u32 rq_base_addr_high;
	u32 rq_pi;
	u32 rq_ci;
	u32 rq_dep;
	u32 rq_entry_block_size;
	u32 rq_status;

	u32 cq_base_addr_low;
	u32 cq_base_addr_high;
	u32 cq_pi;
	u32 cq_ci;
	u32 cq_dep;
	u32 cq_status;
	u32 cq_int_mask;
	u32 cq_int_status;
	u32 cq_int_ro;

	u32 resv[5];
};

struct ubctl_msgq_phy_addr {
	u64 sq_entry_phy_addr;
	u64 cq_entry_phy_addr;
};

struct ubctl_port_link_info {
	time64_t time;
	u32 link_status;
};

struct ubctl_port_link_stats {
	u32 link_info_num;
	u32 link_up_num;
	u32 link_down_num;
	struct ubctl_port_link_info link_info[UBCTL_LINK_SIZE_MAX];
};

struct ubctl_link_status {
	struct ubctl_port_link_info info;
	struct list_head list;
};

struct ubctl_port_link_list {
	u32 port;
	u32 port_type;
	u32 size;
	u32 link_up_num;
	u32 link_down_num;
	struct ubctl_link_status link_info_list;
	struct list_head port_link_list;
};

struct ubctl_port_link_out_info {
	u32 port;
	u32 link_status;
};

struct ubctl_port_bitmap_data {
	u32 port_bitmap;
	u32 chip_id;
	u32 die_id;
	u32 reserved[3];
};

struct ubctl_port_link_stats_data {
	u32 port_id;
	u32 link_status;
	u32 link_state_info;
	u32 port_type;
	u32 reserved[2];
};

struct ubctl_pkt_in_port_info {
	uint32_t port_id;
	uint16_t query_type;
	uint16_t module_type;
};

#define UBCTL_LINK_PROC_ERR_STATE_SIZE 15
struct utool_mac_dfx_link_state {
	u16 cur_state;
	u16 err_state[UBCTL_LINK_PROC_ERR_STATE_SIZE];
};

struct utool_port_link_info {
	u32 port_id;
	u16 query_type;
	u16 module_type;
	u8 target_speed;
	u8 speed_ability_old;
	u8 lane_num;
	u8 fec;
	u8 sds_rate;
	u8 port_usage : 1;
	u8 port_enable : 1;
	u8 port_link : 1;
	u8 reserved_0 : 5;
	u8 driver_type;
	u8 port_mode;
	u32 link_down_err;
	struct utool_mac_dfx_link_state mac_link_state;
	u32 speed_ability;
};

struct ucdev_list_node {
	u32 chip_id;
	u32 die_id;
	u64 port_bitmap;
	struct list_head dev_list;
	struct list_head list;
};

static LIST_HEAD(g_port_link_list);
static DEFINE_MUTEX(g_ubctl_port_link_mutex);

static DEFINE_MUTEX(g_ubctl_rt_bandwidth_mutex);

static int ubctl_trace_data_deal(struct ubctl_dev *ucdev,
				 struct ubctl_query_cmd_param *query_cmd_param,
				 struct ubctl_cmd *cmd, u32 out_len, u32 offset)
{
#define UBCTL_TRACE_SIZE 4U
#define UBCTL_TOTAL_CNT_MAX 64U

	struct fwctl_rpc_ub_out *trace_out = query_cmd_param->out;
	struct ubctl_query_trace *trace_info = cmd->out_data;
	u32 trace_max_len = query_cmd_param->out_len;
	u32 pos_index = offset * UBCTL_TRACE_SIZE;

	if ((trace_info->total_count > UBCTL_TOTAL_CNT_MAX) ||
	    (trace_info->total_count * UBCTL_TRACE_SIZE >= trace_max_len) ||
	    (pos_index >= trace_max_len || cmd->out_len < sizeof(struct ubctl_query_trace))) {
		ubctl_err(ucdev, "cmd out data length is error.\n");
		return -EINVAL;
	}

	if (pos_index == 0)
		memcpy(trace_out->data, cmd->out_data, cmd->out_len);
	else
		memcpy((u32 *)(trace_out->data) + pos_index, trace_info->data,
		       cmd->out_len - sizeof(struct ubctl_query_trace));

	trace_out->data_size = query_cmd_param->out_len;
	return 0;
}

static int ubctl_send_deal_trace(struct ubctl_dev *ucdev,
				 struct ubctl_query_cmd_param *query_cmd_param,
				 struct ubctl_query_cmd_dp *cmd_data, u32 offset)
{
	u32 out_len = UBCTL_DL_TRACE_LEN;
	struct ubctl_cmd cmd = {};
	int ret = 0;

	if (!cmd_data->query_func->data_deal) {
		ubctl_err(ucdev, "ubctl data deal func is null.\n");
		return -EINVAL;
	}

	cmd.op_code = UBCTL_QUERY_DL_TRACE_DFX;

	ret = ubctl_fill_cmd(&cmd, cmd_data->cmd_in, cmd_data->cmd_out,
			     out_len, UBCTL_READ);
	if (ret) {
		ubctl_err(ucdev, "failed to fill cmd by ubctl.\n");
		return ret;
	}

	ret = ubctl_ubase_cmd_send(ucdev->adev, &cmd);
	if (ret) {
		ubctl_err(ucdev, "failed to send ubase cmd, ret = %d.\n", ret);
		return -EINVAL;
	}

	ret = cmd_data->query_func->data_deal(ucdev, query_cmd_param, &cmd,
					      out_len, offset);
	if (ret)
		ubctl_err(ucdev, "failed to deal ubctl data, ret = %d.\n", ret);

	return ret;
}

static int ubctl_query_dl_trace_data(struct ubctl_dev *ucdev,
				     struct ubctl_query_cmd_param *query_cmd_param,
				     struct ubctl_func_dispatch *query_func)
{
	struct fwctl_pkt_in_port *pkt_in = (struct fwctl_pkt_in_port *)query_cmd_param->in->data;
	u32 trace_index = 0, offset = 0, expect_total = 0, out_len = UBCTL_DL_TRACE_LEN, tmp_sum;
	struct ubctl_query_cmd_dp cmd_dp = {};
	int ret = 0;

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_port)) {
		ubctl_err(ucdev, "user data size = %ubytes, it must be %zubytes.\n",
			  query_cmd_param->in->data_size, sizeof(struct fwctl_pkt_in_port));
		return -EINVAL;
	}

	while (1) {
		struct ubctl_query_trace *cmd_in __free(kvfree) = kvzalloc(out_len, GFP_KERNEL);
		if (!cmd_in)
			return -ENOMEM;

		struct ubctl_query_trace *cmd_out __free(kvfree) = kvzalloc(out_len, GFP_KERNEL);
		if (!cmd_out)
			return -ENOMEM;

		cmd_in->index = trace_index;
		cmd_in->port_id = pkt_in->port_id;

		cmd_dp = (struct ubctl_query_cmd_dp) {
			.query_func = query_func,
			.cmd_in = cmd_in,
			.cmd_out = cmd_out,
		};

		ret = ubctl_send_deal_trace(ucdev, query_cmd_param,
					    &cmd_dp, offset);
		if (ret)
			return ret;

		offset = cmd_out->cur_count + 1;
		trace_index = cmd_out->cur_count;
		tmp_sum = cmd_out->cur_count + cmd_in->index;

		if ((tmp_sum <= expect_total) || (tmp_sum > cmd_out->total_count)) {
			ubctl_err(ucdev, "software data size = %ubytes, it must be in (%u, %u].\n",
				  tmp_sum, expect_total, cmd_out->total_count);
			return -EINVAL;
		}

		if (tmp_sum == cmd_out->total_count)
			break;

		expect_total = tmp_sum;
	}

	return ret;
}

static int ubctl_query_perf_data(struct ubctl_dev *ucdev,
				 struct ubctl_query_cmd_param *query_cmd_param,
				 u32 port_bitmap, u32 period, u32 rpc_cmd)
{
	struct ubase_perf_stats_result *result_data, *tmp_result_data;
	u8 *perf_out_data;
	int ret = 0;
	u32 i = 0;

	if (!ucdev || !query_cmd_param)
		return -EINVAL;

	if (!query_cmd_param->in || !query_cmd_param->out) {
		ubctl_err(ucdev, "the input or output data is null.\n");
		return -EINVAL;
	}

	if (query_cmd_param->out_len != UBCTL_MAX_PORT_NUM * UBCTL_DL_PERF_STATS_LEN ||
	    sizeof(*result_data) < UBCTL_DL_PERF_STATS_LEN) {
		ubctl_err(ucdev, "result data size is not equal to out len.\n");
		return -EINVAL;
	}

	result_data = kvzalloc((UBCTL_MAX_PORT_NUM * sizeof(*result_data)), GFP_KERNEL);
	if (!result_data)
		return -ENOMEM;

	tmp_result_data = result_data;
	if (rpc_cmd == UTOOL_CMD_QUERY_DL_PERF) {
		ret = ubctl_query_perf_stats(ucdev, port_bitmap, result_data, UBCTL_MAX_PORT_NUM);
		if (ret)
			goto query_perf_failed;
	} else {
		ret = ubctl_query_perf(ucdev, port_bitmap, result_data, UBCTL_MAX_PORT_NUM, period);
		if (ret)
			goto query_perf_failed;
	}

	perf_out_data = (u8 *)query_cmd_param->out->data;
	for (i = 0; i < UBCTL_MAX_PORT_NUM; i++) {
		memcpy(perf_out_data, result_data, UBCTL_DL_PERF_STATS_LEN);
		query_cmd_param->out->data_size += UBCTL_DL_PERF_STATS_LEN;
		perf_out_data += UBCTL_DL_PERF_STATS_LEN;
		result_data++;
	}

query_perf_failed:
	if (ret)
		ubctl_err(ucdev, "failed to query perf by ubctl, ret = %d.\n", ret);
	kvfree(tmp_result_data);
	return ret;
}

static int ubctl_query_dl_perf_data(struct ubctl_dev *ucdev,
				    struct ubctl_query_cmd_param *query_cmd_param,
				    struct ubctl_func_dispatch *query_func)
{
	if (query_cmd_param->in == NULL) {
		ubctl_err(ucdev, "the input data is null.\n");
		return -EFAULT;
	}

	struct fwctl_pkt_in_port_time *pkt_in =
		(struct fwctl_pkt_in_port_time *)query_cmd_param->in->data;

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_port_time)) {
		ubctl_err(ucdev, "user data size = %ubytes, it must be %zubytes.\n",
			  query_cmd_param->in->data_size, sizeof(struct fwctl_pkt_in_port_time));
		return -EINVAL;
	}

	return ubctl_query_perf_data(ucdev, query_cmd_param, pkt_in->port_id,
				     pkt_in->time, query_func->rpc_cmd);
}

static int ubctl_query_dl_all_perf_data(struct ubctl_dev *ucdev,
					struct ubctl_query_cmd_param *query_cmd_param,
					struct ubctl_func_dispatch *query_func)
{
	struct fwctl_pkt_in_time *pkt_in = (struct fwctl_pkt_in_time *)query_cmd_param->in->data;

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_time)) {
		ubctl_err(ucdev, "user data size = %ubytes, it must be %zubytes.\n",
			  query_cmd_param->in->data_size, sizeof(struct fwctl_pkt_in_time));
		return -EINVAL;
	}

	return ubctl_query_perf_data(ucdev, query_cmd_param, 0, pkt_in->time, query_func->rpc_cmd);
}

static int ubctl_query_dl_perf_stats_data(struct ubctl_dev *ucdev,
					  struct ubctl_query_cmd_param *query_cmd_param,
					  struct ubctl_func_dispatch *query_func)
{
	int ret;

	if (query_cmd_param->in == NULL) {
		ubctl_err(ucdev, "the input data is null.\n");
		return -EFAULT;
	}

	struct fwctl_pkt_in_port *pkt_in = (struct fwctl_pkt_in_port *)query_cmd_param->in->data;

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_port)) {
		ubctl_err(ucdev, "user data size = %ubytes, it must be %zubytes.\n",
			  query_cmd_param->in->data_size, sizeof(struct fwctl_pkt_in_port));
		return -EINVAL;
	}

	ret = ubctl_query_perf_data(ucdev, query_cmd_param, pkt_in->port_id,
				    0, query_func->rpc_cmd);
	query_cmd_param->out->retval = ret;

	return ret;
}

static int ubctl_query_dl_start_perf_data(struct ubctl_dev *ucdev,
					  struct ubctl_query_cmd_param *query_cmd_param,
					  struct ubctl_func_dispatch *query_func)
{
	struct fwctl_pkt_in_port_time *pkt_in;
	int ret;

	if (query_cmd_param->in == NULL) {
		ubctl_err(ucdev, "the input data is empty.\n");
		return -EFAULT;
	}

	pkt_in = (struct fwctl_pkt_in_port_time *)query_cmd_param->in->data;

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_port_time)) {
		ubctl_err(ucdev, "user data size = %ubytes, it must be %zubytes.\n",
			  query_cmd_param->in->data_size, sizeof(struct fwctl_pkt_in_port_time));
		return -EINVAL;
	}

	ret = ubase_open_perf_stats(ucdev->adev, pkt_in->port_id, pkt_in->time);
	if (ret)
		ubctl_err(ucdev, "failed to execute ubase open perf stats, ret = %d.\n", ret);

	query_cmd_param->out->retval = ret;

	return ret;
}

static int ubctl_query_dl_stop_perf_data(struct ubctl_dev *ucdev,
					 struct ubctl_query_cmd_param *query_cmd_param,
					 struct ubctl_func_dispatch *query_func)
{
	struct fwctl_pkt_in_port *pkt_in;
	int ret;

	if (query_cmd_param->in == NULL) {
		ubctl_err(ucdev, "the input data is empty.\n");
		return -EFAULT;
	}

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_port)) {
		ubctl_err(ucdev, "user data size = %ubytes, it must be %zubytes.\n",
			  query_cmd_param->in->data_size, sizeof(struct fwctl_pkt_in_port));
		return -EINVAL;
	}

	pkt_in = (struct fwctl_pkt_in_port *)query_cmd_param->in->data;

	ret = ubase_close_perf_stats(ucdev->adev, pkt_in->port_id);
	if (ret)
		ubctl_err(ucdev, "failed to execute ubase close perf stats, ret = %d.\n", ret);

	return ret;
}

static int ubctl_scc_data_deal(struct ubctl_dev *ucdev, u32 index,
			       struct fwctl_rpc_ub_out *out,
			       struct ubctl_scc_data *scc)
{
#define UBCTL_SCC_OUT_LEN ((UBCTL_SCC_SZ_1M) / (sizeof(u32)))
#define UBCTL_SCC_INDEX_MAX_NUM 1

	u32 scc_data_len = scc->data_size / sizeof(u32);
	u32 data_len = out->data_size / sizeof(u32);
	u32 offset = index * UBCTL_SCC_OUT_LEN;
	u32 *scc_data = out->data;
	void __iomem *vir_addr;
	u64 phy_addr;
	u32 i, j;

	if (index > UBCTL_SCC_INDEX_MAX_NUM) {
		ubctl_err(ucdev, "scc index %u is bigger than maximum %u.\n", index,
			  UBCTL_SCC_INDEX_MAX_NUM);
		return -EINVAL;
	}

	phy_addr = UBCTL_GET_PHY_ADDR(scc->phy_addr_high, scc->phy_addr_low);
	if (!phy_addr) {
		ubctl_err(ucdev, "scc phy addr is invalid.\n");
		return -EFAULT;
	}

	vir_addr = ioremap(phy_addr, scc->data_size);
	if (!vir_addr) {
		ubctl_err(ucdev, "failed to execute ioremap.\n");
		return -EFAULT;
	}

	for (i = offset, j = 0; i < scc_data_len && j < data_len; i++, j++)
		scc_data[j] = readl(vir_addr + i * sizeof(u32));

	iounmap(vir_addr);
	return 0;
}

static int ubctl_scc_data_len_check(struct ubctl_dev *ucdev, u32 out_len,
				    u32 data_size, u32 scc_len)
{
#define UBCTL_SCC_CACHE 0x200000

	if (data_size != UBCTL_SCC_CACHE) {
		ubctl_err(ucdev, "scc data size = %ubytes, and it must be 2M.\n",
			  data_size);
		return -EINVAL;
	}

	if (out_len != scc_len) {
		ubctl_err(ucdev, "scc out len = %ubytes, and it must be %ubytes.\n",
			  out_len, scc_len);
		return -EINVAL;
	}

	return 0;
}

static int ubctl_scc_version_deal(struct ubctl_dev *ucdev,
				  struct ubctl_query_cmd_param *query_cmd_param,
				  struct ubctl_cmd *cmd, u32 out_len, u32 offset)
{
#define UBCTL_SCC_VERSION_SZ 24

	struct fwctl_pkt_in_index *pkt_in = NULL;
	struct ubctl_scc_data *scc = NULL;
	int ret = 0;

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_index)) {
		ubctl_err(ucdev, "user data size = %ubytes, it must be %zubytes.\n",
			  query_cmd_param->in->data_size, sizeof(struct fwctl_pkt_in_index));
		return -EINVAL;
	}
	pkt_in = (struct fwctl_pkt_in_index *)query_cmd_param->in->data;
	scc = (struct ubctl_scc_data *)cmd->out_data;

	ret = ubctl_scc_data_len_check(ucdev, query_cmd_param->out_len,
				       scc->data_size, UBCTL_SCC_VERSION_SZ);
	if (ret) {
		ubctl_err(ucdev, "failed to check scc version data len, ret = %d.\n", ret);
		return -EINVAL;
	}

	query_cmd_param->out->data_size = query_cmd_param->out_len;
	scc->data_size = sizeof(u32);

	return ubctl_scc_data_deal(ucdev, pkt_in->index, query_cmd_param->out, scc);
}

static int ubctl_scc_log_deal(struct ubctl_dev *ucdev,
			      struct ubctl_query_cmd_param *query_cmd_param,
			      struct ubctl_cmd *cmd, u32 out_len, u32 offset)
{
	struct fwctl_pkt_in_index *pkt_in = (struct fwctl_pkt_in_index *)query_cmd_param->in->data;
	struct ubctl_scc_data *scc = (struct ubctl_scc_data *)cmd->out_data;
	int ret = 0;

	if (query_cmd_param->in->data_size != sizeof(*pkt_in)) {
		ubctl_err(ucdev, "user data size = %ubytes, it must be %zubytes.\n",
			  query_cmd_param->in->data_size, sizeof(*pkt_in));
		return -EINVAL;
	}

	ret = ubctl_scc_data_len_check(ucdev, query_cmd_param->out_len,
				       scc->data_size, UBCTL_SCC_SZ_1M);
	if (ret) {
		ubctl_err(ucdev, "failed to check scc log data len, ret = %d.\n", ret);
		return -EINVAL;
	}

	query_cmd_param->out->data_size = query_cmd_param->out_len;

	return ubctl_scc_data_deal(ucdev, pkt_in->index, query_cmd_param->out, scc);
}

static int ubctl_query_scc_data(struct ubctl_dev *ucdev,
				struct ubctl_query_cmd_param *query_cmd_param,
				struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_SCC_DFX, UBCTL_SCC_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_port_infos(struct ubctl_dev *ucdev,
				  struct ubctl_query_cmd_param *query_cmd_param,
				  struct ubctl_func_dispatch *query_func,
				  u32 port_bitmap)
{
#define UBCTL_U32_BIT_NUM 32U

	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_DL_LINK_STATUS_DFX, UBCTL_DL_LINK_STATUS_LEN, UBCTL_READ, NULL, 0 },
	};
	u32 iodie_len = sizeof(struct fwctl_rpc_ub_out) + UBCTL_IO_DIE_INFO_LEN;
	u32 out_data_offset = UBCTL_IO_DIE_INFO_LEN / sizeof(u32);
	struct fwctl_rpc_ub_out *out = query_cmd_param->out;
	u32 out_mem_size = query_cmd_param->out_len;
	u32 *pkt_in = query_cmd_param->in->data;
	u32 data_size = out->data_size;
	int port_num = 0;
	int ret = 0;
	u32 i;

	if (port_bitmap == 0)
		return ret;

	struct fwctl_rpc_ub_out *out_temp __free(kvfree) = kvzalloc(iodie_len, GFP_KERNEL);
	if (!out_temp)
		return -ENOMEM;

	query_cmd_param->out = out_temp;

	for (i = 0; i < UBCTL_U32_BIT_NUM; i++) {
		if (!(port_bitmap & (1UL << i)))
			continue;
		out_temp->data_size = 0;
		*pkt_in = i;
		ret = ubctl_query_data(ucdev, query_cmd_param, query_func,
				       query_dp, ARRAY_SIZE(query_dp));
		if (ret != 0)
			break;

		if ((out_temp->data_size + out_data_offset * sizeof(u32)) > out_mem_size) {
			ubctl_err(ucdev, "port info size = %u, total size = %u, offset size = %lu.\n",
				  out_temp->data_size, out_mem_size, out_data_offset * sizeof(u32));
			ret = -ENOMEM;
			break;
		}

		memcpy(&out->data[out_data_offset], out_temp->data, out_temp->data_size);
		data_size += out_temp->data_size;
		out_data_offset += UBCTL_DL_LINK_STATUS_LEN / sizeof(u32);
		port_num++;
	}

	query_cmd_param->out = out;
	out->data_size = data_size;
	out->data[0] = port_num;

	return ret;
}

static int ubctl_query_iodie_info_data(struct ubctl_dev *ucdev,
				       struct ubctl_query_cmd_param *query_cmd_param,
				       struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_PORT_NUM_DFX, UBCTL_IO_DIE_INFO_LEN, UBCTL_READ, NULL, 0 },
	};
	u32 port_bitmap;
	int ret;

	ret = ubctl_query_data(ucdev, query_cmd_param, query_func,
			       query_dp, ARRAY_SIZE(query_dp));
	if (ret != 0)
		return ret;

	if (query_cmd_param->out->data_size < sizeof(u32))
		return -ENOMEM;
	port_bitmap = *query_cmd_param->out->data;

	return ubctl_query_port_infos(ucdev, query_cmd_param, query_func, port_bitmap);
}

static int ubctl_msgq_que_data_deal(struct ubctl_dev *ucdev,
				    struct ubctl_query_cmd_param *query_cmd_param,
				    struct ubctl_cmd *cmd, u32 out_len, u32 offset)
{
	struct ubctl_msgq *msgq_que_info = (struct ubctl_msgq *)cmd->out_data;
	struct ubctl_msgq_to_user *user_msgq_info = NULL;
	u32 msgq_que_size = query_cmd_param->out_len;

	if (cmd->out_len != out_len ||
	    msgq_que_size != sizeof(struct ubctl_msgq_to_user))
		return -EINVAL;

	user_msgq_info = (struct ubctl_msgq_to_user *)(query_cmd_param->out->data);

	user_msgq_info->sq_pi = msgq_que_info->sq_pi;
	user_msgq_info->sq_ci = msgq_que_info->sq_ci;
	user_msgq_info->sq_dep = msgq_que_info->sq_dep;
	user_msgq_info->sq_status = msgq_que_info->sq_status;
	user_msgq_info->sq_int_mask = msgq_que_info->sq_int_mask;
	user_msgq_info->sq_int_status = msgq_que_info->sq_int_status;
	user_msgq_info->sq_int_ro = msgq_que_info->sq_int_ro;

	user_msgq_info->rq_pi = msgq_que_info->rq_pi;
	user_msgq_info->rq_ci = msgq_que_info->rq_ci;
	user_msgq_info->rq_dep = msgq_que_info->rq_dep;
	user_msgq_info->rq_entry_block_size = msgq_que_info->rq_entry_block_size;
	user_msgq_info->rq_status = msgq_que_info->rq_status;

	user_msgq_info->cq_pi = msgq_que_info->cq_pi;
	user_msgq_info->cq_ci = msgq_que_info->cq_ci;
	user_msgq_info->cq_dep = msgq_que_info->cq_dep;
	user_msgq_info->cq_status = msgq_que_info->cq_status;
	user_msgq_info->cq_int_mask = msgq_que_info->cq_int_mask;
	user_msgq_info->cq_int_status = msgq_que_info->cq_int_status;
	user_msgq_info->cq_int_ro = msgq_que_info->cq_int_ro;

	query_cmd_param->out->data_size = msgq_que_size;

	return 0;
}

static int ubctl_msgq_is_dump(void __iomem *entry_addr)
{
#define UBCTL_MSGQ_PROTOCOL_OPCODE 5
#define UBCTL_MSGQ_OPCODE_START 9
#define UBCTL_MSGQ_OPCODE_END 11

	u32 first_data = readl(entry_addr);
	u32 protocol_op_code = 0;
	u32 task_type = 0;

	protocol_op_code = UBCTL_EXTRACT_BITS(first_data,
					      UBCTL_MSGQ_OPCODE_START,
					      UBCTL_MSGQ_OPCODE_END);
	task_type = UBCTL_EXTRACT_BITS(first_data, 0, 1);
	if (task_type == 0 && protocol_op_code == UBCTL_MSGQ_PROTOCOL_OPCODE)
		return -EINVAL;

	return 0;
}

static int ubctl_msgq_entry_move_data(struct ubctl_query_cmd_param *query_cmd_param,
				      u32 offset, u32 block_size,
				      void __iomem *entry_addr)
{
	u32 msgq_entry_data_size = block_size + offset * sizeof(u32);
	u32 *data_offset = query_cmd_param->out->data + offset;
	u32 block_num = block_size / sizeof(u32);
	u32 i;

	if (msgq_entry_data_size > query_cmd_param->out_len)
		return -EINVAL;

	for (i = 0; i < block_num; i++)
		data_offset[i] = readl((void __iomem *)((u32 *)entry_addr + i));

	return 0;
}

static int ubctl_msgq_check_index(struct ubctl_dev *ucdev, u32 entry_index,
				  struct ubctl_msgq *entry_info)
{
	if (entry_index >= entry_info->sq_dep ||
	    entry_index >= entry_info->cq_dep) {
		ubctl_err(ucdev, "index = %u is illegal.\n", entry_index);
		return -EINVAL;
	}

	return 0;
}

static int ubctl_msgq_all_get_phy_addr(struct ubctl_dev *ucdev, u32 entry_index,
				       struct ubctl_msgq_phy_addr *entry_phy_addr,
				       struct ubctl_msgq *entry_info)
{
#define UBCTL_SQE_SIZE 16

	u64 base_addr;
	int ret;

	ret = ubctl_msgq_check_index(ucdev, entry_index, entry_info);
	if (ret)
		return ret;

	base_addr = UBCTL_GET_PHY_ADDR(entry_info->sq_base_addr_high,
				       entry_info->sq_base_addr_low);
	if (!base_addr) {
		ubctl_err(ucdev, "failed to initial sqe msgq.\n");
		return -EINVAL;
	}

	entry_phy_addr->sq_entry_phy_addr = base_addr +
					    entry_index * UBCTL_SQE_SIZE;

	base_addr = UBCTL_GET_PHY_ADDR(entry_info->cq_base_addr_high,
				       entry_info->cq_base_addr_low);
	if (!base_addr) {
		ubctl_err(ucdev, "failed to initial cqe msgq.\n");
		return -EINVAL;
	}

	entry_phy_addr->cq_entry_phy_addr = base_addr +
					    entry_index * UBCTL_CQE_SIZE;

	return 0;
}

static int ubctl_msgq_sq_entry_data_deal(struct ubctl_dev *ucdev,
					 u64 sq_entry_phy_addr,
					 struct ubctl_query_cmd_param *query_cmd_param)
{
#define UBCTL_SQE_TO_USER_SIZE 8

	void __iomem *sq_entry_addr;
	int ret = 0;

	sq_entry_addr = memremap(sq_entry_phy_addr, UBCTL_SQE_TO_USER_SIZE, MEMREMAP_WB);
	if (!sq_entry_addr)
		return -EFAULT;

	ret = ubctl_msgq_is_dump(sq_entry_addr);
	if (ret) {
		ubctl_err(ucdev, "this entry cannot be dumped, sqe is SPDM verified msg.\n");
		goto err_exec;
	}

	ret = ubctl_msgq_entry_move_data(query_cmd_param, 0,
					 UBCTL_SQE_TO_USER_SIZE, sq_entry_addr);
	if (ret)
		ubctl_err(ucdev, "failed to move sqe data.\n");

err_exec:
	memunmap(sq_entry_addr);
	return ret;
}

static int ubctl_msgq_cq_entry_data_deal(struct ubctl_dev *ucdev,
					 u64 cq_entry_phy_addr,
					 struct ubctl_query_cmd_param *query_cmd_param)
{
#define UBCTL_CQE_OFFSET 2

	void __iomem *cq_entry_addr;
	int ret = 0;

	cq_entry_addr = memremap(cq_entry_phy_addr, UBCTL_CQE_SIZE, MEMREMAP_WB);
	if (!cq_entry_addr)
		return -EFAULT;

	ret = ubctl_msgq_is_dump(cq_entry_addr);
	if (ret) {
		ubctl_err(ucdev, "this entry cannot be dumped, cqe is SPDM verified msg.\n");
		goto err_exec;
	}

	ret = ubctl_msgq_entry_move_data(query_cmd_param, UBCTL_CQE_OFFSET,
					 UBCTL_CQE_SIZE, cq_entry_addr);
	if (ret)
		ubctl_err(ucdev, "failed to move cqe data.\n");

err_exec:
	memunmap(cq_entry_addr);
	return ret;
}

static int ubctl_msgq_entry_data_deal(struct ubctl_dev *ucdev,
				      struct ubctl_query_cmd_param *query_cmd_param,
				      struct ubctl_cmd *cmd, u32 out_len, u32 offset)
{
	struct ubctl_msgq *entry_info = (struct ubctl_msgq *)cmd->out_data;
	u32 msgq_entry_max_len = query_cmd_param->out_len;
	struct ubctl_msgq_phy_addr entry_phy_addr = {};
	u32 entry_index = 0;
	int ret = 0;

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_index)) {
		ubctl_err(ucdev, "user data size = %ubytes, it must be %zubytes.\n",
			  query_cmd_param->in->data_size, sizeof(struct fwctl_pkt_in_index));
		return -EINVAL;
	}
	entry_index = ((struct fwctl_pkt_in_index *)query_cmd_param->in->data)->index;

	ret = ubctl_msgq_all_get_phy_addr(ucdev, entry_index, &entry_phy_addr,
					  entry_info);
	if (ret)
		return ret;

	ret = ubctl_msgq_sq_entry_data_deal(ucdev,
					    entry_phy_addr.sq_entry_phy_addr,
					    query_cmd_param);
	if (ret)
		return ret;

	ret = ubctl_msgq_cq_entry_data_deal(ucdev,
					    entry_phy_addr.cq_entry_phy_addr,
					    query_cmd_param);
	if (ret)
		return ret;

	query_cmd_param->out->data_size = msgq_entry_max_len;

	return ret;
}

static int ubctl_query_msgq_que_stats_data(struct ubctl_dev *ucdev,
					   struct ubctl_query_cmd_param *query_cmd_param,
					   struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_MSGQ_DFX, UBCTL_MSGQ_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static struct ucdev_list_node *ubctl_find_ucdev_list_node(u32 die_id, u32 chip_id)
{
	struct ucdev_list_node *dev_node;

	list_for_each_entry(dev_node, &g_port_link_list, list) {
		if (dev_node->chip_id == chip_id && dev_node->die_id == die_id)
			return dev_node;
	}

	return NULL;
}

static struct ubctl_port_link_list *ubctl_add_port_node(u32 die_id, u32 port,
							struct ucdev_list_node *dev_node)
{
	struct ubctl_port_link_list *new_node = kvzalloc(sizeof(*new_node), GFP_KERNEL);

	if (!new_node)
		return NULL;

	new_node->port = port;
	new_node->size = 0;
	new_node->link_down_num = 0;
	new_node->link_up_num = 0;
	INIT_LIST_HEAD(&new_node->link_info_list.list);
	INIT_LIST_HEAD(&new_node->port_link_list);
	mutex_lock(&g_ubctl_port_link_mutex);
	list_add_tail(&new_node->port_link_list, &dev_node->dev_list);
	mutex_unlock(&g_ubctl_port_link_mutex);

	return new_node;
}

static int ubctl_port_add_link_node(struct ubctl_port_link_list *ubctl_port_link_node,
				    struct ubctl_port_link_info link_info, u32 size)
{
#define UTOOL_LINK_UP_FLAG 0
	struct ubctl_link_status *ubctl_link_status_list;
	struct ubctl_link_status *new_node = NULL;
	struct ubctl_link_status *old_head;

	new_node = kvzalloc(sizeof(*new_node), GFP_KERNEL);
	if (!new_node)
		return -ENOMEM;

	ubctl_link_status_list = &ubctl_port_link_node->link_info_list;
	new_node->info = link_info;
	INIT_LIST_HEAD(&new_node->list);
	list_add_tail(&new_node->list, &ubctl_link_status_list->list);

	if (size == UBCTL_LINK_SIZE_MAX) {
		old_head = list_entry(ubctl_link_status_list->list.next,
				      struct ubctl_link_status, list);
		list_del(&old_head->list);
		kvfree(old_head);
	}

	if (link_info.link_status == UTOOL_LINK_UP_FLAG)
		ubctl_port_link_node->link_up_num++;
	else
		ubctl_port_link_node->link_down_num++;

	return 0;
}

static int ubctl_query_port_bitmap_data(struct auxiliary_device *adev,
					struct ubctl_dev *ucdev, u32 die_id, u32 chip_id)
{
	struct ubctl_port_bitmap_data in_data, out_data;
	struct ucdev_list_node *dev_node;
	struct ubctl_cmd cmd = {};
	int ret = 0;

	cmd.op_code = UBCTL_QUERY_PORT_NUM_DFX;
	ret = ubctl_fill_cmd(&cmd, (void *)&in_data, (void *)&out_data, sizeof(out_data), true);
	if (ret) {
		ubctl_err(ucdev, "failed to fill the cmd params.\n");
		return ret;
	}

	ret = ubctl_ubase_cmd_send(adev, &cmd);
	if (ret) {
		ubctl_err(ucdev, "failed to execute ubase cmd send, retval = %d.\n", ret);
		return -EINVAL;
	}

	mutex_lock(&g_ubctl_port_link_mutex);
	dev_node = ubctl_find_ucdev_list_node(die_id, chip_id);
	if (dev_node == NULL) {
		mutex_unlock(&g_ubctl_port_link_mutex);
		ubctl_err(ucdev, "failed to find ucdev list node.\n");
		return -EINVAL;
	}
	dev_node->port_bitmap = (u64)out_data.port_bitmap;
	mutex_unlock(&g_ubctl_port_link_mutex);

	return ret;
}

static bool ubctl_get_port_link_status(struct auxiliary_device *adev, struct ubctl_dev *ucdev,
				       u32 port_id, u32 port_type)
{
#define UTOOL_QUERY_TYPE_DATA 1
#define UTOOL_MODULE_TYPE_LINK_INFO_ETH 1
#define UTOOL_MODULE_TYPE_LINK_INFO_UB 4

	struct ubctl_pkt_in_port_info pkt_in_data = {
		.port_id = port_id,
		.query_type = UTOOL_QUERY_TYPE_DATA,
		.module_type = 0
	};
	struct utool_port_link_info out_data = {};
	struct ubctl_cmd cmd = {};
	int ret;

	if (port_type == UBCTL_PORT_TYPE_UB) {
		pkt_in_data.module_type = UTOOL_MODULE_TYPE_LINK_INFO_UB;
	} else if (port_type == UBCTL_PORT_TYPE_ETH) {
		pkt_in_data.module_type = UTOOL_MODULE_TYPE_LINK_INFO_ETH;
	} else {
		ubctl_err(ucdev, "unknown port type (%u).\n", port_type);
		return false;
	}

	cmd.op_code = UBCTL_QUERY_PORT_INFO_DFX;
	ret = ubctl_fill_cmd_isread(&cmd, (void *)&pkt_in_data, (void *)&out_data,
				    sizeof(out_data), sizeof(pkt_in_data));
	if (ret) {
		ubctl_err(ucdev, "failed to fill the cmd params for query link status.\n");
		return false;
	}

	ret = ubctl_ubase_cmd_send(adev, &cmd);
	if (ret) {
		ubctl_err(ucdev,
			  "failed to execute ubase cmd for query link status, ret = %d.\n", ret);
		return false;
	}

	return (out_data.port_link != 0);
}

static bool ubctl_check_port_link_stats(struct auxiliary_device *adev,
					struct ubctl_dev *ucdev, u32 port_id,
					struct ubctl_port_link_list *port_node)
{
	struct ubctl_port_link_stats_data in_data, out_data;
	struct ubctl_cmd cmd = {};
	int ret = 0;

	port_node->port_type = UBCTL_PORT_TYPE_UB;
	cmd.op_code = UBCTL_QUERY_DL_LINK_STATUS_DFX;
	in_data.port_id = port_id;
	ret = ubctl_fill_cmd(&cmd, (void *)&in_data, (void *)&out_data, sizeof(out_data), true);
	if (ret) {
		ubctl_err(ucdev, "failed to fill the cmd params.\n");
		return false;
	}

	ret = ubctl_ubase_cmd_send(adev, &cmd);
	if (ret) {
		ubctl_err(ucdev, "failed to execute ubase cmd send, retval = %d.\n", ret);
		return false;
	}
	port_node->port_type = out_data.port_type;
	return ubctl_get_port_link_status(adev, ucdev, port_id, out_data.port_type);
}

static int ubctl_construct_first_link_data(struct auxiliary_device *adev,
					   struct ubctl_dev *ucdev, struct ubase_caps *ucaps)
{
	struct ubctl_port_link_list *new_port_node = NULL;
	struct ubctl_port_link_info link_info;
	struct ucdev_list_node *dev_node;
	u32 port_id;
	int ret = 0;

	ret = ubctl_query_port_bitmap_data(adev, ucdev, ucaps->die_id, ucaps->chip_id);
	if (ret)
		return ret;

	mutex_lock(&g_ubctl_port_link_mutex);
	dev_node = ubctl_find_ucdev_list_node(ucaps->die_id, ucaps->chip_id);
	if (dev_node == NULL) {
		mutex_unlock(&g_ubctl_port_link_mutex);
		ubctl_err(ucdev, "failed to find ucdev list node.\n");
		return -EINVAL;
	}
	mutex_unlock(&g_ubctl_port_link_mutex);

	for (port_id = 0; port_id < UBCTL_MAX_PORT_NUM; port_id++) {
		if (!test_bit(port_id, (unsigned long *)&dev_node->port_bitmap))
			continue;

		new_port_node = ubctl_add_port_node(ucaps->die_id, port_id, dev_node);
		if (!new_port_node)
			return -ENOMEM;

		if (!ubctl_check_port_link_stats(adev, ucdev, port_id, new_port_node))
			continue;

		link_info.time = ktime_get_real_seconds();
		link_info.link_status = 0;
		ret = ubctl_port_add_link_node(new_port_node, link_info, new_port_node->size);
		if (ret) {
			ubctl_warn(ucdev, "ubctl can't construct first link data.\n");
			return ret;
		}

		new_port_node->size++;
	}

	return ret;
}

static struct ubase_crq_event_nb ubctl_crq_events = {
	.opcode = UBCTL_QUERY_PORT_LINK_STATS_DFX,
	.crq_handler = ubctl_handle_link_status_event,
};

int ubctl_port_link_status_init(struct auxiliary_device *adev, struct ubctl_dev *ucdev)
{
	struct ubase_caps *ucaps;
	int ret = 0;

	if (!adev || !ucdev)
		return -EINVAL;

	ucaps = ubase_get_dev_caps(adev);
	if (ucaps == NULL)
		return -ENODEV;

	struct ucdev_list_node *new_node = kvzalloc(sizeof(*new_node), GFP_KERNEL);

	if (!new_node)
		return -ENOMEM;

	new_node->chip_id = ucaps->chip_id;
	new_node->die_id = ucaps->die_id;
	INIT_LIST_HEAD(&new_node->list);
	INIT_LIST_HEAD(&new_node->dev_list);
	list_add(&new_node->list, &g_port_link_list);

	ret = ubctl_construct_first_link_data(adev, ucdev, ucaps);
	if (ret) {
		ubctl_warn(ucdev, "ubctl can't construct first link data.\n");
		return ret;
	}

	ubctl_crq_events.back = adev;
	ret = ubase_register_crq_event(adev, &ubctl_crq_events);
	if (ret)
		return ret;

	return 0;
}

void ubctl_port_link_status_uninit(struct auxiliary_device *adev)
{
	struct ubctl_port_link_list *current_node, *next;
	struct ubctl_link_status *del_node, *del_next;
	struct ucdev_list_node *dev_node;
	struct ubase_caps *ucaps;

	ucaps = ubase_get_dev_caps(adev);
	if (ucaps == NULL)
		return;

	ubase_unregister_crq_event(adev, ubctl_crq_events.opcode);

	mutex_lock(&g_ubctl_port_link_mutex);
	dev_node = ubctl_find_ucdev_list_node(ucaps->die_id, ucaps->chip_id);
	if (dev_node == NULL) {
		mutex_unlock(&g_ubctl_port_link_mutex);
		return;
	}

	list_for_each_entry_safe(current_node, next, &dev_node->dev_list, port_link_list) {
		list_for_each_entry_safe(del_node, del_next,
					 &current_node->link_info_list.list, list) {
			list_del(&del_node->list);
			kvfree(del_node);
		}
		list_del(&current_node->port_link_list);
		kvfree(current_node);
	}
	list_del(&dev_node->list);
	kvfree(dev_node);
	mutex_unlock(&g_ubctl_port_link_mutex);
}

static const char *ubctl_link_status_to_str(u32 status)
{
#define UBCTL_LINK_STATUS_UP 0U
#define UBCTL_LINK_STATUS_DOWN 1U

	switch (status) {
	case UBCTL_LINK_STATUS_UP:
		return "UP";
	case UBCTL_LINK_STATUS_DOWN:
		return "DOWN";
	default:
		return "UNKNOWN";
	}
}

int ubctl_handle_link_status_event(void *dev, void *data, u32 len)
{
	struct ubctl_port_link_list *new_port_node = NULL, *current_node;
	struct auxiliary_device *adev = (struct auxiliary_device *)dev;
	struct ubctl_port_link_info link_info;
	struct ucdev_list_node *dev_node;
	struct ubase_caps *ucaps;
	int ret = 0;
	u32 port;

	if (!dev || !data || len < sizeof(struct ubctl_port_link_out_info))
		return -EINVAL;

	ucaps = ubase_get_dev_caps(adev);
	if (ucaps == NULL)
		return -EINVAL;

	mutex_lock(&g_ubctl_port_link_mutex);
	dev_node = ubctl_find_ucdev_list_node(ucaps->die_id, ucaps->chip_id);
	if (dev_node == NULL) {
		mutex_unlock(&g_ubctl_port_link_mutex);
		return -EINVAL;
	}

	link_info.time = ktime_get_real_seconds();
	link_info.link_status = ((struct ubctl_port_link_out_info *)data)->link_status;
	port = ((struct ubctl_port_link_out_info *)data)->port;

	dev_info(&adev->dev, "the link status has changed, chip = %u, die = %u, port = %u, link_status = %u(%s).\n",
		 ucaps->chip_id, ucaps->die_id, port, link_info.link_status,
		 ubctl_link_status_to_str(link_info.link_status));

	list_for_each_entry(current_node, &dev_node->dev_list, port_link_list) {
		if (current_node->port != port)
			continue;

		ret = ubctl_port_add_link_node(current_node, link_info, current_node->size);
		if (ret) {
			mutex_unlock(&g_ubctl_port_link_mutex);
			return ret;
		}
		if (current_node->size < UBCTL_LINK_SIZE_MAX)
			current_node->size++;

		mutex_unlock(&g_ubctl_port_link_mutex);
		return ret;
	}
	mutex_unlock(&g_ubctl_port_link_mutex);

	new_port_node = ubctl_add_port_node(ucaps->die_id, port, dev_node);
	if (!new_port_node)
		return -EINVAL;

	mutex_lock(&g_ubctl_port_link_mutex);
	ret = ubctl_port_add_link_node(new_port_node, link_info, new_port_node->size);
	if (ret) {
		mutex_unlock(&g_ubctl_port_link_mutex);
		return ret;
	}
	new_port_node->size++;
	mutex_unlock(&g_ubctl_port_link_mutex);

	return ret;
}

static int ubctl_check_port_id(struct ubctl_dev *ucdev, struct fwctl_pkt_in_port *pkt_in,
			       u64 port_bitmap)
{
	int ret = 0;

	if (pkt_in->port_id >= UBCTL_MAX_PORT_NUM ||
	    !test_bit(pkt_in->port_id, (unsigned long *)&port_bitmap)) {
		ubctl_err(ucdev, "ubctl port id = %u, ant it didn't meet expectations.\n",
			  pkt_in->port_id);
		return -EINVAL;
	}

	return ret;
}

static int ubctl_query_port_link_status(struct ubctl_dev *ucdev,
					struct ubctl_query_cmd_param *query_cmd_param,
					struct ubctl_func_dispatch *query_func)
{
	struct fwctl_pkt_in_port *pkt_in = (struct fwctl_pkt_in_port *)query_cmd_param->in->data;
	struct fwctl_rpc_ub_out *out = query_cmd_param->out;
	struct ubctl_port_link_list *current_node;
	struct ubctl_link_status *link_node;
	struct ubctl_port_link_stats *data;
	struct ucdev_list_node *dev_node;
	struct ubase_caps *ucaps = NULL;
	u32 i = 0;
	int ret;

	ucaps = ubase_get_dev_caps(ucdev->adev);
	if (!ucaps) {
		ubctl_err(ucdev, "ubctl get ucaps err, it is null.\n");
		return -EINVAL;
	}

	if (query_cmd_param->out_len != sizeof(struct ubctl_port_link_stats)) {
		ubctl_err(ucdev, "out length = %zubytes, it must be %zubytes.\n",
			  query_cmd_param->out_len, sizeof(struct ubctl_port_link_stats));
		return -EINVAL;
	}

	mutex_lock(&g_ubctl_port_link_mutex);
	dev_node = ubctl_find_ucdev_list_node(ucaps->die_id, ucaps->chip_id);
	if (dev_node == NULL) {
		mutex_unlock(&g_ubctl_port_link_mutex);
		ubctl_err(ucdev, "failed to find ucdev list node.\n");
		return -EINVAL;
	}

	ret = ubctl_check_port_id(ucdev, pkt_in, dev_node->port_bitmap);
	if (ret) {
		mutex_unlock(&g_ubctl_port_link_mutex);
		return ret;
	}

	data = (struct ubctl_port_link_stats *)(&out->data[0]);
	out->data_size = sizeof(struct ubctl_port_link_stats);

	list_for_each_entry(current_node, &dev_node->dev_list, port_link_list) {
		if (current_node->port != pkt_in->port_id)
			continue;
		data->link_info_num = current_node->size;
		data->link_down_num = current_node->link_down_num;
		data->link_up_num = current_node->link_up_num;
		list_for_each_entry(link_node, &current_node->link_info_list.list, list) {
			if (i < UBCTL_LINK_SIZE_MAX) {
				data->link_info[i].link_status = link_node->info.link_status;
				data->link_info[i].time = link_node->info.time;
			}
			i++;
		}
		mutex_unlock(&g_ubctl_port_link_mutex);
		return 0;
	}

	mutex_unlock(&g_ubctl_port_link_mutex);
	data->link_info_num = 0;

	return 0;
}

static int ubctl_check_result_data_invalid(struct ubctl_dev *ucdev,
					   struct ubase_ub_dl_pkt_stats_result *result_data)
{
#define UBCTL_IS_VALID 1

	u32 port_index = 0;
	int ret = 0;
	u32 i = 0;

	for (; i < UBCTL_MAX_PORT_NUM; i++) {
		if (result_data[i].valid != UBCTL_IS_VALID)
			continue;

		port_index = result_data[i].port_id;
		if (port_index >= UBCTL_MAX_PORT_NUM) {
			ubctl_warn(ucdev, "the port id is invalid and exceeds the maximum value %u.\n",
				   UBCTL_MAX_PORT_NUM - 1);
			continue;
		}
		if ((ucdev->rt_bandwidth_data[port_index].port_id == result_data[i].port_id) &&
		(result_data[i].rx_pkt_bytes < ucdev->rt_bandwidth_data[port_index].rx_bandwidth ||
		result_data[i].tx_pkt_bytes < ucdev->rt_bandwidth_data[port_index].tx_bandwidth)) {
			ubctl_warn(ucdev, "first rx data = %llubytes, second rx data = %llubytes, first tx data = %llubytes, second tx data = %llubytes, port_index = %u.\n",
				   ucdev->rt_bandwidth_data[port_index].rx_bandwidth,
				   result_data[i].rx_pkt_bytes,
				   ucdev->rt_bandwidth_data[port_index].tx_bandwidth,
				   result_data[i].tx_pkt_bytes, port_index);
			ret = -EBUSY;
		}
		ucdev->rt_bandwidth_data[port_index].port_id = result_data[i].port_id;
		ucdev->rt_bandwidth_data[port_index].is_valid = result_data[i].valid;
		ucdev->rt_bandwidth_data[port_index].rx_bandwidth = result_data[i].rx_pkt_bytes;
		ucdev->rt_bandwidth_data[port_index].tx_bandwidth = result_data[i].tx_pkt_bytes;
	}

	return ret;
}

static int ubctl_rt_bandwidth_check_param(struct ubctl_dev *ucdev,
					  struct ubctl_query_cmd_param *query_cmd_param)
{
	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_port)) {
		ubctl_err(ucdev, "user in data size = %ubytes, it must be %zubytes.\n",
			  query_cmd_param->in->data_size, sizeof(struct fwctl_pkt_in_port));
		return -EINVAL;
	}
	if (query_cmd_param->out_len !=
	    UBCTL_MAX_PORT_NUM * sizeof(struct ubctl_rt_bandwidth_data)) {
		ubctl_err(ucdev, "out length = %zubytes, it must be %zubytes.\n",
			  query_cmd_param->out_len,
			  UBCTL_MAX_PORT_NUM * sizeof(struct ubctl_rt_bandwidth_data));
		return -EINVAL;
	}

	return 0;
}

static int ubctl_query_rt_bandwidth(struct ubctl_dev *ucdev,
				    struct ubctl_query_cmd_param *query_cmd_param,
				    struct ubctl_func_dispatch *query_func)
{
	struct ubase_ub_dl_pkt_stats_result *result_data;
	struct ubctl_rt_bandwidth_data *usr_out_data;
	struct fwctl_pkt_in_port *pkt_in;
	u64 port_bitmap;
	int ret = 0;
	u32 i = 0;

	ret = ubctl_rt_bandwidth_check_param(ucdev, query_cmd_param);
	if (ret)
		return ret;

	pkt_in = (struct fwctl_pkt_in_port *)query_cmd_param->in->data;
	result_data = kvzalloc((UBCTL_MAX_PORT_NUM * sizeof(*result_data)), GFP_KERNEL);
	if (!result_data)
		return -ENOMEM;

	port_bitmap = (u64)pkt_in->port_id;
	ret = ubase_get_ub_dl_pkt_stats(ucdev->adev, port_bitmap, result_data, UBCTL_MAX_PORT_NUM);
	if (ret) {
		if (ret == -EBUSY) {
			query_cmd_param->out->retval = -EBUSY;
			ret = 0;
		} else {
			ubctl_err(ucdev,
				  "failed to query real time bandwidth by ubctl, ret = %d.\n", ret);
		}
		goto query_rt_bw_end;
	}

	mutex_lock(&g_ubctl_rt_bandwidth_mutex);
	ret = ubctl_check_result_data_invalid(ucdev, result_data);
	if (ret) {
		query_cmd_param->out->retval = -EBUSY;
		ret = 0;
		mutex_unlock(&g_ubctl_rt_bandwidth_mutex);
		goto query_rt_bw_end;
	}
	mutex_unlock(&g_ubctl_rt_bandwidth_mutex);

	usr_out_data = (struct ubctl_rt_bandwidth_data *)query_cmd_param->out->data;
	for (; i < UBCTL_MAX_PORT_NUM; i++) {
		usr_out_data[i].port_id = result_data[i].port_id;
		usr_out_data[i].is_valid = result_data[i].valid;
		usr_out_data[i].rx_bandwidth = result_data[i].rx_pkt_bytes;
		usr_out_data[i].tx_bandwidth = result_data[i].tx_pkt_bytes;
	}
	query_cmd_param->out->data_size = UBCTL_MAX_PORT_NUM * sizeof(*usr_out_data);

query_rt_bw_end:
	kvfree(result_data);
	return ret;
}

static int ubctl_check_dev_name(struct ubctl_dev *ucdev,
				struct ubctl_query_cmd_param *query_cmd_param)
{
	if (!query_cmd_param || !query_cmd_param->in)
		return -EINVAL;

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_dev_name)) {
		ubctl_err(ucdev, "dev name data size = %ubytes, it must be %zubytes.\n",
			  query_cmd_param->in->data_size, sizeof(struct fwctl_pkt_in_dev_name));
		return -EINVAL;
	}

	return 0;
}

static int ubctl_query_dscp(struct ubctl_dev *ucdev,
			    struct ubctl_query_cmd_param *query_cmd_param,
			    struct ubctl_func_dispatch *query_func)
{
	struct ubase_dbg_dscp_vl_map map = {};
	struct fwctl_pkt_in_dev_name *pkt_in;
	u32 *out_data_size;
	u32 out_size;
	void *buf;
	int ret;

	ret = ubctl_check_dev_name(ucdev, query_cmd_param);
	if (ret)
		return ret;

	pkt_in = (struct fwctl_pkt_in_dev_name *)query_cmd_param->in->data;
	pkt_in->dev_name[UBCTL_MAX_DEV_NAME - 1] = '\0';
	out_data_size = &query_cmd_param->out->data_size;
	out_size = query_cmd_param->out_len;
	if (out_size > sizeof(struct ubase_dbg_dscp_vl_map)) {
		ubctl_err(ucdev, "data size(%u) is too large, out data size(%zu).\n", out_size,
			  sizeof(struct ubase_dbg_dscp_vl_map));
		ret = -EINVAL;
		return ret;
	}

	buf = (void *)query_cmd_param->out->data;
	ret = ubase_dbg_get_dscp_vl_map_by_name(pkt_in->dev_name, &map);
	if (ret == -ENODEV)
		ubctl_err(ucdev, "no such device or not supported %s.\n", pkt_in->dev_name);

	if (ret) {
		ubctl_err(ucdev, "failed to get dscp vl map, ret = %d.\n", ret);
		return ret;
	}

	*out_data_size = out_size;
	memcpy(buf, &map, *out_data_size);
	return ret;
}

static int ubctl_query_sl_vl_map(struct ubctl_dev *ucdev,
				 struct ubctl_query_cmd_param *query_cmd_param,
				 struct ubctl_func_dispatch *query_func)
{
	struct fwctl_pkt_in_dev_name *pkt_in;
	struct ubase_dbg_sl_vl_map map = {};
	u32 *out_data_size;
	u32 out_size;
	void *buf;
	int ret;

	ret = ubctl_check_dev_name(ucdev, query_cmd_param);
	if (ret)
		return ret;

	pkt_in = (struct fwctl_pkt_in_dev_name *)query_cmd_param->in->data;
	pkt_in->dev_name[UBCTL_MAX_DEV_NAME - 1] = '\0';
	out_data_size = &query_cmd_param->out->data_size;
	out_size = query_cmd_param->out_len;
	if (out_size > sizeof(struct ubase_dbg_sl_vl_map)) {
		ubctl_err(ucdev, "data size(%u) is too large, out data size(%zu).\n", out_size,
			  sizeof(struct ubase_dbg_sl_vl_map));
		ret = -EINVAL;
		return ret;
	}

	buf = (void *)query_cmd_param->out->data;
	ret = ubase_dbg_get_sl_vl_map_by_name(pkt_in->dev_name, &map);
	if (ret == -ENODEV)
		ubctl_err(ucdev, "no such device or not supported %s.\n", pkt_in->dev_name);

	if (ret) {
		ubctl_err(ucdev, "failed to get sl vl map, ret = %d.\n", ret);
		return ret;
	}

	*out_data_size = out_size;
	memcpy(buf, &map, *out_data_size);
	return ret;
}

static int ubctl_query_caps_info(struct ubctl_dev *ucdev,
				 struct ubctl_query_cmd_param *query_cmd_param,
				 struct ubctl_func_dispatch *query_func)
{
	struct fwctl_pkt_in_dev_name *pkt_in;
	struct ubase_dbg_caps_info info = {};
	u32 *out_data_size;
	u32 out_size;
	void *buf;
	int ret;

	ret = ubctl_check_dev_name(ucdev, query_cmd_param);
	if (ret)
		return ret;

	pkt_in = (struct fwctl_pkt_in_dev_name *)query_cmd_param->in->data;
	pkt_in->dev_name[UBCTL_MAX_DEV_NAME - 1] = '\0';
	out_data_size = &query_cmd_param->out->data_size;
	out_size = query_cmd_param->out_len;
	if (out_size > sizeof(struct ubase_dbg_caps_info)) {
		ubctl_err(ucdev, "data size(%u) is too large, out data size(%zu).\n", out_size,
			  sizeof(struct ubase_dbg_caps_info));
		ret = -EINVAL;
		return ret;
	}

	buf = (void *)query_cmd_param->out->data;
	ret = ubase_dbg_get_caps_info_by_name(pkt_in->dev_name, &info);
	if (ret == -ENODEV)
		ubctl_err(ucdev, "no such device or not supported %s.\n", pkt_in->dev_name);

	if (ret) {
		ubctl_err(ucdev, "failed to get caps info, ret = %d.\n", ret);
		return ret;
	}

	*out_data_size = out_size;
	memcpy(buf, &info, *out_data_size);
	return ret;
}

static int ubctl_query_aeqc(struct ubctl_dev *ucdev,
			    struct ubctl_query_cmd_param *query_cmd_param,
			    struct ubctl_func_dispatch *query_func)
{
	struct fwctl_pkt_in_dev_name *pkt_in;
	u32 buf_size;
	void *buf;
	int ret;

	ret = ubctl_check_dev_name(ucdev, query_cmd_param);
	if (ret)
		return ret;

	pkt_in = (struct fwctl_pkt_in_dev_name *)query_cmd_param->in->data;
	pkt_in->dev_name[UBCTL_MAX_DEV_NAME - 1] = '\0';
	buf_size = query_cmd_param->out_len;
	buf = (void *)query_cmd_param->out->data;

	ret = ubase_dbg_get_aeq_ctx_hw_by_name(pkt_in->dev_name, buf, &buf_size);
	if (ret == -ENODEV)
		ubctl_err(ucdev, "no such device or not supported %s.\n", pkt_in->dev_name);

	if (ret) {
		ubctl_err(ucdev, "failed to get aeq ctx, ret = %d.\n", ret);
		return ret;
	}

	query_cmd_param->out->data_size = buf_size;
	return ret;
}

static int ubctl_query_ceqc(struct ubctl_dev *ucdev,
			    struct ubctl_query_cmd_param *query_cmd_param,
			    struct ubctl_func_dispatch *query_func)
{
	struct fwctl_pkt_in_dev_name *pkt_in;
	u32 buf_size;
	void *buf;
	int ret;

	ret = ubctl_check_dev_name(ucdev, query_cmd_param);
	if (ret)
		return ret;

	pkt_in = (struct fwctl_pkt_in_dev_name *)query_cmd_param->in->data;
	pkt_in->dev_name[UBCTL_MAX_DEV_NAME - 1] = '\0';
	buf_size = query_cmd_param->out_len;
	buf = (void *)query_cmd_param->out->data;

	ret = ubase_dbg_get_ceq_ctx_hw_by_name(pkt_in->dev_name, buf, &buf_size);
	if (ret == -ENODEV)
		ubctl_err(ucdev, "no such device or not supported %s.\n", pkt_in->dev_name);

	if (ret) {
		ubctl_err(ucdev, "failed to get ceq ctx, ret = %d.\n", ret);
		return ret;
	}

	query_cmd_param->out->data_size = buf_size;
	return ret;
}

static struct ubctl_func_dispatch g_ubctl_query_func[] = {
	{ UTOOL_CMD_QUERY_DL_LINK_TRACE, ubctl_query_dl_trace_data,
	  ubctl_trace_data_deal },

	{ UTOOL_CMD_QUERY_SCC_VERSION, ubctl_query_scc_data, ubctl_scc_version_deal },
	{ UTOOL_CMD_QUERY_SCC_LOG, ubctl_query_scc_data, ubctl_scc_log_deal },

	{ UTOOL_CMD_QUERY_DL_PERFORMANCE, ubctl_query_dl_perf_data, NULL },
	{ UTOOL_CMD_QUERY_DL_ALL_PERF, ubctl_query_dl_all_perf_data, NULL },
	{ UTOOL_CMD_QUERY_DL_PERF, ubctl_query_dl_perf_stats_data, NULL },
	{ UTOOL_CMD_QUERY_DL_PERF_START, ubctl_query_dl_start_perf_data, NULL },
	{ UTOOL_CMD_QUERY_DL_PERF_STOP, ubctl_query_dl_stop_perf_data, NULL },

	{ UTOOL_CMD_QUERY_MSGQ_QUE_STATS, ubctl_query_msgq_que_stats_data,
	  ubctl_msgq_que_data_deal },
	{ UTOOL_CMD_QUERY_MSGQ_ENTRY, ubctl_query_msgq_que_stats_data,
	  ubctl_msgq_entry_data_deal },

	{ UTOOL_CMD_QUERY_IO_DIE_PORT_INFO, ubctl_query_iodie_info_data,
	  ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_UMMU_ALL, ubctl_ummu_process_data, NULL },
	{ UTOOL_CMD_QUERY_UMMU_SYNC, ubctl_ummu_process_data, NULL },
	{ UTOOL_CMD_CONFIG_UMMU_SYNC, ubctl_ummu_process_data, NULL },

	{ UTOOL_CMD_QUERY_DL_RT_BANDWIDTH, ubctl_query_rt_bandwidth, NULL },
	{ UTOOL_CMD_QUERY_PORT_LINK_STATS, ubctl_query_port_link_status, NULL },

	{ UTOOL_CMD_QUERY_DSCP_INFO, ubctl_query_dscp, NULL },
	{ UTOOL_CMD_QUERY_SL_VL_MAP_INFO, ubctl_query_sl_vl_map, NULL },
	{ UTOOL_CMD_QUERY_CAPS_INFO, ubctl_query_caps_info, NULL },
	{ UTOOL_CMD_QUERY_AEQC_INFO, ubctl_query_aeqc, NULL },
	{ UTOOL_CMD_QUERY_CEQC_INFO, ubctl_query_ceqc, NULL },

	{ UTOOL_CMD_QUERY_MAX, NULL, NULL }
};

struct ubctl_func_dispatch *ubctl_get_query_func(struct ubctl_dev *ucdev, u32 rpc_cmd)
{
	u32 i;

	if (!ucdev)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(g_ubctl_query_func); i++) {
		if (g_ubctl_query_func[i].rpc_cmd == rpc_cmd)
			return &g_ubctl_query_func[i];
	}

	return NULL;
}

static void ubctl_get_port_type_from_port_id(struct ubctl_dev *ucdev, u32 port_id, u32 *port_type)
{
	struct ubctl_port_link_list *current_node;
	struct ucdev_list_node *dev_node;
	struct ubase_caps *ucaps;
	u32 env_type;

	*port_type = UBCTL_PORT_TYPE_UB;
	env_type = ubase_get_hw_ver(ucdev->adev);
	if (env_type != UBASE_HW_VER_A_0 && env_type != UBASE_HW_VER_A_1)
		return;

	ucaps = ubase_get_dev_caps(ucdev->adev);
	if (!ucaps)
		return;

	mutex_lock(&g_ubctl_port_link_mutex);
	dev_node = ubctl_find_ucdev_list_node(ucaps->die_id, ucaps->chip_id);
	if (dev_node == NULL) {
		mutex_unlock(&g_ubctl_port_link_mutex);
		ubctl_err(ucdev, "failed to find ucdev list node.\n");
		return;
	}

	list_for_each_entry(current_node, &dev_node->dev_list, port_link_list) {
		if (current_node->port == port_id) {
			*port_type = current_node->port_type;
			mutex_unlock(&g_ubctl_port_link_mutex);
			return;
		}
	}
	mutex_unlock(&g_ubctl_port_link_mutex);
}

static int ubctl_check_single_port_type(struct ubctl_dev *ucdev, u32 port_id, u32 expect_port_type)
{
	const char *expected_type;
	u32 port_type;

	ubctl_get_port_type_from_port_id(ucdev, port_id, &port_type);
	if (port_type != expect_port_type) {
		expected_type = (expect_port_type == UBCTL_PORT_TYPE_ETH) ? "UBOE" : "UB";
		ubctl_err(ucdev, "port type of port id(%u) is not %s, the cmd is not allowed.\n",
			  port_id, expected_type);
		return -EOPNOTSUPP;
	}

	return 0;
}

int ubctl_check_port_type(struct ubctl_dev *ucdev, struct ubctl_query_cmd_param *query_cmd_param,
			  u32 expect_port_type)
{
	struct fwctl_pkt_in_port *pkt_in;

	if (!ucdev || !(ucdev->adev))
		return -EINVAL;

	if (!query_cmd_param || !(query_cmd_param->in)) {
		ubctl_err(ucdev, "query cmd parameter or fwctl rpc ub in is null.\n");
		return -EINVAL;
	}

	pkt_in = (struct fwctl_pkt_in_port *)query_cmd_param->in->data;

	return ubctl_check_single_port_type(ucdev, pkt_in->port_id, expect_port_type);
}

int ubctl_check_port_type_from_bitmap(struct ubctl_dev *ucdev,
				      struct ubctl_query_cmd_param *query_cmd_param,
				      u32 expect_port_type)
{
#define UBCTL_PORT_ID_BITMAP_BITS 32U
	struct fwctl_pkt_in_port *pkt_in;
	u32 bitmap;
	int ret;
	u32 i;

	if (!ucdev || !(ucdev->adev))
		return -EINVAL;

	if (!query_cmd_param || !(query_cmd_param->in)) {
		ubctl_err(ucdev, "query cmd parameter or fwctl rpc ub in is null.\n");
		return -EINVAL;
	}

	pkt_in = (struct fwctl_pkt_in_port *)query_cmd_param->in->data;
	bitmap = pkt_in->port_id;

	for (i = 0; i < UBCTL_PORT_ID_BITMAP_BITS; i++) {
		if (!(bitmap & (1U << i)))
			continue;
		ret = ubctl_check_single_port_type(ucdev, i, expect_port_type);
		if (ret)
			return ret;
	}
	return 0;
}
