// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <linux/io.h>
#include <linux/sort.h>

#include "ub_cmdq.h"
#include "ub_cmd.h"

#define UBCTL_CQE_SIZE 16
#define UBCTL_SCC_SZ_1M 0x100000
#define UBCTL_LINK_SIZE_MAX 10
#define UBCTL_MAX_DIE_NUM 8
#define UBCTL_MAX_PORT_NUM 64U

static u32 g_ubctl_ummu_reg_addr[] = {
	// KCMD
	UBCTL_UMMU_SWIF_KCMDQ_DFX_KCMD_STATUS,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_KCMD_ERR_STATUS,
	// CMD_CTRL
	UBCTL_UMMU_SWIF_KCMDQ_DFX_SNP_ERR_CNT,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_0,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_1,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_2,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_3,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_4,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_5,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_6,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_7,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_8,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_9,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_10,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_11,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_12,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_13,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_14,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_ENTRY_STATUS_15,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_SNP_STATUS,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_CTRL_STATUS1,
	UBCTL_UMMU_SWIF_KCMDQ_DFX_CMD_CTRL_STATUS2,
	UBCTL_UMMU_SYNC_TIMEOUT_INFO,
	UBCTL_UMMU_DVM_RECEIVE_REQ_CNT,
	UBCTL_UMMU_DVM_SEND_REQ_CNT,
	UBCTL_UMMU_DVM_REQ_INFO0,
	UBCTL_UMMU_DVM_REQ_INFO1,
	// UCMD
	UBCTL_UMMU_SWIF_UMCMD_DFX0,
	UBCTL_UMMU_SWIF_UMCMD_DFX1,
	UBCTL_UMMU_SWIF_UMCMD_DFX2,
	UBCTL_UMMU_SWIF_UMCMD_DFX3,
	UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_0,
	UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_1,
	UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_2,
	UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_3,
	UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_4,
	UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_5,
	UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX0_6,
	UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX1,
	UBCTL_UMMU_SWIF_UMCMD_RR_WIN_DFX2,
	UBCTL_UMMU_SWIF_UMCMD_CACHE_DFX1,
	UBCTL_UMMU_SWIF_UMCMD_CACHE_DFX2,
	UBCTL_UMMU_SWIF_UMCMD_CACHE_DFX3,
	UBCTL_UMMU_SWIF_UMCMD_CACHE_DFX4,
	UBCTL_UMMU_SWIF_UMCMD_CACHE_DFX5,
	UBCTL_UMMU_SWIF_UMCMD_CACHE_DFX6,
	// EVENT
	UBCTL_UMMU_SWIF_EVENTQ_DFX_DROP_CNT,
	UBCTL_UMMU_GLB_INT_EN,
	UBCTL_UMMU_PMCG_INT_EN,
	UBCTL_UMMU_INT_MASK,
	UBCTL_UMMU_CTRL1,
	UBCTL_UMMU_SPEC_DEF_DFX,
	UBCTL_UMMU_TECT_BASE_CFG,
	UBCTL_UMMU_ERR_STATUS_0,
	UBCTL_UMMU_ROOT_GPF_FAR_L,
	UBCTL_UMMU_ROOT_GPF_FAR_H,
	UBCTL_UMMU_EVENT_QUE_PI,
	UBCTL_UMMU_EVENT_QUE_CI,
	// UBIF
	UBCTL_UMMU_UBIF_DFX0,
	UBCTL_UMMU_UBIF_DFX1,
	UBCTL_UMMU_UBIF_DSTEID_DFX,
	UBCTL_UMMU_UBIF_SYNC_DFX,
	UBCTL_UMMU_UBIF_KV_CACHE_NS_NSE_MISMATCH_DFX0,
	UBCTL_UMMU_UBIF_KV_CACHE_NS_NSE_MISMATCH_DFX1,
	UBCTL_UMMU_UBIF_KV_CACHE_NS_NSE_MISMATCH_DFX2,
	UBCTL_UMMU_UBIF_KV_CACHE_NS_NSE_MISMATCH_DFX3,
	UBCTL_UMMU_UBIF_KV_CACHE_NS_NSE_MISMATCH_DFX4,
	// TBU
	UBCTL_UMMU_TBU_TLB_LKUP_PROC,
	UBCTL_UMMU_TBU_TLB_STAT,
	UBCTL_UMMU_TBU_TLB_FAULT_CNT,
	UBCTL_UMMU_TBU_PLB_LKUP_PROC,
	UBCTL_UMMU_TBU_PLB_STAT,
	UBCTL_UMMU_TBU_PLB_FAULT_CNT,
	UBCTL_UMMU_TBU_INVLD_MG_INFO,
	UBCTL_UMMU_TBU_RAB_STAT,
	UBCTL_UMMU_TBU_CNT,
	UBCTL_UMMU_DFX_TBU_PERM_ERR_CNT,
	UBCTL_UMMU_TBU_DFX0,
	UBCTL_UMMU_TBU_DFX1,
	UBCTL_UMMU_TBU_RAB_ENTRY_INFO_0_7_15,
	// TCU
	UBCTL_UMMU_TCU_PTW_QUEUE_STAT_0_47,
	UBCTL_UMMU_TCU_PPTW_QUEUE_STAT_0_39,
	// CFG
	UBCTL_UMMU_DFX_ECC_MONITOR_0,
	UBCTL_UMMU_DFX_ECC_MONITOR_1,
	UBCTL_UMMU_CFG_DFX_CFGBUS_STATUS,
	// GPC
	UBCTL_UMMU_GPC_QUEUE_STAT_0_15,
	// SKY
	UBCTL_UMMU_SKY_QUEUE_STAT3_SP_0_63,
	// MCMD
	UBCTL_UMMU_MCMD_QUE_PI_0,
	UBCTL_UMMU_MCMD_QUE_PI_1,
	UBCTL_UMMU_MCMD_QUE_PI_2,
	UBCTL_UMMU_MCMD_QUE_PI_3,
	UBCTL_UMMU_MCMD_QUE_PI_4,
	UBCTL_UMMU_MCMD_QUE_PI_5,
	UBCTL_UMMU_MCMD_QUE_PI_6,
	UBCTL_UMMU_MCMD_QUE_PI_7,
	UBCTL_UMMU_MCMD_QUE_CI_0,
	UBCTL_UMMU_MCMD_QUE_CI_1,
	UBCTL_UMMU_MCMD_QUE_CI_2,
	UBCTL_UMMU_MCMD_QUE_CI_3,
	UBCTL_UMMU_MCMD_QUE_CI_4,
	UBCTL_UMMU_MCMD_QUE_CI_5,
	UBCTL_UMMU_MCMD_QUE_CI_6,
	UBCTL_UMMU_MCMD_QUE_CI_7,
	// UMMU_EN
	UBCTL_UMMU_CTRL0,
	// OTHER
	UBCTL_UMMU_SYNC_TIMEOUT_OPEN,
};

struct ubctl_ummu_relation {
	u32 reg_addr;
	u32 reg_config_addr;
	u32 reg_count;
};

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

struct ubctl_rt_bandwidth_data {
	u32 port_id;
	u32 is_valid;
	u64 tx_bandwidth;
	u64 rx_bandwidth;
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

static unsigned long g_ubctl_port_bitmap[UBCTL_MAX_DIE_NUM] = { 0 };
struct ubctl_port_link_list g_port_link_list[UBCTL_MAX_DIE_NUM];
static DEFINE_MUTEX(g_ubctl_port_link_mutex);

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
		ubctl_err(ucdev, "ubctl fill cmd failed.\n");
		return ret;
	}

	ret = ubctl_ubase_cmd_send(ucdev->adev, &cmd);
	if (ret) {
		ubctl_err(ucdev, "ubctl ubase cmd send failed, ret = %d.\n", ret);
		return -EINVAL;
	}

	ret = cmd_data->query_func->data_deal(ucdev, query_cmd_param, &cmd,
					      out_len, offset);
	if (ret)
		ubctl_err(ucdev, "ubctl data deal failed, ret = %d.\n", ret);

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
		ubctl_err(ucdev, "user data of trace is invalid.\n");
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
			ubctl_err(ucdev, "software data of trace is invalid.\n");
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
	struct ubase_perf_stats_result *result_data;
	u8 *perf_out_data;
	int ret = 0;
	u32 i = 0;

	if (!ucdev || !query_cmd_param)
		return -EINVAL;

	if (!query_cmd_param->in || !query_cmd_param->out) {
		ubctl_err(ucdev, "ubctl in or out is null.\n");
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
		ubctl_err(ucdev, "ubctl query perf failed, ret = %d.\n", ret);
	kvfree(result_data);
	return ret;
}

static int ubctl_query_dl_perf_data(struct ubctl_dev *ucdev,
				    struct ubctl_query_cmd_param *query_cmd_param,
				    struct ubctl_func_dispatch *query_func)
{
	if (query_cmd_param->in == NULL) {
		ubctl_err(ucdev, "The input data is empty.\n");
		return -EFAULT;
	}

	struct fwctl_pkt_in_port_time *pkt_in =
		(struct fwctl_pkt_in_port_time *)query_cmd_param->in->data;

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_port_time)) {
		ubctl_err(ucdev, "user data of trace is invalid.\n");
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
		ubctl_err(ucdev, "user data of trace is invalid.\n");
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
		ubctl_err(ucdev, "The input data is empty.\n");
		return -EFAULT;
	}

	struct fwctl_pkt_in_port *pkt_in = (struct fwctl_pkt_in_port *)query_cmd_param->in->data;

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_port)) {
		ubctl_err(ucdev, "user data of trace is invalid.\n");
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
		ubctl_err(ucdev, "The input data is empty.\n");
		return -EFAULT;
	}

	pkt_in = (struct fwctl_pkt_in_port_time *)query_cmd_param->in->data;

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_port_time)) {
		ubctl_err(ucdev, "user data of perf is invalid.\n");
		return -EINVAL;
	}

	ret = ubase_open_perf_stats(ucdev->adev, pkt_in->port_id, pkt_in->time);
	if (ret)
		ubctl_err(ucdev, "ubase open perf stats failed, ret = %d.\n", ret);

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
		ubctl_err(ucdev, "The input data is empty.\n");
		return -EFAULT;
	}

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_port)) {
		ubctl_err(ucdev, "user data of perf is invalid.\n");
		return -EINVAL;
	}

	pkt_in = (struct fwctl_pkt_in_port *)query_cmd_param->in->data;

	ret = ubase_close_perf_stats(ucdev->adev, pkt_in->port_id);
	if (ret)
		ubctl_err(ucdev, "ubase close perf stats failed, ret = %d.\n", ret);

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
		ubctl_err(ucdev, "scc index is invalid, index = %u.\n", index);
		return -EINVAL;
	}

	phy_addr = UBCTL_GET_PHY_ADDR(scc->phy_addr_high, scc->phy_addr_low);
	if (!phy_addr) {
		ubctl_err(ucdev, " scc phy addr is invalid.\n");
		return -EFAULT;
	}

	vir_addr = ioremap(phy_addr, scc->data_size);
	if (!vir_addr) {
		ubctl_err(ucdev, "addr ioremap failed.\n");
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
		ubctl_err(ucdev, "scc data size is not equal to 2M, data size = %u.\n",
			  data_size);
		return -EINVAL;
	}

	if (out_len != scc_len) {
		ubctl_err(ucdev, "scc out len is invalid, out len = %u.\n",
			  out_len);
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
		ubctl_err(ucdev, "user data of scc version is invalid.\n");
		return -EINVAL;
	}
	pkt_in = (struct fwctl_pkt_in_index *)query_cmd_param->in->data;
	scc = (struct ubctl_scc_data *)cmd->out_data;

	ret = ubctl_scc_data_len_check(ucdev, query_cmd_param->out_len,
				       scc->data_size, UBCTL_SCC_VERSION_SZ);
	if (ret) {
		ubctl_err(ucdev, "scc version data len check failed, ret = %d.\n", ret);
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
		ubctl_err(ucdev, "user data of scc log is invalid.\n");
		return -EINVAL;
	}

	ret = ubctl_scc_data_len_check(ucdev, query_cmd_param->out_len,
				       scc->data_size, UBCTL_SCC_SZ_1M);
	if (ret) {
		ubctl_err(ucdev, "scc log data len check failed, ret = %d.\n", ret);
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
				  out_temp->data_size, out_mem_size,
				  out_data_offset * sizeof(u32));
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
		ubctl_err(ucdev, "index is illegal, index = %u.\n", entry_index);
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
		ubctl_err(ucdev, "sqe msgq not initialized.\n");
		return -EINVAL;
	}

	entry_phy_addr->sq_entry_phy_addr = base_addr +
					    entry_index * UBCTL_SQE_SIZE;

	base_addr = UBCTL_GET_PHY_ADDR(entry_info->cq_base_addr_high,
				       entry_info->cq_base_addr_low);
	if (!base_addr) {
		ubctl_err(ucdev, "cqe msgq not initialized.\n");
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
		ubctl_err(ucdev, "move sqe data failed.\n");

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
		ubctl_err(ucdev, "move cqe data failed.\n");

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
		ubctl_err(ucdev, "user data of msgq is invalid.\n");
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

static int compare_resources(const void *a, const void *b)
{
	const struct resource *ra = *(const struct resource **)a;
	const struct resource *rb = *(const struct resource **)b;

	if (ra->start < rb->start)
		return -1;
	if (ra->start > rb->start)
		return 1;
	return 0;
}

static struct resource *ubctl_find_and_sort_resources(struct ubctl_dev *ucdev,
						      struct resource *root,
						      const char *name_substr,
						      u32 ummu_id)
{
#define UBCL_MAX_UMMU_NUM 32U

	struct resource *entry_arr[UBCL_MAX_UMMU_NUM] = {};
	struct resource *p;
	u32 count = 0;

	/*
	 * To traverse the UMMU memory subtree, only need to traverse the child
	 * subtree of the root node.
	 */
	for (p = root->child; p; p = p->sibling) {
		if (!p->name || !strstr(p->name, name_substr))
			continue;
		if (count >= UBCL_MAX_UMMU_NUM) {
			ubctl_err(ucdev, "ummu resources is more than max num = %u.\n",
				  UBCL_MAX_UMMU_NUM);
			return NULL;
		}
		entry_arr[count] = p;
		count++;
	}

	if (ummu_id >= count) {
		ubctl_err(ucdev, "ummuid = %u out of range, current count = %u\n",
			  ummu_id, count);
		return NULL;
	}

	sort(entry_arr, count, sizeof(struct resource *), compare_resources, NULL);

	return entry_arr[ummu_id];
}

static inline u32 ubctl_ummu_get_register_offset(u32 index)
{
	return g_ubctl_ummu_reg_addr[index] - UBCTL_UMMU_REGISTER_BASE;
}

static inline u32 ubctl_ummu_get_reg_count(void)
{
#define UBCTL_UMMU_REPEAT_REG_TYPE_COUNT 5U

	return ARRAY_SIZE(g_ubctl_ummu_reg_addr) + UBCTL_UMMU_GPC_QUEUE_COUNT +
	       UBCTL_UMMU_SKY_QUEUE_COUNT + UBCTL_UMMU_TCU_PTW_QUEUE_COUNT +
	       UBCTL_UMMU_TCU_PPTW_QUEUE_COUNT + UBCTL_UMMU_ENTRY_NUM *
	       UBCTL_UMMU_BANK_NUM - UBCTL_UMMU_REPEAT_REG_TYPE_COUNT;
}

struct ubctl_reg_pro_cmd {
	struct ubctl_dev *ucdev;
	u32 reg_index;
	void __iomem *map_addr;
	u32 *ummu_data;
	u32 map_length;
	u32 *index_offset;
};

static int ubctl_ummu_normal_read(struct ubctl_reg_pro_cmd *cmd)
{
	u32 ummu_reg_cnt = ubctl_ummu_get_reg_count();
	u32 reg_addr_offset;

	reg_addr_offset = ubctl_ummu_get_register_offset(cmd->reg_index);
	if ((reg_addr_offset >= cmd->map_length) || (*cmd->index_offset >= ummu_reg_cnt)) {
		ubctl_err(cmd->ucdev, "ummu reg offset is bigger than map length, index=%u, reg offset=%u, map length=%u.\n",
			  *cmd->index_offset, reg_addr_offset, cmd->map_length);
		return -EFAULT;
	}
	cmd->ummu_data[*cmd->index_offset] = readl(cmd->map_addr + reg_addr_offset);
	(*cmd->index_offset)++;

	return 0;
}

static int ubctl_ummu_process_repeat_reg(struct ubctl_reg_pro_cmd *cmd)
{
	static struct ubctl_ummu_relation ummu_relation[] = {
		{ UBCTL_UMMU_GPC_QUEUE_STAT_0_15, UBCTL_UMMU_GPC_QUEUE_POINTER,
		  UBCTL_UMMU_GPC_QUEUE_COUNT },
		{ UBCTL_UMMU_SKY_QUEUE_STAT3_SP_0_63, UBCTL_UMMU_SKY_QUEUE_POINTER_SP,
		  UBCTL_UMMU_SKY_QUEUE_COUNT },
		{ UBCTL_UMMU_TCU_PTW_QUEUE_STAT_0_47, UBCTL_UMMU_TCU_PTW_QUEUE_POINTER,
		  UBCTL_UMMU_TCU_PTW_QUEUE_COUNT },
		{ UBCTL_UMMU_TCU_PPTW_QUEUE_STAT_0_39, UBCTL_UMMU_TCU_PPTW_QUEUE_POINTER,
		  UBCTL_UMMU_TCU_PPTW_QUEUE_COUNT }
	};

	u32 read_reg_offset, set_reg_offset, write_count, i, j;
	u32 ummu_reg_cnt = ubctl_ummu_get_reg_count();

	for (i = 0; i < ARRAY_SIZE(ummu_relation); i++) {
		if (ummu_relation[i].reg_addr != g_ubctl_ummu_reg_addr[cmd->reg_index])
			continue;
		write_count = ummu_relation[i].reg_count;
		set_reg_offset = ummu_relation[i].reg_config_addr -
				 UBCTL_UMMU_REGISTER_BASE;
		read_reg_offset = ummu_relation[i].reg_addr -
				  UBCTL_UMMU_REGISTER_BASE;
		if ((set_reg_offset >= cmd->map_length) ||
		    (read_reg_offset >= cmd->map_length)) {
			ubctl_err(cmd->ucdev, "ummu set or read reg offset is bigger than map length, set offset=%u, read offset=%u, map length=%u.\n",
				  set_reg_offset, read_reg_offset, cmd->map_length);
			return -EFAULT;
		}

		for (j = 0; j < write_count; j++, (*cmd->index_offset)++) {
			writel(j, cmd->map_addr + set_reg_offset);
			if (*cmd->index_offset >= ummu_reg_cnt) {
				ubctl_err(cmd->ucdev, "index offset is bigger than ummu reg count, index offset=%u, ummu reg count=%u.\n",
					  *cmd->index_offset, ummu_reg_cnt);
				return -EFAULT;
			}
			cmd->ummu_data[*cmd->index_offset] = readl(cmd->map_addr +
								   read_reg_offset);
		}
		return 0;
	}

	return ubctl_ummu_normal_read(cmd);
}

static int ubctl_ummu_process_reg(struct ubctl_reg_pro_cmd *cmd)
{
#define UBCTL_TBU_MASK 0xFFFFFC00U
#define UBCTL_BANK_OFFSET 6

	u32 read_reg_offset, set_reg_offset, origin_value, value, i, j;
	u32 ummu_reg_cnt = ubctl_ummu_get_reg_count();

	if (g_ubctl_ummu_reg_addr[cmd->reg_index] != UBCTL_UMMU_TBU_RAB_ENTRY_INFO_0_7_15)
		return ubctl_ummu_process_repeat_reg(cmd);

	set_reg_offset = UBCTL_UMMU_TBU_RAB_FUNC_EN - UBCTL_UMMU_REGISTER_BASE;
	read_reg_offset = UBCTL_UMMU_TBU_RAB_ENTRY_INFO_0_7_15 -
			  UBCTL_UMMU_REGISTER_BASE;
	if ((set_reg_offset >= cmd->map_length) ||
	    (read_reg_offset >= cmd->map_length)) {
		ubctl_err(cmd->ucdev, "ummu set or read reg offset is bigger than map length, set offset=%u, read offset=%u, map length=%u.\n",
			  set_reg_offset, read_reg_offset, cmd->map_length);
		return -EFAULT;
	}

	origin_value = readl(cmd->map_addr + set_reg_offset);
	origin_value &= UBCTL_TBU_MASK;
	for (i = 0; i < UBCTL_UMMU_BANK_NUM; i++) {
		for (j = 0; j < UBCTL_UMMU_ENTRY_NUM; j++, (*cmd->index_offset)++) {
			value = (i << UBCTL_BANK_OFFSET) | j | origin_value;
			writel(value, cmd->map_addr + set_reg_offset);
			if (*cmd->index_offset >= ummu_reg_cnt) {
				ubctl_err(cmd->ucdev, "index offset is bigger than ummu reg count, index offset=%u, ummu reg count=%u.\n",
					  *cmd->index_offset, ummu_reg_cnt);
				return -EFAULT;
			}
			cmd->ummu_data[*cmd->index_offset] = readl(cmd->map_addr +
								   read_reg_offset);
		}
	}
	return 0;
}

static int ubctl_ummu_copy_data(struct ubctl_dev *ucdev,
				struct ubctl_query_cmd_param *query_cmd_param,
				void __iomem *map_addr, u32 map_length)
{
	u32 ummu_array_cnt = ARRAY_SIZE(g_ubctl_ummu_reg_addr);
	u32 ummu_reg_cnt = ubctl_ummu_get_reg_count();
	u32 *ummu_data = query_cmd_param->out->data;
	u32 index_offset = 0;
	int ret;
	u32 i;

	struct ubctl_reg_pro_cmd reg_pro_cmd = {
		.ucdev = ucdev,
		.reg_index = 0,
		.map_addr = map_addr,
		.ummu_data = ummu_data,
		.map_length = map_length,
		.index_offset = &index_offset,
	};

	if (ummu_reg_cnt * sizeof(u32) > query_cmd_param->out_len) {
		ubctl_err(ucdev, "ummu reg size is big than out len, reg sie=%lu, out len=%lu.\n",
			  ummu_reg_cnt * sizeof(u32), query_cmd_param->out_len);
		return -EINVAL;
	}

	for (i = 0; i < ummu_array_cnt; i++) {
		reg_pro_cmd.reg_index = i;
		ret = ubctl_ummu_process_reg(&reg_pro_cmd);
		if (ret) {
			ubctl_err(ucdev, "ummu process reg failed, ret=%d.\n", ret);
			return ret;
		}
	}
	query_cmd_param->out->data_size = ummu_reg_cnt * sizeof(u32);

	return 0;
}

static int ubctl_ummu_proc_all_data(struct ubctl_dev *ucdev, struct resource *res,
				    struct ubctl_query_cmd_param *query_cmd_param)
{
	u32 map_length = UBCTL_UMMU_REGISTER_MAX_ADDR - UBCTL_UMMU_REGISTER_BASE;
	void __iomem *vaddr;
	int ret;

	vaddr = ioremap(res->start + UBCTL_UMMU_REGISTER_BASE, map_length);
	if (!vaddr) {
		ubctl_err(ucdev, "ioremap ummu reg base failed, map length = %u.\n",
			  map_length);
		return -ENOMEM;
	}
	ret = ubctl_ummu_copy_data(ucdev, query_cmd_param, vaddr, map_length);
	iounmap(vaddr);

	return ret;
}

static int ubctl_ummu_proc_sync_data(struct resource *res,
				     struct ubctl_query_cmd_param *query_cmd_param,
				     struct fwctl_pkt_in_ummuid_value *ummu_data,
				     bool is_query)
{
	u32 *out_data = query_cmd_param->out->data;
	u32 map_length = sizeof(u32);
	void __iomem *vaddr;

	if (sizeof(u32) > query_cmd_param->out_len)
		return -EINVAL;

	vaddr = ioremap(res->start + UBCTL_UMMU_SYNC_TIMEOUT_OPEN, map_length);
	if (!vaddr)
		return -ENOMEM;

	if (is_query) {
		*out_data = readl(vaddr);
	} else {
		*out_data = ummu_data->value;
		writel(*out_data, vaddr);
	}

	query_cmd_param->out->data_size = sizeof(u32);
	iounmap(vaddr);

	return 0;
}

static int ubctl_ummu_process_data(struct ubctl_dev *ucdev,
				   struct ubctl_query_cmd_param *query_cmd_param,
				   struct ubctl_func_dispatch *query_func)
{
#define UMMU_NAME_STR "ummu."

	struct fwctl_pkt_in_ummuid_value *ummu_data;
	struct resource *root = &iomem_resource;
	struct resource *res;

	if (query_cmd_param->in->data_size != sizeof(*ummu_data)) {
		ubctl_err(ucdev, "invalid ummuid value size = %u.\n",
			  query_cmd_param->in->data_size);
		return -EINVAL;
	}

	ummu_data = (struct fwctl_pkt_in_ummuid_value *)(query_cmd_param->in->data);
	res = ubctl_find_and_sort_resources(ucdev, root, UMMU_NAME_STR,
					    ummu_data->ummu_id);
	if (!res)
		return -EINVAL;

	if (query_func->rpc_cmd == UTOOL_CMD_QUERY_UMMU_ALL)
		return ubctl_ummu_proc_all_data(ucdev, res, query_cmd_param);
	if (query_func->rpc_cmd == UTOOL_CMD_QUERY_UMMU_SYNC)
		return ubctl_ummu_proc_sync_data(res, query_cmd_param, ummu_data, true);
	if (query_func->rpc_cmd == UTOOL_CMD_CONFIG_UMMU_SYNC)
		return ubctl_ummu_proc_sync_data(res, query_cmd_param, ummu_data, false);

	return -EINVAL;
}

static struct ubctl_port_link_list *ubctl_add_port_node(u32 die_id, u32 port)
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
	list_add_tail(&new_node->port_link_list, &g_port_link_list[die_id].port_link_list);
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
					struct ubctl_dev *ucdev, u32 die_id)
{
	struct ubctl_port_bitmap_data in_data, out_data;
	struct ubctl_cmd cmd = {};
	int ret = 0;

	cmd.op_code = UBCTL_QUERY_PORT_NUM_DFX;
	ret = ubctl_fill_cmd(&cmd, (void *)&in_data, (void *)&out_data, sizeof(out_data), true);
	if (ret) {
		ubctl_err(ucdev, "ubctl fill cmd failed.\n");
		return ret;
	}

	ret = ubctl_ubase_cmd_send(adev, &cmd);
	if (ret) {
		ubctl_err(ucdev, "ubctl ubase cmd send failed, retval = %d.\n", ret);
		return -EINVAL;
	}

	g_ubctl_port_bitmap[die_id] = (u64)out_data.port_bitmap;

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
	ret = ubctl_fill_cmd(&cmd, (void *)&pkt_in_data, (void *)&out_data, sizeof(out_data), true);
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
					struct ubctl_dev *ucdev, u32 port_id)
{
	struct ubctl_port_link_stats_data in_data, out_data;
	struct ubctl_cmd cmd = {};
	int ret = 0;

	cmd.op_code = UBCTL_QUERY_DL_LINK_STATUS_DFX;
	in_data.port_id = port_id;
	ret = ubctl_fill_cmd(&cmd, (void *)&in_data, (void *)&out_data, sizeof(out_data), true);
	if (ret) {
		ubctl_err(ucdev, "ubctl fill cmd failed.\n");
		return false;
	}

	ret = ubctl_ubase_cmd_send(adev, &cmd);
	if (ret) {
		ubctl_err(ucdev, "ubctl ubase cmd send failed, retval = %d.\n", ret);
		return false;
	}
	return ubctl_get_port_link_status(adev, ucdev, port_id, out_data.port_type);
}

static int ubctl_construct_first_link_data(struct auxiliary_device *adev,
					   struct ubctl_dev *ucdev, u32 die_id)
{
	struct ubctl_port_link_list *new_port_node = NULL;
	struct ubctl_port_link_info link_info;
	u32 port_id;
	int ret = 0;

	ret = ubctl_query_port_bitmap_data(adev, ucdev, die_id);
	if (ret)
		return ret;

	for (port_id = 0; port_id < UBCTL_MAX_PORT_NUM; port_id++) {
		if (!test_bit(port_id, &g_ubctl_port_bitmap[die_id]))
			continue;
		if (!ubctl_check_port_link_stats(adev, ucdev, port_id))
			continue;

		new_port_node = ubctl_add_port_node(die_id, port_id);
		if (!new_port_node)
			return -ENOMEM;

		link_info.time = ktime_get_real_seconds();
		link_info.link_status = 0;
		ret = ubctl_port_add_link_node(new_port_node, link_info, new_port_node->size);
		if (ret)
			return ret;

		new_port_node->size++;
	}

	return ret;
}

static bool ubctl_is_list_head_initialized(struct list_head *head)
{
	return head->next != NULL && head->prev != NULL;
}

static struct ubase_crq_event_nb ubctl_crq_events = {
	.opcode = UBCTL_QUERY_PORT_LINK_STATS_DFX,
	.crq_handler = ubctl_handle_link_status_event,
};

int ubctl_port_link_status_init(struct auxiliary_device *adev, struct ubctl_dev *ucdev)
{
	struct ubase_caps *ucaps;
	int ret = 0;

	ucaps = ubase_get_dev_caps(adev);
	if (ucaps == NULL || ucaps->die_id >= UBCTL_MAX_DIE_NUM)
		return -ENODEV;

	INIT_LIST_HEAD(&g_port_link_list[ucaps->die_id].port_link_list);
	ret = ubctl_construct_first_link_data(adev, ucdev, ucaps->die_id);
	if (ret) {
		ubctl_warn(ucdev, "ubctl construct first link data error, ret = %d.\n", ret);
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
	struct ubase_caps *ucaps;

	ucaps = ubase_get_dev_caps(adev);
	if (ucaps == NULL || ucaps->die_id >= UBCTL_MAX_DIE_NUM)
		return;

	ubase_unregister_crq_event(adev, ubctl_crq_events.opcode);

	if (!ubctl_is_list_head_initialized(&g_port_link_list[ucaps->die_id].port_link_list))
		return;
	mutex_lock(&g_ubctl_port_link_mutex);
	list_for_each_entry_safe(current_node, next,
				 &g_port_link_list[ucaps->die_id].port_link_list, port_link_list) {
		list_for_each_entry_safe(del_node, del_next,
					 &current_node->link_info_list.list, list) {
			list_del(&del_node->list);
			kvfree(del_node);
		}
		list_del(&current_node->port_link_list);
		kvfree(current_node);
	}
	mutex_unlock(&g_ubctl_port_link_mutex);
}

int ubctl_handle_link_status_event(void *dev, void *data, u32 len)
{
	struct ubctl_port_link_list *new_port_node = NULL;
	struct ubctl_port_link_list *current_node;
	struct ubctl_port_link_info link_info;
	struct ubase_caps *ucaps;
	int ret = 0;
	u32 port;

	if (!dev || !data || len < sizeof(struct ubctl_port_link_out_info))
		return -EINVAL;

	ucaps = ubase_get_dev_caps((struct auxiliary_device *)dev);
	if (ucaps == NULL || ucaps->die_id >= UBCTL_MAX_DIE_NUM)
		return -EINVAL;

	if (!ubctl_is_list_head_initialized(&g_port_link_list[ucaps->die_id].port_link_list))
		return -EINVAL;

	link_info.time = ktime_get_real_seconds();
	link_info.link_status = ((struct ubctl_port_link_out_info *)data)->link_status;
	port = ((struct ubctl_port_link_out_info *)data)->port;

	mutex_lock(&g_ubctl_port_link_mutex);
	list_for_each_entry(current_node, &g_port_link_list[ucaps->die_id].port_link_list,
			    port_link_list) {
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

	new_port_node = ubctl_add_port_node(ucaps->die_id, port);
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
			       u32 die_id)
{
	int ret = 0;

	if (die_id >= UBCTL_MAX_DIE_NUM) {
		ubctl_err(ucdev, "ubctl check die id filed, die id = %u.\n", die_id);
		return -EINVAL;
	}

	if (pkt_in->port_id >= UBCTL_MAX_PORT_NUM ||
	    !test_bit(pkt_in->port_id, &g_ubctl_port_bitmap[die_id])) {
		ubctl_err(ucdev, "ubctl port id does not meet expectations, port id = %u.\n",
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
	struct ubase_caps *ucaps = NULL;
	u32 i = 0;
	int ret;

	ucaps = ubase_get_dev_caps(ucdev->adev);
	if (!ucaps) {
		ubctl_err(ucdev, "ubctl get ucaps err, ucaps is null.\n");
		return -EINVAL;
	}

	ret = ubctl_check_port_id(ucdev, pkt_in, ucaps->die_id);
	if (ret)
		return ret;

	if (!ubctl_is_list_head_initialized(&g_port_link_list[ucaps->die_id].port_link_list))
		return -EINVAL;

	if (query_cmd_param->out_len != sizeof(struct ubctl_port_link_stats)) {
		ubctl_err(ucdev, "out len is error = %zu.\n", query_cmd_param->out_len);
		return -EINVAL;
	}

	data = (struct ubctl_port_link_stats *)(&out->data[0]);
	out->data_size = sizeof(struct ubctl_port_link_stats);

	mutex_lock(&g_ubctl_port_link_mutex);
	list_for_each_entry(current_node, &g_port_link_list[ucaps->die_id].port_link_list,
			    port_link_list) {
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

static int ubctl_query_rt_bandwidth(struct ubctl_dev *ucdev,
				    struct ubctl_query_cmd_param *query_cmd_param,
				    struct ubctl_func_dispatch *query_func)
{
#define UTOOL_MAX_PORT_NUM 64U

	struct ubase_ub_dl_pkt_stats_result *result_data;
	struct ubctl_rt_bandwidth_data *usr_out_data;
	struct fwctl_pkt_in_port *pkt_in;
	u64 port_bitmap;
	int ret = 0;
	u32 i = 0;

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_port)) {
		ubctl_err(ucdev, "user in data of trace is invalid.\n");
		return -EINVAL;
	}
	if (query_cmd_param->out_len != UTOOL_MAX_PORT_NUM * sizeof(*usr_out_data)) {
		ubctl_err(ucdev, "user out data of trace is invalid, out len = %lu.\n",
			  query_cmd_param->out_len);
		return -EINVAL;
	}

	pkt_in = (struct fwctl_pkt_in_port *)query_cmd_param->in->data;
	result_data = kvzalloc((UTOOL_MAX_PORT_NUM * sizeof(*result_data)), GFP_KERNEL);
	if (!result_data) {
		ubctl_err(ucdev, "result data create memory failed.\n");
		return -ENOMEM;
	}

	port_bitmap = (u64)pkt_in->port_id;
	ret = ubase_get_ub_dl_pkt_stats(ucdev->adev, port_bitmap, result_data, UTOOL_MAX_PORT_NUM);
	if (ret) {
		ubctl_err(ucdev, "ubctl query real time bandwidth failed, ret = %d.\n", ret);
		goto query_rt_bw_end;
	}

	usr_out_data = (struct ubctl_rt_bandwidth_data *)query_cmd_param->out->data;
	for (; i < UTOOL_MAX_PORT_NUM; i++) {
		usr_out_data[i].port_id = result_data[i].port_id;
		usr_out_data[i].is_valid = result_data[i].valid;
		usr_out_data[i].rx_bandwidth = result_data[i].rx_pkt_bytes;
		usr_out_data[i].tx_bandwidth = result_data[i].tx_pkt_bytes;
	}
	query_cmd_param->out->data_size = UTOOL_MAX_PORT_NUM * sizeof(*usr_out_data);

query_rt_bw_end:
	kvfree(result_data);
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
