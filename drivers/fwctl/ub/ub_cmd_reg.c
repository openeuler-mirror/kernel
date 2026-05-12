// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include "ub_cmdq.h"
#include "ub_cmd_reg.h"

static int ubctl_query_nl_data(struct ubctl_dev *ucdev,
			       struct ubctl_query_cmd_param *query_cmd_param,
			       struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_NL_PKT_STATS_DFX, UBCTL_NL_PKT_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_NL_SSU_STATS_DFX, UBCTL_NL_SSU_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_NL_ABN_DFX, UBCTL_NL_ABN_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_nl_pkt_stats_data(struct ubctl_dev *ucdev,
					 struct ubctl_query_cmd_param *query_cmd_param,
					 struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_NL_PKT_STATS_DFX, UBCTL_NL_PKT_STATS_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_nl_ssu_stats_data(struct ubctl_dev *ucdev,
					 struct ubctl_query_cmd_param *query_cmd_param,
					 struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_NL_SSU_STATS_DFX, UBCTL_NL_SSU_STATS_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_nl_abn_data(struct ubctl_dev *ucdev,
				   struct ubctl_query_cmd_param *query_cmd_param,
				   struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_NL_ABN_DFX, UBCTL_NL_ABN_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_dl_data(struct ubctl_dev *ucdev,
			       struct ubctl_query_cmd_param *query_cmd_param,
			       struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_DL_PKT_STATS_DFX, UBCTL_DL_PKT_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_DL_REPL_DFX, UBCTL_DL_REPL_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_DL_LINK_STATUS_DFX, UBCTL_DL_LINK_STATUS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_DL_LANE_DFX, UBCTL_DL_LANE_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_DL_BIT_ERR_DFX, UBCTL_DL_BIT_ERR_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_dl_pkt_stats_data(struct ubctl_dev *ucdev,
					 struct ubctl_query_cmd_param *query_cmd_param,
					 struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_DL_PKT_STATS_DFX, UBCTL_DL_PKT_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_DL_REPL_DFX, UBCTL_DL_REPL_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_dl_link_status_data(struct ubctl_dev *ucdev,
					   struct ubctl_query_cmd_param *query_cmd_param,
					   struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_DL_LINK_STATUS_DFX, UBCTL_DL_LINK_STATUS_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_dl_lane_data(struct ubctl_dev *ucdev,
				    struct ubctl_query_cmd_param *query_cmd_param,
				    struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_DL_LANE_DFX, UBCTL_DL_LANE_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_dl_bit_err_data(struct ubctl_dev *ucdev,
				       struct ubctl_query_cmd_param *query_cmd_param,
				       struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_DL_BIT_ERR_DFX, UBCTL_DL_BIT_ERR_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_dl_bist_data(struct ubctl_dev *ucdev,
				    struct ubctl_query_cmd_param *query_cmd_param,
				    struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_CONF_DL_BIST_DFX, UBCTL_DL_BIST_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_conf_dl_bist_data(struct ubctl_dev *ucdev,
				   struct ubctl_query_cmd_param *query_cmd_param,
				   struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_CONF_DL_BIST_DFX, UBCTL_DL_BIST_LEN, UBCTL_WRITE, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_dl_bist_err_data(struct ubctl_dev *ucdev,
					struct ubctl_query_cmd_param *query_cmd_param,
					struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_DL_BIST_ERR_DFX, UBCTL_DL_BIST_ERR_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_dp_deal(struct ubctl_dev *ucdev,
			       struct ubctl_query_cmd_param *query_cmd_param,
			       struct ubctl_func_dispatch *query_func,
			       struct ubctl_query_dp *query_dp, u32 query_dp_num)
{
#define UBCTL_TP_RX_BANK_NUM 3U

	u32 *rx_bank_id __free(kvfree) = kvzalloc(sizeof(u32) * UBCTL_TP_RX_BANK_NUM, GFP_KERNEL);
	u32 bank_idx = 0;
	u32 bank_id = 0;
	int ret = 0;
	u32 i;

	if (!rx_bank_id)
		return -ENOMEM;

	for (i = 0; i < query_dp_num; i++) {
		if (query_dp[i].op_code != UBCTL_QUERY_TP_RX_BANK_DFX)
			continue;
		if (bank_idx >= UBCTL_TP_RX_BANK_NUM) {
			ubctl_err(ucdev, "bank_idx is out of bounds: %u.\n", bank_idx);
			return -EINVAL;
		}

		rx_bank_id[bank_idx] = bank_id++;
		query_dp[i].data = (void *)&rx_bank_id[bank_idx++];
		query_dp[i].data_len = (u32)sizeof(u32);
	}

	ret = ubctl_query_data(ucdev, query_cmd_param, query_func,
			       query_dp, query_dp_num);
	if (ret)
		ubctl_err(ucdev, "ubctl query data failed, ret = %d.\n", ret);

	return ret;
}

static int ubctl_query_tp_data(struct ubctl_dev *ucdev,
			       struct ubctl_query_cmd_param *query_cmd_param,
			       struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_TP_TX_DFX, UBCTL_TP_TX_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_DFX, UBCTL_TP_RX_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RQM_DFX, UBCTL_TP_RQM_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_STATE_DFX, UBCTL_TP_STATE_DFX_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_EX_DFX, UBCTL_TP_RX_STATS_EX_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_TX_ROUTE_DFX, UBCTL_TP_TX_ROUTE_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_BANK_DFX, UBCTL_TP_RX_BANK_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_BANK_DFX, UBCTL_TP_RX_BANK_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_BANK_DFX, UBCTL_TP_RX_BANK_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_TX_DFX, UBCTL_TP_TX_ABN_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_DFX, UBCTL_TP_RX_ABN_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_ABN_STATS_DFX, UBCTL_TP_REG_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_dp_deal(ucdev, query_cmd_param, query_func,
				   query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_tp_tx_route_data(struct ubctl_dev *ucdev,
					struct ubctl_query_cmd_param *query_cmd_param,
					struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_TP_TX_ROUTE_DFX, UBCTL_TP_TX_ROUTE_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func, query_dp,
				ARRAY_SIZE(query_dp));
}

static int ubctl_query_tp_abn_stats_data(struct ubctl_dev *ucdev,
					 struct ubctl_query_cmd_param *query_cmd_param,
					 struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_TP_TX_DFX, UBCTL_TP_TX_ABN_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_DFX, UBCTL_TP_RX_ABN_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_ABN_STATS_DFX, UBCTL_TP_REG_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func, query_dp,
				ARRAY_SIZE(query_dp));
}

static int ubctl_query_tp_pkt_stats_data(struct ubctl_dev *ucdev,
					 struct ubctl_query_cmd_param *query_cmd_param,
					 struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_TP_TX_DFX, UBCTL_TP_TX_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_DFX, UBCTL_TP_RX_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RQM_DFX, UBCTL_TP_RQM_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_STATE_DFX, UBCTL_TP_STATE_DFX_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_EX_DFX, UBCTL_TP_RX_STATS_EX_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_tp_rx_bank_data(struct ubctl_dev *ucdev,
				       struct ubctl_query_cmd_param *query_cmd_param,
				       struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_TP_RX_BANK_DFX, UBCTL_TP_RX_BANK_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_BANK_DFX, UBCTL_TP_RX_BANK_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_BANK_DFX, UBCTL_TP_RX_BANK_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_dp_deal(ucdev, query_cmd_param, query_func,
				   query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_ta_data(struct ubctl_dev *ucdev,
			       struct ubctl_query_cmd_param *query_cmd_param,
			       struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_TA_PKT_STATS_DFX, UBCTL_TA_PKT_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TA_PKT_STATS_EX_DFX, UBCTL_TA_PKT_STATS_EX_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TA_ABN_STATS_DFX, UBCTL_TA_ABN_STATS_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_ta_pkt_stats(struct ubctl_dev *ucdev,
				    struct ubctl_query_cmd_param *query_cmd_param,
				    struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_TA_PKT_STATS_DFX, UBCTL_TA_PKT_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TA_PKT_STATS_EX_DFX, UBCTL_TA_PKT_STATS_EX_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_ta_abn_stats(struct ubctl_dev *ucdev,
				    struct ubctl_query_cmd_param *query_cmd_param,
				    struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_TA_ABN_STATS_DFX, UBCTL_TA_ABN_STATS_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_ba_data(struct ubctl_dev *ucdev,
			       struct ubctl_query_cmd_param *query_cmd_param,
			       struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_BA_PKT_STATS_DFX, UBCTL_BA_PKT_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_BA_MAR_DFX, UBCTL_BA_MAR_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_ba_pkt_stats_data(struct ubctl_dev *ucdev,
					 struct ubctl_query_cmd_param *query_cmd_param,
					 struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_BA_PKT_STATS_DFX, UBCTL_BA_PKT_STATS_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_conf_ba_mar_perf(struct ubctl_dev *ucdev,
				  struct ubctl_query_cmd_param *query_cmd_param,
				  struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_CONF_BA_PERF_DFX, UBCTL_CONF_BA_MAR_PERF_LEN, UBCTL_WRITE, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_ba_mar_perf(struct ubctl_dev *ucdev,
				   struct ubctl_query_cmd_param *query_cmd_param,
				   struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_BA_MAR_PERF_DFX, UBCTL_QUERY_BA_MAR_PERF_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_ba_mar_data(struct ubctl_dev *ucdev,
				   struct ubctl_query_cmd_param *query_cmd_param,
				   struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_BA_MAR_DFX, UBCTL_BA_MAR_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_mar_cyc_en_data(struct ubctl_dev *ucdev,
				       struct ubctl_query_cmd_param *query_cmd_param,
				       struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_MAR_CYC_EN_DFX, UBCTL_MAR_CYC_EN_LEN, UBCTL_READ, NULL, 0 },
	};
	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_conf_mar_cyc_en_data(struct ubctl_dev *ucdev,
				      struct ubctl_query_cmd_param *query_cmd_param,
				      struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_MAR_CYC_EN_DFX, UBCTL_MAR_CYC_EN_LEN, UBCTL_WRITE, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_mar_table_data(struct ubctl_dev *ucdev,
				      struct ubctl_query_cmd_param *query_cmd_param,
				      struct ubctl_func_dispatch *query_func)
{
#define UBCTL_UB_MEM_TABLE_ENTRY_LEN 16U
#define UBCTL_UB_MEM_TABLE_ENTRY_NUM 7U

	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_MAR_TABLE_DFX, UBCTL_MAR_TABLE_LEN, UBCTL_READ, NULL, 0 },
	};

	if (!query_cmd_param || !query_cmd_param->in)
		return -EINVAL;

	struct fwctl_pkt_in_table *mar_table =
			(struct fwctl_pkt_in_table *)(query_cmd_param->in->data);

	if (query_cmd_param->in->data_size != sizeof(*mar_table)) {
		ubctl_err(ucdev, "user data of mar table is invalid.\n");
		return -EINVAL;
	}

	if (mar_table->table_num == UBCTL_UB_MEM_TABLE_ENTRY_NUM)
		mar_table->index *= UBCTL_UB_MEM_TABLE_ENTRY_LEN;

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_qos_data(struct ubctl_dev *ucdev,
				struct ubctl_query_cmd_param *query_cmd_param,
				struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_QOS_DFX, UBCTL_QOS_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_scc_debug(struct ubctl_dev *ucdev,
				 struct ubctl_query_cmd_param *query_cmd_param,
				 struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_SCC_DEBUG_DFX, UBCTL_SCC_DEBUG_EN_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_config_scc_debug(struct ubctl_dev *ucdev,
				  struct ubctl_query_cmd_param *query_cmd_param,
				  struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_SCC_DEBUG_DFX, UBCTL_SCC_DEBUG_EN_LEN, UBCTL_WRITE, NULL, 0 },
	};

	if (!query_cmd_param || !query_cmd_param->in)
		return -EINVAL;

	if (query_cmd_param->in->data_size != sizeof(struct fwctl_pkt_in_enable)) {
		ubctl_err(ucdev, "user data of scc debug is invalid.\n");
		return -EINVAL;
	}
	u8 *scc_debug_en = (u8 *)(query_cmd_param->in->data);

	if (*scc_debug_en > 1)
		return -EINVAL;

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_ubommu_data(struct ubctl_dev *ucdev,
				   struct ubctl_query_cmd_param *query_cmd_param,
				   struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_UBOMMU_DFX, UBCTL_UBOMMU_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_port_info_data(struct ubctl_dev *ucdev,
				      struct ubctl_query_cmd_param *query_cmd_param,
				      struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_PORT_INFO_DFX, UBCTL_PORT_INFO_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func, query_dp,
				ARRAY_SIZE(query_dp));
}

static int ubctl_query_ecc_2b_data(struct ubctl_dev *ucdev,
				   struct ubctl_query_cmd_param *query_cmd_param,
				   struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_ECC_2B_DFX, UBCTL_ECC_2B_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func, query_dp,
				ARRAY_SIZE(query_dp));
}

static int ubctl_query_queue_data(struct ubctl_dev *ucdev,
				  struct ubctl_query_cmd_param *query_cmd_param,
				  struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_QUEUE_DFX, UBCTL_QUEUE_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func, query_dp,
				ARRAY_SIZE(query_dp));
}

static int ubctl_query_loopback(struct ubctl_dev *ucdev,
				struct ubctl_query_cmd_param *query_cmd_param,
				struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_LOOPBACK, UBCTL_QUERY_DEBUG_EN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_config_loopback(struct ubctl_dev *ucdev,
				 struct ubctl_query_cmd_param *query_cmd_param,
				 struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_LOOPBACK, UBCTL_QUERY_DEBUG_EN, UBCTL_WRITE, NULL, 0 },
	};
	int ret;

	ret = ubctl_query_data(ucdev, query_cmd_param, query_func,
			       query_dp, ARRAY_SIZE(query_dp));

	if (!query_cmd_param || !query_cmd_param->out)
		return -EINVAL;

	if (query_cmd_param->out->retval == -EBUSY)
		ubctl_err(ucdev, "Current port has been enabled for another loopback mode.\n");
	if (query_cmd_param->out->retval == -EMLINK)
		ubctl_err(ucdev, "Another port has already been enabled.\n");

	return ret;
}

static int ubctl_query_prbs(struct ubctl_dev *ucdev,
			    struct ubctl_query_cmd_param *query_cmd_param,
			    struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_PRBS_RESULT, UBCTL_QUERY_DEBUG_EN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_config_prbs(struct ubctl_dev *ucdev,
			     struct ubctl_query_cmd_param *query_cmd_param,
			     struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_PRBS_RESULT, UBCTL_QUERY_DEBUG_EN, UBCTL_WRITE, NULL, 0 },
	};
	int ret;

	ret = ubctl_query_data(ucdev, query_cmd_param, query_func,
			       query_dp, ARRAY_SIZE(query_dp));

	if (!query_cmd_param || !query_cmd_param->out)
		return -EINVAL;

	if (query_cmd_param->out->retval == -EMLINK)
		ubctl_err(ucdev, "Another port has already been enabled.\n");

	return ret;
}

static int ubctl_query_fw_version(struct ubctl_dev *ucdev,
				  struct ubctl_query_cmd_param *query_cmd_param,
				  struct ubctl_func_dispatch *query_func)
{
#define QUERY_TYPE 1
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_FIRMWARE_VERSION_DFX, UBCTL_FIRMWARE_VERSION_LEN,
		  UBCTL_READ, NULL, 0 },
	};

	if (!query_cmd_param || !query_cmd_param->in)
		return -EINVAL;

	*query_cmd_param->in->data = QUERY_TYPE;
	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_nl_ssu_sw(struct ubctl_dev *ucdev,
				 struct ubctl_query_cmd_param *query_cmd_param,
				 struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_NL_SSU_SW_DFX, UBCTL_NL_SSU_SW_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_nl_ssu_oq(struct ubctl_dev *ucdev,
				 struct ubctl_query_cmd_param *query_cmd_param,
				 struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_NL_SSU_OQ_DFX, UBCTL_NL_SSU_OQ_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_nl_ssu_p2p(struct ubctl_dev *ucdev,
				  struct ubctl_query_cmd_param *query_cmd_param,
				  struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_NL_SSU_P2P_DFX, UBCTL_NL_SSU_P2P_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_conf_nl_ssu_vl_pkt(struct ubctl_dev *ucdev,
				    struct ubctl_query_cmd_param *query_cmd_param,
				    struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_CONF_NL_SSU_VL_PKT_DFX, UBCTL_NL_SSU_VL_PKT_LEN,
		  UBCTL_WRITE, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_nl_ssu_vl_pkt(struct ubctl_dev *ucdev,
				     struct ubctl_query_cmd_param *query_cmd_param,
				     struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_CONF_NL_SSU_VL_PKT_DFX, UBCTL_NL_SSU_VL_PKT_LEN,
		  UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_dump_data(struct ubctl_dev *ucdev,
				 struct ubctl_query_cmd_param *query_cmd_param,
				 struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_NL_PKT_STATS_DFX, UBCTL_NL_PKT_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_NL_SSU_STATS_DFX, UBCTL_NL_SSU_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_NL_ABN_DFX, UBCTL_NL_ABN_LEN, UBCTL_READ, NULL, 0 },

		{ UBCTL_QUERY_TP_TX_DFX, UBCTL_TP_TX_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_DFX, UBCTL_TP_RX_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RQM_DFX, UBCTL_TP_RQM_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_STATE_DFX, UBCTL_TP_STATE_DFX_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_EX_DFX, UBCTL_TP_RX_STATS_EX_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_TX_ROUTE_DFX, UBCTL_TP_TX_ROUTE_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_BANK_DFX, UBCTL_TP_RX_BANK_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_BANK_DFX, UBCTL_TP_RX_BANK_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_BANK_DFX, UBCTL_TP_RX_BANK_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_TX_DFX, UBCTL_TP_TX_ABN_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_RX_DFX, UBCTL_TP_RX_ABN_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TP_ABN_STATS_DFX, UBCTL_TP_REG_LEN, UBCTL_READ, NULL, 0 },

		{ UBCTL_QUERY_TA_PKT_STATS_DFX, UBCTL_TA_PKT_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TA_PKT_STATS_EX_DFX, UBCTL_TA_PKT_STATS_EX_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_TA_ABN_STATS_DFX, UBCTL_TA_ABN_STATS_LEN, UBCTL_READ, NULL, 0 },

		{ UBCTL_QUERY_DL_PKT_STATS_DFX, UBCTL_DL_PKT_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_DL_REPL_DFX, UBCTL_DL_REPL_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_DL_LINK_STATUS_DFX, UBCTL_DL_LINK_STATUS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_DL_LANE_DFX, UBCTL_DL_LANE_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_DL_BIT_ERR_DFX, UBCTL_DL_BIT_ERR_LEN, UBCTL_READ, NULL, 0 },

		{ UBCTL_QUERY_BA_PKT_STATS_DFX, UBCTL_BA_PKT_STATS_LEN, UBCTL_READ, NULL, 0 },
		{ UBCTL_QUERY_BA_MAR_DFX, UBCTL_BA_MAR_LEN, UBCTL_READ, NULL, 0 },

		{ UBCTL_QUERY_QOS_DFX, UBCTL_QOS_LEN, UBCTL_READ, NULL, 0 },

		{ UBCTL_QUERY_UBOMMU_DFX, UBCTL_UBOMMU_LEN, UBCTL_READ, NULL, 0 },

		{ UBCTL_QUERY_ECC_2B_DFX, UBCTL_ECC_2B_LEN, UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_dp_deal(ucdev, query_cmd_param, query_func,
				   query_dp, ARRAY_SIZE(query_dp));
}

static int ubctl_query_port_pkt_stats(struct ubctl_dev *ucdev,
				      struct ubctl_query_cmd_param *query_cmd_param,
				      struct ubctl_func_dispatch *query_func)
{
	struct ubctl_query_dp query_dp[] = {
		{ UBCTL_QUERY_PORT_PKT_STATS_DFX, UBCTL_PORT_PKT_STATS_LEN,
		  UBCTL_READ, NULL, 0 },
	};

	return ubctl_query_data(ucdev, query_cmd_param, query_func,
				query_dp, ARRAY_SIZE(query_dp));
}

static struct ubctl_func_dispatch g_ubctl_query_reg[] = {
	{ UTOOL_CMD_QUERY_NL, ubctl_query_nl_data, ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_NL_PKT_STATS, ubctl_query_nl_pkt_stats_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_NL_SSU_STATS, ubctl_query_nl_ssu_stats_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_NL_ABN, ubctl_query_nl_abn_data, ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_NL_SSU_SW, ubctl_query_nl_ssu_sw, ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_NL_SSU_OQ, ubctl_query_nl_ssu_oq, ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_NL_SSU_P2P, ubctl_query_nl_ssu_p2p, ubctl_query_data_deal },
	{ UTOOL_CMD_CONF_NL_SSU_VL_PKT, ubctl_conf_nl_ssu_vl_pkt, ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_NL_SSU_VL_PKT, ubctl_query_nl_ssu_vl_pkt, ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_DL, ubctl_query_dl_data, ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_DL_PKT_STATS, ubctl_query_dl_pkt_stats_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_DL_LINK_STATUS, ubctl_query_dl_link_status_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_DL_LANE, ubctl_query_dl_lane_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_DL_BIT_ERR, ubctl_query_dl_bit_err_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_DL_BIST, ubctl_query_dl_bist_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_CONF_DL_BIST, ubctl_conf_dl_bist_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_DL_BIST_ERR, ubctl_query_dl_bist_err_data,
	  ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_TP, ubctl_query_tp_data, ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_TP_PKT_STATS, ubctl_query_tp_pkt_stats_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_TP_ABN_STATS, ubctl_query_tp_abn_stats_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_TP_TX_ROUTE, ubctl_query_tp_tx_route_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_TP_RX_BANK, ubctl_query_tp_rx_bank_data,
	  ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_TA, ubctl_query_ta_data, ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_TA_PKT_STATS, ubctl_query_ta_pkt_stats,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_TA_ABN_STATS, ubctl_query_ta_abn_stats,
	  ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_BA, ubctl_query_ba_data, ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_BA_PKT_STATS, ubctl_query_ba_pkt_stats_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_BA_MAR, ubctl_query_ba_mar_data, ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_BA_MAR_TABLE, ubctl_query_mar_table_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_BA_MAR_CYC_EN, ubctl_query_mar_cyc_en_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_CONF_BA_MAR_CYC_EN, ubctl_conf_mar_cyc_en_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_CONFIG_BA_MAR_PEFR_STATS, ubctl_conf_ba_mar_perf,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_BA_MAR_PEFR_STATS, ubctl_query_ba_mar_perf,
	  ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_QOS, ubctl_query_qos_data, ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_SCC_DEBUG_EN, ubctl_query_scc_debug,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_CONF_SCC_DEBUG_EN, ubctl_config_scc_debug,
	  ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_UBOMMU, ubctl_query_ubommu_data, ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_PORT_INFO, ubctl_query_port_info_data,
	  ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_PORT_PKT_STATS, ubctl_query_port_pkt_stats,
	  ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_ECC_2B, ubctl_query_ecc_2b_data, ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_QUEUE, ubctl_query_queue_data, ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_LOOPBACK, ubctl_query_loopback, ubctl_query_data_deal },
	{ UTOOL_CMD_CONF_LOOPBACK, ubctl_config_loopback, ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_PRBS_EN, ubctl_query_prbs, ubctl_query_data_deal },
	{ UTOOL_CMD_CONF_PRBS_EN, ubctl_config_prbs, ubctl_query_data_deal },
	{ UTOOL_CMD_QUERY_PRBS_RESULT, ubctl_query_prbs, ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_FIRMWARE_VERSION, ubctl_query_fw_version,
	  ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_DUMP, ubctl_query_dump_data, ubctl_query_data_deal },

	{ UTOOL_CMD_QUERY_MAX, NULL, NULL }
};

struct ubctl_func_dispatch *ubctl_get_query_reg_func(struct ubctl_dev *ucdev,
						     u32 rpc_cmd)
{
	u32 i;

	if (!ucdev)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(g_ubctl_query_reg); i++) {
		if (g_ubctl_query_reg[i].rpc_cmd == rpc_cmd)
			return &g_ubctl_query_reg[i];
	}

	return NULL;
}
