// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved.
 */

#include <linux/auxiliary_bus.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/io.h>

#include "ub_common.h"
#include "ub_cmd_reg.h"
#include "ub_cmd.h"

#define MAX_IOCTL_COUNT 1024
#define TIME_WINDOW_MS 3000
#define TIME_WINDOW_JIFFIES msecs_to_jiffies(TIME_WINDOW_MS)
#define UBCTL_CMD_CNT_MAX 100

static u32 g_env_type;
static bool g_dev_client_init_flag;

static DEFINE_MUTEX(g_fifo_lock);
static DEFINE_MUTEX(g_dev_client_init_mutex);

struct ubctl_uctx {
	struct fwctl_uctx uctx;
};

static const u32 g_ubctl_env_type_a0_unsupported_cmds[] = {
	UTOOL_CMD_QUERY_SCC_VERSION, UTOOL_CMD_QUERY_SCC_LOG,
	UTOOL_CMD_QUERY_TA_WQE_TIME, UTOOL_CMD_QUERY_UPA_PKT_STATS, UTOOL_CMD_QUERY_UE_INFO
};

static const u32 g_ubctl_env_type_a1_unsupported_cmds[] = {
	UTOOL_CMD_QUERY_TA_WQE_TIME, UTOOL_CMD_QUERY_UPA_PKT_STATS,
	UTOOL_CMD_QUERY_UE_INFO, UTOOL_CMD_QUERY_BA_ICRC
};

static const u32 g_ubctl_env_type_k0_unsupported_cmds[] = {
	UTOOL_CMD_CONF_NL_SSU_VL_PKT, UTOOL_CMD_QUERY_NL_SSU_VL_PKT, UTOOL_CMD_QUERY_DL_BIST,
	UTOOL_CMD_CONF_DL_BIST, UTOOL_CMD_QUERY_DL_BIST_ERR, UTOOL_CMD_QUERY_DL_RT_BANDWIDTH,
	UTOOL_CMD_QUERY_LOOPBACK, UTOOL_CMD_CONF_LOOPBACK,
	UTOOL_CMD_QUERY_PRBS_EN, UTOOL_CMD_CONF_PRBS_EN, UTOOL_CMD_QUERY_PRBS_RESULT,
	UTOOL_CMD_QUERY_PORT_PKT_STATS, UTOOL_CMD_QUERY_UPA_PKT_STATS, UTOOL_CMD_QUERY_BA_ICRC
};

static const u32 g_ubctl_env_type_k1_unsupported_cmds[] = {
	UTOOL_CMD_CONF_NL_SSU_VL_PKT, UTOOL_CMD_QUERY_NL_SSU_VL_PKT, UTOOL_CMD_QUERY_DL_BIST,
	UTOOL_CMD_CONF_DL_BIST, UTOOL_CMD_QUERY_DL_BIST_ERR, UTOOL_CMD_QUERY_DL_RT_BANDWIDTH,
	UTOOL_CMD_QUERY_LOOPBACK, UTOOL_CMD_CONF_LOOPBACK, UTOOL_CMD_QUERY_PRBS_EN,
	UTOOL_CMD_CONF_PRBS_EN, UTOOL_CMD_QUERY_PRBS_RESULT, UTOOL_CMD_QUERY_PORT_PKT_STATS,
	UTOOL_CMD_QUERY_BA_MAR, UTOOL_CMD_QUERY_BA_MAR_TABLE, UTOOL_CMD_QUERY_BA_MAR_CYC_EN,
	UTOOL_CMD_CONF_BA_MAR_CYC_EN, UTOOL_CMD_CONFIG_BA_MAR_PEFR_STATS,
	UTOOL_CMD_QUERY_BA_MAR_PEFR_STATS, UTOOL_CMD_QUERY_BA_ICRC
};

static int ubctl_open_uctx(struct fwctl_uctx *uctx)
{
	return 0;
}

static void ubctl_close_uctx(struct fwctl_uctx *uctx)
{

}

static void *ubctl_fw_info(struct fwctl_uctx *uctx, size_t *length)
{
	return NULL;
}

static int ubctl_check_cmd_cnt(struct ubctl_dev *ucdev)
{
	if (ARRAY_SIZE(g_ubctl_env_type_a0_unsupported_cmds) > UBCTL_CMD_CNT_MAX ||
	    ARRAY_SIZE(g_ubctl_env_type_a1_unsupported_cmds) > UBCTL_CMD_CNT_MAX ||
	    ARRAY_SIZE(g_ubctl_env_type_k0_unsupported_cmds) > UBCTL_CMD_CNT_MAX ||
	    ARRAY_SIZE(g_ubctl_env_type_k1_unsupported_cmds) > UBCTL_CMD_CNT_MAX) {
		ubctl_err(ucdev, "the cmd cnt is larger than max(%u), pls check!\n",
			  UBCTL_CMD_CNT_MAX);
		return -ENOTTY;
	}

	return 0;
}

static int ubctl_check_env_type(struct ubctl_dev *ucdev, u32 rpc_cmd)
{
	const u32 *unsupported_cmds = NULL;
	u32 cmd_count = 0;
	u32 i;

	if (ubctl_check_cmd_cnt(ucdev))
		return -ENOTTY;
	g_env_type = ubase_get_hw_ver(ucdev->adev);

	switch (g_env_type) {
	case UBASE_HW_VER_A_0:
		unsupported_cmds = g_ubctl_env_type_a0_unsupported_cmds;
		cmd_count = ARRAY_SIZE(g_ubctl_env_type_a0_unsupported_cmds);
		break;
	case UBASE_HW_VER_A_1:
		unsupported_cmds = g_ubctl_env_type_a1_unsupported_cmds;
		cmd_count = ARRAY_SIZE(g_ubctl_env_type_a1_unsupported_cmds);
		break;
	case UBASE_HW_VER_K_0:
		unsupported_cmds = g_ubctl_env_type_k0_unsupported_cmds;
		cmd_count = ARRAY_SIZE(g_ubctl_env_type_k0_unsupported_cmds);
		break;
	case UBASE_HW_VER_K_1:
		unsupported_cmds = g_ubctl_env_type_k1_unsupported_cmds;
		cmd_count = ARRAY_SIZE(g_ubctl_env_type_k1_unsupported_cmds);
		break;
	default:
		ubctl_err(ucdev, "env type(%u) is not support.\n", g_env_type);
		return -ENOTTY;
	}

	for (i = 0; i < cmd_count; i++) {
		if (unsupported_cmds[i] == rpc_cmd) {
			ubctl_err(ucdev, "rpc cmd(0x%x) cannot be used in current env type(%u)\n",
				  rpc_cmd, g_env_type);
			return -ENOTTY;
		}
	}

	return 0;
}

/*
 * Verify if RPC (Remote Procedure Call) requests are valid.
 * It determines whether the request is within the allowed time window.
 */
static int ubctl_check_cmd_frequency(struct ubctl_dev *ucdev, enum fwctl_rpc_scope scope)
{
	unsigned long current_jiffies = jiffies;
	unsigned long earliest_jiffies = 0;
	unsigned long record_jiffies = 0;
	int kfifo_ret = 0;

	earliest_jiffies = current_jiffies - TIME_WINDOW_JIFFIES;
	mutex_lock(&g_fifo_lock);
	while (kfifo_peek(&ucdev->ioctl_fifo, &record_jiffies) && record_jiffies) {
		if (time_after(record_jiffies, earliest_jiffies))
			break;

		kfifo_ret = kfifo_get(&ucdev->ioctl_fifo, &record_jiffies);
		if (!kfifo_ret) {
			mutex_unlock(&g_fifo_lock);
			ubctl_err(ucdev, "unexpected events occurred while obtaining data.\n");
			return kfifo_ret;
		}
	}

	if (kfifo_is_full(&ucdev->ioctl_fifo)) {
		mutex_unlock(&g_fifo_lock);
		ubctl_err(ucdev, "the current number of valid requests exceeds the limit, record_jiffies = %lu, current_jiffies = %lu.\n",
			  record_jiffies, current_jiffies);
		return -EBADMSG;
	}
	kfifo_ret = kfifo_put(&ucdev->ioctl_fifo, current_jiffies);
	if (!kfifo_ret) {
		mutex_unlock(&g_fifo_lock);
		ubctl_err(ucdev, "unexpected events occurred while writing data.\n");
		return kfifo_ret;
	}
	mutex_unlock(&g_fifo_lock);
	return 0;
}

static int ubctl_legitimacy_rpc(struct ubctl_dev *ucdev, size_t out_len,
				enum fwctl_rpc_scope scope, u32 rpc_cmd)
{
	int ret;

	if (scope != FWCTL_RPC_CONFIGURATION &&
	    scope != FWCTL_RPC_DEBUG_READ_ONLY)
		return -EOPNOTSUPP;

	if (out_len < sizeof(struct fwctl_rpc_ub_out)) {
		ubctl_dbg(ucdev, "outlen %zu is less than min value %zu.\n",
			  out_len, sizeof(struct fwctl_rpc_ub_out));
		return -EBADMSG;
	}

	ret = ubctl_check_env_type(ucdev, rpc_cmd);
	if (ret)
		return ret;

	ret = ubctl_check_cmd_frequency(ucdev, scope);
	if (ret)
		return ret;

	return 0;
}

static int ubctl_cmd_err(struct ubctl_dev *ucdev, int ret, struct fwctl_rpc_ub_out *out)
{
	/* Keep rpc_out as contains useful debug info for userspace */
	if (!ret || out->retval)
		return 0;

	return ret;
}

static int ubctl_check_ucdev(struct ubctl_dev *ucdev,
			     struct ubctl_query_cmd_param *query_cmd_param)
{
	u32 expected_size = (u32)sizeof(struct fwctl_pkt_dev_info_match);
	struct fwctl_pkt_dev_info_match *pkt_out_data;
	struct fwctl_pkt_dev_info_match *pkt_in_data;
	struct ubase_caps *ucaps;

	if (query_cmd_param->in->data_size != expected_size) {
		ubctl_err(ucdev, "in data size = %ubytes, it must be %ubytes.\n",
			  query_cmd_param->in->data_size, expected_size);
		return -EINVAL;
	}
	if (query_cmd_param->out_len != expected_size) {
		ubctl_err(ucdev, "out data size = %zubytes, it must be %ubytes.\n",
			  query_cmd_param->out_len, expected_size);
		return -EINVAL;
	}

	ucaps = ubase_get_dev_caps(ucdev->adev);
	if (ucaps == NULL)
		return -ENODEV;

	pkt_in_data = (struct fwctl_pkt_dev_info_match *)query_cmd_param->in->data;
	pkt_out_data = (struct fwctl_pkt_dev_info_match *)query_cmd_param->out->data;

	query_cmd_param->out->retval = 0;
	query_cmd_param->out->data_size = sizeof(struct fwctl_pkt_dev_info_match);
	pkt_out_data->chip_id = ucaps->chip_id;
	pkt_out_data->die_id = ucaps->die_id;

	pkt_out_data->is_matched = (pkt_in_data->chip_id == ucaps->chip_id) &&
				   (pkt_in_data->die_id == ucaps->die_id);

	return 0;
}

static int ub_cmd_do(struct ubctl_dev *ucdev,
		     struct ubctl_query_cmd_param *query_cmd_param)
{
	struct ubctl_func_dispatch *ubctl_query_func;
	struct ubctl_func_dispatch *ubctl_query_reg;
	u32 rpc_cmd = query_cmd_param->in->rpc_cmd;
	int ret;

	ubctl_query_reg = ubctl_get_query_reg_func(ucdev, rpc_cmd);
	ubctl_query_func = ubctl_get_query_func(ucdev, rpc_cmd);

	query_cmd_param->out->env_version = g_env_type;

	switch (rpc_cmd) {
	case UTOOL_CMD_QUERY_DEV_INFO:
		return ubctl_check_ucdev(ucdev, query_cmd_param);
	case UTOOL_CMD_CONF_NL_SSU_VL_PKT:
	case UTOOL_CMD_QUERY_NL_SSU_VL_PKT:
	case UTOOL_CMD_QUERY_LOOPBACK:
	case UTOOL_CMD_CONF_LOOPBACK:
	case UTOOL_CMD_QUERY_PRBS_EN:
	case UTOOL_CMD_CONF_PRBS_EN:
	case UTOOL_CMD_QUERY_PRBS_RESULT:
		ret = ubctl_check_port_type(ucdev, query_cmd_param, UBCTL_PORT_TYPE_ETH);
		if (ret)
			return ret;
		break;

	case UTOOL_CMD_QUERY_DL:
	case UTOOL_CMD_QUERY_DL_PKT_STATS:
	case UTOOL_CMD_QUERY_DL_LINK_STATUS:
	case UTOOL_CMD_QUERY_DL_LANE:
	case UTOOL_CMD_QUERY_DL_BIT_ERR:
	case UTOOL_CMD_QUERY_DL_LINK_TRACE:
	case UTOOL_CMD_QUERY_DL_BIST:
	case UTOOL_CMD_CONF_DL_BIST:
	case UTOOL_CMD_QUERY_DL_BIST_ERR:
		ret = ubctl_check_port_type(ucdev, query_cmd_param, UBCTL_PORT_TYPE_UB);
		if (ret)
			return ret;
		break;
	case UTOOL_CMD_QUERY_DL_PERFORMANCE:
	case UTOOL_CMD_QUERY_DL_RT_BANDWIDTH:
	case UTOOL_CMD_QUERY_DL_PERF_START:
	case UTOOL_CMD_QUERY_DL_PERF:
	case UTOOL_CMD_QUERY_DL_PERF_STOP:
		ret = ubctl_check_port_type_from_bitmap(ucdev, query_cmd_param, UBCTL_PORT_TYPE_UB);
		if (ret)
			return ret;
		break;

	default:
		break;
	}

	if (ubctl_query_func && ubctl_query_func->execute) {
		ret = ubctl_query_func->execute(ucdev, query_cmd_param,
						ubctl_query_func);
	} else if (ubctl_query_reg && ubctl_query_reg->execute) {
		ret = ubctl_query_reg->execute(ucdev, query_cmd_param,
					       ubctl_query_reg);
	} else {
		ubctl_err(ucdev, "no corresponding query was found.\n");
		return -EINVAL;
	}

	return ubctl_cmd_err(ucdev, ret, query_cmd_param->out);
}

static void *ubctl_fw_rpc(struct fwctl_uctx *uctx, enum fwctl_rpc_scope scope,
			  void *rpc_in, size_t in_len, size_t *out_len)
{
	struct ubctl_dev *ucdev = container_of(uctx->fwctl, struct ubctl_dev,
					       fwctl);
	u32 opcode = ((struct fwctl_rpc_ub_in *)rpc_in)->rpc_cmd;
	struct ubctl_query_cmd_param query_cmd_param;
	void *rpc_out;
	int ret;

	ubctl_dbg(ucdev, "cmdif: opcode 0x%x inlen %zu outlen %zu\n",
		  opcode, in_len, *out_len);

	ret = ubctl_legitimacy_rpc(ucdev, *out_len, scope, opcode);
	if (ret)
		return ERR_PTR(ret);

	rpc_out = kvzalloc(*out_len, GFP_KERNEL);
	if (!rpc_out)
		return ERR_PTR(-ENOMEM);

	query_cmd_param.out = rpc_out;
	query_cmd_param.in = rpc_in;
	query_cmd_param.out_len = *out_len - offsetof(struct fwctl_rpc_ub_out, data);
	query_cmd_param.in_len = in_len;

	ret = ub_cmd_do(ucdev, &query_cmd_param);

	ubctl_dbg(ucdev, "cmdif: opcode 0x%x retval %d\n", opcode, ret);

	if (ret) {
		kvfree(rpc_out);
		return ERR_PTR(ret);
	}

	return rpc_out;
}

static const struct fwctl_ops ubctl_ops = {
	.device_type = FWCTL_DEVICE_TYPE_UB,
	.uctx_size = sizeof(struct ubctl_uctx),
	.open_uctx = ubctl_open_uctx,
	.close_uctx = ubctl_close_uctx,
	.info = ubctl_fw_info,
	.fw_rpc = ubctl_fw_rpc,
};

DEFINE_FREE(ubctl, struct ubctl_dev *, if (_T) fwctl_put(&_T->fwctl))

static int ubctl_probe(struct auxiliary_device *adev,
		       const struct auxiliary_device_id *id)
{
	struct ubctl_dev *ucdev __free(ubctl) = fwctl_alloc_device(
		adev->dev.parent, &ubctl_ops, struct ubctl_dev, fwctl);
	int ret;

	if (!ucdev)
		return -ENOMEM;

	ret = kfifo_alloc(&ucdev->ioctl_fifo, MAX_IOCTL_COUNT, GFP_KERNEL);
	if (ret) {
		ubctl_err(ucdev, "kfifo alloc device failed, retval = %d.\n", ret);
		return -ENOMEM;
	}

	ret = fwctl_register(&ucdev->fwctl);
	if (ret) {
		ubctl_err(ucdev, "failed to execute fwctl register, retval = %d.\n", ret);
		kfifo_free(&ucdev->ioctl_fifo);
		return ret;
	}

	ret = ubctl_port_link_status_init(adev, ucdev);
	if (ret)
		ubctl_warn(ucdev, "failed to execute fwctl register crq handler event, retval = %d.\n",
			   ret);

	mutex_lock(&g_dev_client_init_mutex);
	if (!g_dev_client_init_flag) {
		ret = ubctl_dev_client_init(ucdev);
		if (ret)
			ubctl_warn(ucdev, "the dev client has not been fully initialized., retval = %d.\n",
				   ret);
		else
			g_dev_client_init_flag = true;
	}
	mutex_unlock(&g_dev_client_init_mutex);

	ucdev->adev = adev;
	auxiliary_set_drvdata(adev, no_free_ptr(ucdev));
	return 0;
}

static void ubctl_remove(struct auxiliary_device *adev)
{
	struct ubctl_dev *ucdev = auxiliary_get_drvdata(adev);

	mutex_lock(&g_dev_client_init_mutex);
	if (g_dev_client_init_flag) {
		ubctl_dev_client_uninit(ucdev);
		g_dev_client_init_flag = false;
	}
	mutex_unlock(&g_dev_client_init_mutex);

	ubctl_port_link_status_uninit(adev);
	fwctl_unregister(&ucdev->fwctl);
	kfifo_free(&ucdev->ioctl_fifo);
	fwctl_put(&ucdev->fwctl);
}

static const struct auxiliary_device_id ubctl_id_table[] = {
	{
		.name = "ubase.fwctl",
	},
	{}
};
MODULE_DEVICE_TABLE(auxiliary, ubctl_id_table);

static struct auxiliary_driver ubctl_driver = {
	.name = "ub_fwctl",
	.probe = ubctl_probe,
	.remove = ubctl_remove,
	.id_table = ubctl_id_table,
};

module_auxiliary_driver(ubctl_driver);

MODULE_IMPORT_NS(FWCTL);
MODULE_DESCRIPTION("UB fwctl driver");
MODULE_AUTHOR("HiSilicon Tech. Co., Ltd.");
MODULE_LICENSE("GPL");
