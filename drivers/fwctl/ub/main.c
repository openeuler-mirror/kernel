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
#define UBCTL_UNSUPPORTED_RPCCMD_CNT_A_0 3
#define UBCTL_UNSUPPORTED_RPCCMD_CNT_K_0 13
#define UBCTL_CMD_CNT_MAX 100

static DEFINE_MUTEX(g_fifo_lock);

struct ubctl_uctx {
	struct fwctl_uctx uctx;
};

struct ubctl_env_type_info {
	u32 env_type;
	enum ub_fwctl_cmdrpc_type unsupported_rpccmd[UBCTL_CMD_CNT_MAX];
	u32 rpc_cmd_count;
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

static int ubctl_legitimacy_rpc(struct ubctl_dev *ucdev, size_t out_len,
				enum fwctl_rpc_scope scope)
{
	/*
	 * Verify if RPC (Remote Procedure Call) requests are valid.
	 * It determines whether the request is within the allowed time window
	 * and whether the output length meets the requirements by checking
	 * the timestamp and output length of the request.
	 */
	unsigned long current_jiffies = jiffies;
	unsigned long earliest_jiffies = current_jiffies - TIME_WINDOW_JIFFIES;
	unsigned long record_jiffies = 0;
	int kfifo_ret = 0;

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
	if (out_len < sizeof(struct fwctl_rpc_ub_out)) {
		ubctl_dbg(ucdev, "outlen %zu is less than min value %zu.\n",
			  out_len, sizeof(struct fwctl_rpc_ub_out));
		return -EBADMSG;
	}

	if (scope != FWCTL_RPC_CONFIGURATION &&
	    scope != FWCTL_RPC_DEBUG_READ_ONLY)
		return -EOPNOTSUPP;

	return 0;
}

static int ubctl_cmd_err(struct ubctl_dev *ucdev, int ret, struct fwctl_rpc_ub_out *out)
{
	/* Keep rpc_out as contains useful debug info for userspace */
	if (!ret || out->retval)
		return 0;

	return ret;
}

static int ubctl_check_rpc_cmd(struct ubctl_dev *ucdev, u32 rpc_cmd)
{
	static struct ubctl_env_type_info ubctl_env_type_info_table[] = {
		{ UBASE_HW_VER_A_0,
		  { UTOOL_CMD_QUERY_SCC_VERSION, UTOOL_CMD_QUERY_SCC_LOG },
		  UBCTL_UNSUPPORTED_RPCCMD_CNT_A_0 },

		{ UBASE_HW_VER_K_0,
		  { UTOOL_CMD_CONF_NL_SSU_VL_PKT, UTOOL_CMD_QUERY_NL_SSU_VL_PKT,
		    UTOOL_CMD_QUERY_DL_BIST, UTOOL_CMD_CONF_DL_BIST, UTOOL_CMD_QUERY_DL_BIST_ERR,
		    UTOOL_CMD_QUERY_DL_RT_BANDWIDTH, UTOOL_CMD_QUERY_LOOPBACK,
		    UTOOL_CMD_CONF_LOOPBACK, UTOOL_CMD_QUERY_PRBS_EN,
		    UTOOL_CMD_CONF_PRBS_EN, UTOOL_CMD_QUERY_PRBS_RESULT,
		    UTOOL_CMD_QUERY_PORT_PKT_STATS, UTOOL_CMD_QUERY_PORT_LINK_STATS },
		  UBCTL_UNSUPPORTED_RPCCMD_CNT_K_0 },
	};
	int env_type_cnt = ARRAY_SIZE(ubctl_env_type_info_table);
	u32 env_type;
	int i, j;

	env_type = ubase_get_hw_ver(ucdev->adev);
	for (i = 0; i < env_type_cnt; i++) {
		if (ubctl_env_type_info_table[i].env_type != env_type)
			continue;
		for (j = 0; j < ubctl_env_type_info_table[i].rpc_cmd_count; j++) {
			if (ubctl_env_type_info_table[i].unsupported_rpccmd[j] != rpc_cmd)
				continue;
			ubctl_err(ucdev, "rpc cmd(0x%x) cannot be used in current env type(%u)\n",
				  rpc_cmd, env_type);
			return -ENOTTY;
		}
		return 0;
	}
	ubctl_err(ucdev, "env type(%u) is not support.\n", env_type);

	return -ENOTTY;
}

static int ub_cmd_do(struct ubctl_dev *ucdev,
		     struct ubctl_query_cmd_param *query_cmd_param)
{
	u32 rpc_cmd = query_cmd_param->in->rpc_cmd;
	struct ubctl_func_dispatch *ubctl_query_reg = ubctl_get_query_reg_func(
		ucdev, rpc_cmd);
	struct ubctl_func_dispatch *ubctl_query_func = ubctl_get_query_func(
		ucdev, rpc_cmd);
	int ret;

	if (ubctl_query_func && ubctl_query_func->execute) {
		ret = ubctl_query_func->execute(ucdev, query_cmd_param,
						ubctl_query_func);
	} else if (ubctl_query_reg && ubctl_query_reg->execute) {
		ret = ubctl_query_reg->execute(ucdev, query_cmd_param,
					       ubctl_query_reg);
	} else {
		ubctl_err(ucdev, "No corresponding query was found.\n");
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

	ret = ubctl_legitimacy_rpc(ucdev, *out_len, scope);
	if (ret)
		return ERR_PTR(ret);

	ret = ubctl_check_rpc_cmd(ucdev, opcode);
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
		ubctl_err(ucdev, "fwctl register failed, retval = %d.\n", ret);
		kfifo_free(&ucdev->ioctl_fifo);
		return ret;
	}

	ret = ubctl_port_link_status_init(adev, ucdev);
	if (ret)
		ubctl_warn(ucdev, "fwctl register crq handler event failed, retval = %d.\n", ret);

	ucdev->adev = adev;
	auxiliary_set_drvdata(adev, no_free_ptr(ucdev));
	return 0;
}

static void ubctl_remove(struct auxiliary_device *adev)
{
	struct ubctl_dev *ucdev = auxiliary_get_drvdata(adev);

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
