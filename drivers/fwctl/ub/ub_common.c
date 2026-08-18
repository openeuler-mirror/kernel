// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include "ub_common.h"
#include "ub_cmdq.h"

#define MAX_DEV_NAME 64
struct ubctl_unic_udma_dev {
	struct list_head list;
	struct device *dev;
	char dev_name[MAX_DEV_NAME];
};

static LIST_HEAD(g_ubctl_dev_list);
static DEFINE_MUTEX(g_ubctl_dev_lock);

static inline void ubctl_struct_cpu_to_le32(u32 *data, u32 cnt)
{
	for (u32 i = 0; i < cnt; i++)
		data[i] = cpu_to_le32(data[i]);
}

static inline void ubctl_struct_le32_to_cpu(u32 *data, u32 cnt)
{
	for (u32 i = 0; i < cnt; i++)
		data[i] = le32_to_cpu(data[i]);
}

static inline int ubctl_ubase_cmd_send_param_check(struct auxiliary_device *adev,
						   struct ubctl_cmd *cmd)
{
	if (!adev || !cmd)
		return -EINVAL;

	if (!cmd->in_data || !cmd->out_data)
		return -EINVAL;

	return 0;
}

static int ubctl_check_root_permission(struct ubctl_cmd *cmd)
{
	switch (cmd->op_code) {
	case UBCTL_QUERY_CONF_NL_SSU_VL_PKT_DFX:
	case UBCTL_QUERY_CONF_DL_BIST_DFX:
	case UBCTL_QUERY_MAR_CYC_EN_DFX:
	case UBCTL_QUERY_SCC_DEBUG_DFX:
	case UBCTL_QUERY_LOOPBACK:
	case UBCTL_QUERY_PRBS_RESULT:
		if ((!cmd->is_read) && (!capable(CAP_SYS_ADMIN)))
			return -EACCES;
		return 0;
	default:
		return 0;
	}
}

int ubctl_ubase_cmd_send(struct auxiliary_device *adev, struct ubctl_cmd *cmd)
{
	struct ubase_cmd_buf in, out;
	int ret;

	if (ubctl_ubase_cmd_send_param_check(adev, cmd))
		return -EINVAL;

	ret = ubctl_check_root_permission(cmd);
	if (ret)
		return ret;

	ubctl_struct_cpu_to_le32(cmd->in_data, cmd->in_len / sizeof(u32));
	ubase_fill_inout_buf(&in, cmd->op_code, cmd->is_read, cmd->in_len,
			     cmd->in_data);
	ubase_fill_inout_buf(&out, cmd->op_code, cmd->is_read, cmd->out_len,
			     cmd->out_data);

	ret = ubase_cmd_send_inout(adev, &in, &out);
	if (ret)
		return ret;

	ubctl_struct_le32_to_cpu(cmd->out_data, cmd->out_len / sizeof(u32));

	return 0;
}

int ubctl_fill_cmd(struct ubctl_cmd *cmd, void *cmd_in, void *cmd_out,
		   u32 out_len, u32 is_read)
{
	if (!cmd || !cmd_in || !cmd_out)
		return -EINVAL;

	cmd->is_read = is_read;
	cmd->in_data = cmd_in;
	cmd->out_data = cmd_out;
	cmd->in_len = out_len;
	cmd->out_len = out_len;

	return 0;
}

int ubctl_fill_cmd_isread(struct ubctl_cmd *cmd, void *cmd_in, void *cmd_out,
			  u32 out_len, u32 in_len)
{
	if (!cmd || !cmd_in || !cmd_out)
		return -EINVAL;

	cmd->is_read = true;
	cmd->in_data = cmd_in;
	cmd->out_data = cmd_out;
	cmd->in_len = in_len;
	cmd->out_len = out_len;

	return 0;
}

static int ubctl_query_param_check(struct ubctl_dev *ucdev,
				   struct ubctl_query_cmd_param *query_cmd_param,
				   struct ubctl_func_dispatch *query_func,
				   struct ubctl_query_dp *query_dp)
{
	if (!ucdev || !query_cmd_param || !query_func || !query_dp)
		return -EINVAL;

	if (!query_cmd_param->in || !query_cmd_param->out) {
		ubctl_err(ucdev, "ubctl in or out is null.\n");
		return -EINVAL;
	}

	if (!query_func->data_deal) {
		ubctl_err(ucdev, "ubctl data deal func is null.\n");
		return -EINVAL;
	}

	return 0;
}

static int ubctl_cmd_send_deal(struct ubctl_dev *ucdev,
			       struct ubctl_query_cmd_param *query_cmd_param,
			       struct ubctl_query_dp *query_dp,
			       struct ubctl_query_cmd_dp *cmd_data, u32 offset)
{
#define UTOOL_EOPNOTSUPP (-95)
	int *retval = &query_cmd_param->out->retval;
	u32 rpc_cmd = query_cmd_param->in->rpc_cmd;
	struct ubctl_cmd cmd = {};
	int ret = 0;

	cmd.op_code = query_dp->op_code;
	ret = ubctl_fill_cmd(&cmd, cmd_data->cmd_in, cmd_data->cmd_out,
			     query_dp->out_len, query_dp->is_read);
	if (ret) {
		ubctl_err(ucdev, "failed to fill cmd params.\n");
		return ret;
	}

	*retval = ubctl_ubase_cmd_send(ucdev->adev, &cmd);
	if (*retval == UTOOL_EOPNOTSUPP) {
		ubctl_warn(ucdev, "this opcode(%#x) is not supported.\n", cmd.op_code);
		if (rpc_cmd == UBCTL_CMD_QUERY_CONF_USER_COMM)
			return -EINVAL;
		*retval = 0;
	}

	if (*retval) {
		ubctl_err(ucdev, "failed to execute ubctl ubase cmd send, retval = %d.\n",
			  *retval);
		return -EINVAL;
	}

	ret = cmd_data->query_func->data_deal(ucdev, query_cmd_param, &cmd,
					      query_dp->out_len, offset);
	if (ret)
		ubctl_err(ucdev, "failed to execute ubctl data deal, ret = %d.\n", ret);

	return ret;
}

static void ubctl_cmd_data_deal(struct ubctl_query_cmd_param *query_cmd_param,
			       struct ubctl_query_dp *query_dp,
			       struct ubctl_query_cmd_dp *cmd_dp)
{
	if (!query_dp->data) {
		memcpy(cmd_dp->cmd_in, query_cmd_param->in->data, query_cmd_param->in->data_size);
		return;
	}

	if (query_dp->op_code == UBCTL_QUERY_TP_RX_BANK_DFX &&
	    query_dp->data_len == (u32)sizeof(u32))
		memcpy(cmd_dp->cmd_in, query_dp->data, sizeof(u32));
}

int ubctl_query_data(struct ubctl_dev *ucdev,
		     struct ubctl_query_cmd_param *query_cmd_param,
		     struct ubctl_func_dispatch *query_func,
		     struct ubctl_query_dp *query_dp, u32 query_dp_num)
{
	u32 offset = 0;
	int ret = 0;
	u32 i;

	ret = ubctl_query_param_check(ucdev, query_cmd_param, query_func, query_dp);
	if (ret) {
		ubctl_err(ucdev, "failed to check ubctl query param, ret = %d.\n", ret);
		return ret;
	}

	for (i = 0; i < query_dp_num; i++) {
		if (query_cmd_param->in->data_size > query_dp[i].out_len) {
			ubctl_err(ucdev, "user data size = %ubytes, it must be smaller than out len %ubytes.\n",
				  query_cmd_param->in->data_size, query_dp[i].out_len);
			return -EINVAL;
		}

		void *cmd_in __free(kvfree) = kvzalloc(query_dp[i].out_len, GFP_KERNEL);
		if (!cmd_in)
			return -ENOMEM;

		void *cmd_out __free(kvfree) = kvzalloc(query_dp[i].out_len, GFP_KERNEL);
		if (!cmd_out)
			return -ENOMEM;

		struct ubctl_query_cmd_dp cmd_dp = (struct ubctl_query_cmd_dp) {
			.query_func = query_func,
			.cmd_in = cmd_in,
			.cmd_out = cmd_out,
		};

		ubctl_cmd_data_deal(query_cmd_param, &query_dp[i], &cmd_dp);
		ret = ubctl_cmd_send_deal(ucdev, query_cmd_param, &query_dp[i],
					  &cmd_dp, offset);
		if (ret)
			return ret;

		offset += query_dp[i].out_len / sizeof(u32);
	}
	return 0;
}

int ubctl_query_data_deal(struct ubctl_dev *ucdev,
			  struct ubctl_query_cmd_param *query_cmd_param,
			  struct ubctl_cmd *cmd, u32 out_len, u32 offset)
{
	if (!ucdev || !query_cmd_param || !cmd)
		return -EINVAL;

	if (!query_cmd_param->in || !query_cmd_param->out) {
		ubctl_err(ucdev, "ubctl in or out is null.\n");
		return -EINVAL;
	}

	if (cmd->out_len != out_len) {
		ubctl_err(ucdev, "out data size = %ubytes, and it must be %ubytes.\n",
			  cmd->out_len, out_len);
		return -EINVAL;
	}

	if ((offset * (u32)sizeof(u32) + out_len) > query_cmd_param->out_len) {
		ubctl_err(ucdev, "offset size = %ubytes is bigger than user out len = %zubytes.\n",
			  (offset * (u32)sizeof(u32) + out_len), query_cmd_param->out_len);
		return -EINVAL;
	}

	memcpy(&query_cmd_param->out->data[offset], cmd->out_data, cmd->out_len);
	query_cmd_param->out->data_size += cmd->out_len;

	return 0;
}

int ubctl_query_perf(struct ubctl_dev *ucdev, u32 port_bitmap,
		     struct ubase_perf_stats_result *result_data,
		     u32 result_data_size, u32 period)
{
	int ret = 0;

	if (!ucdev || !result_data) {
		ubctl_err(ucdev, "ucdev or result data is NULL.\n");
		return -EINVAL;
	}

	ret = ubase_perf_stats(ucdev->adev, (u64)port_bitmap, period,
			       result_data, result_data_size);
	if (ret)
		ubctl_err(ucdev, "failed to collecting performance.\n");

	return ret;
}

int ubctl_query_perf_stats(struct ubctl_dev *ucdev, u32 port_bitmap,
			   struct ubase_perf_stats_result *result_data,
			   u32 result_data_size)
{
	int ret = 0;

	if (!ucdev || !result_data) {
		ubctl_err(ucdev, "ucdev or result data is NULL.\n");
		return -EINVAL;
	}

	ret = ubase_query_perf_stats(ucdev->adev, (u64)port_bitmap, result_data, result_data_size);
	if (ret)
		ubctl_err(ucdev, "failed to collecting performance.\n");

	return ret;
}

struct device *ubctl_find_device_by_name(const char *dev_name)
{
	struct ubctl_unic_udma_dev *entry = NULL;
	struct device *ret_dev = NULL;

	mutex_lock(&g_ubctl_dev_lock);
	list_for_each_entry(entry, &g_ubctl_dev_list, list) {
		if (strcmp(entry->dev_name, dev_name) == 0) {
			ret_dev = entry->dev;
			break;
		}
	}
	mutex_unlock(&g_ubctl_dev_lock);

	return ret_dev;
}

static int ubctl_add_device(struct device *dev, const char *dev_name)
{
	struct ubctl_unic_udma_dev *new_dev_node;

	if (!dev || !dev_name)
		return -EINVAL;

	new_dev_node = kvzalloc(sizeof(struct ubctl_unic_udma_dev), GFP_KERNEL);
	if (!new_dev_node)
		return -ENOMEM;

	memcpy(new_dev_node->dev_name, dev_name, sizeof(new_dev_node->dev_name));
	INIT_LIST_HEAD(&new_dev_node->list);
	new_dev_node->dev = dev;

	mutex_lock(&g_ubctl_dev_lock);
	list_add(&new_dev_node->list, &g_ubctl_dev_list);
	mutex_unlock(&g_ubctl_dev_lock);

	return 0;
}

static void ubctl_remove_device(const char *dev_name)
{
	struct ubctl_unic_udma_dev *current_node;
	struct ubctl_unic_udma_dev *next;

	mutex_lock(&g_ubctl_dev_lock);
	list_for_each_entry_safe(current_node, next, &g_ubctl_dev_list, list) {
		if (strcmp(current_node->dev_name, dev_name) != 0)
			continue;
		list_del(&current_node->list);
		kvfree(current_node);
		break;
	}
	mutex_unlock(&g_ubctl_dev_lock);
}

static int ubctl_add_udma_device(struct ubcore_device *ubc_dev)
{
	struct udma_dev *udev;
	int ret = 0;

	if (!ubc_dev)
		return -EFAULT;

	udev = to_udma_dev(ubc_dev);
	if (!udev)
		ubctl_dev_warn(&ubc_dev->dev, "udev not obtained.\n");

	ret = ubctl_add_device(&udev->comdev.adev->dev, udev->dev_name);
	if (ret)
		ubctl_dev_warn(udev->dev, "device not added, ret = %d.\n", ret);

	return ret;
}

static void ubctl_remove_udma_device(struct ubcore_device *ubc_dev, void *client_ctx)
{
	if (!ubc_dev)
		return;

	ubctl_remove_device(ubc_dev->dev_name);
}

static struct ubcore_client g_ubctl_udma_client = {
	.list_node = LIST_HEAD_INIT(g_ubctl_udma_client.list_node),
	.client_name = "ub_fwctl",
	.add = ubctl_add_udma_device,
	.remove = ubctl_remove_udma_device
};

static int ubctl_netdevice_event(struct notifier_block *tblock,
				 unsigned long event, void *eptr)
{
	struct net_device *netdev;
	int ret = 0;

	netdev = netdev_notifier_info_to_dev((const struct netdev_notifier_info *)eptr);

	switch (event) {
	case NETDEV_REGISTER:
		ret = ubctl_add_device(&netdev->dev, netdev->name);
		break;
	case NETDEV_UNREGISTER:
		ubctl_remove_device(netdev->name);
		break;
	default:
		break;
	}

	return ret;
}

static struct notifier_block g_ubctl_netdevice = {
	.notifier_call = ubctl_netdevice_event,
};

int ubctl_dev_client_init(struct ubctl_dev *ucdev)
{
	int ret;

	ret = ubcore_register_client(&g_ubctl_udma_client);
	if (ret)
		return ret;

	ret = register_netdevice_notifier(&g_ubctl_netdevice);
	if (ret)
		ubcore_unregister_client(&g_ubctl_udma_client);

	return ret;
}

void ubctl_dev_client_uninit(struct ubctl_dev *ucdev)
{
	struct ubctl_unic_udma_dev *current_node;
	struct ubctl_unic_udma_dev *next;
	int ret;

	ret = unregister_netdevice_notifier(&g_ubctl_netdevice);
	if (ret)
		ubctl_warn(ucdev, "netdevice notifier not deregistered, ret = %d.\n", ret);

	ubcore_unregister_client(&g_ubctl_udma_client);

	mutex_lock(&g_ubctl_dev_lock);
	list_for_each_entry_safe(current_node, next, &g_ubctl_dev_list, list) {
		list_del(&current_node->list);
		kvfree(current_node);
	}
	mutex_unlock(&g_ubctl_dev_lock);
}
