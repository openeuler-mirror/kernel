// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include "ubase_cmd.h"
#include "ubase_stats.h"

static int ubase_check_port_bitmap(struct ubase_dev *udev, u64 *port_bitmap,
				   u32 data_size)
{
	unsigned long logic_port_bitmap = udev->caps.dev_caps.logic_port_bitmap;

	if (*port_bitmap) {
		if (data_size < bitmap_weight((unsigned long *)port_bitmap,
					      UBASE_MAX_PORT_NUM) ||
		    !bitmap_subset((unsigned long *)port_bitmap,
				   &logic_port_bitmap, UBASE_MAX_PORT_NUM))
			return -EINVAL;
	} else {
		if (data_size != UBASE_MAX_PORT_NUM ||
		    data_size < bitmap_weight((unsigned long *)&logic_port_bitmap,
					     UBASE_MAX_PORT_NUM))
			return -EINVAL;

		*port_bitmap = logic_port_bitmap;
	}

	return 0;
}

static int ubase_update_mac_stats(struct ubase_dev *udev, u16 port_id, u64 *data,
				  u16 size, bool is_accumulate)
{
	u16 mac_stats_num = udev->caps.dev_caps.mac_stats_num;
	struct ubase_query_mac_stats_cmd *cmd;
	struct ubase_cmd_buf in, out;
	u16 i, cmd_size;
	int ret;

	if (!ubase_dev_mac_stats_supported(udev)) {
		ubase_err(udev, "not support get mac stats.\n");
		return -EOPNOTSUPP;
	}

	cmd_size = mac_stats_num * sizeof(u64) + sizeof(*cmd);
	cmd = kzalloc(cmd_size, GFP_KERNEL);
	if (!cmd) {
		ubase_err(udev, "failed to alloc cmdq out_regs.\n");
		return -ENOMEM;
	}

	cmd->port_id = cpu_to_le16(port_id);
	ubase_fill_inout_buf(&in, UBASE_OPC_STATS_MAC_ALL, true, cmd_size, cmd);
	ubase_fill_inout_buf(&out, UBASE_OPC_STATS_MAC_ALL, true, cmd_size, cmd);
	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret) {
		ubase_err(udev, "failed to get mac stats, ret = %d.\n", ret);
		goto out_send_cmd_fail;
	}

	mac_stats_num = min_t(u16, size, mac_stats_num);
	if (is_accumulate)
		for (i = 0; i < mac_stats_num; i++)
			*data++ += le64_to_cpu(cmd->stats_val[i]);
	else
		for (i = 0; i < mac_stats_num; i++)
			*data++ = le64_to_cpu(cmd->stats_val[i]);

out_send_cmd_fail:
	kfree(cmd);

	return ret;
}

/**
 * ubase_clear_eth_port_stats() - clear eth port stats
 * @adev: auxiliary device
 *
 * The function is used to clear eth port stats.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. Sleep.
 * Return: 0 on success, negative error code otherwise
 */
void ubase_clear_eth_port_stats(struct auxiliary_device *adev)
{
	struct ubase_eth_mac_stats *eth_stats;
	struct ubase_dev *udev;

	if (!adev)
		return;

	udev = __ubase_get_udev_by_adev(adev);
	eth_stats = &udev->stats.eth_stats;
	if (ubase_dev_eth_mac_supported(udev)) {
		mutex_lock(&udev->stats.stats_lock);
		memset(eth_stats, 0, sizeof(*eth_stats));
		mutex_unlock(&udev->stats.stats_lock);
	}
}
EXPORT_SYMBOL(ubase_clear_eth_port_stats);

/**
 * ubase_get_ub_port_stats() - (deprecated) get ub port stats
 * @adev: auxiliary device
 * @port_id: port id
 * @data: ub date link layer stats
 *
 * The function is used to get ub port stats.
 *
 * Deprecated, don't use this function in new code.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. Sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_get_ub_port_stats(struct auxiliary_device *adev, u16 port_id,
			    struct ubase_ub_dl_stats *data)
{
	struct ubase_dev *udev;

	if (!adev || !data)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);

	return ubase_update_mac_stats(udev, port_id, (u64 *)data,
				      sizeof(*data) / sizeof(u64), false);
}
EXPORT_SYMBOL(ubase_get_ub_port_stats);

static int ubase_query_dl_pkt_stats(struct ubase_dev *udev, u16 port_id,
				    struct ubase_query_dl_pkt_stats_cmd *resp)
{
	struct ubase_query_dl_pkt_stats_cmd req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	req.logic_port_id = cpu_to_le16(port_id);

	__ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_UB_DL_PKT_STATS, true,
			       sizeof(req), &req);
	__ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_UB_DL_PKT_STATS, false,
			       sizeof(*resp), resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret && ret != -EPERM)
		dev_err_ratelimited(udev->dev,
				    "failed to query ub dl pkt stats, ret = %d.\n",
				    ret);

	return ret == -EPERM ? -EOPNOTSUPP : ret;
}

static int __ubase_get_ub_dl_pkt_stats(struct ubase_dev *udev, u64 port_bitmap,
				       struct ubase_ub_dl_pkt_stats_result *data,
				       u32 data_size)
{
#define UBASE_FLIT_TO_BYTE	20

	struct ubase_query_dl_pkt_stats_cmd resp;
	unsigned long port_num, k;
	u64 pkt_filts;
	int ret;
	u16 i;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_check_port_bitmap(udev, &port_bitmap, data_size);
	if (ret)
		return ret;

	port_num = bitmap_weight((unsigned long *)&port_bitmap,
				 UBASE_MAX_PORT_NUM);

	for (i = 0, k = 0; i < UBASE_MAX_PORT_NUM && k < port_num; i++) {
		if (!test_bit(i, (unsigned long *)&port_bitmap))
			continue;

		memset(&resp, 0, sizeof(resp));
		ret = ubase_query_dl_pkt_stats(udev, i, &resp);
		if (ret)
			return ret;

		pkt_filts = ubase_size_gen(le32_to_cpu(resp.tx_flit_num_h),
					   le32_to_cpu(resp.tx_flit_num_l));
		data[k].tx_pkt_bytes = pkt_filts * UBASE_FLIT_TO_BYTE;
		pkt_filts = ubase_size_gen(le32_to_cpu(resp.rx_flit_num_h),
					   le32_to_cpu(resp.rx_flit_num_l));
		data[k].rx_pkt_bytes = pkt_filts * UBASE_FLIT_TO_BYTE;
		data[k].port_id = i;
		data[k].valid = 1;

		k++;
	}

	return ret;
}

/**
 * ubase_get_ub_dl_pkt_stats() - get ub dl pkt stats
 * @adev: auxiliary device
 * @port_bitmap: port bitmap
 * @data: ub date dl pkt stats
 * @data_size: valid size of data
 *
 * The function is used to get ub dl pkt stats.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. Sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_get_ub_dl_pkt_stats(struct auxiliary_device *adev, u64 port_bitmap,
			      struct ubase_ub_dl_pkt_stats_result *data,
			      u32 data_size)
{
	struct ubase_dev *udev;

	if (!adev || !data || !data_size)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);
	if (!(ubase_dev_ubl_supported(udev) || ubase_dev_fwctl_supported(udev)))
		return -EOPNOTSUPP;

	return __ubase_get_ub_dl_pkt_stats(udev, port_bitmap, data, data_size);
}
EXPORT_SYMBOL(ubase_get_ub_dl_pkt_stats);

int __ubase_get_eth_port_stats(struct ubase_dev *udev,
			       struct ubase_eth_mac_stats *data)
{
	struct ubase_eth_mac_stats *eth_stats = &udev->stats.eth_stats;
	u32 stats_num = sizeof(*eth_stats) / sizeof(u64);
	int ret;

	mutex_lock(&udev->stats.stats_lock);
	ret = ubase_update_mac_stats(udev, udev->caps.dev_caps.io_port_logic_id,
				     (u64 *)eth_stats, stats_num, true);
	if (ret) {
		mutex_unlock(&udev->stats.stats_lock);
		return ret;
	}

	memcpy(data, &udev->stats.eth_stats, sizeof(*data));
	mutex_unlock(&udev->stats.stats_lock);

	return 0;
}

/**
 * ubase_get_eth_port_stats() - get eth port stats
 * @adev: auxiliary device
 * @data: eth mac stats
 *
 * The function is used to get eth port stats.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. Sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_get_eth_port_stats(struct auxiliary_device *adev,
			     struct ubase_eth_mac_stats *data)
{
	struct ubase_dev *udev;

	if (!adev || !data)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);

	return __ubase_get_eth_port_stats(udev, data);
}
EXPORT_SYMBOL(ubase_get_eth_port_stats);

void ubase_update_activate_stats(struct ubase_dev *udev, bool activate,
				 int result)
{
	struct ubase_activate_dev_stats *record = &udev->stats.activate_record;
	u64 idx, total;

	mutex_lock(&record->lock);

	if (activate)
		record->act_cnt++;
	else
		record->deact_cnt++;

	total = record->act_cnt + record->deact_cnt;
	idx = (total - 1) % UBASE_ACT_STAT_MAX_NUM;
	record->stats[idx].activate = activate;
	record->stats[idx].time = ktime_get_real_seconds();
	record->stats[idx].result = result;

	mutex_unlock(&record->lock);
}

int ubase_update_eth_stats_trylock(struct ubase_dev *udev)
{
	struct ubase_eth_mac_stats *eth_stats = &udev->stats.eth_stats;
	u32 stats_num = sizeof(*eth_stats) / sizeof(u64);
	int ret;

	if (!mutex_trylock(&udev->stats.stats_lock))
		return 0;

	ret = ubase_update_mac_stats(udev, udev->caps.dev_caps.io_port_logic_id,
				     (u64 *)eth_stats, stats_num, true);
	mutex_unlock(&udev->stats.stats_lock);

	return ret;
}
