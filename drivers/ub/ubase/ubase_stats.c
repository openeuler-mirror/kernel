// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/delay.h>

#include "ubase_cmd.h"
#include "ubase_stats.h"

static DEFINE_MUTEX(ubase_perf_mutex);
static LIST_HEAD(ubase_die_list);

int ubase_die_list_init(struct ubase_dev *udev)
{
	struct ubase_caps *dev_caps = &udev->caps.dev_caps;
	struct ubase_die_node *pos_node, *new_node;

	mutex_lock(&ubase_perf_mutex);
	list_for_each_entry(pos_node, &ubase_die_list, list) {
		if (pos_node->chip_id == dev_caps->chip_id &&
		    pos_node->die_id == dev_caps->die_id) {
			pos_node->ref_cnt++;
			mutex_unlock(&ubase_perf_mutex);
			return 0;
		}
	}

	new_node = kzalloc(sizeof(*new_node), GFP_KERNEL);
	if (!new_node) {
		mutex_unlock(&ubase_perf_mutex);
		ubase_err(udev, "failed to alloc die node.\n");
		return -ENOMEM;
	}

	new_node->ref_cnt = 1;
	new_node->chip_id = dev_caps->chip_id;
	new_node->die_id = dev_caps->die_id;

	list_add_tail(&new_node->list, &ubase_die_list);

	mutex_unlock(&ubase_perf_mutex);
	return 0;
}

void ubase_die_list_uninit(struct ubase_dev *udev)
{
	struct ubase_caps *dev_caps = &udev->caps.dev_caps;
	struct ubase_die_node *pos_node, *tmp_node;

	mutex_lock(&ubase_perf_mutex);

	list_for_each_entry_safe(pos_node, tmp_node, &ubase_die_list, list) {
		if (pos_node->chip_id == dev_caps->chip_id &&
		    pos_node->die_id == dev_caps->die_id) {
			pos_node->ref_cnt--;
			if (!pos_node->ref_cnt) {
				list_del(&pos_node->list);
				kfree(pos_node);
			}
			break;
		}
	}

	mutex_unlock(&ubase_perf_mutex);
}

static struct ubase_die_node *ubase_query_die_node(struct ubase_dev *udev)
{
	struct ubase_caps *dev_caps = &udev->caps.dev_caps;
	struct ubase_die_node *pos_node;

	list_for_each_entry(pos_node, &ubase_die_list, list) {
		if (pos_node->chip_id == dev_caps->chip_id &&
		    pos_node->die_id == dev_caps->die_id)
			return pos_node;
	}

	ubase_err(udev, "failed to query chip %u die %u node.\n",
		  dev_caps->chip_id, dev_caps->die_id);

	return NULL;
}

static void ubase_set_die_list(struct ubase_dev *udev, u64 port_bitmap,
			       u32 period)
{
	unsigned long port_num, k, tmp_bitmap;
	struct ubase_die_node *node;
	u8 i;

	port_num = bitmap_weight((unsigned long *)&port_bitmap,
				 UBASE_MAX_PORT_NUM);

	node = ubase_query_die_node(udev);
	tmp_bitmap = node->port_bitmap;

	bitmap_or((unsigned long *)&node->port_bitmap, &tmp_bitmap,
		  (unsigned long *)&port_bitmap, UBASE_MAX_PORT_NUM);

	for (i = 0, k = 0; i < UBASE_MAX_PORT_NUM && k < port_num; i++) {
		if (!test_bit(i, (unsigned long *)&port_bitmap))
			continue;

		node->period[i] = period;
		k++;
	}
}

static void ubase_clear_die_list(struct ubase_dev *udev, u64 port_bitmap)
{
	unsigned long port_num, k, tmp_bitmap;
	struct ubase_die_node *node;
	u8 i;

	port_num = bitmap_weight((unsigned long *)&port_bitmap,
				 UBASE_MAX_PORT_NUM);

	node = ubase_query_die_node(udev);
	tmp_bitmap = node->port_bitmap;

	bitmap_andnot((unsigned long *)&node->port_bitmap, &tmp_bitmap,
		      (unsigned long *)&port_bitmap, UBASE_MAX_PORT_NUM);

	for (i = 0, k = 0; i < UBASE_MAX_PORT_NUM && k < port_num; i++) {
		if (!test_bit(i, (unsigned long *)&port_bitmap))
			continue;

		node->period[i] = 0;
		k++;
	}
}

static int ubase_check_opened_port(struct ubase_dev *udev, u64 port_bitmap)
{
	struct ubase_die_node *pos_node;

	pos_node = ubase_query_die_node(udev);
	if (!pos_node)
		return -EINVAL;

	if (pos_node->port_bitmap & port_bitmap) {
		dev_err_ratelimited(udev->dev,
				    "repeat open, opened_port_bitmap = 0x%llx, try_to_open_bitmap = 0x%llx.\n",
				    pos_node->port_bitmap, port_bitmap);
		/* Do not modify this error code, because the upper-layer
		 * module will evaluate this return value.
		 */
		return -EBADFD;
	}

	return 0;
}

static int ubase_check_query_port(struct ubase_dev *udev, u64 port_bitmap)
{
	struct ubase_die_node *pos_node;

	pos_node = ubase_query_die_node(udev);
	if (!pos_node)
		return -EINVAL;

	if ((pos_node->port_bitmap & port_bitmap) != port_bitmap) {
		dev_err_ratelimited(udev->dev,
				    "not all ports opened, opened_port_bitmap = 0x%llx, query_bitmap = 0x%llx.\n",
				    pos_node->port_bitmap, port_bitmap);
		/* Do not modify this error code, because the upper-layer
		 * module will evaluate this return value
		 */
		return -EBADFD;
	}

	return 0;
}

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
		if (data_size != UBASE_MAX_PORT_NUM)
			return -EINVAL;

		*port_bitmap = logic_port_bitmap;
	}

	return 0;
}

static int ubase_check_bitmap(struct ubase_dev *udev, u64 *port_bitmap)
{
	unsigned long logic_port_bitmap = udev->caps.dev_caps.logic_port_bitmap;

	if (*port_bitmap) {
		if (!bitmap_subset((unsigned long *)port_bitmap,
				   &logic_port_bitmap, UBASE_MAX_PORT_NUM))
			return -EINVAL;
	} else {
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
		dev_err_ratelimited(udev->dev, "not support get mac stats.\n");
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
 * @data: ub data link layer stats
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

static int ubase_start_perf_stats(struct ubase_dev *udev, u32 period,
				  u64 port_bitmap)
{
	struct ubase_start_perf_stats_cmd req = {0};
	struct ubase_cmd_buf in;
	int ret;

	req.period = cpu_to_le32(period);
	req.logic_port_bitmap[0] = cpu_to_le32(lower_32_bits(port_bitmap));
	req.logic_port_bitmap[1] = cpu_to_le32(upper_32_bits(port_bitmap));

	__ubase_fill_inout_buf(&in, UBASE_OPC_START_PERF_STATS, false,
			       sizeof(req), &req);
	ret = __ubase_cmd_send_in(udev, &in);
	if (ret && ret != -EPERM)
		dev_err_ratelimited(udev->dev,
				    "failed to cfg perf stats period, ret = %d.\n",
				    ret);

	return ret == -EPERM ? -EOPNOTSUPP : ret;
}

static int ubase_stop_perf_stats(struct ubase_dev *udev,
				 struct ubase_stop_perf_stats_cmd *resp,
				 u32 period, u16 port_id, bool query_only)
{
	struct ubase_stop_perf_stats_cmd req = {0};
	struct ubase_cmd_buf in, out;
	u16 opcode;
	int ret;

	req.period = cpu_to_le32(period);
	req.port_id = cpu_to_le16(port_id);
	opcode = query_only ? UBASE_OPC_QUERY_PERF_STATS :
		 UBASE_OPC_STOP_PERF_STATS;

	__ubase_fill_inout_buf(&in, opcode, true, sizeof(req), &req);
	__ubase_fill_inout_buf(&out, opcode, false, sizeof(*resp), resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret && ret != -EPERM)
		dev_err_ratelimited(udev->dev,
				    "failed to query perf stats, ret = %d, port_id = %u, opcode = 0x%x.\n",
				    ret, port_id, opcode);

	return ret == -EPERM ? -EOPNOTSUPP : ret;
}

static int ubase_close_only_perf_stats(struct ubase_dev *udev, u64 port_bitmap)
{
	struct ubase_die_node *node = ubase_query_die_node(udev);
	struct ubase_stop_perf_stats_cmd resp;
	u32 k, port_num;
	int ret;
	u8 i;

	port_num = bitmap_weight((unsigned long *)&port_bitmap,
				 UBASE_MAX_PORT_NUM);

	for (i = 0, k = 0; i < UBASE_MAX_PORT_NUM && k < port_num; i++) {
		if (!test_bit(i, (unsigned long *)&port_bitmap))
			continue;

		memset(&resp, 0, sizeof(resp));
		ret = ubase_stop_perf_stats(udev, &resp, node->period[i], i,
					    false);
		if (ret == -EOPNOTSUPP)
			return ret;

		k++;
	}

	return 0;
}

static int __ubase_close_perf_stats(struct ubase_dev *udev, u64 port_bitmap)
{
	struct ubase_close_perf_stats_cmd req = {0};
	struct ubase_cmd_buf in;
	int ret;

	req.logic_port_bitmap[0] = cpu_to_le32(lower_32_bits(port_bitmap));
	req.logic_port_bitmap[1] = cpu_to_le32(upper_32_bits(port_bitmap));

	__ubase_fill_inout_buf(&in, UBASE_OPC_CLOSE_PERF_STATS, false,
			       sizeof(req), &req);

	ret = __ubase_cmd_send_in(udev, &in);
	if (ret == -EOPNOTSUPP) {
		ubase_dbg(udev,
			  "firmware not support new stop cmd, try to stop by old cmd.\n");
		return ubase_close_only_perf_stats(udev, port_bitmap);
	} else if (ret) {
		dev_err_ratelimited(udev->dev,
				    "failed to close perf stats, ret = %d.\n",
				    ret);
	}

	return ret;
}

static void ubase_fill_perf_data(struct ubase_perf_stats_result *data,
				 struct ubase_stop_perf_stats_cmd *resp,
				 u8 port_id)
{
	u32 i;

	data->tx_port_bw = le32_to_cpu(resp->tx_port_bw);
	data->rx_port_bw = le32_to_cpu(resp->rx_port_bw);
	data->tx_max_port_bw = le32_to_cpu(resp->tx_max_port_bw);
	data->rx_max_port_bw = le32_to_cpu(resp->rx_max_port_bw);
	data->port_id = port_id;
	data->valid = 1;

	for (i = 0; i < UBASE_STATS_MAX_VL_NUM; i++) {
		data->tx_vl_bw[i] = le32_to_cpu(resp->tx_vl_bw[i]);
		data->rx_vl_bw[i] = le32_to_cpu(resp->rx_vl_bw[i]);
	}
}

int __ubase_perf_stats(struct ubase_dev *udev, u64 port_bitmap, u32 period,
		       struct ubase_perf_stats_result *data, u32 data_size)
{
#define UBASE_MS_TO_US(ms)	(1000 * (ms))

	struct ubase_stop_perf_stats_cmd resp;
	u32 k, port_num;
	int ret;
	u8 i;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_check_port_bitmap(udev, &port_bitmap, data_size);
	if (ret)
		return ret;

	mutex_lock(&ubase_perf_mutex);

	ret = ubase_check_opened_port(udev, port_bitmap);
	if (ret) {
		mutex_unlock(&ubase_perf_mutex);
		return ret;
	}

	ret = ubase_start_perf_stats(udev, period, port_bitmap);
	if (ret)
		goto unlock;

	usleep_range(UBASE_MS_TO_US(period), UBASE_MS_TO_US(period + 1));

	port_num = bitmap_weight((unsigned long *)&port_bitmap,
				 UBASE_MAX_PORT_NUM);

	for (i = 0, k = 0; i < UBASE_MAX_PORT_NUM && k < port_num; i++) {
		if (!test_bit(i, (unsigned long *)&port_bitmap))
			continue;

		memset(&resp, 0, sizeof(resp));
		ret = ubase_stop_perf_stats(udev, &resp, period, i, false);
		if (!ret)
			ubase_fill_perf_data(&data[k], &resp, i);

		k++;
	}

unlock:
	mutex_unlock(&ubase_perf_mutex);

	return ret;
}

/**
 * ubase_open_perf_stats() - open perf stats
 * @adev: auxiliary device
 * @port_bitmap: port bitmap
 * @period: period, unit: ms
 *
 * The function is used to open the port bandwidth and the bandwidth of each vl
 * under the port. The bandwidth statistics collection duration is 'period'.
 * The larger the 'period', the longer the time required, and the more accurate
 * the bandwidth measurement.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. Sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_open_perf_stats(struct auxiliary_device *adev, u64 port_bitmap,
			  u32 period)
{
	struct ubase_dev *udev;
	int ret;

	if (!adev || !period)
		return -EINVAL;

	udev = ubase_get_udev_by_adev(adev);
	if (!(ubase_dev_ubl_supported(udev) || ubase_dev_fwctl_supported(udev)))
		return -EOPNOTSUPP;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_check_bitmap(udev, &port_bitmap);
	if (ret)
		return ret;

	mutex_lock(&ubase_perf_mutex);

	ret = ubase_check_opened_port(udev, port_bitmap);
	if (ret) {
		mutex_unlock(&ubase_perf_mutex);
		return ret;
	}

	ret = ubase_start_perf_stats(udev, period, port_bitmap);
	if (ret) {
		mutex_unlock(&ubase_perf_mutex);
		return ret;
	}

	ubase_set_die_list(udev, port_bitmap, period);

	mutex_unlock(&ubase_perf_mutex);

	return 0;
}
EXPORT_SYMBOL(ubase_open_perf_stats);

static int __ubase_query_perf_stats(struct ubase_dev *udev, u64 port_bitmap,
				    struct ubase_perf_stats_result *data)
{
	struct ubase_die_node *node = ubase_query_die_node(udev);
	struct ubase_stop_perf_stats_cmd resp;
	u32 k, port_num;
	int ret;
	u8 i;

	port_num = bitmap_weight((unsigned long *)&port_bitmap,
				 UBASE_MAX_PORT_NUM);

	for (i = 0, k = 0; i < UBASE_MAX_PORT_NUM && k < port_num; i++) {
		if (!test_bit(i, (unsigned long *)&port_bitmap))
			continue;

		memset(&resp, 0, sizeof(resp));
		ret = ubase_stop_perf_stats(udev, &resp, node->period[i], i,
					    true);
		if (ret)
			return ret;

		ubase_fill_perf_data(&data[k], &resp, i);

		k++;
	}

	return 0;
}

/**
 * ubase_query_perf_stats() - query perf stats
 * @adev: auxiliary device
 * @port_bitmap: port bitmap
 * @data: stats data
 * @data_size: data size
 *
 * The function is used to query the port bandwidth and the bandwidth of each vl
 * under the port.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. Sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_query_perf_stats(struct auxiliary_device *adev, u64 port_bitmap,
			   struct ubase_perf_stats_result *data, u32 data_size)
{
	struct ubase_dev *udev;
	int ret;

	if (!adev || !data || !data_size)
		return -EINVAL;

	udev = ubase_get_udev_by_adev(adev);
	if (!(ubase_dev_ubl_supported(udev) || ubase_dev_fwctl_supported(udev)))
		return -EOPNOTSUPP;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_check_port_bitmap(udev, &port_bitmap, data_size);
	if (ret)
		return -EINVAL;

	mutex_lock(&ubase_perf_mutex);

	ret = ubase_check_query_port(udev, port_bitmap);
	if (ret) {
		mutex_unlock(&ubase_perf_mutex);
		return ret;
	}

	ret = __ubase_query_perf_stats(udev, port_bitmap, data);

	mutex_unlock(&ubase_perf_mutex);

	return ret;
}
EXPORT_SYMBOL(ubase_query_perf_stats);

/**
 * ubase_close_perf_stats() - close perf stats
 * @adev: auxiliary device
 * @port_bitmap: port bitmap
 *
 * The function is used to close the port bandwidth and the bandwidth of each vl
 * under the port.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe. Sleep.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_close_perf_stats(struct auxiliary_device *adev, u64 port_bitmap)
{
	struct ubase_dev *udev;
	int ret;

	if (!adev)
		return -EINVAL;

	udev = ubase_get_udev_by_adev(adev);
	if (!(ubase_dev_ubl_supported(udev) || ubase_dev_fwctl_supported(udev)))
		return -EOPNOTSUPP;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_check_bitmap(udev, &port_bitmap);
	if (ret)
		return -EINVAL;

	mutex_lock(&ubase_perf_mutex);

	ret = __ubase_close_perf_stats(udev, port_bitmap);
	if (ret) {
		mutex_unlock(&ubase_perf_mutex);
		return ret;
	}

	ubase_clear_die_list(udev, port_bitmap);

	mutex_unlock(&ubase_perf_mutex);

	return 0;
}
EXPORT_SYMBOL(ubase_close_perf_stats);
