// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2019 Hisilicon Limited.

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>

#include "hns3_enet.h"
#include "hclge_cmd.h"
#include "hclge_main.h"
#include "hns3_cae_reset.h"

int hns3_cae_nic_reset(const struct hns3_nic_priv *net_priv,
		       void *buf_in, u32 in_size, void *buf_out,
		       u32 out_size)
{
#define MIN_DOG_INTVAL 12
	struct hnae3_handle *h = net_priv->ae_handle;
	struct reset_param *reset_info = (struct reset_param *)buf_in;
	enum hnae3_reset_type rst_type;
	struct hclge_vport *vport = NULL;
	struct hclge_dev *hdev = NULL;
	bool check = !buf_in || in_size < sizeof(struct reset_param);

	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = container_of(h, struct hclge_vport, nic);
	hdev = vport->back;
	rst_type = HNAE3_NONE_RESET;

	if (test_bit(HCLGE_STATE_REMOVING, &hdev->state)) {
		dev_info(&hdev->pdev->dev, "driver already uninit!\n");
		return 0;
	}

	if (time_before(jiffies, (hdev->last_reset_time + MIN_DOG_INTVAL * HZ)))
		return 0;

	if (reset_info->reset_level == HNAE3_FUNC_RESET)
		rst_type = HNAE3_FUNC_RESET;
	else if (reset_info->reset_level == HNAE3_GLOBAL_RESET)
		rst_type = HNAE3_GLOBAL_RESET;

	hdev->reset_level = rst_type;
	dev_info(&hdev->pdev->dev,
		 "user received reset event, reset type is %d\n",
		 hdev->reset_level);

	/* request reset & schedule reset task */
	set_bit(hdev->reset_level, &hdev->reset_request);
	if (!test_and_set_bit(HCLGE_STATE_RST_SERVICE_SCHED, &hdev->state))
		mod_delayed_work_on(cpumask_first(&hdev->affinity_mask),
				    system_wq, &hdev->service_task, 0);

	return 0;
}

int hns3_cae_nic_timeout_cfg(const struct hns3_nic_priv *net_priv,
			     void *buf_in, u32 in_size,
			     void *buf_out, u32 out_size)
{
	struct tx_timeout_param *out_info =
					     (struct tx_timeout_param *)buf_out;
	struct tx_timeout_param *in_info = (struct tx_timeout_param *)buf_in;
	bool check = !buf_in || in_size < sizeof(struct tx_timeout_param);
	struct net_device *netdev = net_priv->netdev;

	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	if (in_info->wr_flag) {
		netdev->watchdog_timeo = (in_info->tx_timeout_size) * HZ;
	} else {
		check = !buf_out || out_size < sizeof(struct tx_timeout_param);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}
		out_info->tx_timeout_size = (netdev->watchdog_timeo) / HZ;
	}

	return 0;
}
