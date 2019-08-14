// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>

#include "hclge_cmd.h"
#include "hclge_main.h"
#include "hnae3.h"
#include "hns3_enet.h"
#include "hns3_priv_irq.h"

struct hns3_irq_lli_param {
	int is_get;
	u8 computer_cpus;
	u16 tqp_nums;
};

int hns3_irq_lli_cfg(struct hns3_nic_priv *net_priv,
		     void *buf_in, u16 in_size, void *buf_out, u16 *out_size)
{
	struct hns3_irq_lli_param *in_info, *out_info;
	struct hnae3_handle *handle;
	int is_get;

	handle = net_priv->ae_handle;
	in_info = (struct hns3_irq_lli_param *)buf_in;
	out_info = (struct hns3_irq_lli_param *)buf_out;
	is_get = in_info->is_get;

	if (is_get) {
		out_info->computer_cpus = net_priv->vector_num;
		out_info->tqp_nums = handle->kinfo.num_tqps;
	}

	return 0;
}
