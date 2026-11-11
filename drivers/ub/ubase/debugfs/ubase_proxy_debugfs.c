// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <ub/ubase/ubase_comm_debugfs.h>

#include "ubase_cmd.h"
#include "ubase_debugfs.h"
#include "ubase_proxy.h"
#include "ubase_proxy_debugfs.h"

int ubase_dbg_dump_ue_isolated_state(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_ue_node *ue_node;
	int ret;

	if (!ubase_dev_mbx_proxy_supported(udev))
		return -EOPNOTSUPP;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	seq_puts(s, "UE_ID    ISOLATED_STATE\n");

	ret = ubase_update_ue_isolated_state(udev);
	if (ret)
		return ret;

	mutex_lock(&udev->ue_list_lock);
	list_for_each_entry(ue_node, &udev->ue_list, list) {
		seq_printf(s, "%-13u", ue_node->bus_ue_id);
		seq_printf(s, "%-18u", ue_node->isolated);
		seq_puts(s, "\n");
	}
	mutex_unlock(&udev->ue_list_lock);

	return 0;
}

static void ubase_dump_cmdq_ratelimit_record(struct seq_file *s,
					     struct ubase_ue_node *ue_node)
{
	struct ubase_cmdq_ratelimit_stats *record;
	u8 cnt = 1, stats_cnt;
	u64 total, idx;

	seq_printf(s, "\nUE(%u) cmdq ratelimit record:\n",
		   ue_node->bus_ue_id);

	record = &ue_node->cmdq_ratelimit_stats;
	seq_printf(s, "limited count: %llu\n", record->limited_cnt);
	seq_printf(s, "unlimited count: %llu\n", record->unlimited_cnt);

	total = record->limited_cnt + record->unlimited_cnt;
	if (!total) {
		seq_puts(s, "change records: NA\n");
		return;
	}

	seq_puts(s, "change records:\n");
	seq_puts(s, "\tNo.\tTIME\t\t\t\tSTATUS\n");

	stats_cnt = min(total, UBASE_CMDQ_RATELIMIT_STAT_MAX_NUM);
	while (cnt <= stats_cnt) {
		total--;
		idx = total % UBASE_CMDQ_RATELIMIT_STAT_MAX_NUM;
		seq_printf(s, "\t%-2d\t", cnt);
		ubase_dbg_format_time(record->stats[idx].time, s);
		seq_printf(s, "\t%s",
			   record->stats[idx].limited ?
			   "limited" : "unlimited");
		seq_puts(s, "\n");
		cnt++;
	}
}

int ubase_dbg_dump_ue_cmdq_ratelimit_record(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_ue_node *ue_node;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	seq_puts(s, "current time: ");
	ubase_dbg_format_time(ktime_get_real_seconds(), s);
	seq_puts(s, "\n");

	mutex_lock(&udev->ue_list_lock);
	list_for_each_entry(ue_node, &udev->ue_list, list)
		ubase_dump_cmdq_ratelimit_record(s, ue_node);
	mutex_unlock(&udev->ue_list_lock);

	return 0;
}
