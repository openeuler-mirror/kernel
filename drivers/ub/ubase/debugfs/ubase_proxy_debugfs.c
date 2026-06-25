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
