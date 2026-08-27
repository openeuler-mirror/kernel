// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <ub/ubase/ubase_comm_cmd.h>

#include "unic_cmd.h"
#include "unic_dev.h"
#include "unic_hw.h"
#include "unic_netdev.h"
#include "unic_crq.h"

static void __unic_handle_link_status_event(struct auxiliary_device *adev,
					    u8 hw_link_status,
					    u8 all_port_link_down)
{
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	u8 link_status;

	if (test_and_set_bit(UNIC_STATE_LINK_UPDATING, &unic_dev->state))
		return;

	unic_dbg(unic_dev, "HW link_event status = %u.\n", hw_link_status);

	unic_dev->hw.mac.link_status = hw_link_status;
	if (unic_dev_ubl_supported(unic_dev))
		hw_link_status = unic_ub_link_status(all_port_link_down);

	link_status = test_bit(UNIC_STATE_DOWN,
			       &unic_dev->state) ? 0 : hw_link_status;
	if (link_status != unic_dev->sw_link_status) {
		unic_dev->sw_link_status = link_status;
		unic_link_status_change(unic_dev->comdev.netdev, link_status);
	}

	clear_bit(UNIC_STATE_LINK_UPDATING, &unic_dev->state);
}

static void unic_link_fail_parse(struct auxiliary_device *adev,
				 u8 link_fail_code)
{
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	static const struct {
		u8 link_fail_code;
		const char *str;
	} codes[] = {
		{UNIC_LF_REF_CLOCK_LOST, "Reference clock lost!\n"},
		{UNIC_LF_XSFP_TX_DISABLE, "SFP tx is disabled!\n"},
		{UNIC_LF_XSFP_ABSENT, "SFP is absent!\n"}
	};

	if (link_fail_code == UNIC_LF_NORMAL)
		return;

	if (link_fail_code >= UNIC_LF_REF_MAX) {
		unic_warn(unic_dev, "unknown fail code, fail_code = %u.\n",
			  link_fail_code);
		return;
	}

	unic_warn(unic_dev, "link fail cause: %s", codes[link_fail_code - 1].str);
}

int unic_handle_link_status_event(void *dev, void *data, u32 len)
{
	struct unic_link_status_cmd_resp *resp = data;
	struct auxiliary_device *adev = dev;
	u8 hw_link_status = resp->status;

	__unic_handle_link_status_event(adev, hw_link_status,
					resp->all_port_link_down);

	if (!hw_link_status && !ubase_adev_ubl_supported(adev))
		unic_link_fail_parse(adev, resp->link_fail_code);

	return 0;
}
