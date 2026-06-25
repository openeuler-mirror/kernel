/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_prof_adap.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [PROF]" fmt

#include <linux/kernel.h>
#include <linux/semaphore.h>
#include <linux/workqueue.h>

#include "ossl_knl.h"
#include "hinic5_hwdev.h"
#include "hinic5_profile.h"
#include "hinic5_prof_adap.h"

__weak
const struct hinic5_prof_adapter *hinic5_get_prof_adapter(void *hwdev)
{
	return NULL;
}

int hisdk5_init_profile_adapter(struct hinic5_hwdev *hwdev)
{
	const struct hinic5_prof_adapter *adapter = NULL;

	adapter = hinic5_get_prof_adapter((void *)hwdev);
	if (!adapter) {
		sdk_info(hwdev->dev_hdl, "No profile adapter\n");
		return 0;
	}
	sdk_info(hwdev->dev_hdl, "Find profile adapter type: %d\n", adapter->type);

	if (!hinic5_verify_prof_adapter(adapter)) {
		sdk_err(hwdev->dev_hdl, "Invalid profile adapter\n");
		return -EINVAL;
	}

	hwdev->prof_adap = adapter;
	if (adapter->init)
		hwdev->prof_attr = adapter->init((void *)hwdev);

	return 0;
}

void hisdk5_deinit_profile_adapter(struct hinic5_hwdev *hwdev)
{
	if (!hwdev->prof_adap)
		return;

	if (hwdev->prof_adap->deinit) {
		hwdev->prof_adap->deinit(hwdev->prof_attr);
		hwdev->prof_attr = NULL;
	}
	hwdev->prof_adap = NULL;
}

struct hinic5_prof_attr *hinic5_get_prof_attr(void *hwdev)
{
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;

	if (!hwdev) {
		pr_err("hwdev is NULL\n");
		return NULL;
	}

	return dev->prof_attr;
}
