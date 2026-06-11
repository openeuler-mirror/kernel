// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2026. All rights reserved.
 */

#include <linux/mutex.h>

#include <ub/ubfi/ubfi.h>
#include <ub/ubus/ub_black_box.h>

ub_fault_record ub_fault_record_func;
static DEFINE_MUTEX(fault_record_mutex);

void ub_fault_log(struct ub_entity *uent, u32 event_id, void *data)
{
	int ret;

	/* The data can be a null pointer, the above interface may pass NULL */
	if (!uent) {
		pr_err("uent is null\n");
		return;
	}

	mutex_lock(&fault_record_mutex);
	if (!ub_fault_record_func) {
		ub_err(uent, "ub_fault_record_func is not registered\n");
		mutex_unlock(&fault_record_mutex);
		return;
	}

	ret = ub_fault_record_func(uent->ubc->ctl_no, uent_device(uent),
				   uent->entity_idx, event_id, data);
	if (ret)
		ub_err(uent, "ub_fault_record_func execute error, ret=%d\n",
		       ret);

	mutex_unlock(&fault_record_mutex);
}
EXPORT_SYMBOL_GPL(ub_fault_log);

int ub_fault_register(ub_fault_record record)
{
	if (!record)
		return -EINVAL;

	mutex_lock(&fault_record_mutex);
	ub_fault_record_func = record;
	mutex_unlock(&fault_record_mutex);
	pr_info("ub_fault_record register successfully\n");

	return 0;
}
EXPORT_SYMBOL_GPL(ub_fault_register);

void ub_fault_unregister(void)
{
	mutex_lock(&fault_record_mutex);
	ub_fault_record_func = NULL;
	mutex_unlock(&fault_record_mutex);
}
EXPORT_SYMBOL_GPL(ub_fault_unregister);

int ub_fault_vdm(u32 ctl_no, struct ub_vdm_pld *vdm_pld)
{
	struct ub_bus_controller *ubc = NULL;
	struct ub_bus_controller *tmp;
	int ret;

	if (!vdm_pld) {
		pr_err("vdm_pld is null\n");
		return -EINVAL;
	}

	list_for_each_entry(tmp, &ubc_list, node) {
		if (tmp->ctl_no == ctl_no) {
			ubc = tmp;
			break;
		}
	}

	if (!ubc) {
		pr_err("ctl_no %u not found in ubc_list\n", ctl_no);
		return -ENODEV;
	}

	ret = ub_vdm_message(ubc->uent, vdm_pld);
	if (ret)
		pr_err("ub_vdm_message execute error, ret=%d\n", ret);

	return ret;
}
EXPORT_SYMBOL_GPL(ub_fault_vdm);
