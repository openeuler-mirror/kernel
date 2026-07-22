// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#include <ub/ubus/ubus.h>
#include <ub/ubus/uber.h>

static ub_ras_recover_func_t ub_ras_recover_func;
static DEFINE_SPINLOCK(ubus_ghes_lock);

void ub_ras_register_recover_func(ub_ras_recover_func_t func)
{
	spin_lock(&ubus_ghes_lock);
	ub_ras_recover_func = func;
	spin_unlock(&ubus_ghes_lock);
}
EXPORT_SYMBOL_GPL(ub_ras_register_recover_func);

ub_ras_recover_func_t ub_ras_get_recover_func(void)
{
	ub_ras_recover_func_t tmp_func;

	spin_lock(&ubus_ghes_lock);
	tmp_func = ub_ras_recover_func;
	spin_unlock(&ubus_ghes_lock);

	return tmp_func;
}
EXPORT_SYMBOL_GPL(ub_ras_get_recover_func);
