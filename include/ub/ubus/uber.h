/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef _UB_UBUS_UBER_H_
#define _UB_UBUS_UBER_H_

#include <linux/cper.h>

typedef void (*ub_ras_recover_func_t)(struct cper_sec_ubus *err, int severity);

#ifdef CONFIG_UB_UBUS
void ub_ras_register_recover_func(ub_ras_recover_func_t func);
ub_ras_recover_func_t ub_ras_get_recover_func(void);
#else
static inline void ub_ras_register_recover_func(ub_ras_recover_func_t func) {}
static inline ub_ras_recover_func_t ub_ras_get_recover_func(void)
{
	return NULL;
}
#endif /* CONFIG_UB_UBUS */

#endif /* _UB_UBUS_UBER_H_ */
