/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Description: Header File for NL SSU link credit overtime error reporter
 * Author: sxt1001
 * Create: 2026-10-28
 */

#ifndef SENTRY_LOCAL_RAS_H
#define SENTRY_LOCAL_RAS_H

#include <linux/init.h>
#include <linux/proc_fs.h>

/*
 * NL SSU link credit overtime error reporter.
 *
 * The error record layout, valid-field bits and severity enum come from the
 * ubus vendor driver header ("../ubus/vendor/hisilicon/local-ras.h"), included
 * directly by sentry_local_ras.c. The platform match table, sub-module name
 * table and link-credit-overtime filter -- mirrored from the ubus vendor driver
 * (drivers/ub/ubus/vendor/hisilicon/local-ras.c) -- also live in
 * sentry_local_ras.c, so this header only exposes the proc interface and the
 * init/exit hooks consumed by sentry_local_reporter.c.
 */
extern const struct proc_ops proc_local_ras_file_operations;

int sentry_local_ras_init(void);
void sentry_local_ras_exit(void);

#endif /* SENTRY_LOCAL_RAS_H */
