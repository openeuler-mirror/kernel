/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : micro_log_procfs_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Micro log procfs command header
 */

#ifndef MICRO_LOG_PROCFS_CMD_H_
#define MICRO_LOG_PROCFS_CMD_H_

#include <linux/types.h>

int micro_log_procfs_init(void *hwdev);
void micro_log_procfs_exit(void);

#endif /* MICRO_LOG_PROCFS_CMD_H_ */
