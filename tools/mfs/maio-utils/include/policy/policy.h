// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */
#ifndef _POLICY_H_
#define _POLICY_H_

#include "maio.h"

int policy_max_io(void);
int policy_load(struct maio **io);
int policy_evict(struct maio **io);
int policy_register(const char *path);
void policy_unregister(void);
int policy_init(void);
void policy_exit(void);

#endif
