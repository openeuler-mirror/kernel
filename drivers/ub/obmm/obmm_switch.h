/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * Two-phase backend switch entry points (obmm_switch.c): begin/end ioctl
 * bodies, finisher, defensive strand, module-level workqueue.
 */
#ifndef OBMM_SWITCH_H
#define OBMM_SWITCH_H

#include "obmm_core.h"

extern struct workqueue_struct *obmm_switch_wq;

int obmm_switch_begin(struct obmm_cmd_switch_begin *param,
		      struct obmm_cmd_switch_begin __user *uarg);
int obmm_switch_end(const struct obmm_cmd_switch_end *param);
void obmm_switch_finish_fn(struct work_struct *work);
void obmm_switch_force_strand(struct obmm_region *reg);

#endif /* OBMM_SWITCH_H */
