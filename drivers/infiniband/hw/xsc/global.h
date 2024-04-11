/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_GLOBAL_H
#define XSC_GLOBAL_H

#define GLOBAL_UNSET_FORCE_VALUE	255

int get_global_force_pcp(void);
int set_global_force_pcp(int force_pcp);

int get_global_force_dscp(void);
int set_global_force_dscp(int force_dscp);

#endif
