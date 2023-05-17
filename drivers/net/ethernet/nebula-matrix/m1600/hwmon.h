/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#ifndef _NBL_HWMON_H_
#define _NBL_HWMON_H_

int nbl_hwmon_init(struct nbl_adapter *adapter);
void nbl_hwmon_fini(struct nbl_adapter *adapter);

#endif
