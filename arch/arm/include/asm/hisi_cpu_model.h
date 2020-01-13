// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 */

#ifndef __HISI_CPU_MODEL_H__
#define __HISI_CPU_MODEL_H__

enum hisi_cpu_type {
	UNKNOWN_HI_TYPE
};

extern enum hisi_cpu_type hi_cpu_type;

void probe_hisi_cpu_type(void);
#endif /* __HISI_CPU_MODEL_H__ */
