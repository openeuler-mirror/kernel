/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2018-2019 HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef HISI_SEC_H
#define HISI_SEC_H

#include <linux/list.h>
#include "../qm.h"
#include "../sgl.h"
#include "sec_usr_if.h"

#undef pr_fmt
#define pr_fmt(fmt)	"hisi_sec: " fmt

enum sec_endian {
	SEC_LE = 0,
	SEC_32BE,
	SEC_64BE
};

struct hisi_sec_ctrl;

struct hisi_sec {
	struct hisi_qm qm;
	struct list_head list;
	struct hisi_sec_ctrl *ctrl;
	struct dma_pool *sgl_pool;
	int ctx_q_num;
};

struct hisi_sec *find_sec_device(int node);
int hisi_sec_register_to_crypto(void);
void hisi_sec_unregister_from_crypto(void);
#endif
