/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 Hisilicon Limited. */
#ifndef HISI_RDE_H
#define HISI_RDE_H

#include <linux/list.h>
#include "../qm.h"
#include "rde_usr_if.h"

#undef pr_fmt
#define pr_fmt(fmt)	"hisi_rde: " fmt

struct hisi_rde_ctrl;

struct hisi_rde {
	struct hisi_qm qm;
	struct list_head list;
	struct hisi_rde_ctrl *ctrl;
};

struct hisi_rde *find_rde_device(int node);

#endif
