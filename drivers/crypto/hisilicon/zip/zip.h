/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2019 HiSilicon Limited. */

#ifndef HISI_ZIP_H
#define HISI_ZIP_H

#include <linux/list.h>
#include "../qm.h"
#include "zip_usr_if.h"

#undef pr_fmt
#define pr_fmt(fmt)	"hisi_zip: " fmt
#define ZIP_WAIT_DELAY	1000

enum hisi_zip_error_type {
	/* negative compression */
	HZIP_NC_ERR = 0x0d,
};

struct hisi_zip_ctrl;
struct hisi_zip {
	struct hisi_qm qm;
	struct hisi_zip_ctrl *ctrl;
};

int zip_create_qps(struct hisi_qp **qps, int ctx_num);
int hisi_zip_register_to_crypto(void);
void hisi_zip_unregister_from_crypto(void);
#endif
