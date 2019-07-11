/* SPDX-License-Identifier: GPL-2.0+ */
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

enum hisi_sec_error_type {
	/* negative compression */
	HSEC_NC_ERR = 0x0d,
};

struct hisi_sec_ctrl;

struct hisi_sec {
	struct hisi_qm qm;
	struct list_head list;
	struct hisi_sec_ctrl *ctrl;
	struct dma_pool *sgl_pool;
};

struct hisi_sec *find_sec_device(int node);
int hisi_sec_register_to_crypto(void);
void hisi_sec_unregister_from_crypto(void);
#endif
