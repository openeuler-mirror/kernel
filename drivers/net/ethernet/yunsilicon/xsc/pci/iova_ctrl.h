/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef _IOVA_CTRL_H_
#define _IOVA_CTRL_H_

#include <linux/types.h>

#define IOVA_CTRL_CB_NAME	"iova_ctrl"

enum {
	XSC_IOVA_CTRL_GET_IOVA = 0,
	XSC_IOVA_CTRL_PUT,
};

struct iova_segment {
	u64 iova;
	u64 size;
	u64 pa;
};

int iova_ctrl_cb_init(void);
void iova_ctrl_cb_fini(void);

#endif /* _IOVA_CTRL_H_ */
