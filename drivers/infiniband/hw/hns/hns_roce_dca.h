/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2022 Hisilicon Limited. All rights reserved.
 */

#ifndef __HNS_ROCE_DCA_H
#define __HNS_ROCE_DCA_H

#include <rdma/uverbs_ioctl.h>

/* DCA page state (32 bit) */
struct hns_dca_page_state {
	u32 buf_id : 29; /* If zero, means page can be used by any buffer. */
	u32 lock : 1; /* @buf_id locked this page to prepare access. */
	u32 active : 1; /* @buf_id is accessing this page. */
	u32 head : 1; /* This page is the head in a continuous address range. */
};

extern const struct uapi_definition hns_roce_dca_uapi_defs[];

struct hns_dca_shrink_resp {
	u64 free_key; /* free buffer's key which registered by the user */
	u32 free_mems; /* free buffer count which no any QP be using */
};

#define HNS_DCA_INVALID_BUF_ID 0UL

void hns_roce_register_udca(struct hns_roce_dev *hr_dev,
			    struct hns_roce_ucontext *uctx);
void hns_roce_unregister_udca(struct hns_roce_dev *hr_dev,
			      struct hns_roce_ucontext *uctx);

void hns_roce_enable_dca(struct hns_roce_dev *hr_dev,
			 struct hns_roce_qp *hr_qp);
void hns_roce_disable_dca(struct hns_roce_dev *hr_dev,
			  struct hns_roce_qp *hr_qp);
#endif
