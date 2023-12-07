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

#define HNS_DCA_INVALID_BUF_ID 0UL
#define HNS_DCA_INVALID_DCA_NUM ~0U

/*
 * buffer id(29b) = tag(7b) + owner(22b)
 * [28:22] tag  : indicate the QP config update times.
 * [21: 0] owner: indicate the QP to which the page belongs.
 */
#define HNS_DCA_ID_MASK GENMASK(28, 0)
#define HNS_DCA_TAG_MASK GENMASK(28, 22)
#define HNS_DCA_OWN_MASK GENMASK(21, 0)

#define HNS_DCA_BUF_ID_TO_TAG(buf_id) (((buf_id) & HNS_DCA_TAG_MASK) >> 22)
#define HNS_DCA_BUF_ID_TO_QPN(buf_id) ((buf_id) & HNS_DCA_OWN_MASK)
#define HNS_DCA_TO_BUF_ID(qpn, tag) (((qpn) & HNS_DCA_OWN_MASK) | \
					(((tag) << 22) & HNS_DCA_TAG_MASK))

struct hns_dca_attach_attr {
	u32 sq_offset;
	u32 sge_offset;
	u32 rq_offset;
};

struct hns_dca_attach_resp {
#define HNS_DCA_ATTACH_FLAGS_NEW_BUFFER BIT(0)
	u32 alloc_flags;
	u32 alloc_pages;
};

struct hns_dca_detach_attr {
	u32 sq_idx;
};

typedef int (*hns_dca_enum_callback)(struct hns_dca_page_state *, u32, void *);

void hns_roce_init_dca(struct hns_roce_dev *hr_dev);
void hns_roce_cleanup_dca(struct hns_roce_dev *hr_dev);

void hns_roce_register_udca(struct hns_roce_dev *hr_dev, int max_qps,
			    struct hns_roce_ucontext *uctx);
void hns_roce_unregister_udca(struct hns_roce_dev *hr_dev,
			      struct hns_roce_ucontext *uctx);

int hns_roce_enable_dca(struct hns_roce_qp *hr_qp, struct ib_udata *udata);
void hns_roce_disable_dca(struct hns_roce_dev *hr_dev,
			  struct hns_roce_qp *hr_qp, struct ib_udata *udata);

int hns_roce_dca_attach(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp,
			struct hns_dca_attach_attr *attr);
void hns_roce_dca_detach(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp,
			 struct hns_dca_detach_attr *attr);
void hns_roce_modify_dca(struct hns_roce_dev *hr_dev, struct hns_roce_qp *hr_qp,
			 struct ib_udata *udata);

void hns_roce_enum_dca_pool(struct hns_roce_dca_ctx *dca_ctx, void *param,
			    hns_dca_enum_callback cb);
#endif
