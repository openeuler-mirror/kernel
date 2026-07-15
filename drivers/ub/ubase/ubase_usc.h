/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_USC_H__
#define __UBASE_USC_H__

#include <linux/types.h>

#define UBASE_ALLOC_RC_ENTRY 0x100
#define UBASE_FREE_RC_ENTRY  0x101

int ubase_usc_init(struct ubase_dev *udev);
void ubase_usc_uninit(struct ubase_dev *udev);
bool ubase_ctx_in_usc(u8 mb_attr_op);

int ubase_cmd_ctx_buf_alloc_usc(struct ubase_dev *udev,
				struct ubase_ctx_buf_cap *ctx_buf,
				struct ubase_mbx_attr *attr);
void ubase_cmd_ctx_buf_free_usc(struct ubase_dev *udev,
				struct ubase_ctx_buf_cap *ctx_buf,
				u16 mb_cmd);

typedef int (*mem_init_t)(struct device *dev, struct ubase_mm_ops *mm_ops);
typedef void (*mem_uninit_t)(struct device *dev, struct ubase_mm_ops *mm_ops);

extern int usc_mem_init(struct device *dev, struct ubase_mm_ops *mm_ops);
extern void usc_mem_uninit(struct device *dev, struct ubase_mm_ops *mm_ops);

int ubase_alloc_rc_buf_usc(struct ubase_dev *udev,
			   struct ubase_rc_queue *entry, size_t size);
void ubase_free_rc_buf_usc(struct ubase_dev *udev,
			   struct ubase_rc_queue *entry, size_t size);

#endif /* __UBASE_USC_H__ */
