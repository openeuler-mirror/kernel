/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_EVENT_H__
#define __UNIC_EVENT_H__

#include <linux/netdevice.h>

enum unic_dbg_ctx_type {
	UNIC_DBG_JFS_CTX = 0,
	UNIC_DBG_JFR_CTX,
	UNIC_DBG_SQ_JFC_CTX,
	UNIC_DBG_RQ_JFC_CTX,
};

struct unic_ctx_info {
	u32 start_idx;
	u32 ctx_size;
	u8 op;
	const char *ctx_name;
};

int unic_register_event(struct auxiliary_device *adev);
void unic_unregister_event(struct auxiliary_device *adev);
int unic_comp_handler(struct notifier_block *nb, unsigned long jfcn, void *data);
int unic_get_ctx_info(struct unic_dev *unic_dev,
		      enum unic_dbg_ctx_type ctx_type,
		      struct unic_ctx_info *ctx_info);
void unic_mask_ctx_key_words(void *buf, enum unic_dbg_ctx_type ctx_type);

#endif /* __UNIC_EVENT_H__ */
