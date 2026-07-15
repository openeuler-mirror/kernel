/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_CTX_MGT_H__
#define __UBASEPROXY_CTX_MGT_H__

#include "ubaseproxy_dev.h"

#define UBASEPROXY_ALL_UES		0xFFFF
#define UBASEPROXY_UE_ALL_CTX_VA	0x1F

enum ubaseproxy_ctx_va_status {
	UBASEPROXY_CTX_VA_UNINTED = 0,
	UBASEPROXY_CTX_VA_INITING = 1,
	UBASEPROXY_CTX_VA_INTED = 2,
};

struct ubaseproxy_ctx_buf_map {
	struct ubase_ctx_buf_cap *ctx;
	u16 mb_cmd;
};

struct ubaseproxy_update_va_status_cmd {
	__le16	bus_ue_id;
	__le16	ctx_bitmap;
	u8	status;
	u8	resv[19];
};

struct ubaseproxy_ctx_page {
	dma_addr_t		iova;
	u32			npage;
	refcount_t		refcount;
};

static inline int ubaseproxy_check_ctx_mask_field(u32 field, int bit_width)
{
	u32 field_mask = GENMASK(bit_width - 1, 0);

	return (field == 0) || (field == field_mask);
}

int ubaseproxy_ue_res_info_init(struct ubaseproxy_dev *udev);
void ubaseproxy_ue_res_info_uninit(struct ubaseproxy_dev *udev);
int ubaseproxy_ue_ctx_default_init(struct ubaseproxy_dev *udev);
void ubaseproxy_ue_ctx_default_uninit(struct ubaseproxy_dev *udev);
int ubaseproxy_check_ctx_mask_value(struct ubaseproxy_dev *udev,
				    void *ctx_value, void *mask_value,
				    void *default_value, u16 size);
int ubaseproxy_update_ctx_va_status(struct ubaseproxy_dev *udev,
				    u16 bus_ue_id, u16 bitmap, u8 status);
void ubaseproxy_ue_ctx_buf_free(struct ubaseproxy_dev *udev,
				struct ubaseproxy_ue_ctx_buf *ctx_buf);
void ubaseproxy_erase_ue_ctx_resources(struct ubaseproxy_dev *udev,
				       struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa);

#endif /* __UBASEPROXY_CTX_MGT_H__ */
