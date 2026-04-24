/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_DTUMEM_H__
#define __UBASE_DTUMEM_H__

#include "ubase_dev.h"

struct ubase_query_dtu_info_cmd {
	__le32 pa_base_addr_l;
	__le32 pa_base_addr_h;
	__le32 pa_size_l;
	__le32 pa_size_h;
	__le32 va_base_addr_l;
	__le32 va_base_addr_h;
	__le32 mem_node_id_l;
	__le32 mem_node_id_h;
};

struct ubase_cfg_dtu_tbl {
	/* BD0 */
	u8 en; /* 0: delete, 1: config */
	u8 resv0;
	__le16 win_num;

	u8 execlusive : 1;
	u8 resv1 : 7;

	u8 perm_read : 1;
	u8 perm_write : 1;
	u8 perm_atomic : 1;
	u8 resv2 : 5;

	u8 bufferable : 1;
	u8 modified : 1;
	u8 read_allocate : 1;
	u8 write_allocate : 1;
	u8 resv3 : 4;

	u8 snoop : 1;
	u8 resv4 : 7;

	__le32 resv5;
	__le32 tid;
	__le32 base_addr_l;
	__le32 base_addr_h;

	/* BD1 */
	__le32 limit_addr_l;
	__le32 limit_addr_h;
	__le32 target_addr_l;
	__le32 target_addr_h;
	__le32 tokenvalue0;
	__le32 tokenvalue1;
	u8 resv6[8];
};

int ubase_dtu_mem_init(struct ubase_dev *udev);
void ubase_dtu_mem_uninit(struct ubase_dev *udev);
void *ubase_dtu_alloc(struct ubase_dev *udev, struct page **page,
		      size_t size, dma_addr_t *iova);
void ubase_dtu_free(struct ubase_dev *udev, struct page *page,
		    size_t size, dma_addr_t iova);

#endif /* __UBASE_DTUMEM_H__ */
