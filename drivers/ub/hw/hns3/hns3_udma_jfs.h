/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei HNS3_UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#ifndef _HNS3_UDMA_JFS_H
#define _HNS3_UDMA_JFS_H

#include "hns3_udma_qp.h"
struct hns3_udma_jfs {
	struct ubcore_jfs		ubcore_jfs;
	uint32_t			jfs_id;
	enum ubcore_transport_mode	tp_mode;
	union {
		struct xarray		node_table;
		struct hns3_udma_qp	um_qp;
	};
	struct hns3_udma_qpn_bitmap	qpn_map;
	struct hns3_udma_jfc		*jfc;
};

static inline struct hns3_udma_jfs *to_hns3_udma_jfs(struct ubcore_jfs *jfs)
{
	return container_of(jfs, struct hns3_udma_jfs, ubcore_jfs);
}

struct ubcore_jfs *hns3_udma_create_jfs(struct ubcore_device *dev,
					struct ubcore_jfs_cfg *cfg,
					struct ubcore_udata *udata);
int hns3_udma_destroy_jfs(struct ubcore_jfs *ubcore_jfs);

#endif /* _HNS3_UDMA_JFS_H */
