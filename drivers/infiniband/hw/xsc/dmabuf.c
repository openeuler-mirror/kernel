// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */
#include <rdma/ib_verbs.h>

#include "dmabuf.h"
#include "xsc_ib.h"

struct ib_umem_dmabuf *
ib_umem_ex_dmabuf_get_pinned(struct ib_device *device,
			     unsigned long offset,
			     size_t size, int fd,
			     int access)
{
	return ib_umem_dmabuf_get_pinned(device, offset, size,
					 fd, access);
}
