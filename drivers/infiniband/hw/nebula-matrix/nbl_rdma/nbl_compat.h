/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_COMPAT_H
#define NBL_COMPAT_H

#define RDMA_MMAP_DB_SUPPORT
#define kc_ib_register_device(device, name, dev)  \
	ib_register_device(device, name, dev)

#endif  /*NBL_COMPAT_H*/
