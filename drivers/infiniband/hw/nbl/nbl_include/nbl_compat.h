/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_COMPAT_H
#define NBL_COMPAT_H

#define kc_ib_register_device(device, name, dev)  \
	ib_register_device(device, name, dev)
#define nbl_ib_umem_release(umem, nbl_peer) do { if (umem) ib_umem_release(umem); } while (0)

#endif  /*NBL_COMPAT_H*/
