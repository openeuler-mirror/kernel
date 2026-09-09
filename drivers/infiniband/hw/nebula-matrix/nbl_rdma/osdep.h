/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 */
#ifndef NBL_OSDEP_H
#define NBL_OSDEP_H

struct nbl_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
} __packed;

#endif /* NBL_OSDEP_H */
