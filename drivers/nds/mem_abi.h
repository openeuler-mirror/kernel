/* SPDX-License-Identifier: GPL-2.0 */
#ifndef P2P_MEM_ABI_H_
#define P2P_MEM_ABI_H_

#include <linux/types.h>

/* Mirrors the kernel P2P ABI in CANN's ascend_kernel_hal.h. */
struct p2p_page_info {
	u64 pa;
	u64 reserved[4];
};

#define P2P_GET_PAGE_VERSION 0x1

struct p2p_page_table {
	u32 version;
	u64 page_size;
	struct p2p_page_info *pages_info;
	u64 page_num;
	u64 reserved[4];
};

int hal_kernel_p2p_get_pages(u64 va, u64 len, void (*free_callback)(void *data), void *data,
			     struct p2p_page_table **page_table);
int hal_kernel_p2p_put_pages(struct p2p_page_table *page_table);

#endif
