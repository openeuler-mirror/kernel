/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _GMEM_SWAP_POLICY_H
#define _GMEM_SWAP_POLICY_H

#include <linux/mm_types.h>

struct swap_policy {
	int (*init)(void);
	int (*add_page)(struct page *page);
	int (*del_page)(struct page *page);
	int (*update_page)(struct page *page);
	int (*pick_victim_pages)(struct list_head *page_list, int nid, unsigned long *nr);
};

#endif /* _GMEM_SWAP_POLICY_H */
