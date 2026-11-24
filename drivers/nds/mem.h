/* SPDX-License-Identifier: GPL-2.0 */
#ifndef P2P_MEM_H_
#define P2P_MEM_H_

#include "mem_abi.h"

int p2p_mem_get_pages(u64 addr, u64 size, void (*free_callback)(void *data), void *data,
		      struct p2p_page_table **page_table);
int p2p_mem_put_pages(struct p2p_page_table *page_table);

int p2p_mem_init(void);
void p2p_mem_exit(void);

#endif
