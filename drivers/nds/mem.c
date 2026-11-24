// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "p2p: " fmt

#include <linux/errno.h>
#include <linux/module.h>

#include "mem.h"

static typeof(hal_kernel_p2p_get_pages) *get_pages;
static typeof(hal_kernel_p2p_put_pages) *put_pages;

int p2p_mem_init(void)
{
	get_pages = symbol_get(hal_kernel_p2p_get_pages);
	if (!get_pages) {
		pr_err("required symbol hal_kernel_p2p_get_pages is unavailable\n");
		return -ENODEV;
	}

	put_pages = symbol_get(hal_kernel_p2p_put_pages);
	if (!put_pages) {
		pr_err("required symbol hal_kernel_p2p_put_pages is unavailable\n");
		goto put_get_pages;
	}

	return 0;

put_get_pages:
	symbol_put(hal_kernel_p2p_get_pages);
	return -ENODEV;
}

int p2p_mem_get_pages(u64 addr, u64 size, void (*free_callback)(void *data), void *data,
		      struct p2p_page_table **page_table)
{
	return get_pages(addr, size, free_callback, data, page_table);
}

int p2p_mem_put_pages(struct p2p_page_table *page_table)
{
	return put_pages(page_table);
}

void p2p_mem_exit(void)
{
	symbol_put(hal_kernel_p2p_put_pages);
	symbol_put(hal_kernel_p2p_get_pages);
}
