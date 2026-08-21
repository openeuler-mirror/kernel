// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "p2p: " fmt

#include <linux/errno.h>
#include <linux/module.h>

#include "mem.h"

static typeof(devmm_get_mem_pa_list) *get_mem_pa_list;
static typeof(devmm_put_mem_pa_list) *put_mem_pa_list;
static typeof(devmm_get_mem_page_size) *get_mem_page_size;

int p2p_mem_init(void)
{
	get_mem_pa_list = symbol_get(devmm_get_mem_pa_list);
	if (!get_mem_pa_list) {
		pr_err("required symbol devmm_get_mem_pa_list is unavailable\n");
		return -ENODEV;
	}

	put_mem_pa_list = symbol_get(devmm_put_mem_pa_list);
	if (!put_mem_pa_list) {
		pr_err("required symbol devmm_put_mem_pa_list is unavailable\n");
		goto put_get_mem_pa_list;
	}

	get_mem_page_size = symbol_get(devmm_get_mem_page_size);
	if (!get_mem_page_size) {
		pr_err("required symbol devmm_get_mem_page_size is unavailable\n");
		goto put_put_mem_pa_list;
	}

	return 0;

put_put_mem_pa_list:
	symbol_put(devmm_put_mem_pa_list);
put_get_mem_pa_list:
	symbol_put(devmm_get_mem_pa_list);
	return -ENODEV;
}

int p2p_mem_get_pa_list(struct devmm_svm_process_id *process_id, u64 addr,
			u64 size, u64 *pa_list, u32 pa_num)
{
	return get_mem_pa_list(process_id, addr, size, pa_list, pa_num);
}

void p2p_mem_put_pa_list(struct devmm_svm_process_id *process_id, u64 addr,
			 u64 size, u64 *pa_list, u32 pa_num)
{
	put_mem_pa_list(process_id, addr, size, pa_list, pa_num);
}

int p2p_mem_get_page_size(struct devmm_svm_process_id *process_id, u64 addr,
			  u64 size)
{
	return get_mem_page_size(process_id, addr, size);
}

void p2p_mem_exit(void)
{
	symbol_put(devmm_get_mem_page_size);
	symbol_put(devmm_put_mem_pa_list);
	symbol_put(devmm_get_mem_pa_list);
}
