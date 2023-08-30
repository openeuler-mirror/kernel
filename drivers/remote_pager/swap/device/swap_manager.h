/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Generalized Memory Management.
 *
 * Copyright (C) 2023- Huawei, Inc.
 * Author: Chen Jun
 *
 */
#ifndef _GMEM_SWAP_MANAGER_H_
#define _GMEM_SWAP_MANAGER_H_

#include <linux/mm_types.h>

#include "ksymbol.h"

int init_swap_manager(char *policy_name);

int add_swap_page(struct page *page);
int del_swap_page(struct page *page);
int update_page(struct page *page);

int need_wake_up_swapd_node(int nid);
int need_wake_up_swapd(void);
int do_swap_node(int nid);
int do_swap(void);
void wake_up_swapd(void);

#endif /* _GMEM_SWAP_MANAGER_H_ */
