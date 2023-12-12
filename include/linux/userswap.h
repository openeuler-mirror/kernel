/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */

#ifndef _LINUX_USERSWAP_H
#define _LINUX_USERSWAP_H

#include <linux/mman.h>

#ifdef CONFIG_USERSWAP

extern struct static_key_false userswap_enabled;

/*
 * In uswap situation, we use the bit 0 of the returned address to indicate
 * whether the pages are dirty.
 */
#define USWAP_PAGES_DIRTY	1

unsigned long uswap_mremap(unsigned long old_addr, unsigned long old_len,
			   unsigned long new_addr, unsigned long new_len);

#endif /* CONFIG_USERSWAP */
#endif /* _LINUX_USERSWAP_H */
