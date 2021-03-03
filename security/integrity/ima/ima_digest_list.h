/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2017-2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_digest_list.h
 *      Header of ima_digest_list.c
 */

#ifndef __LINUX_IMA_DIGEST_LIST_H
#define __LINUX_IMA_DIGEST_LIST_H

#define DIGEST_LIST_OP_ADD 0
#define DIGEST_LIST_OP_DEL 1

#ifdef CONFIG_IMA_DIGEST_LIST
extern struct ima_h_table ima_digests_htable;

int ima_parse_compact_list(loff_t size, void *buf, int op);
#else
static inline int ima_parse_compact_list(loff_t size, void *buf, int op)
{
	return -EOPNOTSUPP;
}
#endif /*CONFIG_IMA_DIGEST_LIST*/
#endif /*LINUX_IMA_DIGEST_LIST_H*/
