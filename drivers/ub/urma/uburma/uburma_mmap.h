/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: uburma mmap head file
 * Author: Wen Chen
 * Create: 2024-03-18
 * Note:
 * History: 2024-03-18: Create file
 */

#ifndef UBURMA_MMAP_H
#define UBURMA_MMAP_H

#include <linux/sched/mm.h>

#include "uburma_types.h"

void uburma_unmap_vma_pages(struct uburma_file *ufile);
const struct vm_operations_struct *uburma_get_umap_ops(void);
void uburma_umap_priv_init(struct uburma_umap_priv *priv,
	struct vm_area_struct *vma);

#endif /* UBURMA_MMAP_H */
