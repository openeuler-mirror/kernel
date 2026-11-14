/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 *
 * Description: uburma device file ops file
 * Author: Qian Guoxin
 * Create: 2021-8-4
 * Note:
 * History: 2021-8-4: Create file
 */

#ifndef UBURMA_FILE_OPS_H
#define UBURMA_FILE_OPS_H

#include <linux/types.h>
#include <linux/kref.h>
#include <linux/fs.h>
#include <linux/mm_types.h>

/**
 * uburma_is_delay_free_enabled() - check asynchronous resource release mode
 *
 * The module parameter may be changed at runtime. Callers making a multi-step
 * decision should read the returned value once and reuse it.
 *
 * Return: true when asynchronous resource release is enabled.
 */
bool uburma_is_delay_free_enabled(void);

void uburma_release_file(struct kref *ref);
int uburma_mmap(struct file *filp, struct vm_area_struct *vma);
int uburma_open(struct inode *inode, struct file *filp);
int uburma_close(struct inode *inode, struct file *filp);
long uburma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

#endif /* UBURMA_FILE_OPS_H */
