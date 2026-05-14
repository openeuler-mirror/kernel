/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hinic5_vram_api.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_HINIC5_VRAM_API_H
#define HINIC5_HINIC5_VRAM_API_H

#if !defined(__UEFI__) && !defined(__WIN__)
#include <linux/notifier.h>
#include <linux/numa.h>
#endif

#define HINIC5_VRAM_NUMA_NODE0         0
#define HINIC5_VRAM_NUMA_NODE1         1
#define HINIC5_CQM_OVS_PAGESIZE_ORDER       9
#define HINIC5_VRAM_NAME_APPLY_LEN 64

struct hinic5_vram_buf_info {
	char buf_hinic5_vram_name[HINIC5_VRAM_NAME_APPLY_LEN];
	int use_hinic5_vram;
};

#if defined(__UEFI__) || defined(__WIN__) || defined(__VMWARE__)
#define hinic5_hinic5_vram_kalloc_node(name, size, numa) 0
#define hinic5_hinic5_vram_kfree(vaddr, name, size)
#define get_use_hinic5_vram_flag() 0
#else

/**
 * @brief alloc hinic5_vram memory
 * @param name name of hinic5_vram memory
 * @param size size of hinic5_vram memory
 * @param numa hinic5_vram numa node. if greater than environment numa num, apply for idle nodes
 **/
void __iomem *hinic5_hinic5_vram_kalloc_node(char *name, u64 size, u8 numa);
/**
 * @brief free hinic5_vram memory
 * @param vaddr virtual address of hinic5_vram memory
 * @param name  name of hinic5_vram memory
 * @param size  size of hinic5_vram memory
 **/
void hinic5_hinic5_vram_kfree(void __iomem *vaddr, char *name, u64 size);
/**
 * @brief get use-hinic5_vram flag
 * @return
 * - Zero for not-use-hinic5_vram. Non-zero for use-hinic5_vram.
 **/
int get_use_hinic5_vram_flag(void);

#endif
#endif /* HINIC5_HINIC5_VRAM_API_H */