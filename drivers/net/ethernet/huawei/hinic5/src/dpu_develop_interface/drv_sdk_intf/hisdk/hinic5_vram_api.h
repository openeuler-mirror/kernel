/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_vram_api.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : VRAM memory allocation interface for hinic5
 */

#ifndef HINIC5_VRAM_API_H
#define HINIC5_VRAM_API_H

#if !defined(__UEFI__) && !defined(__WIN__)
#include <linux/notifier.h>
#include <linux/numa.h>
#endif

#define VRAM_NUMA_NODE0         0
#define VRAM_NUMA_NODE1         1
#define CQM_OVS_PAGESIZE_ORDER       9
#define VRAM_NAME_APPLY_LEN 64

struct vram_buf_info {
	char buf_vram_name[VRAM_NAME_APPLY_LEN];
	int use_vram;
};

#if defined(__UEFI__) || defined(__WIN__) || defined(__VMWARE__)
#define hi5_vram_kalloc_node(name, size, numa) 0
#define hi5_vram_kfree(vaddr, name, size)
#define get5_use_vram_flag() 0
#else

/**
 * @brief alloc vram memory
 * @param name name of vram memory
 * @param size size of vram memory
 * @param numa vram numa node. if greater than environment numa num, apply for idle nodes
 **/
void __iomem *hi5_vram_kalloc_node(char *name, u64 size, u8 numa);
/**
 * @brief free vram memory
 * @param vaddr virtual address of vram memory
 * @param name  name of vram memory
 * @param size  size of vram memory
 **/
void hi5_vram_kfree(void __iomem *vaddr, char *name, u64 size);
/**
 * @brief get use-vram flag
 * @return
 * - Zero for not-use-vram. Non-zero for use-vram.
 **/
int get5_use_vram_flag(void);

#endif
#endif /* HINIC5_VRAM_API_H */