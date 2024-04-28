/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */
#ifndef __CVM_GUEST_H
#define __CVM_GUEST_H

#ifdef CONFIG_CVM_GUEST
struct device;

extern int set_cvm_memory_encrypted(unsigned long addr, int numpages);

extern int set_cvm_memory_decrypted(unsigned long addr, int numpages);

extern bool is_cvm_world(void);

#define is_swiotlb_for_alloc is_swiotlb_for_alloc
static inline bool is_swiotlb_for_alloc(struct device *dev)
{
	/* Force dma alloc by swiotlb in Confidential VMs */
	return is_cvm_world();
}

extern void __init swiotlb_cvm_update_mem_attributes(void);

#else

static inline int set_cvm_memory_encrypted(unsigned long addr, int numpages)
{
	return 0;
}

static inline int set_cvm_memory_decrypted(unsigned long addr, int numpages)
{
	return 0;
}

static inline bool is_cvm_world(void)
{
	return false;
}

static inline void __init swiotlb_cvm_update_mem_attributes(void) {}

#endif /* CONFIG_CVM_GUEST */
#endif /* __CVM_GUEST_H */
