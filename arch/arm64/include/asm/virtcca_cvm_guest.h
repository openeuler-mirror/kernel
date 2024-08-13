/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */
#ifndef __VIRTCCA_CVM_GUEST_H
#define __VIRTCCA_CVM_GUEST_H

#ifdef CONFIG_HISI_VIRTCCA_GUEST
struct device;

extern int set_cvm_memory_encrypted(unsigned long addr, int numpages);

extern int set_cvm_memory_decrypted(unsigned long addr, int numpages);

extern bool is_virtcca_cvm_world(void);

extern void __init swiotlb_cvm_update_mem_attributes(void);

extern void virtcca_cvm_tsi_init(void);

#else

static inline int set_cvm_memory_encrypted(unsigned long addr, int numpages)
{
	return 0;
}

static inline int set_cvm_memory_decrypted(unsigned long addr, int numpages)
{
	return 0;
}

static inline bool is_virtcca_cvm_world(void)
{
	return false;
}

static inline void __init swiotlb_cvm_update_mem_attributes(void) {}

static inline void virtcca_cvm_tsi_init(void) {}

#endif /* CONFIG_HISI_VIRTCCA_GUEST */
#endif /* __VIRTCCA_CVM_GUEST_H */
