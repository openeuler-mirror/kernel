/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */

#ifndef __VIRTCCA_CVM_DOMAIN_H
#define __VIRTCCA_CVM_DOMAIN_H
#include <linux/device.h>
#include <linux/virtcca_cvm_sched.h>

#ifdef CONFIG_HISI_VIRTCCA_GUEST

extern void enable_swiotlb_for_cvm_dev(struct device *dev, bool enable);

#else

static inline void enable_swiotlb_for_cvm_dev(struct device *dev, bool enable) {}

static inline void virtcca_its_init(void) {}

static inline struct page *virtcca_its_alloc_shared_pages_node(int node, gfp_t gfp,
			unsigned int order)
{
	return NULL;
}

static inline void virtcca_its_free_shared_pages(void *addr, int order) {}

#endif

#ifdef CONFIG_HISI_VIRTCCA_HOST

bool is_virtcca_cvm_enable(void);
u64 virtcca_get_tmi_version(void);

#else

static inline bool is_virtcca_cvm_enable(void)
{
	return 0;
}

static inline u64 virtcca_get_tmi_version(void)
{
	return 0;
}
#endif

#ifdef CONFIG_HISI_VIRTCCA_CODA
struct pci_dev;

size_t virtcca_pci_get_rom_size(void  *pdev, void __iomem *rom,
			       size_t size);
bool is_virtcca_cc_dev(u32 sid);
int virtcca_add_coda_pci_dev(struct pci_dev *pdev);
void virtcca_dev_destroy(u64 dev_num, u64 clean);
bool is_virtcca_pci_cc_dev(struct device *dev);
int virtcca_create_vdev(struct device *dev);
bool is_virtcca_secure_vf(struct device *dev, struct device_driver *drv);
int virtcca_kvm_prepare_dirty_bitmap(struct kvm *kvm, void *new);
void virtcca_kvm_enable_log_dirty(struct kvm *kvm, void *new, bool *flush);
bool virtcca_kvm_is_realm(struct kvm *kvm);

#else
static inline size_t virtcca_pci_get_rom_size(void  *pdev, void __iomem *rom,
			       size_t size)
{
	return 0;
}

static inline bool is_virtcca_cc_dev(u32 sid)
{
	return false;
}

static inline int virtcca_add_coda_pci_dev(struct pci_dev *pdev)
{
	return 0;
}

static inline void virtcca_dev_destroy(u64 dev_num, u64 clean) {}

static inline bool is_virtcca_pci_cc_dev(struct device *dev)
{
	return false;
}

static inline int virtcca_create_vdev(struct device *dev)
{
	return 0;
}

static inline bool is_virtcca_secure_vf(struct device *dev, struct device_driver *drv)
{
	return false;
}

static inline int virtcca_kvm_prepare_dirty_bitmap(struct kvm *kvm, void *new)
{
	return 0;
}

static inline void virtcca_kvm_enable_log_dirty(struct kvm *kvm, void *new, bool *flush)
{
	;
}

static inline bool virtcca_kvm_is_realm(struct kvm *kvm)
{
	return false;
}
#endif /* CONFIG_HISI_VIRTCCA_CODA */


#if defined(CONFIG_HISI_VIRTCCA_HOST) || defined(CONFIG_HISI_VIRTCCA_GUEST)

void virtcca_raw_data_kern_ctx_cleanup(void *ctx);
int virtcca_raw_data_attr_user_to_kernel(void *usr_data, void *ctx);
int virtcca_raw_data_attr_kernel_to_user(void __user *usr_data_up, void *usr_data,
						void *ctx);

#endif

#endif /* __VIRTCCA_CVM_DOMAIN_H */
