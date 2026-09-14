// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */
#include <linux/hashtable.h>
#include <linux/pci.h>
#include <linux/vfio.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/io-64-nonatomic-hi-lo.h>
#include <asm/rmi_cmds.h>
#include <asm/kvm_emulate.h>
#include <asm/hisi_cca_da.h>

#include "../../../../drivers/iommu/arm/arm-smmu-v3/arm-smmu-v3.h"
#include "../../../../drivers/iommu/arm/arm-smmu-v3/arm-r-smmu-v3.h"

#define MAX_REALM_DEV_NUM_ORDER		8
#define PCI_DEVICE_ID_HUAWEI_ZIP_PF	0xa250
#define PCI_DEVICE_ID_HUAWEI_SEC_PF	0xa255
#define PCI_DEVICE_ID_HUAWEI_HPRE_PF	0xa258
#define PCI_BDF_MASK			0xffff

struct dev_hash_entry {
	u16 root_bdf; /* The bdf of the root device: pcie root port, or acc PF */
	bool delegated; /* True if device is delegated to Realm */
	u32 assigned_cnt; /* The count of devs assigned in VMs */
	struct hlist_node node; /* hash table */
};

static DEFINE_HASHTABLE(g_root_dev_htable, MAX_REALM_DEV_NUM_ORDER);
static DEFINE_SPINLOCK(g_dev_htable_lock);

static DEFINE_HASHTABLE(g_realm_dev_htable, MAX_REALM_DEV_NUM_ORDER);
static DEFINE_SPINLOCK(g_realm_dev_lock);

static DECLARE_BITMAP(g_pcipc_ns, (PCI_BDF_MASK + 1));
static DEFINE_SPINLOCK(g_pcipc_ns_lock);

static DECLARE_BITMAP(g_dev_protected, (PCI_BDF_MASK + 1));
static DEFINE_SPINLOCK(g_dev_protected_lock);

bool is_support_rme(void)
{
	return static_branch_unlikely(&kvm_rme_is_available) && (kvm_get_cvm_type() == ARMCCA_CVM);
}
EXPORT_SYMBOL_GPL(is_support_rme);

void hisi_pcipc_ns_remove(const struct pci_device_id *id_table)
{
	const struct pci_device_id *ent;
	struct pci_dev *pdev = NULL;
	uint16_t bdf;

	if (!is_support_rme())
		return;

	spin_lock(&g_pcipc_ns_lock);
	for_each_pci_dev(pdev) {
		ent = pci_match_id(id_table, pdev);
		if (!ent)
			continue;
		bdf = pci_dev_id(pdev);
		bitmap_clear(g_pcipc_ns, bdf, 1);
	}
	spin_unlock(&g_pcipc_ns_lock);
}
EXPORT_SYMBOL_GPL(hisi_pcipc_ns_remove);

/*
 * hisi_pcipc_ns_add should be called before pci_register_driver
 */
void hisi_pcipc_ns_add(const struct pci_device_id *id_table)
{
	const struct pci_device_id *ent;
	struct pci_dev *pdev = NULL;
	uint16_t bdf;

	if (!is_support_rme())
		return;

	spin_lock(&g_pcipc_ns_lock);
	for_each_pci_dev(pdev) {
		ent = pci_match_id(id_table, pdev);
		if (!ent)
			continue;

		bdf = pci_dev_id(pdev);
		bitmap_set(g_pcipc_ns, bdf, 1);
	}
	spin_unlock(&g_pcipc_ns_lock);
}
EXPORT_SYMBOL_GPL(hisi_pcipc_ns_add);

bool is_hisi_pcipc_ns(struct device *dev)
{
	bool is_pcipc_ns = false;

	if (!is_support_rme() || !dev)
		return false;

	if (dev_is_pci(dev)) {
		spin_lock(&g_pcipc_ns_lock);
		is_pcipc_ns = bitmap_read(g_pcipc_ns, pci_dev_id(to_pci_dev(dev)), 1);
		spin_unlock(&g_pcipc_ns_lock);
	}

	return is_pcipc_ns;
}
EXPORT_SYMBOL_GPL(is_hisi_pcipc_ns);

struct realm *rme_get_realm(u64 vttbr)
{
	struct realm_dev_entry *dev_entry;
	struct vfio_device *vfio_device;
	struct device *dev = NULL;
	struct kvm *kvm;
	int bkt;

	spin_lock(&g_realm_dev_lock);
	hash_for_each(g_realm_dev_htable, bkt, dev_entry, node) {
		if (dev_entry->vttbr == vttbr) {
			dev = dev_entry->dev;
			break;
		}
	}
	spin_unlock(&g_realm_dev_lock);

	if (!dev)
		return NULL;

	vfio_device = dev_get_drvdata(dev);
	if (!vfio_device || vfio_device->dev != dev) {
		pr_err("Can not find vfio_device\n");
		return NULL;
	}

	kvm = vfio_device->kvm;
	if (!kvm) {
		pr_err("Can not find kvm\n");
		return NULL;
	}

	return &kvm->arch.realm;
}

static void rme_dev_entry_set(struct realm_dev_entry *dev_entry,
			      struct device *dev, u64 vttbr, bool realm,
			      u64 ns_vttbr, bool pcipc_ns)
{
	dev_entry->dev = dev;
	dev_entry->vttbr = vttbr;
	dev_entry->realm = realm;
	dev_entry->ns_vttbr = ns_vttbr;
	dev_entry->pcipc_ns = pcipc_ns;
}

void rme_add_dev_entry(struct device *dev, u64 vttbr, bool realm, u64 ns_vttbr,
		       bool pcipc_ns)
{
	struct realm_dev_entry *dev_entry;

	spin_lock(&g_realm_dev_lock);
	hash_for_each_possible(g_realm_dev_htable, dev_entry, node, (u64)dev) {
		if (dev_entry->dev == dev) {
			rme_dev_entry_set(dev_entry, dev, vttbr, realm, ns_vttbr,
					  pcipc_ns);
			spin_unlock(&g_realm_dev_lock);
			return;
		}
	}
	dev_entry = kzalloc(sizeof(*dev_entry), GFP_ATOMIC);
	if (!dev_entry) {
		spin_unlock(&g_realm_dev_lock);
		pr_err("Alloc realm_dev_entry failed\n");
		return;
	}
	rme_dev_entry_set(dev_entry, dev, vttbr, realm, ns_vttbr, pcipc_ns);
	hash_add(g_realm_dev_htable, &dev_entry->node, (u64)dev);
	spin_unlock(&g_realm_dev_lock);
}
EXPORT_SYMBOL_GPL(rme_add_dev_entry);

void rme_update_msi_iova(u64 vttbr, u64 msi_iova, u64 iova)
{
	struct realm_dev_entry *dev_entry;
	int bkt;

	spin_lock(&g_realm_dev_lock);
	hash_for_each(g_realm_dev_htable, bkt, dev_entry, node) {
		if (dev_entry->vttbr == vttbr && dev_entry->msi_iova == 0) {
			dev_entry->msi_iova = msi_iova;
			dev_entry->msi_page_index = (iova - REALM_MSI_ORIG_IOVA) / MSI_PAGE_SIZE;
			break;
		}
	}
	spin_unlock(&g_realm_dev_lock);
}

static struct realm_dev_entry rme_get_dev_entry(struct device *dev)
{
	struct realm_dev_entry *dev_entry;
	struct realm_dev_entry ret = {0};

	spin_lock(&g_realm_dev_lock);
	hash_for_each_possible(g_realm_dev_htable, dev_entry, node, (u64)dev) {
		if (dev_entry->dev == dev) {
			ret = *dev_entry;
			break;
		}
	}
	spin_unlock(&g_realm_dev_lock);
	return ret;
}

u64 rme_get_msi_iova(struct device *dev, u64 msi_page_index)
{
	struct realm_dev_entry *dev_entry = NULL;
	u64 vttbr = 0;
	int bkt;

	spin_lock(&g_realm_dev_lock);
	hash_for_each(g_realm_dev_htable, bkt, dev_entry, node) {
		if (dev_entry->dev == dev) {
			vttbr = dev_entry->vttbr;
			break;
		}
	}
	if (vttbr == 0)
		goto out;

	hash_for_each(g_realm_dev_htable, bkt, dev_entry, node) {
		if (dev_entry->vttbr == vttbr &&
		    dev_entry->msi_page_index == msi_page_index &&
		    dev_entry->msi_iova) {
			spin_unlock(&g_realm_dev_lock);
			return dev_entry->msi_iova;
		}
	}

out:
	spin_unlock(&g_realm_dev_lock);
	return REALM_MSI_ORIG_IOVA + msi_page_index * MSI_PAGE_SIZE;
}

u64 rme_get_ns_vttbr(struct device *dev)
{
	return rme_get_dev_entry(dev).ns_vttbr;
}
EXPORT_SYMBOL_GPL(rme_get_ns_vttbr);

bool rme_is_realm_dev(struct device *dev)
{
	return rme_get_dev_entry(dev).realm;
}
EXPORT_SYMBOL_GPL(rme_is_realm_dev);

bool rme_is_pcipc_ns_dev(struct device *dev)
{
	struct realm_dev_entry dev_entry = rme_get_dev_entry(dev);

	return !dev_entry.realm && dev_entry.pcipc_ns;
}
EXPORT_SYMBOL_GPL(rme_is_pcipc_ns_dev);

void rme_remove_dev_entry(struct device *dev)
{
	struct hlist_node *next;
	struct realm_dev_entry *dev_entry;

	spin_lock(&g_realm_dev_lock);
	hash_for_each_possible_safe(g_realm_dev_htable, dev_entry, next, node, (u64)dev) {
		if (dev_entry->dev == dev) {
			hash_del(&dev_entry->node);
			kfree(dev_entry);
			break;
		}
	}
	spin_unlock(&g_realm_dev_lock);
}
EXPORT_SYMBOL_GPL(rme_remove_dev_entry);

int realm_smmu_init_l2_strtab(struct arm_smmu_device *smmu, u32 sid)
{
	int ret;
	size_t size;
	struct arm_smmu_ste *l2ptr;
	struct realm_smmu_strtab_cfg *cfg = &smmu->realm.strtab_cfg;
	struct arm_smmu_strtab_l1_desc *desc = &cfg->l1_desc[sid >> STRTAB_SPLIT];

	if (desc->l2ptr)
		return 0;

	size = (1 << STRTAB_SPLIT) * sizeof(struct arm_smmu_ste);
	desc->span = STRTAB_SPLIT + 1;

	l2ptr = dma_alloc_coherent(smmu->dev, size, &desc->l2ptr_dma, GFP_KERNEL);
	if (!l2ptr)
		return -ENOMEM;

	ret = granule_delegate_range(desc->l2ptr_dma, size);
	if (ret) {
		dev_err(smmu->dev,
			"failed to delegate realm l2 stream table for SID %u\n",
			sid);
		goto out_free;
	}

	ret = realm_config_strtab_l2(SMMU_STRTAB_L2_INIT, smmu->realm.ioaddr,
				     cfg->strtab_dma, sid, desc->l2ptr_dma,
				     desc->span);
	if (ret) {
		dev_err(smmu->dev,
			"failed to init realm l2 stream table for SID %u\n",
			sid);
		goto out_undelegate;
	}
	desc->l2ptr = l2ptr;
	return 0;

out_undelegate:
	if (WARN_ON(granule_undelegate_range(desc->l2ptr_dma, size)))
		return ret;
out_free:
	dma_free_coherent(smmu->dev, size, l2ptr, desc->l2ptr_dma);
	return ret;
}
EXPORT_SYMBOL_GPL(realm_smmu_init_l2_strtab);

/**
 * get_child_devices_rec - Traverse pcie topology to find child devices
 * If dev is a bridge, get it's children
 * If dev is a regular device, get itself
 * @dev: Device for which to get child devices
 * @devs: All child devices under input dev
 * @max_devs: Max num of devs
 * @ndev: Num of child devices
 */
static int get_child_devices_rec(struct pci_dev *dev, uint16_t *devs,
				  int max_devs, int *ndev, struct pci_dev **pdevs)
{
	struct pci_bus *bus = dev->subordinate;

	if (bus) { /* dev is a bridge */
		struct pci_dev *child;
		int ret = 0;

		list_for_each_entry(child, &bus->devices, bus_list) {
			ret = get_child_devices_rec(child, devs, max_devs, ndev, pdevs);
			if (ret < 0)
				return ret;
		}
	} else { /* dev is a regular device */
		uint16_t bdf = pci_dev_id(dev);
		int i;
		/* check if bdf is already in devs */
		for (i = 0; i < *ndev; i++) {
			if (devs[i] == bdf)
				return *ndev;
		}
		/* check overflow */
		if (*ndev >= max_devs)
			return -EINVAL;

		devs[*ndev] = bdf;
		if (pdevs)
			pdevs[*ndev] = dev;
		*ndev = *ndev + 1;
	}

	return *ndev;
}

static bool is_hisi_acc_dev(struct pci_dev *pdev)
{
	switch (pdev->vendor) {
	case PCI_VENDOR_ID_HUAWEI:
		switch (pdev->device) {
		case PCI_DEVICE_ID_HUAWEI_ZIP_PF:
		case PCI_DEVICE_ID_HUAWEI_SEC_PF:
		case PCI_DEVICE_ID_HUAWEI_HPRE_PF:
		case PCI_DEVICE_ID_HUAWEI_ZIP_VF:
		case PCI_DEVICE_ID_HUAWEI_SEC_VF:
		case PCI_DEVICE_ID_HUAWEI_HPRE_VF:
			return true;
		default:
			return false;
		}
	default:
		return false;
	}
}

static int get_vf_devices(struct pci_dev *pf_dev, uint16_t *devs,
				    int max_devs, struct pci_dev **pdevs)
{
	struct pci_dev *vf_dev;
	unsigned short vf_device_id;
	int ndev = 0;

	/* Add PF device */
	devs[ndev] = pci_dev_id(pf_dev);
	if (pdevs)
		pdevs[ndev] = pf_dev;
	ndev++;

	/* Get VF device id */
	if (pf_dev->device == PCI_DEVICE_ID_HUAWEI_ZIP_PF)
		vf_device_id = PCI_DEVICE_ID_HUAWEI_ZIP_VF;
	else if (pf_dev->device == PCI_DEVICE_ID_HUAWEI_SEC_PF)
		vf_device_id = PCI_DEVICE_ID_HUAWEI_SEC_VF;
	else
		vf_device_id = PCI_DEVICE_ID_HUAWEI_HPRE_VF;

	/* Loop through all the VFs to find enabled VFs */
	vf_dev = pci_get_device(pf_dev->vendor, vf_device_id, NULL);
	while (vf_dev) {
		if (vf_dev->is_virtfn && (vf_dev->physfn == pf_dev)) {
			if (ndev >= max_devs)
				return -EINVAL;

			devs[ndev] = pci_dev_id(vf_dev);
			if (pdevs)
				pdevs[ndev] = vf_dev;
			ndev++;
		}
		vf_dev = pci_get_device(pf_dev->vendor, vf_device_id, vf_dev);
	}
	return ndev;
}

/**
 * rme_get_all_dev_info - Retrieve all devices under the root port
 * @rp_dev: root port device
 * @params: Assign device parameters
 *
 * Returns:
 * %0 if get all devices under the root port successful
 * %-EINVAL if the total number of devices under the root port exceeds the maximum
 */
static int rme_get_all_dev_info(struct pci_dev *rp_dev,
				struct rmi_dev_delegate_params *params,
				struct pci_dev **pdevs)
{
	int ret;

	params->root_bdf = pci_dev_id(rp_dev);
	if (is_hisi_acc_dev(rp_dev)) {
		/* Only search if we are a PF */
		if (!rp_dev->is_physfn) {
			pci_err(rp_dev, "Root dev is not a PF\n");
			return -EINVAL;
		}

		ret = get_vf_devices(rp_dev, params->devs, MAX_DEV_PER_PORT, pdevs);
	} else {
		int ndev = 0;

		params->devs[ndev] = pci_dev_id(rp_dev);
		ndev++;

		ret = get_child_devices_rec(rp_dev, params->devs,
					    MAX_DEV_PER_PORT, &ndev,
					    pdevs);
	}

	if (ret < 0) {
		pci_err(rp_dev, "Dev nums overflow\n");
		return -EINVAL;
	}
	params->num_dev = (uint16_t)ret;
	return 0;
}

static struct pci_dev *rme_get_root_dev(struct pci_dev *pdev)
{
	if (is_hisi_acc_dev(pdev))
		return pci_physfn(pdev);

	return pcie_find_root_port(pdev);
}

static inline bool is_root_dev_delegated(u16 root_bdf)
{
	struct dev_hash_entry *entry;

	hash_for_each_possible(g_root_dev_htable, entry, node, root_bdf) {
		if (entry->root_bdf == root_bdf && entry->delegated)
			return true;
	}

	return false;
}

bool is_dev_delegated(struct pci_dev *pdev)
{
	struct pci_dev *root_dev;
	unsigned long flags;
	bool is_delegated;

	root_dev = rme_get_root_dev(pdev);
	if (!root_dev)
		return false;

	spin_lock_irqsave(&g_dev_htable_lock, flags);
	is_delegated = is_root_dev_delegated(pci_dev_id(root_dev));
	spin_unlock_irqrestore(&g_dev_htable_lock, flags);

	return is_delegated;
}
EXPORT_SYMBOL_GPL(is_dev_delegated);

int cca_add_protected_virtfn(struct pci_dev *virtfn)
{
	unsigned long flags;
	u16 dev_bdf = pci_dev_id(virtfn);

	if (dev_bdf > PCI_BDF_MASK)
		return -EINVAL;

	spin_lock_irqsave(&g_dev_protected_lock, flags);
	bitmap_set(g_dev_protected, dev_bdf, 1);
	spin_unlock_irqrestore(&g_dev_protected_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(cca_add_protected_virtfn);

static inline struct dev_hash_entry *find_root_dev_entry(u16 root_bdf)
{
	struct dev_hash_entry *entry;

	hash_for_each_possible(g_root_dev_htable, entry, node, root_bdf) {
		if (entry->root_bdf == root_bdf)
			return entry;
	}

	return NULL;
}

static inline struct dev_hash_entry *add_root_dev_entry(u16 root_bdf)
{
	struct dev_hash_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return NULL;

	entry->root_bdf = root_bdf;
	entry->delegated = false;
	entry->assigned_cnt = 0;

	hash_add(g_root_dev_htable, &entry->node, root_bdf);

	return entry;
}

static int rme_root_dev_delegate(phys_addr_t params_addr)
{
	unsigned long out_dev_bdf = ~0;
	unsigned long last_dev_bdf = ~0;
	phys_addr_t dev_info_phys;
	void *dev_info;
	int ret;

retry:
	ret = rmi_root_dev_delegate(params_addr, &out_dev_bdf);
	if (ret == RMI_ERROR_DEV_INFO) {

		dev_info = (void *)get_zeroed_page(GFP_ATOMIC);
		if (!dev_info) {
			pr_err("Failed to allocate page for dev %#lx\n",
			       out_dev_bdf);
			return -ENOMEM;
		}

		dev_info_phys = virt_to_phys(dev_info);
		if (rmi_granule_delegate(dev_info_phys)) {
			free_page((unsigned long)dev_info);
			return -ENXIO;
		}
		ret = rmi_dev_init(out_dev_bdf, dev_info_phys);
		if (ret && ret != RMI_ERROR_DEV_EXISTS) {
			if (WARN_ON(rmi_granule_undelegate(dev_info_phys))) {
				/* leak the page */
				return -ENXIO;
			}
			free_page((unsigned long)dev_info);
			return -ENXIO;
		}
		last_dev_bdf = out_dev_bdf;
		goto retry;
	} else if (ret) {
		return -ENXIO;
	}

	return 0;
}

/* Unbind the drivers before switching to secure state.
 * In SR-IOV scenaios： Unbind all VFs' native drivers.
 * Otherwise: Unbind the PF's native drivers.
 */
static int _realm_unbind_drivers(struct pci_dev **pdevs, uint16_t nr)
{
	bool is_sriov = false;
	bool is_pcipc_ns_driver = false;

	for (uint16_t i = 0; i < nr; i++) {
		if (!pdevs[i] || pdevs[i] == pci_physfn(pdevs[i]))
			continue;
		is_sriov = true;
		/* Only unbind the VF with its own driver */
		if (!pdevs[i]->driver || !strcmp(pdevs[i]->driver->name, "vfio-pci"))
			continue;
		pci_info(pdevs[i], "rme unbind VF driver for device: %x\n", pci_dev_id(pdevs[i]));
		device_release_driver(&pdevs[i]->dev);
		cond_resched();
	}

	if (is_sriov)
		return 0;

	for (uint16_t i = 0; i < nr; i++) {
		if (!pdevs[i] || !pdevs[i]->driver)
			continue;
		if (is_hisi_pcipc_ns(&pdevs[i]->dev)) {
			is_pcipc_ns_driver = true;
			break;
		}
	}

	if (is_pcipc_ns_driver)
		return 0;

	for (uint16_t i = 0; i < nr; i++) {
		if (!pdevs[i] || !pdevs[i]->driver)
			continue;
		if (pdevs[i] == pci_physfn(pdevs[i]) &&
			strcmp(pdevs[i]->driver->name, "vfio-pci")) {
			pci_info(pdevs[i], "rme unbind PF driver for device: %x\n",
				     pci_dev_id(pdevs[i]));
			device_release_driver(&pdevs[i]->dev);
		}
	}
	return 0;
}

static int delegate_root_dev(struct pci_dev *root_dev)
{
	struct rmi_dev_delegate_params *params = NULL;
	int ret;

	params = (struct rmi_dev_delegate_params *)get_zeroed_page(GFP_ATOMIC);
	if (!params)
		return -ENOMEM;

	ret = rme_get_all_dev_info(root_dev, params, NULL);
	if (ret) {
		free_page((unsigned long)params);
		return ret;
	}

	spin_lock(&g_dev_protected_lock);
	for (int i = 0; i < params->num_dev; i++)
		bitmap_set(g_dev_protected, params->devs[i], 1);
	spin_unlock(&g_dev_protected_lock);

	ret = rme_root_dev_delegate(virt_to_phys(params));
	if (ret)
		pci_err(root_dev, "Failed to delegate\n");

	free_page((unsigned long)params);
	return ret;
}

/* Delegate root dev and devs under it to realm, undelegation is not supported */
static int dev_assign_to_realm(struct dev_hash_entry *entry, struct pci_dev *root_dev)
{
	int ret = 0;

	if (!entry->delegated && entry->assigned_cnt != 0) {
		pci_err(root_dev, "Dev is in normal vm use\n");
		return -EBUSY;
	}

	if (entry->delegated) {
		entry->assigned_cnt++;
		return 0;
	}

	ret = delegate_root_dev(root_dev);
	if (ret)
		return ret;

	entry->delegated = true;
	entry->assigned_cnt++;
	return 0;
}

static int dev_assign_to_ns(struct dev_hash_entry *entry, struct pci_dev *root_dev)
{
	if (entry->delegated) {
		pci_err(root_dev, "Dev is delegated to realm\n");
		return -EINVAL;
	}

	entry->assigned_cnt++;
	return 0;
}

static int rme_dev_assign(struct pci_dev *root_dev, struct kvm *kvm)
{
	struct dev_hash_entry *entry;
	int ret;

	spin_lock(&g_dev_htable_lock);
	entry = find_root_dev_entry(pci_dev_id(root_dev));
	if (!entry) {
		entry = add_root_dev_entry(pci_dev_id(root_dev));
		if (!entry) {
			spin_unlock(&g_dev_htable_lock);
			return -ENOMEM;
		}
	}

	ret = kvm_is_realm(kvm) ? dev_assign_to_realm(entry, root_dev) :
				  dev_assign_to_ns(entry, root_dev);
	spin_unlock(&g_dev_htable_lock);
	return ret;
}

static void rme_dev_unassign(struct pci_dev *pdev)
{
	struct dev_hash_entry *entry;
	struct pci_dev *root_dev;

	root_dev = rme_get_root_dev(pdev);
	if (!root_dev)
		return;

	spin_lock(&g_dev_htable_lock);
	entry = find_root_dev_entry(pci_dev_id(root_dev));
	if (!entry) {
		spin_unlock(&g_dev_htable_lock);
		return;
	}

	if (entry->assigned_cnt != 0)
		entry->assigned_cnt--;

	if (!entry->delegated && entry->assigned_cnt == 0) {
		hash_del(&entry->node);
		kfree(entry);
	}

	spin_unlock(&g_dev_htable_lock);
}

static int realm_add_dev_to_list(struct pci_dev *pdev, struct kvm *kvm)
{
	struct rdev_node *realm_dev;

	/* Add the dev to list first. Once the RD is created, do rmi_dev_attach */
	realm_dev = kzalloc(sizeof(*realm_dev), GFP_KERNEL);
	if (!realm_dev)
		return -ENOMEM;

	realm_dev->dev_bdf = pci_dev_id(pdev);
	realm_dev->dev = &pdev->dev;
	list_add_tail(&realm_dev->list, &kvm->arch.realm.rdev_list);

	return 0;
}

static void realm_del_dev_from_list(struct pci_dev *pdev, struct kvm *kvm)
{
	struct rdev_node *pos, *n;
	struct realm *realm;

	if (!kvm_is_realm(kvm))
		return;

	realm = &kvm->arch.realm;
	list_for_each_entry_safe(pos, n, &realm->rdev_list, list) {
		if (pos->dev == &pdev->dev) {
			list_del(&pos->list);
			kfree(pos);
			break;
		}
	}
}

static int rme_dev_delegate(struct pci_dev *pdev, struct pci_dev *root_dev)
{
	phys_addr_t dev_info_phys;
	void *dev_info;
	int ret;

	ret = rmi_dev_delegate(pci_dev_id(pdev), pci_dev_id(root_dev));
	/* Handle the case that the device is created after the root port is delegated */
	if (ret == RMI_ERROR_DEV_INFO) {
		dev_info = (void *)get_zeroed_page(GFP_ATOMIC);
		if (!dev_info) {
			pci_err(pdev, "Failed to allocate page for dev\n");
			return -ENOMEM;
		}

		dev_info_phys = virt_to_phys(dev_info);
		if (rmi_granule_delegate(dev_info_phys)) {
			free_page((unsigned long)dev_info);
			return -ENXIO;
		}

		ret = rmi_dev_init(pci_dev_id(pdev), dev_info_phys);
		if (ret && ret != RMI_ERROR_DEV_EXISTS) {
			if (WARN_ON(rmi_granule_undelegate(dev_info_phys))) {
				/* leak the page */
				return -ENXIO;
			}
			free_page((unsigned long)dev_info);
			return -ENXIO;
		}

		ret = rmi_dev_delegate(pci_dev_id(pdev), pci_dev_id(root_dev));
		if (ret)
			return -ENXIO;
	} else if (ret) {
		return -ENXIO;
	}

	return 0;
}

static int realm_unbind_drivers(struct pci_dev *root_dev)
{
	struct rmi_dev_delegate_params *params = NULL;
	struct pci_dev **pdevs;
	int ret;

	params = (struct rmi_dev_delegate_params *)get_zeroed_page(GFP_ATOMIC);
	if (!params)
		return -ENOMEM;

	pdevs = kcalloc(MAX_DEV_PER_PORT, sizeof(struct pci_dev *), GFP_KERNEL);
	if (!pdevs) {
		free_page((unsigned long)params);
		return -ENOMEM;
	}

	ret = rme_get_all_dev_info(root_dev, params, pdevs);
	if (ret)
		goto out;

	ret = _realm_unbind_drivers(pdevs, params->num_dev);

out:
	kfree(pdevs);
	free_page((unsigned long)params);
	return ret;
}

int kvm_rme_assign_device(struct pci_dev *pdev, struct kvm *kvm)
{
	struct pci_dev *root_dev;
	int ret;

	if (!is_support_rme() || !pdev || !kvm)
		return -EINVAL;

	root_dev = rme_get_root_dev(pdev);
	if (!root_dev) {
		/* Integrated PCIe device such as PCIe PMU is not supported to assigned to realm */
		if (kvm_is_realm(kvm))
			return -EINVAL;
		else
			return 0;
	}

	if (kvm_is_realm(kvm)) {
		ret = realm_unbind_drivers(root_dev);
		if (ret) {
			pci_err(pdev, "Failed to unbind drivers\n");
			return ret;
		}
	}

	ret = rme_dev_assign(root_dev, kvm);
	if (ret) {
		pci_err(pdev, "Failed to assign dev\n");
		return ret;
	}

	if (!kvm_is_realm(kvm))
		return 0;

	ret = realm_add_dev_to_list(pdev, kvm);
	if (ret) {
		pci_err(pdev, "Failed to add dev list\n");
		rme_dev_unassign(pdev);
		return ret;
	}

	ret = rme_dev_delegate(pdev, root_dev);
	if (ret) {
		pci_err(pdev, "Failed to delegate dev\n");
		realm_del_dev_from_list(pdev, kvm);
		rme_dev_unassign(pdev);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(kvm_rme_assign_device);

void kvm_rme_unassign_device(struct pci_dev *pdev, struct kvm *kvm)
{
	if (!pdev || !kvm || !is_support_rme())
		return;

	/* Rme dev undelegate will be processed in _kvm_destroy_realm */
	if (kvm_is_realm(kvm))
		rmi_dev_detach(pci_dev_id(pdev));

	rme_dev_unassign(pdev);
}
EXPORT_SYMBOL_GPL(kvm_rme_unassign_device);

void realm_destroy_dev_list(struct realm *realm)
{
	struct rdev_node *pos, *n;

	list_for_each_entry_safe(pos, n, &realm->rdev_list, list) {
		WARN_ON(rmi_dev_undelegate(pos->dev_bdf));
		list_del(&pos->list);
		kfree(pos);
	}
}

/* After RD created, call this to do attach dev */
int realm_attach_devs(struct realm *realm)
{
	struct rdev_node *dev;
	phys_addr_t rd;
	int ret;

	if (!realm || !realm->rd)
		return -EINVAL;

	rd = virt_to_phys(realm->rd);

	list_for_each_entry(dev, &realm->rdev_list, list) {
		struct iommu_domain *domain;
		struct arm_smmu_domain *smmu_domain;
		struct arm_smmu_s2_cfg *s2_cfg;
		struct arm_smmu_device *smmu;
		bool lvl_strtab;
		u64 smmu_addr;

		domain = iommu_get_domain_for_dev(dev->dev);
		smmu_domain = to_smmu_domain(domain);

		if (!smmu_domain) {
			ret = -EINVAL;
			goto err_detach;
		}

		smmu = smmu_domain->smmu;
		smmu_addr = smmu->realm.ioaddr;

		ret = realm_smmu_init_l2_strtab(smmu, dev->dev_bdf);
		if (ret)
			goto err_detach;

		s2_cfg = &smmu_domain->s2_cfg;
		lvl_strtab = !!(smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB);
		ret = rmi_dev_attach(dev->dev_bdf, rd, smmu_addr, s2_cfg->vmid,
				     lvl_strtab);
		if (ret)
			goto err_detach;
	}

	return 0;

err_detach:
	realm_destroy_dev_list(realm);

	return ret;
}

void kvm_complete_dev_op(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	struct realm_rec *rec = vcpu->arch.rec;

	rec->run->enter.dev_bdf = run->rme_dev.dev_bdf;
	rec->run->enter.vfio_dev = run->rme_dev.vfio_dev;
}

#define MMIO_REG_8_BIT 8
#define MMIO_REG_16_BIT 16
#define MMIO_REG_32_BIT 32
#define MMIO_REG_64_BIT 64

static u8 rme_mmio_read8(unsigned long addr, struct pci_dev *pdev)
{
	unsigned long value;
	int ret;

	ret = rmi_dev_mmio_read(addr, MMIO_REG_8_BIT, &value, pci_dev_id(pdev));
	if (ret) {
		pr_err("rmi_dev_mmio_read error, ret = %d\n", ret);
		return 0;
	}

	return value;
}

static u16 rme_mmio_read16(unsigned long addr, struct pci_dev *pdev)
{
	unsigned long value;
	int ret;

	ret = rmi_dev_mmio_read(addr, MMIO_REG_16_BIT, &value, pci_dev_id(pdev));
	if (ret) {
		pr_err("rmi_dev_mmio_read error, ret = %d\n", ret);
		return 0;
	}

	return value;
}

static u32 rme_mmio_read32(unsigned long addr, struct pci_dev *pdev)
{
	unsigned long value;
	int ret;

	ret = rmi_dev_mmio_read(addr, MMIO_REG_32_BIT, &value, pci_dev_id(pdev));
	if (ret) {
		pr_err("rmi_dev_mmio_read error, ret = %d\n", ret);
		return 0;
	}

	return value;
}

static void rme_mmio_write32(unsigned long addr, unsigned long value,
			     struct pci_dev *pdev)
{
	int ret;

	ret = rmi_dev_mmio_write(addr, MMIO_REG_32_BIT, value, pci_dev_id(pdev));
	if (ret)
		pr_err("rmi_dev_mmio_write error, ret = %d\n", ret);
}

static u64 rme_mmio_read64(unsigned long addr, struct pci_dev *pdev)
{
	unsigned long value;
	int ret;

	ret = rmi_dev_mmio_read(addr, MMIO_REG_64_BIT, &value, pci_dev_id(pdev));
	if (ret) {
		pr_err("rmi_dev_mmio_read error, ret = %d\n", ret);
		return 0;
	}

	return value;
}

static int rme_mmio_write64(unsigned long addr, unsigned long value,
			     struct pci_dev *pdev)
{
	int ret;

	ret = rmi_dev_mmio_write(addr, MMIO_REG_64_BIT, value, pci_dev_id(pdev));
	if (ret)
		pr_err("rmi_dev_mmio_write error, ret = %d\n", ret);
	return ret;
}

static inline u64 get_pci_desc_pbase(struct pci_dev *dev, u16 msi_index)
{
	u64 table_pbase, desc_pbase;
	u32 table_offset;
	u8 bir;

	/* Get the MSI-X table physical address */
	pci_read_config_dword(dev, dev->msix_cap + PCI_MSIX_TABLE, &table_offset);
	bir = (u8)(table_offset & PCI_MSIX_TABLE_BIR);
	table_offset &= PCI_MSIX_TABLE_OFFSET;
	table_pbase = pci_resource_start(dev, bir) + table_offset;

	/* Get the MSI-X entry physical address */
	desc_pbase = table_pbase + msi_index * PCI_MSIX_ENTRY_SIZE;

	return desc_pbase;
}

bool rme_dev_pci_read_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	struct pci_dev *dev = msi_desc_to_pci_dev(desc);
	u64 pbase;

	if (!is_support_rme() || !is_dev_delegated(dev))
		return false;

	pbase = get_pci_desc_pbase(dev, desc->msi_index);

	msg->address_lo = rme_mmio_read32(pbase + PCI_MSIX_ENTRY_LOWER_ADDR, dev);
	msg->address_hi = rme_mmio_read32(pbase + PCI_MSIX_ENTRY_UPPER_ADDR, dev);
	msg->data = rme_mmio_read32(pbase + PCI_MSIX_ENTRY_DATA, dev);

	return true;
}
EXPORT_SYMBOL_GPL(rme_dev_pci_read_msi_msg);

static u64 rme_get_msi_addr(struct msi_desc *desc, struct msi_msg *msg)
{
	struct pci_dev *dev = msi_desc_to_pci_dev(desc);
	u64 addr = (u64)msg->address_lo | ((u64)msg->address_hi << 32);
	u64 iova_rel;
	u64 msi_page_index;
	u64 page_offset;

	if (!addr)
		return addr;

	iova_rel = addr - REALM_MSI_ORIG_IOVA;
	msi_page_index = iova_rel / MSI_PAGE_SIZE;
	page_offset = iova_rel % MSI_PAGE_SIZE;

	return rme_get_msi_iova(&dev->dev, msi_page_index) + page_offset;
}

bool rme_dev_pci_write_msg_msi(struct msi_desc *desc, struct msi_msg *msg)
{
	struct pci_dev *dev = msi_desc_to_pci_dev(desc);
	u64 pbase, msi_addr;
	bool unmasked;
	u32 ctrl;

	if (!is_support_rme() || !is_dev_delegated(dev))
		return false;

	msi_addr = rme_get_msi_addr(desc, msg);

	pbase = get_pci_desc_pbase(dev, desc->msi_index);

	ctrl = desc->pci.msix_ctrl;
	unmasked = !(ctrl & PCI_MSIX_ENTRY_CTRL_MASKBIT);

	rme_mmio_write32(pbase + PCI_MSIX_ENTRY_LOWER_ADDR, lower_32_bits(msi_addr), dev);
	rme_mmio_write32(pbase + PCI_MSIX_ENTRY_UPPER_ADDR, upper_32_bits(msi_addr), dev);
	rme_mmio_write32(pbase + PCI_MSIX_ENTRY_DATA, msg->data, dev);

	if (unmasked && desc->pci.msi_attrib.can_mask)
		rme_mmio_write32(pbase + PCI_MSIX_ENTRY_VECTOR_CTRL, ctrl, dev);

	/* Ensure that the writes are visible in the device */
	rme_mmio_read32(pbase + PCI_MSIX_ENTRY_DATA, dev);

	return true;
}
EXPORT_SYMBOL_GPL(rme_dev_pci_write_msg_msi);

void rme_dev_fix_msi_address(struct msi_desc *desc, struct msi_msg *msg)
{
	struct pci_dev *dev = msi_desc_to_pci_dev(desc);
	u64 msi_addr;

	if (!is_support_rme() || !is_dev_delegated(dev))
		return;

	msi_addr = rme_get_msi_addr(desc, msg);
	msg->address_lo = lower_32_bits(msi_addr);
	msg->address_hi = upper_32_bits(msi_addr);
}
EXPORT_SYMBOL_GPL(rme_dev_fix_msi_address);

bool rme_dev_msix_prepare_msi_desc(struct pci_dev *dev, struct msi_desc *desc)
{
	u64 pbase;

	if (!is_support_rme() || !is_dev_delegated(dev))
		return false;

	pbase = get_pci_desc_pbase(dev, desc->msi_index);

	desc->pci.msix_ctrl = rme_mmio_read32(pbase + PCI_MSIX_ENTRY_VECTOR_CTRL, dev);

	return true;
}
EXPORT_SYMBOL_GPL(rme_dev_msix_prepare_msi_desc);

bool rme_dev_pci_msix_write_vector_ctrl(struct msi_desc *desc, u32 ctrl)
{
	struct pci_dev *dev = msi_desc_to_pci_dev(desc);
	u64 pbase;

	if (!is_support_rme() || !is_dev_delegated(dev))
		return false;

	pbase = get_pci_desc_pbase(dev, desc->msi_index);

	if (desc->pci.msi_attrib.can_mask)
		rme_mmio_write32(pbase + PCI_MSIX_ENTRY_VECTOR_CTRL, ctrl, dev);

	return true;
}
EXPORT_SYMBOL_GPL(rme_dev_pci_msix_write_vector_ctrl);

bool rme_dev_pci_msix_mask(struct msi_desc *desc)
{
	struct pci_dev *dev = msi_desc_to_pci_dev(desc);
	u64 pbase;

	if (!is_support_rme() || !is_dev_delegated(dev))
		return false;

	pbase = get_pci_desc_pbase(dev, desc->msi_index);

	/* Flush write to device */
	rme_mmio_read32(pbase, dev);

	return true;
}
EXPORT_SYMBOL_GPL(rme_dev_pci_msix_mask);

bool rme_dev_msix_mask_all(struct pci_dev *dev, int tsize)
{
	u64 pbase;
	u32 ctrl = PCI_MSIX_ENTRY_CTRL_MASKBIT;
	u16 rw_ctrl;
	int i;

	if (!is_support_rme() || !is_dev_delegated(dev))
		return false;

	pbase = get_pci_desc_pbase(dev, 0);

	if (pci_msi_ignore_mask)
		goto out;

	for (i = 0; i < tsize; i++, pbase += PCI_MSIX_ENTRY_SIZE)
		rme_mmio_write32(pbase + PCI_MSIX_ENTRY_VECTOR_CTRL, ctrl, dev);

out:
	pci_read_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, &rw_ctrl);
	rw_ctrl &= ~PCI_MSIX_FLAGS_MASKALL;
	rw_ctrl |= 0;
	pci_write_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, rw_ctrl);

	pcibios_free_irq(dev);
	return true;
}
EXPORT_SYMBOL_GPL(rme_dev_msix_mask_all);

/**
 * rme_mmio_va_to_pa - To convert the virtual address of the mmio space
 * to a physical address, it is necessary to implement this interface
 * because the kernel insterface __pa has an error when converting the
 * physical address of the virtual address of the mmio space
 * @addr:	MMIO virtual address
 */
static u64 rme_mmio_va_to_pa(const void *addr)
{
	uint64_t pa, par_el1;

	asm volatile(
		"AT S1E1W, %0\n"
		::"r"((uint64_t)(addr))
	);
	isb();
	asm volatile(
		"mrs %0, par_el1\n"
		: "=r"(par_el1)
	);

	pa = ((uint64_t)(addr) & (PAGE_SIZE - 1)) |
		(par_el1 & ULL(0x000ffffffffff000));

	if (par_el1 & UL(1 << 0))
		return (uint64_t)(addr);
	else
		return pa;
}

u32 rme_readl_hook(void __iomem *addr, struct pci_dev *pdev)
{
	if (is_support_rme() && is_dev_delegated(pdev))
		return rme_mmio_read32(rme_mmio_va_to_pa(addr), pdev);

	return readl(addr);
}
EXPORT_SYMBOL_GPL(rme_readl_hook);

int rme_writeq_hook(u64 val, void __iomem *addr, struct pci_dev *pdev)
{
	if (is_support_rme() && is_dev_delegated(pdev))
		return rme_mmio_write64(rme_mmio_va_to_pa(addr), val, pdev);

	writeq(val, addr);
	return 0;
}
EXPORT_SYMBOL_GPL(rme_writeq_hook);

u32 rme_read32be_hook(void __iomem *addr, struct pci_dev *pdev)
{
	if (is_support_rme() && is_dev_delegated(pdev)) {
		u32 t = rme_mmio_read32(rme_mmio_va_to_pa(addr), pdev);

		return cpu_to_be32(t);
	}

	return ioread32be(addr);
}
EXPORT_SYMBOL_GPL(rme_read32be_hook);

u16 rme_read16be_hook(void __iomem *addr, struct pci_dev *pdev)
{
	if (is_support_rme() && is_dev_delegated(pdev)) {
		u16 t = rme_mmio_read16(rme_mmio_va_to_pa(addr), pdev);

		return cpu_to_be16(t);
	}

	return ioread16be(addr);
}
EXPORT_SYMBOL_GPL(rme_read16be_hook);

u8 rme_read8_hook(void __iomem *addr, struct pci_dev *pdev)
{
	if (is_support_rme() && is_dev_delegated(pdev))
		return rme_mmio_read8(rme_mmio_va_to_pa(addr), pdev);

	return ioread8(addr);
}
EXPORT_SYMBOL_GPL(rme_read8_hook);

void rme_writel_hook(u32 val, void __iomem *addr, struct pci_dev *pdev)
{
	if (is_support_rme() && is_dev_delegated(pdev))
		return rme_mmio_write32(rme_mmio_va_to_pa(addr),
			   (u32 __force)__cpu_to_le32(val), pdev);

	writel(val, addr);
}
EXPORT_SYMBOL_GPL(rme_writel_hook);

void __rme_raw_writel_hook(u32 val, void __iomem *addr, struct pci_dev *pdev)
{
	if (is_support_rme() && is_dev_delegated(pdev)) {
		rme_mmio_write32(rme_mmio_va_to_pa(addr), val, pdev);
		return;
	}
	__raw_writel(val, addr);
}
EXPORT_SYMBOL_GPL(__rme_raw_writel_hook);

void rme_write32be_hook(u32 val, void __iomem *addr, struct pci_dev *pdev)
{
	if (is_support_rme() && is_dev_delegated(pdev))
		return rme_mmio_write32(rme_mmio_va_to_pa(addr), cpu_to_be32(val), pdev);

	iowrite32be(val, addr);
}
EXPORT_SYMBOL_GPL(rme_write32be_hook);

void rme_lo_hi_writeq_hook(__u64 val, void __iomem *addr, struct pci_dev *pdev)
{
	if (is_support_rme() && is_dev_delegated(pdev)) {
		rme_mmio_write32(rme_mmio_va_to_pa(addr), (u32)val, pdev);
		rme_mmio_write32(rme_mmio_va_to_pa(addr + 4), (u32)(val >> 32), pdev);
		return;
	}
	lo_hi_writeq(val, addr);
}
EXPORT_SYMBOL_GPL(rme_lo_hi_writeq_hook);

void rme_hi_lo_writeq_hook(__u64 val, void __iomem *addr, struct pci_dev *pdev)
{
	if (is_support_rme() && is_dev_delegated(pdev)) {
		rme_mmio_write32(rme_mmio_va_to_pa(addr + 4), (u32)(val >> 32), pdev);
		rme_mmio_write32(rme_mmio_va_to_pa(addr), (u32)val, pdev);
		return;
	}
	hi_lo_writeq(val, addr);
}
EXPORT_SYMBOL_GPL(rme_hi_lo_writeq_hook);

u64 rme_lo_hi_readq_hook(void __iomem *addr, struct pci_dev *pdev)
{
	if (is_support_rme() && is_dev_delegated(pdev))
		return rme_mmio_read64(rme_mmio_va_to_pa(addr), pdev);

	return lo_hi_readq(addr);
}
EXPORT_SYMBOL_GPL(rme_lo_hi_readq_hook);

int __rme_iowrite64_copy_hook(void __iomem *to, const void *from,
	size_t count, struct pci_dev *pdev)
{
	int ret = 0;

	if (is_support_rme() && is_dev_delegated(pdev)) {
		u64 __iomem *dst = to;
		const u64 *src = from;
		const u64 *end = src + count;

		while (src < end) {
			ret = rme_mmio_write64(rme_mmio_va_to_pa(dst++), *src++, pdev);
			if (ret)
				break;
		}
		return ret;
	}
	__iowrite64_copy(to, from, count);
	return ret;
}
EXPORT_SYMBOL_GPL(__rme_iowrite64_copy_hook);

bool is_realm_device(struct device *dev, struct device_driver *drv)
{
	if (dev_is_pci(dev) && is_support_rme() &&
		is_dev_delegated(to_pci_dev(dev)) &&
		strcmp(drv->name, "vfio-pci"))
		return true;

	return false;
}
EXPORT_SYMBOL_GPL(is_realm_device);

bool is_dev_ecam_protected(u16 dev_bdf)
{
	unsigned long flags;
	bool is_dev_ecam_protected = false;

	spin_lock_irqsave(&g_dev_protected_lock, flags);
	is_dev_ecam_protected = bitmap_read(g_dev_protected, dev_bdf, 1);
	spin_unlock_irqrestore(&g_dev_protected_lock, flags);

	return is_dev_ecam_protected;
}

/* If device is realm dev, read config need transfer to rmm */
int ccada_pci_generic_config_read(void __iomem *addr, unsigned char bus_num,
				   unsigned int devfn, u32 size, u32 *val)
{
	int ret;
	u16 dev_bdf = PCI_DEVID(bus_num, devfn);
	u64 bits = MMIO_RW_32BITS;
	unsigned long ret_val;

	if (MMIO_RW_8BITS * size <= MMIO_RW_16BITS)
		bits = MMIO_RW_8BITS * size;

	ret = rmi_dev_mmio_read(rme_mmio_va_to_pa(addr), bits, &ret_val, dev_bdf);
	if (ret)
		return ret;
	*val = (u32)ret_val;
	return ret;
}

/* If device is realm dev, write config need transfer to rmm */
int ccada_pci_generic_config_write(void __iomem *addr, unsigned char bus_num,
				    unsigned int devfn, u32 size, u32 val)
{
	u16 dev_bdf = PCI_DEVID(bus_num, devfn);
	u64 bits = MMIO_RW_32BITS;

	if (MMIO_RW_8BITS * size <= MMIO_RW_16BITS)
		bits = MMIO_RW_8BITS * size;

	return rmi_dev_mmio_write(rme_mmio_va_to_pa(addr), bits, val, dev_bdf);
}
