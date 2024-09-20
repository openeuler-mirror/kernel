// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */
#include <linux/kvm_host.h>
#include <linux/iommu.h>
#include <asm/virtcca_coda.h>

struct cc_dev_config {
	u32               sid; /* BDF number of the device */
	u32               vmid; /* virtual machine id */
	u32               root_bd; /* root bus and device number. */
	bool              secure; /* device secure attribute */
	/* MSI addr for confidential device with iommu group granularity */
	u64               msi_addr;
	struct hlist_node node; /* device hash table */
};

static DEFINE_HASHTABLE(g_cc_dev_htable, MAX_CC_DEV_NUM_ORDER);

/**
 * get_root_bd - Traverse pcie topology to find the root <bus,device> number
 * @dev: The device for which to get root bd
 *
 * Returns:
 * %-1 if error or not pci device
 */
static int get_root_bd(struct device *dev)
{
	struct pci_dev *pdev;

	if (!dev_is_pci(dev))
		return -1;
	pdev = to_pci_dev(dev);
	if (pdev->bus == NULL)
		return -1;

	while (!pci_is_root_bus(pdev->bus))
		pdev = pci_upstream_bridge(pdev);

	return pci_dev_id(pdev) & MASK_DEV_FUNCTION;
}

/**
 * get_child_devices_rec - Traverse pcie topology to find child devices
 * If dev is a bridge, get it's children
 * If dev is a regular device, get itself
 * @dev: Device for which to get child devices
 * @devs: All child devices under input dev
 * @max_devs: Max num of devs
 * @ndev: Num of child devices
 */
static void get_child_devices_rec(struct pci_dev *dev, uint16_t *devs,
	int max_devs, int *ndev)
{
	struct pci_bus *bus = dev->subordinate;

	if (bus) { /* dev is a bridge */
		struct pci_dev *child;

		list_for_each_entry(child, &bus->devices, bus_list) {
			get_child_devices_rec(child, devs, max_devs, ndev);
		}
	} else { /* dev is a regular device */
		uint16_t bdf = pci_dev_id(dev);
		int i;
		/* check if bdf is already in devs */
		for (i = 0; i < *ndev; i++) {
			if (devs[i] == bdf)
				return;
		}
		/* check overflow */
		if (*ndev >= max_devs) {
			pr_warn("S_SMMU: devices num over max devs\n");
			return;
		}
		devs[*ndev] = bdf;
		*ndev = *ndev + 1;
	}
}

/**
 * get_sibling_devices - Get all devices which share the same root_bd as dev
 * @dev: Device for which to get child devices
 * @devs: All child devices under input dev
 * @max_devs: Max num of devs
 *
 * Returns:
 * %0 if get child devices failure
 */
static int get_sibling_devices(struct device *dev, uint16_t *devs, int max_devs)
{
	struct pci_dev *pdev;
	int ndev = 0;

	if (!dev_is_pci(dev))
		return ndev;

	pdev = to_pci_dev(dev);
	if (pdev->bus == NULL)
		return ndev;

	while (!pci_is_root_bus(pdev->bus))
		pdev = pci_upstream_bridge(pdev);

	get_child_devices_rec(pdev, devs, max_devs, &ndev);
	return ndev;
}

/**
 * add_cc_dev_obj - Add device obj to hash tablse
 * @sid: Stream id of device
 * @vmid: Virtual machine id
 * @root_bd: Root port bus device num
 * @secure: Whether the device is secure or not
 *
 * Returns:
 * %0 if add obj success
 * %-ENOMEM if alloc obj failed
 */
static int add_cc_dev_obj(u32 sid, u32 vmid, u32 root_bd, bool secure)
{
	struct cc_dev_config *obj;

	hash_for_each_possible(g_cc_dev_htable, obj, node, sid) {
		if (obj->sid == sid) {
			obj->vmid = vmid;
			obj->root_bd = root_bd;
			obj->secure = secure;
			return 0;
		}
	}

	obj = kzalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		return -ENOMEM;

	obj->sid = sid;
	obj->vmid = vmid;
	obj->root_bd = root_bd;
	obj->secure = secure;

	hash_add(g_cc_dev_htable, &obj->node, sid);
	return 0;
}

/**
 * is_cc_root_bd - Whether the root port is secure or not
 * @root_bd: Root port bus device num
 *
 * Returns:
 * %true if the root bd is secure
 * %false if the root bd is non-secure
 */
static bool is_cc_root_bd(u32 root_bd)
{
	int bkt;
	struct cc_dev_config *obj;

	hash_for_each(g_cc_dev_htable, bkt, obj, node) {
		if (obj->root_bd == root_bd && obj->secure)
			return true;
	}

	return false;
}

/**
 * is_cc_vmid - Whether the vm is confidential vm
 * @vmid: Virtual machine id
 *
 * Returns:
 * %true if the vm is confidential
 * %false if the vm is not confidential
 */
bool is_cc_vmid(u32 vmid)
{
	int bkt;
	struct cc_dev_config *obj;

	hash_for_each(g_cc_dev_htable, bkt, obj, node) {
		if (vmid > 0 && obj->vmid == vmid)
			return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(is_cc_vmid);

/**
 * is_cc_dev - Whether the stream id of dev is confidential
 * @sid: Stream id of dev
 *
 * Returns:
 * %true if the dev is confidential
 * %false if the dev is not confidential
 */
bool is_cc_dev(u32 sid)
{
	struct cc_dev_config *obj;

	hash_for_each_possible(g_cc_dev_htable, obj, node, sid) {
		if (obj != NULL && obj->sid == sid)
			return obj->secure;
	}

	return false;
}
EXPORT_SYMBOL(is_cc_dev);

/**
 * get_g_cc_dev_msi_addr - Obtain the msi address of confidential device
 * @sid: Stream id of dev
 *
 * Returns:
 * %0 if does not find the confidential device that matches the stream id
 * %msi_addr return the msi address of confidential device that matches the stream id
 */
u64 get_g_cc_dev_msi_addr(u32 sid)
{
	struct cc_dev_config *obj;

	hash_for_each_possible(g_cc_dev_htable, obj, node, sid) {
		if (obj != NULL && obj->sid == sid)
			return obj->msi_addr;
	}
	return 0;
}

/**
 * set_g_cc_dev_msi_addr - Set the msi address of confidential device
 * @sid: Stream id of dev
 * @msi_addr: Msi address
 */
void set_g_cc_dev_msi_addr(u32 sid, u64 msi_addr)
{
	struct cc_dev_config *obj;

	hash_for_each_possible(g_cc_dev_htable, obj, node, sid) {
		if (obj != NULL && obj->sid == sid && !obj->msi_addr) {
			obj->msi_addr = msi_addr;
			return;
		}
	}
}

/* Secure device hash table init */
void g_cc_dev_table_init(void)
{
	hash_init(g_cc_dev_htable);
}
EXPORT_SYMBOL(g_cc_dev_table_init);

/**
 * virtcca_tmi_dev_attach - Complete the stage2 page table establishment
 * for the security device
 * @arm_smmu_domain: The handle of smmu domain
 * @kvm: The handle of virtual machine
 *
 * Returns:
 * %0 if attach dev success
 * %-ENXIO if the root port of device does not have pcipc capability
 */
u32 virtcca_tmi_dev_attach(struct arm_smmu_domain *arm_smmu_domain, struct kvm *kvm)
{
	unsigned long flags;
	int i, j;
	struct arm_smmu_master *master;
	int ret = 0;
	u64 cmd[CMDQ_ENT_DWORDS] = {0};
	struct virtcca_cvm *virtcca_cvm = kvm->arch.virtcca_cvm;

	spin_lock_irqsave(&arm_smmu_domain->devices_lock, flags);
	/*
	 * Traverse all devices under the secure smmu domain and
	 * set the correspnding address translation table for each device
	 */
	list_for_each_entry(master, &arm_smmu_domain->devices, domain_head) {
		if (master && master->num_streams >= 0) {
			for (i = 0; i < master->num_streams; i++) {
				u32 sid = master->streams[i].id;

				for (j = 0; j < i; j++)
					if (master->streams[j].id == sid)
						break;
				if (j < i)
					continue;
				ret = tmi_dev_attach(sid, virtcca_cvm->rd,
					arm_smmu_domain->smmu->s_smmu_id);
				if (ret) {
					dev_err(arm_smmu_domain->smmu->dev, "CoDA: dev protected failed!\n");
					ret = -ENXIO;
					goto out;
				}
				/* Need to config ste */
				cmd[0] |= FIELD_PREP(CMDQ_0_OP, CMDQ_OP_CFGI_STE);
				cmd[0] |= FIELD_PREP(CMDQ_CFGI_0_SID, sid);
				cmd[1] |= FIELD_PREP(CMDQ_CFGI_1_LEAF, true);
				tmi_smmu_queue_write(cmd[0], cmd[1],
					arm_smmu_domain->smmu->s_smmu_id);
			}
		}
	}

out:
	spin_unlock_irqrestore(&arm_smmu_domain->devices_lock, flags);
	return ret;
}

/**
 * virtcca_secure_dev_ste_create - Setting up the STE config content
 * for the security device
 * @smmu: An SMMUv3 instance
 * @master: SMMU private data for each master
 * @sid: Stream id of device
 *
 * Returns:
 * %0 if create ste success
 * %-ENOMEM alloc ste params failed
 * %-EINVAL set ste config content failed
 */
static int virtcca_secure_dev_ste_create(struct arm_smmu_device *smmu,
	struct arm_smmu_master *master, u32 sid)
{
	struct tmi_smmu_ste_params *params_ptr;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	struct arm_smmu_strtab_l1_desc *desc = &cfg->l1_desc[sid >> STRTAB_SPLIT];

	params_ptr = kzalloc(sizeof(*params_ptr), GFP_KERNEL);
	if (!params_ptr)
		return -ENOMEM;

	/* Sync Level 2 STE to TMM */
	params_ptr->ns_src = desc->l2ptr_dma + ((sid & ((1 << STRTAB_SPLIT) - 1)) * STE_ENTRY_SIZE);
	params_ptr->sid = sid;
	params_ptr->smmu_id = smmu->s_smmu_id;

	if (tmi_smmu_ste_create(__pa(params_ptr)) != 0) {
		kfree(params_ptr);
		dev_err(smmu->dev, "CoDA: failed to create ste level 2\n");
		return -EINVAL;
	}

	kfree(params_ptr);

	return 0;
}

/**
 * virtcca_delegate_secure_dev - Delegate device to secure state
 * @smmu: An SMMUv3 instance
 * @root_bd: The port where the secure device is located
 * @dev: Secure device
 *
 * Returns:
 * %0 if delegate success
 * %-ENOMEM if alloc params failed
 * %-EINVAL if the dev is invalid
 */
static inline int virtcca_delegate_secure_dev(uint16_t root_bd, struct arm_smmu_device *smmu,
	struct device *dev)
{
	int i;
	u64 ret = 0;
	struct tmi_dev_delegate_params *params = NULL;

	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (!params)
		return -ENOMEM;

	params->root_bd = root_bd;
	params->num_dev = get_sibling_devices(dev, params->devs, MAX_DEV_PER_PORT);
	if (params->num_dev >= MAX_DEV_PER_PORT) {
		ret = -EINVAL;
		goto out;
	}

	dev_info(smmu->dev, "CoDA: Delegate %d devices as %02x:%02x to secure\n",
			params->num_dev, root_bd >> DEV_BUS_NUM,
			(root_bd & MASK_DEV_BUS) >> DEV_FUNCTION_NUM);
	ret = tmi_dev_delegate(__pa(params));
	if (ret) {
		dev_err(smmu->dev, "CoDA: failed to delegate device to secure\n");
		goto out;
	}

	for (i = 0; i < params->num_dev; i++) {
		ret = add_cc_dev_obj(params->devs[i], 0, root_bd, true);
		if (ret)
			break;
	}

out:
	kfree(params);
	return ret;
}

/**
 * add_secure_dev_to_cc_table - Add secure device to hash table
 * @smmu: An SMMUv3 instance
 * @smmu_domain: The handle of smmu_domain
 * @root_bd: The port where the secure device is located
 * @master: SMMU private data for each master
 *
 * Returns:
 * %0 if add to hash table success
 * %-ENOMEM if alloc obj failed
 * %-EINVAL if stream id is invalid
 */
static inline int add_secure_dev_to_cc_table(struct arm_smmu_device *smmu,
	struct arm_smmu_domain *smmu_domain, uint16_t root_bd, struct arm_smmu_master *master)
{
	int i, j;
	u64 ret = 0;

	for (i = 0; i < master->num_streams; i++) {
		u32 sid = master->streams[i].id;

		for (j = 0; j < i; j++)
			if (master->streams[j].id == sid)
				break;
		if (j < i)
			continue;
		if (!is_cc_dev(sid)) {
			dev_err(smmu->dev, "CoDA: sid is not cc dev\n");
			return -EINVAL;
		}
		ret = add_cc_dev_obj(sid, smmu_domain->s2_cfg.vmid, root_bd, true);
		if (ret)
			break;
	}
	return ret;
}

/**
 * virtcca_enable_secure_dev - Enable the PCIe protection controller function
 * of the security device
 * @smmu_domain: The handle of smmu_domain
 * @master: SMMU private data for each master
 * @dev: Secure device
 *
 * Returns:
 * %0 if the root port of secure dev successfully set up pcipc capability
 * %-ENOMEM alloc ste params failed
 * %-EINVAL set ste config content failed
 */
static int virtcca_enable_secure_dev(struct arm_smmu_domain *smmu_domain,
	struct arm_smmu_master *master, struct device *dev)
{
	u64 ret = 0;
	uint16_t root_bd = get_root_bd(dev);
	struct arm_smmu_device *smmu = smmu_domain->smmu;

	if (!is_cc_root_bd(root_bd)) {
		ret = virtcca_delegate_secure_dev(root_bd, smmu, dev);
		if (ret)
			return ret;
	}

	ret = add_secure_dev_to_cc_table(smmu, smmu_domain, root_bd, master);

	return ret;
}

/**
 * virtcca_secure_dev_operator - Implement security settings for corresponding devices
 * targeting the secure smmu domain
 * @domain: The handle of iommu_domain
 * @dev: Secure device
 *
 * Returns:
 * %0 if the domain does not need to enable secure or the domain
 * successfully set up security features
 * %-EINVAL if the smmu does not initialize secure state
 * %-ENOMEM if the device create secure ste failed
 * %-ENOENT if the device does not have fwspec
 */
int virtcca_secure_dev_operator(struct device *dev, void *domain)
{
	int i, j;
	int ret;
	struct iommu_domain *iommu_domain = (struct iommu_domain *)domain;
	struct iommu_fwspec *fwspec = NULL;
	struct arm_smmu_device *smmu = NULL;
	struct arm_smmu_domain *smmu_domain = NULL;
	struct arm_smmu_master *master = NULL;

	if (!is_virtcca_cvm_enable())
		return 0;

	fwspec = dev_iommu_fwspec_get(dev);
	if (!fwspec)
		return -ENOENT;

	smmu_domain = to_smmu_domain(iommu_domain);
	master = dev_iommu_priv_get(dev);
	smmu = master->smmu;

	if (!smmu && !virtcca_smmu_enable(smmu)) {
		dev_err(smmu->dev, "CoDA: security smmu not initialized for the device\n");
		return -EINVAL;
	}

	ret = virtcca_enable_secure_dev(smmu_domain, master, dev);
	if (ret)
		return ret;

	for (i = 0; i < master->num_streams; i++) {
		u32 sid = master->streams[i].id;
		/* Bridged PCI devices may end up with duplicated IDs */
		for (j = 0; j < i; j++)
			if (master->streams[j].id == sid)
				break;
		if (j < i)
			continue;
		if (virtcca_secure_dev_ste_create(smmu, master, sid))
			return -ENOMEM;
	}

	dev_info(smmu->dev, "CoDA: attach confidential dev: %s", dev_name(dev));

	return ret;
}
EXPORT_SYMBOL_GPL(virtcca_secure_dev_operator);

/**
 * virtcca_attach_secure_dev - Attach the device of iommu
 * group to confidential virtual machine
 * @domain: The handle of iommu domain
 * @group: Iommu group
 *
 * Returns:
 * %0 if attach the all devices success
 * %-EINVAL if the smmu does not initialize secure state
 * %-ENOMEM if the device create secure ste failed
 * %-ENOENT if the device does not have fwspec
 */
int virtcca_attach_secure_dev(struct iommu_domain *domain, struct iommu_group *group)
{
	int ret;

	ret = iommu_group_for_each_dev(group, (void *)domain, virtcca_secure_dev_operator);

	return ret;
}
EXPORT_SYMBOL_GPL(virtcca_attach_secure_dev);
