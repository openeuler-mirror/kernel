// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#include <linux/iopoll.h>
#include <linux/pci.h>

#include "arm-smmu-v3.h"
#include "arm-s-smmu-v3.h"

struct cc_dev_config {
	u32               sid; /* BDF number of the device */
	u32               vmid; /* virtual machine id */
	u32               root_bd; /* root bus and device number. */
	bool              secure; /* device secure attribute */
	struct hlist_node node; /* device hash table */
};

static bool g_s_smmu_id_map_init;

static DEFINE_HASHTABLE(g_cc_dev_htable, MAX_CC_DEV_NUM_ORDER);
static DECLARE_BITMAP(g_s_smmu_id_map, ARM_S_SMMU_MAX_IDS);

/*
 * Add secure IRQs index based on arm_smmu_msi_index
 * Struct arm_s_smmu_msi_index need keep same as struct arm_smmu_msi_index
 */
enum arm_s_smmu_msi_index {
	EVTQ_MSI_INDEX,
	GERROR_MSI_INDEX,
	PRIQ_MSI_INDEX,
	S_EVTQ_MSI_INDEX,
	S_GERROR_MSI_INDEX,
	ARM_S_SMMU_MAX_MSIS,
};

/* Add secure IRQs cfg based on arm_smmu_msi_cfg */
static phys_addr_t arm_s_smmu_msi_cfg[ARM_S_SMMU_MAX_MSIS][ARM_S_SMMU_MAX_CFGS] = {
	[S_EVTQ_MSI_INDEX] = {
		ARM_SMMU_S_EVTQ_IRQ_CFG0,
		ARM_SMMU_S_EVTQ_IRQ_CFG1,
		ARM_SMMU_S_EVTQ_IRQ_CFG2,
	},
	[S_GERROR_MSI_INDEX] = {
		ARM_SMMU_S_GERROR_IRQ_CFG0,
		ARM_SMMU_S_GERROR_IRQ_CFG1,
		ARM_SMMU_S_GERROR_IRQ_CFG2,
	},
};

static inline void virtcca_smmu_set_irq(struct arm_smmu_device *smmu)
{
	smmu->s_evtq_irq = msi_get_virq(smmu->dev, S_EVTQ_MSI_INDEX);
	smmu->s_gerr_irq = msi_get_virq(smmu->dev, S_GERROR_MSI_INDEX);
}

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
	while (pdev->bus->parent != NULL)
		pdev = pdev->bus->self;

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

	while (pdev->bus->parent != NULL)
		pdev = pdev->bus->self;

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
static bool is_cc_vmid(u32 vmid)
{
	int bkt;
	struct cc_dev_config *obj;

	hash_for_each(g_cc_dev_htable, bkt, obj, node) {
		if (vmid > 0 && obj->vmid == vmid)
			return true;
	}

	return false;
}

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
 * virtcca_smmu_cmdq_need_forward - Whether the cmd queue need transfer to secure world
 * @cmd0: Command consists of 128 bits, cmd0 is the low 64 bits
 * @cmd1: Cmdq is the high 64 bits of command
 * @forward: Need transfer to secure world or not
 */
static void virtcca_smmu_cmdq_need_forward(u64 cmd0, u64 cmd1, u64 *forward)
{
	u64 opcode = FIELD_GET(CMDQ_0_OP, cmd0);

	switch (opcode) {
	case CMDQ_OP_TLBI_EL2_ALL:
	case CMDQ_OP_TLBI_NSNH_ALL:
		*forward = 1;
		break;
	case CMDQ_OP_PREFETCH_CFG:
	case CMDQ_OP_CFGI_CD:
	case CMDQ_OP_CFGI_STE:
	case CMDQ_OP_CFGI_CD_ALL:
		*forward = (uint64_t)is_cc_dev(FIELD_GET(CMDQ_CFGI_0_SID, cmd0));
		break;

	case CMDQ_OP_CFGI_ALL:
		*forward = 1;
		break;
	case CMDQ_OP_TLBI_NH_VA:
	case CMDQ_OP_TLBI_S2_IPA:
	case CMDQ_OP_TLBI_NH_ASID:
	case CMDQ_OP_TLBI_S12_VMALL:
		*forward = (uint64_t)is_cc_vmid(FIELD_GET(CMDQ_TLBI_0_VMID, cmd0));
		break;
	case CMDQ_OP_TLBI_EL2_VA:
	case CMDQ_OP_TLBI_EL2_ASID:
		*forward = 0;
		break;
	case CMDQ_OP_ATC_INV:
		*forward = (uint64_t)is_cc_dev(FIELD_GET(CMDQ_ATC_0_SID, cmd0));
		break;
	case CMDQ_OP_PRI_RESP:
		*forward = (uint64_t)is_cc_dev(FIELD_GET(CMDQ_PRI_0_SID, cmd0));
		break;
	case CMDQ_OP_RESUME:
		*forward = (uint64_t)is_cc_dev(FIELD_GET(CMDQ_RESUME_0_SID, cmd0));
		break;
	case CMDQ_OP_CMD_SYNC:
		*forward = 0;
		break;
	default:
		*forward = 0;
	}
}

/**
 * virtcca_smmu_queue_write - Write queue command to TMM
 * @smmu: An SMMUv3 instance
 * @src: Command information
 * @n_dwords: Num of command
 */
static void virtcca_smmu_queue_write(struct arm_smmu_device *smmu, u64 *src, size_t n_dwords)
{
	u64 cmd0, cmd1;
	u64 forward = 0;

	if (!is_virtcca_cvm_enable())
		return;

	if (!virtcca_smmu_enable(smmu))
		return;

	if (n_dwords == ARM_S_SMMU_CMD_COUNT) {
		cmd0 = cpu_to_le64(src[0]);
		cmd1 = cpu_to_le64(src[1]);
		virtcca_smmu_cmdq_need_forward(cmd0, cmd1, &forward);

		/* need forward queue command to TMM */
		if (forward) {
			if (tmi_smmu_queue_write(cmd0, cmd1, smmu->s_smmu_id))
				dev_err(smmu->dev, "S_SMMU: s queue write failed\n");
		}
	}
}

/**
 * virtcca_smmu_cmdq_write_entries - Write a batch of queue command
 * to TMM, if need sync, will send additional cmd queue
 * @smmu: An SMMUv3 instance
 * @cmds: A batch of queue command
 * @llq: Head and tail pointers of a circular queue
 * @q: Smmu queue
 * @n: Num of command
 * @sync: Whethe need to sync or not
 */
void virtcca_smmu_cmdq_write_entries(struct arm_smmu_device *smmu, u64 *cmds,
	struct arm_smmu_ll_queue *llq, struct arm_smmu_queue *q,
	int n, bool sync)
{
	int i;

	if (!is_virtcca_cvm_enable())
		return;

	if (!virtcca_smmu_enable(smmu))
		return;

	for (i = 0; i < n; i++) {
		u64 *cmd = &cmds[i * CMDQ_ENT_DWORDS];

		virtcca_smmu_queue_write(smmu, cmd, CMDQ_ENT_DWORDS);
	}


	if (sync) {
		u32 prod;
		u64 cmd_sync[CMDQ_ENT_DWORDS];
		struct arm_smmu_cmdq_ent ent = {
			.opcode = CMDQ_OP_CMD_SYNC,
		};

		prod = (Q_WRP(llq, llq->prod) | Q_IDX(llq, llq->prod)) + n;
		prod = Q_OVF(llq->prod) | Q_WRP(llq, prod) | Q_IDX(llq, prod);
		if (smmu->options & ARM_SMMU_OPT_MSIPOLL) {
			ent.sync.msiaddr = q->base_dma + Q_IDX(&q->llq, prod) *
				q->ent_dwords * 8;
		}
		memset(cmd_sync, 0, 1 << CMDQ_ENT_SZ_SHIFT);
		cmd_sync[0] |= FIELD_PREP(CMDQ_0_OP, ent.opcode);
		if (ent.sync.msiaddr) {
			cmd_sync[0] |= FIELD_PREP(CMDQ_SYNC_0_CS, CMDQ_SYNC_0_CS_IRQ);
			cmd_sync[1] |= ent.sync.msiaddr & CMDQ_SYNC_1_MSIADDR_MASK;
		} else {
			cmd_sync[0] |= FIELD_PREP(CMDQ_SYNC_0_CS, CMDQ_SYNC_0_CS_SEV);
		}
		cmd_sync[0] |= FIELD_PREP(CMDQ_SYNC_0_MSH, ARM_SMMU_SH_ISH);
		cmd_sync[0] |= FIELD_PREP(CMDQ_SYNC_0_MSIATTR, ARM_SMMU_MEMATTR_OIWB);
		virtcca_smmu_queue_write(smmu, cmd_sync, CMDQ_ENT_DWORDS);
	}
}

/**
 * virtcca_smmu_init_one_queue - Initialize a queue of the corresponding type
 * @smmu: An SMMUv3 instance
 * @q: Smmu queue
 * @dwords: Size of command
 * @name: Queue name
 */
static void virtcca_smmu_init_one_queue(struct arm_smmu_device *smmu,
	struct arm_smmu_queue *q, size_t dwords, const char *name)
{
	size_t qsz;
	struct tmi_smmu_queue_params *params_ptr = NULL;

	params_ptr = kzalloc(sizeof(*params_ptr), GFP_KERNEL);
	if (!params_ptr) {
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		return;
	}

	qsz = ((1 << q->llq.max_n_shift) * dwords) << ARM_S_QUEUE_SHIFT_SIZE;
	if (!strcmp(name, "cmdq")) {
		params_ptr->ns_src = q->base_dma;
		params_ptr->smmu_base_addr = smmu->ioaddr;
		params_ptr->size = qsz;
		params_ptr->smmu_id = smmu->s_smmu_id;
		params_ptr->type = TMI_SMMU_CMD_QUEUE;
		tmi_smmu_queue_create(__pa(params_ptr));
	}

	if (!strcmp(name, "evtq")) {
		params_ptr->ns_src = q->base_dma;
		params_ptr->smmu_base_addr = smmu->ioaddr;
		params_ptr->size = qsz;
		params_ptr->smmu_id = smmu->s_smmu_id;
		params_ptr->type = TMI_SMMU_EVT_QUEUE;
		tmi_smmu_queue_create(__pa(params_ptr));
	}

	kfree(params_ptr);
}

/**
 * virtcca_smmu_write_reg_sync - Write values to secure smmu registers and wait for completion
 * @smmu: An SMMUv3 instance
 * @val: Expected value to be written
 * @cmp_val: Complete value need to be compare
 * @reg_off: Offset of object register
 * @ack_off: Acknowledge offset of object register
 *
 * Returns:
 * -ENXIO if write register failed
 * %0 if write success
 */
static int virtcca_smmu_write_reg_sync(struct arm_smmu_device *smmu, u32 val,
	u32 cmp_val, u32 reg_off, u32 ack_off)
{
	u32 reg;

	if (tmi_smmu_write(smmu->ioaddr, reg_off, val, ARM_S_SMMU_REG_32_BIT))
		return -ENXIO;

	return virtcca_cvm_read_poll_timeout_atomic(tmi_smmu_read, reg, reg == cmp_val,
				       1, ARM_SMMU_POLL_TIMEOUT_US, false,
				       smmu->ioaddr, ack_off, ARM_S_SMMU_REG_32_BIT);
}

/**
 * virtcca_smmu_update_gbpa - Write values to glabal bypass register
 * @smmu: An SMMUv3 instance
 * @set: Number of bits to be set
 * @clr: Number of bits to be clear
 *
 * Returns:
 * %0 update gbpa register success
 */
static int virtcca_smmu_update_gbpa(struct arm_smmu_device *smmu, u32 set, u32 clr)
{
	int ret;
	u32 reg;

	ret = virtcca_cvm_read_poll_timeout_atomic(tmi_smmu_read, reg, !(reg & S_GBPA_UPDATE),
				       1, ARM_SMMU_POLL_TIMEOUT_US, false,
				       smmu->ioaddr, ARM_SMMU_S_GBPA, ARM_S_SMMU_REG_32_BIT);
	if (ret)
		return ret;

	reg &= ~clr;
	reg |= set;

	ret = tmi_smmu_write(smmu->ioaddr, ARM_SMMU_S_GBPA,
		reg | S_GBPA_UPDATE, ARM_S_SMMU_REG_32_BIT);
	if (ret)
		return ret;

	ret = virtcca_cvm_read_poll_timeout_atomic(tmi_smmu_read, reg, !(reg & S_GBPA_UPDATE),
			1, ARM_SMMU_POLL_TIMEOUT_US, false,
			smmu->ioaddr, ARM_SMMU_S_GBPA, ARM_S_SMMU_REG_32_BIT);
	if (ret)
		dev_err(smmu->dev, "S_SMMU: s_gbpa not responding to update\n");
	return ret;
}

/**
 * virtcca_smmu_device_disable - Disable the secure smmu
 * @smmu: An SMMUv3 instance
 *
 * Returns:
 * %0 disable secure smmu success
 */
static int virtcca_smmu_device_disable(struct arm_smmu_device *smmu)
{
	int ret = 0;

	ret = virtcca_smmu_write_reg_sync(smmu, 0, 0, ARM_SMMU_S_CR0, ARM_SMMU_S_CR0ACK);
	if (ret) {
		dev_err(smmu->dev, "S_SMMU: failed to clear s_cr0\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		return ret;
	}
	return 0;
}

/**
 * virtcca_smmu_evtq_thread - The secure evt queue thread
 * @irq: Irq index
 * @dev: Smmu device
 */
static irqreturn_t virtcca_smmu_evtq_thread(int irq, void *dev)
{
	struct arm_smmu_device *smmu = dev;

	if (virtcca_smmu_enable(smmu))
		tmi_handle_s_evtq(smmu->s_smmu_id);

	return IRQ_HANDLED;
}

/**
 * virtcca_smmu_gerror_handler - The secure gerror handler
 * @irq: Irq index
 * @dev: Smmu device
 *
 * Returns:
 * %IRQ_NONE no errors pending
 */
irqreturn_t virtcca_smmu_gerror_handler(int irq, void *dev)
{
	u64 gerror, gerrorn, active;
	u64 ret;
	struct arm_smmu_device *smmu = dev;

	ret = tmi_smmu_read(smmu->ioaddr, ARM_SMMU_S_GERROR, ARM_S_SMMU_REG_32_BIT);
	if (ret >> ARM_S_SMMU_REG_32_BIT) {
		dev_err(smmu->dev, "S_SMMU: get arm_smmu_s_gerror register failed\n");
		return IRQ_NONE;
	}
	gerror = ret & ARM_S_SMMU_MASK_UPPER_32_BIT;

	ret = tmi_smmu_read(smmu->ioaddr, ARM_SMMU_S_GERRORN, ARM_S_SMMU_REG_32_BIT);
	if (ret >> ARM_S_SMMU_REG_32_BIT) {
		dev_err(smmu->dev, "S_SMMU: get arm_smmu_s_gerror register failed\n");
		return IRQ_NONE;
	}
	gerrorn = ret & ARM_S_SMMU_MASK_UPPER_32_BIT;

	active = gerror ^ gerrorn;
	if (!(active & GERROR_ERR_MASK))
		return IRQ_NONE; /* No errors pending */

	dev_warn(smmu->dev,
		 "S_SMMU: unexpected secure global error reported, this could be serious, active %llx\n",
		 active);

	if (active & GERROR_SFM_ERR) {
		dev_err(smmu->dev, "S_SMMU: device has entered service failure mode!\n");
		virtcca_smmu_device_disable(smmu);
	}

	if (active & GERROR_MSI_GERROR_ABT_ERR)
		dev_warn(smmu->dev, "S_SMMU: gerror msi write aborted\n");

	if (active & GERROR_MSI_PRIQ_ABT_ERR)
		dev_warn(smmu->dev, "S_SMMU: priq msi write aborted\n");

	if (active & GERROR_MSI_EVTQ_ABT_ERR)
		dev_warn(smmu->dev, "S_SMMU: evtq msi write aborted\n");

	if (active & GERROR_MSI_CMDQ_ABT_ERR)
		dev_warn(smmu->dev, "S_SMMU: cmdq msi write aborted\n");

	if (active & GERROR_PRIQ_ABT_ERR)
		dev_err(smmu->dev, "S_SMMU: priq write aborted -- events may have been lost\n");

	if (active & GERROR_EVTQ_ABT_ERR)
		dev_err(smmu->dev, "S_SMMU: evtq write aborted -- events may have been lost\n");

	if (active & GERROR_CMDQ_ERR)
		dev_warn(smmu->dev, "S_SMMU: cmdq err\n");

	if (tmi_smmu_write(smmu->ioaddr, ARM_SMMU_S_GERRORN, gerror, ARM_S_SMMU_REG_32_BIT)) {
		dev_err(smmu->dev, "S_SMMU: write arm_smmu_s_gerrorn failed\n");
		return IRQ_NONE;
	}

	return IRQ_HANDLED;
}

/**
 * virtcca_smmu_disable_irq - Disable secure smmu irq function
 * @smmu: An SMMUv3 instance
 */
static void virtcca_smmu_disable_irq(struct arm_smmu_device *smmu)
{
	if (virtcca_smmu_write_reg_sync(smmu, 0, 0,
		ARM_SMMU_S_IRQ_CTRL, ARM_SMMU_S_IRQ_CTRLACK)) {
		dev_err(smmu->dev, "S_SMMU: failed to disable secure irqs\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
	}
}

/**
 * virtcca_smmu_enable_irq - Enable secure smmu irq function
 * @smmu: An SMMUv3 instance
 * @irqen_flags: Mask value of irq
 */
static void virtcca_smmu_enable_irq(struct arm_smmu_device *smmu, u32 irqen_flags)
{
	if (virtcca_smmu_write_reg_sync(smmu, irqen_flags,
		irqen_flags, ARM_SMMU_S_IRQ_CTRL, ARM_SMMU_S_IRQ_CTRLACK)) {
		dev_err(smmu->dev, "S_SMMU: failed to enable irq for secure evtq\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
	}
}

/**
 * platform_get_s_irq_byname_optional - Get irq index from platform
 * @pdev: The handle of platform_device
 * @smmu: An SMMUv3 instance
 */
static void platform_get_s_irq_byname_optional(struct platform_device *pdev,
	struct arm_smmu_device *smmu)
{
	int irq;

	irq = platform_get_irq_byname_optional(pdev, "s_eventq");
	if (irq > 0)
		smmu->s_evtq_irq = irq;

	irq = platform_get_irq_byname_optional(pdev, "s_gerror");
	if (irq > 0)
		smmu->s_gerr_irq = irq;
}

/**
 * virtcca_smmu_tmi_dev_attach - Complete the stage2 page table establishment
 * for the security device
 * @arm_smmu_domain: The handle of smmu domain
 * @kvm: The handle of virtual machine
 *
 * Returns:
 * %0 if attach dev success
 * %-ENXIO if the root port of device does not have pcipc capability
 */
u32 virtcca_smmu_tmi_dev_attach(struct arm_smmu_domain *arm_smmu_domain, struct kvm *kvm)
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
					dev_err(arm_smmu_domain->smmu->dev, "S_SMMU: dev protected failed!\n");
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
 * virtcca_smmu_secure_dev_ste_create - Setting up the STE config content
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
static int virtcca_smmu_secure_dev_ste_create(struct arm_smmu_device *smmu,
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
		dev_err(smmu->dev, "S_SMMU: failed to create ste level 2\n");
		return -EINVAL;
	}

	kfree(params_ptr);

	return 0;
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
			dev_err(smmu->dev, "S_SMMU: sid is not cc dev\n");
			return -EINVAL;
		}
		ret = add_cc_dev_obj(sid, smmu_domain->s2_cfg.vmid, root_bd, true);
		if (ret)
			break;
	}
	return ret;
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

	dev_info(smmu->dev, "S_SMMU: Delegate %d devices as %02x:%02x to secure\n",
			params->num_dev, root_bd >> DEV_BUS_NUM,
			(root_bd & MASK_DEV_BUS) >> DEV_FUNCTION_NUM);
	ret = tmi_dev_delegate(__pa(params));
	if (ret) {
		dev_err(smmu->dev, "S_SMMU: failed to delegate device to secure\n");
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
 * virtcca_smmu_write_msi_msg - Write secure smmu msi msg
 * @desc: Descriptor structure for MSI based interrupts
 * @msg: Representation of a MSI message
 *
 * Returns:
 * %false if the msi index is not the secure msi
 * %true write msi msg success
 */
bool virtcca_smmu_write_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	phys_addr_t doorbell;

	if (!is_virtcca_cvm_enable())
		return false;

	if (desc->msi_index != S_EVTQ_MSI_INDEX &&
		desc->msi_index != S_GERROR_MSI_INDEX)
		return false;

	struct device *dev = msi_desc_to_dev(desc);
	struct arm_smmu_device *smmu = dev_get_drvdata(dev);
	phys_addr_t *cfg = arm_s_smmu_msi_cfg[desc->msi_index];

	doorbell = (((u64)msg->address_hi) << ARM_S_SMMU_REG_32_BIT) | msg->address_lo;
	doorbell &= MSI_CFG0_ADDR_MASK;
	tmi_smmu_write((u64)smmu->ioaddr, cfg[0], doorbell, ARM_S_SMMU_REG_64_BIT);
	tmi_smmu_write((u64)smmu->ioaddr, cfg[1], msg->data, ARM_S_SMMU_REG_32_BIT);
	tmi_smmu_write((u64)smmu->ioaddr, cfg[2],
		ARM_SMMU_MEMATTR_DEVICE_nGnRE, ARM_S_SMMU_REG_32_BIT);
	return true;
}

/**
 * arm_s_smmu_setup_msis - Enable secure smmu msi
 * @smmu: An SMMUv3 instance
 */
static void arm_s_smmu_setup_msis(struct arm_smmu_device *smmu)
{
	int ret;
	struct device *dev = smmu->dev;

	virtcca_smmu_set_irq_cfg(smmu);

	if (!(smmu->features & ARM_SMMU_FEAT_MSI))
		return;

	if (!dev->msi.domain) {
		dev_info(smmu->dev, "S_SMMU: msi_domain absent - falling back to wired irqs\n");
		return;
	}

	/* Allocate MSIs for s_evtq, s_gerror. Ignore cmdq */
	ret = platform_msi_domain_alloc_range_irqs(dev, S_EVTQ_MSI_INDEX,
		S_GERROR_MSI_INDEX, _arm_smmu_write_msi_msg);
	if (ret) {
		dev_warn(dev, "S_SMMU: failed to allocate msis - falling back to wired irqs\n");
		return;
	}

	virtcca_smmu_set_irq(smmu);
}

/**
 * virtcca_smmu_setup_unique_irqs - Set secure irq handle
 * @smmu: An SMMUv3 instance
 * @resume: Resume or not
 */
static void virtcca_smmu_setup_unique_irqs(struct arm_smmu_device *smmu, bool resume)
{
	int irq, ret;

	if (!virtcca_smmu_enable(smmu))
		return;

	if (!resume)
		arm_s_smmu_setup_msis(smmu);

	irq = smmu->s_evtq_irq;
	if (irq) {
		ret = devm_request_threaded_irq(smmu->dev, irq, NULL,
						virtcca_smmu_evtq_thread,
						IRQF_ONESHOT,
						"arm-smmu-v3-s_evtq", smmu);
		if (ret < 0) {
			smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
			dev_warn(smmu->dev, "S_SMMU: failed to enable s_evtq irq\n");
		}
	}

	irq = smmu->s_gerr_irq;
	if (irq) {
		ret = devm_request_irq(smmu->dev, irq, virtcca_smmu_gerror_handler,
				       0, "arm-smmu-v3-s_gerror", smmu);
		if (ret < 0) {
			smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
			dev_warn(smmu->dev, "S_SMMU: failed to enable s_gerror irq\n");
		}
	}
}

/**
 * _arm_smmu_write_reg_sync - Write value to smmu registers and wait for completion
 * @smmu: An SMMUv3 instance
 * @val: Expected value to be written
 * @reg_off: Offset of object register
 * @ack_off: Acknowledge offset of object register
 *
 * Returns:
 * %0 if write success
 */
static int _arm_smmu_write_reg_sync(struct arm_smmu_device *smmu, u32 val,
	u32 reg_off, u32 ack_off)
{
	u32 reg;

	writel_relaxed(val, smmu->base + reg_off);
	return readl_relaxed_poll_timeout(smmu->base + ack_off, reg, reg == val,
					  1, ARM_SMMU_POLL_TIMEOUT_US);
}

/**
 * virtcca_smmu_setup_irqs - Initialize the smmu irq
 * @smmu: An SMMUv3 instance
 * @resume: Resume or not
 */
static void virtcca_smmu_setup_irqs(struct arm_smmu_device *smmu, bool resume)
{
	int irq, ret;
	u32 irqen_flags = IRQ_CTRL_EVTQ_IRQEN | IRQ_CTRL_GERROR_IRQEN;

	ret = _arm_smmu_write_reg_sync(smmu, 0, ARM_SMMU_IRQ_CTRL,
				      ARM_SMMU_IRQ_CTRLACK);
	if (ret) {
		dev_err(smmu->dev, "S_SMMU: failed to disable irqs\n");
		return;
	}
	/* Disable IRQs first */
	virtcca_smmu_disable_irq(smmu);

	irq = smmu->combined_irq;
	if (!irq)
		virtcca_smmu_setup_unique_irqs(smmu, resume);

	if (smmu->features & ARM_SMMU_FEAT_PRI)
		irqen_flags |= IRQ_CTRL_PRIQ_IRQEN;

	/* Enable interrupt generation on the SMMU */
	ret = _arm_smmu_write_reg_sync(smmu, irqen_flags,
		ARM_SMMU_IRQ_CTRL, ARM_SMMU_IRQ_CTRLACK);
	if (ret)
		dev_warn(smmu->dev, "S_SMMU: failed to enable irqs\n");

	virtcca_smmu_enable_irq(smmu, IRQ_CTRL_EVTQ_IRQEN | IRQ_CTRL_GERROR_IRQEN);
}

/* Alloc smmu id for secure smmu */
static int virtcca_smmu_id_alloc(void)
{
	int idx;

	do {
		idx = find_first_zero_bit(g_s_smmu_id_map, ARM_S_SMMU_MAX_IDS);
		if (idx == ARM_S_SMMU_MAX_IDS) {
			pr_warn("S_SMMU: s_smmu_id over than max ids\n");
			return ARM_S_SMMU_INVALID_ID;
		}
	} while (test_and_set_bit(idx, g_s_smmu_id_map));

	return idx;
}

/**
 * virtcca_smmu_map_init - For SMMU, it has various uses. In virtCCA scenario,
 * only smmus used by PCIe devices require secure state initialization.
 * @smmu: An SMMUv3 instance
 * @ioaddr: Smmu address
 *
 * Returns:
 * %true if the smmu need to initialize secure state
 * %false the smmu does not need to initialize secure state
 */
static bool virtcca_smmu_map_init(struct arm_smmu_device *smmu, resource_size_t ioaddr)
{
	if (!g_s_smmu_id_map_init) {
		set_bit(0, g_s_smmu_id_map);
		hash_init(g_cc_dev_htable);
		g_s_smmu_id_map_init = true;
	}
	smmu->ioaddr = ioaddr;

	if (tmi_smmu_pcie_core_check(ioaddr) == SMMU_PCIE_CORE_IS_VALID) {
		smmu->s_smmu_id = virtcca_smmu_id_alloc();
		return true;
	}

	smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
	return false;
}

/**
 * arm_s_smmu_device_enable - Enable the smmu secure state
 * @smmu: An SMMUv3 instance
 * @enables: The smmu attribute need to enable
 * @bypass: Bypass smmu
 * @disable_bypass: Global bypass smmu
 */
static void arm_s_smmu_device_enable(struct arm_smmu_device *smmu,
	u32 enables, bool bypass, bool disable_bypass)
{
	int ret = 0;

	/* Enable the SMMU interface, or ensure bypass */
	if (!bypass || disable_bypass) {
		enables |= CR0_SMMUEN;
	} else {
		ret = virtcca_smmu_update_gbpa(smmu, 0, S_GBPA_ABORT);
		if (ret) {
			dev_err(smmu->dev, "S_SMMU: failed to update s gbpa!\n");
			smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
			return;
		}
	}
	/* Mask BIT1 and BIT4 which are RES0 in SMMU_S_CRO */
	ret = virtcca_smmu_write_reg_sync(smmu, enables & ~SMMU_S_CR0_RESERVED,
		enables & ~SMMU_S_CR0_RESERVED, ARM_SMMU_S_CR0, ARM_SMMU_S_CR0ACK);

	if (ret) {
		dev_err(smmu->dev, "S_SMMU: failed to enable s smmu!\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
	}

	dev_info(smmu->dev, "S_SMMU: secure smmu id:%lld init end!\n", smmu->s_smmu_id);
}

/**
 * arm_s_smmu_idr1_support_secure - Whether the smmu support secure registers
 * and secure stage2 translate
 * @smmu: An SMMUv3 instance
 *
 * Returns:
 * %false if the smmu does not support secure initialize
 * %true if the smmu support secure initialize
 */
static bool arm_s_smmu_idr1_support_secure(struct arm_smmu_device *smmu)
{
	u64 rv;

	rv = tmi_smmu_read(smmu->ioaddr, ARM_SMMU_S_IDR1, ARM_S_SMMU_REG_32_BIT);
	if (rv >> ARM_S_SMMU_REG_32_BIT) {
		dev_err(smmu->dev, "S_SMMU: get arm_smmu_s_idr1 register failed!\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		return false;
	}

	if (!(rv & S_IDR1_SECURE_IMPL)) {
		dev_err(smmu->dev, "S_SMMU: does not implement secure state!\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		return false;
	}

	if (!(rv & S_IDR1_SEL2)) {
		dev_err(smmu->dev, "S_SMMU: secure stage2 translation not supported!\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		return false;
	}
	dev_info(smmu->dev, "S_SMMU: secure smmu id:%lld start init!\n", smmu->s_smmu_id);
	return true;
}

/**
 * virtcca_smmu_secure_dev_operator - Implement security settings for corresponding devices
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
int virtcca_smmu_secure_dev_operator(struct iommu_domain *domain, struct device *dev)
{
	int i, j;
	int ret;
	struct iommu_fwspec *fwspec = NULL;
	struct arm_smmu_device *smmu = NULL;
	struct arm_smmu_domain *smmu_domain = NULL;
	struct arm_smmu_master *master = NULL;

	if (!is_virtcca_cvm_enable())
		return 0;

	fwspec = dev_iommu_fwspec_get(dev);
	if (!fwspec)
		return -ENOENT;

	smmu_domain = to_smmu_domain(domain);
	master = dev_iommu_priv_get(dev);
	smmu = master->smmu;

	if (!smmu && !virtcca_smmu_enable(smmu)) {
		dev_err(smmu->dev, "S_SMMU: security smmu not initialized for the device\n");
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
		if (virtcca_smmu_secure_dev_ste_create(smmu, master, sid))
			return -ENOMEM;
	}

	dev_info(smmu->dev, "S_SMMU: attach confidential dev: %s", dev_name(dev));

	return ret;
}
EXPORT_SYMBOL_GPL(virtcca_smmu_secure_dev_operator);

/**
 * virtcca_smmu_device_init - Initialize the smmu security features
 * @pdev: The handle of iommu_domain
 * @smmu: An SMMUv3 instance
 * @ioaddr: SMMU address
 * @resume: Resume or not
 * @disable_bypass: Global disable smmu bypass
 */
void virtcca_smmu_device_init(struct platform_device *pdev, struct arm_smmu_device *smmu,
	resource_size_t ioaddr, bool resume, bool disable_bypass)
{
	u64 rv;
	int ret, irq;
	u32 reg, enables;
	struct tmi_smmu_cfg_params *params_ptr;

	/* Whether startup parameter (virtcca_cvm_host) is enabled or not */
	if (!is_virtcca_cvm_enable())
		return;

	/*
	 * For SMMU, it has various uses. In virtCCA scenario,
	 * only smmus used by PCIe devices require secure state initialization.
	 */
	if (!virtcca_smmu_map_init(smmu, ioaddr))
		return;

	/* Determine whether the smmu hardware supports secure state initialization */
	if (!virtcca_smmu_enable(smmu) || !arm_s_smmu_idr1_support_secure(smmu))
		return;

	irq = platform_get_irq_byname_optional(pdev, "combined");
	if (irq <= 0)
		platform_get_s_irq_byname_optional(pdev, smmu);

	/* Create cmd queue */
	virtcca_smmu_init_one_queue(smmu, &smmu->cmdq.q, CMDQ_ENT_DWORDS, "cmdq");

	/* Create evt queue */
	virtcca_smmu_init_one_queue(smmu, &smmu->evtq.q, EVTQ_ENT_DWORDS, "evtq");

	rv = tmi_smmu_read(smmu->ioaddr, ARM_SMMU_S_CR0, ARM_S_SMMU_REG_32_BIT);
	if (rv >> 32) {
		dev_err(smmu->dev, "S_SMMU: failed to read s_cr0\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		return;
	}

	rv = rv & ARM_S_SMMU_MASK_UPPER_32_BIT;
	if (rv & S_CR0_SMMUEN) {
		dev_warn(smmu->dev, "S_SMMU: secure smmu currently enabled! resetting...\n");
		virtcca_smmu_update_gbpa(smmu, S_GBPA_ABORT, 0);
	}

	ret = virtcca_smmu_device_disable(smmu);
	if (ret) {
		dev_err(smmu->dev, "S_SMMU: failed to disable s smmu\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		return;
	}

	/* CR1 (table and queue memory attributes) */
	reg = FIELD_PREP(CR1_TABLE_SH, ARM_SMMU_SH_ISH) |
	      FIELD_PREP(CR1_TABLE_OC, CR1_CACHE_WB) |
	      FIELD_PREP(CR1_TABLE_IC, CR1_CACHE_WB) |
	      FIELD_PREP(CR1_QUEUE_SH, ARM_SMMU_SH_ISH) |
	      FIELD_PREP(CR1_QUEUE_OC, CR1_CACHE_WB) |
	      FIELD_PREP(CR1_QUEUE_IC, CR1_CACHE_WB);

	ret = tmi_smmu_write(smmu->ioaddr, ARM_SMMU_S_CR1, reg, ARM_S_SMMU_REG_32_BIT);
	if (ret) {
		dev_err(smmu->dev, "S_SMMU: failed to write s_cr1\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		return;
	}

	/* CR2 (random crap) */
	reg = CR2_PTM | CR2_RECINVSID;

	if (smmu->features & ARM_SMMU_FEAT_E2H)
		reg |= CR2_E2H;

	ret = tmi_smmu_write(smmu->ioaddr, ARM_SMMU_S_CR2, reg, ARM_S_SMMU_REG_32_BIT);
	if (ret) {
		dev_err(smmu->dev, "S_SMMU: failed to write s_cr2\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		return;
	}

	params_ptr = kzalloc(sizeof(*params_ptr), GFP_KERNEL);
	if (!params_ptr) {
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		return;
	}

	/* Secure cmd queue */
	params_ptr->is_cmd_queue = 1;
	params_ptr->smmu_id = smmu->s_smmu_id;
	params_ptr->ioaddr = smmu->ioaddr;
	params_ptr->strtab_base_RA_bit =
		(smmu->strtab_cfg.strtab_base >> S_STRTAB_BASE_RA_SHIFT) & 0x1;
	params_ptr->q_base_RA_WA_bit =
		(smmu->cmdq.q.q_base >> S_CMDQ_BASE_RA_SHIFT) & 0x1;
	if (tmi_smmu_device_reset(__pa(params_ptr)) != 0) {
		dev_err(smmu->dev, "S_SMMU: failed to set s cmd queue regs\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		kfree(params_ptr);
		return;
	}

	/* Enable secure cmdq */
	enables = CR0_CMDQEN;
	ret = virtcca_smmu_write_reg_sync(smmu, enables, enables, ARM_SMMU_S_CR0,
				      ARM_SMMU_S_CR0ACK);
	if (ret) {
		dev_err(smmu->dev, "S_SMMU: failed to enable secure command queue\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		kfree(params_ptr);
		return;
	}

	enables |= CR0_EVTQEN;

	/* Secure event queue */
	memset(params_ptr, 0, sizeof(struct tmi_smmu_ste_params));
	params_ptr->is_cmd_queue = 0;
	params_ptr->ioaddr = smmu->ioaddr;
	params_ptr->smmu_id = smmu->s_smmu_id;
	params_ptr->q_base_RA_WA_bit =
		 (smmu->evtq.q.q_base >> S_EVTQ_BASE_WA_SHIFT) & 0x1;
	params_ptr->strtab_base_RA_bit =
		(smmu->strtab_cfg.strtab_base >> S_STRTAB_BASE_RA_SHIFT) & 0x1;
	if (tmi_smmu_device_reset(__pa(params_ptr)) != 0) {
		dev_err(smmu->dev, "S_SMMU: failed to set s event queue regs\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		kfree(params_ptr);
		return;
	}
	kfree(params_ptr);

	/* Enable secure eventq */
	ret = virtcca_smmu_write_reg_sync(smmu, enables, enables, ARM_SMMU_S_CR0,
					ARM_SMMU_S_CR0ACK);
	if (ret) {
		dev_err(smmu->dev, "S_SMMU: failed to disable secure event queue\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		return;
	}

	ret = virtcca_smmu_write_reg_sync(smmu, SMMU_S_INIT_INV_ALL, 0,
		ARM_SMMU_S_INIT, ARM_SMMU_S_INIT);
	if (ret) {
		dev_err(smmu->dev, "S_SMMU: failed to write s_init\n");
		smmu->s_smmu_id = ARM_S_SMMU_INVALID_ID;
		return;
	}

	/* Enable the secure irqs */
	virtcca_smmu_setup_irqs(smmu, resume);

	/* Enable the secure smmu interface, or ensure bypass */
	arm_s_smmu_device_enable(smmu, enables, smmu->bypass, disable_bypass);
}
