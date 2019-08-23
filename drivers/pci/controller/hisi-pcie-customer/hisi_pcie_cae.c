// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/device.h>
#include <linux/module.h>

#define	CHIP_OFFSET			0x200000000000UL
#define	APB_SUBCTRL_BASE	0x148070000UL

#define	DEVICE_NAME "pcie_reg_dev"

static const struct vm_operations_struct mmap_pcie_mem_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys
#endif
};

static int pcie_reg_mmap(struct file *filep, struct vm_area_struct *vma)
{
	u64 size = vma->vm_end - vma->vm_start;
	u32 chip_id = (u32)vma->vm_pgoff;
	u64 phy_addr;

	pr_info("[PCIe Base] tools map chipid:%d\n", chip_id);
	phy_addr = APB_SUBCTRL_BASE + CHIP_OFFSET * chip_id;
	/* It's illegal to wrap around the end of the physical address space. */
	vma->vm_pgoff = phy_addr >> PAGE_SHIFT;

	vma->vm_page_prot =  pgprot_device(vma->vm_page_prot);

	vma->vm_ops = &mmap_pcie_mem_ops;

	/* Remap-pfn-range will mark the range VM_IO */
	if (remap_pfn_range(vma,
			    vma->vm_start,
			    vma->vm_pgoff,
			    size,
			    vma->vm_page_prot)) {
		return -EAGAIN;
	}
	return 0;
}

static int pcie_open(struct inode *inode, struct file *f)
{
	return 0;
}

static int pcie_release(struct inode *inode, struct file *f)
{
	return 0;
}

static const struct file_operations pcie_dfx_fops = {
	.owner          = THIS_MODULE,
	.open           = pcie_open,
	.release        = pcie_release,
	.llseek         = noop_llseek,
	.mmap           = pcie_reg_mmap,
};

static struct miscdevice pcie_dfx_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.fops = &pcie_dfx_fops,
	.name = DEVICE_NAME,
};

static int __init misc_dev_init(void)
{
	return misc_register(&pcie_dfx_misc);
}

static void __exit misc_dev_exit(void)
{
	(void)misc_deregister(&pcie_dfx_misc);
}

module_init(misc_dev_init);
module_exit(misc_dev_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Huawei Technology Company");
MODULE_DESCRIPTION("PCIe DFX TOOL");
MODULE_VERSION("V1.0");

