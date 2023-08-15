// SPDX-License-Identifier: GPL-2.0
#include <linux/pci.h>
#include <linux/delay.h>

#include <asm/sw64io.h>

#ifdef CONFIG_DCA
static void enable_sw_dca(struct pci_dev *dev)
{
	struct pci_controller *hose = (struct pci_controller *)dev->sysdata;
	unsigned long node, rc_index, dca_ctl, dca_conf;
	int i;

	if (dev->class >> 8 != PCI_CLASS_NETWORK_ETHERNET)
		return;
	node = hose->node;
	rc_index = hose->index;
	for (i = 0; i < 256; i++) {
		dca_conf = read_piu_ior1(node, rc_index, DEVICEID0 + (i << 7));
		if (dca_conf >> 63)
			continue;
		else {
			dca_conf = (1UL << 63) | (dev->bus->number << 8) | dev->devfn;
			printk("dca device index %d, dca_conf = %#lx\n", i, dca_conf);
			write_piu_ior1(node, rc_index, DEVICEID0 + (i << 7), dca_conf);
			break;
		}
	}
	dca_ctl = read_piu_ior1(node, rc_index, DCACONTROL);
	if (dca_ctl & 0x1) {
		dca_ctl = 0x2;
		write_piu_ior1(node, rc_index, DCACONTROL, dca_ctl);
		printk("Node %ld RC %ld enable DCA 1.0\n", node, rc_index);
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, PCI_ANY_ID, enable_sw_dca);
#endif

void __init reserve_mem_for_pci(void)
{
	int ret;
	unsigned long base = PCI_32BIT_MEMIO;

	ret = add_memmap_region(base, PCI_32BIT_MEMIO_SIZE, memmap_pci);
	if (ret) {
		pr_err("reserved pages for pcie memory space failed\n");
		return;
	}

	pr_info("reserved pages for pcie memory space %lx:%lx\n", base >> PAGE_SHIFT,
			(base + PCI_32BIT_MEMIO_SIZE) >> PAGE_SHIFT);
}
