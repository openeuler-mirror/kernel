// SPDX-License-Identifier: GPL-2.0

#include <asm/sw64_init.h>

void set_devint_wken(int node)
{
	unsigned long val;

	/* enable INTD wakeup */
	val = 0x80;
	sw64_io_write(node, DEVINT_WKEN, val);
	sw64_io_write(node, DEVINTWK_INTEN, val);
}

void set_pcieport_service_irq(int node, int index)
{
	if (IS_ENABLED(CONFIG_PCIE_PME))
		write_piu_ior0(node, index, PMEINTCONFIG, PME_ENABLE_INTD_CORE0);

	if (IS_ENABLED(CONFIG_PCIEAER))
		write_piu_ior0(node, index, AERERRINTCONFIG, AER_ENABLE_INTD_CORE0);
}

int chip_pcie_configure(struct pci_controller *hose)
{
	struct pci_dev *dev;
	struct pci_bus *bus, *top;
	struct list_head *next;
	unsigned int max_read_size, smallest_max_payload;
	int max_payloadsize;
	unsigned long rc_index, node;
	unsigned long piuconfig0, value;
	unsigned int pcie_caps_offset;
	unsigned int rc_conf_value;
	u16 devctl, new_values;
	bool rc_ari_disabled = false, found = false;
	unsigned char bus_max_num;

	node = hose->node;
	rc_index = hose->index;
	smallest_max_payload = read_rc_conf(node, rc_index, RC_EXP_DEVCAP);
	smallest_max_payload &= PCI_EXP_DEVCAP_PAYLOAD;
	bus_max_num = hose->busn_space->start;

	top = hose->bus;
	bus = top;
	next = top->devices.next;

	for (;;) {
		if (next == &bus->devices) {
			/* end of this bus, go up or finish */
			if (bus == top)
				break;

			next = bus->self->bus_list.next;
			bus = bus->self->bus;
			continue;
		}
		dev = list_entry(next, struct pci_dev, bus_list);
		if (dev->subordinate) {
			/* this is a pci-pci bridge, do its devices next */
			next = dev->subordinate->devices.next;
			bus = dev->subordinate;
		} else
			next = dev->bus_list.next;

		if (!found) {
			if (pci_is_root_bus(dev->bus)) {
				if (list_empty(&dev->subordinate->devices))
					rc_ari_disabled = true;
			} else {
				if (!pci_ari_enabled(dev->bus)) {
					rc_ari_disabled = true;
					found = true;
				}
			}
		}

		if (bus->busn_res.end > bus_max_num)
			bus_max_num = bus->busn_res.end;

		/* Query device PCIe capability register  */
		pcie_caps_offset = dev->pcie_cap;
		if (pcie_caps_offset == 0)
			continue;
		max_payloadsize = dev->pcie_mpss;
		if (max_payloadsize < smallest_max_payload)
			smallest_max_payload = max_payloadsize;
	}

	if (rc_ari_disabled) {
		rc_conf_value = read_rc_conf(node, rc_index, RC_EXP_DEVCTL2);
		rc_conf_value &= ~PCI_EXP_DEVCTL2_ARI;
		write_rc_conf(node, rc_index, RC_EXP_DEVCTL2, rc_conf_value);
	} else {
		rc_conf_value = read_rc_conf(node, rc_index, RC_EXP_DEVCTL2);
		rc_conf_value |= PCI_EXP_DEVCTL2_ARI;
		write_rc_conf(node, rc_index, RC_EXP_DEVCTL2, rc_conf_value);
	}

	rc_conf_value = read_rc_conf(node, rc_index, RC_EXP_DEVCAP);
	rc_conf_value &= PCI_EXP_DEVCAP_PAYLOAD;
	max_payloadsize = rc_conf_value;
	if (max_payloadsize < smallest_max_payload)
		smallest_max_payload = max_payloadsize;

	max_read_size = 0x2;   /* Limit to 512B */
	value = read_rc_conf(node, rc_index, RC_EXP_DEVCTL);
	value &= ~(PCI_EXP_DEVCTL_PAYLOAD | PCI_EXP_DEVCTL_READRQ);
	value |= (max_read_size << 12) | (smallest_max_payload << 5);
	write_rc_conf(node, rc_index, RC_EXP_DEVCTL, value);
	new_values = (max_read_size << 12) | (smallest_max_payload << 5);

	piuconfig0 = read_piu_ior0(node, rc_index, PIUCONFIG0);
	piuconfig0 &= ~(0x7fUL << 9);
	if (smallest_max_payload == 0x2) {
		piuconfig0 |= (0x20UL << 9);
		write_piu_ior0(node, rc_index, PIUCONFIG0, piuconfig0);
	} else {
		piuconfig0 |= (0x40UL << 9);
		write_piu_ior0(node, rc_index, PIUCONFIG0, piuconfig0);
	}

	printk("Node%ld RC%ld MPSS %luB, MRRS %luB, Piuconfig0 %#lx, ARI %s\n",
			node, rc_index, (1UL << smallest_max_payload) << 7,
			(1UL << max_read_size) << 7, piuconfig0,
			rc_ari_disabled ? "disabled" : "enabled");

	/* Now, set the max_payload_size for all devices to that value. */
	bus = top;
	next = top->devices.next;
	for (;;) {
		if (next == &bus->devices) {
			/* end of this bus, go up or finish */
			if (bus == top)
				break;
			next = bus->self->bus_list.next;
			bus = bus->self->bus;
			continue;
		}
		dev = list_entry(next, struct pci_dev, bus_list);
		if (dev->subordinate) {
			/* this is a pci-pci bridge, do its devices next */
			next = dev->subordinate->devices.next;
			bus = dev->subordinate;
		} else
			next = dev->bus_list.next;

		pcie_caps_offset = dev->pcie_cap;
		if (pcie_caps_offset == 0)
			continue;

		pci_read_config_word(dev, pcie_caps_offset + PCI_EXP_DEVCTL, &devctl);
		devctl &= ~(PCI_EXP_DEVCTL_PAYLOAD | PCI_EXP_DEVCTL_READRQ);
		devctl |= new_values;
		pci_write_config_word(dev, pcie_caps_offset + PCI_EXP_DEVCTL, devctl);
	}

	return bus_max_num;
}

static int check_pci_linkup(unsigned long node, unsigned long index)
{
	unsigned long rc_debug;

	if (is_guest_or_emul()) {
		if (node == 0 && index == 0)
			return 0;
		else
			return 1;
	} else {
		rc_debug = read_piu_ior1(node, index, RCDEBUGINF1);
	}

	return !(rc_debug & 0x1);
}

static void set_rc_piu(unsigned long node, unsigned long index)
{
	unsigned int i, value;
	u32 rc_misc_ctrl;

	if (is_guest_or_emul())
		return;

	/* configure RC, set PCI-E root controller */
	write_rc_conf(node, index, RC_COMMAND, 0x00100007);
	write_rc_conf(node, index, RC_PORT_LINK_CTL, 0x1f0020);
	write_rc_conf(node, index, RC_EXP_DEVCTL, 0x2850);
	write_rc_conf(node, index, RC_EXP_DEVCTL2, 0x6);
	write_rc_conf(node, index, RC_ORDER_RULE_CTL, 0x0100);

	/* enable DBI_RO_WR_EN */
	rc_misc_ctrl = read_rc_conf(node, index, RC_MISC_CONTROL_1);
	write_rc_conf(node, index, RC_MISC_CONTROL_1, rc_misc_ctrl | 0x1);

	/* fix up DEVICE_ID_VENDOR_ID register */
	value = (PCI_DEVICE_ID_CHIP3 << 16) | PCI_VENDOR_ID_JN;
	write_rc_conf(node, index, RC_VENDOR_ID, value);

	/* set PCI-E root class code */
	value = read_rc_conf(node, index, RC_REVISION_ID);
	write_rc_conf(node, index, RC_REVISION_ID, (PCI_CLASS_BRIDGE_HOST << 16) | value);

	/* disable DBI_RO_WR_EN */
	write_rc_conf(node, index, RC_MISC_CONTROL_1, rc_misc_ctrl);

	write_rc_conf(node, index, RC_PRIMARY_BUS, 0xffffff);
	write_piu_ior0(node, index, PIUCONFIG0, 0x38056);
	write_piu_ior1(node, index, PIUCONFIG1, 0x2);
	write_piu_ior1(node, index, ERRENABLE, -1);

	/* set DMA offset value PCITODMA_OFFSET */
	write_piu_ior0(node, index, EPDMABAR, PCITODMA_OFFSET);
	if (IS_ENABLED(CONFIG_PCI_MSI)) {
		write_piu_ior0(node, index, MSIADDR, MSIX_MSG_ADDR);
		for (i = 0; i < 256; i++)
			write_piu_ior0(node, index, MSICONFIG0 + (i << 7), 0);
	}
}

static void set_intx(unsigned long node, unsigned long index,
			   unsigned long int_conf)
{
	if (is_guest_or_emul())
		return;

	write_piu_ior0(node, index, INTACONFIG, int_conf | (0x8UL << 10));
	write_piu_ior0(node, index, INTBCONFIG, int_conf | (0x4UL << 10));
	write_piu_ior0(node, index, INTCCONFIG, int_conf | (0x2UL << 10));
	write_piu_ior0(node, index, INTDCONFIG, int_conf | (0x1UL << 10));
}

static unsigned long get_rc_enable(unsigned long node)
{
	unsigned long rc_enable;

	if (is_guest_or_emul())
		return 1;

	rc_enable = sw64_io_read(node, IO_START);

	return rc_enable;
}

static int map_irq(const struct pci_dev *dev, u8 slot, u8 pin)
{
	struct pci_controller *hose = dev->sysdata;

	if (pci_pcie_type(dev) == PCI_EXP_TYPE_ROOT_PORT)
		return hose->service_irq;
	else
		return hose->int_irq;
}

static void hose_init(struct pci_controller *hose)
{
	unsigned long pci_io_base;

	hose->sparse_mem_base = 0;
	hose->sparse_io_base = 0;
	pci_io_base = IO_BASE | (hose->node << IO_NODE_SHIFT)
			      | PCI_BASE | (hose->index << IO_RC_SHIFT);

	hose->dense_mem_base = pci_io_base;
	hose->dense_io_base = pci_io_base | PCI_LEGACY_IO;
	hose->ep_config_space_base = __va(pci_io_base | PCI_EP_CFG);
	hose->rc_config_space_base = __va(pci_io_base | PCI_RC_CFG);

	hose->mem_space->start = pci_io_base + PCI_32BIT_MEMIO;
	hose->mem_space->end = hose->mem_space->start + PCI_32BIT_MEMIO_SIZE - 1;
	hose->mem_space->name = "pci memory space";
	hose->mem_space->flags = IORESOURCE_MEM;

	if (request_resource(&iomem_resource, hose->mem_space) < 0)
		pr_err("Failed to request MEM on hose %ld\n", hose->index);
	hose->pre_mem_space->start =  pci_io_base | PCI_64BIT_MEMIO;
	hose->pre_mem_space->end = hose->pre_mem_space->start + PCI_64BIT_MEMIO_SIZE - 1;
	hose->pre_mem_space->name = "pci pre mem space";
	hose->pre_mem_space->flags = IORESOURCE_MEM | IORESOURCE_PREFETCH | IORESOURCE_MEM_64;

	if (request_resource(&iomem_resource, hose->pre_mem_space) < 0)
		pr_err("Failed to request 64bit MEM on hose %ld\n", hose->index);
	hose->io_space->start = pci_io_base | PCI_LEGACY_IO;
	hose->io_space->end = hose->io_space->start + PCI_LEGACY_IO_SIZE - 1;
	hose->io_space->name = "pci io space";
	hose->io_space->flags = IORESOURCE_IO;

	if (request_resource(&ioport_resource, hose->io_space) < 0)
		pr_err("Failed to request IO on hose %ld\n", hose->index);
	hose->busn_space->name = "PCI busn";
	hose->busn_space->start = 0xff;
	hose->busn_space->end = 0xff;
	hose->busn_space->flags = IORESOURCE_BUS;
	hose->first_busno = hose->self_busno = hose->busn_space->start;
	hose->last_busno  = hose->busn_space->end;

	if (is_in_host()) {
		if (IS_ENABLED(CONFIG_PCI_MSI))
			memset(hose->piu_msiconfig, 0, 256/8);
	}
};

static struct sw64_pci_init_ops chip_pci_init_ops = {
	.map_irq = map_irq,
	.get_rc_enable = get_rc_enable,
	.hose_init = hose_init,
	.set_rc_piu = set_rc_piu,
	.check_pci_linkup = check_pci_linkup,
	.set_intx = set_intx,
};

void __init setup_chip_pci_ops(void)
{
	sw64_chip_init->pci_init = chip_pci_init_ops;
}
