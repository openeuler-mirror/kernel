// SPDX-License-Identifier: GPL-2.0
#include <linux/pci.h>
#include <linux/clocksource.h>

#include <asm/sw64_init.h>
#include <asm/sw64io.h>
#include <asm/pci.h>
#include <asm/irq_impl.h>
#include <asm/wrperfmon.h>
#include "../../../../drivers/pci/pci.h"

static u64 read_longtime(struct clocksource *cs)
{
	u64 result;
	unsigned long node;

	if (IS_ENABLED(CONFIG_SW64_FPGA) || IS_ENABLED(CONFIG_SW64_SIM))
		node = 0;
	else
		node = __this_cpu_read(hard_node_id);
	result = sw64_io_read(node, LONG_TIME);

	return result;
}

static int longtime_enable(struct clocksource *cs)
{
	switch (cpu_desc.model) {
	case CPU_SW3231:
		sw64_io_write(0, GPIO_SWPORTA_DR, 0);
		sw64_io_write(0, GPIO_SWPORTA_DDR, 0xff);
		break;
	case CPU_SW831:
		sw64_io_write(0, LONG_TIME_START_EN, 0x1);
		break;
	default:
		break;
	}

	return 0;
}

static struct clocksource clocksource_longtime = {
	.name	= "longtime",
	.rating	= 100,
	.enable	= longtime_enable,
	.flags	= CLOCK_SOURCE_IS_CONTINUOUS,
	.mask	= CLOCKSOURCE_MASK(64),
	.shift	= 0,
	.mult	= 0,
	.read	= read_longtime,
};

static u64 read_vtime(struct clocksource *cs)
{
	u64 result;
	unsigned long vtime_addr = IO_BASE | LONG_TIME;

	result = rdio64(vtime_addr);
	return result;
}

static int vtime_enable(struct clocksource *cs)
{
	return 0;
}

static struct clocksource clocksource_vtime = {
	.name	= "vtime",
	.rating	= 100,
	.enable	= vtime_enable,
	.flags	= CLOCK_SOURCE_IS_CONTINUOUS,
	.mask	= CLOCKSOURCE_MASK(64),
	.shift	= 0,
	.mult	= 0,
	.read	= read_vtime,
};

void setup_chip_clocksource(void)
{
#ifdef CONFIG_SW64_SIM
	clocksource_register_khz(&clocksource_longtime, 400000); /* Hardware Simulator 400Mhz */
#elif defined(CONFIG_SW64_FPGA)
	clocksource_register_khz(&clocksource_longtime, 1000); /* FPGA 1Mhz */
#else
	if (is_in_host())
		clocksource_register_khz(&clocksource_longtime, 25000);
	else
		clocksource_register_khz(&clocksource_vtime, 25000);
#endif
}

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

static int chip3_get_cpu_nums(void)
{
	unsigned long trkmode;
	int cpus;

	if (is_guest_or_emul())
		return 1;

	trkmode = sw64_io_read(0, TRKMODE);
	trkmode = (trkmode >> 6) & 0x3;
	cpus = 1 << trkmode;

	return cpus;
}

static unsigned long chip3_get_vt_node_mem(int nodeid)
{
	return *(unsigned long *)MMSIZE & MMSIZE_MASK;
}

static unsigned long chip3_get_node_mem(int nodeid)
{
	unsigned long mc_config, mc_online, mc_cap, mc_num;
	unsigned long node_mem;

	mc_config = sw64_io_read(nodeid, MC_CAP_CFG) & 0xf;
	mc_cap = (1UL << mc_config) << 28;
	mc_online = sw64_io_read(nodeid, MC_ONLINE) & 0xff;
	mc_num = __kernel_ctpop(mc_online);
	node_mem = mc_cap * mc_num;

	return node_mem;
}

static void chip3_setup_vt_core_start(struct cpumask *cpumask)
{
	int i;
	unsigned long coreonline;

	coreonline = sw64_io_read(0, CORE_ONLINE);

	for (i = 0; i < 64 ; i++) {
		if (coreonline & (1UL << i))
			cpumask_set_cpu(i, cpumask);
	}
}

static void chip3_setup_core_start(struct cpumask *cpumask)
{
	int i, j, cpus;
	unsigned long coreonline;

	cpus = chip3_get_cpu_nums();
	for (i = 0; i < cpus; i++) {
		coreonline = sw64_io_read(i, CORE_ONLINE);
		for (j = 0; j < 32 ; j++) {
			if (coreonline & (1UL << j))
				cpumask_set_cpu(i * 32 + j, cpumask);
		}
	}

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

static int chip3_check_pci_vt_linkup(unsigned long node, unsigned long index)
{
	if (node == 0 && index == 0)
		return 0;
	else
		return 1;
}

static int chip3_check_pci_linkup(unsigned long node, unsigned long index)
{
	unsigned long rc_debug;

#ifdef CONFIG_SW64_FPGA           //for PCIE4.0
	printk("waiting for link up...\n");
	if (index == 0)
		sw64_io_write(node, PIU_TOP0_CONFIG, 0x10011);
	else
		sw64_io_write(node, PIU_TOP1_CONFIG, 0x10011);
	mdelay(10);
	rc_debug = read_piu_ior1(node, index, RCDEBUGINF1);
	while (!(rc_debug & 0x1)) {
		udelay(10);
		rc_debug = read_piu_ior1(node, index, RCDEBUGINF1);
	}
	mdelay(10);
#endif
#ifdef CONFIG_SW64_SIM
	printk("waiting for link up...\n");
	rc_debug = read_piu_ior1(node, index, RCDEBUGINF1);
	while (!(rc_debug & 0x1)) {
		udelay(10);
		rc_debug = read_piu_ior1(node, index, RCDEBUGINF1);
	}
#endif
	rc_debug = read_piu_ior1(node, index, RCDEBUGINF1);

	return !(rc_debug & 0x1);
}

static void chip3_set_rc_piu(unsigned long node, unsigned long index)
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

	if (IS_ENABLED(CONFIG_SUSPEND) && IS_ENABLED(CONFIG_SW64_SIM)) {
		value = read_rc_conf(node, index, RC_LINK_STAT);
		value |= 0x3;
		write_rc_conf(node, index, RC_LINK_STAT, value);
	}

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

static void chip3_set_intx(unsigned long node, unsigned long index,
			   unsigned long int_conf)
{
	if (is_guest_or_emul())
		return;

	write_piu_ior0(node, index, INTACONFIG, int_conf | (0x8UL << 10));
	write_piu_ior0(node, index, INTBCONFIG, int_conf | (0x4UL << 10));
	write_piu_ior0(node, index, INTCCONFIG, int_conf | (0x2UL << 10));
	write_piu_ior0(node, index, INTDCONFIG, int_conf | (0x1UL << 10));
}

static unsigned long chip3_get_rc_enable(unsigned long node)
{
	unsigned long rc_enable;

	if (is_guest_or_emul())
		return 1;

	if (!IS_ENABLED(CONFIG_SW64_ASIC)) {
		rc_enable = 0x1;
		sw64_io_write(node, IO_START, rc_enable);
	}
	rc_enable = sw64_io_read(node, IO_START);

	return rc_enable;
}

static int chip3_map_irq(const struct pci_dev *dev, u8 slot, u8 pin)
{
	struct pci_controller *hose = dev->sysdata;

	if (pci_pcie_type(dev) == PCI_EXP_TYPE_ROOT_PORT)
		return hose->service_irq;
	else
		return hose->int_irq;
}

extern struct pci_controller *hose_head, **hose_tail;
static void sw6_handle_intx(unsigned int offset)
{
	struct pci_controller *hose;
	unsigned long value;

	hose = hose_head;
	for (hose = hose_head; hose; hose = hose->next) {
		value = read_piu_ior0(hose->node, hose->index, INTACONFIG + (offset << 7));
		if (value >> 63) {
			value = value & (~(1UL << 62));
			write_piu_ior0(hose->node, hose->index, INTACONFIG + (offset << 7), value);
			handle_irq(hose->int_irq);
			value = value | (1UL << 62);
			write_piu_ior0(hose->node, hose->index, INTACONFIG + (offset << 7), value);
		}

		if (IS_ENABLED(CONFIG_PCIE_PME)) {
			value = read_piu_ior0(hose->node, hose->index, PMEINTCONFIG);
			if (value >> 63) {
				handle_irq(hose->service_irq);
				write_piu_ior0(hose->node, hose->index, PMEINTCONFIG, value);
			}
		}

		if (IS_ENABLED(CONFIG_PCIEAER)) {
			value = read_piu_ior0(hose->node, hose->index, AERERRINTCONFIG);
			if (value >> 63) {
				handle_irq(hose->service_irq);
				write_piu_ior0(hose->node, hose->index, AERERRINTCONFIG, value);
			}
		}

		if (hose->iommu_enable) {
			value = read_piu_ior0(hose->node, hose->index, IOMMUEXCPT_STATUS);
			if (value >> 63)
				handle_irq(hose->int_irq);
		}
	}
}

static void chip3_device_interrupt(unsigned long irq_info)
{
	unsigned int i;

	if (is_guest_or_emul()) {
		handle_irq(irq_info);
		return;
	}

	for (i = 0; i < 4; i++) {
		if ((irq_info >> i) & 0x1)
			sw6_handle_intx(i);
	}
}

static void chip3_hose_init(struct pci_controller *hose)
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

static void chip3_init_ops_fixup(void)
{
	if (is_guest_or_emul()) {
		sw64_chip_init->early_init.setup_core_start = chip3_setup_vt_core_start;
		sw64_chip_init->early_init.get_node_mem = chip3_get_vt_node_mem;
		sw64_chip_init->pci_init.check_pci_linkup = chip3_check_pci_vt_linkup;
	}
};

static void chip3_ops_fixup(void)
{
	if (is_guest_or_emul())
		sw64_chip->suspend = NULL;
};

static struct sw64_chip_init_ops chip3_chip_init_ops = {
	.early_init = {
		.setup_core_start = chip3_setup_core_start,
		.get_node_mem = chip3_get_node_mem,
	},
	.pci_init = {
		.map_irq = chip3_map_irq,
		.get_rc_enable = chip3_get_rc_enable,
		.hose_init = chip3_hose_init,
		.set_rc_piu = chip3_set_rc_piu,
		.check_pci_linkup = chip3_check_pci_linkup,
		.set_intx = chip3_set_intx,
	},
	.fixup = chip3_init_ops_fixup,
};

static struct sw64_chip_ops chip3_chip_ops = {
	.get_cpu_num = chip3_get_cpu_nums,
	.fixup = chip3_ops_fixup,
};

void __init sw64_setup_chip_ops(void)
{
	sw64_chip_init = &chip3_chip_init_ops;
	sw64_chip = &chip3_chip_ops;
}

/* Performance counter hook.  A module can override this to do something useful. */
static void dummy_perf(unsigned long vector, struct pt_regs *regs)
{
	irq_err_count++;
	pr_crit("Performance counter interrupt!\n");
}

void (*perf_irq)(unsigned long, struct pt_regs*) = dummy_perf;
EXPORT_SYMBOL(perf_irq);

#ifdef CONFIG_PCI_MSI
extern void handle_pci_msi_interrupt(unsigned long type,
				     unsigned long vector,
				     unsigned long pci_msi1_addr);
#else
void handle_pci_msi_interrupt(unsigned long type,
			      unsigned long vector, unsigned long pci_msi1_addr)
{
	pr_warn("SW arch disable CONFIG_PCI_MSI option.\n");
}
#endif

static void handle_fault_int(void)
{
	int node;

	node = __this_cpu_read(hard_node_id);
	printk("enter fault int, si_fault_stat = %#lx\n",
			sw64_io_read(node, SI_FAULT_STAT));
	sw64_io_write(node, SI_FAULT_INT_EN, 0);
	sw64_io_write(node, DLI_RLTD_FAULT_INTEN, 0);
	sw64_io_write(node, DUAL_CG0_FAULT_INTEN, 0);
	sw64_io_write(node, DUAL_CG1_FAULT_INTEN, 0);
	sw64_io_write(node, DUAL_CG2_FAULT_INTEN, 0);
	sw64_io_write(node, DUAL_CG3_FAULT_INTEN, 0);
	sw64_io_write(node, DUAL_CG4_FAULT_INTEN, 0);
	sw64_io_write(node, DUAL_CG5_FAULT_INTEN, 0);
	sw64_io_write(node, DUAL_CG6_FAULT_INTEN, 0);
	sw64_io_write(node, DUAL_CG7_FAULT_INTEN, 0);
}

static void handle_mt_int(void)
{
	printk("enter mt int\n");
}

static void handle_nmi_int(void)
{
	printk("enter nmi int\n");
}

static void handle_dev_int(struct pt_regs *regs)
{
	unsigned long config_val, val, stat;
	int node = 0;
	unsigned int hwirq;

	config_val = sw64_io_read(node, DEV_INT_CONFIG);
	val = config_val & (~(1UL << 8));
	sw64_io_write(node, DEV_INT_CONFIG, val);
	stat = sw64_io_read(node, MCU_DVC_INT);

	while (stat) {
		hwirq = ffs(stat) - 1;
		handle_domain_irq(NULL, hwirq, regs);
		stat &= ~(1UL << hwirq);
	}
	/*do handle irq */

	sw64_io_write(node, DEV_INT_CONFIG, config_val);
}

asmlinkage void do_entInt(unsigned long type, unsigned long vector,
			  unsigned long irq_arg, struct pt_regs *regs)
{
	struct pt_regs *old_regs;

	if (is_guest_or_emul()) {
		if ((type & 0xffff) > 15) {
			vector = type;
			if (vector == 16)
				type = INT_INTx;
			else
				type = INT_MSI;
		}
	}

	switch (type & 0xffff) {
	case INT_MSI:
		old_regs = set_irq_regs(regs);
		handle_pci_msi_interrupt(type, vector, irq_arg);
		set_irq_regs(old_regs);
		return;
	case INT_INTx:
		old_regs = set_irq_regs(regs);
		chip3_device_interrupt(vector);
		set_irq_regs(old_regs);
		return;

	case INT_IPI:
#ifdef CONFIG_SMP
		handle_ipi(regs);
		return;
#else
		irq_err_count++;
		pr_crit("Interprocessor interrupt? You must be kidding!\n");
#endif
		break;
	case INT_RTC:
		old_regs = set_irq_regs(regs);
		sw64_timer_interrupt();
		set_irq_regs(old_regs);
		return;
	case INT_VT_SERIAL:
		old_regs = set_irq_regs(regs);
		handle_irq(type);
		set_irq_regs(old_regs);
		return;
	case INT_VT_HOTPLUG:
		old_regs = set_irq_regs(regs);
		handle_irq(type);
		set_irq_regs(old_regs);
		return;
	case INT_PC0:
		perf_irq(PERFMON_PC0, regs);
		return;
	case INT_PC1:
		perf_irq(PERFMON_PC1, regs);
		return;
	case INT_DEV:
		old_regs = set_irq_regs(regs);
		handle_dev_int(regs);
		set_irq_regs(old_regs);
		return;
	case INT_FAULT:
		old_regs = set_irq_regs(regs);
		handle_fault_int();
		set_irq_regs(old_regs);
		return;
	case INT_MT:
		old_regs = set_irq_regs(regs);
		handle_mt_int();
		set_irq_regs(old_regs);
		return;
	case INT_NMI:
		old_regs = set_irq_regs(regs);
		handle_nmi_int();
		set_irq_regs(old_regs);
		return;
	default:
		pr_crit("Hardware intr	%ld %lx? uh?\n", type, vector);
	}
	pr_crit("PC = %016lx PS = %04lx\n", regs->pc, regs->ps);
}
EXPORT_SYMBOL(do_entInt);

/*
 * Early fix up the chip3 Root Complex settings
 */
static void chip3_pci_fixup_root_complex(struct pci_dev *dev)
{
	int i;
	struct pci_bus *bus = dev->bus;
	struct pci_controller *hose = bus->sysdata;

	hose->self_busno = hose->busn_space->start;

	if (likely(bus->number == hose->self_busno)) {
		if (IS_ENABLED(CONFIG_HOTPLUG_PCI_PCIE)) {
			/* Check Root Complex port again */
			dev->is_hotplug_bridge = 0;
			dev->current_state = PCI_D0;
		}

		dev->class &= 0xff;
		dev->class |= PCI_CLASS_BRIDGE_PCI << 8;
		for (i = 0; i < PCI_NUM_RESOURCES; i++) {
			dev->resource[i].start = 0;
			dev->resource[i].end   = 0;
			dev->resource[i].flags = IORESOURCE_PCI_FIXED;
		}
	}
	atomic_inc(&dev->enable_cnt);

	dev->no_msi = 1;
}

DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_JN, PCI_DEVICE_ID_CHIP3, chip3_pci_fixup_root_complex);
