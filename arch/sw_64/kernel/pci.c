// SPDX-License-Identifier: GPL-2.0
#include <linux/pci.h>
#include <linux/acpi.h>
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/syscore_ops.h>

#include <asm/sw64_init.h>

#include "pci_impl.h"

unsigned long rc_linkup;

/*
 * raw_pci_read/write - Platform-specific PCI config space access.
 */
int raw_pci_read(unsigned int domain, unsigned int bus, unsigned int devfn,
			int reg, int len, u32 *val)
{
	struct pci_bus *bus_tmp = pci_find_bus(domain, bus);

	if (bus_tmp)
		return bus_tmp->ops->read(bus_tmp, devfn, reg, len, val);

	return -EINVAL;
}

int raw_pci_write(unsigned int domain, unsigned int bus, unsigned int devfn,
			int reg, int len, u32 val)
{
	struct pci_bus *bus_tmp = pci_find_bus(domain, bus);

	if (bus_tmp)
		return bus_tmp->ops->write(bus_tmp, devfn, reg, len, val);

	return -EINVAL;
}

#ifdef CONFIG_ACPI
struct pci_bus *pci_acpi_scan_root(struct acpi_pci_root *root)
{
	return NULL;
}
#endif

/*
 * The PCI controller list.
 */

struct pci_controller *hose_head, **hose_tail = &hose_head;
static void __init pcibios_reserve_legacy_regions(struct pci_bus *bus);

/* Quirks */
static void quirk_isa_bridge(struct pci_dev *dev)
{
	dev->class = PCI_CLASS_BRIDGE_ISA << 8;
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82378, quirk_isa_bridge);

/* Just declaring that the power-of-ten prefixes are actually the
 * power-of-two ones doesn't make it true :)
 */
#define KB			1024
#define MB			(1024*KB)
#define GB			(1024*MB)

resource_size_t pcibios_default_alignment(void)
{
	if (is_in_guest())
		return PAGE_SIZE;
	else
		return 0;
}

resource_size_t pcibios_align_resource(void *data, const struct resource *res,
		resource_size_t size, resource_size_t align)
{
	struct pci_dev *dev = data;
	struct pci_controller *hose = dev->sysdata;
	unsigned long alignto;
	resource_size_t start = res->start;

	if (res->flags & IORESOURCE_IO) {
		/* Make sure we start at our min on all hoses */
		if (start - hose->io_space->start < PCIBIOS_MIN_IO)
			start = PCIBIOS_MIN_IO + hose->io_space->start;
		/*
		 * Put everything into 0x00-0xff region modulo 0x400
		 */
		if (start & 0x300)
			start = (start + 0x3ff) & ~0x3ff;
	} else if (res->flags & IORESOURCE_MEM) {
		/* Make sure we start at our min on all hoses */
		if (start - hose->mem_space->start < PCIBIOS_MIN_MEM)
			start = PCIBIOS_MIN_MEM + hose->mem_space->start;
		/*
		 * The following holds at least for the Low Cost
		 * Sw_64 implementation of the PCI interface:
		 *
		 * In sparse memory address space, the first
		 * octant (16MB) of every 128MB segment is
		 * aliased to the very first 16 MB of the
		 * address space (i.e., it aliases the ISA
		 * memory address space).  Thus, we try to
		 * avoid allocating PCI devices in that range.
		 * Can be allocated in 2nd-7th octant only.
		 * Devices that need more than 112MB of
		 * address space must be accessed through
		 * dense memory space only!
		 */

		/* Align to multiple of size of minimum base.  */
		alignto = max_t(resource_size_t, 0x1000UL, align);
		start = ALIGN(start, alignto);
		if (hose->sparse_mem_base && size <= 7 * 16*MB) {
			if (((start / (16*MB)) & 0x7) == 0) {
				start &= ~(128*MB - 1);
				start += 16*MB;
				start  = ALIGN(start, alignto);
			}
			if (start/(128*MB) != (start + size - 1)/(128*MB)) {
				start &= ~(128*MB - 1);
				start += (128 + 16)*MB;
				start  = ALIGN(start, alignto);
			}
		}
	}

	return start;
}

#undef KB
#undef MB
#undef GB

static int __init
pcibios_init(void)
{
	sw64_init_pci();
	return 0;
}
subsys_initcall(pcibios_init);

char *pcibios_setup(char *str)
{
	return str;
}

void pcibios_fixup_bus(struct pci_bus *bus)
{
	/* Propagate hose info into the subordinate devices.  */
	struct pci_controller *hose = bus->sysdata;
	struct pci_dev *dev = bus->self;

	if (!dev || bus->number == hose->first_busno) {
		bus->resource[0] = hose->io_space;
		bus->resource[1] = hose->mem_space;
		bus->resource[2] = hose->pre_mem_space;
	}
}

void pcibios_update_irq(struct pci_dev *dev, int irq)
{
	pci_write_config_byte(dev, PCI_INTERRUPT_LINE, irq);
}

/* Helper for generic DMA-mapping functions. */
struct pci_dev *sw64_gendev_to_pci(struct device *dev)
{
	if (dev && dev->bus == &pci_bus_type)
		return to_pci_dev(dev);

	return NULL;
}

void __init pcibios_claim_one_bus(struct pci_bus *b)
{
	struct pci_dev *dev;
	struct pci_bus *child_bus;

	list_for_each_entry(dev, &b->devices, bus_list) {
		int i;

		for (i = 0; i < PCI_NUM_RESOURCES; i++) {
			struct resource *r = &dev->resource[i];

			if (r->parent || !r->start || !r->flags)
				continue;
			if (r->flags & IORESOURCE_PCI_FIXED) {
				if (pci_claim_resource(dev, i) == 0)
					continue;

				pci_claim_bridge_resource(dev, i);
			}
		}
	}

	list_for_each_entry(child_bus, &b->children, node)
		pcibios_claim_one_bus(child_bus);
}

static void __init
pcibios_claim_console_setup(void)
{
	struct pci_bus *b;

	list_for_each_entry(b, &pci_root_buses, node)
		pcibios_claim_one_bus(b);
}

int __weak chip_pcie_configure(struct pci_controller *hose)
{
	return 0;
}

unsigned char last_bus = PCI0_BUS;
void __init common_init_pci(void)
{
	struct pci_controller *hose;
	struct pci_host_bridge *bridge;
	struct pci_bus *bus;
	unsigned int init_busnr;
	int need_domain_info = 0;
	int ret;
	unsigned long offset;

	/* Scan all of the recorded PCI controllers. */
	hose = hose_head;
	for (hose = hose_head; hose; hose = hose->next) {
		bridge = pci_alloc_host_bridge(0);
		if (!bridge)
			continue;
		hose->busn_space->start = last_bus;
		init_busnr = (0xff << 16) + ((last_bus + 1) << 8) + (last_bus);
		write_rc_conf(hose->node, hose->index, RC_PRIMARY_BUS, init_busnr);
		offset = hose->mem_space->start - PCI_32BIT_MEMIO;
		if (is_in_host())
			hose->first_busno = last_bus + 1;
		else
			hose->first_busno = last_bus;
		pci_add_resource_offset(&bridge->windows, hose->mem_space, offset);
		pci_add_resource_offset(&bridge->windows, hose->io_space, hose->io_space->start);
		pci_add_resource_offset(&bridge->windows, hose->pre_mem_space, 0);
		pci_add_resource_offset(&bridge->windows, hose->busn_space, 0);
		bridge->dev.parent = NULL;
		bridge->sysdata = hose;
		bridge->busnr = hose->busn_space->start;
		bridge->ops = &sw64_pci_ops;
		bridge->swizzle_irq = pci_common_swizzle;
		bridge->map_irq = sw64_map_irq;

		ret = pci_scan_root_bus_bridge(bridge);
		if (ret) {
			pci_free_host_bridge(bridge);
			continue;
		}

		bus = hose->bus = bridge->bus;
		hose->need_domain_info = need_domain_info;

		if (is_in_host())
			last_bus = chip_pcie_configure(hose);
		else
			while (pci_find_bus(pci_domain_nr(bus), last_bus))
				last_bus++;

		hose->last_busno = hose->busn_space->end = last_bus;
		init_busnr = read_rc_conf(hose->node, hose->index, RC_PRIMARY_BUS);
		init_busnr &= ~(0xff << 16);
		init_busnr |= last_bus << 16;
		write_rc_conf(hose->node, hose->index, RC_PRIMARY_BUS, init_busnr);
		pci_bus_update_busn_res_end(bus, last_bus);
		last_bus++;
	}

	pcibios_claim_console_setup();
#ifdef CONFIG_SUNWAY_IOMMU
	register_syscore_ops(&iommu_cpu_syscore_ops);
#endif

	if (is_in_host()) {
		list_for_each_entry(bus, &pci_root_buses, node)
			pcibios_reserve_legacy_regions(bus);
	}

	pr_info("SW arch assign unassigned resources.\n");

	pci_assign_unassigned_resources();

	for (hose = hose_head; hose; hose = hose->next) {
		bus = hose->bus;
		if (bus)
			pci_bus_add_devices(bus);
	}
}

struct pci_controller * __init
alloc_pci_controller(void)
{
	struct pci_controller *hose;

	hose = memblock_alloc(sizeof(*hose), SMP_CACHE_BYTES);

	*hose_tail = hose;
	hose_tail = &hose->next;

	return hose;
}

struct resource * __init
alloc_resource(void)
{
	struct resource *res;

	res = memblock_alloc(sizeof(*res), SMP_CACHE_BYTES);

	return res;
}

static struct pci_controller *pci_bus_to_hose(unsigned long bus)
{
	struct pci_controller *hose;

	for (hose = hose_head; hose; hose = hose->next) {
		if (bus >= hose->first_busno && bus <= hose->last_busno)
			return hose;
	}
	return NULL;
}

/* Provide information on locations of various I/O regions in physical
 * memory.  Do this on a per-card basis so that we choose the right hose.
 */

asmlinkage long sys_pciconfig_iobase(long which, unsigned long bus, unsigned long dfn)
{
	struct pci_controller *hose;

	hose = pci_bus_to_hose(bus);
	if (hose == NULL)
		return -ENODEV;

	switch (which & ~IOBASE_FROM_HOSE) {
	case IOBASE_HOSE:
		return hose->index;
	case IOBASE_SPARSE_MEM:
		return hose->sparse_mem_base;
	case IOBASE_DENSE_MEM:
		return hose->dense_mem_base;
	case IOBASE_SPARSE_IO:
		return hose->sparse_io_base;
	case IOBASE_DENSE_IO:
		return hose->dense_io_base;
	case IOBASE_ROOT_BUS:
		return hose->bus->number;
	}

	return -EOPNOTSUPP;
}

void pci_iounmap(struct pci_dev *dev, void __iomem *addr)
{
}
EXPORT_SYMBOL(pci_iounmap);

static void __init pcibios_reserve_legacy_regions(struct pci_bus *bus)
{
	struct pci_controller *hose = bus->sysdata;
	resource_size_t offset;
	struct resource *res;

	pr_debug("Reserving legacy ranges for domain %04x\n", pci_domain_nr(bus));

	/* Check for IO */
	if (!(hose->io_space->flags & IORESOURCE_IO))
		goto no_io;
	offset = (unsigned long)hose->io_space->start;
	res = kzalloc(sizeof(struct resource), GFP_KERNEL);
	BUG_ON(res == NULL);
	res->name = "Legacy IO";
	res->flags = IORESOURCE_IO;
	res->start = offset;
	res->end = (offset + 0xfff) & 0xfffffffffffffffful;
	pr_debug("Candidate legacy IO: %pR\n", res);
	if (request_resource(hose->io_space, res)) {
		pr_debug("PCI %04x:%02x Cannot reserve Legacy IO %pR\n",
				pci_domain_nr(bus), bus->number, res);
		kfree(res);
	}

no_io:
	return;
}

/* PCIe RC operations */
int sw6_pcie_read_rc_cfg(struct pci_bus *bus, unsigned int devfn,
		int where, int size, u32 *val)
{
	u32 data;
	struct pci_controller *hose = bus->sysdata;
	void __iomem *cfg_iobase = hose->rc_config_space_base;

	if (IS_ENABLED(CONFIG_PCI_DEBUG))
		pr_debug("rc read addr:%px bus %d, devfn %#x, where %#x size=%d\t",
				cfg_iobase + ((where & ~3) << 5), bus->number, devfn, where, size);

	if ((uintptr_t)where & (size - 1)) {
		*val = 0;
		return PCIBIOS_BAD_REGISTER_NUMBER;
	}

	if (unlikely(devfn > 0)) {
		*val = ~0;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	data = readl(cfg_iobase + ((where & ~3) << 5));

	switch (size) {
	case 1:
		*val = (data >> (8 * (where & 0x3))) & 0xff;
		break;
	case 2:
		*val = (data >> (8 * (where & 0x2))) & 0xffff;
		break;
	default:
		*val = data;
		break;
	}

	if (IS_ENABLED(CONFIG_PCI_DEBUG))
		pr_debug("*val %#x\n ", *val);

	return PCIBIOS_SUCCESSFUL;
}

int sw6_pcie_write_rc_cfg(struct pci_bus *bus, unsigned int devfn,
		int where, int size, u32 val)
{
	u32 data;
	u32 shift = 8 * (where & 3);
	struct pci_controller *hose = bus->sysdata;
	void __iomem *cfg_iobase = (void *)hose->rc_config_space_base;

	if ((uintptr_t)where & (size - 1))
		return PCIBIOS_BAD_REGISTER_NUMBER;

	switch (size) {
	case 1:
		data = readl(cfg_iobase + ((where & ~3) << 5));
		data &= ~(0xff << shift);
		data |= (val & 0xff) << shift;
		break;
	case 2:
		data = readl(cfg_iobase + ((where & ~3) << 5));
		data &= ~(0xffff << shift);
		data |= (val & 0xffff) << shift;
		break;
	default:
		data = val;
		break;
	}

	if (IS_ENABLED(CONFIG_PCI_DEBUG))
		pr_debug("rc write addr:%px bus %d, devfn %#x, where %#x *val %#x size %d\n",
				cfg_iobase + ((where & ~3) << 5), bus->number, devfn, where, val, size);

	writel(data, cfg_iobase + ((where & ~3) << 5));

	return PCIBIOS_SUCCESSFUL;
}

int sw6_pcie_config_read(struct pci_bus *bus, unsigned int devfn,
		int where, int size, u32 *val)
{
	struct pci_controller *hose = bus->sysdata;
	int ret = PCIBIOS_DEVICE_NOT_FOUND;

	if (is_guest_or_emul())
		return pci_generic_config_read(bus, devfn, where, size, val);

	hose->self_busno = hose->busn_space->start;

	if (unlikely(bus->number == hose->self_busno)) {
		ret = sw6_pcie_read_rc_cfg(bus, devfn, where, size, val);
	} else {
		if (test_bit(hose->node * 8 + hose->index, &rc_linkup)) {
			ret = pci_generic_config_read(bus, devfn, where, size, val);
		} else {
			return ret;
		}
	}
	return ret;
}

int sw6_pcie_config_write(struct pci_bus *bus, unsigned int devfn,
		int where, int size, u32 val)
{
	struct pci_controller *hose = bus->sysdata;

	if (is_guest_or_emul())
		return pci_generic_config_write(bus, devfn, where, size, val);

	hose->self_busno = hose->busn_space->start;

	if (unlikely(bus->number == hose->self_busno))
		return sw6_pcie_write_rc_cfg(bus, devfn, where, size, val);
	else
		return pci_generic_config_write(bus, devfn, where, size, val);
}

/*
 *sw6_pcie_valid_device - Check if a valid device is present on bus
 *@bus: PCI Bus structure
 *@devfn: device/function
 *
 *Return: 'true' on success and 'false' if invalid device is found
 */
static bool sw6_pcie_valid_device(struct pci_bus *bus, unsigned int devfn)
{
	struct pci_controller *hose = bus->sysdata;

	if (is_in_host()) {
		/* Only one device down on each root complex */
		if (bus->number == hose->self_busno && devfn > 0)
			return false;
	}

	return true;
}

/*
 *sw6_pcie_map_bus - Get configuration base
 *@bus: PCI Bus structure
 *@devfn: Device/function
 *@where: Offset from base
 *
 *Return: Base address of the configuration space needed to be
 *accessed.
 */
static void __iomem *sw6_pcie_map_bus(struct pci_bus *bus,
		unsigned int devfn, int where)
{
	struct pci_controller *hose = bus->sysdata;
	void __iomem *cfg_iobase;
	unsigned long relbus;

	if (!sw6_pcie_valid_device(bus, devfn))
		return NULL;

	relbus = (bus->number << 24) | (devfn << 16) | where;

	cfg_iobase = hose->ep_config_space_base + relbus;

	if (IS_ENABLED(CONFIG_PCI_DEBUG))
		pr_debug("addr:%px bus %d, devfn %d, where %d\n",
				cfg_iobase, bus->number, devfn, where);
	return cfg_iobase;
}

struct pci_ops sw64_pci_ops = {
	.map_bus = sw6_pcie_map_bus,
	.read    = sw6_pcie_config_read,
	.write   = sw6_pcie_config_write,
};

int sw64_map_irq(const struct pci_dev *dev, u8 slot, u8 pin)
{
	return sw64_chip_init->pci_init.map_irq(dev, slot, pin);
}

static void __init
sw64_init_host(unsigned long node, unsigned long index)
{
	struct pci_controller *hose;
	int ret = 0;

	hose = alloc_pci_controller();
	if (!hose) {
		printk("alloc NODE %ld RC %ld hose failed\n", node, index);
		return;
	}
	hose->iommu_enable = false;
	hose->io_space = alloc_resource();
	hose->mem_space = alloc_resource();
	hose->pre_mem_space = alloc_resource();
	hose->busn_space = alloc_resource();
	hose->index = index;
	hose->node = node;

	sw64_chip_init->pci_init.hose_init(hose);

	if (sw64_chip_init->pci_init.set_rc_piu)
		sw64_chip_init->pci_init.set_rc_piu(node, index);

	ret = sw64_chip_init->pci_init.check_pci_linkup(node, index);
	if (ret == 0) {
		/* Root Complex downstream port is link up */
		set_bit(node * 8 + index, &rc_linkup);          //8-bit per node
	}
}

void __weak set_devint_wken(int node) {}

void __init sw64_init_arch(void)
{
	if (IS_ENABLED(CONFIG_PCI)) {
		unsigned long node, cpu_num;
		unsigned long rc_enable;
		char id[8], msg[64];
		int i;

		pr_info("SW arch PCI initialize!\n");
		cpu_num = sw64_chip->get_cpu_num();

		for (node = 0; node < cpu_num; node++) {
			set_devint_wken(node);
			rc_enable = sw64_chip_init->pci_init.get_rc_enable(node);
			if (rc_enable == 0) {
				printk("PCIe is disabled on node %ld\n", node);
				continue;
			}
			for (i = 0; i < MAX_NR_RCS; i++) {
				if ((rc_enable >> i) & 0x1)
					sw64_init_host(node, i);
			}
			if ((rc_linkup >> node * 8) & 0xff) {
				memset(msg, 0, 64);
				sprintf(msg, "Node %ld: RC [ ", node);
				for (i = 0; i < MAX_NR_RCS; i++) {
					if ((rc_linkup >> (i + node * 8)) & 1) {
						memset(id, 0, 8);
						sprintf(id, "%d ", i);
						strcat(msg, id);
					}
				}
				strcat(msg, "] link up");
				pr_info("%s\n", msg);
			} else {
				pr_info("Node %ld: no RC link up\n", node);
			}
		}
	}
}

void __weak set_pcieport_service_irq(int node, int index) {}

static void __init sw64_init_intx(struct pci_controller *hose)
{
	unsigned long int_conf, node, val_node;
	unsigned long index, irq;
	int rcid;

	node = hose->node;
	index = hose->index;

	if (!node_online(node))
		val_node = next_node_in(node, node_online_map);
	else
		val_node = node;
	irq = irq_alloc_descs_from(NR_IRQS_LEGACY, 2, val_node);
	WARN_ON(irq < 0);
	irq_set_chip_and_handler(irq, &dummy_irq_chip, handle_level_irq);
	irq_set_status_flags(irq, IRQ_LEVEL);
	hose->int_irq = irq;
	irq_set_chip_and_handler(irq + 1, &dummy_irq_chip, handle_level_irq);
	hose->service_irq = irq + 1;
	rcid = cpu_to_rcid(0);

	printk_once(KERN_INFO "INTx are directed to node %d core %d.\n",
			((rcid >> 6) & 0x3), (rcid & 0x1f));
	int_conf = 1UL << 62 | rcid; /* rebase all intx on the first logical cpu */
	if (sw64_chip_init->pci_init.set_intx)
		sw64_chip_init->pci_init.set_intx(node, index, int_conf);

	set_pcieport_service_irq(node, index);
}

void __init sw64_init_irq(void)
{
	struct pci_controller *hose;

	/* Scan all of the recorded PCI controllers. */
	hose = hose_head;
	for (hose = hose_head; hose; hose = hose->next)
		sw64_init_intx(hose);
}

void __init
sw64_init_pci(void)
{
	common_init_pci();
}

static int setup_bus_dma_cb(struct pci_dev *pdev, void *data)
{
	pdev->dev.bus_dma_limit = DMA_BIT_MASK(32);
	return 0;
}

static void fix_bus_dma_limit(struct pci_dev *dev)
{
	pci_walk_bus(dev->subordinate, setup_bus_dma_cb, NULL);
	pr_info("Set zx200 bus_dma_limit to 32-bit\n");
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_ZHAOXIN, 0x071f, fix_bus_dma_limit);
