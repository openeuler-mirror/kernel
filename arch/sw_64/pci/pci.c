// SPDX-License-Identifier: GPL-2.0
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/pci-ecam.h>

#include <asm/pci.h>
#include <asm/sw64_init.h>

/**
 * There are some special aspects to the Root Complex of Sunway:
 * 1. Root Complex config space base addr is different
 *    from EP config space base addr.
 * 2. For the case of multiple Root Complex, different
 *    Root Complex have config space base addr.
 *
 * These means that even if multiple Root Complex share
 * the same segment group number, their bus numbers can
 * still overlap.
 *
 * But due to a Xorg related issue, we can not overlap
 * the bus numbers of multiple Root Complex. So, after
 * scanning the Root Complex, use "last_bus" to record
 * the next bus number of the current maximum used bus
 * number, and use it as the start bus number of the
 * next Root Complex to be scanned.
 *
 * A question: when there is too much RCs, may 256 bus
 * numbers be insufficient?
 */
static unsigned char last_bus = 0;

void sw64_pci_root_bridge_prepare(struct pci_host_bridge *bridge)
{
	struct pci_controller *hose = NULL;
	struct resource_entry *entry = NULL;
	struct pci_bus *bus = bridge->bus;
	unsigned long flags = 0;
	unsigned int init_busnr = 0;

	hose = pci_bus_to_pci_controller(bus);

	resource_list_for_each_entry(entry, &bridge->windows) {
		flags = entry->res->flags;
		if (flags & IORESOURCE_IO) {
			entry->offset = entry->res->start;
			hose->io_space = entry->res;
		} else if (flags & IORESOURCE_BUS) {
			entry->res->start = last_bus;
			hose->busn_space = entry->res;
		} else if (flags & IORESOURCE_MEM) {
			if (!(flags & IORESOURCE_PREFETCH)) {
				entry->offset = entry->res->start - PCI_32BIT_MEMIO;
				hose->mem_space = entry->res;
			} else
				hose->pre_mem_space = entry->res;
		}
	}

	/**
	 * We scan Root Complex and update bus num in kernel,
	 * not in firmware. Firmware just pass 0x0-0xff via _CRS.
	 *
	 * So, need to update bus num of pci host bridge here.
	 */
	bridge->busnr = last_bus;
	dev_set_name(&bridge->dev, "pci%04x:%02x", pci_domain_nr(bus), last_bus);

	/**
	 * At this point, pci_bus has been created and use old
	 * bridge->busnr, so need to update bus->number here.
	 */
	bus->number = last_bus;

	bridge->swizzle_irq = pci_common_swizzle;
	bridge->map_irq = sw64_pci_map_irq;

	init_busnr = (0xff << 16) + ((last_bus + 1) << 8) + (last_bus);
	write_rc_conf(hose->node, hose->index, RC_PRIMARY_BUS, init_busnr);

	hose->first_busno = last_bus + (is_in_host() ? 1 : 0);

	pci_add_flags(PCI_REASSIGN_ALL_BUS);
}

static void sw64_pci_root_bridge_reserve_legacy_io(struct pci_host_bridge *bridge)
{
	struct pci_bus *bus = bridge->bus;
	struct resource_entry *entry = NULL;
	struct resource *res = NULL;

	resource_list_for_each_entry(entry, &bridge->windows) {
		if (!(entry->res->flags & IORESOURCE_IO))
			continue;

		res = kzalloc(sizeof(struct resource), GFP_KERNEL);
		if (res == NULL) {
			pr_err("alloc resource for legacy io out of mem\n");
			return;
		}

		res->name  = "legacy io";
		res->flags = IORESOURCE_IO;
		res->start = entry->res->start;
		res->end   = (res->start + 0xFFF) & 0xFFFFFFFFFFFFFFFFUL;

		pr_info("reserving legacy io %pR for domain %04x\n",
			res, pci_domain_nr(bus));
		if (request_resource(entry->res, res)) {
			pr_err("pci %04x:%02x reserve legacy io %pR failed\n",
				pci_domain_nr(bus), bus->number, res);
			kfree(res);
		}
	}
}

void sw64_pci_root_bridge_scan_finish_up(struct pci_host_bridge *bridge)
{
	struct pci_controller *hose = NULL;
	struct pci_bus *bus = NULL;
	unsigned int init_busnr = 0;

	bus = bridge->bus;

	hose = pci_bus_to_pci_controller(bus);
	hose->bus = bus;

	if (is_in_host())
		last_bus = chip_pcie_configure(hose);
	else {
		while (pci_find_bus(pci_domain_nr(bus), last_bus))
			last_bus++;
	}

	hose->last_busno = last_bus;
	hose->busn_space->end = last_bus;

	init_busnr = read_rc_conf(hose->node, hose->index, RC_PRIMARY_BUS);
	init_busnr &= ~(0xff << 16);
	init_busnr |= last_bus << 16;
	write_rc_conf(hose->node, hose->index, RC_PRIMARY_BUS, init_busnr);

	pci_bus_update_busn_res_end(bus, last_bus);
	last_bus++;

	pr_info("bus number update to %u\n", last_bus);

	if (is_in_host())
		sw64_pci_root_bridge_reserve_legacy_io(bridge);

	/**
	 * Root Complex of SW64 does not support ASPM, causing
	 * control field(_OSC) unable to be updated.
	 *
	 * Related logic can be found in "negotiate_os_control".
	 */
	bridge->native_aer = 1;
	bridge->native_pme = 1;

	/**
	 * Since some buggy firmwares may configure invalid bridge bus numbers,
	 * the kernel re-assigns all PCI bus numbers when scan Root Complex.
	 *
	 * However, users may trigger a pci bus rescan in the userspace by the
	 * command below:
	 *
	 * > echo 1 > /sys/bus/pci/rescan
	 *
	 * Unexpected errors may occur on the endpoint devices due to the re-assign
	 * bus numbers of upstream bridges.
	 *
	 * To work around this problem, the flag PCI_REASSIGN_ALL_BUS is set before
	 * scanning Root Complex and cleared after scanning Root Complex.
	 */
	pci_clear_flags(PCI_REASSIGN_ALL_BUS);
}

