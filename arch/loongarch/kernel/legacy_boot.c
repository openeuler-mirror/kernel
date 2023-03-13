// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Yun Liu, liuyun@loongson.cn
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
#include <linux/acpi.h>
#include <linux/efi.h>
#include <linux/export.h>
#include <linux/memblock.h>
#include <linux/of_fdt.h>
#include <linux/initrd.h>
#include <asm/early_ioremap.h>
#include <asm/bootinfo.h>
#include <asm/loongson.h>
#include "legacy_boot.h"

#define MAX_CORE_PIC 256
#define PREFIX			"ACPI: "

#define MSI_MSG_ADDRESS		0x2FF00000
#define MSI_MSG_DEFAULT_COUNT	0xC0

struct boot_params *efi_bp;
struct loongsonlist_mem_map *g_mmap;
struct acpi_madt_lio_pic *acpi_liointc;
struct acpi_madt_eio_pic *acpi_eiointc[MAX_IO_PICS];

struct acpi_madt_ht_pic *acpi_htintc;
struct acpi_madt_lpc_pic *acpi_pchlpc;
struct acpi_madt_msi_pic *acpi_pchmsi[MAX_IO_PICS];
struct acpi_madt_bio_pic *acpi_pchpic[MAX_IO_PICS];

struct irq_domain *cpu_domain;
struct irq_domain *liointc_domain;
struct irq_domain *pch_lpc_domain;
struct irq_domain *pch_msi_domain[MAX_IO_PICS];
struct irq_domain *pch_pic_domain[MAX_IO_PICS];

char arcs_cmdline[COMMAND_LINE_SIZE];
int nr_io_pics;
int bpi_version;

struct acpi_madt_lio_pic liointc_default = {
		.address = LOONGSON_REG_BASE + 0x1400,
		.size = 256,
		.cascade = {2, 3},
		.cascade_map = {0x00FFFFFF, 0xff000000},
};

struct acpi_madt_lpc_pic pchlpc_default = {
	.address = LS7A_LPC_REG_BASE,
	.size = SZ_4K,
	.cascade = 19,
};

struct acpi_madt_eio_pic eiointc_default[MAX_IO_PICS];
struct acpi_madt_msi_pic pchmsi_default[MAX_IO_PICS];
struct acpi_madt_bio_pic pchpic_default[MAX_IO_PICS];

static int
acpi_parse_lapic(union acpi_subtable_headers *header, const unsigned long end)
{
	struct acpi_madt_local_apic *processor = NULL;

	processor = (struct acpi_madt_local_apic *)header;
	if (BAD_MADT_ENTRY(processor, end))
		return -EINVAL;

	acpi_table_print_madt_entry(&header->common);
	set_processor_mask(processor->id, processor->lapic_flags);

	return 0;
}

static int acpi_parse_madt_lapic(void)
{
	int ret;
	struct acpi_subtable_proc madt_proc[1];

	memset(madt_proc, 0, sizeof(madt_proc));
	madt_proc[0].id = ACPI_MADT_TYPE_LOCAL_APIC;
	madt_proc[0].handler = acpi_parse_lapic;
	ret = acpi_table_parse_entries_array(ACPI_SIG_MADT,
				sizeof(struct acpi_table_madt),
				madt_proc, ARRAY_SIZE(madt_proc),
				MAX_CORE_PIC);
	if (ret < 0) {
		pr_err(PREFIX "Error parsing LAPIC entries\n");
		return ret;
	}

	return 0;
}

static int bad_pch_pic(unsigned long address)
{
	if (nr_io_pics >= MAX_IO_PICS) {
		pr_warn("WARNING: Max # of I/O PCH_PICs (%d) exceeded (found %d), skipping\n",
			MAX_IO_PICS, nr_io_pics);
		return 1;
	}
	if (!address) {
		pr_warn("WARNING: Bogus (zero) I/O PCH_PIC address found in table, skipping!\n");
		return 1;
	}
	return 0;
}

void register_default_pic(int id, u32 address, u32 irq_base)
{
	int idx, entries;
	unsigned long addr;

	if (bad_pch_pic(address))
		return;

	idx = nr_io_pics;

	pchpic_default[idx].address = address;
	if (idx)
		pchpic_default[idx].address |= nid_to_addrbase(id) | HT1LO_OFFSET;
	pchpic_default[idx].id = id;
	pchpic_default[idx].version = 0;
	pchpic_default[idx].size = 0x1000;
	pchpic_default[idx].gsi_base = irq_base;

	msi_group[nr_io_pics].pci_segment = nr_io_pics;
	pch_group[nr_io_pics].node = msi_group[nr_io_pics].node = id;

	addr = pchpic_default[idx].address;
	entries = (((unsigned long)ls7a_readq(address) >> 48) & 0xff) + 1;
	pchmsi_default[idx].msg_address = MSI_MSG_ADDRESS;
	pchmsi_default[idx].start = entries;
	pchmsi_default[idx].count = MSI_MSG_DEFAULT_COUNT;

	eiointc_default[idx].cascade = 3;
	eiointc_default[idx].node = id;
	eiointc_default[idx].node_map = 1;

	if (idx) {
		eiointc_default[idx].cascade = 0x4;
		eiointc_default[0].node_map = 0x1DF;
		eiointc_default[idx].node_map = 0xFE20;
	}

	acpi_pchpic[idx] = &pchpic_default[idx];
	acpi_pchmsi[idx] = &pchmsi_default[idx];
	acpi_eiointc[idx] = &eiointc_default[idx];

	nr_io_pics++;
}

static int
acpi_parse_legacy_pch_pic(struct acpi_subtable_header *header,
		const unsigned long end)
{
	struct acpi_madt_io_apic *pch_pic = NULL;

	pch_pic = (struct acpi_madt_io_apic *)header;

	if (BAD_MADT_ENTRY(pch_pic, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	register_default_pic(pch_pic->id, pch_pic->address,
			pch_pic->global_irq_base);

	return 0;
}

/*
 * Parse PCH_PIC related entries in MADT
 * returns 0 on success, < 0 on error
 */
static int acpi_parse_madt_pch_pic_entries(void)
{
	int count;

	/*
	 * ACPI interpreter is required to complete interrupt setup,
	 * so if it is off, don't enumerate the io-apics with ACPI.
	 * If MPS is present, it will handle them,
	 * otherwise the system will stay in PIC mode
	 */
	if (acpi_disabled || acpi_noirq)
		return -ENODEV;

	count = acpi_table_parse_madt(ACPI_MADT_TYPE_IO_APIC,
			(void *)acpi_parse_legacy_pch_pic, MAX_IO_PICS);
	if (!count) {
		printk(KERN_ERR PREFIX "No PCH_PIC entries present\n");
		return -ENODEV;
	} else if (count < 0) {
		printk(KERN_ERR PREFIX "Error parsing PCH_PIC entry\n");
		return count;
	}

	return 0;
}

int legacy_madt_table_init(void)
{
	int error;

	/* Parse MADT LAPIC entries */
	error = acpi_parse_madt_lapic();
	if (!error) {
		acpi_liointc = &liointc_default;
		acpi_pchlpc = &pchlpc_default;
		acpi_parse_madt_pch_pic_entries();
	}
	if (error == -EINVAL) {
		pr_err(PREFIX
			"Invalid BIOS MADT, disabling ACPI\n");
		disable_acpi();
		return -1;
	}

	loongson_sysconf.nr_cpus = num_processors;
	return 0;
}

int setup_legacy_IRQ(void)
{
	int i, ret;
	struct irq_domain *pic_domain;

	if (!acpi_eiointc[0])
		cpu_data[0].options &= ~LOONGARCH_CPU_EXTIOI;

	ret = cpuintc_acpi_init(NULL, 0);
	if (ret) {
		printk("CPU domain init eror!\n");
		return -1;
	}
	cpu_domain = irq_find_matching_fwnode(cpuintc_handle, DOMAIN_BUS_ANY);
	if (!cpu_domain) {
		printk("CPU domain error!\n");
		return -1;
	}
	ret = liointc_acpi_init(cpu_domain, acpi_liointc);
	if (ret) {
		printk("Liointc domain init eror!\n");
		return -1;
	}
	liointc_domain = irq_find_matching_fwnode(liointc_handle, DOMAIN_BUS_ANY);
	if (cpu_has_extioi) {
		pr_info("Using EIOINTC interrupt mode\n");
		for (i = 0; i < nr_io_pics; i++) {
			ret = eiointc_acpi_init(cpu_domain, acpi_eiointc[i]);
			if (ret) {
				printk("Eiointc domain init eror!\n");
				return -1;
			}
			pch_pic_parse_madt((union acpi_subtable_headers *)acpi_pchpic[i], 0);
			pch_msi_parse_madt((union acpi_subtable_headers *)acpi_pchmsi[i], 0);
		}
	/* HTVECINTC maybe not use */
	} else {
		pr_info("Using HTVECINTC interrupt mode\n");
		ret = htvec_acpi_init(liointc_domain, acpi_htintc);
		if (ret) {
			printk("HTVECintc domain init eror!\n");
			return -1;
		}
		pch_pic_parse_madt((union acpi_subtable_headers *)acpi_pchpic[0], 0);
		pch_msi_parse_madt((union acpi_subtable_headers *)acpi_pchmsi[0], 0);
	}

	pic_domain = irq_find_matching_fwnode(pch_pic_handle[0], DOMAIN_BUS_ANY);
	if (!pic_domain) {
		printk("Pic domain error!\n");
		return -1;
	}
	if (pic_domain && !cpu_has_hypervisor)
		pch_lpc_acpi_init(pic_domain, acpi_pchlpc);

	return 0;
}

/*
 * Manage initrd
 */
#ifdef CONFIG_BLK_DEV_INITRD
static unsigned long init_initrd(unsigned long ps, unsigned long z)
{
	static int initalized;

	if (!ps || !z)
		return 0;

	initrd_start = (unsigned long)__va(ps);
	initrd_end = initrd_start + z;
	/*
	 * Board specific code or command line parser should have
	 * already set up initrd_start and initrd_end. In these cases
	 * perfom sanity checks and use them if all looks good.
	 */
	if (initrd_start < PAGE_OFFSET || initrd_end <= initrd_start) {
		pr_err("initrd start load address error!");
		goto disable;
	}

	if (initrd_start & ~PAGE_MASK) {
		pr_err("initrd start must be page aligned\n");
		goto disable;
	}

	memblock_reserve(__pa(initrd_start), z);
	initrd_below_start_ok = 1;

	if (!initalized)
		pr_info("Initial ramdisk at: 0x%lx (%lu bytes)\n",
				initrd_start, z);
	initalized = 1;

	return 0;
disable:
	printk(KERN_CONT " - disabling initrd\n");
	initrd_start = 0;
	initrd_end = 0;
	return 0;
}

static int early_initrd(char *p)
{
	unsigned long start, size;
	char *endp;

	if (!efi_bp)
		return 0;
	start = memparse(p, &endp);
	if (*endp == ',')
		size = memparse(endp + 1, NULL);

	if (start + size > PFN_PHYS(max_low_pfn)) {
		pr_err(KERN_INFO "Initrd physical address is out of memory!");
		return 0;
	}

	init_initrd(start, size);

	return 0;
}
early_param("initrd", early_initrd);

static int rd_start_early(char *p)
{
	unsigned long start;

	if (!efi_bp)
		return 0;

	start = memparse(p, &p);
	initrd_start = start;
	initrd_end += start;
	init_initrd(__pa(start), initrd_end - start);

	return 0;
}
early_param("rd_start", rd_start_early);

static int rd_size_early(char *p)
{
	unsigned long size;

	if (!efi_bp)
		return 0;
	size = memparse(p, &p);
	initrd_end += size;

	init_initrd(__pa(initrd_start), size);
	return 0;
}
early_param("rd_size", rd_size_early);

#else  /* !CONFIG_BLK_DEV_INITRD */
static unsigned long init_initrd(void)
{
	return 0;
}
#endif

void fw_init_cmdline(unsigned long argc, unsigned long cmdp)
{
	int i;
	char **_fw_argv;

	_fw_argv = (char **)cmdp;

	arcs_cmdline[0] = '\0';
	for (i = 1; i < argc; i++) {
		strlcat(arcs_cmdline, _fw_argv[i], COMMAND_LINE_SIZE);
		if (i < (argc - 1))
			strlcat(arcs_cmdline, " ", COMMAND_LINE_SIZE);
	}
	strlcat(boot_command_line, arcs_cmdline, COMMAND_LINE_SIZE);
}

static u8 ext_listhdr_checksum(u8 *buffer, u32 length)
{
	u8 sum = 0;
	u8 *end = buffer + length;

	while (buffer < end) {
		sum = (u8)(sum + *(buffer++));
	}

	return (sum);
}

static int parse_mem(struct _extention_list_hdr *head)
{
	g_mmap = (struct loongsonlist_mem_map *)head;
	if (ext_listhdr_checksum((u8 *)g_mmap, head->length)) {
		printk("mem checksum error\n");
		return -EPERM;
	}
	return 0;
}

/* legacy firmware passed, add use this info if need vbios */
static int parse_vbios(struct _extention_list_hdr *head)
{
	struct loongsonlist_vbios *pvbios;
	pvbios = (struct loongsonlist_vbios *)head;

	if (ext_listhdr_checksum((u8 *)pvbios, head->length)) {
		printk("vbios_addr checksum error\n");
		return -EPERM;
	}
	return 0;
}

/* legacy firmware passed, add use this info if need screeninfo KVM? */
static int parse_screeninfo(struct _extention_list_hdr *head)
{
	struct loongsonlist_screeninfo *pscreeninfo;

	pscreeninfo = (struct loongsonlist_screeninfo *)head;
	if (ext_listhdr_checksum((u8 *)pscreeninfo, head->length)) {
		printk("screeninfo_addr checksum error\n");
		return -EPERM;
	}

	memcpy(&screen_info, &pscreeninfo->si, sizeof(screen_info));
	return 0;
}

static int list_find(struct boot_params *bp)
{
	struct _extention_list_hdr *fhead = NULL;
	unsigned long index;

	fhead = bp->extlist;
	if (!fhead) {
		printk("the bp ext struct empty!\n");
		return -1;
	}
	do {
		if (memcmp(&(fhead->signature), LOONGSON_MEM_SIGNATURE, 3) == 0) {
			if (parse_mem(fhead) != 0) {
				printk("parse mem failed\n");
				return -EPERM;
			}
		} else if (memcmp(&(fhead->signature), LOONGSON_VBIOS_SIGNATURE, 5) == 0) {
			if (parse_vbios(fhead) != 0) {
				printk("parse vbios failed\n");
				return -EPERM;
			}
		} else if (memcmp(&(fhead->signature), LOONGSON_SCREENINFO_SIGNATURE, 5) == 0) {
			if (parse_screeninfo(fhead) != 0) {
				printk("parse screeninfo failed\n");
				return -EPERM;
			}
		}
		fhead = (struct _extention_list_hdr *)fhead->next;
		index = (unsigned long)fhead;
	} while (index);
	return 0;
}

unsigned int bpi_init(void)
{
	return list_find(efi_bp);
}

static void register_addrs_set(u64 *registers, const u64 addr, int num)
{
	u64 i;

	for (i = 0; i < num; i++) {
		*registers = (i << 44) | addr;
		registers++;
	}
}

static int get_bpi_version(u64 *signature)
{
	u8 data[9];
	int version = BPI_VERSION_NONE;
	data[8] = 0;
	memcpy(data, signature, sizeof(*signature));
	if (kstrtoint(&data[3], 10, &version))
		return BPI_VERSION_NONE;
	return version;
}

static void __init parse_bpi_flags(void)
{
	if (efi_bp->flags & BPI_FLAGS_UEFI_SUPPORTED) {
		set_bit(EFI_BOOT, &efi.flags);
	} else {
		clear_bit(EFI_BOOT, &efi.flags);
	}
}

unsigned long legacy_boot_init(unsigned long argc, unsigned long cmdptr, unsigned long bpi)
{
	int ret;

	if (!bpi || (argc < 2))
		return -1;
	efi_bp = (struct boot_params *)bpi;
	bpi_version = get_bpi_version(&efi_bp->signature);
	pr_info("BPI%d with boot flags %llx.\n", bpi_version, efi_bp->flags);
	if (bpi_version == BPI_VERSION_NONE) {
		if (cpu_has_hypervisor)
			pr_err("Fatal error, bpi ver BONE!\n");
		else
			panic("Fatal error, bpi ver BONE!\n");
	} else if (bpi_version == BPI_VERSION_V2)
		parse_bpi_flags();

	fw_init_cmdline(argc, cmdptr);
	ret = bpi_init();
	if (ret) {
		pr_err("init legacy firmware error!\n");
		return -1;
	}

	return 0;
}

static int __init add_legacy_isa_io(struct fwnode_handle *fwnode, unsigned long isa_base)
{
	int ret = 0;
	unsigned long vaddr;
	struct logic_pio_hwaddr *range;

	range = kzalloc(sizeof(*range), GFP_ATOMIC);
	if (!range)
		return -ENOMEM;

	range->fwnode = fwnode;
	range->size = ISA_IOSIZE;
	range->hw_start = isa_base;
	range->flags = LOGIC_PIO_CPU_MMIO;

	ret = logic_pio_register_range(range);
	if (ret) {
		kfree(range);
		return ret;
	}

	if (range->io_start != 0) {
		logic_pio_unregister_range(range);
		kfree(range);
		return -EINVAL;
	}

	vaddr = (unsigned long)(PCI_IOBASE + range->io_start);
	ret = ioremap_page_range(vaddr, vaddr + range->size, range->hw_start, pgprot_device(PAGE_KERNEL));
	return ret;
}

static struct fwnode_handle * __init parse_isa_base(u64 *cpu_addr)
{
	struct device_node *np;
	const __be32 *ranges = NULL;
	int len;
	struct device_node *node;

	for_each_node_by_name(np, "isa") {
		node = of_node_get(np);

		if (!node)
			break;

		ranges = of_get_property(node, "ranges", &len);

		if (!ranges || (ranges && len > 0))
			break;
	}
	if (ranges) {
		ranges += 2;
		*cpu_addr = of_translate_address(np, ranges);
		return &np->fwnode;
	}

	return NULL;
}

static int __init register_legacy_isa_io(void)
{
	struct fwnode_handle *fwnode;
	u64 cpu_addr;

	if (!acpi_disabled) {
		cpu_addr = ISA_PHY_IOBASE;
		fwnode = kzalloc(sizeof(*fwnode), GFP_ATOMIC);
	} else {
		fwnode = parse_isa_base(&cpu_addr);
	}

	if (fwnode)
		add_legacy_isa_io(fwnode, cpu_addr);

	return 0;
}
arch_initcall(register_legacy_isa_io);
