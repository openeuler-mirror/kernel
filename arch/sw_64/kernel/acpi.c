// SPDX-License-Identifier: GPL-2.0

#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/irqdomain.h>

#include <asm/early_ioremap.h>

int acpi_disabled = 1;
EXPORT_SYMBOL(acpi_disabled);
int acpi_noirq;				/* skip ACPI IRQ initialization */
int acpi_pci_disabled;		/* skip ACPI PCI scan and IRQ initialization */
EXPORT_SYMBOL(acpi_pci_disabled);
int acpi_strict;
u64 arch_acpi_wakeup_start;
u64 acpi_saved_sp_s3;

#define MAX_LOCAL_APIC 256

#define PREFIX			"ACPI: "
/*
 * The default interrupt routing model is PIC (8259).  This gets
 * overridden if IOAPICs are enumerated (below).
 */
enum acpi_irq_model_id acpi_irq_model = ACPI_IRQ_MODEL_IOSAPIC;
void __iomem *__init __acpi_map_table(unsigned long phys, unsigned long size)
{
	if (!phys || !size)
		return NULL;

	return early_ioremap(phys, size);
}
void __init __acpi_unmap_table(void __iomem *map, unsigned long size)
{
	if (!map || !size)
		return;

	early_iounmap(map, size);
}
/*
 * Following __acpi_xx functions should be implemented for sepecific cpu.
 */
int acpi_gsi_to_irq(u32 gsi, unsigned int *irqp)
{
	if (irqp != NULL)
		*irqp = acpi_register_gsi(NULL, gsi, -1, -1);

	return 0;
}
EXPORT_SYMBOL_GPL(acpi_gsi_to_irq);

int acpi_isa_irq_to_gsi(unsigned int isa_irq, u32 *gsi)
{
	if (gsi)
		*gsi = isa_irq;

	return 0;
}

int (*acpi_suspend_lowlevel)(void);

/*
 * success: return IRQ number (>=0)
 * failure: return < 0
 */
static struct irq_domain *irq_default_domain;
int acpi_register_gsi(struct device *dev, u32 gsi, int trigger, int polarity)
{
	u32 irq;

	irq = irq_find_mapping(irq_default_domain, gsi);

	return irq;
}
EXPORT_SYMBOL_GPL(acpi_register_gsi);

void acpi_unregister_gsi(u32 gsi)
{

}
EXPORT_SYMBOL_GPL(acpi_unregister_gsi);
/*
 *  ACPI based hotplug support for CPU
 */
#ifdef CONFIG_ACPI_HOTPLUG_CPU
#include <acpi/processor.h>

/* wrapper to silence section mismatch warning */
int __ref acpi_map_lsapic(acpi_handle handle, int physid, int *pcpu)
{
	return 0;
}
EXPORT_SYMBOL(acpi_map_lsapic);

int acpi_unmap_lsapic(int cpu)
{
	return 0;
}
EXPORT_SYMBOL(acpi_unmap_lsapic);
#endif /* CONFIG_ACPI_HOTPLUG_CPU */

u8 acpi_checksum(u8 *table, u32 length)
{
	u8 ret = 0;

	while (length--) {
		ret += *table;
		table++;
	}
	return -ret;
}

static int __init parse_acpi(char *arg)
{
	if (!arg)
		return -EINVAL;

	/* "acpi=off" disables both ACPI table parsing and interpreter */
	if (strcmp(arg, "off") == 0) {
		disable_acpi();
	} else {
		/* Core will printk when we return error. */
		return -EINVAL;
	}
	return 0;
}
early_param("acpi", parse_acpi);

/*
 * __acpi_acquire_global_lock
 * will always return -1 indicating owning the lock.
 *
 * __acpi_release_global_lock will always return 0 indicating
 * no acquring request pending.
 */
int __acpi_acquire_global_lock(unsigned int *lock)
{
	return -1;
}

int __acpi_release_global_lock(unsigned int *lock)
{
	return 0;
}

#ifdef CONFIG_ACPI_NUMA
static __init int setup_node(int pxm)
{
	return acpi_map_pxm_to_node(pxm);
}

/*
 * Callback for SLIT parsing.  pxm_to_node() returns NUMA_NO_NODE for
 * I/O localities since SRAT does not list them.  I/O localities are
 * not supported at this point.
 */
extern unsigned char __node_distances[MAX_NUMNODES][MAX_NUMNODES];
unsigned int numa_distance_cnt;

static inline unsigned int get_numa_distances_cnt(struct acpi_table_slit *slit)
{
	return slit->locality_count;
}

void __init numa_set_distance(int from, int to, int distance)
{
	unsigned char *numa_distance = (unsigned char *)__node_distances;

	if ((u8)distance != distance ||
			(from == to && distance != LOCAL_DISTANCE)) {
		pr_warn_once("Warning: invalid distance parameter, from=%d to=%d distance=%d\n",
				from, to, distance);
		return;
	}

	numa_distance[from * numa_distance_cnt + to] = distance;
}

void __init acpi_numa_slit_init(struct acpi_table_slit *slit)
{
	int i, j;

	numa_distance_cnt = get_numa_distances_cnt(slit);

	for (i = 0; i < slit->locality_count; i++) {
		const int from_node = pxm_to_node(i);

		if (from_node == NUMA_NO_NODE)
			continue;

		for (j = 0; j < slit->locality_count; j++) {
			const int to_node = pxm_to_node(j);

			if (to_node == NUMA_NO_NODE)
				continue;

			numa_set_distance(from_node, to_node,
					slit->entry[slit->locality_count * i + j]);
		}
	}
}

extern cpumask_t possible_cpu_per_node;
/* Callback for Proximity Domain -> CPUID mapping */
void __init
acpi_numa_processor_affinity_init(struct acpi_srat_cpu_affinity *pa)
{
	int pxm, node;

	if (srat_disabled())
		return;
	if (pa->header.length != sizeof(struct acpi_srat_cpu_affinity)) {
		bad_srat();
		return;
	}
	if ((pa->flags & ACPI_SRAT_CPU_ENABLED) == 0)
		return;
	pxm = pa->proximity_domain_lo;
	if (acpi_srat_revision >= 2) {
		pxm |= (pa->proximity_domain_hi[0] << 8);
		pxm |= (pa->proximity_domain_hi[1] << 16);
		pxm |= (pa->proximity_domain_hi[2] << 24);
	}
	node = setup_node(pxm);
	if (node < 0) {
		pr_err("SRAT: Too many proximity domains %x\n", pxm);
		bad_srat();
		return;
	}

	if (pa->apic_id >= CONFIG_NR_CPUS) {
		pr_err("SRAT: PXM %u -> CPU 0x%02x -> Node %u skipped apicid that is too big\n", pxm, pa->apic_id, node);
		return;
	}

	if (!cpu_guestmode)
		numa_add_cpu(__cpu_number_map[pa->apic_id], node);
	else
		numa_add_cpu(pa->apic_id, node);

	set_cpuid_to_node(pa->apic_id, node);
	node_set(node, numa_nodes_parsed);
	acpi_numa = 1;
	pr_err("SRAT: PXM %u -> CPU 0x%02x -> Node %u\n",
		pxm, pa->apic_id, node);
}

#ifdef CONFIG_MEMORY_HOTPLUG
static inline int save_add_info(void) { return 1; }
#else
static inline int save_add_info(void) { return 0; }
#endif

/* Callback for parsing of the Proximity Domain <-> Memory Area mappings */
int __init
acpi_numa_memory_affinity_init(struct acpi_srat_mem_affinity *ma)
{
	u64 start, end;
	u32 hotpluggable;
	int node, pxm;

	if (srat_disabled())
		goto out_err;
	if (ma->header.length != sizeof(struct acpi_srat_mem_affinity))
		goto out_err_bad_srat;
	if ((ma->flags & ACPI_SRAT_MEM_ENABLED) == 0)
		goto out_err;
	hotpluggable = ma->flags & ACPI_SRAT_MEM_HOT_PLUGGABLE;
	if (hotpluggable && !save_add_info())
		goto out_err;

	start = ma->base_address;
	end = start + ma->length;
	pxm = ma->proximity_domain;
	if (acpi_srat_revision <= 1)
		pxm &= 0xff;

	node = setup_node(pxm);
	if (node < 0) {
		pr_err("SRAT: Too many proximity domains.\n");
		goto out_err_bad_srat;
	}
	if (numa_add_memblk(node, start, end) < 0)
		goto out_err_bad_srat;

	node_set(node, numa_nodes_parsed);

	pr_info("SRAT: Node %u PXM %u [mem %#010Lx-%#010Lx]%s%s\n",
		node, pxm,
		(unsigned long long) start, (unsigned long long) end - 1,
		hotpluggable ? " hotplug" : "",
		ma->flags & ACPI_SRAT_MEM_NON_VOLATILE ? " non-volatile" : "");

	/* Mark hotplug range in memblock. */
	if (hotpluggable && memblock_mark_hotplug(start, ma->length))
		pr_warn("SRAT: Failed to mark hotplug range [mem %#010Lx-%#010Lx] in memblock\n",
			(unsigned long long)start, (unsigned long long)end - 1);

	max_possible_pfn = max(max_possible_pfn, PFN_UP(end - 1));

	return 0;
out_err_bad_srat:
	bad_srat();
out_err:
	return -1;
}

void __init acpi_numa_arch_fixup(void) {}
#endif

#ifdef CONFIG_ACPI_HOTPLUG_CPU
#include <acpi/processor.h>
static int acpi_map_cpu2node(acpi_handle handle, int cpu, int physid)
{
#ifdef CONFIG_ACPI_NUMA
	int nid;

	nid = acpi_get_node(handle);
	if (nid != NUMA_NO_NODE) {
		set_cpuid_to_node(cpu, nid);
		node_set(nid, numa_nodes_parsed);
	}
#endif
	return 0;
}

int acpi_map_cpu(acpi_handle handle, phys_cpuid_t physid, u32 acpi_id,
			int *pcpu)
{
	int cpu;
	struct acpi_madt_local_apic *processor;

	processor = kzalloc(sizeof(struct acpi_madt_local_apic), GFP_KERNEL);
	processor->id = physid;
	processor->processor_id = acpi_id;
	processor->lapic_flags = ACPI_MADT_ENABLED;

	cpu = set_processor_mask(processor);
	if (cpu < 0) {
		pr_info(PREFIX "Unable to map lapic to logical cpu number\n");
		return cpu;
	}

	acpi_map_cpu2node(handle, cpu, physid);

	*pcpu = cpu;
	return 0;
}
EXPORT_SYMBOL(acpi_map_cpu);

int acpi_unmap_cpu(int cpu)
{
#ifdef CONFIG_ACPI_NUMA
	set_cpuid_to_node(cpu, NUMA_NO_NODE);
#endif
	set_cpu_present(cpu, false);
	num_processors--;

	pr_info("cpu%d hot remove!\n", cpu);

	return 0;
}
EXPORT_SYMBOL(acpi_unmap_cpu);
#endif /* CONFIG_ACPI_HOTPLUG_CPU */

void __init acpi_boot_table_init(void)

{
	/*
	 * If acpi_disabled, bail out
	 */
	if (!acpi_disabled) {
		if (acpi_table_init()) {
			pr_err("Failed to init ACPI tables\n");
			disable_acpi();
		}
		pr_info("Enable ACPI support\n");
	}
}
