// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "arm64 cpu-park: " fmt

#include <linux/arm_sdei.h>
#include <linux/delay.h>
#include <linux/kexec.h>
#include <linux/memblock.h>
#include <linux/ioport.h>
#include <linux/io.h>
#include <linux/types.h>

#include <asm/cacheflush.h>
#include <asm/cpu_ops.h>
#include <asm/cpu_park.h>
#include <asm/mmu_context.h>

#define PARK_SECTION_SIZE 1024

struct cpu_park_section {
	unsigned long exit;	/* exit address of park look */
	unsigned long magic;	/* maigc represent park state */
	char text[0];		/* text section of park */
};

struct cpu_park_info {
	/* Physical address of reserved park memory. */
	unsigned long start;
	/* park reserve mem len should be PARK_SECTION_SIZE * NR_CPUS */
	unsigned long len;
	/* Virtual address of reserved park memory. */
	unsigned long start_v;
};

static struct cpu_park_info park_info = {
	.start = 0,
	.len = PARK_SECTION_SIZE * NR_CPUS,
	.start_v = 0,
};

static int __init parse_park_mem(char *p)
{
	if (!p)
		return 0;

	park_info.start = PAGE_ALIGN(memparse(p, NULL));
	if (park_info.start == 0)
		pr_info("cpu park mem params[%s]", p);

	return 0;
}
early_param("cpuparkmem", parse_park_mem);

void __init reserve_park_mem(void)
{
	if (park_info.start == 0 || park_info.len == 0)
		return;

	park_info.start = PAGE_ALIGN(park_info.start);
	park_info.len = PAGE_ALIGN(park_info.len);

	if (!memblock_is_region_memory(park_info.start, park_info.len)) {
		pr_warn("region is not memory!");
		goto out;
	}

	if (memblock_is_region_reserved(park_info.start, park_info.len)) {
		pr_warn("region overlaps reserved memory!");
		goto out;
	}

	memblock_remove(park_info.start, park_info.len);
	pr_info("mem reserved: 0x%016lx - 0x%016lx (%ld MB)",
		park_info.start, park_info.start + park_info.len,
		park_info.len >> 20);

	return;
out:
	park_info.start = 0;
	park_info.len = 0;
	return;
}

static int mmap_cpu_park_mem(void)
{
	if (!park_info.start)
		return -ENOMEM;

	if (park_info.start_v)
		return 0;

	park_info.start_v = (unsigned long)__ioremap(park_info.start,
						     park_info.len,
						     PAGE_KERNEL_EXEC);
	if (!park_info.start_v) {
		pr_warn("map park memory failed.");
		return -ENOMEM;
	}

	return 0;
}

static inline unsigned long cpu_park_section_v(unsigned int cpu)
{
	return park_info.start_v + PARK_SECTION_SIZE * (cpu - 1);
}

static inline unsigned long cpu_park_section_p(unsigned int cpu)
{
	return park_info.start + PARK_SECTION_SIZE * (cpu - 1);
}

/*
 * Write the secondary_entry to exit section of park state.
 * Then the secondary cpu will jump straight into the kernel
 * by the secondary_entry.
 */
int write_park_exit(unsigned int cpu)
{
	struct cpu_park_section *park_section;
	unsigned long *park_exit;
	unsigned long *park_text;

	if (mmap_cpu_park_mem() != 0)
		return -EPERM;

	park_section = (struct cpu_park_section *)cpu_park_section_v(cpu);
	park_exit = &park_section->exit;
	park_text = (unsigned long *)park_section->text;
	pr_debug("park_text 0x%lx : 0x%lx, do_cpu_park text 0x%lx : 0x%lx",
		 (unsigned long)park_text, *park_text,
		 (unsigned long)do_cpu_park,
		 *(unsigned long *)do_cpu_park);

	/*
	 * Test first 8 bytes to determine
	 * whether needs to write cpu park exit.
	 */
	if (*park_text == *(unsigned long *)do_cpu_park) {
		writeq_relaxed(__pa_symbol(secondary_entry), park_exit);
		__flush_dcache_area((__force void *)park_exit,
				    sizeof(unsigned long));
		flush_icache_range((unsigned long)park_exit,
				   (unsigned long)(park_exit + 1));
		sev();
		dsb(sy);
		isb();

		pr_debug("Write cpu %u secondary entry 0x%lx to 0x%lx.",
			cpu, *park_exit, (unsigned long)park_exit);
		pr_info("Boot cpu %u from PARK state.", cpu);
		return 0;
	}

	return -EPERM;
}

/* Install cpu park sections for the specific cpu. */
static void install_cpu_park(unsigned int cpu)
{
	struct cpu_park_section *park_section;
	unsigned long *park_exit;
	unsigned long *park_magic;
	unsigned long park_text_len;

	park_section = (struct cpu_park_section *)cpu_park_section_v(cpu);
	pr_debug("Install cpu park on cpu %u park exit 0x%lx park text 0x%lx",
		 cpu, (unsigned long)park_section,
		 (unsigned long)(park_section->text));

	park_exit = &park_section->exit;
	park_magic = &park_section->magic;
	park_text_len = PARK_SECTION_SIZE - sizeof(struct cpu_park_section);

	*park_exit = 0UL;
	*park_magic = 0UL;
	memcpy((void *)park_section->text, do_cpu_park, park_text_len);
	__flush_dcache_area((void *)park_section, PARK_SECTION_SIZE);
}

int uninstall_cpu_park(unsigned int cpu)
{
	unsigned long park_section;

	if (mmap_cpu_park_mem() != 0)
		return -EPERM;

	park_section = cpu_park_section_v(cpu);
	memset((void *)park_section, 0, PARK_SECTION_SIZE);
	__flush_dcache_area((void *)park_section, PARK_SECTION_SIZE);

	return 0;
}

static int cpu_wait_park(unsigned int cpu)
{
	long timeout;
	struct cpu_park_section *park_section;

	volatile unsigned long *park_magic;

	park_section = (struct cpu_park_section *)cpu_park_section_v(cpu);
	park_magic = &park_section->magic;

	timeout = USEC_PER_SEC;
	while (*park_magic != PARK_MAGIC && timeout--)
		udelay(1);

	if (timeout > 0)
		pr_debug("cpu %u park done.", cpu);
	else
		pr_err("cpu %u park failed.", cpu);

	return *park_magic == PARK_MAGIC;
}

static void cpu_park(unsigned int cpu)
{
	unsigned long park_section_p;
	unsigned long park_exit_phy;
	unsigned long do_park;
	typeof(enter_cpu_park) *park;

	park_section_p = cpu_park_section_p(cpu);
	park_exit_phy = park_section_p;
	pr_debug("Go to park cpu %u exit address 0x%lx", cpu, park_exit_phy);

	do_park = park_section_p + sizeof(struct cpu_park_section);
	park = (void *)__pa_symbol(enter_cpu_park);

	cpu_install_idmap();
	park(do_park, park_exit_phy);
	unreachable();
}

void cpu_park_stop(void)
{
	int cpu = smp_processor_id();
	const struct cpu_operations *ops = NULL;
	/*
	 * Go to cpu park state.
	 * Otherwise go to cpu die.
	 */
	if (kexec_in_progress && park_info.start_v) {
		machine_kexec_mask_interrupts();
		cpu_park(cpu);

		ops = get_cpu_ops(cpu);
		if (ops && ops->cpu_die)
			ops->cpu_die(cpu);
	}
}

int kexec_smp_send_park(void)
{
	unsigned long cpu;

	if (WARN_ON(!kexec_in_progress)) {
		pr_crit("%s called not in kexec progress.", __func__);
		return -EPERM;
	}

	if (mmap_cpu_park_mem() != 0) {
		pr_info("no cpuparkmem, goto normal way.");
		return -EPERM;
	}

	local_irq_disable();

	if (num_online_cpus() > 1) {
		cpumask_t mask;

		cpumask_copy(&mask, cpu_online_mask);
		cpumask_clear_cpu(smp_processor_id(), &mask);

		for_each_cpu(cpu, &mask)
			install_cpu_park(cpu);
		smp_cross_send_stop(&mask);

		/* Wait for other CPUs to park */
		for_each_cpu(cpu, &mask)
			cpu_wait_park(cpu);
		pr_info("smp park other cpus done\n");
	}

	sdei_mask_local_cpu();

	return 0;
}
