#include <stdio.h>
#include <stdlib.h>
#include <api/fs/fs.h>
#include "header.h"

#define MIDR "/regs/identification/midr_el1"
#define MIDR_SIZE 19
#define MIDR_REVISION_MASK      0xf
#define MIDR_VARIANT_SHIFT      20
#define MIDR_VARIANT_MASK       (0xf << MIDR_VARIANT_SHIFT)

/* Return value of midr_el1 if success, else return 0. */
static int read_midr_el1(char *buf, int cpu_nr)
{
	char path[PATH_MAX];
	const char *sysfs = sysfs__mountpoint();
	u64 midr = 0;
	FILE *file;

	if (!sysfs)
		return 0;

	scnprintf(path, PATH_MAX, "%s/devices/system/cpu/cpu%d"MIDR,
		  sysfs, cpu_nr);

	file = fopen(path, "r");
	if (!file) {
		pr_debug("fopen failed for file %s\n", path);
		return 0;
	}

	if (!fgets(buf, MIDR_SIZE, file)) {
		fclose(file);
		return 0;
	}
	fclose(file);

	/* Ignore/clear Variant[23:20] and Revision[3:0] of MIDR */
	midr = strtoul(buf, NULL, 16);
	midr &= (~(MIDR_VARIANT_MASK | MIDR_REVISION_MASK));
	scnprintf(buf, MIDR_SIZE, "0x%016lx", midr);

	return midr;
}

int get_cpuid(char *buffer, size_t sz __maybe_unused)
{
	if (read_midr_el1(buffer, 0))
		return 0;

	return -1;
}

char *get_cpuid_str(struct perf_pmu *pmu)
{
	char *buf = NULL;
	int cpu;
	u64 midr = 0;
	struct cpu_map *cpus;

	if (!pmu || !pmu->cpus)
		return NULL;

	buf = malloc(MIDR_SIZE);
	if (!buf)
		return NULL;

	/* read midr from list of cpus mapped to this pmu */
	cpus = cpu_map__get(pmu->cpus);
	for (cpu = 0; cpu < cpus->nr; cpu++) {
		midr = read_midr_el1(buf, cpus->map[cpu]);
		if (midr)
			/* got midr break loop */
			break;
	}

	if (!midr) {
		pr_err("failed to get cpuid string for PMU %s\n", pmu->name);
		free(buf);
		buf = NULL;
	}

	cpu_map__put(cpus);
	return buf;
}
