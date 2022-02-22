/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_PERF_REGS_H
#define ARCH_PERF_REGS_H

#include <stdlib.h>
#include <linux/types.h>
#include <asm/perf_regs.h>

void perf_regs_load(u64 *regs);

#define PERF_REGS_MASK	((1ULL << PERF_REG_SW64_MAX) - 1)
#define PERF_REGS_MAX	PERF_REG_SW64_MAX
#define PERF_SAMPLE_REGS_ABI	PERF_SAMPLE_REGS_ABI_64

#define PERF_REG_IP	PERF_REG_SW64_PC
#define PERF_REG_SP	PERF_REG_SW64_HAE

static inline const char *perf_reg_name(int id)
{
	switch (id) {
	case PERF_REG_SW64_R0:
		return "r0";
	default:
		return NULL;
	}

	return NULL;
}

#endif /* ARCH_PERF_REGS_H */
