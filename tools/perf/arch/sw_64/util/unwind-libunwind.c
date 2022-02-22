// SPDX-License-Identifier: GPL-2.0
#include <errno.h>

#ifndef REMOTE_UNWIND_LIBUNWIND
#include <libunwind.h>
#include "perf_regs.h"
#include "../../util/unwind.h"
#include "../../util/debug.h"
#endif

int LIBUNWIND__ARCH_REG_ID(int regnum)
{
	switch (regnum) {
	case UNW_SW_64_R26:
		return PERF_REG_SW64_R26;
	case UNW_SW_64_R30:
		return PERF_REG_SW64_HAE;
	case UNW_SW_64_PC:
		return PERF_REG_SW64_PC;
	default:
		pr_err("unwind: invalid reg id %d\n", regnum);
		return -EINVAL;
	}

	return -EINVAL;
}
