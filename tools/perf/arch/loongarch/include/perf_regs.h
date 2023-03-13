/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_PERF_REGS_H
#define ARCH_PERF_REGS_H

#include <stdlib.h>
#include <linux/types.h>
#include <asm/perf_regs.h>

#define PERF_REGS_MAX PERF_REG_LOONGARCH_MAX
#define PERF_REG_IP PERF_REG_LOONGARCH_PC
#define PERF_REG_SP PERF_REG_LOONGARCH_R3

#define PERF_REGS_MASK ((1ULL << PERF_REG_LOONGARCH_MAX) - 1)

static inline const char *__perf_reg_name(int id)
{
	switch (id) {
	case PERF_REG_LOONGARCH_PC:
		return "PC";
	case PERF_REG_LOONGARCH_R1:
		return "$1";
	case PERF_REG_LOONGARCH_R2:
		return "$2";
	case PERF_REG_LOONGARCH_R3:
		return "$3";
	case PERF_REG_LOONGARCH_R4:
		return "$4";
	case PERF_REG_LOONGARCH_R5:
		return "$5";
	case PERF_REG_LOONGARCH_R6:
		return "$6";
	case PERF_REG_LOONGARCH_R7:
		return "$7";
	case PERF_REG_LOONGARCH_R8:
		return "$8";
	case PERF_REG_LOONGARCH_R9:
		return "$9";
	case PERF_REG_LOONGARCH_R10:
		return "$10";
	case PERF_REG_LOONGARCH_R11:
		return "$11";
	case PERF_REG_LOONGARCH_R12:
		return "$12";
	case PERF_REG_LOONGARCH_R13:
		return "$13";
	case PERF_REG_LOONGARCH_R14:
		return "$14";
	case PERF_REG_LOONGARCH_R15:
		return "$15";
	case PERF_REG_LOONGARCH_R16:
		return "$16";
	case PERF_REG_LOONGARCH_R17:
		return "$17";
	case PERF_REG_LOONGARCH_R18:
		return "$18";
	case PERF_REG_LOONGARCH_R19:
		return "$19";
	case PERF_REG_LOONGARCH_R20:
		return "$20";
	case PERF_REG_LOONGARCH_R21:
		return "$21";
	case PERF_REG_LOONGARCH_R22:
		return "$22";
	case PERF_REG_LOONGARCH_R23:
		return "$23";
	case PERF_REG_LOONGARCH_R24:
		return "$24";
	case PERF_REG_LOONGARCH_R25:
		return "$25";
	case PERF_REG_LOONGARCH_R26:
		return "$26";
	case PERF_REG_LOONGARCH_R27:
		return "$27";
	case PERF_REG_LOONGARCH_R28:
		return "$28";
	case PERF_REG_LOONGARCH_R29:
		return "$29";
	case PERF_REG_LOONGARCH_R30:
		return "$30";
	case PERF_REG_LOONGARCH_R31:
		return "$31";
	default:
		break;
	}
	return NULL;
}

#endif /* ARCH_PERF_REGS_H */
